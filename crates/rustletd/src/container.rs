//! A container as the daemon holds it in memory.
//!
//! Its state lives in a `watch` channel: one place to read it, and every
//! change wakes whoever waits on it (`wait`, `stop` waiting for the exit,
//! `logs -f` and `stats` noticing the end). Every change is also written to
//! the database before anyone is woken.
//!
//! Lifecycle operations (start, stop, restart, pause, rm) hold `op`, a
//! tokio mutex, for their whole duration, `.await`s included, so two of them
//! never interleave on one container. What happens *to* a container (it
//! exits) doesn't take `op`: the exit monitor cleans up, publishes the exit,
//! and only then hands the restart policy to a task that takes `op` like
//! any operation, so a `stop` waiting for the exit it caused can't deadlock
//! with it.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustlet_shim::client::ShimStream;
use rustlet_spec::container::{
    ContainerInspect, ContainerState, ContainerStatus, ContainerSummary, RestartPolicy, RestartPolicyName,
};
use tokio::sync::{oneshot, watch};

use crate::db::{Db, Persisted, Record};
use crate::error::{ApiError, ApiResult};

/// What the watch channel carries.
#[derive(Debug, Clone, Default)]
pub struct Shared {
    pub persisted: Persisted,
    /// How many runs have ended (an exit has been handled completely).
    pub exits: u64,
    pub removed: bool,
}

/// An attach to a container that hasn't started yet: `start` connects it to
/// the shim before it lets the program run.
pub struct PendingAttach {
    pub stdin: bool,
    /// The client's latest terminal size: applied before the start.
    pub resize: Arc<Mutex<Option<(u16, u16)>>>,
    pub tx: oneshot::Sender<ApiResult<ShimStream>>,
}

pub struct Container {
    pub record: Record,
    pub op: tokio::sync::Mutex<()>,
    shared: watch::Sender<Shared>,
    pub pending_attach: Mutex<Vec<PendingAttach>>,
    /// The restart policy's timer, while the container is `restarting`.
    pub restart_timer: Mutex<Option<tokio::task::AbortHandle>>,
    pub backoff: Mutex<Backoff>,
}

impl Container {
    pub fn new(record: Record, persisted: Persisted) -> Container {
        Container {
            record,
            op: tokio::sync::Mutex::new(()),
            shared: watch::Sender::new(Shared { persisted, exits: 0, removed: false }),
            pending_attach: Mutex::new(Vec::new()),
            restart_timer: Mutex::new(None),
            backoff: Mutex::new(Backoff::default()),
        }
    }

    pub fn id(&self) -> &str {
        &self.record.id
    }

    pub fn persisted(&self) -> Persisted {
        self.shared.borrow().persisted.clone()
    }

    pub fn status(&self) -> ContainerStatus {
        self.shared.borrow().persisted.state.status
    }

    pub fn subscribe(&self) -> watch::Receiver<Shared> {
        self.shared.subscribe()
    }

    /// Changes the persisted state: written to the database, then published.
    pub fn update(&self, db: &Db, f: impl FnOnce(&mut Persisted)) -> ApiResult<()> {
        let mut next = self.persisted();
        f(&mut next);
        let saved = db.save_state(self.id(), &next);
        self.shared.send_modify(|s| s.persisted = next);
        saved
    }

    /// The end of a run: the state, and one more exit for those waiting.
    pub fn finish_run(&self, db: &Db, f: impl FnOnce(&mut Persisted)) {
        let mut next = self.persisted();
        f(&mut next);
        if let Err(e) = db.save_state(self.id(), &next) {
            tracing::warn!(id = %self.id(), "save the exit: {e}");
        }
        self.shared.send_modify(|s| {
            s.persisted = next;
            s.exits += 1;
        });
    }

    pub fn mark_removed(&self) {
        self.shared.send_modify(|s| s.removed = true);
        // Attaches still waiting for a start that won't come.
        self.fail_pending_attaches(&ApiError::no_such_container(&self.record.name));
    }

    /// Ends the attaches waiting for a start with `e`.
    pub fn fail_pending_attaches(&self, e: &ApiError) {
        for p in self.pending_attach.lock().unwrap_or_else(|e| e.into_inner()).drain(..) {
            let _ = p.tx.send(Err(e.clone()));
        }
    }

    pub fn cancel_restart(&self) -> bool {
        match self.restart_timer.lock().unwrap_or_else(|e| e.into_inner()).take() {
            Some(t) => {
                t.abort();
                true
            }
            None => false,
        }
    }

    pub fn summary(&self) -> ContainerSummary {
        let r = &self.record;
        ContainerSummary {
            id: r.id.clone(),
            name: r.name.clone(),
            image: r.image.clone(),
            image_id: r.image_id.clone(),
            command: r.command.clone(),
            created: r.created.clone(),
            state: self.persisted().state,
            labels: r.config.labels.clone(),
        }
    }

    /// The cgroup of the current or last run, else where the next goes.
    pub fn cgroup(&self, cgroup_parent: &str) -> String {
        self.persisted().cgroup.unwrap_or_else(|| cgroup_path(cgroup_parent, self.id()))
    }

    pub fn inspect(&self, paths: &crate::config::Paths, cgroup_parent: &str) -> ContainerInspect {
        let r = &self.record;
        let cgroup = self.cgroup(cgroup_parent);
        let state = self.persisted().state;
        let dir = paths.container_dir(&r.id);
        ContainerInspect {
            id: r.id.clone(),
            name: r.name.clone(),
            created: r.created.clone(),
            image: r.image.clone(),
            image_id: r.image_id.clone(),
            command: r.command.clone(),
            config: r.config.clone(),
            rootfs: state.status.is_live().then(|| dir.join("rootfs").display().to_string()),
            state,
            hostname: r.hostname.clone(),
            dir: dir.display().to_string(),
            log_path: paths.container_log(&r.id).display().to_string(),
            cgroup,
            uid_map: (r.config.userns == rustlet_spec::container::UsernsMode::Remap)
                .then(|| format!("0 {} {}", rustlet_runtime::spec::REMAP_HOST_ID, rustlet_runtime::spec::REMAP_SIZE)),
        }
    }
}

/// `<parent>/containers/<id>`.
pub fn cgroup_path(parent: &str, id: &str) -> String {
    format!("{parent}/containers/{id}")
}

/// Should a container that exited like `st` be started again?
pub fn should_restart(policy: &RestartPolicy, st: &Persisted) -> bool {
    if st.manually_stopped {
        return false;
    }
    match policy.name {
        RestartPolicyName::No => false,
        RestartPolicyName::Always | RestartPolicyName::UnlessStopped => true,
        RestartPolicyName::OnFailure => {
            st.state.exit_code != Some(0) && (policy.max_retries == 0 || st.state.restart_count < policy.max_retries)
        }
    }
}

/// Should the daemon start this stopped container when it starts? Docker's
/// rule: `always` even after a manual stop, `unless-stopped` unless stopped
/// by hand.
pub fn start_at_boot(policy: &RestartPolicy, st: &Persisted) -> bool {
    match policy.name {
        RestartPolicyName::Always => true,
        RestartPolicyName::UnlessStopped => !st.manually_stopped,
        _ => false,
    }
}

/// The delay before a restart, as Docker's: 100 ms, doubling up to a
/// minute; back to 100 ms once a run lasted 10 seconds.
#[derive(Debug, Clone, Copy)]
pub struct Backoff {
    next: Duration,
}

impl Backoff {
    pub const INITIAL: Duration = Duration::from_millis(100);
    pub const MAX: Duration = Duration::from_secs(60);
    pub const RESET_AFTER: Duration = Duration::from_secs(10);

    pub fn delay(&mut self, ran_for: Option<Duration>) -> Duration {
        if ran_for.is_some_and(|d| d >= Self::RESET_AFTER) {
            self.next = Self::INITIAL;
        }
        let d = self.next;
        self.next = (self.next * 2).min(Self::MAX);
        d
    }

    pub fn reset(&mut self) {
        self.next = Self::INITIAL;
    }
}

impl Default for Backoff {
    fn default() -> Backoff {
        Backoff { next: Backoff::INITIAL }
    }
}

/// How long the last run lasted.
pub fn ran_for(state: &ContainerState) -> Option<Duration> {
    let parse = |s: &Option<String>| chrono::DateTime::parse_from_rfc3339(s.as_deref()?).ok();
    let (start, end) = (parse(&state.started_at)?, parse(&state.finished_at)?);
    (end - start).to_std().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exited(code: i32, restarts: u32, manual: bool) -> Persisted {
        let mut p = Persisted::default();
        p.state.status = ContainerStatus::Exited;
        p.state.exit_code = Some(code);
        p.state.restart_count = restarts;
        p.manually_stopped = manual;
        p
    }

    #[test]
    fn restart_policies() {
        let p = |s| RestartPolicy::parse(s).unwrap();
        assert!(!should_restart(&p("no"), &exited(1, 0, false)));
        assert!(should_restart(&p("always"), &exited(0, 0, false)));
        assert!(!should_restart(&p("always"), &exited(0, 0, true)));
        assert!(should_restart(&p("unless-stopped"), &exited(0, 9, false)));
        assert!(should_restart(&p("on-failure"), &exited(1, 100, false)));
        assert!(!should_restart(&p("on-failure"), &exited(0, 0, false)));
        assert!(should_restart(&p("on-failure:2"), &exited(1, 1, false)));
        assert!(!should_restart(&p("on-failure:2"), &exited(1, 2, false)));
        // At daemon start.
        assert!(start_at_boot(&p("always"), &exited(0, 0, true)));
        assert!(!start_at_boot(&p("unless-stopped"), &exited(0, 0, true)));
        assert!(start_at_boot(&p("unless-stopped"), &exited(0, 0, false)));
        assert!(!start_at_boot(&p("on-failure"), &exited(1, 0, false)));
    }

    #[test]
    fn backoff_doubles_to_a_minute_and_resets_after_a_long_run() {
        let mut b = Backoff::default();
        let quick = Some(Duration::from_secs(1));
        let delays: Vec<u128> = (0..12).map(|_| b.delay(quick).as_millis()).collect();
        assert_eq!(&delays[..4], [100, 200, 400, 800]);
        assert_eq!(*delays.last().unwrap(), 60_000);
        assert_eq!(b.delay(Some(Duration::from_secs(30))).as_millis(), 100);
        assert_eq!(b.delay(None).as_millis(), 200);
    }

    #[test]
    fn run_durations() {
        let s = ContainerState {
            started_at: Some("2026-10-01T10:00:00Z".into()),
            finished_at: Some("2026-10-01T10:00:12.5Z".into()),
            ..Default::default()
        };
        assert_eq!(ran_for(&s), Some(Duration::from_millis(12_500)));
        assert_eq!(ran_for(&ContainerState::default()), None);
    }
}

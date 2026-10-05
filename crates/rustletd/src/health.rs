//! Healthchecks: a command run in a container now and then, whose exit
//! status says whether the container works.
//!
//! ```text
//!  start ──► starting ──check ok──► healthy ◄──┐
//!               │                      │ fail   │ ok
//!               │ `retries` fails      ▼        │
//!               └────────────────► unhealthy ───┘
//! ```
//!
//! The check comes from the image (`HEALTHCHECK`) or the container's
//! options (`--health-*`, compose's `healthcheck`), the container's
//! options over the image's one by one ([`HealthPlan::resolve`]); `NONE`
//! turns it off. Docker's rules:
//!
//! - every run starts `starting`; the first check comes `interval` after
//!   the start (or `start_interval` during the start period);
//! - exit status 0 is a success: `healthy`, and the count of failures in a
//!   row goes back to 0; anything else, a check that takes longer than
//!   `timeout` (it is killed), or one that can't run, is a failure;
//! - a failure during the start period (`start_period` after the start,
//!   while the status is still `starting`) doesn't count; after it,
//!   `retries` failures in a row make the container `unhealthy`;
//! - the last five checks are kept, with what they printed (4 KiB each).
//!
//! A check is an exec through the container's shim, as `rustlet exec`'s
//! processes are, but not one of the daemon's exec sessions: there is no
//! exec id to inspect and no `exec_*` event, only a `health_status` event
//! when the verdict changes. Its state is part of the container's
//! ([`rustlet_spec::container::ContainerState::health`]), saved with every
//! check, so `inspect` and `ps` show it and a restarted daemon picks it up
//! where the last one left it (the monitor of a container that is taken
//! over starts again from its saved state, its start period counted from
//! the container's start). A paused container isn't checked: its
//! processes are frozen, and a check would only time out.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use rustlet_image::config::Healthcheck as ImageHealthcheck;
use rustlet_shim::client::{ShimClient, StreamEvent};
use rustlet_shim::protocol::{ExecRequest, Request, Response};
use rustlet_spec::container::{ContainerStatus, Health, HealthConfig, HealthResult, HealthStatus};

use crate::container::Container;
use crate::daemon::Daemon;

const DEFAULT_INTERVAL: Duration = Duration::from_secs(30);
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_START_INTERVAL: Duration = Duration::from_secs(5);
const DEFAULT_RETRIES: u32 = 3;
/// Checks kept in [`Health::log`].
const LOG_ENTRIES: usize = 5;
/// What a check's output is cut to.
const MAX_OUTPUT: usize = 4096;

/// A container's effective healthcheck.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthPlan {
    /// What runs: the program and its arguments.
    pub args: Vec<String>,
    pub interval: Duration,
    pub timeout: Duration,
    pub start_period: Duration,
    pub start_interval: Duration,
    pub retries: u32,
}

impl HealthPlan {
    /// The container's options over its image's, one by one, as Docker
    /// merges them; `None` when there is no check (none given, or `NONE`).
    /// `shell` is the image's `SHELL`, for `CMD-SHELL`.
    pub fn resolve(
        container: Option<&HealthConfig>,
        image: Option<&ImageHealthcheck>,
        shell: Option<&[String]>,
    ) -> Option<HealthPlan> {
        let test = match container {
            Some(c) if !c.test.is_empty() => c.test.clone(),
            _ => image.map(|i| i.test.clone()).unwrap_or_default(),
        };
        let args = match test.split_first() {
            Some((kind, rest)) if kind == "CMD" && !rest.is_empty() => rest.to_vec(),
            Some((kind, [command])) if kind == "CMD-SHELL" => {
                let mut args = shell.map(<[String]>::to_vec).unwrap_or_else(|| vec!["/bin/sh".into(), "-c".into()]);
                args.push(command.clone());
                args
            }
            // NONE, nothing at all, or what Docker would refuse too.
            _ => return None,
        };
        // A container's value if it gave one, else the image's, else the
        // default; 0 counts as not given, in both.
        let pick = |own: Option<u64>, image: Option<i64>, default: Duration| {
            own.filter(|&n| n > 0)
                .or_else(|| image.and_then(|n| u64::try_from(n).ok()).filter(|&n| n > 0))
                .map_or(default, Duration::from_nanos)
        };
        let c = container.cloned().unwrap_or_default();
        Some(HealthPlan {
            args,
            interval: pick(c.interval, image.and_then(|i| i.interval), DEFAULT_INTERVAL),
            timeout: pick(c.timeout, image.and_then(|i| i.timeout), DEFAULT_TIMEOUT),
            start_period: pick(c.start_period, image.and_then(|i| i.start_period), Duration::ZERO),
            start_interval: pick(c.start_interval, image.and_then(|i| i.start_interval), DEFAULT_START_INTERVAL),
            retries: c
                .retries
                .filter(|&n| n > 0)
                .or_else(|| image.and_then(|i| i.retries).and_then(|n| u32::try_from(n).ok()).filter(|&n| n > 0))
                .unwrap_or(DEFAULT_RETRIES),
        })
    }
}

/// Records a check's result in `health`: Docker's rules (see the module
/// docs). `in_start_period`: the start period hasn't passed yet. Returns
/// the new status if it changed.
pub fn record(health: &mut Health, result: HealthResult, retries: u32, in_start_period: bool) -> Option<HealthStatus> {
    let before = health.status;
    if result.exit_code == 0 {
        health.status = HealthStatus::Healthy;
        health.failing_streak = 0;
    } else if !(in_start_period && health.status == HealthStatus::Starting) {
        health.failing_streak += 1;
        if health.failing_streak >= retries {
            health.status = HealthStatus::Unhealthy;
        }
    }
    health.log.push(result);
    let excess = health.log.len().saturating_sub(LOG_ENTRIES);
    health.log.drain(..excess);
    (health.status != before).then_some(health.status)
}

impl Daemon {
    /// Starts checking a run that just started (`fresh`: its health starts
    /// over, `starting`), or one taken over from the last daemon (its saved
    /// health goes on). Without a check, the run has no health.
    pub fn start_health(self: &Arc<Self>, c: &Arc<Container>, image: Option<&rustlet_image::Image>, fresh: bool) {
        stop_health(c);
        let plan = HealthPlan::resolve(
            c.record.config.healthcheck.as_ref(),
            image.and_then(|i| i.config.healthcheck.as_ref()),
            image.and_then(|i| i.config.shell.as_deref()),
        );
        let Some(plan) = plan else {
            if fresh {
                let _ = c.update(&self.db, |s| s.state.health = None);
            }
            return;
        };
        let mut health = if fresh { None } else { c.persisted().state.health };
        if health.is_none() {
            let _ = c.update(&self.db, |s| s.state.health = Some(Health::default()));
            health = Some(Health::default());
        }
        let health = health.unwrap_or_default();
        let (d, c2) = (self.clone(), c.clone());
        let task = tokio::spawn(async move { d.check_health(c2, plan, health).await });
        *c.health_task.lock().unwrap_or_else(|e| e.into_inner()) = Some(task.abort_handle());
    }

    /// The monitor of one run: checks until it is aborted (the run ended).
    async fn check_health(self: Arc<Self>, c: Arc<Container>, plan: HealthPlan, mut health: Health) {
        let socket = self.paths.shim(c.id()).socket();
        // The start period runs from the container's start, as Docker's:
        // a new daemon taking a container over doesn't give it another.
        let since_start = c
            .persisted()
            .state
            .started_at
            .and_then(|t| chrono::DateTime::parse_from_rfc3339(&t).ok())
            .and_then(|t| (chrono::Utc::now() - t.with_timezone(&chrono::Utc)).to_std().ok())
            .unwrap_or_default();
        let started = Instant::now().checked_sub(since_start).unwrap_or_else(Instant::now);
        loop {
            let in_start_period = health.status == HealthStatus::Starting && started.elapsed() < plan.start_period;
            tokio::time::sleep(if in_start_period { plan.start_interval } else { plan.interval }).await;
            match c.status() {
                ContainerStatus::Running => {}
                ContainerStatus::Paused => continue,
                // The run is ending; its exit stops this task.
                _ => return,
            }
            let in_start_period = health.status == HealthStatus::Starting && started.elapsed() < plan.start_period;
            let result = run_check(&socket, &plan).await;
            let changed = record(&mut health, result, plan.retries, in_start_period);
            let saved = health.clone();
            let _ = c.update(&self.db, |s| {
                if s.state.status.is_live() {
                    s.state.health = Some(saved);
                }
            });
            if let Some(status) = changed {
                tracing::info!(id = %c.id(), %status, "health");
                if status != HealthStatus::Starting {
                    self.emit(&c, "health_status", &[("health_status", status.to_string())]);
                }
            }
        }
    }
}

/// Stops a run's checks (it ended, or another monitor takes over).
pub fn stop_health(c: &Container) {
    if let Some(task) = c.health_task.lock().unwrap_or_else(|e| e.into_inner()).take() {
        task.abort();
    }
}

/// One check: an exec through the shim, killed after the timeout.
async fn run_check(socket: &Path, plan: &HealthPlan) -> HealthResult {
    static N: AtomicU64 = AtomicU64::new(0);
    let start = rustlet_shim::logfile::now();
    let failed = |exit_code: i32, output: String| HealthResult {
        start: start.clone(),
        end: rustlet_shim::logfile::now(),
        exit_code,
        output,
    };
    let request = Request::Exec(ExecRequest {
        kill_on_disconnect: true,
        exec_id: format!("health-{}", N.fetch_add(1, Ordering::Relaxed)),
        args: plan.args.clone(),
        ..ExecRequest::default()
    });
    let opened = async { ShimClient::connect(socket).await?.open_stream(&request).await }.await;
    let mut stream = match opened {
        Ok((Response::Started { .. }, Some(stream))) => stream,
        Ok((Response::Error { message, exit_code }, _)) => return failed(exit_code.unwrap_or(-1), message),
        Ok((other, _)) => return failed(-1, format!("the shim said {other:?}")),
        Err(e) => return failed(-1, format!("the container's shim: {e}")),
    };
    let mut output = Vec::new();
    let read = async {
        loop {
            match stream.recv().await {
                Ok(Some(StreamEvent::Stdout(b) | StreamEvent::Stderr(b))) => {
                    let room = MAX_OUTPUT.saturating_sub(output.len());
                    output.extend_from_slice(&b[..b.len().min(room)]);
                }
                Ok(Some(StreamEvent::Exited(exit))) => return Some(exit.code),
                Ok(None) | Err(_) => return None,
            }
        }
    };
    let code = tokio::time::timeout(plan.timeout, read).await;
    let text = String::from_utf8_lossy(&output).into_owned();
    match code {
        Ok(Some(code)) => HealthResult { start, end: rustlet_shim::logfile::now(), exit_code: code, output: text },
        Ok(None) => failed(-1, format!("{text}the check ended without an exit status")),
        Err(_) => {
            // The process is the shim's to reap; it only has to die.
            let _ = stream.writer().signal(9).await;
            failed(-1, format!("Health check exceeded timeout ({:?})", plan.timeout))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    fn result(code: i32) -> HealthResult {
        HealthResult { exit_code: code, ..HealthResult::default() }
    }

    #[test]
    fn the_containers_options_go_over_the_images_one_by_one() {
        let image = ImageHealthcheck {
            test: s(&["CMD-SHELL", "curl -f http://localhost/"]),
            interval: Some(10_000_000_000),
            timeout: None,
            start_period: Some(5_000_000_000),
            start_interval: None,
            retries: Some(5),
        };
        let p = HealthPlan::resolve(None, Some(&image), None).unwrap();
        assert_eq!(p.args, s(&["/bin/sh", "-c", "curl -f http://localhost/"]));
        assert_eq!(
            (p.interval, p.timeout, p.start_period, p.start_interval, p.retries),
            (Duration::from_secs(10), DEFAULT_TIMEOUT, Duration::from_secs(5), DEFAULT_START_INTERVAL, 5)
        );
        // Options only: the image's command with them.
        let own = HealthConfig { interval: Some(1_000_000), retries: Some(1), ..HealthConfig::default() };
        let p = HealthPlan::resolve(Some(&own), Some(&image), Some(&s(&["/bin/bash", "-eu", "-c"]))).unwrap();
        assert_eq!(p.args, s(&["/bin/bash", "-eu", "-c", "curl -f http://localhost/"]));
        assert_eq!((p.interval, p.retries, p.start_period), (Duration::from_millis(1), 1, Duration::from_secs(5)));
        // Its own command.
        let own = HealthConfig { test: s(&["CMD", "pg_isready", "-q"]), ..HealthConfig::default() };
        assert_eq!(HealthPlan::resolve(Some(&own), Some(&image), None).unwrap().args, s(&["pg_isready", "-q"]));
        // NONE turns the image's off; nothing at all is no check.
        let none = HealthConfig { test: s(&["NONE"]), ..HealthConfig::default() };
        assert_eq!(HealthPlan::resolve(Some(&none), Some(&image), None), None);
        assert_eq!(HealthPlan::resolve(None, None, None), None);
        let image_none = ImageHealthcheck { test: s(&["NONE"]), ..image.clone() };
        assert_eq!(HealthPlan::resolve(None, Some(&image_none), None), None);
        // What Docker refuses is no check either.
        for bad in [&["CMD"][..], &["CMD-SHELL", "a", "b"], &["WHAT", "x"]] {
            let own = HealthConfig { test: s(bad), ..HealthConfig::default() };
            assert_eq!(HealthPlan::resolve(Some(&own), None, None), None, "{bad:?}");
        }
    }

    #[test]
    fn retries_failures_in_a_row_make_it_unhealthy_and_a_success_heals() {
        let mut h = Health::default();
        assert_eq!(record(&mut h, result(1), 3, false), None);
        assert_eq!(record(&mut h, result(1), 3, false), None);
        assert_eq!(h.failing_streak, 2);
        assert_eq!(record(&mut h, result(0), 3, false), Some(HealthStatus::Healthy));
        assert_eq!(h.failing_streak, 0);
        for _ in 0..2 {
            assert_eq!(record(&mut h, result(1), 3, false), None);
        }
        assert_eq!(h.status, HealthStatus::Healthy, "two failures of three");
        assert_eq!(record(&mut h, result(-1), 3, false), Some(HealthStatus::Unhealthy));
        assert_eq!(record(&mut h, result(1), 3, false), None, "no change, no event");
        assert_eq!(record(&mut h, result(0), 3, false), Some(HealthStatus::Healthy));
        assert_eq!(h.log.len(), LOG_ENTRIES, "the last five");
        assert_eq!(h.log.last().unwrap().exit_code, 0);
    }

    #[test]
    fn failures_in_the_start_period_dont_count_until_a_success() {
        let mut h = Health::default();
        for _ in 0..10 {
            assert_eq!(record(&mut h, result(1), 1, true), None);
        }
        assert_eq!((h.status, h.failing_streak), (HealthStatus::Starting, 0));
        assert_eq!(record(&mut h, result(0), 1, true), Some(HealthStatus::Healthy));
        // Once healthy, the start period no longer shields failures.
        assert_eq!(record(&mut h, result(1), 1, true), Some(HealthStatus::Unhealthy));
        // After the start period, a starting container counts them.
        let mut h = Health::default();
        assert_eq!(record(&mut h, result(1), 2, false), None);
        assert_eq!(record(&mut h, result(1), 2, false), Some(HealthStatus::Unhealthy));
    }
}

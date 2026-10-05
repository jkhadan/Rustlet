//! The OCI lifecycle operations on an existing container: `start`, `state`,
//! `kill`, `delete`, plus runc's `pause`/`resume`, `ps`, `list` and
//! `events --stats`.
//!
//! None of these keep any process around: they read `<root>/<id>/state.json`,
//! check the live system, act, and exit. Talking to init always goes through
//! a pidfd opened *before* checking init's start time (see
//! `create::open_init`), so a recycled PID can never be signalled by mistake.
//! Operations that change a container hold its lock ([`StateDir::lock`]),
//! so they never interleave with each other or with a running `create`.

use std::os::fd::AsFd;
use std::path::Path;
use std::time::Duration;

use nix::sys::signal::Signal;
use nix::unistd::Pid;
use rustlet_sys::Errno;
use rustlet_sys::process;

use crate::cgroups::{Cgroup, stats};
use crate::create::{self, TEARDOWN_TIMEOUT};
use crate::error::{Context, Error, Result};
use crate::state::{self, State, StateDir, Status};

/// How long `pause`/`resume` wait for the kernel to (un)freeze.
const FREEZE_TIMEOUT: Duration = Duration::from_secs(10);

fn load(root: &Path, id: &str) -> Result<(StateDir, State)> {
    let dir = StateDir::new(root, id)?;
    let state = dir.load()?;
    Ok((dir, state))
}

fn wrong_status(state: &State, doing: &str) -> Error {
    Error::container(format!("cannot {doing} container {:?}: it is {}", state.id, state.status))
}

/// `start`: lets a `created` container's init `execve` the program.
pub fn start(root: &Path, id: &str) -> Result<()> {
    let dir = StateDir::new(root, id)?;
    let _lock = dir.lock()?;
    let state = dir.load()?;
    if state.status != Status::Created {
        return Err(wrong_status(&state, "start"));
    }
    let init = create::open_init(&state)?;
    create::release(&dir, &init)
}

/// `state`: the OCI state document, with a live status.
pub fn state(root: &Path, id: &str) -> Result<State> {
    Ok(load(root, id)?.1.for_display())
}

/// `list`: every container under `root`.
pub fn list(root: &Path) -> Result<Vec<State>> {
    Ok(state::list(root)?.iter().map(State::for_display).collect())
}

/// `kill`: sends `sig` to init, or with `all` to every process in the
/// container's cgroup.
///
/// For `--all`, SIGKILL goes through `cgroup.kill` (atomic). Any other
/// signal is sent PID by PID from `cgroup.procs`, with the cgroup *frozen*
/// meanwhile (as runc does): a frozen process can't fork or exit, so the list
/// can't go stale while we walk it and no PID can be recycled under us.
/// Child cgroups are included for every signal.
pub fn kill(root: &Path, id: &str, sig: Signal, all: bool) -> Result<()> {
    let dir = StateDir::new(root, id)?;
    let _lock = dir.lock()?;
    let state = dir.load()?;
    if state.status == Status::Stopped {
        return Err(wrong_status(&state, "kill"));
    }
    let init = create::open_init(&state)?;
    if all {
        let cg = state.cgroup()?.ok_or_else(|| Error::container("kill --all needs a cgroup (linux.cgroupsPath)"))?;
        if sig == Signal::SIGKILL {
            return cg.kill();
        }
        let was_frozen = cg.read("cgroup.freeze")? == "1";
        // A prior request may still be in progress: wait for confirmed
        // freezing in either case before trusting the process list.
        cg.freeze(FREEZE_TIMEOUT).inspect_err(|_| {
            if !was_frozen {
                let _ = cg.thaw(FREEZE_TIMEOUT);
            }
        })?;
        let result = (|| {
            let mut result = Ok(());
            for pid in cg.all_procs()? {
                match nix::sys::signal::kill(pid, sig) {
                    Ok(()) | Err(Errno::ESRCH) => {}
                    Err(e) => result = Err(e).with_context(|| format!("kill {pid}")),
                }
            }
            result
        })();
        if !was_frozen {
            // Restore the original state even if listing or signalling
            // failed; otherwise `kill --all` silently pauses the container.
            let thawed = cg.thaw(FREEZE_TIMEOUT);
            result?;
            thawed?;
            return Ok(());
        }
        return result;
    }
    process::pidfd_send_signal(init.as_fd(), sig).with_context(|| format!("send {sig:?} to container init"))
}

/// `delete`: removes a stopped container. A `created` (or half-created) one
/// is killed first, as runc does: it never ran anything. A running or paused
/// one only with `force`, which kills everything in it.
///
/// Unreadable state is an error even with `force`: a live init or cgroup
/// may still depend on it, and reporting success would orphan them.
pub fn delete(root: &Path, id: &str, force: bool) -> Result<()> {
    let dir = StateDir::new(root, id)?;
    let _lock = dir.lock()?;
    let state = dir.load()?;
    let cgroup = state.cgroup()?;
    match state.status {
        Status::Stopped => {}
        Status::Created | Status::Creating => kill_all(&state, cgroup.as_ref())?,
        Status::Running | Status::Paused if force => kill_all(&state, cgroup.as_ref())?,
        _ => {
            return Err(Error::container(format!(
                "cannot delete container {id:?}: it is {} (stop it first, or use --force)",
                state.status
            )));
        }
    }
    if let Some(cg) = &cgroup {
        // init may be gone while other processes (e.g. with a shared PID
        // namespace) linger; `remove_tree` kills them too.
        cg.remove_tree(TEARDOWN_TIMEOUT)?;
    }
    dir.remove()
}

fn kill_all(state: &State, cgroup: Option<&Cgroup>) -> Result<()> {
    let init = create::open_init(state).ok();
    create::kill_everything(cgroup, init.as_ref())
}

/// `pause`: freezes every process in the container (`cgroup.freeze`). If
/// the kernel doesn't confirm in time, the freeze is rolled back, so the
/// container is never left half-frozen with a status that says "running".
pub fn pause(root: &Path, id: &str) -> Result<()> {
    let dir = StateDir::new(root, id)?;
    let _lock = dir.lock()?;
    let state = dir.load()?;
    if state.status != Status::Running {
        return Err(wrong_status(&state, "pause"));
    }
    let cg = freezable(&state)?;
    cg.freeze(FREEZE_TIMEOUT).inspect_err(|_| {
        let _ = cg.thaw(FREEZE_TIMEOUT);
    })
}

/// `resume`: thaws a paused container (also one whose freeze was requested
/// but never completed).
pub fn resume(root: &Path, id: &str) -> Result<()> {
    let dir = StateDir::new(root, id)?;
    let _lock = dir.lock()?;
    let state = dir.load()?;
    let cg = freezable(&state)?;
    let freeze_requested = cg.read("cgroup.freeze").is_ok_and(|v| v == "1");
    if state.status != Status::Paused && !freeze_requested {
        return Err(wrong_status(&state, "resume"));
    }
    cg.thaw(FREEZE_TIMEOUT)
}

fn freezable(state: &State) -> Result<Cgroup> {
    state.cgroup()?.ok_or_else(|| Error::container("pause/resume need a cgroup (linux.cgroupsPath)"))
}

/// `ps`: host PIDs of the container's processes.
pub fn ps(root: &Path, id: &str) -> Result<Vec<Pid>> {
    let (_dir, state) = load(root, id)?;
    if state.status == Status::Stopped {
        return Ok(Vec::new());
    }
    match state.cgroup()? {
        Some(cg) => cg.all_procs(),
        None => Ok(vec![state.init_pid()]),
    }
}

/// `events --stats`: one runc-style stats envelope,
/// `{"type":"stats","id":…,"data":{…cgroup stats…, "network":[…]}}`.
/// Works on a stopped container too, until it is deleted: that's how you
/// find out after the fact that it was OOM-killed.
pub fn stats(root: &Path, id: &str) -> Result<serde_json::Value> {
    let (_dir, state) = load(root, id)?;
    let cg = state.cgroup()?.ok_or_else(|| Error::container("stats need a cgroup (linux.cgroupsPath)"))?;
    let mut data = serde_json::to_value(cg.stats()?).expect("Stats always serializes");
    let network = if state.init_alive() { stats::net_dev(state.init_pid()).unwrap_or_default() } else { Vec::new() };
    data["network"] = serde_json::to_value(network).expect("NetDev always serializes");
    Ok(serde_json::json!({ "type": "stats", "id": state.id, "data": data }))
}

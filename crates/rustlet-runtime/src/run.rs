//! `rustlet-runc run`: create, start, and (in the foreground) supervise a
//! container until it exits, then delete it.
//!
//! ## Signals in the foreground
//!
//! Signals reach `rustlet-runc` from two directions, and which ones to
//! forward depends on whether the container has a terminal of its own:
//!
//! * **Without a PTY** the container shares our terminal *and process group*,
//!   so the terminal driver already delivers Ctrl-C (SIGINT), Ctrl-\
//!   (SIGQUIT) and resizes (SIGWINCH) to it directly. Those arrive with
//!   `si_code == SI_KERNEL` and are not forwarded (it would deliver them
//!   twice).
//! * **With a PTY** the container is in a session of its own. Your terminal
//!   is in raw mode, so Ctrl-C is just a byte relayed to the PTY, whose line
//!   discipline turns it into SIGINT *inside* the container. A SIGWINCH from
//!   your terminal becomes a resize of the PTY; everything else is forwarded.
//! * Signals from other processes (`kill <runc pid>`, systemd) are always
//!   forwarded to init through its pidfd.
//!
//! PID 1 of a namespace ignores every signal it has no handler for (only
//! SIGKILL/SIGSTOP from outside get through): `sleep 100` as init shrugs off
//! SIGTERM. That is kernel behaviour, not a forwarding bug.

use std::os::fd::{AsFd, OwnedFd};

use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::signal::Signal;
use nix::sys::signalfd::SignalFd;
use rustlet_sys::Errno;
use rustlet_sys::process::{self, WaitResult, WaitTarget};

use crate::cgroups::Cgroup;
use crate::console::{self, Relay};
use crate::create::{self, CreateOptions, Spawned};
use crate::error::{Context, Result};

/// Options for [`run`].
#[derive(Debug, Clone)]
pub struct RunOptions {
    pub create: CreateOptions,
    /// Return once the program runs, leaving the container behind.
    pub detach: bool,
}

/// Creates and starts the container. In the foreground, waits for it,
/// deletes it, and returns its exit status shell-style (the exit code, or
/// 128 + signal number). Detached, returns 0 once the program runs.
pub fn run(opts: &RunOptions) -> Result<i32> {
    let mut c = create::spawn(&opts.create, !opts.detach)?;
    // The foreground relay needs the master before init blocks on anything
    // that writes to the terminal; it was sent before `Ready`.
    let mut relay = match c.console.take() {
        Some(sock) => Some(Relay::new(console::receive_master(sock.as_fd())?)?),
        None => None,
    };
    create::release(&c.dir, &c.pidfd)?;
    // Started: other commands (state, kill, pause) may act on it now.
    drop(c.lock.take());
    // execve's verdict: EOF (the CLOEXEC socket closed, the program runs) or
    // an error message.
    if let Some(msg) = c.sync.recv()? {
        return Err(msg.into_error());
    }
    tracing::debug!(pid = c.state.pid, "container process is running");
    if opts.detach {
        c.keep();
        return Ok(0);
    }

    let status = supervise(&c.pidfd, &c.sfd, relay.as_mut(), c.terminal)?;
    // Restore the terminal before anything else is printed.
    drop(relay);
    teardown(&mut c)?;
    Ok(status)
}

/// Forwards signals, pumps the terminal, and waits for the process behind
/// `pidfd` (init, or an `exec`'d process) to exit.
pub(crate) fn supervise(pidfd: &OwnedFd, sfd: &SignalFd, mut relay: Option<&mut Relay>, own_tty: bool) -> Result<i32> {
    let mut relay_open = relay.is_some();
    loop {
        let relay_fds: Vec<_> = match (&relay, relay_open) {
            (Some(r), true) => r.fds(),
            _ => Vec::new(),
        };
        let mut fds = vec![PollFd::new(sfd.as_fd(), PollFlags::POLLIN), PollFd::new(pidfd.as_fd(), PollFlags::POLLIN)];
        fds.extend(relay_fds.iter().map(|fd| PollFd::new(*fd, PollFlags::POLLIN)));
        // The relay asks for an immediate retry while it holds input the
        // PTY couldn't take yet.
        let timeout = match (&relay, relay_open) {
            (Some(r), true) => r.poll_timeout(),
            _ => PollTimeout::NONE,
        };
        match poll(&mut fds, timeout) {
            Ok(_) | Err(Errno::EINTR) => {}
            Err(e) => return Err(e).context("poll"),
        }
        let revents: Vec<PollFlags> = fds.iter().map(|f| f.revents().unwrap_or(PollFlags::empty())).collect();
        drop(fds);
        drop(relay_fds);

        if revents[0].contains(PollFlags::POLLIN) {
            while let Some(info) = sfd.read_signal().context("read signalfd")? {
                let Ok(sig) = Signal::try_from(info.ssi_signo as i32) else { continue };
                match (&relay, sig) {
                    (Some(r), Signal::SIGWINCH) => r.resize()?,
                    _ => forward(pidfd, sig, info.ssi_code, own_tty),
                }
            }
        }
        if relay_open && let Some(r) = relay.as_mut() {
            relay_open = r.pump(&revents[2..])?;
        }
        // A pidfd becomes readable when its process exits.
        if !revents[1].is_empty() {
            match process::waitid(WaitTarget::PidFd(pidfd.as_fd()), true).context("waitid")? {
                WaitResult::StillAlive => continue,
                done => {
                    tracing::debug!(?done, "container exited");
                    if let Some(r) = relay.as_mut() {
                        // Whatever init printed last may still sit in the PTY.
                        r.drain()?;
                    }
                    return Ok(done.exit_code().unwrap_or(1));
                }
            }
        }
    }
}

fn forward(pidfd: &OwnedFd, sig: Signal, code: i32, own_tty: bool) {
    let from_shared_tty = !own_tty
        && code == rustlet_sys::signal::SI_KERNEL
        && matches!(sig, Signal::SIGINT | Signal::SIGQUIT | Signal::SIGWINCH | Signal::SIGHUP);
    if sig == Signal::SIGCHLD || from_shared_tty || (own_tty && sig == Signal::SIGWINCH) {
        return;
    }
    tracing::debug!(?sig, "forwarding signal to container");
    match process::pidfd_send_signal(pidfd.as_fd(), sig) {
        Ok(()) | Err(Errno::ESRCH) => {}
        Err(e) => tracing::warn!(?sig, %e, "could not forward signal"),
    }
}

/// After a foreground container's init exited: kill whatever is left (with
/// `--pid=host` there can be orphans), report an OOM kill, remove the cgroup
/// and the state directory.
fn teardown(c: &mut Spawned) -> Result<()> {
    if let Some(cg) = &c.cgroup {
        report_oom(cg);
    }
    if !c.dir.exists() {
        // Someone ran `delete --force` while we were supervising: nothing
        // is left to clean up, and the exit status still stands.
        c.keep();
        return Ok(());
    }
    let _lock = c.dir.lock()?;
    if let Some(cg) = &c.cgroup {
        cg.remove_tree(create::TEARDOWN_TIMEOUT)?;
    }
    c.dir.remove()?;
    c.keep();
    Ok(())
}

/// The OOM killer leaves no trace in the exit status (it's just SIGKILL),
/// only in the cgroup's `memory.events`.
fn report_oom(cg: &Cgroup) {
    match cg.memory_events() {
        Ok(ev) if ev.oom_kill > 0 => {
            let limit = cg.read("memory.max").unwrap_or_else(|_| "?".into());
            eprintln!(
                "rustlet-runc: warning: the OOM killer killed {} process(es) in the container (memory.max = {limit})",
                ev.oom_kill
            );
        }
        Ok(_) => {}
        Err(e) => tracing::debug!(%e, "could not read memory.events"),
    }
}

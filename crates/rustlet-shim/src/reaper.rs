//! Reaping every child, and telling whoever asked how each one ended.
//!
//! The shim is a *child subreaper* (`PR_SET_CHILD_SUBREAPER`): when a
//! process below it loses its parent, the kernel re-parents it to the shim
//! instead of PID 1. So the shim's children are the `rustlet-runc`
//! processes it starts, and, once each of those has exited, what they
//! left behind: container init (made by `create`) and every process `exec
//! -d` started. A process inside the container that forks and exits leaves
//! its children to the container's own init, not to the shim: re-parenting
//! looks for a subreaper only in the dying parent's PID namespace.
//!
//! One loop collects them all: on `SIGCHLD`, `waitid(P_ALL, WNOHANG)` until
//! nothing is left. That is why the shim never uses `tokio::process` or
//! `Child::wait`: whichever reaps first gets the status, and the other
//! would wait forever.
//!
//! A status nobody asked for yet is kept ([`Reaper::watch`] finds it). The
//! shim runs on one thread, so calling `watch` right after spawning, with no
//! `.await` in between, can't miss anything: the loop only runs when the
//! caller yields.

use std::cell::RefCell;
use std::collections::HashMap;
use std::io;
use std::rc::Rc;

use rustlet_sys::process::{WaitResult, WaitTarget, waitid};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::oneshot;

/// How many statuses of processes nobody watches are kept at most.
const MAX_UNCLAIMED: usize = 1024;

pub struct Reaper {
    inner: RefCell<Inner>,
}

#[derive(Default)]
struct Inner {
    waiters: HashMap<i32, oneshot::Sender<WaitResult>>,
    unclaimed: HashMap<i32, WaitResult>,
}

impl Reaper {
    /// Installs the `SIGCHLD` handler and starts the loop (on the current
    /// `LocalSet`). Call it before spawning anything.
    pub fn start() -> io::Result<Rc<Reaper>> {
        let mut sigchld = signal(SignalKind::child())?;
        let reaper = Rc::new(Reaper { inner: RefCell::new(Inner::default()) });
        let r = reaper.clone();
        tokio::task::spawn_local(async move {
            loop {
                r.reap();
                if sigchld.recv().await.is_none() {
                    break;
                }
            }
        });
        Ok(reaper)
    }

    /// The exit status of `pid`, a child (or soon-to-be child) of the shim.
    /// Call it before the next `.await` after spawning `pid`.
    pub fn watch(&self, pid: i32) -> oneshot::Receiver<WaitResult> {
        let (tx, rx) = oneshot::channel();
        let mut inner = self.inner.borrow_mut();
        match inner.unclaimed.remove(&pid) {
            Some(status) => {
                let _ = tx.send(status);
            }
            None => {
                inner.waiters.insert(pid, tx);
            }
        }
        rx
    }

    /// Collects every child that has exited.
    fn reap(&self) {
        loop {
            match waitid(WaitTarget::Any, true) {
                Ok(WaitResult::StillAlive) => return,
                Ok(status) => {
                    let pid = status.pid().expect("an exited child has a pid").as_raw();
                    let mut inner = self.inner.borrow_mut();
                    match inner.waiters.remove(&pid) {
                        Some(tx) => {
                            let _ = tx.send(status);
                        }
                        None => {
                            tracing::debug!(pid, ?status, "reaped a process nobody waits for (yet)");
                            if inner.unclaimed.len() >= MAX_UNCLAIMED {
                                inner.unclaimed.clear();
                            }
                            inner.unclaimed.insert(pid, status);
                        }
                    }
                }
                // ECHILD: no children at all.
                Err(_) => return,
            }
        }
    }
}

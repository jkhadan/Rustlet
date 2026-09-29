//! The sync channel between `rustlet-runc` and container init.
//!
//! A `socketpair(AF_UNIX, SOCK_SEQPACKET)`: like a pipe, but bidirectional
//! and message-oriented (every `send` arrives as exactly one `recv`), and
//! the kernel reports the peer's disappearance as a zero-length read.
//!
//! The conversation, from container init's side:
//!
//! ```text
//!   ◄── Proceed               the parent has finished its part: the user
//!                             namespace's maps, idmapped mounts, rlimits
//!                             and oom_score_adj (see `create`)
//!   setup (mounts, pivot_root, tty, identity, $PATH lookup) …
//!   ──► Ready                 "created": now blocking on exec.fifo
//!   … `start` opens exec.fifo, init writes one byte, then execve …
//!   ──► EOF                   the channel's fd is O_CLOEXEC, so a
//!                             successful execve closes it
//!   ──► Error{…}              instead, at any point where init fails
//! ```
//!
//! The EOF trick is how the parent learns about success without the user's
//! program having to say anything. For `create`, the parent only waits for
//! `Ready` and exits; a later exec failure goes to the container's stderr.

// nix's send/recv still take raw fds.
use std::os::fd::{AsRawFd, OwnedFd};

use nix::sys::socket::{AddressFamily, MsgFlags, SockFlag, SockType, recv, send, socketpair};
use rustlet_sys::Errno;
use serde::{Deserialize, Serialize};

use crate::error::{Context, Error, Result};

/// Messages between `rustlet-runc` and container init.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum SyncMsg {
    /// Parent → init, the only message in that direction: go ahead with the
    /// setup.
    Proceed,
    /// Init is fully set up and about to block on `exec.fifo`.
    Ready,
    /// Init failed before (or at) `execve`. `exec` says whether it was the
    /// final `execve` of the user's program that failed.
    Error {
        message: String,
        errno: Option<i32>,
        #[serde(default)]
        exec: bool,
    },
}

impl SyncMsg {
    pub(crate) fn from_error(e: &Error) -> SyncMsg {
        let message = match e {
            // Don't nest "container init failed: container init failed: …".
            Error::Init { message, .. } | Error::Exec { message, .. } => message.clone(),
            other => other.to_string(),
        };
        SyncMsg::Error { message, errno: e.errno().map(|e| e as i32), exec: matches!(e, Error::Exec { .. }) }
    }

    /// Turns a received message into an [`Error`] (`Ready` where an error
    /// was expected is a protocol violation).
    pub(crate) fn into_error(self) -> Error {
        match self {
            SyncMsg::Error { message, errno, exec: true } if errno.is_some() => {
                Error::Exec { message, errno: Errno::from_raw(errno.unwrap_or(libc::EIO)) }
            }
            SyncMsg::Error { message, errno, .. } => Error::Init { message, errno },
            SyncMsg::Ready | SyncMsg::Proceed => {
                Error::Init { message: format!("unexpected {self:?} from container init"), errno: None }
            }
        }
    }
}

/// One end of the channel.
#[derive(Debug)]
pub(crate) struct SyncSocket(OwnedFd);

impl std::os::fd::AsFd for SyncSocket {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.0.as_fd()
    }
}

/// Creates a connected pair: `(parent end, child end)`.
pub(crate) fn pair() -> Result<(SyncSocket, SyncSocket)> {
    let (a, b) = socketpair(AddressFamily::Unix, SockType::SeqPacket, None, SockFlag::SOCK_CLOEXEC)
        .context("socketpair(SOCK_SEQPACKET)")?;
    Ok((SyncSocket(a), SyncSocket(b)))
}

impl SyncSocket {
    /// Init side: waits for the parent's [`SyncMsg::Proceed`].
    pub(crate) fn wait_proceed(&self) -> Result<()> {
        match self.recv()? {
            Some(SyncMsg::Proceed) => Ok(()),
            None => Err(Error::Init { message: "rustlet-runc went away during create".into(), errno: None }),
            Some(other) => Err(Error::Init { message: format!("unexpected {other:?} from rustlet-runc"), errno: None }),
        }
    }

    /// Sends one message. `MSG_NOSIGNAL`: if the parent is gone we want
    /// `EPIPE`, not a SIGPIPE that kills init with a confusing status.
    pub(crate) fn send(&self, msg: &SyncMsg) -> Result<()> {
        let bytes = serde_json::to_vec(msg).expect("SyncMsg always serializes");
        loop {
            match send(self.0.as_raw_fd(), &bytes, MsgFlags::MSG_NOSIGNAL) {
                Ok(_) => return Ok(()),
                Err(Errno::EINTR) => continue,
                Err(e) => return Err(e).context("send sync message"),
            }
        }
    }

    /// Receives one message, or `None` once the peer's end is closed.
    pub(crate) fn recv(&self) -> Result<Option<SyncMsg>> {
        let mut buf = vec![0u8; 64 * 1024];
        let n = loop {
            match recv(self.0.as_raw_fd(), &mut buf, MsgFlags::empty()) {
                Ok(n) => break n,
                Err(Errno::EINTR) => continue,
                Err(e) => return Err(e).context("receive sync message"),
            }
        };
        if n == 0 {
            return Ok(None);
        }
        serde_json::from_slice(&buf[..n])
            .map(Some)
            .map_err(|e| Error::Init { message: format!("garbled sync message: {e}"), errno: None })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_then_eof() {
        let (parent, child) = pair().unwrap();
        child.send(&SyncMsg::Error { message: "boom".into(), errno: Some(1), exec: false }).unwrap();
        drop(child);
        assert_eq!(
            parent.recv().unwrap(),
            Some(SyncMsg::Error { message: "boom".into(), errno: Some(1), exec: false })
        );
        assert_eq!(parent.recv().unwrap(), None);
    }

    #[test]
    fn exec_failures_survive_the_round_trip() {
        let e = Error::Exec { message: "not found".into(), errno: Errno::ENOENT };
        assert!(matches!(SyncMsg::from_error(&e).into_error(), Error::Exec { errno: Errno::ENOENT, .. }));
        // An ENOENT from anywhere else stays an Init error.
        let e = Error::Sys { context: "mount bind /nope on /data".into(), errno: Errno::ENOENT };
        let back = SyncMsg::from_error(&e).into_error();
        assert!(matches!(back, Error::Init { errno: Some(2), .. }), "{back:?}");
        assert!(back.to_string().starts_with("container init failed: mount bind /nope"), "{back}");
    }
}

//! Passing file descriptors over Unix sockets (`SCM_RIGHTS`).
//!
//! This is how a PTY master created *inside* the container reaches the shim
//! (the OCI "console socket" protocol): the fd itself travels in the
//! ancillary data of a `sendmsg`, and the receiver gets a new fd number that
//! refers to the same open file.

use std::io::{IoSlice, IoSliceMut};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};

use nix::sys::socket::{ControlMessage, ControlMessageOwned, MsgFlags, recvmsg, sendmsg};

use crate::{Errno, Result};

/// Sends `data` plus `fds` in one message. `MSG_NOSIGNAL`: if the peer is
/// gone this returns `EPIPE` instead of raising SIGPIPE (container init has
/// reset SIGPIPE to its default action, which would kill it).
pub fn send_fds(sock: BorrowedFd<'_>, data: &[u8], fds: &[BorrowedFd<'_>]) -> Result<usize> {
    let raw: Vec<RawFd> = fds.iter().map(AsRawFd::as_raw_fd).collect();
    let iov = [IoSlice::new(data)];
    let cmsg = [ControlMessage::ScmRights(&raw)];
    let cmsgs: &[ControlMessage<'_>] = if raw.is_empty() { &[] } else { &cmsg };
    sendmsg::<()>(sock.as_raw_fd(), &iov, cmsgs, MsgFlags::MSG_NOSIGNAL, None)
}

/// Receives one message and up to `max_fds` descriptors. Returns the number
/// of data bytes and the received fds (always close-on-exec).
pub fn recv_fds(sock: BorrowedFd<'_>, buf: &mut [u8], max_fds: usize) -> Result<(usize, Vec<OwnedFd>)> {
    let mut space = nix::cmsg_space!([RawFd; 8]);
    if max_fds > 8 {
        return Err(Errno::EINVAL);
    }
    let mut iov = [IoSliceMut::new(buf)];
    let msg = recvmsg::<()>(sock.as_raw_fd(), &mut iov, Some(&mut space), MsgFlags::MSG_CMSG_CLOEXEC)?;
    let mut fds = Vec::new();
    for c in msg.cmsgs()? {
        if let ControlMessageOwned::ScmRights(list) = c {
            for fd in list {
                // SAFETY: the kernel installed these descriptors in our
                // table for this message; nothing else owns them yet.
                fds.push(unsafe { OwnedFd::from_raw_fd(fd) });
            }
        }
    }
    let n = msg.bytes;
    if fds.len() > max_fds {
        fds.truncate(max_fds);
    }
    Ok((n, fds))
}

/// Peer credentials of a connected Unix socket (`SO_PEERCRED`).
pub fn peer_credentials(sock: BorrowedFd<'_>) -> Result<(libc::pid_t, libc::uid_t, libc::gid_t)> {
    let c = nix::sys::socket::getsockopt(&sock, nix::sys::socket::sockopt::PeerCredentials)?;
    Ok((c.pid(), c.uid(), c.gid()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::sys::socket::{AddressFamily, SockFlag, SockType, socketpair};
    use std::io::{Read, Seek, Write};
    use std::os::fd::AsFd;

    #[test]
    fn fd_round_trip() {
        let (a, b) = socketpair(AddressFamily::Unix, SockType::Stream, None, SockFlag::SOCK_CLOEXEC).unwrap();
        let mut f = tempfile::tempfile().unwrap();
        f.write_all(b"passed").unwrap();
        send_fds(a.as_fd(), b"x", &[f.as_fd()]).unwrap();
        let mut buf = [0u8; 4];
        let (n, fds) = recv_fds(b.as_fd(), &mut buf, 1).unwrap();
        assert_eq!(n, 1);
        let mut g = std::fs::File::from(fds.into_iter().next().unwrap());
        g.rewind().unwrap();
        let mut s = String::new();
        g.read_to_string(&mut s).unwrap();
        assert_eq!(s, "passed");
    }
}

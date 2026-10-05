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
    let (n, received) = {
        let msg = recvmsg::<()>(sock.as_raw_fd(), &mut iov, Some(&mut space), MsgFlags::MSG_CMSG_CLOEXEC)?;
        let received = msg.cmsgs().map(|messages| {
            let mut fds = Vec::new();
            for c in messages {
                if let ControlMessageOwned::ScmRights(list) = c {
                    for fd in list {
                        // SAFETY: the kernel installed these descriptors in our
                        // table for this message; nothing else owns them yet.
                        fds.push(unsafe { OwnedFd::from_raw_fd(fd) });
                    }
                }
            }
            fds
        });
        (msg.bytes, received)
    };
    let mut fds = match received {
        Ok(fds) => fds,
        Err(e) => {
            // nix refuses to iterate a truncated control buffer, but Linux
            // already installed the SCM_RIGHTS descriptors that fit in it.
            // Close those before propagating the truncation error.
            close_truncated_rights(&space);
            return Err(e);
        }
    };
    if fds.len() > max_fds {
        fds.truncate(max_fds);
    }
    Ok((n, fds))
}

/// Discards descriptors from the complete portions of a Linux control
/// buffer. The kernel shortens a truncated SCM_RIGHTS record's `cmsg_len`
/// to include only the installed whole descriptor values. Unused bytes in
/// our zero-initialized buffer have a zero length and end the walk.
fn close_truncated_rights(mut control: &[u8]) {
    let header_len = std::mem::size_of::<libc::cmsghdr>();
    let alignment = std::mem::size_of::<usize>();
    while control.len() >= header_len {
        let length = usize::from_ne_bytes(control[..alignment].try_into().expect("a complete control header"));
        if length < header_len || length > control.len() {
            break;
        }
        let field = |offset| i32::from_ne_bytes(control[offset..offset + 4].try_into().expect("a complete field"));
        let level = field(std::mem::offset_of!(libc::cmsghdr, cmsg_level));
        let kind = field(std::mem::offset_of!(libc::cmsghdr, cmsg_type));
        if level == libc::SOL_SOCKET && kind == libc::SCM_RIGHTS {
            for bytes in control[header_len..length].as_chunks::<{ std::mem::size_of::<RawFd>() }>().0 {
                let fd = RawFd::from_ne_bytes(*bytes);
                // SAFETY: these complete SCM_RIGHTS values were written by
                // recvmsg and refer to descriptors the kernel installed.
                // nix returned before decoding any of them, so none has an
                // owner yet; dropping the new owner closes each one once.
                drop(unsafe { OwnedFd::from_raw_fd(fd) });
            }
        }
        let Some(next) = length.checked_add(alignment - 1).map(|n| n & !(alignment - 1)) else { break };
        let Some(rest) = control.get(next..) else { break };
        control = rest;
    }
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
    use std::os::unix::fs::MetadataExt;

    #[test]
    fn truncated_rights_do_not_leak_received_descriptors() {
        let (a, b) = socketpair(AddressFamily::Unix, SockType::Stream, None, SockFlag::SOCK_CLOEXEC).unwrap();
        let file = tempfile::tempfile().unwrap();
        let identity = file.metadata().unwrap();
        let copies = || {
            std::fs::read_dir("/proc/self/fd")
                .unwrap()
                .filter_map(|entry| std::fs::metadata(entry.ok()?.path()).ok())
                .filter(|meta| meta.dev() == identity.dev() && meta.ino() == identity.ino())
                .count()
        };
        let before = copies();
        let descriptors = vec![file.as_fd(); 9];
        send_fds(a.as_fd(), b"x", &descriptors).unwrap();
        let mut buf = [0u8; 1];
        assert_eq!(recv_fds(b.as_fd(), &mut buf, 1).unwrap_err(), Errno::ENOBUFS);
        assert_eq!(copies(), before, "truncated SCM_RIGHTS leaked descriptors for the sent file");
    }

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

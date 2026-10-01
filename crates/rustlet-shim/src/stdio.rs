//! A process's stdio, as the shim holds it: three pipes, or the master of
//! the terminal the container made for itself.
//!
//! **Pipes.** The process's ends become `rustlet-runc`'s stdin/stdout/stderr
//! (the runtime passes its own on to the process); the shim keeps the other
//! ends. Each pipe is chowned to the process's user *as the host sees it*:
//! a pipe made by the shim belongs to host root, and a process that reopens
//! its stdio (`/dev/stderr` is `/proc/self/fd/2`, and nginx logs there)
//! needs to own it, or be a root that is root on the host too. In a user
//! namespace, container uid 101 is host uid 1000101. (containerd's shim does
//! the same for user namespaces, `IoUID`/`IoGID`.)
//!
//! **Terminal.** Init creates the PTY inside the container and sends the
//! master over the *console socket*, a Unix socket the shim listens on, with
//! `SCM_RIGHTS` (the OCI protocol). Only the shim holds the master: the
//! container's output is read from it, input written to it, and the window
//! size set on it.

use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::Path;
use std::process::Stdio;

use nix::fcntl::{FcntlArg, OFlag, fcntl};
use nix::unistd::{Gid, Uid};
use rustlet_runtime::oci_spec::runtime::{LinuxNamespaceType, Spec};
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
use tokio::net::UnixListener;

use crate::runc::Stdio3;

/// A non-blocking fd driven by tokio: a pipe end or a PTY master.
pub struct FdIo(AsyncFd<OwnedFd>);

impl FdIo {
    pub fn new(fd: OwnedFd) -> io::Result<FdIo> {
        let flags = fcntl(&fd, FcntlArg::F_GETFL)?;
        fcntl(&fd, FcntlArg::F_SETFL(OFlag::from_bits_truncate(flags) | OFlag::O_NONBLOCK))?;
        Ok(FdIo(AsyncFd::new(fd)?))
    }

    pub fn fd(&self) -> BorrowedFd<'_> {
        self.0.get_ref().as_fd()
    }

    /// Reads what is there; 0 at the end. For a PTY master, the end is
    /// `EIO`: every slave fd has been closed.
    pub async fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut ready = self.0.readable().await?;
            match ready.try_io(|fd| nix::unistd::read(fd, buf).map_err(io::Error::from)) {
                Ok(Ok(n)) => return Ok(n),
                Ok(Err(e)) if e.raw_os_error() == Some(libc::EIO) => return Ok(0),
                Ok(Err(e)) => return Err(e),
                Err(_would_block) => continue,
            }
        }
    }

    pub async fn write_all(&self, mut data: &[u8]) -> io::Result<()> {
        while !data.is_empty() {
            let mut ready = self.0.writable().await?;
            match ready.try_io(|fd| nix::unistd::write(fd, data).map_err(io::Error::from)) {
                Ok(Ok(n)) => data = &data[n..],
                Ok(Err(e)) => return Err(e),
                Err(_would_block) => continue,
            }
        }
        Ok(())
    }
}

/// The shim's ends of a process's pipes.
pub struct PipeEnds {
    /// `None` without `--stdin` (the process gets /dev/null).
    pub stdin: Option<FdIo>,
    pub stdout: FdIo,
    pub stderr: FdIo,
}

/// The process's ends of its pipes; [`ChildEnds::into_stdio`] hands them to
/// `rustlet-runc`.
pub struct ChildEnds {
    pub stdin: Option<OwnedFd>,
    pub stdout: OwnedFd,
    pub stderr: OwnedFd,
}

impl ChildEnds {
    pub fn into_stdio(self) -> Stdio3 {
        Stdio3 {
            stdin: self.stdin.map_or_else(Stdio::null, Stdio::from),
            stdout: Stdio::from(self.stdout),
            stderr: Stdio::from(self.stderr),
        }
    }
}

/// Three pipes (two without `stdin`); the process's ends belong to
/// `owner` (host uid and gid).
pub fn pipes(stdin: bool, owner: (u32, u32)) -> io::Result<(ChildEnds, PipeEnds)> {
    let pipe = || nix::unistd::pipe2(OFlag::O_CLOEXEC).map_err(io::Error::from);
    let (out_r, out_w) = pipe()?;
    let (err_r, err_w) = pipe()?;
    let (in_r, in_w) = if stdin { pipe().map(|(r, w)| (Some(r), Some(w)))? } else { (None, None) };
    // A pipe is one inode: chowning either end chowns both.
    let chown = |fd: &OwnedFd| {
        nix::unistd::fchown(fd, Some(Uid::from_raw(owner.0)), Some(Gid::from_raw(owner.1))).map_err(io::Error::from)
    };
    chown(&out_w)?;
    chown(&err_w)?;
    if let Some(r) = &in_r {
        chown(r)?;
    }
    let child = ChildEnds { stdin: in_r, stdout: out_w, stderr: err_w };
    let ours =
        PipeEnds { stdin: in_w.map(FdIo::new).transpose()?, stdout: FdIo::new(out_r)?, stderr: FdIo::new(err_r)? };
    Ok((child, ours))
}

/// Where the PTY master arrives (`--console-socket`).
pub struct ConsoleSocket {
    listener: UnixListener,
    path: std::path::PathBuf,
}

impl ConsoleSocket {
    pub fn bind(path: &Path) -> io::Result<ConsoleSocket> {
        let _ = std::fs::remove_file(path);
        Ok(ConsoleSocket { listener: UnixListener::bind(path)?, path: path.to_owned() })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Accepts the runtime's connection and receives the master. The
    /// sender decides what it sends, so it must turn out to be a PTY master.
    pub async fn receive_master(&self) -> io::Result<OwnedFd> {
        let (stream, _) = self.listener.accept().await?;
        loop {
            stream.readable().await?;
            let mut buf = [0u8; 64];
            let got = stream.try_io(Interest::READABLE, || {
                rustlet_sys::socket::recv_fds(stream.as_fd(), &mut buf, 1).map_err(io::Error::from)
            });
            match got {
                Ok((n, fds)) => {
                    let Some(master) = fds.into_iter().next() else {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            if n == 0 {
                                "the console socket closed before the terminal arrived"
                            } else {
                                "the console socket message carried no file descriptor"
                            },
                        ));
                    };
                    // TIOCGPTN works on a master only (a slave passes isatty).
                    if !rustlet_sys::term::isatty(master.as_fd())
                        || rustlet_sys::term::pty_number(master.as_fd()).is_err()
                    {
                        return Err(io::Error::other("the console socket sent something that is not a PTY master"));
                    }
                    return Ok(master);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            }
        }
    }
}

impl Drop for ConsoleSocket {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// The host uid and gid of container user `uid`:`gid` under `spec`'s user
/// namespace (the same ids without one). Ids the maps don't cover stay as
/// they are; the runtime refuses such a process anyway.
pub fn host_ids(spec: &Spec, uid: u32, gid: u32) -> (u32, u32) {
    let Some(linux) = spec.linux() else { return (uid, gid) };
    let new_userns = linux
        .namespaces()
        .as_deref()
        .unwrap_or_default()
        .iter()
        .any(|ns| ns.typ() == LinuxNamespaceType::User && ns.path().is_none());
    if !new_userns {
        return (uid, gid);
    }
    let map = |maps: Option<&[rustlet_runtime::oci_spec::runtime::LinuxIdMapping]>, id: u32| {
        maps.unwrap_or_default()
            .iter()
            .find(|m| id >= m.container_id() && id - m.container_id() < m.size())
            .map_or(id, |m| m.host_id() + (id - m.container_id()))
    };
    (map(linux.uid_mappings().as_deref(), uid), map(linux.gid_mappings().as_deref(), gid))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustlet_runtime::spec::{default_spec, with_user_namespace};

    #[test]
    fn host_ids_follow_the_user_namespace() {
        let mut spec = default_spec();
        assert_eq!(host_ids(&spec, 101, 101), (101, 101));
        with_user_namespace(&mut spec, 1_000_000, 65_536);
        assert_eq!(host_ids(&spec, 0, 0), (1_000_000, 1_000_000));
        assert_eq!(host_ids(&spec, 101, 102), (1_000_101, 1_000_102));
        // Unmapped: unchanged.
        assert_eq!(host_ids(&spec, 70_000, 70_000), (70_000, 70_000));
    }

    #[tokio::test]
    async fn pipes_carry_data_and_end() {
        use std::io::{Read, Write};
        let me = (nix::unistd::geteuid().as_raw(), nix::unistd::getegid().as_raw());
        let (child, ours) = pipes(true, me).unwrap();
        let mut stdout = std::fs::File::from(child.stdout);
        stdout.write_all(b"out").unwrap();
        drop(stdout);
        let mut buf = [0u8; 16];
        assert_eq!(ours.stdout.read(&mut buf).await.unwrap(), 3);
        assert_eq!(&buf[..3], b"out");
        // Its write end is gone: the next read is the end.
        assert_eq!(ours.stdout.read(&mut buf).await.unwrap(), 0);
        ours.stdin.as_ref().unwrap().write_all(b"input").await.unwrap();
        let mut got = [0u8; 5];
        std::fs::File::from(child.stdin.unwrap()).read_exact(&mut got).unwrap();
        assert_eq!(&got, b"input");
    }
}

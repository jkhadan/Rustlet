//! Foreground stdio for a process in a user namespace, without a terminal.
//!
//! Without a terminal, a foreground container (or `exec`'d process) just
//! inherits `rustlet-runc`'s stdin, stdout and stderr. In a user namespace
//! that is not quite enough: the fds work, but they can't be *reopened*.
//! `/dev/stderr` is a symlink to `/proc/self/fd/2`, and opening it opens the
//! pipe or file behind fd 2 afresh, permission check included. A pipe that
//! our caller made belongs to host root, whom the container's user
//! namespace doesn't map, so to the container it is somebody else's `0600`
//! file: `EACCES`. Images do reopen their stdio: nginx logs to
//! `/var/log/nginx/error.log -> /dev/stderr`, shell scripts write
//! `>/dev/stderr`.
//!
//! So, like runc (`setupProcessPipes`), `rustlet-runc` gives such a process
//! three pipes of its own and relays between them and its own stdio
//! ([`PipeRelay`]). The pipes are chowned to the process's user as the host
//! sees it (container uid 101 is host 1000101): that user may reopen them,
//! and so may container root, whose capabilities cover every mapped owner.
//! (runc chowns to container root, which leaves a non-root process with
//! `EACCES`.) A *detached* container's stdio is its caller's business: the
//! shim (Phase 4) hands `create` pipes it chowned the same way, as
//! containerd's shim does.
//!
//! The relay never waits on the container: input is written non-blocking,
//! and while the container isn't reading, its output keeps moving (a
//! container blocked writing to a full stdout would otherwise never get back
//! to reading its stdin, and neither side would move again).

use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::time::{Duration, Instant};

use nix::fcntl::{FcntlArg, OFlag, fcntl};
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::unistd::{Gid, Uid};
use rustlet_sys::Errno;

use crate::error::{Context, Result};

/// Bytes moved per read.
const CHUNK: usize = 64 * 1024;
/// How long one `pump` waits at most for the container to take input.
const WRITE_BUDGET: Duration = Duration::from_millis(50);
/// What `drain` copies at most once the process has exited (a leftover
/// process may keep writing).
const DRAIN_LIMIT: usize = 4 << 20;

/// The process's ends of its three pipes, for [`ContainerStdio::install`].
pub(crate) struct ContainerStdio {
    stdin: OwnedFd,
    stdout: OwnedFd,
    stderr: OwnedFd,
}

impl ContainerStdio {
    /// In the child, before anything else: makes the pipes fds 0, 1 and 2.
    /// (`dup2` clears close-on-exec on the copies; the originals keep it.)
    pub(crate) fn install(self) -> Result<()> {
        for (fd, stdio) in [(&self.stdin, 0), (&self.stdout, 1), (&self.stderr, 2)] {
            rustlet_sys::term::dup2_stdio(fd.as_fd(), stdio)
                .with_context(|| format!("dup2 a stdio pipe onto fd {stdio}"))?;
        }
        Ok(())
    }
}

/// Three pipes owned by host `uid`/`gid`: the process's ends and our relay.
/// Call it before `clone3`; the child keeps [`ContainerStdio`] and drops the
/// relay, the parent the other way round.
pub(crate) fn pipes(uid: u32, gid: u32) -> Result<(ContainerStdio, PipeRelay)> {
    let pipe = || nix::unistd::pipe2(OFlag::O_CLOEXEC).context("pipe2 (stdio)");
    let (stdin_r, stdin_w) = pipe()?;
    let (stdout_r, stdout_w) = pipe()?;
    let (stderr_r, stderr_w) = pipe()?;
    // One inode per pipe, shared by both ends: chowning either end does.
    for fd in [&stdin_r, &stdout_w, &stderr_w] {
        nix::unistd::fchown(fd, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid)))
            .with_context(|| format!("chown a stdio pipe to {uid}:{gid}"))?;
    }
    for fd in [&stdin_w, &stdout_r, &stderr_r] {
        set_nonblocking(fd.as_fd()).context("make a stdio pipe non-blocking")?;
    }
    let dup = |f: BorrowedFd<'_>, what: &str| f.try_clone_to_owned().with_context(|| format!("dup {what}"));
    let relay = PipeRelay {
        input: Some(dup(std::io::stdin().as_fd(), "stdin")?),
        to_process: Some(stdin_w),
        from_stdout: Some(stdout_r),
        from_stderr: Some(stderr_r),
        stdout: dup(std::io::stdout().as_fd(), "stdout")?,
        stderr: dup(std::io::stderr().as_fd(), "stderr")?,
        pending: Vec::with_capacity(CHUNK),
        buf: vec![0; CHUNK],
    };
    Ok((ContainerStdio { stdin: stdin_r, stdout: stdout_w, stderr: stderr_w }, relay))
}

/// Relays our stdin to the process's stdin pipe, and its stdout and stderr
/// pipes to ours. Same protocol as the terminal relay (`console::Relay`):
/// poll [`fds`](Self::fds) for `POLLIN`, hand the results to
/// [`pump`](Self::pump) in the same order, and use
/// [`poll_timeout`](Self::poll_timeout).
pub struct PipeRelay {
    /// A dup of our stdin; `None` once it has ended.
    input: Option<OwnedFd>,
    /// The write end of the process's stdin (`O_NONBLOCK`). Closed once
    /// input has ended and been delivered: that is the process's EOF.
    to_process: Option<OwnedFd>,
    /// The read ends of its stdout and stderr (`O_NONBLOCK`); `None` at EOF.
    from_stdout: Option<OwnedFd>,
    from_stderr: Option<OwnedFd>,
    /// Dups of our stdout and stderr (blocking, like any writer's).
    stdout: OwnedFd,
    stderr: OwnedFd,
    /// Input read but not yet taken by the process. No new input is read
    /// until it is, so it never holds more than one chunk.
    pending: Vec<u8>,
    buf: Vec<u8>,
}

/// Which pipe a read is from.
#[derive(Clone, Copy)]
enum Out {
    Stdout,
    Stderr,
}

impl PipeRelay {
    /// The fds to poll for `POLLIN`, in the order [`pump`](Self::pump)
    /// expects: `[input, stdout, stderr]`, leaving out what has ended (and
    /// input while earlier input is still pending).
    pub fn fds(&self) -> Vec<BorrowedFd<'_>> {
        let input = if self.pending.is_empty() { self.input.as_ref() } else { None };
        [input, self.from_stdout.as_ref(), self.from_stderr.as_ref()].into_iter().flatten().map(AsFd::as_fd).collect()
    }

    /// None (wait for an event) normally, zero while input waits for the
    /// process to read: then `pump` must run anyway to push the rest (it
    /// waits on the pipe itself, at most `WRITE_BUDGET`, so this doesn't spin).
    pub fn poll_timeout(&self) -> PollTimeout {
        if self.pending.is_empty() { PollTimeout::NONE } else { PollTimeout::ZERO }
    }

    /// Moves whatever is ready. `Ok(false)` once the process has closed both
    /// its stdout and stderr.
    pub fn pump(&mut self, revents: &[PollFlags]) -> Result<bool> {
        let mut events = revents.iter().copied();
        let mut next =
            |present: bool| if present { events.next().unwrap_or(PollFlags::empty()) } else { PollFlags::empty() };
        let input_ev = next(self.pending.is_empty() && self.input.is_some());
        let out_ev = next(self.from_stdout.is_some());
        let err_ev = next(self.from_stderr.is_some());
        if (input_ev | out_ev | err_ev).contains(PollFlags::POLLNVAL) {
            return Err(Errno::EBADF).context("poll: a stdio relay fd is not open");
        }
        // Output first: it may be what the process is blocked on.
        if !out_ev.is_empty() {
            self.copy(Out::Stdout)?;
        }
        if !err_ev.is_empty() {
            self.copy(Out::Stderr)?;
        }
        if !input_ev.is_empty() {
            self.read_input(input_ev)?;
        }
        if !self.pending.is_empty() {
            self.flush_input()?;
        }
        if self.input.is_none() && self.pending.is_empty() {
            // Delivered everything: closing our end is the process's EOF.
            self.to_process = None;
        }
        Ok(self.from_stdout.is_some() || self.from_stderr.is_some())
    }

    /// After the process exited: copies what its pipes still hold, without
    /// waiting (a leftover process that still has them open may never
    /// close them), at most `DRAIN_LIMIT` bytes.
    pub fn drain(&mut self) -> Result<()> {
        let mut copied = 0;
        for which in [Out::Stdout, Out::Stderr] {
            while copied < DRAIN_LIMIT {
                match self.copy(which)? {
                    0 => break,
                    n => copied += n,
                }
            }
        }
        Ok(())
    }

    /// One chunk from a pipe to our stdout/stderr; the number of bytes moved
    /// (0 at EOF, or when nothing is there right now).
    fn copy(&mut self, which: Out) -> Result<usize> {
        let (from, to) = match which {
            Out::Stdout => (&mut self.from_stdout, &self.stdout),
            Out::Stderr => (&mut self.from_stderr, &self.stderr),
        };
        let Some(fd) = from.as_ref() else { return Ok(0) };
        match nix::unistd::read(fd, &mut self.buf) {
            Ok(0) => {
                *from = None;
                Ok(0)
            }
            Ok(n) => {
                write_all(to.as_fd(), &self.buf[..n])?;
                Ok(n)
            }
            Err(Errno::EAGAIN | Errno::EINTR) => Ok(0),
            Err(e) => Err(e).context("read the container's output"),
        }
    }

    /// One chunk of our input into `pending`, or the end of input.
    fn read_input(&mut self, ev: PollFlags) -> Result<()> {
        let Some(input) = self.input.as_ref() else { return Ok(()) };
        let ended = if ev.contains(PollFlags::POLLIN) {
            match nix::unistd::read(input, &mut self.buf) {
                Ok(0) => true,
                Ok(n) => {
                    self.pending.extend_from_slice(&self.buf[..n]);
                    false
                }
                Err(Errno::EAGAIN | Errno::EINTR) => false,
                // A terminal that hung up, or one we may no longer read.
                Err(Errno::EIO) => true,
                Err(e) => return Err(e).context("read input"),
            }
        } else {
            // POLLHUP/POLLERR without POLLIN: the writer is gone.
            true
        };
        if ended {
            self.input = None;
        }
        Ok(())
    }

    /// Writes `pending` into the process's stdin for at most `WRITE_BUDGET`,
    /// moving its output meanwhile; what doesn't fit stays for the next call.
    fn flush_input(&mut self) -> Result<()> {
        let deadline = Instant::now() + WRITE_BUDGET;
        while !self.pending.is_empty() {
            let Some(to) = self.to_process.as_ref() else {
                self.pending.clear();
                break;
            };
            match nix::unistd::write(to, &self.pending) {
                Ok(n) => {
                    self.pending.drain(..n);
                }
                Err(Errno::EINTR) => {}
                // The process closed its stdin: nobody will read the rest.
                // (SIGPIPE is ignored in this process, as std arranges.)
                Err(Errno::EPIPE) => {
                    self.pending.clear();
                    self.input = None;
                    self.to_process = None;
                }
                Err(Errno::EAGAIN) => {
                    let left = deadline.saturating_duration_since(Instant::now());
                    if left.is_zero() {
                        break;
                    }
                    // +1 ms: poll counts whole milliseconds.
                    let timeout = PollTimeout::try_from(left + Duration::from_millis(1)).unwrap_or(PollTimeout::MAX);
                    let mut pfds = vec![PollFd::new(to.as_fd(), PollFlags::POLLOUT)];
                    pfds.extend(self.from_stdout.as_ref().map(|f| PollFd::new(f.as_fd(), PollFlags::POLLIN)));
                    pfds.extend(self.from_stderr.as_ref().map(|f| PollFd::new(f.as_fd(), PollFlags::POLLIN)));
                    match poll(&mut pfds, timeout) {
                        Ok(_) | Err(Errno::EINTR) => {}
                        Err(e) => return Err(e).context("poll the container's stdin"),
                    }
                    drop(pfds);
                    // Keep its output moving: it may be blocked on it.
                    self.copy(Out::Stdout)?;
                    self.copy(Out::Stderr)?;
                }
                Err(e) => return Err(e).context("write to the container's stdin"),
            }
        }
        Ok(())
    }
}

/// Sets `O_NONBLOCK` on the open file behind `fd`.
fn set_nonblocking(fd: BorrowedFd<'_>) -> rustlet_sys::Result<()> {
    let flags = OFlag::from_bits_retain(fcntl(fd, FcntlArg::F_GETFL)?);
    fcntl(fd, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK)).map(drop)
}

fn write_all(fd: BorrowedFd<'_>, mut data: &[u8]) -> Result<()> {
    while !data.is_empty() {
        match nix::unistd::write(fd, data) {
            Ok(n) => data = &data[n..],
            Err(Errno::EINTR) => {}
            Err(e) => return Err(e).context("write the container's output"),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A relay over test pipes instead of our real stdio.
    fn relay() -> (PipeRelay, OwnedFd, OwnedFd, OwnedFd, ContainerStdio) {
        let (in_r, in_w) = nix::unistd::pipe2(OFlag::O_CLOEXEC).unwrap();
        let (out_r, out_w) = nix::unistd::pipe2(OFlag::O_CLOEXEC).unwrap();
        let (err_r, err_w) = nix::unistd::pipe2(OFlag::O_CLOEXEC).unwrap();
        let (child, mut relay) = pipes(nix::unistd::geteuid().as_raw(), nix::unistd::getegid().as_raw()).unwrap();
        relay.input = Some(in_r);
        relay.stdout = out_w;
        relay.stderr = err_w;
        (relay, in_w, out_r, err_r, child)
    }

    fn pump_until(relay: &mut PipeRelay, mut done: impl FnMut(&PipeRelay) -> bool) {
        for _ in 0..1000 {
            if done(relay) {
                return;
            }
            let fds = relay.fds();
            let mut pfds: Vec<PollFd<'_>> = fds.iter().map(|f| PollFd::new(*f, PollFlags::POLLIN)).collect();
            poll(&mut pfds, PollTimeout::from(20u8)).unwrap();
            let revents: Vec<PollFlags> = pfds.iter().map(|p| p.revents().unwrap_or(PollFlags::empty())).collect();
            drop(pfds);
            drop(fds);
            relay.pump(&revents).unwrap();
        }
        panic!("relay didn't get there");
    }

    #[test]
    fn moves_input_and_output_and_delivers_eof() {
        let (mut relay, in_w, out_r, err_r, child) = relay();
        nix::unistd::write(&in_w, b"hello").unwrap();
        drop(in_w);
        nix::unistd::write(&child.stdout, b"out").unwrap();
        nix::unistd::write(&child.stderr, b"err").unwrap();
        // Input reaches the process's stdin, then EOF (our end closed).
        pump_until(&mut relay, |r| r.to_process.is_none());
        let mut buf = [0u8; 16];
        let n = nix::unistd::read(&child.stdin, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello");
        assert_eq!(nix::unistd::read(&child.stdin, &mut buf).unwrap(), 0, "EOF after the input");
        // Output came across; closing the process's ends ends the relay.
        drop(child);
        pump_until(&mut relay, |r| r.from_stdout.is_none() && r.from_stderr.is_none());
        assert_eq!(nix::unistd::read(&out_r, &mut buf).unwrap(), 3);
        assert_eq!(&buf[..3], b"out");
        assert_eq!(nix::unistd::read(&err_r, &mut buf).unwrap(), 3);
        assert_eq!(&buf[..3], b"err");
    }

    #[test]
    fn a_process_that_does_not_read_cannot_stall_the_relay() {
        let (mut relay, in_w, out_r, _err_r, child) = relay();
        // More input than a pipe holds, which the process never reads.
        std::thread::spawn(move || {
            let chunk = vec![b'x'; 1 << 20];
            let _ = nix::unistd::write(&in_w, &chunk);
        });
        // Once its stdin pipe is full, input waits in `pending`…
        pump_until(&mut relay, |r| !r.pending.is_empty() && r.input.is_some());
        // …while the process writes output: the relay must keep that moving.
        nix::unistd::write(&child.stdout, b"still here").unwrap();
        let start = Instant::now();
        pump_until(&mut relay, |_| {
            let mut buf = [0u8; 32];
            let mut p = [PollFd::new(out_r.as_fd(), PollFlags::POLLIN)];
            poll(&mut p, PollTimeout::ZERO).unwrap();
            p[0].revents().is_some_and(|r| r.contains(PollFlags::POLLIN))
                && nix::unistd::read(&out_r, &mut buf).unwrap() == 10
        });
        assert!(start.elapsed() < Duration::from_secs(5));
        assert!(!relay.pending.is_empty(), "input waits for the process, it isn't dropped");
        drop(child);
    }

    #[test]
    fn pipes_belong_to_the_given_owner() {
        let (uid, gid) = (nix::unistd::geteuid().as_raw(), nix::unistd::getegid().as_raw());
        let (child, _relay) = pipes(uid, gid).unwrap();
        let st = rustlet_sys::fs::fstatx(child.stdout.as_fd()).unwrap();
        assert_eq!((st.uid, st.gid), (uid, gid));
        assert_eq!(st.file_type(), libc::S_IFIFO);
    }
}

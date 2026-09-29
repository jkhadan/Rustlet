//! Process creation and control: `clone3`, `fork`, pidfds, `waitid`, `setns`.
//!
//! ## Why `clone3` and not `fork` + `unshare`?
//!
//! `clone3(2)` creates the child directly inside new namespaces, places it in
//! a cgroup (`CLONE_INTO_CGROUP`) *before it runs a single instruction*, and
//! returns a pidfd (`CLONE_PIDFD`), a race-free handle to the child that
//! cannot be confused with a recycled PID.
//!
//! ## Why is a *safe* `fork`/`clone3` sound here?
//!
//! After `fork` in a multithreaded process only the calling thread exists in
//! the child. Any lock another thread held (malloc's, stdout's…) stays
//! locked forever, so the child may only call async-signal-safe functions.
//! That is why `nix::unistd::fork` is `unsafe`. Our wrappers **refuse to run
//! unless the caller is single-threaded**: a single-threaded process cannot
//! have locks held by other threads, and nothing can spawn a new thread while
//! we check, because we *are* the only thread. That runtime check lets us
//! expose these functions as safe. We also never pass `CLONE_VM`,
//! `CLONE_THREAD` or a custom stack, so the child always gets its own copy of
//! our address space, just as with `fork`.

use std::mem::size_of;
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd};

use bitflags::bitflags;
use nix::sys::signal::Signal;
use nix::unistd::Pid;

use crate::{Errno, Result, check, owned_fd};

bitflags! {
    /// Flags accepted by our `clone3`, `unshare` and `setns` wrappers.
    ///
    /// Only the namespace flags and a few safe extras are exposed. Flags that
    /// would share memory or threads with the child (`CLONE_VM`,
    /// `CLONE_THREAD`, …) are deliberately absent.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct CloneFlags: u64 {
        /// New mount namespace.
        const NEWNS = libc::CLONE_NEWNS as u64;
        /// New cgroup namespace.
        const NEWCGROUP = libc::CLONE_NEWCGROUP as u64;
        /// New UTS (hostname) namespace.
        const NEWUTS = libc::CLONE_NEWUTS as u64;
        /// New System V IPC / POSIX message-queue namespace.
        const NEWIPC = libc::CLONE_NEWIPC as u64;
        /// New user namespace.
        const NEWUSER = libc::CLONE_NEWUSER as u64;
        /// New PID namespace (affects *children*, see `unshare(2)`).
        const NEWPID = libc::CLONE_NEWPID as u64;
        /// New network namespace.
        const NEWNET = libc::CLONE_NEWNET as u64;
        /// New time namespace (Linux 5.6). Works with clone3, unshare and
        /// setns, but not with the legacy clone(), where 0x80 overlaps CSIGNAL.
        const NEWTIME = 0x0000_0080;
        /// Return a pidfd for the child (clone3 only).
        const PIDFD = libc::CLONE_PIDFD as u64;
        /// Start the child in the cgroup given by `Clone3::cgroup` (5.7).
        const INTO_CGROUP = 0x2_0000_0000;
    }
}

impl CloneFlags {
    /// Only the `CLONE_NEW*` bits.
    pub const ALL_NAMESPACES: CloneFlags = CloneFlags::NEWNS
        .union(CloneFlags::NEWCGROUP)
        .union(CloneFlags::NEWUTS)
        .union(CloneFlags::NEWIPC)
        .union(CloneFlags::NEWUSER)
        .union(CloneFlags::NEWPID)
        .union(CloneFlags::NEWNET)
        .union(CloneFlags::NEWTIME);

    /// Namespace bits as the `c_int` that `unshare`/`setns` take.
    fn ns_bits(self) -> Result<libc::c_int> {
        let ns = self.intersection(Self::ALL_NAMESPACES);
        if ns != self {
            return Err(Errno::EINVAL);
        }
        libc::c_int::try_from(ns.bits()).map_err(|_| Errno::EINVAL)
    }
}

/// `struct clone_args` from `<linux/sched.h>` (size version 2, 88 bytes).
#[repr(C)]
#[derive(Default)]
struct CloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    set_tid: u64,
    set_tid_size: u64,
    cgroup: u64,
}

/// Which side of a `fork`/`clone3` we are on.
#[derive(Debug)]
pub enum Forked {
    /// We are the new child process.
    Child,
    /// We are the parent; this is the child's PID (in *our* PID namespace)
    /// and, if `CLONE_PIDFD` was requested, a pidfd for it.
    Parent { pid: Pid, pidfd: Option<OwnedFd> },
}

/// Builder for a `clone3(2)` call.
#[derive(Debug)]
pub struct Clone3<'fd> {
    flags: CloneFlags,
    cgroup: Option<BorrowedFd<'fd>>,
    exit_signal: Signal,
}

impl Default for Clone3<'_> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'fd> Clone3<'fd> {
    /// A plain `fork`-like clone that delivers `SIGCHLD` on exit.
    pub fn new() -> Self {
        Clone3 { flags: CloneFlags::empty(), cgroup: None, exit_signal: Signal::SIGCHLD }
    }

    /// Adds clone flags (namespaces, `PIDFD`).
    pub fn flags(mut self, flags: CloneFlags) -> Self {
        self.flags |= flags - CloneFlags::INTO_CGROUP;
        self
    }

    /// Places the child in the cgroup whose directory `fd` refers to
    /// (`CLONE_INTO_CGROUP`). The fd must be an `O_DIRECTORY`/`O_PATH` fd on
    /// a cgroup2 directory.
    pub fn into_cgroup(mut self, fd: BorrowedFd<'fd>) -> Self {
        self.flags |= CloneFlags::INTO_CGROUP;
        self.cgroup = Some(fd);
        self
    }

    /// Runs `clone3`. Fails with `EDEADLK` if the caller is multithreaded
    /// (see the module docs for why that check makes this function safe),
    /// and with `EINVAL` if the flags contain any bit `CloneFlags` doesn't
    /// name.
    pub fn spawn(self) -> Result<Forked> {
        // bitflags' public `from_bits_retain` can build a `CloneFlags` with
        // *any* bits, including CLONE_VM or CLONE_THREAD. Passing those on
        // would make the child share our memory, breaking the soundness
        // argument above, so the absence of dangerous flags must be checked,
        // not just assumed from the type.
        if !CloneFlags::all().contains(self.flags) {
            return Err(Errno::EINVAL);
        }
        ensure_single_threaded()?;
        let mut pidfd: libc::c_int = -1;
        let mut args =
            CloneArgs { flags: self.flags.bits(), exit_signal: self.exit_signal as u64, ..Default::default() };
        if self.flags.contains(CloneFlags::PIDFD) {
            args.pidfd = &raw mut pidfd as u64;
        }
        if let Some(cg) = self.cgroup {
            args.cgroup = cg.as_raw_fd() as u64;
        }
        // SAFETY: `args` is a correctly laid out `struct clone_args` that
        // lives across the call; the only pointer in it (`pidfd`) points to
        // a live local `c_int`. No CLONE_VM/CLONE_THREAD/stack is passed, so
        // the child gets a private copy of our address space and continues
        // exactly like after `fork`. We verified above that we are the only
        // thread, so no lock can be held by a thread that won't exist in the
        // child.
        let ret = unsafe { libc::syscall(libc::SYS_clone3, &raw mut args, size_of::<CloneArgs>()) };
        match check(ret)? {
            0 => Ok(Forked::Child),
            pid => Ok(Forked::Parent {
                pid: Pid::from_raw(pid as libc::pid_t),
                pidfd: self.flags.contains(CloneFlags::PIDFD).then(|| owned_fd(pidfd.into())),
            }),
        }
    }
}

/// `fork(2)` that refuses to run in a multithreaded process.
pub fn fork() -> Result<Forked> {
    ensure_single_threaded()?;
    // SAFETY: we are single-threaded (checked above), so the child inherits
    // no locks held by vanished threads and may run arbitrary code.
    match unsafe { nix::unistd::fork() }? {
        nix::unistd::ForkResult::Child => Ok(Forked::Child),
        nix::unistd::ForkResult::Parent { child } => Ok(Forked::Parent { pid: child, pidfd: None }),
    }
}

/// Number of threads in the calling process, from `/proc/self/status`.
pub fn thread_count() -> Result<usize> {
    let status = std::fs::read_to_string("/proc/self/status").map_err(|_| Errno::EIO)?;
    status.lines().find_map(|l| l.strip_prefix("Threads:")).and_then(|v| v.trim().parse().ok()).ok_or(Errno::EIO)
}

/// Returns `EDEADLK` unless the caller is the only thread in its process.
///
/// `setns(CLONE_NEWUSER)` and `setns(CLONE_NEWNS)` also demand a
/// single-threaded caller; the runtime calls this before any of them.
pub fn ensure_single_threaded() -> Result<()> {
    match thread_count()? {
        1 => Ok(()),
        _ => Err(Errno::EDEADLK),
    }
}

/// `unshare(2)` for namespace flags.
pub fn unshare(flags: CloneFlags) -> Result<()> {
    nix::sched::unshare(nix::sched::CloneFlags::from_bits_retain(flags.ns_bits()?))
}

/// `setns(2)`. `fd` may be a namespace fd (`/proc/<pid>/ns/<type>`, then
/// `flags` is that one type or empty) or a **pidfd**, in which case several
/// namespace types can be joined atomically (Linux 5.8).
pub fn setns(fd: BorrowedFd<'_>, flags: CloneFlags) -> Result<()> {
    let bits = flags.ns_bits()?;
    // SAFETY: plain syscall on a borrowed (therefore open) fd.
    let ret = unsafe { libc::setns(fd.as_raw_fd(), bits) };
    crate::check_int(ret).map(drop)
}

/// `pidfd_open(2)`: a pidfd for an existing process.
pub fn pidfd_open(pid: Pid) -> Result<OwnedFd> {
    // SAFETY: plain syscall with integer arguments; it returns a new fd.
    let ret = unsafe { libc::syscall(libc::SYS_pidfd_open, pid.as_raw(), 0) };
    check(ret).map(owned_fd)
}

/// `pidfd_send_signal(2)`: signal the process a pidfd refers to. Unlike
/// `kill(2)` this cannot hit an unrelated process that recycled the PID.
pub fn pidfd_send_signal(pidfd: BorrowedFd<'_>, sig: Signal) -> Result<()> {
    // SAFETY: plain syscall; `info` is NULL (the kernel fills it as for kill).
    let ret = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd(),
            sig as libc::c_int,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    check(ret).map(drop)
}

/// How a child finished (or that it hasn't).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitResult {
    /// No child changed state (only with `nohang`).
    StillAlive,
    /// Exited normally with this status code.
    Exited { pid: Pid, code: i32 },
    /// Killed by a signal.
    Signaled { pid: Pid, signal: i32, core_dumped: bool },
}

impl WaitResult {
    /// The PID that changed state, if any.
    pub fn pid(&self) -> Option<Pid> {
        match *self {
            WaitResult::StillAlive => None,
            WaitResult::Exited { pid, .. } | WaitResult::Signaled { pid, .. } => Some(pid),
        }
    }

    /// Shell-style exit code: the status, or 128 + signal number.
    pub fn exit_code(&self) -> Option<i32> {
        match *self {
            WaitResult::StillAlive => None,
            WaitResult::Exited { code, .. } => Some(code),
            WaitResult::Signaled { signal, .. } => Some(128 + signal),
        }
    }
}

/// Which children `waitid` should consider.
#[derive(Debug, Clone, Copy)]
pub enum WaitTarget<'fd> {
    /// Any child (`P_ALL`). Used by the shim's reaper loop.
    Any,
    /// The process a pidfd refers to (`P_PIDFD`, Linux 5.4).
    PidFd(BorrowedFd<'fd>),
    /// One PID (`P_PID`).
    Pid(Pid),
}

/// `waitid(2)` for exited children (`WEXITED`), optionally non-blocking.
/// Retries on `EINTR`.
pub fn waitid(target: WaitTarget<'_>, nohang: bool) -> Result<WaitResult> {
    waitid_with(target, libc::WEXITED | if nohang { libc::WNOHANG } else { 0 })
}

/// Has the child exited? Like `waitid(…, nohang)`, but with `WNOWAIT`: a
/// dead child stays a zombie, so its `/proc/<pid>` entry can still be read,
/// and a later [`waitid`] still reaps it.
pub fn waitid_peek(target: WaitTarget<'_>) -> Result<WaitResult> {
    waitid_with(target, libc::WEXITED | libc::WNOHANG | libc::WNOWAIT)
}

fn waitid_with(target: WaitTarget<'_>, options: libc::c_int) -> Result<WaitResult> {
    const P_PIDFD: libc::idtype_t = 3;
    let (idtype, id) = match target {
        WaitTarget::Any => (libc::P_ALL, 0),
        WaitTarget::PidFd(fd) => (P_PIDFD, fd.as_raw_fd() as libc::id_t),
        WaitTarget::Pid(pid) => (libc::P_PID, pid.as_raw() as libc::id_t),
    };
    loop {
        // SAFETY: an all-zero `siginfo_t` is a valid value of the type.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: `info` is a valid, writable `siginfo_t` for the kernel to fill.
        let ret = unsafe { libc::waitid(idtype, id, &raw mut info, options) };
        if ret < 0 {
            let e = Errno::last();
            if e == Errno::EINTR {
                continue;
            }
            return Err(e);
        }
        // SAFETY: after a successful waitid the kernel initialized the
        // `si_pid` union member (it is zero when WNOHANG found nothing).
        let pid = unsafe { info.si_pid() };
        if pid == 0 {
            return Ok(WaitResult::StillAlive);
        }
        // SAFETY: as above, `si_status` is initialized for SIGCHLD siginfo.
        let status = unsafe { info.si_status() };
        let pid = Pid::from_raw(pid);
        return Ok(match info.si_code {
            libc::CLD_EXITED => WaitResult::Exited { pid, code: status },
            libc::CLD_DUMPED => WaitResult::Signaled { pid, signal: status, core_dumped: true },
            _ => WaitResult::Signaled { pid, signal: status, core_dumped: false },
        });
    }
}

/// `prlimit(2)`: sets a resource limit of *another* process. The runtime sets
/// container init's limits from outside, because inside a user namespace init
/// may not raise a hard limit itself (that takes `CAP_SYS_RESOURCE` in the
/// initial user namespace).
pub fn prlimit(pid: Pid, resource: nix::sys::resource::Resource, soft: u64, hard: u64) -> Result<()> {
    let new = libc::rlimit64 { rlim_cur: soft, rlim_max: hard };
    // SAFETY: `new` is a valid `rlimit64` that lives across the call, and the
    // old-limit pointer is NULL (the kernel then doesn't write anything).
    let ret = unsafe {
        libc::prlimit64(pid.as_raw(), resource as libc::__rlimit_resource_t, &raw const new, std::ptr::null_mut())
    };
    crate::check_int(ret).map(drop)
}

/// Opens a namespace file such as `/proc/<pid>/ns/net` (`O_RDONLY|O_CLOEXEC`).
pub fn open_ns(path: impl AsRef<std::path::Path>) -> Result<OwnedFd> {
    let f = std::fs::File::open(path.as_ref()).map_err(|e| Errno::from_raw(e.raw_os_error().unwrap_or(libc::EIO)))?;
    Ok(OwnedFd::from(f))
}

/// `sethostname(2)`.
pub fn sethostname(name: &str) -> Result<()> {
    nix::unistd::sethostname(name)
}

/// `setdomainname(2)` (not wrapped by nix).
pub fn setdomainname(name: &str) -> Result<()> {
    let bytes = name.as_bytes();
    // SAFETY: `bytes` is valid for `len` bytes; the kernel copies them.
    let ret = unsafe { libc::setdomainname(bytes.as_ptr().cast(), bytes.len()) };
    crate::check_int(ret).map(drop)
}

/// Replaces the process image, resolving nothing: `path` must be the file
/// to execute. Only returns on error.
pub fn execve(path: &std::ffi::CStr, args: &[std::ffi::CString], env: &[std::ffi::CString]) -> Errno {
    match nix::unistd::execve(path, args, env) {
        Err(e) => e,
        Ok(never) => match never {},
    }
}

/// Executes the file an fd refers to (`execveat(fd, "", …, AT_EMPTY_PATH)`).
/// Used to re-exec the runtime from its sealed memfd copy.
pub fn fexecve(fd: BorrowedFd<'_>, args: &[std::ffi::CString], env: &[std::ffi::CString]) -> Errno {
    match nix::unistd::fexecve(fd, args, env) {
        Err(e) => e,
        Ok(never) => match never {},
    }
}

/// Exits immediately without running atexit handlers or flushing stdio
/// (`_exit(2)`). Used by forked children that must not unwind into code
/// that belongs to the parent.
pub fn exit_now(code: i32) -> ! {
    // SAFETY: `_exit` is always safe to call; it never returns.
    unsafe { libc::_exit(code) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spawn_rejects_unnamed_flags() {
        // CLONE_VM smuggled in through from_bits_retain must never reach the
        // kernel. (EINVAL comes before the thread check, so this is safe to
        // run on a libtest worker thread: nothing is ever cloned.)
        let vm = CloneFlags::from_bits_retain(libc::CLONE_VM as u64);
        assert_eq!(Clone3::new().flags(vm | CloneFlags::NEWPID).spawn().unwrap_err(), Errno::EINVAL);
    }

    #[test]
    fn ns_bits_rejects_non_namespace_flags() {
        assert!(CloneFlags::PIDFD.ns_bits().is_err());
        assert_eq!(CloneFlags::NEWNET.ns_bits().unwrap(), libc::CLONE_NEWNET);
    }

    #[test]
    fn clone_args_matches_kernel_size() {
        // CLONE_ARGS_SIZE_VER2 == 88
        assert_eq!(size_of::<CloneArgs>(), 88);
    }

    #[test]
    fn thread_count_is_positive() {
        assert!(thread_count().unwrap() >= 1);
    }
}

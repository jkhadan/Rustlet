//! Small `prctl(2)` helpers used by the runtime and the shim.

use nix::sys::signal::Signal;

use crate::{Result, check_int};

fn prctl(option: libc::c_int, arg2: libc::c_ulong) -> Result<libc::c_int> {
    // SAFETY: every option used in this module takes only integer arguments.
    let ret = unsafe { libc::prctl(option, arg2, 0 as libc::c_ulong, 0 as libc::c_ulong, 0 as libc::c_ulong) };
    check_int(ret)
}

/// `PR_SET_NO_NEW_PRIVS`: from now on `execve` can never grant privileges
/// (setuid bits and file capabilities are ignored). One-way; inherited.
pub fn set_no_new_privs() -> Result<()> {
    prctl(libc::PR_SET_NO_NEW_PRIVS, 1).map(drop)
}

/// `PR_GET_NO_NEW_PRIVS`.
pub fn no_new_privs() -> Result<bool> {
    prctl(libc::PR_GET_NO_NEW_PRIVS, 0).map(|v| v == 1)
}

/// `PR_SET_KEEPCAPS`: keep permitted caps across a setuid away from 0.
pub fn set_keepcaps(on: bool) -> Result<()> {
    prctl(libc::PR_SET_KEEPCAPS, on.into()).map(drop)
}

/// `PR_SET_DUMPABLE`. A non-dumpable process's `/proc/<pid>` files are owned
/// by root and it cannot be ptrace-attached by same-uid processes.
pub fn set_dumpable(on: bool) -> Result<()> {
    prctl(libc::PR_SET_DUMPABLE, on.into()).map(drop)
}

/// `PR_GET_DUMPABLE`.
pub fn dumpable() -> Result<bool> {
    prctl(libc::PR_GET_DUMPABLE, 0).map(|v| v == 1)
}

/// `PR_SET_CHILD_SUBREAPER`: orphaned descendants are re-parented to us
/// instead of PID 1. The shim relies on this to reap container init after
/// `rustlet-runc create` exits.
pub fn set_child_subreaper() -> Result<()> {
    prctl(libc::PR_SET_CHILD_SUBREAPER, 1).map(drop)
}

/// `PR_SET_PDEATHSIG`: get `sig` when the parent *thread* dies. `None`
/// clears it. Note the kernel also clears it on credential changes.
pub fn set_pdeathsig(sig: Option<Signal>) -> Result<()> {
    prctl(libc::PR_SET_PDEATHSIG, sig.map_or(0, |s| s as libc::c_ulong)).map(drop)
}

/// `PR_GET_SECCOMP`: 0 = disabled, 1 = strict, 2 = filter.
pub fn seccomp_mode() -> Result<i32> {
    prctl(libc::PR_GET_SECCOMP, 0)
}

/// `PR_SET_NAME` (the 15-byte `comm`). Longer names are truncated.
pub fn set_name(name: &str) -> Result<()> {
    let mut buf = [0u8; 16];
    let n = name.len().min(15);
    buf[..n].copy_from_slice(&name.as_bytes()[..n]);
    // SAFETY: `buf` is a live, NUL-terminated 16-byte buffer.
    let ret = unsafe { libc::prctl(libc::PR_SET_NAME, buf.as_ptr() as libc::c_ulong, 0, 0, 0) };
    check_int(ret).map(drop)
}

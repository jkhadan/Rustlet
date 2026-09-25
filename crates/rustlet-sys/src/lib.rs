//! # rustlet-sys: the safety boundary
//!
//! Every other crate in Rustlets carries `#![forbid(unsafe_code)]`. Anything
//! that has to talk to the kernel below the level of `std` or `nix` lives here,
//! behind a *safe* function signature. The rules for this crate:
//!
//! 1. **Every `unsafe` block has a `// SAFETY:` comment** explaining why the
//!    invariants hold (enforced by `clippy::undocumented_unsafe_blocks`), and
//!    each block contains a single unsafe operation
//!    (`clippy::multiple_unsafe_ops_per_block`).
//! 2. **File descriptors cross the boundary as [`OwnedFd`]/[`BorrowedFd`]**
//!    ("I/O safety"): a function that creates an fd returns an `OwnedFd` that
//!    closes itself on drop; a function that uses an fd borrows it, so the
//!    compiler proves the fd is still open for the duration of the call.
//! 3. **Flags are typed** (`bitflags`), so you cannot pass `MS_*` mount flags
//!    where `MOUNT_ATTR_*` flags are expected.
//! 4. **Errors are [`Errno`]**, the raw kernel error. Higher layers add context.
//!
//! Where `nix` already offers a good safe wrapper (basic `mount`, `unshare`,
//! termios, signals, `mknodat`, …) callers use `nix` directly; this crate only
//! fills the gaps: the new mount API, `clone3`, pidfds, `openat2`, `statx`,
//! capabilities, seccomp, eBPF, `SCM_RIGHTS`, and a small rtnetlink codec.
//!
//! Everything here targets **x86_64 Linux**. The syscall numbers used are the
//! x86_64 ones from `libc`, and the minimum kernel is 6.8 (for
//! `fsconfig("lowerdir+")`).
//!
//! [`OwnedFd`]: std::os::fd::OwnedFd
//! [`BorrowedFd`]: std::os::fd::BorrowedFd

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
compile_error!("rustlet-sys supports x86_64 Linux only");

pub mod bpf;
pub mod caps;
pub mod fs;
pub mod keyring;
pub mod mount;
pub mod mountinfo;
pub mod netlink;
pub mod prctl;
pub mod process;
pub mod procfs;
pub mod seccomp;
pub mod signal;
pub mod socket;
pub mod term;
pub mod tree;
pub mod xattr;

pub use nix::errno::Errno;

/// Result type used throughout this crate: `Ok(T)` or the raw kernel `errno`.
pub type Result<T> = std::result::Result<T, Errno>;

use std::ffi::CString;

/// Converts a Rust string into a `CString`, mapping interior NUL bytes to
/// `EINVAL` (the kernel's answer for such a path anyway).
pub(crate) fn cstr(s: impl AsRef<std::ffi::OsStr>) -> Result<CString> {
    use std::os::unix::ffi::OsStrExt;
    CString::new(s.as_ref().as_bytes()).map_err(|_| Errno::EINVAL)
}

/// Turns the return value of a raw syscall into a `Result`: negative values
/// mean failure with `errno` set.
pub(crate) fn check(ret: libc::c_long) -> Result<libc::c_long> {
    if ret < 0 { Err(Errno::last()) } else { Ok(ret) }
}

/// Same as [`check`] for functions that return `c_int`.
pub(crate) fn check_int(ret: libc::c_int) -> Result<libc::c_int> {
    if ret < 0 { Err(Errno::last()) } else { Ok(ret) }
}

/// Wraps a freshly returned fd number in an `OwnedFd`.
///
/// Only call this with a value a syscall *just* returned as a new fd; this
/// function is private so that invariant stays local to this crate.
pub(crate) fn owned_fd(raw: libc::c_long) -> std::os::fd::OwnedFd {
    use std::os::fd::FromRawFd;
    debug_assert!(raw >= 0 && raw <= i32::MAX as libc::c_long);
    // SAFETY: `raw` was just returned by the kernel as a new file descriptor,
    // so nothing else owns it; `OwnedFd` becomes its unique owner.
    unsafe { std::os::fd::OwnedFd::from_raw_fd(raw as libc::c_int) }
}

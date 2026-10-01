//! The new (fd-based) mount API, plus `pivot_root`.
//!
//! The classic `mount(2)` takes *paths*. Between the moment you check a path
//! and the moment the kernel resolves it again inside `mount`, a malicious
//! container could swap a directory for a symlink. That race is behind
//! CVE-2019-19921, CVE-2021-30465 and several runc 2025 CVEs.
//!
//! The new API (Linux 5.2+) works on file descriptors instead:
//!
//! ```text
//!   fsopen("proc")          -> fs context fd     (a filesystem being set up)
//!   fsconfig(fd, key, val)  -> configure it
//!   fsmount(fd)             -> detached mount fd (a mount not attached anywhere)
//!   open_tree(path, CLONE)  -> detached copy of an existing mount (a bind)
//!   mount_setattr(fd, ...)  -> change ro/nosuid/nodev/idmap on a mount fd
//!   move_mount(mnt, target) -> attach it; `target` can itself be an fd that
//!                              was resolved safely with openat2(RESOLVE_IN_ROOT)
//! ```
//!
//! Resolve once, hold the fd, attach to the fd: nothing gets re-resolved.

use std::ffi::CStr;
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd};
use std::path::Path;

use bitflags::bitflags;

use crate::{Errno, Result, check, cstr, owned_fd};

bitflags! {
    /// `MOUNT_ATTR_*` for `fsmount` and `mount_setattr`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct MountAttr: u64 {
        const RDONLY = 0x0000_0001;
        const NOSUID = 0x0000_0002;
        const NODEV = 0x0000_0004;
        const NOEXEC = 0x0000_0008;
        const NOATIME = 0x0000_0010;
        const STRICTATIME = 0x0000_0020;
        const NODIRATIME = 0x0000_0080;
        const IDMAP = 0x0010_0000;
        const NOSYMFOLLOW = 0x0020_0000;
    }
}

impl MountAttr {
    /// The `MOUNT_ATTR__ATIME` mask: atime flags are a 2-bit field and must
    /// be cleared as a group.
    pub const ATIME_MASK: MountAttr = MountAttr::from_bits_retain(0x70);
}

bitflags! {
    /// Flags for `open_tree(2)`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct OpenTreeFlags: u32 {
        /// Make a detached *copy* of the mount (a bind mount in waiting).
        const CLONE = 1;
        const CLOEXEC = libc::O_CLOEXEC as u32;
        /// With CLONE: copy the whole subtree (rbind).
        const RECURSIVE = libc::AT_RECURSIVE as u32;
        /// Operate on the fd itself when the path is "".
        const EMPTY_PATH = libc::AT_EMPTY_PATH as u32;
        const SYMLINK_NOFOLLOW = libc::AT_SYMLINK_NOFOLLOW as u32;
    }
}

bitflags! {
    /// Flags for `move_mount(2)`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct MoveMountFlags: u32 {
        const F_SYMLINKS = 0x01;
        const F_AUTOMOUNTS = 0x02;
        /// The source is the fd itself (`from_path` = "").
        const F_EMPTY_PATH = 0x04;
        const T_SYMLINKS = 0x10;
        const T_AUTOMOUNTS = 0x20;
        /// The target is the fd itself (`to_path` = "").
        const T_EMPTY_PATH = 0x40;
    }
}

/// Mount propagation types for `mount_setattr`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Propagation {
    Private,
    Slave,
    Shared,
    Unbindable,
}

impl Propagation {
    fn bits(self) -> u64 {
        match self {
            Propagation::Private => libc::MS_PRIVATE,
            Propagation::Slave => libc::MS_SLAVE,
            Propagation::Shared => libc::MS_SHARED,
            Propagation::Unbindable => libc::MS_UNBINDABLE,
        }
    }
}

/// `struct mount_attr` from `<linux/mount.h>`.
#[repr(C)]
#[derive(Default)]
struct RawMountAttr {
    attr_set: u64,
    attr_clr: u64,
    propagation: u64,
    userns_fd: u64,
}

/// What `mount_setattr` should change.
#[derive(Debug, Default)]
pub struct SetAttr<'fd> {
    pub set: MountAttr,
    pub clear: MountAttr,
    pub propagation: Option<Propagation>,
    /// For `MountAttr::IDMAP`: the user namespace whose mapping to apply.
    pub userns: Option<BorrowedFd<'fd>>,
}

const FSOPEN_CLOEXEC: u32 = 1;
const FSMOUNT_CLOEXEC: u32 = 1;

const FSCONFIG_SET_FLAG: u32 = 0;
const FSCONFIG_SET_STRING: u32 = 1;
const FSCONFIG_SET_FD: u32 = 5;
const FSCONFIG_CMD_CREATE: u32 = 6;

/// A filesystem context from `fsopen`. Configure it, then [`FsContext::mount`].
#[derive(Debug)]
pub struct FsContext {
    fd: OwnedFd,
    fstype: String,
}

impl FsContext {
    /// `fsopen(fstype, FSOPEN_CLOEXEC)`.
    pub fn open(fstype: &str) -> Result<FsContext> {
        let name = cstr(fstype)?;
        // SAFETY: `name` is a valid NUL-terminated string for the call.
        let ret = unsafe { libc::syscall(libc::SYS_fsopen, name.as_ptr(), FSOPEN_CLOEXEC) };
        Ok(FsContext { fd: owned_fd(check(ret)?), fstype: fstype.to_owned() })
    }

    fn config(&self, cmd: u32, key: Option<&CStr>, value: *const libc::c_void, aux: libc::c_int) -> Result<()> {
        let key_ptr = key.map_or(std::ptr::null(), CStr::as_ptr);
        // SAFETY: `key_ptr` is NULL or a live C string, `value` is NULL or
        // points to a live C string (checked by the callers below), and the
        // fs context fd is owned by `self`.
        let ret = unsafe { libc::syscall(libc::SYS_fsconfig, self.fd.as_raw_fd(), cmd, key_ptr, value, aux) };
        check(ret).map(drop).inspect_err(|_| {
            // The kernel explains most fsconfig failures in the context log.
            if let Some(msg) = self.log().last() {
                log_hint(&self.fstype, msg);
            }
        })
    }

    /// `fsconfig(FSCONFIG_SET_FLAG, key)`, e.g. `"newinstance"`.
    pub fn set_flag(&self, key: &str) -> Result<()> {
        let key = cstr(key)?;
        self.config(FSCONFIG_SET_FLAG, Some(&key), std::ptr::null(), 0)
    }

    /// `fsconfig(FSCONFIG_SET_STRING, key, value)`, e.g. `("mode", "755")`.
    pub fn set_string(&self, key: &str, value: &str) -> Result<()> {
        let key = cstr(key)?;
        let value = cstr(value)?;
        self.config(FSCONFIG_SET_STRING, Some(&key), value.as_ptr().cast(), 0)
    }

    /// `fsconfig(FSCONFIG_SET_FD, key, fd)`, e.g. overlay's `"lowerdir+"`
    /// with a layer's fd (kernel 6.13; Rustlets passes paths, for 6.8).
    pub fn set_fd(&self, key: &str, fd: BorrowedFd<'_>) -> Result<()> {
        let key = cstr(key)?;
        self.config(FSCONFIG_SET_FD, Some(&key), std::ptr::null(), fd.as_raw_fd())
    }

    /// Applies a classic comma-separated option string such as
    /// `"mode=755,size=65536k,newinstance"`: `k=v` becomes `set_string`, a
    /// bare word becomes `set_flag`.
    pub fn set_options(&self, data: &str) -> Result<()> {
        for opt in data.split(',').filter(|o| !o.is_empty()) {
            match opt.split_once('=') {
                Some((k, v)) => self.set_string(k, v)?,
                None => self.set_flag(opt)?,
            }
        }
        Ok(())
    }

    /// `FSCONFIG_CMD_CREATE` + `fsmount`: creates the superblock and returns a
    /// detached mount fd, ready for [`move_mount`].
    pub fn mount(&self, attrs: MountAttr) -> Result<OwnedFd> {
        self.config(FSCONFIG_CMD_CREATE, None, std::ptr::null(), 0)?;
        // SAFETY: plain syscall on an fd we own.
        let ret = unsafe { libc::syscall(libc::SYS_fsmount, self.fd.as_raw_fd(), FSMOUNT_CLOEXEC, attrs.bits()) };
        check(ret).map(owned_fd)
    }

    /// Drains the context's message log (`e ...`, `w ...`, `i ...` lines).
    pub fn log(&self) -> Vec<String> {
        let mut out = Vec::new();
        let mut buf = [0u8; 1024];
        while let Ok(n) = nix::unistd::read(&self.fd, &mut buf) {
            if n == 0 {
                break;
            }
            out.push(String::from_utf8_lossy(&buf[..n]).trim_end().to_owned());
        }
        out
    }

    /// Borrow the underlying context fd.
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        use std::os::fd::AsFd;
        self.fd.as_fd()
    }
}

fn log_hint(fstype: &str, msg: &str) {
    // Diagnostic only: surfaces the kernel's explanation on stderr in debug
    // builds, where it saves a lot of guesswork.
    if cfg!(debug_assertions) {
        eprintln!("fsconfig({fstype}): kernel says: {msg}");
    }
}

/// `open_tree(dirfd, path, flags)`. With `CLONE` this returns a detached bind
/// mount of `path`; add `RECURSIVE` for an rbind.
pub fn open_tree(dirfd: Option<BorrowedFd<'_>>, path: &Path, flags: OpenTreeFlags) -> Result<OwnedFd> {
    let p = cstr(path)?;
    let dfd = dirfd.map_or(libc::AT_FDCWD, |f| f.as_raw_fd());
    // SAFETY: `p` is a valid C string; `dfd` is AT_FDCWD or a borrowed fd.
    let ret = unsafe { libc::syscall(libc::SYS_open_tree, dfd, p.as_ptr(), (flags | OpenTreeFlags::CLOEXEC).bits()) };
    check(ret).map(owned_fd)
}

/// `move_mount(2)` between two fds, both with empty paths: attach the
/// detached mount `from` onto the directory/file that `to` refers to.
pub fn move_mount_fd(from: BorrowedFd<'_>, to: BorrowedFd<'_>) -> Result<()> {
    move_mount(
        Some(from),
        Path::new(""),
        Some(to),
        Path::new(""),
        MoveMountFlags::F_EMPTY_PATH | MoveMountFlags::T_EMPTY_PATH,
    )
}

/// General `move_mount(2)`.
pub fn move_mount(
    from_dfd: Option<BorrowedFd<'_>>,
    from_path: &Path,
    to_dfd: Option<BorrowedFd<'_>>,
    to_path: &Path,
    flags: MoveMountFlags,
) -> Result<()> {
    let fp = cstr(from_path)?;
    let tp = cstr(to_path)?;
    let fd1 = from_dfd.map_or(libc::AT_FDCWD, |f| f.as_raw_fd());
    let fd2 = to_dfd.map_or(libc::AT_FDCWD, |f| f.as_raw_fd());
    // SAFETY: both paths are valid C strings and both dirfds are AT_FDCWD
    // or borrowed (open) fds.
    let ret = unsafe { libc::syscall(libc::SYS_move_mount, fd1, fp.as_ptr(), fd2, tp.as_ptr(), flags.bits()) };
    check(ret).map(drop)
}

/// `mount_setattr(2)` on the mount an fd refers to (`AT_EMPTY_PATH`),
/// optionally for the whole subtree (`recursive` = `AT_RECURSIVE`).
pub fn mount_setattr(fd: BorrowedFd<'_>, recursive: bool, attr: &SetAttr<'_>) -> Result<()> {
    let mut raw = RawMountAttr {
        attr_set: attr.set.bits(),
        attr_clr: attr.clear.bits(),
        propagation: attr.propagation.map_or(0, Propagation::bits),
        userns_fd: attr.userns.map_or(0, |f| f.as_raw_fd() as u64),
    };
    let mut flags = libc::AT_EMPTY_PATH as libc::c_uint;
    if recursive {
        flags |= libc::AT_RECURSIVE as libc::c_uint;
    }
    let empty = c"";
    // SAFETY: `raw` is a correctly laid out `struct mount_attr` living across
    // the call, its size is passed, and `fd` is borrowed.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_mount_setattr,
            fd.as_raw_fd(),
            empty.as_ptr(),
            flags,
            &raw mut raw,
            std::mem::size_of::<RawMountAttr>(),
        )
    };
    check(ret).map(drop)
}

/// `pivot_root(new_root, put_old)`. The runtime calls it as
/// `pivot_root(".", ".")` after `fchdir(new_root)`; see
/// `rustlet_runtime::rootfs` for why that works without a put_old directory.
pub fn pivot_root(new_root: &Path, put_old: &Path) -> Result<()> {
    let a = cstr(new_root)?;
    let b = cstr(put_old)?;
    // SAFETY: both arguments are valid C strings for the duration of the call.
    let ret = unsafe { libc::syscall(libc::SYS_pivot_root, a.as_ptr(), b.as_ptr()) };
    check(ret).map(drop)
}

/// `umount2(path, flags)`.
pub fn umount2(path: &Path, flags: nix::mount::MntFlags) -> Result<()> {
    nix::mount::umount2(path, flags)
}

/// Classic `mount(2)` for the few places that still need it (changing
/// propagation of `/`, remounts). Re-exported so callers need not pull
/// in nix's mount feature themselves.
pub use nix::mount::{MntFlags, MsFlags, mount};

/// `fchdir(2)`.
pub fn fchdir(fd: BorrowedFd<'_>) -> Result<()> {
    nix::unistd::fchdir(fd)
}

/// Checks whether `Errno` means "this kernel doesn't know the syscall".
pub fn is_unsupported(e: Errno) -> bool {
    matches!(e, Errno::ENOSYS | Errno::EOPNOTSUPP)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mount_attr_struct_size() {
        // MOUNT_ATTR_SIZE_VER0 == 32
        assert_eq!(std::mem::size_of::<RawMountAttr>(), 32);
    }

    #[test]
    fn open_tree_without_privilege_fails_cleanly() {
        // Unprivileged callers get EPERM for CLONE; we just check the
        // wrapper returns an error instead of crashing.
        if nix::unistd::geteuid().is_root() {
            return;
        }
        assert!(open_tree(None, Path::new("/"), OpenTreeFlags::CLONE).is_err());
    }
}

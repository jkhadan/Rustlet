//! A private procfs handle for writes that must not be redirected.
//!
//! Container init writes a handful of `/proc` files as root: sysctls under
//! `/proc/sys`, `oom_score_adj`, and so on. Going through the path
//! `/proc/...` is dangerous, because by the time init runs, `/proc` is part of
//! a mount tree the container's config (or a racing process that shares a
//! volume with it) can influence. CVE-2025-52881 is the example: an attacker
//! bind-mounts a *different* procfs file, say `/proc/sys/kernel/core_pattern`,
//! over one the runtime is about to write, and an innocent-looking write
//! becomes a host-wide change (a `core_pattern` of `|/evil` makes the kernel
//! run `/evil` as root on the host the next time anything crashes).
//!
//! The defence is to not use the container's `/proc` at all. We create a
//! procfs instance of our own with `fsopen("proc")` + `fsmount`: that gives a
//! **detached** mount, attached to no directory, so nothing can be mounted
//! over or inside it (you need a path to mount onto, and it has none). Every
//! lookup then starts at the fd for its root and is walked with
//!
//! * `RESOLVE_BENEATH`: never climb above that root;
//! * `RESOLVE_NO_XDEV`: never cross into another mount (there is none, but
//!   if there ever were, we would refuse rather than follow);
//! * `RESOLVE_NO_SYMLINKS` (implies `RESOLVE_NO_MAGICLINKS`): procfs is full
//!   of links that point elsewhere, `/proc/self/fd/*` and `/proc/self/root`
//!   being the dangerous ones.
//!
//! and the result is checked to be on procfs (`fstatfs` = `PROC_SUPER_MAGIC`).
//! This is the approach of libpathrs, which runc adopted for the same CVE.
//!
//! One consequence of "no symlinks": `/proc/self` is itself a symlink (to the
//! caller's pid), so [`ProcHandle::open`] rewrites a leading `self` component
//! to our pid before resolving.

use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::{Component, Path, PathBuf};

use nix::fcntl::OFlag;
use nix::sys::stat::Mode;
use nix::unistd::Pid;
use rustlet_sys::Errno;
use rustlet_sys::fs::{ResolveFlags, fs_magic, magic, openat2};
use rustlet_sys::mount::{FsContext, MountAttr};

use crate::error::{Context, Error, Result};

/// A procfs instance of our own, mounted detached (never attached anywhere,
/// so nothing in the container can mount over or into it).
///
/// **Use it only in the process that created it.** The instance shows the
/// PID namespace its creator was in, and `self/` is rewritten to the
/// *caller's* pid: in any other process (or in a process whose PID namespace
/// differs from the instance's) that pid names a different process, or none.
/// Container init creates one right after `clone3`, in the container's new
/// PID namespace, so `self/` becomes `1/`.
///
/// The fd is close-on-exec (`FSMOUNT_CLOEXEC`), so it never reaches the
/// container's program. It must not: with it, `openat` could reach a
/// writable `/proc/sys` that no read-only path covers.
#[derive(Debug)]
pub(crate) struct ProcHandle {
    /// The root directory of the detached procfs mount.
    root: OwnedFd,
}

impl ProcHandle {
    /// A new procfs instance for the caller's PID namespace.
    ///
    /// The kernel picks the namespace at `fsopen` time (the caller's
    /// *active* PID namespace, which `setns(CLONE_NEWPID)` does not change;
    /// only children are born into a joined one). `nosuid`, `nodev` and
    /// `noexec`, like any `/proc`: nothing on procfs is ever executed through
    /// this handle. Needs `CAP_SYS_ADMIN` over that PID namespace's owning
    /// user namespace.
    pub(crate) fn new() -> Result<ProcHandle> {
        let fs = FsContext::open("proc").context("fsopen(proc) for the private procfs handle")?;
        let root = fs
            .mount(MountAttr::NOSUID | MountAttr::NODEV | MountAttr::NOEXEC)
            .context("fsmount the private procfs handle")?;
        // Can't really fail: we asked for procfs. But the handle's whole
        // point is certainty, so check anyway (as libpathrs does).
        check_procfs(root.as_fd(), Path::new(""))?;
        Ok(ProcHandle { root })
    }

    /// Opens `path`, relative to the procfs root (`sys/net/ipv4/ip_forward`;
    /// a leading `self/` means the calling process), with no symlinks, no
    /// magic links and no mount crossings, and checks the result really is
    /// a procfs file.
    ///
    /// `thread-self/` is not rewritten, so it fails with `ELOOP` (it is a
    /// symlink too); nothing needs per-thread files yet.
    pub(crate) fn open(&self, path: &Path, flags: OFlag) -> Result<OwnedFd> {
        let rel = rewrite_self(path, nix::unistd::getpid()).map_err(|why| Error::Sys {
            context: format!("procfs path {}: {why}", path.display()),
            errno: Errno::EINVAL,
        })?;
        let resolve =
            ResolveFlags::BENEATH | ResolveFlags::NO_XDEV | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS;
        let fd = openat2(Some(self.root.as_fd()), &rel, flags, Mode::empty(), resolve)
            .with_context(|| format!("open {}", shown(path)))?;
        check_procfs(fd.as_fd(), path)?;
        Ok(fd)
    }

    /// `open(path, O_WRONLY)` + one `write` of `value`.
    ///
    /// *One* write, because that is what sysctl handlers expect: with the
    /// default `kernel.sysctl_writes_strict = 1`, a numeric sysctl ignores a
    /// write that doesn't start at offset 0, so a value split across two
    /// `write` calls would be silently cut short. A short write is therefore
    /// an error, not something to retry.
    pub(crate) fn write(&self, path: &Path, value: &str) -> Result<()> {
        let fd = self.open(path, OFlag::O_WRONLY | OFlag::O_CLOEXEC)?;
        let n = nix::unistd::write(&fd, value.as_bytes()).with_context(|| format!("write {}", shown(path)))?;
        if n != value.len() {
            return Err(Error::Io {
                context: format!("write {}", shown(path)),
                err: std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    format!("short write ({n} of {} bytes)", value.len()),
                ),
            });
        }
        Ok(())
    }
}

/// `path` as users know it, for messages.
fn shown(path: &Path) -> String {
    format!("/proc/{}", path.display())
}

/// Proves that `fd` is on procfs. `path` is only for the message.
fn check_procfs(fd: BorrowedFd<'_>, path: &Path) -> Result<()> {
    let f_type = fs_magic(fd).with_context(|| format!("fstatfs {}", shown(path)))?;
    if f_type != magic::PROC_SUPER_MAGIC {
        return Err(Error::Sys {
            context: format!("{} is not on procfs (f_type {f_type:#x})", shown(path)),
            errno: Errno::EXDEV,
        });
    }
    Ok(())
}

/// Validates a procfs-relative path and rewrites a leading `self` to `pid`.
///
/// Relative, because it is resolved against the handle's root; no `..`,
/// because `RESOLVE_BENEATH` would refuse it anyway and a caller that builds
/// such a path has a bug worth hearing about. `.` components and repeated or
/// trailing slashes are dropped (`Path::components` normalises them).
fn rewrite_self(path: &Path, pid: Pid) -> std::result::Result<PathBuf, &'static str> {
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            // The first name (`out` is still empty; a leading `./` doesn't count).
            Component::Normal(n) if n == "self" && out.as_os_str().is_empty() => out.push(pid.to_string()),
            Component::Normal(n) => out.push(n),
            Component::CurDir => {}
            Component::RootDir | Component::Prefix(_) => return Err("must be relative to the procfs root"),
            Component::ParentDir => return Err("must not contain `..`"),
        }
    }
    if out.as_os_str().is_empty() {
        return Err("is empty");
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rw(p: &str) -> std::result::Result<PathBuf, &'static str> {
        rewrite_self(Path::new(p), Pid::from_raw(42))
    }

    #[test]
    fn leading_self_becomes_our_pid() {
        assert_eq!(rw("self/oom_score_adj").unwrap(), Path::new("42/oom_score_adj"));
        assert_eq!(rw("self").unwrap(), Path::new("42"));
        assert_eq!(rw("./self/attr/exec").unwrap(), Path::new("42/attr/exec"));
        // Only the first component: `self` further down is a literal name.
        assert_eq!(rw("1/task/self").unwrap(), Path::new("1/task/self"));
        assert_eq!(rw("sys//net/ipv4/ip_forward/").unwrap(), Path::new("sys/net/ipv4/ip_forward"));
    }

    #[test]
    fn rejects_absolute_dotdot_and_empty() {
        for bad in ["/proc/self/status", "/sys/kernel/ostype", "sys/../self", "..", "", "."] {
            assert!(rw(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    /// Creating a procfs instance needs `CAP_SYS_ADMIN`: only runs as root
    /// (e.g. under `cargo xtask itest`), and passes trivially otherwise.
    #[test]
    fn real_procfs_instance() {
        if !nix::unistd::geteuid().is_root() {
            return;
        }
        let proc = ProcHandle::new().unwrap();
        // Plain files open, and `self` really is us.
        let fd = proc.open(Path::new("self/stat"), OFlag::O_RDONLY).unwrap();
        let stat = std::io::read_to_string(std::fs::File::from(fd)).unwrap();
        assert!(stat.starts_with(&format!("{} (", std::process::id())), "{stat}");
        // Magic links and plain symlinks are both refused.
        assert_eq!(proc.open(Path::new("self/fd/0"), OFlag::O_RDONLY).unwrap_err().errno(), Some(Errno::ELOOP));
        assert_eq!(proc.open(Path::new("net"), OFlag::O_RDONLY).unwrap_err().errno(), Some(Errno::ELOOP));
        assert_eq!(proc.open(Path::new("self/root"), OFlag::O_PATH).unwrap_err().errno(), Some(Errno::ELOOP));
        // A write of the current value back is a no-op that exercises `write`.
        let adj = std::fs::read_to_string("/proc/self/oom_score_adj").unwrap();
        proc.write(Path::new("self/oom_score_adj"), adj.trim()).unwrap();
    }
}

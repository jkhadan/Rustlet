//! Resolving and creating paths *inside* the container's rootfs, from the
//! host side, without ever leaving it.
//!
//! Before `pivot_root`, the runtime has to find `/dev/pts` or `/etc/hosts`
//! inside a directory tree that the image author controls. The rootfs can
//! contain `dev -> /` or `etc -> ../../../../etc`, and a plain
//! `join(rootfs, "/dev/pts")` would follow those out onto the host.
//!
//! Every lookup here goes through `openat2(RESOLVE_IN_ROOT)` relative to an
//! fd for the rootfs. The kernel then treats that fd as `/` for the whole
//! walk: absolute symlinks restart at the rootfs, and `..` stops there. We
//! get back an `O_PATH` fd for the exact inode that was found, and mount onto
//! *that fd*, so the path is never resolved a second time.

use std::ffi::OsStr;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::{Component, Path, PathBuf};

use nix::fcntl::OFlag;
use nix::sys::stat::Mode;
use rustlet_sys::Errno;
use rustlet_sys::fs::{fstatx, open_in_root};

/// `/a/b` -> `a/b`; openat2 wants a path relative to the root fd.
fn relative(p: &Path) -> &Path {
    p.strip_prefix("/").unwrap_or(p)
}

/// Opens a directory inside `root` as an `O_PATH` fd.
pub(crate) fn open_dir(root: BorrowedFd<'_>, path: &Path) -> Result<OwnedFd, Errno> {
    open_in_root(root, relative(path), OFlag::O_DIRECTORY)
}

/// `mkdir -p` inside `root`: creates each missing component with `mode`,
/// resolving the path so far from `root` each time (so a symlink planted
/// halfway down still cannot lead outside). Returns an `O_PATH` fd for the
/// final directory.
pub(crate) fn mkdir_all(root: BorrowedFd<'_>, path: &Path, mode: Mode) -> Result<OwnedFd, Errno> {
    let mut so_far = PathBuf::new();
    let mut dir = open_dir(root, Path::new("."))?;
    for c in relative(path).components() {
        let name: &OsStr = match c {
            Component::Normal(n) => n,
            Component::CurDir | Component::RootDir => continue,
            // Callers pass cleaned paths; `..` would make "create the
            // missing component" meaningless.
            Component::ParentDir | Component::Prefix(_) => return Err(Errno::EINVAL),
        };
        so_far.push(name);
        dir = match open_dir(root, &so_far) {
            Ok(fd) => fd,
            Err(Errno::ENOENT) => {
                // `name` is a single component and `dir` the directory we
                // just resolved safely, so this creates exactly one entry
                // right there.
                match nix::sys::stat::mkdirat(&dir, name, mode) {
                    Ok(()) | Err(Errno::EEXIST) => {}
                    Err(e) => return Err(e),
                }
                open_dir(root, &so_far)?
            }
            Err(e) => return Err(e),
        };
    }
    Ok(dir)
}

/// Finds (or creates) the mount point `dest` inside `root` and returns an
/// `O_PATH` fd for it. `dir` says whether it must be a directory (most
/// mounts) or a file (bind mounts of files, like `/etc/resolv.conf`).
pub(crate) fn ensure_mount_target(root: BorrowedFd<'_>, dest: &Path, dir: bool) -> Result<OwnedFd, Errno> {
    let rel = relative(dest);
    let fd = match open_in_root(root, rel, OFlag::empty()) {
        Ok(fd) => fd,
        Err(Errno::ENOENT) if dir => mkdir_all(root, rel, Mode::from_bits_truncate(0o755))?,
        Err(Errno::ENOENT) => {
            let parent = mkdir_all(root, rel.parent().unwrap_or(Path::new("")), Mode::from_bits_truncate(0o755))?;
            let name = rel.file_name().ok_or(Errno::EINVAL)?;
            // O_CREAT without O_EXCL: if something appeared meanwhile, we
            // use it; the type check below still applies.
            let f = nix::fcntl::openat(
                &parent,
                name,
                OFlag::O_CREAT | OFlag::O_WRONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                Mode::from_bits_truncate(0o644),
            )?;
            drop(f);
            open_in_root(root, rel, OFlag::empty())?
        }
        Err(e) => return Err(e),
    };
    let st = fstatx(fd.as_fd())?;
    match (dir, st.is_dir()) {
        (true, false) => Err(Errno::ENOTDIR),
        (false, true) => Err(Errno::EISDIR),
        _ => Ok(fd),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root_fd(p: &Path) -> OwnedFd {
        nix::fcntl::open(p, OFlag::O_PATH | OFlag::O_DIRECTORY, Mode::empty()).unwrap()
    }

    #[test]
    fn mkdir_all_stays_inside_through_absolute_symlinks() {
        let outside = tempfile::tempdir().unwrap();
        let root = tempfile::tempdir().unwrap();
        // `evil` points at the *host* path of `outside`...
        std::os::unix::fs::symlink(outside.path(), root.path().join("evil")).unwrap();
        let r = root_fd(root.path());
        // ...which inside the root means `<root>/<outside path>`. That doesn't
        // exist yet, so the link dangles: like `mkdir -p`, fail (EEXIST on the
        // link, then ENOENT through it) rather than guess.
        assert!(mkdir_all(r.as_fd(), Path::new("/evil/sub"), Mode::from_bits_truncate(0o755)).is_err());
        // Once the link's target exists *inside* the root, it is followed there.
        let inside = root.path().join(outside.path().strip_prefix("/").unwrap());
        std::fs::create_dir_all(&inside).unwrap();
        mkdir_all(r.as_fd(), Path::new("/evil/sub"), Mode::from_bits_truncate(0o755)).unwrap();
        assert!(inside.join("sub").is_dir(), "{} missing", inside.join("sub").display());
        // Either way, nothing was ever created in the real `outside`.
        assert!(std::fs::read_dir(outside.path()).unwrap().next().is_none(), "escaped the root");
    }

    #[test]
    fn creates_file_targets_and_checks_types() {
        let root = tempfile::tempdir().unwrap();
        let r = root_fd(root.path());
        ensure_mount_target(r.as_fd(), Path::new("/etc/resolv.conf"), false).unwrap();
        assert!(root.path().join("etc/resolv.conf").is_file());
        assert_eq!(ensure_mount_target(r.as_fd(), Path::new("/etc"), false).unwrap_err(), Errno::EISDIR);
        assert_eq!(ensure_mount_target(r.as_fd(), Path::new("/etc/resolv.conf"), true).unwrap_err(), Errno::ENOTDIR);
        ensure_mount_target(r.as_fd(), Path::new("/proc"), true).unwrap();
        assert!(root.path().join("proc").is_dir());
    }
}

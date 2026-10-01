//! `safe_remove_tree`: `rm -rf` that cannot escape into a mount.
//!
//! The classic mistake: a container's bind-mounted volume (say `/home/you`)
//! is still mounted under the container directory when the daemon deletes
//! that directory, and `rm -rf` happily recurses into your home. Comparing
//! `st_dev` doesn't save you: a bind mount of the *same filesystem* has the
//! same `st_dev`, and on this host `/home` and `/var/lib` share `/dev/sda3`.
//!
//! So this function:
//! 1. refuses outright if `/proc/self/mountinfo` lists any mount at or under
//!    the path (the caller must unmount first, deepest first;
//!    see [`unmount_under`]);
//! 2. walks with `openat2(RESOLVE_NO_XDEV | RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH)`,
//!    so it never follows a symlink or crosses a mount while descending;
//! 3. compares `statx` **mount IDs** (unique per mount, bind or not) for every
//!    entry against the root's mount ID before touching it;
//! 4. deletes with `unlinkat` relative to the directory fd it already holds.

use std::ffi::OsStr;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use nix::fcntl::OFlag;
use nix::sys::stat::Mode;
use nix::unistd::UnlinkatFlags;

use crate::fs::{ResolveFlags, openat2, statx};
use crate::mountinfo;
use crate::{Errno, Result};

const MAX_DEPTH: usize = 4096;

/// Why `safe_remove_tree` refused.
#[derive(Debug)]
pub enum RemoveError {
    /// A mount is still active at or below the path.
    MountsPresent(Vec<std::path::PathBuf>),
    /// An entry lives on a different mount than the root (a mount appeared
    /// while we were walking, or the path is on an unexpected mount).
    CrossesMount(std::path::PathBuf),
    /// The path isn't absolute or is `/`.
    BadPath,
    Sys(Errno, std::path::PathBuf),
}

impl std::fmt::Display for RemoveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RemoveError::MountsPresent(m) => {
                write!(f, "refusing to delete: mounts still present under the path: {m:?}")
            }
            RemoveError::CrossesMount(p) => write!(f, "refusing to delete: {} is on a different mount", p.display()),
            RemoveError::BadPath => write!(f, "refusing to delete: path must be absolute and not /"),
            RemoveError::Sys(e, p) => write!(f, "{}: {e}", p.display()),
        }
    }
}

impl std::error::Error for RemoveError {}

/// Recursively deletes `path`. Missing paths are not an error.
pub fn safe_remove_tree(path: &Path) -> std::result::Result<(), RemoveError> {
    if !path.is_absolute() || path.parent().is_none() {
        return Err(RemoveError::BadPath);
    }
    let sys = |e: Errno| RemoveError::Sys(e, path.to_owned());
    // (1) mountinfo check. Mount points are listed without symlinks, so
    // resolve ours the same way first.
    let canon = match std::fs::canonicalize(path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(sys(Errno::from_raw(e.raw_os_error().unwrap_or(libc::EIO)))),
    };
    if canon != path {
        // `path` itself went through a symlink; refuse rather than guess.
        return Err(RemoveError::BadPath);
    }
    let mounts = mountinfo::read_self().map_err(|_| sys(Errno::EIO))?;
    let under: Vec<_> = mountinfo::mounts_under(&mounts, path).into_iter().map(|m| m.mount_point).collect();
    if !under.is_empty() {
        return Err(RemoveError::MountsPresent(under));
    }

    let parent = path.parent().ok_or(RemoveError::BadPath)?;
    let name = path.file_name().ok_or(RemoveError::BadPath)?;
    let parent_fd = openat2(None, parent, OFlag::O_PATH | OFlag::O_DIRECTORY, Mode::empty(), ResolveFlags::NO_SYMLINKS)
        .map_err(sys)?;
    let st = statx(Some(parent_fd.as_fd()), name, libc::AT_SYMLINK_NOFOLLOW).map_err(sys)?;
    if !st.is_dir() {
        return nix::unistd::unlinkat(&parent_fd, name, UnlinkatFlags::NoRemoveDir).map_err(sys);
    }
    let root = open_dir_beneath(parent_fd.as_fd(), name).map_err(sys)?;
    let root_mnt = crate::fs::fstatx(root.as_fd()).map_err(sys)?.mnt_id;
    remove_contents(root, root_mnt, path, 0)?;
    nix::unistd::unlinkat(&parent_fd, name, UnlinkatFlags::RemoveDir).map_err(sys)
}

/// Recursively deletes the entry `name` in the directory `dir`: a file,
/// symlink, or whole directory tree, never following a symlink and never
/// leaving `dir`'s mount.
///
/// Unlike [`safe_remove_tree`] this takes no path and doesn't consult
/// mountinfo, so it is for trees only the caller writes to, such as an image
/// layer being unpacked, where a later archive entry replaces a directory
/// with a file. The mount-ID comparison still stops it at any mount.
pub fn remove_tree_at(dir: BorrowedFd<'_>, name: &OsStr) -> std::result::Result<(), RemoveError> {
    let shown = Path::new(name);
    let sys = |e: Errno| RemoveError::Sys(e, shown.to_owned());
    if name.is_empty() || name == "." || name == ".." || name.as_bytes().contains(&b'/') {
        return Err(RemoveError::BadPath);
    }
    let st = statx(Some(dir), name, libc::AT_SYMLINK_NOFOLLOW).map_err(sys)?;
    if !st.is_dir() {
        return nix::unistd::unlinkat(dir, name, UnlinkatFlags::NoRemoveDir).map_err(sys);
    }
    let mnt = crate::fs::fstatx(dir).map_err(sys)?.mnt_id;
    if st.mnt_id != mnt {
        return Err(RemoveError::CrossesMount(shown.to_owned()));
    }
    let sub = open_dir_beneath(dir, name).map_err(|e| match e {
        Errno::EXDEV => RemoveError::CrossesMount(shown.to_owned()),
        e => sys(e),
    })?;
    remove_contents(sub, mnt, shown, 0)?;
    nix::unistd::unlinkat(dir, name, UnlinkatFlags::RemoveDir).map_err(sys)
}

fn open_dir_beneath(dir: BorrowedFd<'_>, name: &OsStr) -> Result<OwnedFd> {
    openat2(
        Some(dir),
        name,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW,
        Mode::empty(),
        ResolveFlags::NO_XDEV | ResolveFlags::NO_SYMLINKS | ResolveFlags::BENEATH,
    )
}

fn remove_contents(dir: OwnedFd, root_mnt: u64, path: &Path, depth: usize) -> std::result::Result<(), RemoveError> {
    if depth > MAX_DEPTH {
        return Err(RemoveError::Sys(Errno::ELOOP, path.to_owned()));
    }
    let sys = |e: Errno, p: &Path| RemoveError::Sys(e, p.to_owned());
    // Collect names first: deleting while iterating a directory stream is
    // allowed but may skip entries.
    let names: Vec<Vec<u8>> = {
        let dup = dir.try_clone().map_err(|_| sys(Errno::EMFILE, path))?;
        let mut d = nix::dir::Dir::from_fd(dup).map_err(|e| sys(e, path))?;
        d.iter()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_bytes().to_vec())
            .filter(|n| n != b"." && n != b"..")
            .collect()
    };
    for raw in names {
        let name = OsStr::from_bytes(&raw);
        let child = path.join(name);
        let st = match statx(Some(dir.as_fd()), name, libc::AT_SYMLINK_NOFOLLOW) {
            Ok(s) => s,
            Err(Errno::ENOENT) => continue,
            Err(e) => return Err(sys(e, &child)),
        };
        if st.mnt_id != root_mnt {
            return Err(RemoveError::CrossesMount(child));
        }
        if st.is_dir() {
            let sub = open_dir_beneath(dir.as_fd(), name).map_err(|e| match e {
                Errno::EXDEV => RemoveError::CrossesMount(child.clone()),
                e => sys(e, &child),
            })?;
            remove_contents(sub, root_mnt, &child, depth + 1)?;
            nix::unistd::unlinkat(&dir, name, UnlinkatFlags::RemoveDir).map_err(|e| sys(e, &child))?;
        } else {
            nix::unistd::unlinkat(&dir, name, UnlinkatFlags::NoRemoveDir).map_err(|e| sys(e, &child))?;
        }
    }
    Ok(())
}

/// Unmounts every mount at or below `path`, deepest first, with
/// `MNT_DETACH`. Returns the mount points it unmounted.
pub fn unmount_under(path: &Path) -> Result<Vec<std::path::PathBuf>> {
    let mut done = Vec::new();
    // Re-read after each pass: unmounting can reveal mounts that were
    // stacked underneath.
    for _ in 0..64 {
        let mounts = mountinfo::read_self().map_err(|_| Errno::EIO)?;
        let under = mountinfo::mounts_under(&mounts, path);
        if under.is_empty() {
            return Ok(done);
        }
        for m in under {
            match crate::mount::umount2(&m.mount_point, nix::mount::MntFlags::MNT_DETACH) {
                Ok(()) | Err(Errno::EINVAL) | Err(Errno::ENOENT) => done.push(m.mount_point),
                Err(e) => return Err(e),
            }
        }
    }
    Err(Errno::EBUSY)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removes_plain_tree_but_not_symlink_targets() {
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("precious"), "keep me").unwrap();

        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim");
        std::fs::create_dir_all(victim.join("a/b/c")).unwrap();
        std::fs::write(victim.join("a/b/c/file"), "x").unwrap();
        std::os::unix::fs::symlink(outside.path(), victim.join("a/escape")).unwrap();

        safe_remove_tree(&victim.canonicalize().unwrap()).unwrap();
        assert!(!victim.exists());
        assert_eq!(std::fs::read_to_string(outside.path().join("precious")).unwrap(), "keep me");
    }

    #[test]
    fn rejects_relative_and_root() {
        assert!(matches!(safe_remove_tree(Path::new("relative")), Err(RemoveError::BadPath)));
        assert!(matches!(safe_remove_tree(Path::new("/")), Err(RemoveError::BadPath)));
    }

    #[test]
    fn remove_tree_at_deletes_entries_of_any_type_without_following_links() {
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("precious"), "keep me").unwrap();
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("tree/a/b")).unwrap();
        std::fs::write(dir.path().join("tree/a/b/f"), "x").unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join("tree/a/escape")).unwrap();
        std::fs::write(dir.path().join("file"), "x").unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join("link")).unwrap();
        let fd = nix::fcntl::open(dir.path(), OFlag::O_RDONLY | OFlag::O_DIRECTORY, Mode::empty()).unwrap();
        for name in ["tree", "file", "link"] {
            remove_tree_at(fd.as_fd(), OsStr::new(name)).unwrap();
            assert!(dir.path().join(name).symlink_metadata().is_err(), "{name} still exists");
        }
        assert_eq!(std::fs::read_to_string(outside.path().join("precious")).unwrap(), "keep me");
        for bad in ["", ".", "..", "a/b"] {
            assert!(matches!(remove_tree_at(fd.as_fd(), OsStr::new(bad)), Err(RemoveError::BadPath)), "{bad:?}");
        }
    }

    #[test]
    fn refuses_when_mount_present() {
        // /proc has mounts under it (at least itself) on any Linux host.
        assert!(matches!(safe_remove_tree(Path::new("/proc")), Err(RemoveError::MountsPresent(_))));
    }
}

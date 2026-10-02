//! Copy-up: an empty volume gets the image's files.
//!
//! When a container mounts a volume that is empty over a path where its
//! image has files (`-v data:/var/lib/postgresql/data`, or the image's own
//! `VOLUME`), Docker first copies those files into the volume, so the
//! program finds what its image put there, and from then on it lives in the
//! volume. The daemon does the same at each start, while the container's
//! root filesystem is mounted but no container process exists yet.
//!
//! The source is image content (and the container's own changes): it is
//! untrusted, and the daemon is root. So the copy is made the way unpacking
//! is (`unpack`):
//!
//! - **the source directory** is resolved inside the root filesystem
//!   (`openat2(RESOLVE_IN_ROOT)`: a symlink such as `/var/run → /run`
//!   leads to the container's `/run`, never the host's);
//! - **below it, nothing is followed**: every entry is examined with
//!   `AT_SYMLINK_NOFOLLOW` and opened with `O_NOFOLLOW` relative to its
//!   parent's fd, so a symlink is copied as a symlink, whatever it points
//!   to;
//! - **the destination** is written only through fds below the volume's
//!   own directory, each entry created exclusively (`O_EXCL`, `mkdirat`,
//!   `symlinkat`, `mknodat`), never through a path;
//! - **kept**: contents, owner (translated by `map_owner`), mode (after
//!   the owner: `chown` clears setuid bits), extended attributes (after the
//!   owner: `chown` clears `security.capability`; overlay's own
//!   `trusted.overlay.*`/`user.overlay.*` are skipped), access and
//!   modification times (directories' last, after their contents), hard
//!   links between files of the copied tree, FIFOs;
//! - **skipped** (and listed): device nodes and sockets;
//! - the volume's directory itself takes the source directory's owner and
//!   mode (Docker's `copyOwnership`).
//!
//! The walk uses its own stack, not recursion, so a deep tree can't
//! exhaust the daemon's thread stack.

use std::os::fd::BorrowedFd;
use std::path::{Path, PathBuf};

use crate::error::Result;

/// What a copy-up did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CopyUp {
    /// False: the root filesystem has no directory at that path, so there
    /// was nothing to copy.
    pub copied: bool,
    /// Entries created below the volume's directory.
    pub entries: u64,
    /// Bytes of file content copied.
    pub bytes: u64,
    /// Device nodes and sockets left out, relative to the copied directory.
    pub skipped: Vec<PathBuf>,
}

/// Copies the directory at `path` (absolute, in the container) of the root
/// filesystem `root` into `dest`, the volume's directory, which should be
/// empty ([`is_empty`]; an entry that already exists there is an error).
/// `map_owner` turns owners as seen through `root` into those to write
/// (the identity, except under `--userns=remap`, whose idmapped root
/// filesystem shows the image's owners shifted by 1000000 while volumes
/// hold them unshifted).
pub fn copy_up(
    root: BorrowedFd<'_>,
    path: &Path,
    dest: BorrowedFd<'_>,
    map_owner: &dyn Fn(u32, u32) -> (u32, u32),
) -> Result<CopyUp> {
    let _ = (root, path, dest, map_owner);
    unimplemented!()
}

/// Has the directory `dir` no entries (other than `.` and `..`)?
pub fn is_empty(dir: BorrowedFd<'_>) -> Result<bool> {
    let _ = dir;
    unimplemented!()
}

//! `COPY` and `ADD`: files from a build context, or from another stage's
//! filesystem, into the root filesystem a build step is making.
//!
//! The builder mounts the step's root filesystem (an overlay of the image
//! so far, with an empty upper directory), and this module writes into it;
//! the upper directory then becomes the step's layer (`diff`). Both sides
//! are untrusted in their own way: the destination is an image's tree,
//! whose symlinks its author chose (`/app → /etc`), and the source is a
//! user's directory, whose symlinks may point anywhere on the host. The
//! daemon is root. So, as in `unpack` and `copyup`:
//!
//! - **destination paths** are resolved inside the root filesystem
//!   (`openat2(RESOLVE_IN_ROOT)`): `/app/x` through `/app → /etc` is the
//!   *image's* `/etc/x`; missing directories are made one component at a
//!   time, relative to the fd of the last one;
//! - **source paths** are resolved inside their root the same way (a
//!   symlink in the context to `/etc` leads to the context's `etc`, if it
//!   has one, never the host's); the named source itself is followed (within
//!   its root), what is below it never is: a symlink in a copied directory is
//!   copied as a symlink;
//! - every entry is created relative to its parent's fd, an existing one of
//!   the same name replaced (a directory merges with a directory; anything
//!   else is removed first, with `remove_tree_at`);
//! - files are opened `O_NOFOLLOW | O_NONBLOCK` and checked to be the inode
//!   examined; FIFOs aren't opened; device nodes and sockets are skipped.
//!
//! ## Docker's rules
//!
//! - Each source is a path relative to the source root (a leading `/` is
//!   the root too: the build context can't be left), and may hold wildcards
//!   (`*`, `?`, `[…]`, Go's `filepath.Match`, per component). A source that
//!   matches nothing is an error, naming it.
//! - The destination is absolute, or relative to the working directory; a
//!   trailing `/` makes it a directory. With more than one source (or a
//!   wildcard matching more than one), it must be one.
//! - A source **directory** is copied by its *contents* into the
//!   destination directory, which is created if missing; directories merge.
//! - A source **file** goes to `<dest>/<its name>` when the destination ends
//!   in `/` or is an existing directory (in the root filesystem, after
//!   resolving it), else to the destination path itself.
//! - Copies keep their source's mode (`spec.mode`, `--chmod`, replaces it
//!   for every file and directory copied), modification time and extended
//!   attributes (overlay's own excepted); their owner is `spec.owner`
//!   (`0:0` unless `--chown`). Directories the copy has to create, the
//!   destination's missing parents included, are `0755` and also
//!   `spec.owner`'s. Hard links between copied files stay links.
//! - `ADD` (`spec.extract_archives`): a source that is a tar archive
//!   (plain, gzip or zstd, told by its content, not its name) is extracted
//!   into the destination directory instead of copied, as `tar -x` would
//!   (`unpack::unpack_with` without whiteouts, confined to that directory),
//!   keeping the archive's owners and modes. Anything else is copied as by
//!   `COPY`. (URLs are refused before this module is reached.)
//!
//! Unprivileged (the unit tests), owners can't be set: the copies keep the
//! caller's, as `unpack` does.
//!
//! ## The cache key
//!
//! [`digest`] hashes what [`copy`] would copy, with the same matching:
//! every entry's path relative to its source, type, mode, size and content
//! (a SHA-256 of a file's bytes), a symlink's target; plus the
//! destination, owner and `--chmod`. Not modification times and not the
//! source's owners (the copy sets its own): touching a file doesn't make a
//! cached `COPY` run again, changing its content does.

use std::os::fd::BorrowedFd;
use std::path::PathBuf;

use crate::digest::Digest;
use crate::error::Result;

/// One `COPY` or `ADD`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopySpec {
    /// The sources, as the instruction gives them (variables expanded).
    pub sources: Vec<String>,
    /// The destination, as given: absolute, or relative to `workdir`.
    pub dest: String,
    /// The image's working directory, absolute.
    pub workdir: String,
    /// The owner of every copy and of the directories made (`--chown`).
    pub owner: (u32, u32),
    /// `--chmod`: the mode of every file and directory copied.
    pub mode: Option<u32>,
    /// `ADD`: extract tar archives instead of copying them.
    pub extract_archives: bool,
}

/// What [`copy`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CopyReport {
    /// Entries created or replaced (directories merged into count too).
    pub entries: u64,
    /// Bytes of file content copied or extracted.
    pub bytes: u64,
    /// Archives extracted (`ADD`).
    pub extracted: u64,
    /// Device nodes and sockets left out, as source paths.
    pub skipped: Vec<PathBuf>,
}

/// Copies `spec.sources` from the source root `src` (the build context's
/// directory, or another stage's mounted root filesystem) into the root
/// filesystem `dest` (see the module docs).
pub fn copy(src: BorrowedFd<'_>, dest: BorrowedFd<'_>, spec: &CopySpec) -> Result<CopyReport> {
    let _ = (src, dest, spec);
    unimplemented!("copy: agent D")
}

/// A digest of what [`copy`] would copy from `src` (see the module docs):
/// the build cache's key for the step.
pub fn digest(src: BorrowedFd<'_>, spec: &CopySpec) -> Result<Digest> {
    let _ = (src, spec);
    unimplemented!("digest: agent D")
}

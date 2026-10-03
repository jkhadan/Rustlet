//! Commit: what a container changed, as a layer.
//!
//! A container's changes are all in its overlay's upper directory
//! (`containers/<id>/upper`, see `rootfs`): files it created or modified
//! (whole, overlay copies a file up before the first write), directories
//! it created or that hold changed entries, a **whiteout** (a character
//! device 0:0) for each entry of a lower layer it deleted, and the
//! attribute `trusted.overlay.opaque=y` on a directory it deleted and made
//! again (the lower layers' entries of it are gone). A layer says the same
//! in a tar archive, the other way round from unpacking (`unpack`):
//!
//! ```text
//!  upper/                                 layer.tar
//!  ├─ etc/hostname     (file)        ──►  etc/  etc/hostname
//!  ├─ tmp/old          (char 0:0)    ──►  tmp/  tmp/.wh.old
//!  └─ var/cache/       (opaque=y)    ──►  var/  var/cache/  var/cache/.wh..wh..opq
//! ```
//!
//! `rustlet commit` and every `RUN`, `COPY` and `ADD` of a build go through
//! [`commit_layer`]: the archive, gzipped, becomes a blob of the store,
//! whose uncompressed digest is the layer's diff ID.
//!
//! ## Rules
//!
//! - **Deterministic**: entries in byte order of their names, parents
//!   before children (a directory's entry, then its opaque marker if it has
//!   one, then its entries); names relative, without `./`, directories
//!   ending in `/`; no user or group names; header times in whole seconds.
//!   The same upper directory always makes the same bytes.
//! - **Never followed**: a symlink is stored as one; every entry is
//!   examined relative to its parent's fd (`AT_SYMLINK_NOFOLLOW`), and a
//!   file is opened `O_NOFOLLOW | O_NONBLOCK` and checked to be the inode
//!   that was examined; FIFOs are never opened. A file must still have its
//!   size when read (a paused or stopped container's upper doesn't change);
//!   otherwise the commit fails rather than write a wrong header.
//! - **Whiteouts** become empty regular files `.wh.<name>`. Overlay makes
//!   them as hard links to one inode in `work/work`, so they are *never*
//!   tar hard links of each other. **Opaque** directories (the `y` value;
//!   `x` means something else) get a `.wh..wh..opq` entry.
//! - **Hard links** between other files of the upper directory stay hard
//!   links: the first name (in the archive's order) is the file, later ones
//!   are link entries to it.
//! - **Attributes**: every extended attribute except overlay's own
//!   (`trusted.overlay.*`, `user.overlay.*`: opaque markers, `origin`,
//!   `impure`, `uuid`…), as PAX `SCHILY.xattr.<name>` records. Owners are
//!   translated by [`DiffOptions::map_owner`] (an upper directory of a
//!   `--userns=remap` container holds host ids: [`unmap_remap`]), and so
//!   are the ids inside a version 3 `security.capability` and POSIX ACLs,
//!   as `copyup` does.
//! - **Left out** (listed in [`DiffReport::skipped`]): device nodes other
//!   than whiteouts, sockets, and [`DiffOptions::skip`]'s paths with
//!   everything below them: a container's mount points (`/proc`, `/dev`,
//!   `/etc/resolv.conf`, its volumes' targets) are made by the runtime when
//!   the image lacks them, and are no change of the container's; what is
//!   below one was hidden by the mount.
//! - PAX records for what ustar headers can't hold: names over 100 bytes,
//!   link targets over 100, ids over 2097151, sizes over 8 GiB.
//! - The walk uses its own stack (depth capped, as `copyup`'s), not
//!   recursion.

use std::io::Write;
use std::path::{Path, PathBuf};

use oci_spec::image::Descriptor;

use crate::content::ContentStore;
use crate::digest::Digest;
use crate::error::Result;

/// How [`diff`] reads an upper directory.
pub struct DiffOptions<'a> {
    /// Absolute paths in the container that were mount points while it
    /// ran: left out, with everything below them.
    pub skip: &'a [PathBuf],
    /// Owners as stored in the upper directory → owners in the layer.
    pub map_owner: &'a dyn Fn(u32, u32) -> (u32, u32),
}

impl Default for DiffOptions<'_> {
    fn default() -> Self {
        DiffOptions { skip: &[], map_owner: &|uid, gid| (uid, gid) }
    }
}

/// What [`diff`] wrote.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DiffReport {
    /// Archive entries written (whiteout and opaque markers included).
    pub entries: u64,
    /// Bytes of file content.
    pub bytes: u64,
    pub whiteouts: u64,
    pub opaque_dirs: u64,
    /// Entries left out, as absolute paths in the container.
    pub skipped: Vec<String>,
    /// The digest and size of the archive: the layer's diff ID.
    pub diff_id: Option<Digest>,
    pub tar_size: u64,
}

/// A layer [`commit_layer`] stored.
#[derive(Debug, Clone)]
pub struct CommittedLayer {
    /// The blob (`application/vnd.oci.image.layer.v1.tar+gzip`).
    pub descriptor: Descriptor,
    pub diff_id: Digest,
    pub report: DiffReport,
}

/// Writes the changes recorded in the overlay upper directory `upper` as an
/// uncompressed layer archive to `out` (see the module docs).
pub fn diff(upper: &Path, out: &mut dyn Write, options: &DiffOptions<'_>) -> Result<DiffReport> {
    let _ = (upper, out, options);
    unimplemented!("diff: agent C")
}

/// [`diff`], gzipped into the store as a layer blob.
pub fn commit_layer(content: &ContentStore, upper: &Path, options: &DiffOptions<'_>) -> Result<CommittedLayer> {
    let _ = (content, upper, options);
    unimplemented!("commit_layer: agent C")
}

/// The owners of a `--userns=remap` container's upper directory, as its
/// image would have them: host ids 1000000–1065535 are container ids
/// 0–65535; anything else is an id the container saw as unmapped, 65534
/// (`nobody`).
pub fn unmap_remap(uid: u32, gid: u32) -> (u32, u32) {
    let back = |id: u32| {
        id.checked_sub(rustlet_runtime::spec::REMAP_HOST_ID)
            .filter(|&c| c < rustlet_runtime::spec::REMAP_SIZE)
            .unwrap_or(65534)
    };
    (back(uid), back(gid))
}

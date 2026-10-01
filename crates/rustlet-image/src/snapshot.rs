//! Snapshots: unpacked layers, keyed by chain ID.
//!
//! ```text
//! snapshots/
//! ├─ 4693057ce236…/            chain ID (hex) of an image's bottom layer
//! │  ├─ fs/                    the layer's files: an overlay lower directory
//! │  └─ snapshot.json          chain ID, diff ID, parent, blob, size, …
//! ├─ 9b1e4c0d27fa…/            the next layer up (its parent is the one above)
//! └─ .tmp-…/                   an unpack in progress
//! ```
//!
//! A snapshot holds *one* layer's files: whiteouts and opaque markers in it
//! refer to the snapshots below, which is why the key is the chain ID (the
//! layer *and* its parents) rather than the diff ID alone. The container's
//! rootfs is an overlay of an image's snapshots (`rootfs`).
//!
//! Unpacking happens in `.tmp-<random>/` and is renamed into place only when
//! the layer's blob digest and diff ID both check out, so a snapshot
//! directory that exists is complete and correct.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::content::ContentStore;
use crate::digest::Digest;
use crate::error::Result;
use crate::image::{Image, Layer};
use crate::unpack::UnpackReport;

/// What `snapshot.json` records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotInfo {
    pub chain_id: Digest,
    pub diff_id: Digest,
    /// The chain ID of the snapshot below, if any.
    pub parent: Option<Digest>,
    /// The compressed blob it was unpacked from.
    pub blob: Digest,
    /// Bytes of regular-file data in the layer.
    pub size: u64,
    /// Archive entries processed.
    pub entries: u64,
    /// RFC 3339 time of the unpack.
    pub created: String,
}

/// An unpacked layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub info: SnapshotInfo,
    /// `snapshots/<chain ID hex>`.
    pub dir: PathBuf,
}

impl Snapshot {
    /// The layer's files (an overlay lower directory).
    pub fn fs(&self) -> PathBuf {
        self.dir.join("fs")
    }
}

/// What [`Snapshotter::ensure`] reports per layer.
#[derive(Debug, Clone)]
pub enum SnapshotEvent<'a> {
    /// The snapshot already existed.
    Exists { layer: &'a Layer },
    /// Unpacking starts.
    Unpacking { layer: &'a Layer },
    /// Unpacked and verified.
    Unpacked { layer: &'a Layer, report: &'a UnpackReport },
}

/// The `snapshots/` directory.
#[derive(Debug, Clone)]
pub struct Snapshotter {
    dir: PathBuf,
}

impl Snapshotter {
    /// Opens `dir` (it must exist; `Store::open` creates it).
    pub fn open(dir: PathBuf) -> Result<Snapshotter> {
        Ok(Snapshotter { dir })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The snapshot for `chain_id`, if it exists.
    pub fn get(&self, chain_id: &Digest) -> Result<Option<Snapshot>> {
        let _ = chain_id;
        unimplemented!("snapshot::get")
    }

    /// Every snapshot, sorted by chain ID.
    pub fn list(&self) -> Result<Vec<Snapshot>> {
        unimplemented!("snapshot::list")
    }

    /// Unpacks every layer of `image` that has no snapshot yet (bottom
    /// first, each verified against its blob digest and diff ID) and returns
    /// all of the image's snapshots, bottom first. Needs root: unpacking
    /// preserves owners, creates whiteouts and sets `trusted.*` attributes.
    pub fn ensure(
        &self,
        content: &ContentStore,
        image: &Image,
        events: &mut dyn FnMut(SnapshotEvent<'_>),
    ) -> Result<Vec<Snapshot>> {
        let _ = (content, image, events);
        unimplemented!("snapshot::ensure")
    }
}

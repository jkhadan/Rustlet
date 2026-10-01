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

use std::os::fd::AsFd;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use nix::fcntl::OFlag;
use nix::sys::stat::Mode;
use serde::{Deserialize, Serialize};

use crate::content::ContentStore;
use crate::digest::Digest;
use crate::error::{Context, Error, Result};
use crate::image::{Image, Layer};
use crate::unpack::{UnpackReport, unpack};

const INFO: &str = "snapshot.json";

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
        // Canonical, because failed unpacks are removed with
        // `safe_remove_tree`, which refuses paths that go through symlinks.
        let dir = dir.canonicalize().with_context(|| format!("open {}", dir.display()))?;
        Ok(Snapshotter { dir })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The snapshot for `chain_id`, if it exists.
    pub fn get(&self, chain_id: &Digest) -> Result<Option<Snapshot>> {
        let dir = self.dir.join(chain_id.hex());
        let info_path = dir.join(INFO);
        let bytes = match std::fs::read(&info_path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e).with_context(|| format!("read {}", info_path.display())),
        };
        let info: SnapshotInfo =
            serde_json::from_slice(&bytes).with_context(|| format!("parse {}", info_path.display()))?;
        if &info.chain_id != chain_id {
            return Err(Error::invalid(format!("{} says it is snapshot {}", info_path.display(), info.chain_id)));
        }
        if !dir.join("fs").is_dir() {
            return Err(Error::invalid(format!("snapshot {} has no fs/ directory", dir.display())));
        }
        Ok(Some(Snapshot { info, dir }))
    }

    /// Every snapshot, sorted by chain ID. In-progress unpacks (`.tmp-*`)
    /// and anything not named by a chain ID are skipped.
    pub fn list(&self) -> Result<Vec<Snapshot>> {
        let mut out = Vec::new();
        for entry in std::fs::read_dir(&self.dir).with_context(|| format!("list {}", self.dir.display()))? {
            let entry = entry.with_context(|| format!("list {}", self.dir.display()))?;
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else { continue };
            let Ok(chain_id) = Digest::from_hex(&name) else { continue };
            if let Some(s) = self.get(&chain_id)? {
                out.push(s);
            }
        }
        out.sort_by(|a, b| a.info.chain_id.cmp(&b.info.chain_id));
        Ok(out)
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
        let mut out = Vec::with_capacity(image.layers.len());
        for layer in &image.layers {
            match self.get(&layer.chain_id) {
                Ok(Some(s)) => {
                    events(SnapshotEvent::Exists { layer });
                    out.push(s);
                    continue;
                }
                Ok(None) => {}
                // A directory under the chain ID whose snapshot.json doesn't
                // parse: unpacking again replaces it (see `unpack_layer`).
                Err(e @ (Error::Json { .. } | Error::Invalid(_))) => {
                    tracing::warn!("snapshot {} is unusable, unpacking it again: {e}", layer.chain_id);
                }
                Err(e) => return Err(e),
            }
            events(SnapshotEvent::Unpacking { layer });
            let (snapshot, report) = self.unpack_layer(content, layer)?;
            events(SnapshotEvent::Unpacked { layer, report: &report });
            out.push(snapshot);
        }
        Ok(out)
    }

    /// Unpacks one layer into `.tmp-…/fs`, verifies it, and renames the
    /// directory to the chain ID. If another unpack of the same layer got
    /// there first, its result is used and ours discarded: same chain ID,
    /// same verified content.
    fn unpack_layer(&self, content: &ContentStore, layer: &Layer) -> Result<(Snapshot, UnpackReport)> {
        static N: AtomicU64 = AtomicU64::new(0);
        let tmp = self.dir.join(format!(
            ".tmp-{}-{}-{}",
            layer.chain_id.short(),
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::DirBuilder::new().mode(0o700).create(&tmp).with_context(|| format!("create {}", tmp.display()))?;
        let result = self.unpack_into(content, layer, &tmp);
        let info = match result {
            Ok(info) => info,
            Err(e) => {
                discard(&tmp);
                return Err(e);
            }
        };
        let (info, report) = info;
        let dest = self.dir.join(layer.chain_id.hex());
        if let Err(e) = self.publish(&tmp, &dest, &info.chain_id) {
            discard(&tmp);
            return Err(e);
        }
        let snapshot = self.get(&info.chain_id)?.ok_or_else(|| {
            Error::NotFound(format!("snapshot {} vanished right after it was unpacked", info.chain_id))
        })?;
        Ok((snapshot, report))
    }

    /// Renames the finished `tmp` to `dest`, durably. If `dest` exists:
    /// another unpack of the layer finished first (a usable snapshot: ours
    /// is dropped), or a crash left a directory without a usable
    /// `snapshot.json` (moved aside and deleted, then ours takes its place).
    fn publish(&self, tmp: &Path, dest: &Path, chain_id: &Digest) -> Result<()> {
        static N: AtomicU64 = AtomicU64::new(0);
        let rename = || std::fs::rename(tmp, dest).with_context(|| format!("move snapshot into {}", dest.display()));
        match std::fs::rename(tmp, dest) {
            Ok(()) => {}
            Err(e) if matches!(e.raw_os_error(), Some(libc::EEXIST | libc::ENOTEMPTY)) => {
                if matches!(self.get(chain_id), Ok(Some(_))) {
                    discard(tmp);
                    return Ok(());
                }
                let aside = self.dir.join(format!(
                    ".broken-{}-{}-{}",
                    chain_id.short(),
                    std::process::id(),
                    N.fetch_add(1, Ordering::Relaxed)
                ));
                tracing::warn!("replacing {}, which has no usable snapshot.json", dest.display());
                std::fs::rename(dest, &aside).with_context(|| format!("move {} aside", dest.display()))?;
                discard(&aside);
                rename()?;
            }
            Err(e) => return Err(e).with_context(|| format!("move snapshot into {}", dest.display())),
        }
        // The rename itself is only durable once the directory is synced.
        sync_dir(&self.dir)
    }

    fn unpack_into(&self, content: &ContentStore, layer: &Layer, tmp: &Path) -> Result<(SnapshotInfo, UnpackReport)> {
        let fs = tmp.join("fs");
        std::fs::DirBuilder::new().mode(0o755).create(&fs).with_context(|| format!("create {}", fs.display()))?;
        std::fs::set_permissions(&fs, std::fs::Permissions::from_mode(0o755))
            .with_context(|| format!("chmod {}", fs.display()))?;
        let fd = nix::fcntl::open(
            &fs,
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .with_context(|| format!("open {}", fs.display()))?;
        let blob = content.open_blob(&layer.blob)?;
        let report = unpack(blob, layer.compression, fd.as_fd())
            .map_err(|e| prefix(e, &format!("layer {}", layer.blob.short())))?;
        let mismatch = |what: &str, expected: String, actual: String| Error::DigestMismatch {
            what: format!("{what} of layer {}", layer.blob.short()),
            expected,
            actual,
        };
        let shown = |d: &Option<Digest>| d.as_ref().map_or_else(|| "nothing".into(), Digest::to_string);
        if report.blob_digest.as_ref() != Some(&layer.blob) {
            return Err(mismatch("blob digest", layer.blob.to_string(), shown(&report.blob_digest)));
        }
        if report.blob_size != layer.size {
            return Err(mismatch("blob size", layer.size.to_string(), report.blob_size.to_string()));
        }
        if report.diff_id.as_ref() != Some(&layer.diff_id) {
            return Err(mismatch("diff ID", layer.diff_id.to_string(), shown(&report.diff_id)));
        }
        let info = SnapshotInfo {
            chain_id: layer.chain_id.clone(),
            diff_id: layer.diff_id.clone(),
            parent: layer.parent.clone(),
            blob: layer.blob.clone(),
            size: report.bytes,
            entries: report.entries,
            created: chrono::Utc::now().to_rfc3339(),
        };
        let json = serde_json::to_vec_pretty(&info).context("serialize snapshot.json")?;
        std::fs::write(tmp.join(INFO), json).with_context(|| format!("write {}", tmp.join(INFO).display()))?;
        // Every file of the snapshot, snapshot.json included, is on disk
        // before the directory gets its final name: a snapshot that exists
        // after a crash is complete.
        nix::unistd::syncfs(&fd).with_context(|| format!("sync {}", fs.display()))?;
        Ok((info, report))
    }
}

/// `fsync` of a directory: makes the renames and creations in it durable.
pub(crate) fn sync_dir(dir: &Path) -> Result<()> {
    let fd = nix::fcntl::open(dir, OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC, Mode::empty())
        .with_context(|| format!("open {}", dir.display()))?;
    nix::unistd::fsync(&fd).with_context(|| format!("fsync {}", dir.display()))
}

/// Removes a failed or redundant unpack. Best effort: a leftover `.tmp-*`
/// is ignored by everything and removed by `scripts/cleanup.sh --purge`.
fn discard(tmp: &Path) {
    if let Err(e) = rustlet_sys::tree::safe_remove_tree(tmp) {
        tracing::warn!("could not remove {}: {e}", tmp.display());
    }
}

/// Adds `what` in front of an error's message.
fn prefix(e: Error, what: &str) -> Error {
    match e {
        Error::Invalid(m) => Error::Invalid(format!("{what}: {m}")),
        Error::Unsupported(m) => Error::Unsupported(format!("{what}: {m}")),
        Error::Io { context, source } => Error::Io { context: format!("{what}: {context}"), source },
        Error::Sys { context, errno } => Error::Sys { context: format!("{what}: {context}"), errno },
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::import::{config, import};
    use crate::store::Store;

    /// A one-layer image in a fresh store (unpacking works without root:
    /// files keep the caller as owner).
    fn store_with_image() -> (tempfile::TempDir, Store, Image) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("store")).unwrap();
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_size(2);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, "etc/hello", &b"hi"[..]).unwrap();
        let image =
            import(store.content(), "local/snap:1", &[b.into_inner().unwrap()], config(&["true"], &[], None).unwrap())
                .unwrap();
        (dir, store, image)
    }

    #[test]
    fn a_directory_left_by_a_crash_is_replaced() {
        let (_dir, store, image) = store_with_image();
        let snapshots = store.snapshots();
        let chain = &image.layers[0].chain_id;
        // What a crash between rename and metadata used to leave: the chain
        // ID's directory, without (or with a torn) snapshot.json.
        for torn in [None, Some(&b"{\"chain_id\": \"sha"[..])] {
            let dest = snapshots.dir().join(chain.hex());
            std::fs::create_dir_all(dest.join("fs/stale")).unwrap();
            if let Some(bytes) = torn {
                std::fs::write(dest.join(INFO), bytes).unwrap();
            }
            let got = snapshots.ensure(store.content(), &image, &mut |_| {}).unwrap();
            assert_eq!(std::fs::read_to_string(got[0].fs().join("etc/hello")).unwrap(), "hi");
            assert!(!got[0].fs().join("stale").exists(), "the leftover was replaced, not merged");
            let names: Vec<_> = std::fs::read_dir(snapshots.dir()).unwrap().map(|e| e.unwrap().file_name()).collect();
            assert_eq!(names, [std::ffi::OsString::from(chain.hex())], "nothing left aside");
            std::fs::remove_dir_all(&dest).unwrap();
        }
    }

    #[test]
    fn snapshots_are_listed_and_found_by_chain_id() {
        let (_dir, store, image) = store_with_image();
        let snaps = store.snapshots().ensure(store.content(), &image, &mut |_| {}).unwrap();
        assert_eq!(store.snapshots().list().unwrap(), snaps);
        let info = &snaps[0].info;
        assert_eq!(
            (&info.chain_id, &info.diff_id, info.parent.as_ref()),
            (&image.layers[0].chain_id, &image.layers[0].diff_id, None)
        );
        assert_eq!((info.entries, info.size), (1, 2));
        // A second ensure finds it.
        let mut events = Vec::new();
        store
            .snapshots()
            .ensure(store.content(), &image, &mut |e| events.push(matches!(e, SnapshotEvent::Exists { .. })))
            .unwrap();
        assert_eq!(events, [true]);
    }
}

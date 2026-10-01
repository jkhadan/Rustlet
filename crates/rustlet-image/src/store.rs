//! The image store's root directory and its parts.
//!
//! ```text
//! /var/lib/rustlet/            0711  (daemon data root, docs/architecture.md §3)
//! ├─ content/                  the OCI image layout (`content`)
//! ├─ ingest/                   partial downloads
//! ├─ snapshots/                unpacked layers by chain ID (`snapshot`)
//! ├─ containers/               one directory per container's rootfs (`rootfs`)
//! └─ store.lock                serializes index.json updates
//! ```
//!
//! Everything below the root is `0700`: images can contain anything, setuid
//! binaries included, and nothing on the host but the store's owner needs to
//! look. The root itself is `0711` so that a path below it can be handed to
//! another root-owned program (`rustlet-runc` opens the container rootfs by
//! path) without making anything listable.

use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::content::ContentStore;
use crate::error::{Context, Error, Result};
use crate::snapshot::Snapshotter;

/// The store's root and its parts.
#[derive(Debug, Clone)]
pub struct Store {
    root: PathBuf,
    content: ContentStore,
    snapshots: Snapshotter,
}

impl Store {
    /// Where the daemon (and `cargo xtask image-run`) keep images.
    pub const DEFAULT_ROOT: &'static str = "/var/lib/rustlet";

    /// Opens the store at `root`, creating what's missing. `root` must be an
    /// absolute path; each directory must be a real directory (not a symlink)
    /// owned by the calling user.
    pub fn open(root: impl AsRef<Path>) -> Result<Store> {
        let root = root.as_ref().to_owned();
        if !root.is_absolute() {
            return Err(Error::invalid(format!("store root {} must be an absolute path", root.display())));
        }
        if let Some(parent) = root.parent() {
            std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
        }
        secure_dir(&root, 0o711)?;
        for sub in ["content", "ingest", "snapshots", "containers"] {
            secure_dir(&root.join(sub), 0o700)?;
        }
        let content = ContentStore::open(root.join("content"), root.join("ingest"), root.join("store.lock"))?;
        let snapshots = Snapshotter::open(root.join("snapshots"))?;
        Ok(Store { root, content, snapshots })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Blobs and image names.
    pub fn content(&self) -> &ContentStore {
        &self.content
    }

    /// Unpacked layers.
    pub fn snapshots(&self) -> &Snapshotter {
        &self.snapshots
    }

    /// Where container rootfs directories go (`containers/<id>`).
    pub fn containers_dir(&self) -> PathBuf {
        self.root.join("containers")
    }
}

/// `mkdir` (if missing), then insist on a real directory owned by us, with
/// exactly `mode`.
fn secure_dir(path: &Path, mode: u32) -> Result<()> {
    match std::fs::DirBuilder::new().mode(mode).create(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e).with_context(|| format!("create {}", path.display())),
    }
    let meta = std::fs::symlink_metadata(path).with_context(|| format!("stat {}", path.display()))?;
    if !meta.is_dir() {
        return Err(Error::invalid(format!("{} must be a directory (not a symlink)", path.display())));
    }
    let euid = nix::unistd::geteuid().as_raw();
    if meta.uid() != euid {
        return Err(Error::invalid(format!("{} is owned by uid {}, not by us ({euid})", path.display(), meta.uid())));
    }
    if meta.mode() & 0o7777 != mode {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .with_context(|| format!("chmod {:o} {}", mode, path.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_the_layout_with_tight_modes() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("store");
        let s = Store::open(&root).unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().mode() & 0o7777;
        assert_eq!(mode(&root), 0o711);
        for sub in ["content", "ingest", "snapshots", "containers"] {
            assert_eq!(mode(&root.join(sub)), 0o700, "{sub}");
        }
        assert!(root.join("content/oci-layout").is_file());
        assert_eq!(s.containers_dir(), root.join("containers"));
        Store::open(&root).unwrap();
        assert!(Store::open("relative/path").is_err());
    }

    #[test]
    fn refuses_a_symlinked_root() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("real")).unwrap();
        std::os::unix::fs::symlink(dir.path().join("real"), dir.path().join("link")).unwrap();
        assert!(Store::open(dir.path().join("link")).is_err());
    }
}

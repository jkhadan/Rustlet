//! Helpers for the image tests (`im_`): an image store in a temp directory,
//! layers built entry by entry with explicit owners, and mounted rootfs that
//! are always unmounted again, even when a test fails halfway.

use std::io::Read;
use std::path::{Path, PathBuf};

use rustlet_image::import::{config, import};
use rustlet_image::rootfs::{ContainerRootfs, remap};
use rustlet_image::snapshot::Snapshot;
use rustlet_image::{Image, Store};

use crate::host_mounts;

/// A store (`content/`, `snapshots/`, `containers/`) in a temp directory on
/// the root filesystem (ext4: overlay needs `trusted.*` attributes and
/// `d_type` from its layers' filesystem).
pub struct TestStore {
    pub dir: tempfile::TempDir,
    pub store: Store,
    mounts_before: Vec<(String, String, String)>,
    /// Image tests take turns: unlike the others, they mount overlays on
    /// the host itself, and a test's "host mount table unchanged" check
    /// must not see its neighbour's.
    _turn: std::sync::MutexGuard<'static, ()>,
}

static TURN: std::sync::Mutex<()> = std::sync::Mutex::new(());

impl Default for TestStore {
    fn default() -> Self {
        TestStore::new()
    }
}

impl TestStore {
    pub fn new() -> TestStore {
        assert!(nix::unistd::geteuid().is_root(), "{}", crate::PRIVILEGED);
        // A test that failed while holding the lock poisons it; the next
        // one may still go.
        let turn = TURN.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let dir = tempfile::Builder::new().prefix("rustlet-itest-store-").tempdir().unwrap();
        let store = Store::open(dir.path().join("store")).unwrap();
        TestStore { dir, store, mounts_before: host_mounts(), _turn: turn }
    }

    /// Imports `layers` (uncompressed tars) with `cmd`/`env`/`user`.
    pub fn import(&self, name: &str, layers: &[Vec<u8>], cmd: &[&str], user: Option<&str>) -> Image {
        let env = ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"];
        import(self.store.content(), name, layers, config(cmd, &env, user).unwrap()).unwrap()
    }

    /// Unpacks what isn't yet and returns the image's snapshots.
    pub fn snapshots(&self, image: &Image) -> Vec<Snapshot> {
        self.store.snapshots().ensure(self.store.content(), image, &mut |_| {}).unwrap()
    }

    /// Mounts `image` as the rootfs of a new container directory.
    pub fn mount(&self, image: &Image, userns: bool) -> Mounted {
        let layers = self.snapshots(image);
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let id = format!("c{}", N.fetch_add(1, std::sync::atomic::Ordering::Relaxed));
        let maps = remap();
        let dir = self.store.containers_dir().join(id);
        let rootfs = ContainerRootfs::mount(&dir, &layers, userns.then_some(&maps)).unwrap();
        Mounted { rootfs: Some(rootfs) }
    }
}

impl Drop for TestStore {
    fn drop(&mut self) {
        // Every mounted rootfs is a `Mounted`, dropped (unmounted) before the
        // store; nothing may be left.
        let _ = rustlet_sys::tree::unmount_under(self.dir.path());
        if !std::thread::panicking() {
            crate::assert_host_mounts_unchanged(&self.mounts_before, &host_mounts());
        }
    }
}

/// A container rootfs; unmounted and deleted on drop.
pub struct Mounted {
    pub rootfs: Option<ContainerRootfs>,
}

impl Mounted {
    /// The merged view (`root.path`).
    pub fn path(&self, p: &str) -> PathBuf {
        self.rootfs.as_ref().unwrap().rootfs().join(p.trim_start_matches('/'))
    }

    /// The container's writable layer.
    pub fn upper(&self, p: &str) -> PathBuf {
        self.rootfs.as_ref().unwrap().upper().join(p.trim_start_matches('/'))
    }

    pub fn root(&self) -> PathBuf {
        self.rootfs.as_ref().unwrap().rootfs()
    }
}

impl Drop for Mounted {
    fn drop(&mut self) {
        if let Some(r) = self.rootfs.take() {
            r.remove().unwrap();
        }
    }
}

/// A layer archive, built entry by entry. Names are written verbatim into
/// the header (the tar crate's setters refuse `..`).
pub struct LayerBuilder {
    out: tar::Builder<Vec<u8>>,
}

impl Default for LayerBuilder {
    fn default() -> Self {
        LayerBuilder::new()
    }
}

impl LayerBuilder {
    pub fn new() -> LayerBuilder {
        LayerBuilder { out: tar::Builder::new(Vec::new()) }
    }

    fn header(name: &str, kind: tar::EntryType, size: u64, mode: u32, owner: (u64, u64)) -> tar::Header {
        let mut h = tar::Header::new_gnu();
        assert!(name.len() < 100);
        h.as_old_mut().name[..name.len()].copy_from_slice(name.as_bytes());
        h.set_entry_type(kind);
        h.set_size(size);
        h.set_mode(mode);
        h.set_mtime(1_700_000_000);
        h.set_uid(owner.0);
        h.set_gid(owner.1);
        h.set_cksum();
        h
    }

    pub fn dir(mut self, name: &str, mode: u32, owner: (u64, u64)) -> Self {
        let h = Self::header(name, tar::EntryType::Directory, 0, mode, owner);
        self.out.append(&h, std::io::empty()).unwrap();
        self
    }

    pub fn file(mut self, name: &str, data: &[u8], mode: u32, owner: (u64, u64)) -> Self {
        let h = Self::header(name, tar::EntryType::Regular, data.len() as u64, mode, owner);
        self.out.append(&h, data).unwrap();
        self
    }

    /// A file with extended attributes (PAX `SCHILY.xattr.*`).
    pub fn file_with_xattrs(
        self,
        name: &str,
        data: &[u8],
        mode: u32,
        owner: (u64, u64),
        xattrs: &[(&str, &[u8])],
    ) -> Self {
        let mut s = self;
        let records: Vec<(String, &[u8])> = xattrs.iter().map(|(k, v)| (format!("SCHILY.xattr.{k}"), *v)).collect();
        s.out.append_pax_extensions(records.iter().map(|(k, v)| (k.as_str(), *v))).unwrap();
        s.file(name, data, mode, owner)
    }

    pub fn symlink(mut self, name: &str, target: &str, owner: (u64, u64)) -> Self {
        let mut h = Self::header(name, tar::EntryType::Symlink, 0, 0o777, owner);
        h.as_old_mut().linkname[..target.len()].copy_from_slice(target.as_bytes());
        h.set_cksum();
        self.out.append(&h, std::io::empty()).unwrap();
        self
    }

    pub fn hardlink(mut self, name: &str, target: &str) -> Self {
        let mut h = Self::header(name, tar::EntryType::Link, 0, 0o644, (0, 0));
        h.as_old_mut().linkname[..target.len()].copy_from_slice(target.as_bytes());
        h.set_cksum();
        self.out.append(&h, std::io::empty()).unwrap();
        self
    }

    /// `.wh.<name>`: deletes `path` from the layers below.
    pub fn whiteout(self, path: &str) -> Self {
        let (dir, name) = path.rsplit_once('/').map_or(("", path), |(d, n)| (d, n));
        let entry = if dir.is_empty() { format!(".wh.{name}") } else { format!("{dir}/.wh.{name}") };
        self.file(&entry, b"", 0o644, (0, 0))
    }

    /// `<dir>/.wh..wh..opq`: hides the lower layers' contents of `dir`.
    pub fn opaque(self, dir: &str) -> Self {
        self.file(&format!("{dir}/.wh..wh..opq"), b"", 0o644, (0, 0))
    }

    pub fn device(mut self, name: &str, kind: tar::EntryType, major: u32, minor: u32) -> Self {
        let mut h = Self::header(name, kind, 0, 0o666, (0, 0));
        h.set_device_major(major).unwrap();
        h.set_device_minor(minor).unwrap();
        h.set_cksum();
        self.out.append(&h, std::io::empty()).unwrap();
        self
    }

    pub fn finish(self) -> Vec<u8> {
        self.out.into_inner().unwrap()
    }
}

/// The Alpine minirootfs (uncompressed) that `cargo xtask rootfs` cached:
/// a layer with a working shell.
pub fn alpine_layer() -> Vec<u8> {
    let cache = Path::new(env!("CARGO_MANIFEST_DIR")).join("../.rustlet-dev/cache");
    let tarball = std::fs::read_dir(&cache)
        .unwrap_or_else(|e| panic!("{}: {e} (run `cargo xtask rootfs`)", cache.display()))
        .map(|e| e.unwrap().path())
        .find(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("alpine-minirootfs-") && n.ends_with(".tar.gz"))
        })
        .unwrap_or_else(|| panic!("no Alpine minirootfs in {} (run `cargo xtask rootfs`)", cache.display()));
    let mut tar = Vec::new();
    flate2::read::GzDecoder::new(std::fs::File::open(tarball).unwrap()).read_to_end(&mut tar).unwrap();
    tar
}

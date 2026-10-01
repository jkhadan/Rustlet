//! The content store: an [OCI image layout] on disk.
//!
//! ```text
//! /var/lib/rustlet/content/
//! ├─ oci-layout          {"imageLayoutVersion": "1.0.0"}
//! ├─ index.json          the store's image names (see below)
//! └─ blobs/sha256/
//!    ├─ 1c4eef65…        a manifest
//!    ├─ 8c45ad2f…        a config
//!    └─ 9824c27e…        a layer, still compressed, exactly as downloaded
//! ```
//!
//! Every blob is filed under its own digest, so storing is idempotent and
//! two images sharing a layer share the file. A blob arrives through an
//! [`Ingest`]: written under `ingest/`, hashed while it streams, and renamed
//! into `blobs/` only once its size and digest match what the descriptor
//! promised. A half-finished or corrupted download never appears in `blobs/`.
//!
//! **Names.** `index.json` lists one descriptor per image name, carrying the
//! name in the standard `org.opencontainers.image.ref.name` annotation and,
//! when the image came from a registry, the digest the registry returned for
//! that name (`io.rustlet.image.repo-digest`; for a multi-platform image
//! that's the index's, Docker's "RepoDigest"). Keeping names here, rather
//! than in a database, keeps the directory a valid OCI layout that `skopeo`
//! or `umoci` can read as it is, and makes `save`/`load` a copy.
//!
//! `index.json` is replaced atomically (write a temporary file, rename), so
//! readers need no lock; writers serialize their read-modify-write with an
//! open-file-description lock ([`ContentStore::lock`]), which excludes other
//! threads as well as other processes.
//!
//! [OCI image layout]: https://github.com/opencontainers/image-spec/blob/main/image-layout.md

use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use oci_spec::image::{Descriptor, ImageIndex, ImageIndexBuilder, MediaType};

use crate::digest::{Digest, Hasher};
use crate::error::{Context, Error, Result};
use crate::media;

/// `org.opencontainers.image.ref.name`: the image name a descriptor in
/// `index.json` stands for.
pub const REF_NAME: &str = "org.opencontainers.image.ref.name";
/// The digest a registry returned for the name when it was pulled.
pub const REPO_DIGEST: &str = "io.rustlet.image.repo-digest";

/// An image name in the store.
#[derive(Debug, Clone, PartialEq)]
pub struct RefEntry {
    /// The normalized reference, e.g. `docker.io/library/alpine:latest`.
    pub name: String,
    /// What the name points at: a single-platform image manifest.
    pub target: Descriptor,
    /// The digest the registry returned for the name at pull time.
    pub repo_digest: Option<Digest>,
}

impl RefEntry {
    /// The target manifest's digest.
    pub fn manifest_digest(&self) -> Result<Digest> {
        Digest::from_oci(self.target.digest())
    }
}

/// The OCI layout plus its ingest directory and lock file.
#[derive(Debug, Clone)]
pub struct ContentStore {
    dir: PathBuf,
    ingest: PathBuf,
    lock: PathBuf,
}

impl ContentStore {
    /// Opens (creating if needed) the layout at `dir`. Partial downloads go
    /// to `ingest` (same filesystem, for the final rename); `lock` is the
    /// lock file for `index.json` updates.
    pub fn open(dir: PathBuf, ingest: PathBuf, lock: PathBuf) -> Result<ContentStore> {
        let blobs = dir.join("blobs/sha256");
        std::fs::create_dir_all(&blobs).with_context(|| format!("create {}", blobs.display()))?;
        std::fs::create_dir_all(&ingest).with_context(|| format!("create {}", ingest.display()))?;
        let store = ContentStore { dir, ingest, lock };
        let layout = store.dir.join("oci-layout");
        if !layout.exists() {
            atomic_write(&layout, br#"{"imageLayoutVersion":"1.0.0"}"#)?;
        }
        if !store.index_path().exists() {
            let _lock = store.lock()?;
            if !store.index_path().exists() {
                store.write_index(&empty_index())?;
            }
        }
        Ok(store)
    }

    /// The layout directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn index_path(&self) -> PathBuf {
        self.dir.join("index.json")
    }

    /// Where the blob with this digest lives (whether or not it exists).
    pub fn blob_path(&self, digest: &Digest) -> PathBuf {
        self.dir.join("blobs/sha256").join(digest.hex())
    }

    /// The size of a stored blob, or `None` if the store doesn't have it.
    pub fn blob_size(&self, digest: &Digest) -> Result<Option<u64>> {
        match std::fs::symlink_metadata(self.blob_path(digest)) {
            Ok(m) if m.is_file() => Ok(Some(m.len())),
            Ok(_) => Err(Error::invalid(format!("blob {digest} is not a regular file"))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("stat blob {digest}")),
        }
    }

    /// Does the store have this blob, with this size?
    pub fn has_blob(&self, digest: &Digest, size: u64) -> Result<bool> {
        Ok(self.blob_size(digest)? == Some(size))
    }

    /// Opens a stored blob for reading. Its content isn't re-verified here;
    /// consumers that care hash what they read (unpacking does).
    pub fn open_blob(&self, digest: &Digest) -> Result<File> {
        std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(self.blob_path(digest)).map_err(
            |e| match e.kind() {
                std::io::ErrorKind::NotFound => Error::NotFound(format!("blob {digest} is not in the store")),
                _ => Error::Io { context: format!("open blob {digest}"), source: e },
            },
        )
    }

    /// Reads a small blob (a manifest or config) whole, refusing anything
    /// over `max` bytes, and checks it against its digest.
    pub fn read_blob(&self, digest: &Digest, max: u64) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        self.open_blob(digest)?.take(max + 1).read_to_end(&mut bytes).with_context(|| format!("read blob {digest}"))?;
        if bytes.len() as u64 > max {
            return Err(Error::invalid(format!("blob {digest} is larger than {max} bytes")));
        }
        let actual = Digest::of(&bytes);
        if &actual != digest {
            return Err(Error::DigestMismatch {
                what: format!("stored blob {digest}"),
                expected: digest.to_string(),
                actual: actual.to_string(),
            });
        }
        Ok(bytes)
    }

    /// Stores `bytes` (a manifest or config) and returns its digest.
    pub fn write_blob(&self, bytes: &[u8]) -> Result<Digest> {
        let digest = Digest::of(bytes);
        let mut ingest = self.ingest(&digest, Some(bytes.len() as u64))?;
        ingest.write_all(bytes).with_context(|| format!("write blob {digest}"))?;
        ingest.commit()?;
        Ok(digest)
    }

    /// Starts writing the blob `expected` (of `size` bytes, if known). See
    /// [`Ingest`].
    pub fn ingest(&self, expected: &Digest, size: Option<u64>) -> Result<Ingest> {
        static N: AtomicU64 = AtomicU64::new(0);
        let name = format!("{}-{}-{}.partial", expected.hex(), std::process::id(), N.fetch_add(1, Ordering::Relaxed));
        let path = self.ingest.join(name);
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
            .with_context(|| format!("create {}", path.display()))?;
        Ok(Ingest {
            file,
            path,
            dest: self.blob_path(expected),
            hasher: Hasher::new(),
            written: 0,
            expected: expected.clone(),
            size,
            done: false,
        })
    }

    /// Takes the store's write lock (blocking). Hold it across a whole
    /// read-modify-write of `index.json`.
    ///
    /// An open-file-description lock (`F_OFD_SETLKW`). A classic POSIX
    /// record lock belongs to the *process*, so two threads of the daemon
    /// would both get it; an OFD lock, like an `flock`, belongs to one
    /// *open* of the file, and every call opens the file anew, so threads
    /// exclude each other as processes do. (`flock` would do as well; the
    /// fcntl form is the one `nix` offers for this workspace's Rust.)
    pub fn lock(&self) -> Result<StoreLock> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&self.lock)
            .with_context(|| format!("open {}", self.lock.display()))?;
        let whole_file = libc::flock {
            l_type: libc::F_WRLCK as libc::c_short,
            l_whence: libc::SEEK_SET as libc::c_short,
            l_start: 0,
            l_len: 0,
            l_pid: 0,
        };
        loop {
            match nix::fcntl::fcntl(&file, nix::fcntl::FcntlArg::F_OFD_SETLKW(&whole_file)) {
                Ok(_) => return Ok(StoreLock(file)),
                Err(rustlet_sys::Errno::EINTR) => continue,
                Err(e) => return Err(e).with_context(|| format!("lock {}", self.lock.display())),
            }
        }
    }

    fn read_index(&self) -> Result<ImageIndex> {
        let path = self.index_path();
        let bytes = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
        serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))
    }

    fn write_index(&self, index: &ImageIndex) -> Result<()> {
        // Through a `Value`, whose maps are sorted: annotations are a
        // HashMap in oci-spec, and the file should only change when its
        // content does.
        let value = serde_json::to_value(index).context("serialize index.json")?;
        let json = serde_json::to_vec_pretty(&value).context("serialize index.json")?;
        atomic_write(&self.index_path(), &json)
    }

    /// Every image name in the store, sorted by name. Descriptors without a
    /// name (another tool's) are left alone and not listed.
    pub fn refs(&self) -> Result<Vec<RefEntry>> {
        let mut out: Vec<RefEntry> = self.read_index()?.manifests().iter().filter_map(ref_entry).collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    /// The entry for `name` (a normalized reference), if the store has it.
    pub fn resolve(&self, name: &str) -> Result<Option<RefEntry>> {
        Ok(self.refs()?.into_iter().find(|r| r.name == name))
    }

    /// Points `entry.name` at `entry.target`, replacing what it pointed at.
    /// The target's blob must already be in the store.
    pub fn set_ref(&self, entry: &RefEntry) -> Result<()> {
        let media_type = entry.target.media_type().to_string();
        if !media::is_manifest(&media_type) {
            return Err(Error::invalid(format!(
                "{}: a name must point at an image manifest, not {media_type}",
                entry.name
            )));
        }
        let target = Digest::from_oci(entry.target.digest())?;
        if !self.has_blob(&target, entry.target.size())? {
            return Err(Error::NotFound(format!("{}: manifest {target} is not in the store", entry.name)));
        }
        let mut desc = entry.target.clone();
        let mut annotations = desc.annotations().clone().unwrap_or_default();
        annotations.insert(REF_NAME.to_owned(), entry.name.clone());
        match &entry.repo_digest {
            Some(d) => annotations.insert(REPO_DIGEST.to_owned(), d.to_string()),
            None => annotations.remove(REPO_DIGEST),
        };
        desc.set_annotations(Some(annotations));

        let _lock = self.lock()?;
        let index = self.read_index()?;
        let mut manifests: Vec<Descriptor> =
            index.manifests().iter().filter(|d| ref_name(d) != Some(entry.name.as_str())).cloned().collect();
        manifests.push(desc);
        manifests.sort_by(|a, b| ref_name(a).cmp(&ref_name(b)));
        let mut index = index;
        index.set_manifests(manifests);
        self.write_index(&index)
    }

    /// Removes the name `name`. Returns whether it existed. Blobs stay.
    pub fn remove_ref(&self, name: &str) -> Result<bool> {
        let _lock = self.lock()?;
        let mut index = self.read_index()?;
        let before = index.manifests().len();
        let kept: Vec<Descriptor> = index.manifests().iter().filter(|d| ref_name(d) != Some(name)).cloned().collect();
        let removed = kept.len() != before;
        if removed {
            index.set_manifests(kept);
            self.write_index(&index)?;
        }
        Ok(removed)
    }
}

/// The store's write lock; released on drop.
#[derive(Debug)]
pub struct StoreLock(#[allow(dead_code)] File);

fn ref_name(d: &Descriptor) -> Option<&str> {
    d.annotations().as_ref()?.get(REF_NAME).map(String::as_str)
}

fn ref_entry(d: &Descriptor) -> Option<RefEntry> {
    let annotations: &HashMap<String, String> = d.annotations().as_ref()?;
    let name = annotations.get(REF_NAME)?.clone();
    let repo_digest = annotations.get(REPO_DIGEST).and_then(|s| Digest::parse(s).ok());
    Some(RefEntry { name, target: d.clone(), repo_digest })
}

fn empty_index() -> ImageIndex {
    ImageIndexBuilder::default()
        .schema_version(2u32)
        .media_type(MediaType::ImageIndex)
        .manifests(Vec::<Descriptor>::new())
        .build()
        .expect("static index")
}

/// Writes `path` atomically: a temporary file next to it, fsync'ed, renamed
/// over it.
fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    static N: AtomicU64 = AtomicU64::new(0);
    let tmp = path.with_extension(format!("tmp-{}-{}", std::process::id(), N.fetch_add(1, Ordering::Relaxed)));
    let result = (|| {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp)
            .with_context(|| format!("create {}", tmp.display()))?;
        f.write_all(bytes).with_context(|| format!("write {}", tmp.display()))?;
        f.sync_all().with_context(|| format!("fsync {}", tmp.display()))?;
        std::fs::rename(&tmp, path).with_context(|| format!("rename {} into place", tmp.display()))?;
        // The rename is durable once the directory is.
        crate::snapshot::sync_dir(path.parent().unwrap_or(Path::new("/")))
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// A blob being written into the store.
///
/// Bytes written are hashed and counted as they go; writing more than the
/// expected size fails right away. [`commit`](Self::commit) checks the final
/// size and digest and only then renames the file into `blobs/`. Dropping an
/// uncommitted ingest deletes the partial file.
#[derive(Debug)]
pub struct Ingest {
    file: File,
    path: PathBuf,
    dest: PathBuf,
    hasher: Hasher,
    written: u64,
    expected: Digest,
    size: Option<u64>,
    done: bool,
}

impl Ingest {
    /// Bytes written so far.
    pub fn written(&self) -> u64 {
        self.written
    }

    /// The digest this blob must have.
    pub fn expected(&self) -> &Digest {
        &self.expected
    }

    /// Verifies size and digest, makes the data durable, and moves the blob
    /// into place. If the store meanwhile got the same blob from elsewhere
    /// (a concurrent pull), the copy is simply dropped: same digest, same bytes.
    pub fn commit(mut self) -> Result<()> {
        if let Some(size) = self.size
            && self.written != size
        {
            return Err(Error::DigestMismatch {
                what: format!("size of blob {}", self.expected),
                expected: size.to_string(),
                actual: self.written.to_string(),
            });
        }
        let actual = self.hasher.digest();
        if actual != self.expected {
            return Err(Error::DigestMismatch {
                what: format!("blob {}", self.expected),
                expected: self.expected.to_string(),
                actual: actual.to_string(),
            });
        }
        self.file.sync_all().with_context(|| format!("fsync {}", self.path.display()))?;
        std::fs::rename(&self.path, &self.dest)
            .with_context(|| format!("move blob {} into the store", self.expected))?;
        self.done = true;
        // The rename is durable once the directory is.
        crate::snapshot::sync_dir(self.dest.parent().unwrap_or(Path::new("/")))
    }
}

impl Write for Ingest {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if let Some(size) = self.size
            && self.written + buf.len() as u64 > size
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("blob {} is larger than its descriptor's {size} bytes", self.expected),
            ));
        }
        let n = self.file.write(buf)?;
        self.hasher.update(&buf[..n]);
        self.written += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

impl Drop for Ingest {
    fn drop(&mut self) {
        if !self.done {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// A descriptor for content of `media_type`.
pub fn descriptor(media_type: &str, digest: &Digest, size: u64) -> Descriptor {
    Descriptor::new(MediaType::from(media_type), size, digest.to_oci())
}

/// A descriptor for an image manifest stored by [`ContentStore::write_blob`],
/// with the host platform recorded (as `skopeo` does in `index.json`).
pub fn manifest_descriptor(media_type: &str, digest: &Digest, size: u64) -> Descriptor {
    let mut d = descriptor(media_type, digest, size);
    let platform = oci_spec::image::PlatformBuilder::default()
        .os(oci_spec::image::Os::Linux)
        .architecture(oci_spec::image::Arch::Amd64)
        .build()
        .expect("static platform");
    d.set_platform(Some(platform));
    d
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, ContentStore) {
        let dir = tempfile::tempdir().unwrap();
        let s =
            ContentStore::open(dir.path().join("content"), dir.path().join("ingest"), dir.path().join("lock")).unwrap();
        (dir, s)
    }

    #[test]
    fn a_new_store_is_an_empty_oci_layout() {
        let (dir, s) = store();
        let layout: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.path().join("content/oci-layout")).unwrap()).unwrap();
        assert_eq!(layout["imageLayoutVersion"], "1.0.0");
        let index: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.path().join("content/index.json")).unwrap()).unwrap();
        assert_eq!(index["schemaVersion"], 2);
        assert_eq!(index["manifests"], serde_json::json!([]));
        assert!(s.refs().unwrap().is_empty());
        // Opening again keeps what is there.
        let again = ContentStore::open(s.dir.clone(), s.ingest.clone(), s.lock.clone()).unwrap();
        assert!(again.refs().unwrap().is_empty());
    }

    #[test]
    fn blobs_are_verified_before_they_appear() {
        let (dir, s) = store();
        let d = s.write_blob(b"hello").unwrap();
        assert_eq!(d, Digest::of(b"hello"));
        assert_eq!(s.read_blob(&d, 100).unwrap(), b"hello");
        assert!(s.has_blob(&d, 5).unwrap() && !s.has_blob(&d, 6).unwrap());
        assert!(s.read_blob(&d, 4).is_err(), "over the size cap");

        // Wrong content: commit fails and nothing is left behind.
        let other = Digest::of(b"other");
        let mut i = s.ingest(&other, Some(5)).unwrap();
        i.write_all(b"wrong").unwrap();
        assert!(matches!(i.commit(), Err(Error::DigestMismatch { .. })));
        assert_eq!(s.blob_size(&other).unwrap(), None);
        // Too long: refused while writing.
        let mut i = s.ingest(&other, Some(2)).unwrap();
        assert!(i.write_all(b"other").is_err());
        drop(i);
        // Too short.
        let mut i = s.ingest(&other, Some(6)).unwrap();
        i.write_all(b"other").unwrap();
        assert!(matches!(i.commit(), Err(Error::DigestMismatch { .. })));
        assert_eq!(std::fs::read_dir(dir.path().join("ingest")).unwrap().count(), 0, "partials left behind");

        // A blob tampered with on disk is caught when read.
        std::fs::write(s.blob_path(&d), b"HELLO").unwrap();
        assert!(matches!(s.read_blob(&d, 100), Err(Error::DigestMismatch { .. })));
    }

    #[test]
    fn names_live_in_index_json() {
        let (_dir, s) = store();
        let m1 = s.write_blob(b"{\"m\":1}").unwrap();
        let m2 = s.write_blob(b"{\"m\":2}").unwrap();
        let entry = |name: &str, d: &Digest| RefEntry {
            name: name.into(),
            target: manifest_descriptor(media::OCI_MANIFEST, d, 7),
            repo_digest: Some(Digest::of(b"index")),
        };
        s.set_ref(&entry("docker.io/library/b:latest", &m1)).unwrap();
        s.set_ref(&entry("docker.io/library/a:latest", &m1)).unwrap();
        s.set_ref(&entry("docker.io/library/b:latest", &m2)).unwrap();
        let refs = s.refs().unwrap();
        assert_eq!(
            refs.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(),
            ["docker.io/library/a:latest", "docker.io/library/b:latest"]
        );
        let b = s.resolve("docker.io/library/b:latest").unwrap().unwrap();
        assert_eq!(b.manifest_digest().unwrap(), m2);
        assert_eq!(b.repo_digest, Some(Digest::of(b"index")));
        // Rewritten deterministically: same content, same bytes.
        let before = std::fs::read(s.dir.join("index.json")).unwrap();
        s.set_ref(&entry("docker.io/library/b:latest", &m2)).unwrap();
        assert_eq!(std::fs::read(s.dir.join("index.json")).unwrap(), before);
        assert!(s.remove_ref("docker.io/library/a:latest").unwrap());
        assert!(!s.remove_ref("docker.io/library/a:latest").unwrap());
        assert_eq!(s.refs().unwrap().len(), 1);
        // A name can't point at a manifest the store doesn't have.
        let missing = entry("docker.io/library/c:latest", &Digest::of(b"nope"));
        assert!(matches!(s.set_ref(&missing), Err(Error::NotFound(_))));
        // Names point at single-platform manifests, never at indexes.
        let mut index = entry("docker.io/library/d:latest", &m1);
        index.target = descriptor(media::OCI_INDEX, &m1, 7);
        assert!(matches!(s.set_ref(&index), Err(Error::Invalid(_))));
    }

    #[test]
    fn concurrent_writers_do_not_lose_names() {
        let (_dir, s) = store();
        let m = s.write_blob(b"{}").unwrap();
        std::thread::scope(|scope| {
            for t in 0..8 {
                let s = &s;
                let m = &m;
                scope.spawn(move || {
                    for i in 0..10 {
                        s.set_ref(&RefEntry {
                            name: format!("docker.io/library/t{t}:{i}"),
                            target: manifest_descriptor(media::OCI_MANIFEST, m, 2),
                            repo_digest: None,
                        })
                        .unwrap();
                    }
                });
            }
        });
        assert_eq!(s.refs().unwrap().len(), 80);
    }
}

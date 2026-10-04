//! `save` and `load`: images as one tar archive.
//!
//! ## What `save` writes
//!
//! An [OCI image layout], as a tar archive: the store's own format
//! (`content`), holding only the images asked for.
//!
//! ```text
//!  oci-layout                {"imageLayoutVersion":"1.0.0"}
//!  index.json                one manifest descriptor per name (an image saved by id: one, unnamed)
//!  manifest.json             Docker's: [{"Config": "blobs/sha256/…", "RepoTags": ["alpine:latest"], "Layers": [...]}]
//!  blobs/sha256/<hex>        every manifest, config and layer, once
//! ```
//!
//! `index.json` names an image twice, as Docker 25+'s `docker save` does:
//! `io.containerd.image.name` holds the full name
//! (`docker.io/library/alpine:latest`) and `org.opencontainers.image.ref.name`
//! the tag (`latest`), which is what the OCI spec means it for (the store's
//! own `index.json` uses it for the full name). `manifest.json` lets
//! Docker's older loader read the same archive (`RepoTags` in Docker's
//! short form: `alpine:latest`, `ghcr.io/o/n:1`). Entries are written in a
//! fixed order (the metadata files, then the blobs by digest) with fixed
//! headers (mode 0644, uid/gid 0, time 0), so the same images make the same
//! archive, in whatever order they are asked for (`index.json` lists names
//! in byte order, then images saved by id by digest; `manifest.json` lists
//! images by manifest digest). Blobs are streamed from the store, never
//! held whole, and checked against their digests as they go. A name pinned
//! to a digest (`alpine@sha256:…`) has no tag: `index.json` carries only its
//! full name, `RepoTags` leaves it out.
//!
//! ## What `load` reads
//!
//! Either format, entry by entry, in any order:
//!
//! - **OCI image layout** (`save`'s, `docker save` since Docker 25,
//!   `skopeo copy … oci-archive:`): each `blobs/sha256/<hex>` entry is
//!   stored through an [`crate::content::Ingest`] expecting that digest,
//!   so a blob that doesn't hash to its name never reaches the store.
//!   `index.json` is read (at most 4 MiB); its descriptors may be image
//!   manifests or indexes (nested ones too), from which the `linux/amd64`
//!   manifest is chosen as for a pull (`manifest::select_platform`). Names
//!   come from `io.containerd.image.name`, else from
//!   `org.opencontainers.image.ref.name` when that is a full reference
//!   (it has a `/`, `:` or `@`; a bare tag names nothing).
//! - **Docker's older format** (`docker save` before 25): `manifest.json`
//!   lists per image its `Config` (`<hex>.json`, stored expecting that
//!   digest), `RepoTags` and `Layers` (`<dir>/layer.tar`, uncompressed or
//!   compressed, stored under the digest they hash to; a duplicate layer is
//!   a symlink to another's `layer.tar`, resolved within the archive). The
//!   loader writes an OCI manifest for each (`import::write_image`; the
//!   layers' media types from their content, `media::detect_compression`),
//!   once each layer's uncompressed digest is the config's diff ID for it,
//!   as Docker's loader checks. When both `index.json` and `manifest.json`
//!   are there, `index.json` wins.
//!
//! Other entries (`repositories`, `<dir>/json`, `<dir>/VERSION`) are
//! ignored. Once the archive ends, every image must load
//! (`Image::from_manifest`: its config parses, one diff ID per layer) with
//! every blob present, or the load fails naming what is missing; only then
//! are names set ([`ContentStore::set_ref`]), and an image without one is
//! kept ([`ContentStore::keep`]). A name listed for two images goes to the
//! later one. Blobs already stored aren't written again (an entry's data is
//! skipped). JSON files are capped as manifests and configs are (4 and
//! 8 MiB); the archive itself isn't.
//!
//! [OCI image layout]: https://github.com/opencontainers/image-spec/blob/main/image-layout.md

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::{self, BufReader, Read, Write};

use oci_spec::image::Descriptor;
use serde::Deserialize;
use serde_json::{Value, json};
use tar::EntryType;

use crate::config::{ImageConfig, MAX_CONFIG_BYTES};
use crate::content::{self, ContentStore, RefEntry};
use crate::diff::{EntryHeader, TarWriter};
use crate::digest::{Digest, HashingReader};
use crate::error::{Context, Error, Result};
use crate::image::Image;
use crate::import;
use crate::manifest::{self, Fetched, MAX_MANIFEST_BYTES, Platform};
use crate::media::{self, Compression};
use crate::reference::ImageRef;

/// `io.containerd.image.name`: an image's full name, in `docker save`'s
/// `index.json`.
const IMAGE_NAME: &str = "io.containerd.image.name";
const OCI_LAYOUT: &[u8] = br#"{"imageLayoutVersion":"1.0.0"}"#;
/// How deep indexes may nest below `index.json`.
const MAX_NESTING: usize = 4;
/// How many links a path in the archive may lead through.
const MAX_LINKS: usize = 40;

/// What [`save`] wrote.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SaveReport {
    pub images: usize,
    pub blobs: usize,
    /// Bytes of blob content.
    pub bytes: u64,
}

/// Progress of a [`load`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadProgress {
    /// A blob of the archive, verified and stored, or already there.
    Blob { digest: Digest, size: u64, existed: bool },
}

/// An image a [`load`] put in the store.
#[derive(Debug, Clone)]
pub struct Loaded {
    pub image: Image,
    /// The names it was given (normalized); none: it was kept unnamed.
    pub names: Vec<String>,
}

/// Writes `images` (each with the names it carries in the archive, in the
/// store's normalized form; none for an image saved by id) as a tar
/// archive to `out` (see the module docs).
pub fn save(content: &ContentStore, images: &[(Image, Vec<String>)], out: &mut dyn Write) -> Result<SaveReport> {
    // An image asked for twice (by two names, by name and by id) is saved
    // once, with every name.
    let mut by_manifest: BTreeMap<&Digest, (&Image, BTreeSet<&str>)> = BTreeMap::new();
    for (image, names) in images {
        let (_, all) = by_manifest.entry(&image.manifest_digest).or_insert_with(|| (image, BTreeSet::new()));
        all.extend(names.iter().map(String::as_str));
    }
    let mut blobs: BTreeMap<Digest, u64> = BTreeMap::new();
    // Sorted as the store sorts its own: names first, then by digest.
    let mut index: Vec<((u8, String), Value)> = Vec::new();
    let mut docker = Vec::new();
    for (&digest, (image, names)) in &by_manifest {
        let size = content
            .blob_size(digest)?
            .ok_or_else(|| Error::NotFound(format!("manifest {digest} is not in the store")))?;
        blobs.insert(digest.clone(), size);
        blobs.insert(image.config_digest.clone(), image.manifest.config().size());
        for layer in &image.layers {
            blobs.insert(layer.blob.clone(), layer.size);
        }
        let media_type = image.manifest.media_type().as_ref().map_or(media::OCI_MANIFEST.to_owned(), |m| m.to_string());
        let descriptor = || json!({"mediaType": media_type, "digest": digest.to_string(), "size": size});
        let mut tags = Vec::new();
        for name in names {
            let reference = ImageRef::parse(name)?;
            let mut annotations = serde_json::Map::new();
            annotations.insert(IMAGE_NAME.to_owned(), reference.name().into());
            if let Some(tag) = tag(&reference) {
                annotations.insert(content::REF_NAME.to_owned(), tag.into());
                tags.push(familiar(&reference, tag));
            }
            let mut named = descriptor();
            named["annotations"] = annotations.into();
            index.push(((0, reference.name()), named));
        }
        if names.is_empty() {
            index.push(((1, digest.to_string()), descriptor()));
        }
        docker.push(json!({
            "Config": blob_path(&image.config_digest),
            "RepoTags": tags,
            "Layers": image.layers.iter().map(|l| blob_path(&l.blob)).collect::<Vec<_>>(),
        }));
    }
    index.sort_by(|a, b| a.0.cmp(&b.0));
    // All there, before a byte is written.
    for (digest, &size) in &blobs {
        if !content.has_blob(digest, size)? {
            return Err(Error::NotFound(format!("blob {digest} ({size} bytes) is not in the store")));
        }
    }
    let index = json!({
        "schemaVersion": 2,
        "mediaType": media::OCI_INDEX,
        "manifests": index.into_iter().map(|(_, d)| d).collect::<Vec<_>>(),
    });
    let index = serde_json::to_vec(&index).context("serialize index.json")?;
    let docker = serde_json::to_vec(&docker).context("serialize manifest.json")?;

    let mut tar = TarWriter::new(out);
    for (name, bytes) in [("oci-layout", OCI_LAYOUT), ("index.json", &index[..]), ("manifest.json", &docker[..])] {
        tar.header(&fixed(name.as_bytes(), bytes.len() as u64))?;
        tar.data(&mut &bytes[..], bytes.len() as u64, name)?;
    }
    for (digest, &size) in &blobs {
        let what = format!("blob {digest}");
        let mut blob = HashingReader::new(content.open_blob(digest)?);
        tar.header(&fixed(blob_path(digest).as_bytes(), size))?;
        tar.data(&mut blob, size, &what)?;
        let actual = blob.digest();
        if &actual != digest {
            return Err(Error::DigestMismatch {
                what: format!("stored {what}"),
                expected: digest.to_string(),
                actual: actual.to_string(),
            });
        }
    }
    tar.finish()?;
    Ok(SaveReport { images: by_manifest.len(), blobs: blobs.len(), bytes: blobs.values().sum() })
}

/// Reads an archive from `input` into the store (see the module docs).
pub fn load(
    content: &ContentStore,
    input: &mut dyn Read,
    progress: &mut dyn FnMut(LoadProgress),
) -> Result<Vec<Loaded>> {
    let mut found = Found::default();
    let mut archive = tar::Archive::new(BufReader::with_capacity(1 << 16, input));
    for entry in archive.entries().context("read the archive")? {
        found.entry(content, entry.context("read the archive")?, progress)?;
    }
    let images = match (&found.index, &found.manifest) {
        (Some(index), _) => oci_images(content, index)?,
        (None, Some(manifest)) => found.docker_images(content, manifest)?,
        (None, None) => {
            return Err(Error::invalid("not an image archive: it has neither index.json nor manifest.json"));
        }
    };
    name(content, images)
}

/// `save`'s header for a file: 0644, owned by root, from the epoch.
fn fixed(name: &[u8], size: u64) -> EntryHeader<'_> {
    EntryHeader { name, kind: EntryType::Regular, mode: 0o644, uid: 0, gid: 0, mtime: 0, size, link: b"", xattrs: &[] }
}

fn blob_path(digest: &Digest) -> String {
    format!("blobs/sha256/{}", digest.hex())
}

/// The tag a name has, unless it is pinned to a digest.
fn tag(reference: &ImageRef) -> Option<&str> {
    if reference.digest().is_some() { None } else { reference.tag() }
}

/// Docker's short form of a tagged name: `alpine:latest` for
/// `docker.io/library/alpine:latest`, `bitnami/redis:7` for Docker Hub's
/// others, the whole name elsewhere.
fn familiar(reference: &ImageRef, tag: &str) -> String {
    let repository = reference.repository();
    match reference.registry() {
        "docker.io" => {
            let path = repository.strip_prefix("library/").filter(|rest| !rest.contains('/')).unwrap_or(repository);
            format!("{path}:{tag}")
        }
        registry => format!("{registry}/{repository}:{tag}"),
    }
}

/// What a [`load`] found in the archive.
#[derive(Default)]
struct Found {
    /// Each file stored as a blob, and each link, by its path.
    paths: HashMap<String, Held>,
    index: Option<Vec<u8>>,
    manifest: Option<Vec<u8>>,
}

/// What a path of the archive holds.
enum Held {
    Blob {
        digest: Digest,
        size: u64,
    },
    /// A symlink or hard link to another path (made relative to the
    /// archive's root).
    Link(String),
}

/// An image found, not named yet.
struct Candidate {
    image: Image,
    names: Vec<String>,
    /// Its manifest's descriptor.
    target: Descriptor,
}

impl Found {
    /// Reads, stores or notes one entry of the archive.
    fn entry<R: Read>(
        &mut self,
        content: &ContentStore,
        mut entry: tar::Entry<'_, R>,
        progress: &mut dyn FnMut(LoadProgress),
    ) -> Result<()> {
        let raw = entry.path_bytes().into_owned();
        let path = clean(&raw);
        let kind = entry.header().entry_type();
        if matches!(kind, EntryType::Symlink | EntryType::Link) {
            let target = entry.link_name_bytes().map(|t| t.into_owned()).unwrap_or_default();
            // A symlink is relative to its directory, a hard link's target
            // to the archive's root.
            let target = match kind {
                EntryType::Symlink if !target.starts_with(b"/") => [parent(&path).as_bytes(), b"/", &target].concat(),
                _ => target,
            };
            self.paths.insert(path, Held::Link(clean(&target)));
            return Ok(());
        }
        // Files only. (An old-style directory is a file whose name ends in `/`.)
        if !matches!(kind, EntryType::Regular | EntryType::Continuous) || raw.ends_with(b"/") || path.is_empty() {
            return Ok(());
        }
        let size = entry.size();
        let held = match path.as_str() {
            "index.json" => {
                self.index = Some(read_json(&mut entry, size, &path, MAX_MANIFEST_BYTES)?);
                return Ok(());
            }
            "manifest.json" => {
                self.manifest = Some(read_json(&mut entry, size, &path, MAX_MANIFEST_BYTES)?);
                return Ok(());
            }
            "oci-layout" | "repositories" => return Ok(()),
            // Docker's older format's `<id>/json` and `<id>/VERSION`.
            p if p.split('/').count() == 2 && (p.ends_with("/json") || p.ends_with("/VERSION")) => return Ok(()),
            p => match named(p) {
                Some((digest, max)) => store_named(content, &mut entry, p, &digest, size, max, progress)?,
                None => store_unnamed(content, &mut entry, p, progress)?,
            },
        };
        self.paths.insert(path, held);
        Ok(())
    }

    /// The images of Docker's older format, `manifest.json`'s entries.
    fn docker_images(&self, content: &ContentStore, manifest: &[u8]) -> Result<Vec<Candidate>> {
        /// One entry of `manifest.json` (`LayerSources`, foreign layers'
        /// URLs, aside: such a layer must be in the archive too).
        #[derive(Deserialize)]
        #[serde(rename_all = "PascalCase")]
        struct Listed {
            config: String,
            #[serde(default)]
            repo_tags: Option<Vec<String>>,
            #[serde(default)]
            layers: Vec<String>,
        }
        let listed: Vec<Listed> = serde_json::from_slice(manifest).context("parse manifest.json")?;
        // Uncompressed digests, by blob: a layer listed twice is read once.
        let mut diff_ids: HashMap<Digest, Digest> = HashMap::new();
        let mut out = Vec::with_capacity(listed.len());
        for item in listed {
            let names = item
                .repo_tags
                .unwrap_or_default()
                .iter()
                .map(|tag| ImageRef::parse(tag).map(|r| r.name()))
                .collect::<Result<Vec<_>>>()?;
            let what = names.first().cloned().unwrap_or_else(|| item.config.clone());
            let (config_digest, _) = self.resolve(&item.config, &what, "config")?;
            let config = content.read_blob(&config_digest, MAX_CONFIG_BYTES)?;
            let diff_ids_listed = ImageConfig::parse(&config)?.diff_ids;
            if diff_ids_listed.len() != item.layers.len() {
                return Err(Error::invalid(format!(
                    "{what}: {} layers, but its config lists {} diff IDs",
                    item.layers.len(),
                    diff_ids_listed.len()
                )));
            }
            let mut layers = Vec::with_capacity(item.layers.len());
            for (path, expected) in item.layers.iter().zip(&diff_ids_listed) {
                let (digest, size) = self.resolve(path, &what, "layer")?;
                let compression = media::detect_compression(&magic(content, &digest)?);
                let diff_id = match diff_ids.get(&digest) {
                    Some(diff_id) => diff_id.clone(),
                    None => {
                        let diff_id = uncompressed_digest(content, &digest, compression)?;
                        diff_ids.insert(digest.clone(), diff_id.clone());
                        diff_id
                    }
                };
                if &diff_id != expected {
                    return Err(Error::DigestMismatch {
                        what: format!("{what}: diff ID of layer {path}"),
                        expected: expected.to_string(),
                        actual: diff_id.to_string(),
                    });
                }
                layers.push(content::descriptor(media::layer_media_type(compression), &digest, size));
            }
            let target = import::write_image(content, &config, &layers)?;
            let image = Image::from_manifest(content, &Digest::from_oci(target.digest())?, None, None)?;
            out.push(Candidate { image, names, target });
        }
        Ok(out)
    }

    /// The blob a path of the archive holds, through links within the
    /// archive. `what` and `kind` name it in errors.
    fn resolve(&self, path: &str, what: &str, kind: &str) -> Result<(Digest, u64)> {
        let mut at = clean(path.as_bytes());
        for _ in 0..MAX_LINKS {
            match self.paths.get(&at) {
                Some(Held::Blob { digest, size }) => return Ok((digest.clone(), *size)),
                Some(Held::Link(target)) => at = target.clone(),
                None => break,
            }
        }
        Err(Error::NotFound(format!("{what}: its {kind} {path} is not in the archive")))
    }
}

/// Reads a JSON file of the archive whole, at most `max` bytes.
fn read_json(data: &mut dyn Read, size: u64, path: &str, max: u64) -> Result<Vec<u8>> {
    if size > max {
        return Err(Error::invalid(format!("{path} has {size} bytes, more than {max}")));
    }
    let mut bytes = Vec::new();
    data.take(max + 1).read_to_end(&mut bytes).with_context(|| format!("read {path}"))?;
    Ok(bytes)
}

/// The digest a path names, if it is a blob's (`blobs/sha256/<hex>`) or a
/// config's of Docker's older format (`<hex>.json`, with the most a config
/// may have).
fn named(path: &str) -> Option<(Digest, Option<u64>)> {
    if let Some(hex) = path.strip_prefix("blobs/sha256/") {
        return Digest::from_hex(hex).ok().map(|d| (d, None));
    }
    let hex = path.strip_suffix(".json")?;
    Digest::from_hex(hex).ok().map(|d| (d, Some(MAX_CONFIG_BYTES)))
}

/// A blob its path names: stored through an ingest that checks it hashes to
/// `digest`, unless the store has it already.
fn store_named(
    content: &ContentStore,
    data: &mut dyn Read,
    path: &str,
    digest: &Digest,
    size: u64,
    max: Option<u64>,
    progress: &mut dyn FnMut(LoadProgress),
) -> Result<Held> {
    if let Some(max) = max
        && size > max
    {
        return Err(Error::invalid(format!("{path} has {size} bytes, more than an image config may ({max})")));
    }
    let existed = content.has_blob(digest, size)?;
    if !existed {
        let mut ingest = content.ingest(digest, Some(size))?;
        copy(data, &mut ingest).with_context(|| format!("store {path}"))?;
        ingest.commit()?;
    }
    progress(LoadProgress::Blob { digest: digest.clone(), size, existed });
    Ok(Held::Blob { digest: digest.clone(), size })
}

/// Any other file (a layer of Docker's older format, say): stored under the
/// digest it hashes to, unless the store has that already.
fn store_unnamed(
    content: &ContentStore,
    data: &mut dyn Read,
    path: &str,
    progress: &mut dyn FnMut(LoadProgress),
) -> Result<Held> {
    let mut writer = content.blob_writer()?;
    let mut data = HashingReader::new(data);
    copy(&mut data, &mut writer).with_context(|| format!("store {path}"))?;
    let (digest, size) = (data.digest(), data.count());
    let existed = content.has_blob(&digest, size)?;
    if !existed {
        writer.finish()?;
    } // else dropping the writer deletes the copy
    progress(LoadProgress::Blob { digest: digest.clone(), size, existed });
    Ok(Held::Blob { digest, size })
}

/// `io::copy`, with a buffer for blobs of any size.
fn copy(src: &mut dyn Read, dst: &mut dyn Write) -> io::Result<u64> {
    let mut buf = vec![0; 1 << 18];
    let mut total = 0;
    loop {
        let n = match src.read(&mut buf) {
            Ok(0) => return Ok(total),
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        dst.write_all(&buf[..n])?;
        total += n as u64;
    }
}

/// The images `index.json` lists: each descriptor an image manifest, or an
/// index to choose `linux/amd64` from.
fn oci_images(content: &ContentStore, index: &[u8]) -> Result<Vec<Candidate>> {
    let index = match manifest::parse(index, None).map_err(|e| Error::invalid(format!("index.json: {e}")))? {
        Fetched::Index(index) => index,
        Fetched::Manifest(_) => return Err(Error::invalid("index.json is an image manifest, not an index")),
    };
    index
        .manifests()
        .iter()
        .map(|listed| {
            let names = listed_names(listed)?;
            let what = names.first().cloned().unwrap_or_else(|| listed.digest().to_string());
            let target = image_manifest(content, listed, &what, 0)?;
            let image = checked_image(content, &target, &what)?;
            Ok(Candidate { image, names, target })
        })
        .collect()
}

/// The name an `index.json` descriptor gives its image, if it gives one
/// (see the module docs).
fn listed_names(listed: &Descriptor) -> Result<Vec<String>> {
    let Some(annotations) = listed.annotations() else { return Ok(Vec::new()) };
    if let Some(name) = annotations.get(IMAGE_NAME) {
        return Ok(vec![ImageRef::parse(name)?.name()]);
    }
    Ok(annotations
        .get(content::REF_NAME)
        .filter(|name| name.contains(['/', ':', '@']))
        .and_then(|name| ImageRef::parse(name).ok())
        .map(|reference| vec![reference.name()])
        .unwrap_or_default())
}

/// The image manifest a descriptor stands for: itself, or the `linux/amd64`
/// one of the index it names (looking into the indexes that index lists
/// when it has no such manifest itself).
fn image_manifest(content: &ContentStore, listed: &Descriptor, what: &str, depth: usize) -> Result<Descriptor> {
    let media_type = listed.media_type().to_string();
    if media::is_manifest(&media_type) {
        return Ok(listed.clone());
    }
    if !media::is_index(&media_type) {
        return Err(Error::unsupported(format!("{what}: {media_type} is neither an image manifest nor an index")));
    }
    if depth >= MAX_NESTING {
        return Err(Error::invalid(format!("{what}: indexes nested more than {MAX_NESTING} deep")));
    }
    let digest = Digest::from_oci(listed.digest())?;
    present(content, &digest, listed.size(), what, "index")?;
    let index = match manifest::parse(&content.read_blob(&digest, MAX_MANIFEST_BYTES)?, Some(media_type.as_str()))? {
        Fetched::Index(index) => index,
        Fetched::Manifest(_) => {
            return Err(Error::invalid(format!("{what}: {digest} is an image manifest, not an index")));
        }
    };
    let not_here = match manifest::select_platform(&index, &Platform::host()) {
        Ok(found) => return Ok(found),
        Err(e) => e,
    };
    let mut last = not_here;
    for nested in index.manifests().iter().filter(|d| media::is_index(d.media_type().as_ref())) {
        match image_manifest(content, nested, what, depth + 1) {
            Ok(found) => return Ok(found),
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// The image `target` names, once every blob it needs is in the store.
fn checked_image(content: &ContentStore, target: &Descriptor, what: &str) -> Result<Image> {
    let digest = Digest::from_oci(target.digest())?;
    present(content, &digest, target.size(), what, "manifest")?;
    let bytes = content.read_blob(&digest, MAX_MANIFEST_BYTES)?;
    let manifest = match manifest::parse(&bytes, Some(target.media_type().as_ref()))? {
        Fetched::Manifest(manifest) => manifest,
        Fetched::Index(_) => {
            return Err(Error::invalid(format!("{what}: {digest} is an index, not an image manifest")));
        }
    };
    let config = manifest.config();
    present(content, &Digest::from_oci(config.digest())?, config.size(), what, "config")?;
    for layer in manifest.layers() {
        present(content, &Digest::from_oci(layer.digest())?, layer.size(), what, "layer")?;
    }
    Image::from_manifest(content, &digest, None, None)
}

/// Is the blob in the store (after the archive's were stored)?
fn present(content: &ContentStore, digest: &Digest, size: u64, what: &str, kind: &str) -> Result<()> {
    if content.has_blob(digest, size)? {
        return Ok(());
    }
    Err(Error::NotFound(format!("{what}: its {kind} {digest} ({size} bytes) is not in the archive")))
}

/// The first bytes of a stored blob (four, if it has them): what tells its
/// compression.
fn magic(content: &ContentStore, digest: &Digest) -> Result<Vec<u8>> {
    let mut magic = Vec::with_capacity(4);
    content.open_blob(digest)?.take(4).read_to_end(&mut magic).with_context(|| format!("read blob {digest}"))?;
    Ok(magic)
}

/// The digest of a stored layer once decompressed: its diff ID.
fn uncompressed_digest(content: &ContentStore, digest: &Digest, compression: Compression) -> Result<Digest> {
    let open = || content.open_blob(digest).map(|blob| BufReader::with_capacity(1 << 16, blob));
    let tar: Box<dyn Read> = match compression {
        // The blob is the tar.
        Compression::None => return Ok(digest.clone()),
        Compression::Gzip => Box::new(flate2::read::MultiGzDecoder::new(open()?)),
        Compression::Zstd => {
            Box::new(zstd::stream::read::Decoder::with_buffer(open()?).context("start zstd decompression")?)
        }
    };
    let mut tar = HashingReader::new(tar);
    io::copy(&mut tar, &mut io::sink()).with_context(|| format!("decompress layer {digest}"))?;
    Ok(tar.digest())
}

/// Names the images found, or keeps those without a name, now that every
/// one of them loads. An image listed more than once (once per name) is
/// one; a name listed for two images is the later one's.
fn name(content: &ContentStore, found: Vec<Candidate>) -> Result<Vec<Loaded>> {
    let mut images: Vec<Candidate> = Vec::new();
    let mut by_digest: HashMap<Digest, usize> = HashMap::new();
    let mut owners: HashMap<String, usize> = HashMap::new();
    for Candidate { image, names, target } in found {
        let i = *by_digest.entry(image.manifest_digest.clone()).or_insert_with(|| {
            images.push(Candidate { image, names: Vec::new(), target });
            images.len() - 1
        });
        for name in names {
            if let Some(before) = owners.insert(name.clone(), i) {
                images[before].names.retain(|n| n != &name);
            }
            images[i].names.push(name);
        }
    }
    for Candidate { image, names, target } in &images {
        let target = content::manifest_descriptor(target.media_type().as_ref(), &image.manifest_digest, target.size());
        if names.is_empty() {
            content.keep(&target)?;
        }
        for name in names {
            content.set_ref(&RefEntry { name: name.clone(), target: target.clone(), repo_digest: None })?;
        }
    }
    Ok(images
        .into_iter()
        .map(|Candidate { mut image, names, .. }| {
            image.name = names.first().cloned();
            Loaded { image, names }
        })
        .collect())
}

/// A path of the archive as manifests name it: no empty or `.` components,
/// `..` taking one back (never above the archive's root).
fn clean(raw: &[u8]) -> String {
    let mut parts: Vec<&[u8]> = Vec::new();
    for part in raw.split(|&b| b == b'/') {
        match part {
            b"" | b"." => {}
            b".." => {
                parts.pop();
            }
            part => parts.push(part),
        }
    }
    String::from_utf8_lossy(&parts.join(&b'/')).into_owned()
}

/// The directory a (clean) path is in; empty at the top.
fn parent(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(dir, _)| dir)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    fn store(tmp: &Path, name: &str) -> ContentStore {
        let dir = tmp.join(name);
        ContentStore::open(dir.join("content"), dir.join("ingest"), dir.join("lock")).unwrap()
    }

    /// A layer archive (uncompressed) with these files.
    fn layer(files: &[(&str, &str)]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        for (name, data) in files {
            let mut h = tar::Header::new_gnu();
            h.set_size(data.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            b.append_data(&mut h, name, data.as_bytes()).unwrap();
        }
        b.into_inner().unwrap()
    }

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    /// An image made of `layers`, named `name`, in `content`.
    fn image(content: &ContentStore, name: &str, layers: &[Vec<u8>]) -> Image {
        import::import(content, name, layers, import::config(&["sh"], &[], None).unwrap()).unwrap()
    }

    fn config_json(diff_ids: &[Digest], architecture: &str) -> Vec<u8> {
        let diff_ids: Vec<String> = diff_ids.iter().map(ToString::to_string).collect();
        serde_json::to_vec(&json!({
            "architecture": architecture, "os": "linux",
            "rootfs": {"type": "layers", "diff_ids": diff_ids},
        }))
        .unwrap()
    }

    fn save_all(content: &ContentStore, images: &[(Image, Vec<String>)]) -> Vec<u8> {
        let mut out = Vec::new();
        let report = save(content, images, &mut out).unwrap();
        assert_eq!(report.images, images.iter().map(|(i, _)| &i.manifest_digest).collect::<BTreeSet<_>>().len());
        out
    }

    fn load_all(content: &ContentStore, archive: &[u8]) -> (Result<Vec<Loaded>>, Vec<LoadProgress>) {
        let mut events = Vec::new();
        let result = load(content, &mut &archive[..], &mut |p| events.push(p));
        (result, events)
    }

    #[derive(Debug, Clone)]
    enum Item {
        File(Vec<u8>),
        Symlink(&'static str),
        Dir,
    }

    fn file(data: impl AsRef<[u8]>) -> Item {
        Item::File(data.as_ref().to_vec())
    }

    /// An archive of `items`, in this order.
    fn archive<S: AsRef<str>>(items: &[(S, Item)]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        for (name, item) in items {
            let mut h = tar::Header::new_gnu();
            h.set_mode(0o644);
            h.set_size(0);
            match item {
                Item::File(data) => {
                    h.set_size(data.len() as u64);
                    h.set_cksum();
                    b.append_data(&mut h, name.as_ref(), &data[..]).unwrap();
                }
                Item::Symlink(target) => {
                    h.set_entry_type(EntryType::Symlink);
                    b.append_link(&mut h, name.as_ref(), target).unwrap();
                }
                Item::Dir => {
                    h.set_entry_type(EntryType::Directory);
                    h.set_cksum();
                    b.append_data(&mut h, name.as_ref(), io::empty()).unwrap();
                }
            }
        }
        b.into_inner().unwrap()
    }

    /// The files of an archive, in order.
    fn files(archive: &[u8]) -> Vec<(String, Item)> {
        let mut a = tar::Archive::new(archive);
        a.entries()
            .unwrap()
            .map(|e| {
                let mut e = e.unwrap();
                let mut data = Vec::new();
                e.read_to_end(&mut data).unwrap();
                (String::from_utf8(e.path_bytes().into_owned()).unwrap(), Item::File(data))
            })
            .collect()
    }

    fn data<'a>(files: &'a [(String, Item)], name: &str) -> &'a [u8] {
        match files.iter().find(|(n, _)| n == name) {
            Some((_, Item::File(data))) => data,
            _ => panic!("no file {name}"),
        }
    }

    fn ref_names(content: &ContentStore) -> Vec<String> {
        content.refs().unwrap().into_iter().map(|r| r.name).collect()
    }

    /// `blobs/sha256/<hex>` with the blob's bytes, from `content`.
    fn blob_item(content: &ContentStore, digest: &Digest) -> (String, Item) {
        (blob_path(digest), file(std::fs::read(content.blob_path(digest)).unwrap()))
    }

    #[test]
    fn saved_images_load_into_another_store_with_the_same_digests() {
        let tmp = tempfile::tempdir().unwrap();
        let (a, b) = (store(tmp.path(), "a"), store(tmp.path(), "b"));
        let base = layer(&[("etc/os-release", "ID=test\n")]);
        let alpine = image(&a, "alpine:3", &[base.clone(), layer(&[("bin/sh", "#!")])]);
        let web = image(&a, "ghcr.io/o/web:1", &[base, layer(&[("app/main", "print()")])]);
        let web_names = vec!["ghcr.io/o/web:1".to_owned(), "ghcr.io/o/web:latest".to_owned()];
        let saved =
            save_all(&a, &[(alpine.clone(), vec!["docker.io/library/alpine:3".into()]), (web.clone(), web_names)]);

        let (loaded, events) = load_all(&b, &saved);
        let mut got: Vec<_> = loaded.unwrap().into_iter().map(|l| (l.image.manifest_digest, l.names)).collect();
        got.sort();
        let mut want = vec![
            (alpine.manifest_digest.clone(), vec!["docker.io/library/alpine:3".to_owned()]),
            (web.manifest_digest.clone(), vec!["ghcr.io/o/web:1".to_owned(), "ghcr.io/o/web:latest".to_owned()]),
        ];
        want.sort();
        assert_eq!(got, want);
        assert_eq!(ref_names(&b), ["docker.io/library/alpine:3", "ghcr.io/o/web:1", "ghcr.io/o/web:latest"]);
        for (name, original) in [("alpine:3", &alpine), ("ghcr.io/o/web:1", &web), ("ghcr.io/o/web:latest", &web)] {
            let image = Image::load(&b, name).unwrap();
            assert_eq!(image.manifest_digest, original.manifest_digest, "{name}");
            assert_eq!(image.config_digest, original.config_digest, "{name}");
            assert_eq!(image.layers, original.layers, "{name}");
        }
        assert!(b.kept().unwrap().is_empty());
        // 2 manifests, 2 configs, 3 layers (the base is shared), all new.
        assert_eq!(events.len(), 7);
        assert!(events.iter().all(|LoadProgress::Blob { existed, .. }| !existed));
        assert_eq!(std::fs::read_dir(tmp.path().join("b/ingest")).unwrap().count(), 0);

        // What Docker reads: both kinds of name, and its own manifest.json.
        let files = files(&saved);
        let index: Value = serde_json::from_slice(data(&files, "index.json")).unwrap();
        let named: Vec<(&str, &str)> = index["manifests"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| {
                let annotations = &d["annotations"];
                (annotations[IMAGE_NAME].as_str().unwrap(), annotations[content::REF_NAME].as_str().unwrap())
            })
            .collect();
        assert_eq!(
            named,
            [("docker.io/library/alpine:3", "3"), ("ghcr.io/o/web:1", "1"), ("ghcr.io/o/web:latest", "latest")]
        );
        let docker: Vec<Value> = serde_json::from_slice(data(&files, "manifest.json")).unwrap();
        let mut tags: Vec<Value> = docker.iter().map(|m| m["RepoTags"].clone()).collect();
        tags.sort_by_key(|t| t.to_string());
        assert_eq!(tags, [json!(["alpine:3"]), json!(["ghcr.io/o/web:1", "ghcr.io/o/web:latest"])]);
        for m in &docker {
            for path in std::iter::once(&m["Config"]).chain(m["Layers"].as_array().unwrap()) {
                data(&files, path.as_str().unwrap());
            }
        }
    }

    #[test]
    fn an_image_saved_by_id_loads_kept_without_a_name() {
        let tmp = tempfile::tempdir().unwrap();
        let (a, b) = (store(tmp.path(), "a"), store(tmp.path(), "b"));
        let img = image(&a, "local/x:1", &[layer(&[("x", "x")])]);
        let saved = save_all(&a, &[(img.clone(), vec![])]);
        let files = files(&saved);
        let index: Value = serde_json::from_slice(data(&files, "index.json")).unwrap();
        assert_eq!(index["manifests"][0]["digest"], img.manifest_digest.to_string());
        assert!(index["manifests"][0].get("annotations").is_none());
        let docker: Value = serde_json::from_slice(data(&files, "manifest.json")).unwrap();
        assert_eq!(docker[0]["RepoTags"], json!([]));

        let loaded = load_all(&b, &saved).0.unwrap();
        assert_eq!(loaded.len(), 1);
        assert!(loaded[0].names.is_empty() && loaded[0].image.name.is_none());
        assert!(ref_names(&b).is_empty());
        let kept: Vec<String> = b.kept().unwrap().iter().map(|d| d.digest().to_string()).collect();
        assert_eq!(kept, [img.manifest_digest.to_string()]);
    }

    #[test]
    fn loading_again_finds_every_blob_stored() {
        let tmp = tempfile::tempdir().unwrap();
        let (a, b) = (store(tmp.path(), "a"), store(tmp.path(), "b"));
        let img = image(&a, "again:1", &[layer(&[("a", "1")]), layer(&[("b", "2")])]);
        let saved = save_all(&a, &[(img.clone(), vec!["docker.io/library/again:1".into()])]);
        let (first, first_events) = load_all(&b, &saved);
        let (second, second_events) = load_all(&b, &saved);
        let digests = |events: &[LoadProgress]| {
            events.iter().map(|LoadProgress::Blob { digest, size, .. }| (digest.clone(), *size)).collect::<Vec<_>>()
        };
        assert_eq!(digests(&first_events), digests(&second_events));
        assert!(first_events.iter().all(|LoadProgress::Blob { existed, .. }| !existed));
        assert!(second_events.iter().all(|LoadProgress::Blob { existed, .. }| *existed));
        assert_eq!(first.unwrap()[0].image.manifest_digest, second.unwrap()[0].image.manifest_digest);
        assert_eq!(ref_names(&b), ["docker.io/library/again:1"]);
        // Into the store it came from: nothing new either.
        let (_, events) = load_all(&a, &saved);
        assert!(events.iter().all(|LoadProgress::Blob { existed, .. }| *existed));
    }

    #[test]
    fn a_tampered_blob_fails_the_load_and_names_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let (a, b) = (store(tmp.path(), "a"), store(tmp.path(), "b"));
        let img = image(&a, "tampered:1", &[layer(&[("a", "the original")])]);
        let saved = save_all(&a, &[(img.clone(), vec!["docker.io/library/tampered:1".into()])]);
        let mut files = files(&saved);
        let path = blob_path(&img.layers[0].blob);
        let Some((_, Item::File(blob))) = files.iter_mut().find(|(n, _)| *n == path) else { panic!("no {path}") };
        let middle = blob.len() / 2;
        blob[middle] ^= 0xff;

        let err = load_all(&b, &archive(&files)).0.unwrap_err();
        assert!(matches!(err, Error::DigestMismatch { .. }), "{err}");
        assert!(err.to_string().contains(&img.layers[0].blob.to_string()), "{err}");
        assert!(ref_names(&b).is_empty() && b.kept().unwrap().is_empty());
        assert!(!b.has_blob(&img.layers[0].blob, img.layers[0].size).unwrap());
    }

    #[test]
    fn a_missing_blob_fails_the_load_naming_it() {
        let tmp = tempfile::tempdir().unwrap();
        let (a, b) = (store(tmp.path(), "a"), store(tmp.path(), "b"));
        let img = image(&a, "partial:1", &[layer(&[("a", "1")]), layer(&[("b", "2")])]);
        let saved = save_all(&a, &[(img.clone(), vec!["docker.io/library/partial:1".into()])]);
        let missing = &img.layers[1].blob;
        let files: Vec<_> = files(&saved).into_iter().filter(|(n, _)| *n != blob_path(missing)).collect();
        let err = load_all(&b, &archive(&files)).0.unwrap_err();
        assert!(matches!(err, Error::NotFound(_)), "{err}");
        let message = err.to_string();
        assert!(message.contains(&missing.to_string()) && message.contains("partial:1"), "{message}");
        assert!(ref_names(&b).is_empty() && b.kept().unwrap().is_empty());
    }

    #[test]
    fn docker_s_older_format_loads_with_its_duplicate_layers_linked() {
        let tmp = tempfile::tempdir().unwrap();
        let b = store(tmp.path(), "b");
        let first = layer(&[("etc/hostname", "legacy\n")]);
        let second = layer(&[("bin/tool", "#!/bin/sh\n")]);
        let compressed = gzip(&second);
        let diff_ids = [Digest::of(&first), Digest::of(&first), Digest::of(&second)];
        let config = config_json(&diff_ids, "amd64");
        let config_name = format!("{}.json", Digest::of(&config).hex());
        let manifest = json!([{
            "Config": config_name,
            "RepoTags": ["legacy:1", "example.com/team/legacy:1"],
            "Layers": ["aaa/layer.tar", "bbb/layer.tar", "./ccc/layer.tar"],
        }]);
        let legacy = archive(&[
            ("aaa", Item::Dir),
            ("aaa/VERSION", file("1.0")),
            ("aaa/json", file("{}")),
            ("aaa/layer.tar", file(&first)),
            ("bbb", Item::Dir),
            // A layer listed twice is saved once; the other is a link.
            ("bbb/layer.tar", Item::Symlink("../aaa/layer.tar")),
            ("bbb/json", file("{}")),
            ("ccc/layer.tar", file(&compressed)),
            (config_name.as_str(), file(&config)),
            ("manifest.json", file(manifest.to_string())),
            ("repositories", file(r#"{"legacy":{"1":"ccc"}}"#)),
        ]);

        let (loaded, events) = load_all(&b, &legacy);
        let loaded = loaded.unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].names, ["docker.io/library/legacy:1", "example.com/team/legacy:1"]);
        assert_eq!(events.len(), 3, "two layers and a config: {events:?}");
        let image = Image::load(&b, "legacy:1").unwrap();
        assert_eq!(image.manifest_digest, loaded[0].image.manifest_digest);
        assert_eq!(image.config_digest, Digest::of(&config), "the config is stored as it was");
        assert_eq!(image.layers.iter().map(|l| l.diff_id.clone()).collect::<Vec<_>>(), diff_ids);
        assert_eq!(
            image.layers.iter().map(|l| l.media_type.as_str()).collect::<Vec<_>>(),
            [media::OCI_LAYER, media::OCI_LAYER, media::OCI_LAYER_GZIP]
        );
        assert_eq!(image.layers[0].blob, image.layers[1].blob);
        assert_eq!(image.layers[2].blob, Digest::of(&compressed));
        assert_eq!(image.manifest.media_type().as_ref().map(ToString::to_string).as_deref(), Some(media::OCI_MANIFEST));
        assert_eq!(ref_names(&b), ["docker.io/library/legacy:1", "example.com/team/legacy:1"]);
    }

    #[test]
    fn a_legacy_layer_that_is_not_what_its_config_says_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let b = store(tmp.path(), "b");
        let tar = layer(&[("a", "1")]);
        for (stored, compressed) in [(tar.clone(), false), (gzip(&tar), true)] {
            let config = config_json(&[Digest::of(b"something else")], "amd64");
            let config_name = format!("{}.json", Digest::of(&config).hex());
            let manifest = json!([{"Config": config_name, "RepoTags": ["wrong:1"], "Layers": ["l/layer.tar"]}]);
            let legacy = archive(&[
                ("l/layer.tar", file(&stored)),
                (config_name.as_str(), file(&config)),
                ("manifest.json", file(manifest.to_string())),
            ]);
            let err = load_all(&b, &legacy).0.unwrap_err();
            assert!(matches!(err, Error::DigestMismatch { .. }), "compressed: {compressed}: {err}");
            assert!(err.to_string().contains("l/layer.tar"), "{err}");
            assert!(ref_names(&b).is_empty());
        }
        // A link that leads nowhere but to itself.
        let config = config_json(&[Digest::of(&tar)], "amd64");
        let config_name = format!("{}.json", Digest::of(&config).hex());
        let manifest = json!([{"Config": config_name, "RepoTags": ["lacking:1"], "Layers": ["l/layer.tar"]}]);
        let legacy = archive(&[
            ("l/layer.tar", Item::Symlink("layer.tar")),
            (config_name.as_str(), file(&config)),
            ("manifest.json", file(manifest.to_string())),
        ]);
        let err = load_all(&b, &legacy).0.unwrap_err();
        assert!(matches!(err, Error::NotFound(_)) && err.to_string().contains("l/layer.tar"), "{err}");
    }

    #[test]
    fn an_index_of_platforms_loads_its_amd64_image() {
        let tmp = tempfile::tempdir().unwrap();
        let (a, b) = (store(tmp.path(), "a"), store(tmp.path(), "b"));
        let amd64 = image(&a, "multi:amd64", &[layer(&[("arch", "amd64")])]);
        // An arm64 image of which the archive has only the manifest.
        let arm_tar = layer(&[("arch", "arm64")]);
        let arm_layer = gzip(&arm_tar);
        let arm_blob = a.write_blob(&arm_layer).unwrap();
        let arm64 = import::write_image(
            &a,
            &config_json(&[Digest::of(&arm_tar)], "arm64"),
            &[content::descriptor(media::OCI_LAYER_GZIP, &arm_blob, arm_layer.len() as u64)],
        )
        .unwrap();
        let amd64_size = a.blob_size(&amd64.manifest_digest).unwrap().unwrap();
        let platform = |digest: String, size: u64, arch: &str| {
            json!({"mediaType": media::OCI_MANIFEST, "digest": digest, "size": size,
                   "platform": {"os": "linux", "architecture": arch}})
        };
        let inner = serde_json::to_vec(&json!({"schemaVersion": 2, "mediaType": media::OCI_INDEX, "manifests": [
            platform(arm64.digest().to_string(), arm64.size(), "arm64"),
            platform(amd64.manifest_digest.to_string(), amd64_size, "amd64"),
        ]}))
        .unwrap();
        // An index of indexes, too: no manifest of its own.
        let index_of = |bytes: &[u8]| json!({"mediaType": media::OCI_INDEX, "digest": Digest::of(bytes).to_string(), "size": bytes.len()});
        let outer = json!({"schemaVersion": 2, "mediaType": media::OCI_INDEX, "manifests": [index_of(&inner)]});
        let outer = serde_json::to_vec(&outer).unwrap();
        let named = |mut d: Value, name: &str| {
            d["annotations"] = json!({IMAGE_NAME: name, content::REF_NAME: "1"});
            d
        };
        let index = json!({"schemaVersion": 2, "manifests": [
            named(index_of(&inner), "docker.io/library/multi:1"),
            named(index_of(&outer), "docker.io/library/nested:1"),
        ]});
        let mut items = vec![
            ("oci-layout".to_owned(), file(OCI_LAYOUT)),
            ("index.json".to_owned(), file(index.to_string())),
            (blob_path(&Digest::of(&inner)), file(&inner)),
            (blob_path(&Digest::of(&outer)), file(&outer)),
            blob_item(&a, &amd64.manifest_digest),
            blob_item(&a, &amd64.config_digest),
            blob_item(&a, &Digest::from_oci(arm64.digest()).unwrap()),
        ];
        items.extend(amd64.layers.iter().map(|l| blob_item(&a, &l.blob)));

        let loaded = load_all(&b, &archive(&items)).0.unwrap();
        assert_eq!(loaded.len(), 1, "both names lead to the one amd64 image");
        assert_eq!(loaded[0].image.manifest_digest, amd64.manifest_digest);
        assert_eq!(loaded[0].names, ["docker.io/library/multi:1", "docker.io/library/nested:1"]);
        assert_eq!(Image::load(&b, "nested:1").unwrap().manifest_digest, amd64.manifest_digest);

        // Without the amd64 manifest, the load fails naming the image.
        let items: Vec<_> = items.into_iter().filter(|(n, _)| *n != blob_path(&amd64.manifest_digest)).collect();
        let c = store(tmp.path(), "c");
        let err = load_all(&c, &archive(&items)).0.unwrap_err();
        assert!(err.to_string().contains("multi:1"), "{err}");
        assert!(ref_names(&c).is_empty());
    }

    #[test]
    fn either_index_json_or_manifest_json_is_enough() {
        let tmp = tempfile::tempdir().unwrap();
        let a = store(tmp.path(), "a");
        let img = image(&a, "either:1", &[layer(&[("a", "1")]), layer(&[("b", "2")])]);
        let saved = save_all(&a, &[(img.clone(), vec!["docker.io/library/either:1".into()])]);
        for left_out in ["manifest.json", "index.json"] {
            let b = store(tmp.path(), left_out);
            let files: Vec<_> = files(&saved).into_iter().filter(|(n, _)| n != left_out).collect();
            let loaded = load_all(&b, &archive(&files)).0.unwrap();
            assert_eq!(loaded[0].names, ["docker.io/library/either:1"], "without {left_out}");
            // Docker's manifest.json leads to the very same OCI manifest.
            assert_eq!(loaded[0].image.manifest_digest, img.manifest_digest, "without {left_out}");
            assert_eq!(Image::load(&b, "either:1").unwrap().layers, img.layers, "without {left_out}");
        }
    }

    #[test]
    fn save_writes_the_same_bytes_for_the_same_images() {
        let tmp = tempfile::tempdir().unwrap();
        let a = store(tmp.path(), "a");
        let x = image(&a, "x:1", &[layer(&[("x", "x")])]);
        let y = image(&a, "y:1", &[layer(&[("y", "y")]), layer(&[("z", "z")])]);
        let (x_names, y_names) = (vec!["docker.io/library/x:1".to_owned()], vec!["docker.io/library/y:1".to_owned()]);
        let mut one = Vec::new();
        let report = save(&a, &[(x.clone(), x_names.clone()), (y.clone(), y_names.clone())], &mut one).unwrap();
        // Another order, a name twice, an image by id as well as by name.
        let y_twice = [y_names.clone(), y_names].concat();
        let two = save_all(&a, &[(y.clone(), y_twice), (x.clone(), x_names), (y.clone(), vec![])]);
        assert_eq!(one, two);

        let mut blobs: Vec<String> = [&x, &y]
            .iter()
            .flat_map(|i| [&i.manifest_digest, &i.config_digest].into_iter().chain(i.layers.iter().map(|l| &l.blob)))
            .map(blob_path)
            .collect();
        blobs.sort();
        let mut want = vec!["oci-layout".to_owned(), "index.json".to_owned(), "manifest.json".to_owned()];
        want.extend(blobs.iter().cloned());
        let mut archive = tar::Archive::new(&one[..]);
        let mut names = Vec::new();
        for entry in archive.entries().unwrap() {
            let entry = entry.unwrap();
            let h = entry.header();
            assert_eq!(
                (h.entry_type(), h.mode().unwrap(), h.uid().unwrap(), h.gid().unwrap(), h.mtime().unwrap()),
                (EntryType::Regular, 0o644, 0, 0, 0)
            );
            assert_eq!(h.username_bytes(), Some(&b""[..]));
            names.push(String::from_utf8(entry.path_bytes().into_owned()).unwrap());
        }
        assert_eq!(names, want);
        let bytes = files(&one)
            .iter()
            .skip(3)
            .map(|(_, f)| match f {
                Item::File(d) => d.len() as u64,
                _ => 0,
            })
            .sum();
        assert_eq!(report, SaveReport { images: 2, blobs: blobs.len(), bytes });
    }

    #[test]
    fn save_needs_every_blob_before_it_writes() {
        let tmp = tempfile::tempdir().unwrap();
        let a = store(tmp.path(), "a");
        let img = image(&a, "gone:1", &[layer(&[("x", "x")])]);
        std::fs::remove_file(a.blob_path(&img.layers[0].blob)).unwrap();
        let mut out = Vec::new();
        let err = save(&a, &[(img.clone(), vec![])], &mut out).unwrap_err();
        assert!(matches!(err, Error::NotFound(_)), "{err}");
        assert!(err.to_string().contains(&img.layers[0].blob.to_string()), "{err}");
        assert!(out.is_empty(), "nothing written");
    }

    #[test]
    fn a_name_listed_for_two_images_is_the_later_ones() {
        let tmp = tempfile::tempdir().unwrap();
        let (a, b) = (store(tmp.path(), "a"), store(tmp.path(), "b"));
        let x = image(&a, "x:1", &[layer(&[("x", "x")])]);
        let y = image(&a, "y:1", &[layer(&[("y", "y")])]);
        let descriptor = |image: &Image, annotations: Value| {
            let size = a.blob_size(&image.manifest_digest).unwrap().unwrap();
            json!({"mediaType": media::OCI_MANIFEST, "digest": image.manifest_digest.to_string(), "size": size,
                   "annotations": annotations})
        };
        let index = json!({"schemaVersion": 2, "manifests": [
            descriptor(&x, json!({IMAGE_NAME: "docker.io/library/dup:1"})),
            descriptor(&y, json!({IMAGE_NAME: "docker.io/library/dup:1"})),
            // A bare tag names nothing.
            descriptor(&x, json!({content::REF_NAME: "latest"})),
            // A full reference does.
            descriptor(&y, json!({content::REF_NAME: "example.com/y:2"})),
        ]});
        let mut items = vec![("index.json".to_owned(), file(index.to_string()))];
        for image in [&x, &y] {
            items.push(blob_item(&a, &image.manifest_digest));
            items.push(blob_item(&a, &image.config_digest));
            items.extend(image.layers.iter().map(|l| blob_item(&a, &l.blob)));
        }
        let loaded = load_all(&b, &archive(&items)).0.unwrap();
        let summary: Vec<_> = loaded.into_iter().map(|l| (l.image.manifest_digest, l.names)).collect();
        assert_eq!(
            summary,
            [
                (x.manifest_digest.clone(), vec![]),
                (y.manifest_digest.clone(), vec!["docker.io/library/dup:1".to_owned(), "example.com/y:2".to_owned()]),
            ]
        );
        assert_eq!(Image::load(&b, "dup:1").unwrap().manifest_digest, y.manifest_digest);
        assert_eq!(b.kept().unwrap().len(), 1);
    }

    #[test]
    fn names_come_from_the_containerd_annotation_or_a_full_ref_name() {
        let listed = |annotations: &[(&str, &str)]| {
            let mut d = content::descriptor(media::OCI_MANIFEST, &Digest::of(b"m"), 1);
            if !annotations.is_empty() {
                d.set_annotations(Some(annotations.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()));
            }
            d
        };
        for (annotations, want) in [
            (vec![], vec![]),
            (vec![(content::REF_NAME, "latest")], vec![]),
            (vec![(content::REF_NAME, "x:2")], vec!["docker.io/library/x:2"]),
            (vec![(content::REF_NAME, "docker.io/library/x:2")], vec!["docker.io/library/x:2"]),
            (vec![(content::REF_NAME, "Not/Valid")], vec![]),
            (vec![(IMAGE_NAME, "example.com/a/b:1"), (content::REF_NAME, "1")], vec!["example.com/a/b:1"]),
        ] {
            assert_eq!(listed_names(&listed(&annotations)).unwrap(), want, "{annotations:?}");
        }
        assert!(listed_names(&listed(&[(IMAGE_NAME, "Not Valid")])).is_err());
    }

    #[test]
    fn what_is_not_an_image_archive_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let b = store(tmp.path(), "b");
        let err = load_all(&b, &archive(&[("hello.txt", file("hi"))])).0.unwrap_err();
        assert!(err.to_string().contains("not an image archive"), "{err}");
        let huge = vec![b' '; (MAX_MANIFEST_BYTES + 1) as usize];
        let err = load_all(&b, &archive(&[("index.json", file(&huge))])).0.unwrap_err();
        assert!(err.to_string().contains("more than"), "{err}");
        let manifest = r#"{"schemaVersion":2,"config":{},"layers":[]}"#;
        let err = load_all(&b, &archive(&[("index.json", file(manifest))])).0.unwrap_err();
        assert!(err.to_string().contains("index.json"), "{err}");
    }

    #[test]
    fn paths_and_short_names() {
        assert_eq!(clean(b"./a//b/./c"), "a/b/c");
        assert_eq!(clean(b"/../../x"), "x");
        assert_eq!(clean(b"a/../../b/"), "b");
        assert_eq!((parent("a/b/c"), parent("c")), ("a/b", ""));
        let pinned = format!("docker.io/library/alpine@{}", Digest::of(b""));
        for (name, short) in [
            ("docker.io/library/alpine:latest", Some("alpine:latest")),
            ("docker.io/bitnami/redis:7", Some("bitnami/redis:7")),
            ("docker.io/library/a/b:1", Some("library/a/b:1")),
            ("ghcr.io/o/n:1", Some("ghcr.io/o/n:1")),
            ("localhost:5000/x:2", Some("localhost:5000/x:2")),
            (pinned.as_str(), None),
        ] {
            let reference = ImageRef::parse(name).unwrap();
            assert_eq!(tag(&reference).map(|t| familiar(&reference, t)).as_deref(), short, "{name}");
        }
        assert_eq!(named("blobs/sha256/x"), None);
        let hex = Digest::of(b"").hex().to_owned();
        assert_eq!(named(&format!("{hex}.json")), Some((Digest::of(b""), Some(MAX_CONFIG_BYTES))));
        assert_eq!(named(&format!("blobs/sha256/{hex}")), Some((Digest::of(b""), None)));
        assert_eq!(named(&format!("dir/{hex}.json")), None);
    }
}

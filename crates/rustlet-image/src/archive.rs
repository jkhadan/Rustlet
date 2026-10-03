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
//! archive. Blobs are streamed from the store, never held whole.
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
//!   `org.opencontainers.image.ref.name` when that is a full reference.
//! - **Docker's older format** (`docker save` before 25): `manifest.json`
//!   lists per image its `Config` (`<hex>.json`, stored expecting that
//!   digest), `RepoTags` and `Layers` (`<dir>/layer.tar`, uncompressed or
//!   compressed, stored under the digest they hash to; a duplicate layer is
//!   a symlink to another's `layer.tar`, resolved within the archive). The
//!   loader writes an OCI manifest for each (`import::write_image`; the
//!   layers' media types from their content, `media::detect_compression`).
//!   When both `index.json` and `manifest.json` are there, `index.json`
//!   wins.
//!
//! Other entries (`repositories`, `<dir>/json`, `<dir>/VERSION`) are
//! ignored. Once the archive ends, every image must load
//! (`Image::from_manifest`: its config parses, one diff ID per layer) with
//! every blob present, or the load fails naming what is missing; only then
//! are names set ([`ContentStore::set_ref`]), and an image without one is
//! kept ([`ContentStore::keep`]). Blobs already stored aren't written again
//! (an entry's data is skipped). JSON files are capped as manifests and
//! configs are (4 and 8 MiB); the archive itself isn't.
//!
//! [OCI image layout]: https://github.com/opencontainers/image-spec/blob/main/image-layout.md

use std::io::{Read, Write};

use crate::content::ContentStore;
use crate::digest::Digest;
use crate::error::Result;
use crate::image::Image;

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
    let _ = (content, images, out);
    unimplemented!("save: agent C")
}

/// Reads an archive from `input` into the store (see the module docs).
pub fn load(
    content: &ContentStore,
    input: &mut dyn Read,
    progress: &mut dyn FnMut(LoadProgress),
) -> Result<Vec<Loaded>> {
    let _ = (content, input, progress);
    unimplemented!("load: agent C")
}

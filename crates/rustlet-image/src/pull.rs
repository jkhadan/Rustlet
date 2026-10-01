//! Pulling images from a registry into the content store.
//!
//! CONTRACT (to be implemented; delete this paragraph when done). The
//! registry protocol (auth challenge, manifest and blob requests) is
//! `oci-client`'s; this module decides *what* to fetch and verifies and
//! stores it:
//!
//! 1. `pull_manifest_raw(reference, media::MANIFEST_TYPES)` keeps the exact
//!    bytes (their digest is the manifest's identity). If the reference pins
//!    a digest, the bytes must hash to it. The digest of this first response
//!    is the *repo digest*.
//! 2. An index: [`manifest::select_platform`] for `options.platform`, then
//!    fetch that manifest by digest (bytes must hash to the descriptor's
//!    digest, size must match, and it must be a manifest, not another index).
//! 3. `manifest::check_manifest`, then the config blob (≤
//!    `config::MAX_CONFIG_BYTES`) and every layer blob, each skipped if the
//!    store already has it with the right size (`ContentStore::has_blob`),
//!    else streamed (`Client::pull_blob_stream`) into a
//!    `ContentStore::ingest` with the descriptor's digest and size, then
//!    `commit`ted. Up to `options.max_concurrent_downloads` blobs at once.
//!    Nothing unverified is ever renamed into `blobs/`.
//! 4. The config must parse (`ImageConfig::parse`), its diff_ids count must
//!    equal the manifest's layer count, and `check_runnable` must pass.
//! 5. Store the manifest bytes (`write_blob`), then `set_ref` with
//!    `content::manifest_descriptor(media type, digest, size)`, name =
//!    `reference.name()`, repo digest from step 1. Return `Image::load`.
//!
//! Progress events go to the caller's callback; serialized with serde they
//! are the NDJSON lines a daemon streams (Phase 4).

use serde::Serialize;

use crate::content::ContentStore;
use crate::digest::Digest;
use crate::error::Result;
use crate::image::Image;
use crate::manifest::Platform;
use crate::reference::ImageRef;

/// When to contact the registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PullPolicy {
    /// Only if the store doesn't have the name yet (Docker's default).
    #[default]
    Missing,
    /// Always ask the registry what the name points at now. A `HEAD`
    /// request first: if the store already has that manifest, nothing is
    /// downloaded (and Docker Hub doesn't count a `HEAD` as a pull).
    Always,
    /// Never: the store must have it.
    Never,
}

/// How to pull.
#[derive(Debug, Clone)]
pub struct PullOptions {
    /// Which image of a multi-platform index to take.
    pub platform: Platform,
    /// Blobs downloaded at once (Docker: 3).
    pub max_concurrent_downloads: usize,
    /// Registries (`host[:port]`) to talk plain HTTP to; tests use one on
    /// `127.0.0.1`. Everything else is HTTPS.
    pub insecure_registries: Vec<String>,
}

impl Default for PullOptions {
    fn default() -> PullOptions {
        PullOptions { platform: Platform::host(), max_concurrent_downloads: 3, insecure_registries: Vec::new() }
    }
}

/// Which kind of blob a progress event is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlobKind {
    Config,
    Layer,
}

/// A pull's progress, one event at a time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Progress {
    /// Asking the registry what `reference` points at.
    Resolving { reference: String },
    /// The manifest is chosen.
    Resolved {
        reference: String,
        /// The single-platform manifest that will be stored.
        manifest: Digest,
        /// What the registry returned for the reference (an index's digest
        /// for a multi-platform image).
        repo_digest: Digest,
        platform: String,
        layers: usize,
        /// Total compressed size of the config and layers.
        size: u64,
    },
    /// The store already has this blob.
    Exists { kind: BlobKind, digest: Digest, size: u64 },
    /// Bytes received so far (sent at most every 1 MiB or so, and at the end).
    Downloading { kind: BlobKind, digest: Digest, current: u64, total: u64 },
    /// Received in full and verified.
    Downloaded { kind: BlobKind, digest: Digest, size: u64 },
    /// The name now points at the manifest.
    Done { reference: String, manifest: Digest },
}

/// A registry client.
pub struct Puller {
    options: PullOptions,
}

impl Puller {
    pub fn new(options: PullOptions) -> Puller {
        Puller { options }
    }

    pub fn options(&self) -> &PullOptions {
        &self.options
    }

    /// Pulls `reference` into `content` and returns the stored image.
    /// Anonymous access only (the registry's bearer-token challenge is
    /// answered without credentials).
    pub async fn pull(
        &self,
        content: &ContentStore,
        reference: &ImageRef,
        progress: &(dyn Fn(&Progress) + Send + Sync),
    ) -> Result<Image> {
        let _ = (content, reference, progress);
        unimplemented!("pull::Puller::pull")
    }
}

/// The image `reference` names, contacting the registry as `policy` says.
pub async fn ensure(
    content: &ContentStore,
    puller: &Puller,
    reference: &ImageRef,
    policy: PullPolicy,
    progress: &(dyn Fn(&Progress) + Send + Sync),
) -> Result<Image> {
    let _ = (content, puller, reference, policy, progress);
    unimplemented!("pull::ensure")
}

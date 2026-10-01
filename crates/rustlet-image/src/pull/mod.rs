//! Pulling images from a registry into the content store.
//!
//! A registry keeps content by digest and lets names (tags) point at some
//! of it. A tag moves: `alpine:latest` is a different image every few
//! weeks. A digest doesn't: `sha256:1c4eef65…` names the same bytes
//! forever. So a pull asks once what the reference points at *now*, and
//! from then on asks only for content by digest. Every document names the
//! next ones by digest, so each can be checked as it arrives against a
//! digest that is already trusted:
//!
//! ```text
//!  GET /v2/library/alpine/manifests/latest ─► index      repo digest = sha256 of these bytes
//!        │ select_platform(linux/amd64)
//!        ▼
//!  GET …/manifests/sha256:9a1c… ────────────► manifest   must hash to the index entry's digest
//!        ├─ GET …/blobs/sha256:8c45… ───────► config     must hash to the manifest's config digest
//!        └─ GET …/blobs/sha256:9824… (×N) ──► layers     each must hash to its descriptor's digest
//! ```
//!
//! The protocol itself is `oci-client`'s: the `/v2/` HTTP API, redirects
//! to a CDN, and the anonymous token handshake (`/v2/` answers `401` with
//! `WWW-Authenticate: Bearer realm=…`, and a pull token is asked for there
//! without credentials, as `docker pull` does for public images). This
//! module decides what to fetch, in what order, and checks and files what
//! arrives:
//!
//! 1. **Resolve.** The reference's manifest is fetched raw, with an
//!    `Accept` header that lists indexes first, and its exact bytes are
//!    kept: the digest is of the bytes, and re-serialized JSON would hash
//!    differently. If the reference pins a digest (`name@sha256:…`), the
//!    bytes must hash to it. An index is narrowed to one manifest by
//!    platform ([`crate::manifest::select_platform`]), which is then fetched by
//!    digest and must have exactly the digest and size the index gave.
//! 2. **Config.** It is small and says what the image is, so it comes
//!    first: it must parse, list one diff ID per layer and be for this
//!    host's platform before any layer is fetched. Refusing an arm64-only
//!    image costs one small download, not hundreds of megabytes.
//! 3. **Layers**, up to `max_concurrent_downloads` at a time. A blob the
//!    store already has (same digest, same size) is skipped; that is how
//!    images share layers. Any other streams into an
//!    [`Ingest`](crate::content::Ingest), which hashes and counts the
//!    bytes as they arrive and moves the file into `blobs/` only once its
//!    size and digest are what the descriptor said. (`oci-client` checks
//!    digests too; nothing here relies on it.)
//! 4. **Manifest, then name.** The manifest goes into the store only after
//!    everything it names, and the name into `index.json` last. A pull
//!    that fails at any point sets no name and leaves nothing unverified
//!    behind: partial downloads are deleted, and whatever reached `blobs/`
//!    is exactly what its digest says, so the next attempt skips it.
//!
//! **Repo digest and manifest digest.** For a single-platform image they
//! are the same. For a multi-platform one the registry answers the tag with
//! the index, whose digest identifies the image on every platform: it is
//! what `docker images --digests` shows and what people pin with
//! `name@sha256:…`. The store keeps only the manifest chosen from the
//! index, under the name, and records the index's digest beside it
//! ([`RefEntry::repo_digest`]). That record is what lets
//! [`PullPolicy::Always`] see, from a single `HEAD` request, that a name
//! still points at what the store has.
//!
//! Progress goes to the caller's callback one [`Progress`] at a time;
//! serialized with serde they are the NDJSON lines the daemon streams
//! (Phase 4).

#[cfg(test)]
mod tests;

use std::collections::HashSet;
use std::io::Write;
use std::time::Duration;

use bytes::Bytes;
use futures::stream::{self, StreamExt, TryStreamExt};
use oci_client::Client;
use oci_client::client::{ClientConfig, ClientProtocol};
use oci_client::errors::{DigestError, OciDistributionError};
use oci_client::secrets::RegistryAuth;
use oci_spec::image::{Descriptor, ImageManifest};
use serde::Serialize;

use crate::config::{ImageConfig, MAX_CONFIG_BYTES};
use crate::content::{ContentStore, RefEntry, manifest_descriptor};
use crate::digest::Digest;
use crate::error::{Context, Error, Result};
use crate::image::Image;
use crate::manifest::{self, Fetched, MAX_MANIFEST_BYTES, Platform};
use crate::media;
use crate::reference::ImageRef;

/// A download reports its progress about every this many bytes.
const PROGRESS_STEP: u64 = 1 << 20;

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
///
/// A pull sends `Resolving`, `Resolved`, then for each blob (the config
/// first, then the layers, interleaved) either `Exists` or a run of
/// `Downloading` ending in `Downloaded`, and finally `Done`.
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
        /// `os/arch[/variant]`: the index entry's, for a multi-platform
        /// image. A single-platform manifest doesn't say, so this is the
        /// platform asked for, which the config is checked against before
        /// any layer is fetched.
        platform: String,
        layers: usize,
        /// Total compressed size of the config and layers.
        size: u64,
    },
    /// The store already has this blob.
    Exists { kind: BlobKind, digest: Digest, size: u64 },
    /// Bytes received so far: 0 when the response starts, then about every
    /// 1 MiB, and once at the end.
    Downloading { kind: BlobKind, digest: Digest, current: u64, total: u64 },
    /// Received in full and verified.
    Downloaded { kind: BlobKind, digest: Digest, size: u64 },
    /// The name now points at the manifest.
    Done { reference: String, manifest: Digest },
}

/// A registry client. It keeps connections and registry tokens between
/// pulls, so one is enough for a whole daemon.
pub struct Puller {
    options: PullOptions,
    client: Client,
}

impl Puller {
    /// A client for `options`. Nothing is contacted until the first pull.
    pub fn new(options: PullOptions) -> Puller {
        let client = Client::new(ClientConfig {
            protocol: ClientProtocol::HttpsExcept(options.insecure_registries.clone()),
            // Platforms are chosen by `manifest::select_platform`, which knows
            // about variants and attestation entries. oci-client's resolver
            // would only run inside its own pull functions, unused here.
            platform_resolver: None,
            connect_timeout: Some(Duration::from_secs(30)),
            // Per read, not per request: a layer may take minutes to arrive,
            // but a connection that sends nothing for a minute is dead.
            read_timeout: Some(Duration::from_secs(60)),
            user_agent: concat!("rustlet/", env!("CARGO_PKG_VERSION")),
            ..ClientConfig::default()
        });
        Puller { options, client }
    }

    pub fn options(&self) -> &PullOptions {
        &self.options
    }

    /// Pulls `reference` into `content` and returns the stored image.
    /// Anonymous access only (the registry's bearer-token challenge is
    /// answered without credentials).
    ///
    /// Fails with `DigestMismatch` if anything isn't the digest or size
    /// that named it, `Unsupported` for what isn't a container image for
    /// this host (an artifact, another platform), `NotFound` if an index
    /// has no manifest for `options.platform`, and `Registry` for what the
    /// registry refused or the network broke.
    pub async fn pull(
        &self,
        content: &ContentStore,
        reference: &ImageRef,
        progress: &(dyn Fn(&Progress) + Send + Sync),
    ) -> Result<Image> {
        progress(&Progress::Resolving { reference: reference.name() });
        self.fetch(content, reference, progress).await
    }

    /// Everything `pull` does after announcing it.
    async fn fetch(
        &self,
        content: &ContentStore,
        reference: &ImageRef,
        progress: &(dyn Fn(&Progress) + Send + Sync),
    ) -> Result<Image> {
        let Resolution { repo_digest, digest, bytes, media_type, manifest, platform } = self.resolve(reference).await?;
        let config = manifest.config();
        let config_digest = Digest::from_oci(config.digest())?;
        progress(&Progress::Resolved {
            reference: reference.name(),
            manifest: digest.clone(),
            repo_digest: repo_digest.clone(),
            platform,
            layers: manifest.layers().len(),
            // The sizes are the registry's word: saturate rather than overflow.
            size: manifest.layers().iter().fold(config.size(), |sum, l| sum.saturating_add(l.size())),
        });
        let fetcher = Fetcher { client: &self.client, content, reference, progress };

        // The config first: it says whether the layers are worth fetching.
        if config.size() > MAX_CONFIG_BYTES {
            return Err(Error::invalid(format!(
                "{reference}: config of {} bytes is larger than {MAX_CONFIG_BYTES}",
                config.size()
            )));
        }
        fetcher.blob(BlobKind::Config, &config_digest, config.size()).await?;
        let image_config =
            ImageConfig::parse(&content.read_blob(&config_digest, MAX_CONFIG_BYTES)?).map_err(about(reference))?;
        if image_config.diff_ids.len() != manifest.layers().len() {
            return Err(Error::invalid(format!(
                "{reference}: the manifest lists {} layers but the config {} diff_ids",
                manifest.layers().len(),
                image_config.diff_ids.len()
            )));
        }
        image_config.check_runnable().map_err(about(reference))?;

        // Then the layers, a few at a time; a layer listed twice is fetched once.
        let mut seen = HashSet::new();
        let mut layers = Vec::new();
        for layer in manifest.layers() {
            let blob = (Digest::from_oci(layer.digest())?, layer.size());
            if seen.insert(blob.clone()) {
                layers.push(blob);
            }
        }
        // A future does nothing until polled, so these are only plans yet.
        // (Made up front rather than in a `map` over the stream: a closure
        // that borrows its argument, inside the stream's type, keeps rustc
        // from seeing that the pull future is `Send`.)
        let downloads: Vec<_> =
            layers.iter().map(|(digest, size)| fetcher.blob(BlobKind::Layer, digest, *size)).collect();
        // They all run in this task, taking turns at their awaits (nothing is
        // spawned, so they can borrow). The first error ends the pull: the
        // stream is dropped with the other downloads still in it, and each
        // unfinished Ingest deletes its partial file as it goes.
        stream::iter(downloads)
            .buffer_unordered(self.options.max_concurrent_downloads.max(1))
            .try_collect::<()>()
            .await?;

        // Everything the manifest names is stored. Now the manifest itself,
        // and last the name, which is what makes the image visible.
        content.write_blob(&bytes)?;
        let name = reference.name();
        let image = Image::from_manifest(content, &digest, Some(name.clone()), Some(repo_digest.clone()))?;
        content.set_ref(&RefEntry {
            name: name.clone(),
            target: manifest_descriptor(&media_type, &digest, bytes.len() as u64),
            repo_digest: Some(repo_digest),
        })?;
        progress(&Progress::Done { reference: name, manifest: digest });
        Ok(image)
    }

    /// Asks the registry what `reference` points at, and narrows an index
    /// down to the manifest for `options.platform`.
    async fn resolve(&self, reference: &ImageRef) -> Result<Resolution> {
        let bytes = self.manifest_bytes(reference).await?;
        let repo_digest = Digest::of(&bytes);
        // oci-client checks this too, but the store's integrity shouldn't
        // hang on a dependency's.
        if let Some(pinned) = reference.digest()
            && pinned != repo_digest
        {
            return Err(Error::DigestMismatch {
                what: format!("{reference}: manifest"),
                expected: pinned.to_string(),
                actual: repo_digest.to_string(),
            });
        }
        let (digest, bytes, manifest, entry) = match manifest::parse(&bytes, None).map_err(about(reference))? {
            Fetched::Manifest(m) => (repo_digest.clone(), bytes, *m, None),
            Fetched::Index(index) => {
                let entry = manifest::select_platform(&index, &self.options.platform).map_err(about(reference))?;
                let digest = Digest::from_oci(entry.digest())?;
                if entry.size() > MAX_MANIFEST_BYTES {
                    return Err(Error::invalid(format!(
                        "{reference}: manifest {digest} of {} bytes is larger than {MAX_MANIFEST_BYTES}",
                        entry.size()
                    )));
                }
                let bytes = self.manifest_bytes(&reference.with_digest(&digest)).await?;
                if bytes.len() as u64 != entry.size() {
                    return Err(Error::DigestMismatch {
                        what: format!("{reference}: size of manifest {digest}"),
                        expected: entry.size().to_string(),
                        actual: bytes.len().to_string(),
                    });
                }
                let actual = Digest::of(&bytes);
                if actual != digest {
                    return Err(Error::DigestMismatch {
                        what: format!("{reference}: {} manifest", self.options.platform),
                        expected: digest.to_string(),
                        actual: actual.to_string(),
                    });
                }
                let manifest =
                    match manifest::parse(&bytes, Some(entry.media_type().as_ref())).map_err(about(reference))? {
                        Fetched::Manifest(m) => *m,
                        Fetched::Index(_) => {
                            return Err(Error::invalid(format!(
                                "{reference}: {digest} is listed as an image manifest but is another index"
                            )));
                        }
                    };
                (digest, bytes, manifest, Some(entry))
            }
        };
        let media_type = manifest_media_type(&manifest, entry.as_ref());
        if !media::is_manifest(&media_type) {
            return Err(Error::unsupported(format!("{reference}: {media_type} is not an image manifest")));
        }
        let platform = match entry.as_ref().and_then(|e| e.platform().as_ref()) {
            Some(p) => Platform {
                os: p.os().to_string(),
                architecture: p.architecture().to_string(),
                variant: p.variant().clone(),
            }
            .to_string(),
            None => self.options.platform.to_string(),
        };
        Ok(Resolution { repo_digest, digest, bytes, media_type, manifest, platform })
    }

    /// The exact bytes the registry serves as `reference`'s manifest.
    /// (oci-client buffers the whole response; `manifest::parse` refuses
    /// anything over `MAX_MANIFEST_BYTES` afterwards.)
    async fn manifest_bytes(&self, reference: &ImageRef) -> Result<Bytes> {
        let (bytes, _digest) = self
            .client
            .pull_manifest_raw(reference.oci(), &RegistryAuth::Anonymous, &media::MANIFEST_TYPES)
            .await
            .map_err(|e| registry_error(reference, "fetch manifest", e))?;
        Ok(bytes)
    }

    /// What `reference` points at now, from a `HEAD` request: just the
    /// `Docker-Content-Digest` header, no body (oci-client falls back to a
    /// `GET` if the header is missing). `None` for a digest that isn't
    /// sha256: nothing in the store can match it.
    async fn head(&self, reference: &ImageRef) -> Result<Option<Digest>> {
        let digest = self
            .client
            .fetch_manifest_digest(reference.oci(), &RegistryAuth::Anonymous)
            .await
            .map_err(|e| registry_error(reference, "check for a newer image", e))?;
        Ok(Digest::parse(&digest).ok())
    }
}

/// What a reference resolved to.
struct Resolution {
    /// The digest of the registry's answer for the reference.
    repo_digest: Digest,
    /// The single-platform manifest: its digest, exact bytes, media type
    /// and parsed form.
    digest: Digest,
    bytes: Bytes,
    media_type: String,
    manifest: ImageManifest,
    /// For [`Progress::Resolved`].
    platform: String,
}

/// What every blob download of one pull shares.
struct Fetcher<'a> {
    client: &'a Client,
    content: &'a ContentStore,
    reference: &'a ImageRef,
    progress: &'a (dyn Fn(&Progress) + Send + Sync),
}

impl Fetcher<'_> {
    /// Makes sure the store has blob `digest` of `size` bytes, downloading
    /// it if it hasn't.
    ///
    /// The writes are plain blocking `write`s from async code. They land in
    /// the page cache and return at memory speed, so they stay inline; only
    /// `commit`'s fsync can take a while, and it holds up just this pull's
    /// other downloads, whose bytes wait in the socket buffers meanwhile.
    /// Inline is also what makes cleanup deterministic: when a pull fails,
    /// every unfinished Ingest is dropped, partial file and all, before
    /// `pull` returns, which a `spawn_blocking` commit would outlive.
    async fn blob(&self, kind: BlobKind, digest: &Digest, size: u64) -> Result<()> {
        let report = |event: Progress| (self.progress)(&event);
        if self.content.has_blob(digest, size)? {
            report(Progress::Exists { kind, digest: digest.clone(), size });
            return Ok(());
        }
        // Asked for by digest alone: given the whole descriptor, oci-client
        // would also try its `urls`, download locations that can point
        // anywhere (Windows base layers use them). Only the registry is
        // asked here.
        let digest_str = digest.to_string();
        let mut body = self
            .client
            .pull_blob_stream(self.reference.oci(), digest_str.as_str())
            .await
            .map_err(|e| registry_error(self.reference, &format!("download blob {digest}"), e))?;
        if let Some(announced) = body.content_length
            && announced != size
        {
            // No point downloading what can't match.
            return Err(size_mismatch(self.reference, digest, size, announced.to_string()));
        }
        let mut ingest = self.content.ingest(digest, Some(size))?;
        let downloading = |current| Progress::Downloading { kind, digest: digest.clone(), current, total: size };
        report(downloading(0));
        let mut reported = 0;
        while let Some(chunk) = body.next().await {
            let chunk = match chunk {
                Ok(chunk) => chunk,
                // oci-client hashes the body too, and reports a mismatch as an
                // error item after the last byte. `commit` below makes the
                // same checks (and the size's) with this module's own hasher.
                Err(e) if is_verification_error(&e) => break,
                Err(e) => {
                    let cause = with_causes(&e);
                    return Err(Error::Registry(format!("{}: download blob {digest}: {cause}", self.reference)));
                }
            };
            let received = ingest.written() + chunk.len() as u64;
            if received > size {
                return Err(size_mismatch(self.reference, digest, size, format!("at least {received}")));
            }
            ingest.write_all(&chunk).with_context(|| format!("write blob {digest}"))?;
            if received - reported >= PROGRESS_STEP {
                report(downloading(received));
                reported = received;
            }
        }
        if ingest.written() != reported {
            report(downloading(ingest.written()));
        }
        // Size and digest checked, fsync'ed, renamed into blobs/.
        ingest.commit().map_err(about(self.reference))?;
        report(Progress::Downloaded { kind, digest: digest.clone(), size });
        Ok(())
    }
}

/// The image `reference` names, contacting the registry as `policy` says.
///
/// `Missing` and `Never` take what the store has under the name without
/// touching the network; only `Missing` pulls when there's nothing.
/// `Always` sends a `HEAD` for the reference: if the store already has
/// what that points at, the name is (re)pointed there and nothing is
/// downloaded (the events report every blob as existing); otherwise it
/// pulls.
pub async fn ensure(
    content: &ContentStore,
    puller: &Puller,
    reference: &ImageRef,
    policy: PullPolicy,
    progress: &(dyn Fn(&Progress) + Send + Sync),
) -> Result<Image> {
    let name = reference.name();
    match policy {
        PullPolicy::Missing | PullPolicy::Never if content.resolve(&name)?.is_some() => Image::load(content, &name),
        PullPolicy::Missing => puller.pull(content, reference, progress).await,
        PullPolicy::Never => Err(Error::NotFound(format!(
            "image {name} is not in the store, and the pull policy is never: pull it first"
        ))),
        PullPolicy::Always => {
            progress(&Progress::Resolving { reference: name });
            if let Some(current) = puller.head(reference).await?
                && let Some(image) = already_stored(content, reference, &current)?
            {
                report_stored(reference, &current, &image, progress);
                return Ok(image);
            }
            puller.fetch(content, reference, progress).await
        }
    }
}

/// The image, if the store already has what the registry says `reference`
/// points at (`current`); the name is pointed there if it wasn't.
fn already_stored(content: &ContentStore, reference: &ImageRef, current: &Digest) -> Result<Option<Image>> {
    let name = reference.name();
    // The name was pulled from exactly this: its manifest, or the index its
    // manifest was chosen from (indexes aren't stored, so this record is
    // the only trace of one).
    if let Some(entry) = content.resolve(&name)?
        && entry.repo_digest.as_ref() == Some(current)
    {
        let target = entry.manifest_digest()?;
        if !content.has_blob(&target, entry.target.size())? {
            return Ok(None);
        }
        let image = Image::from_manifest(content, &target, Some(name), entry.repo_digest)?;
        return Ok(complete(content, &image)?.then_some(image));
    }
    // A manifest the store has from another name, or from this one before
    // the tag moved away and back.
    let Some(size) = content.blob_size(current)? else {
        return Ok(None);
    };
    let Fetched::Manifest(m) = manifest::parse(&content.read_blob(current, MAX_MANIFEST_BYTES)?, None)? else {
        return Ok(None);
    };
    let media_type = manifest_media_type(&m, None);
    if !media::is_manifest(&media_type) {
        return Ok(None);
    }
    let image = Image::from_manifest(content, current, Some(name.clone()), Some(current.clone()))?;
    if !complete(content, &image)? {
        return Ok(None);
    }
    content.set_ref(&RefEntry {
        name,
        target: manifest_descriptor(&media_type, current, size),
        repo_digest: Some(current.clone()),
    })?;
    Ok(Some(image))
}

/// Does the store have every blob `image` needs? A stored manifest
/// normally means yes, since a pull stores it last, but blobs can be
/// deleted by hand.
fn complete(content: &ContentStore, image: &Image) -> Result<bool> {
    if !content.has_blob(&image.config_digest, image.manifest.config().size())? {
        return Ok(false);
    }
    for layer in &image.layers {
        if !content.has_blob(&layer.blob, layer.size)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// The events of a pull that found everything in the store already.
fn report_stored(
    reference: &ImageRef,
    repo_digest: &Digest,
    image: &Image,
    progress: &(dyn Fn(&Progress) + Send + Sync),
) {
    let config_size = image.manifest.config().size();
    progress(&Progress::Resolved {
        reference: reference.name(),
        manifest: image.manifest_digest.clone(),
        repo_digest: repo_digest.clone(),
        platform: image.config.platform(),
        layers: image.layers.len(),
        size: image.layers.iter().fold(config_size, |sum, l| sum.saturating_add(l.size)),
    });
    progress(&Progress::Exists { kind: BlobKind::Config, digest: image.config_digest.clone(), size: config_size });
    let mut seen = HashSet::new();
    for layer in &image.layers {
        if seen.insert((&layer.blob, layer.size)) {
            progress(&Progress::Exists { kind: BlobKind::Layer, digest: layer.blob.clone(), size: layer.size });
        }
    }
    progress(&Progress::Done { reference: reference.name(), manifest: image.manifest_digest.clone() });
}

/// The media type to file manifest `m` under: its own `mediaType`, else
/// what the index entry said, else OCI's (Docker's schema 2 requires the
/// field; OCI only recommends it).
fn manifest_media_type(m: &ImageManifest, entry: Option<&Descriptor>) -> String {
    match (m.media_type(), entry) {
        (Some(own), _) => own.to_string(),
        (None, Some(entry)) => entry.media_type().to_string(),
        (None, None) => media::OCI_MANIFEST.to_owned(),
    }
}

/// Puts `reference` in front of an error's message, so that "not a
/// container image" or "blob …: expected …" says which image.
fn about(reference: &ImageRef) -> impl Fn(Error) -> Error + '_ {
    move |e| match e {
        Error::Invalid(m) => Error::Invalid(format!("{reference}: {m}")),
        Error::Unsupported(m) => Error::Unsupported(format!("{reference}: {m}")),
        Error::NotFound(m) => Error::NotFound(format!("{reference}: {m}")),
        Error::DigestMismatch { what, expected, actual } => {
            Error::DigestMismatch { what: format!("{reference}: {what}"), expected, actual }
        }
        e => e,
    }
}

/// An `oci-client` error as ours, saying which reference and what for. A
/// digest that didn't verify is the content's fault, not the network's,
/// and keeps its own variant.
fn registry_error(reference: &ImageRef, doing: &str, e: OciDistributionError) -> Error {
    match e {
        OciDistributionError::DigestError(DigestError::VerificationError { expected, actual }) => {
            Error::DigestMismatch { what: format!("{reference}: {doing}"), expected, actual }
        }
        // The registry's own words ("manifest unknown", "pull access
        // denied…", the rate limit) are the useful part.
        OciDistributionError::RegistryError { envelope, url } => {
            let reasons: Vec<String> = envelope
                .errors
                .iter()
                .map(|e| if e.message.is_empty() { format!("{:?}", e.code) } else { e.message.clone() })
                .collect();
            Error::Registry(format!("{reference}: {doing}: {} ({url})", reasons.join("; ")))
        }
        e => Error::Registry(format!("{reference}: {doing}: {}", with_causes(&e))),
    }
}

/// A blob that isn't the size its descriptor says (worded as
/// `Ingest::commit` words it).
fn size_mismatch(reference: &ImageRef, digest: &Digest, expected: u64, actual: String) -> Error {
    Error::DigestMismatch {
        what: format!("{reference}: size of blob {digest}"),
        expected: expected.to_string(),
        actual,
    }
}

/// Is this oci-client's "the body didn't hash to the digest" error?
fn is_verification_error(e: &std::io::Error) -> bool {
    matches!(
        e.get_ref().and_then(|inner| inner.downcast_ref::<DigestError>()),
        Some(DigestError::VerificationError { .. })
    )
}

/// `error: cause: cause…`. HTTP errors keep the interesting part ("connection
/// refused") a few sources down.
fn with_causes(e: &dyn std::error::Error) -> String {
    let mut out = e.to_string();
    let mut source = e.source();
    while let Some(cause) = source {
        let text = cause.to_string();
        // Some errors already include their source's text.
        if !out.contains(&text) {
            out.push_str(": ");
            out.push_str(&text);
        }
        source = cause.source();
    }
    out
}

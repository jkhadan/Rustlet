//! An image the store has: its manifest, config and layers, cross-checked.

use oci_spec::image::ImageManifest;

use crate::config::{ImageConfig, MAX_CONFIG_BYTES};
use crate::content::ContentStore;
use crate::digest::{Digest, chain_ids};
use crate::error::{Error, Result};
use crate::manifest::{self, Fetched, MAX_MANIFEST_BYTES};
use crate::media::{self, Compression};
use crate::reference::ImageRef;

/// One layer of an image, with every identity it has.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layer {
    /// Digest of the compressed blob (from the manifest).
    pub blob: Digest,
    /// Size of the compressed blob.
    pub size: u64,
    pub media_type: String,
    pub compression: Compression,
    /// Digest of the uncompressed tar stream (from the config).
    pub diff_id: Digest,
    /// This layer together with everything below it (see `digest`).
    pub chain_id: Digest,
    /// The chain ID of the layer below, if any.
    pub parent: Option<Digest>,
}

/// A complete image in the store.
#[derive(Debug, Clone)]
pub struct Image {
    /// The name it was looked up by, if it was looked up by name.
    pub name: Option<String>,
    /// The digest the registry returned for that name at pull time.
    pub repo_digest: Option<Digest>,
    pub manifest_digest: Digest,
    pub manifest: ImageManifest,
    pub config_digest: Digest,
    pub config: ImageConfig,
    /// Bottom layer first.
    pub layers: Vec<Layer>,
}

impl Image {
    /// Loads an image by name (`alpine`, normalized to
    /// `docker.io/library/alpine:latest`) or by manifest digest
    /// (`sha256:…`). Every blob it needs must be in the store.
    pub fn load(content: &ContentStore, name_or_digest: &str) -> Result<Image> {
        if name_or_digest.starts_with("sha256:") {
            return Image::from_manifest(content, &Digest::parse(name_or_digest)?, None, None);
        }
        let name = ImageRef::parse(name_or_digest)?.name();
        let entry =
            content.resolve(&name)?.ok_or_else(|| Error::NotFound(format!("image {name} is not in the store")))?;
        Image::from_manifest(content, &entry.manifest_digest()?, Some(name), entry.repo_digest)
    }

    /// Loads the image whose manifest has digest `digest`.
    pub fn from_manifest(
        content: &ContentStore,
        digest: &Digest,
        name: Option<String>,
        repo_digest: Option<Digest>,
    ) -> Result<Image> {
        let bytes = content.read_blob(digest, MAX_MANIFEST_BYTES)?;
        let manifest = match manifest::parse(&bytes, None)? {
            Fetched::Manifest(m) => *m,
            Fetched::Index(_) => return Err(Error::invalid(format!("{digest} is an index, not an image manifest"))),
        };
        let config_digest = Digest::from_oci(manifest.config().digest())?;
        let config = ImageConfig::parse(&content.read_blob(&config_digest, MAX_CONFIG_BYTES)?)?;
        if manifest.layers().len() != config.diff_ids.len() {
            return Err(Error::invalid(format!(
                "image {digest}: the manifest lists {} layers but the config {} diff_ids",
                manifest.layers().len(),
                config.diff_ids.len()
            )));
        }
        let chains = chain_ids(&config.diff_ids);
        let layers = manifest
            .layers()
            .iter()
            .zip(&config.diff_ids)
            .zip(&chains)
            .enumerate()
            .map(|(i, ((d, diff_id), chain_id))| {
                let media_type = d.media_type().to_string();
                Ok(Layer {
                    blob: Digest::from_oci(d.digest())?,
                    size: d.size(),
                    compression: media::layer_compression(&media_type)?,
                    media_type,
                    diff_id: diff_id.clone(),
                    chain_id: chain_id.clone(),
                    parent: i.checked_sub(1).map(|p| chains[p].clone()),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Image { name, repo_digest, manifest_digest: digest.clone(), manifest, config_digest, config, layers })
    }

    /// The chain ID of the top layer: what identifies the image's
    /// filesystem, whatever its config says.
    pub fn top_chain_id(&self) -> Option<&Digest> {
        self.layers.last().map(|l| &l.chain_id)
    }

    /// Total size of the compressed layers.
    pub fn compressed_size(&self) -> u64 {
        self.layers.iter().map(|l| l.size).sum()
    }

    /// A short name for messages: the name, else the manifest digest.
    pub fn display_name(&self) -> String {
        self.name.clone().unwrap_or_else(|| self.manifest_digest.to_string())
    }
}

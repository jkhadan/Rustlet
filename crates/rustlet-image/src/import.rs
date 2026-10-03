//! Making an image from local layer archives, the way `docker import` does
//! (and the builder will, Phase 7): no registry involved.
//!
//! It is the pull pipeline backwards, which makes it a compact description
//! of what an image *is*:
//!
//! 1. each layer: the uncompressed tar's sha256 is its **diff ID**; gzip it,
//!    and the compressed bytes' sha256 is the **blob digest**;
//! 2. the **config** lists the diff IDs (`rootfs.diff_ids`) and how to run
//!    the image (`config`), and is stored as a blob;
//! 3. the **manifest** names the config and the layer blobs by digest, and
//!    is stored as a blob;
//! 4. the **name** points at the manifest in `index.json`.
//!
//! Tests use it to build images in a few lines; `cargo xtask image-run
//! --local-alpine` makes one from the Alpine minirootfs for offline use.
//! Its last two steps, [`write_image`], are how the builder, `commit` and
//! `load` store the images they make.

use std::io::Write;

use oci_spec::image::{
    Arch, Config, ConfigBuilder, Descriptor, HistoryBuilder, ImageConfigurationBuilder, ImageManifestBuilder,
    MediaType, Os, RootFsBuilder,
};

use crate::config::ImageConfig;
use crate::content::{ContentStore, RefEntry, descriptor, manifest_descriptor};
use crate::digest::Digest;
use crate::error::{Context, Error, Result};
use crate::image::Image;
use crate::media;
use crate::reference::ImageRef;

/// Stores an image made of `layers` (uncompressed tar archives, bottom
/// first) and `config` (Env, Cmd, User, …) under `name`, and returns it.
pub fn import(content: &ContentStore, name: &str, layers: &[Vec<u8>], config: Config) -> Result<Image> {
    let reference = ImageRef::parse(name)?;
    let mut diff_ids = Vec::with_capacity(layers.len());
    let mut layer_descriptors: Vec<Descriptor> = Vec::with_capacity(layers.len());
    let mut history = Vec::with_capacity(layers.len());
    for (i, tar) in layers.iter().enumerate() {
        diff_ids.push(Digest::of(tar).to_string());
        let gz = gzip(tar).with_context(|| format!("compress layer {i}"))?;
        let blob = content.write_blob(&gz)?;
        layer_descriptors.push(descriptor(media::OCI_LAYER_GZIP, &blob, gz.len() as u64));
        history.push(
            HistoryBuilder::default()
                .created_by(format!("rustlet import: layer {i}"))
                .build()
                .map_err(|e| Error::invalid(format!("history: {e}")))?,
        );
    }
    let image_config = ImageConfigurationBuilder::default()
        .architecture(Arch::Amd64)
        .os(Os::Linux)
        .config(config)
        .rootfs(
            RootFsBuilder::default()
                .typ("layers")
                .diff_ids(diff_ids)
                .build()
                .map_err(|e| Error::invalid(format!("rootfs: {e}")))?,
        )
        .history(history)
        .build()
        .map_err(|e| Error::invalid(format!("image config: {e}")))?;
    let config_json = serde_json::to_vec(&image_config).context("serialize the image config")?;
    let target = write_image(content, &config_json, &layer_descriptors)?;
    content.set_ref(&RefEntry { name: reference.name(), target, repo_digest: None })?;
    Image::load(content, &reference.name())
}

/// Stores an image whose layer blobs are already in the store: `config`
/// (the image config's JSON, exactly as it should be stored) and a manifest
/// naming it and `layers` (bottom first), both as OCI media types. Returns
/// the manifest's descriptor, ready for `index.json`; nothing is named
/// (the caller names, keeps or caches the image). The config must parse as
/// one and list one diff ID per layer, and every layer blob must be in the
/// store with its descriptor's size.
pub fn write_image(content: &ContentStore, config: &[u8], layers: &[Descriptor]) -> Result<Descriptor> {
    let parsed = ImageConfig::parse(config)?;
    if parsed.diff_ids.len() != layers.len() {
        return Err(Error::invalid(format!(
            "the image config lists {} diff IDs for {} layers",
            parsed.diff_ids.len(),
            layers.len()
        )));
    }
    for layer in layers {
        let digest = Digest::from_oci(layer.digest())?;
        media::layer_compression(layer.media_type().as_ref())?;
        if !content.has_blob(&digest, layer.size())? {
            return Err(Error::NotFound(format!("layer {digest} ({} bytes) is not in the store", layer.size())));
        }
    }
    let config_digest = content.write_blob(config)?;
    let manifest = ImageManifestBuilder::default()
        .schema_version(2u32)
        .media_type(MediaType::ImageManifest)
        .config(descriptor(media::OCI_CONFIG, &config_digest, config.len() as u64))
        .layers(layers.to_vec())
        .build()
        .map_err(|e| Error::invalid(format!("manifest: {e}")))?;
    let manifest_json = serde_json::to_vec(&manifest).context("serialize the manifest")?;
    let manifest_digest = content.write_blob(&manifest_json)?;
    Ok(manifest_descriptor(media::OCI_MANIFEST, &manifest_digest, manifest_json.len() as u64))
}

/// A process config for [`import`]: `cmd`, `env` and optionally `user`.
pub fn config(cmd: &[&str], env: &[&str], user: Option<&str>) -> Result<Config> {
    let mut b = ConfigBuilder::default()
        .cmd(cmd.iter().map(|s| s.to_string()).collect::<Vec<_>>())
        .env(env.iter().map(|s| s.to_string()).collect::<Vec<_>>());
    if let Some(u) = user {
        b = b.user(u.to_owned());
    }
    b.build().map_err(|e| Error::invalid(format!("config: {e}")))
}

fn gzip(data: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(data)?;
    e.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imported_images_load_back_with_matching_digests() {
        let dir = tempfile::tempdir().unwrap();
        let content =
            ContentStore::open(dir.path().join("content"), dir.path().join("ingest"), dir.path().join("lock")).unwrap();
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_size(2);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, "hello", &b"hi"[..]).unwrap();
        let tar = b.into_inner().unwrap();
        let image =
            import(&content, "local/test:1", &[tar.clone(), tar.clone()], config(&["sh"], &["A=1"], None).unwrap())
                .unwrap();
        assert_eq!(image.name.as_deref(), Some("docker.io/local/test:1"));
        assert_eq!(image.layers.len(), 2);
        assert_eq!(image.layers[0].diff_id, Digest::of(&tar));
        assert_eq!(image.layers[0].blob, image.layers[1].blob, "identical layers share a blob");
        assert_ne!(image.layers[0].chain_id, image.layers[1].chain_id, "but not a chain ID");
        assert_eq!(image.layers[1].parent.as_ref(), Some(&image.layers[0].chain_id));
        assert_eq!(image.config.config().unwrap().cmd().as_deref(), Some(&["sh".to_string()][..]));
        image.config.check_runnable().unwrap();
    }

    #[test]
    fn write_image_checks_what_it_is_given() {
        let dir = tempfile::tempdir().unwrap();
        let content =
            ContentStore::open(dir.path().join("content"), dir.path().join("ingest"), dir.path().join("lock")).unwrap();
        let tar = vec![0u8; 1024];
        let gz = gzip(&tar).unwrap();
        let blob = content.write_blob(&gz).unwrap();
        let layer = descriptor(media::OCI_LAYER_GZIP, &blob, gz.len() as u64);
        let config = |ids: &[Digest]| {
            serde_json::to_vec(&serde_json::json!({
                "architecture": "amd64", "os": "linux",
                "rootfs": {"type": "layers", "diff_ids": ids.iter().map(|d| d.to_string()).collect::<Vec<_>>()},
            }))
            .unwrap()
        };
        let target = write_image(&content, &config(&[Digest::of(&tar)]), std::slice::from_ref(&layer)).unwrap();
        let image = Image::from_manifest(&content, &Digest::from_oci(target.digest()).unwrap(), None, None).unwrap();
        assert_eq!(image.layers[0].diff_id, Digest::of(&tar));
        assert!(content.refs().unwrap().is_empty(), "nothing is named");
        // One diff ID per layer; layers the store has.
        assert!(write_image(&content, &config(&[]), std::slice::from_ref(&layer)).is_err());
        let missing = descriptor(media::OCI_LAYER_GZIP, &Digest::of(b"x"), 1);
        assert!(matches!(write_image(&content, &config(&[Digest::of(&tar)]), &[missing]), Err(Error::NotFound(_))));
        // No layers at all: an image built FROM scratch with nothing in it.
        assert!(write_image(&content, &config(&[]), &[]).is_ok());
    }
}

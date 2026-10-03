//! Media types: what kind of JSON or blob a descriptor points to.
//!
//! Registries serve two dialects with the same structure: Docker's "image
//! manifest v2, schema 2" (2016) and OCI's image spec (2017, derived from
//! it). Both are accepted; Docker's older schema 1 is not (it was signed
//! JSON with a different layout, and Docker Hub stopped serving it).

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

pub const OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";
pub const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
pub const OCI_CONFIG: &str = "application/vnd.oci.image.config.v1+json";
pub const OCI_LAYER: &str = "application/vnd.oci.image.layer.v1.tar";
pub const OCI_LAYER_GZIP: &str = "application/vnd.oci.image.layer.v1.tar+gzip";
pub const OCI_LAYER_ZSTD: &str = "application/vnd.oci.image.layer.v1.tar+zstd";

pub const DOCKER_MANIFEST_LIST: &str = "application/vnd.docker.distribution.manifest.list.v2+json";
pub const DOCKER_MANIFEST: &str = "application/vnd.docker.distribution.manifest.v2+json";
pub const DOCKER_CONFIG: &str = "application/vnd.docker.container.image.v1+json";
pub const DOCKER_LAYER_GZIP: &str = "application/vnd.docker.image.rootfs.diff.tar.gzip";
pub const DOCKER_LAYER: &str = "application/vnd.docker.image.rootfs.diff.tar";

/// The `Accept` header for manifest requests. Indexes first: a registry
/// may answer a client that accepts no index with a platform's manifest of
/// its own choosing (the reference registry picks linux/amd64), and we want
/// to choose.
pub const MANIFEST_TYPES: [&str; 4] = [OCI_INDEX, DOCKER_MANIFEST_LIST, OCI_MANIFEST, DOCKER_MANIFEST];

/// Is `media_type` a multi-platform index (OCI index, Docker manifest list)?
pub fn is_index(media_type: &str) -> bool {
    matches!(media_type, OCI_INDEX | DOCKER_MANIFEST_LIST)
}

/// Is `media_type` a single-platform image manifest?
pub fn is_manifest(media_type: &str) -> bool {
    matches!(media_type, OCI_MANIFEST | DOCKER_MANIFEST)
}

/// Is `media_type` an image config?
pub fn is_config(media_type: &str) -> bool {
    matches!(media_type, OCI_CONFIG | DOCKER_CONFIG)
}

/// How a layer blob is compressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Compression {
    None,
    Gzip,
    Zstd,
}

/// The compression of a layer with this media type, or why it can't be
/// unpacked: Windows "foreign" layers live on Microsoft's servers, and other
/// artifacts (Helm charts, signatures, WASM modules…) aren't filesystems.
pub fn layer_compression(media_type: &str) -> Result<Compression> {
    match media_type {
        OCI_LAYER | DOCKER_LAYER => Ok(Compression::None),
        OCI_LAYER_GZIP | DOCKER_LAYER_GZIP => Ok(Compression::Gzip),
        OCI_LAYER_ZSTD => Ok(Compression::Zstd),
        m if m.contains("foreign") || m.contains("nondistributable") => Err(Error::unsupported(format!(
            "layer media type {m}: non-distributable (Windows) layers are not supported"
        ))),
        m if m.ends_with("+encrypted") => {
            Err(Error::unsupported(format!("layer media type {m}: encrypted layers are not supported")))
        }
        m => Err(Error::unsupported(format!("layer media type {m:?} is not a filesystem layer"))),
    }
}

/// The compression of data that starts with `magic` (its first bytes, at
/// least four for zstd): gzip (`1f 8b`), zstd (`28 b5 2f fd`), else none.
/// Layers and archives are told apart this way where no media type says
/// (Docker's older `save` format, `ADD`), as `docker load` does.
pub fn detect_compression(magic: &[u8]) -> Compression {
    match magic {
        [0x1f, 0x8b, ..] => Compression::Gzip,
        [0x28, 0xb5, 0x2f, 0xfd, ..] => Compression::Zstd,
        _ => Compression::None,
    }
}

/// The OCI layer media type for `compression`.
pub fn layer_media_type(compression: Compression) -> &'static str {
    match compression {
        Compression::None => OCI_LAYER,
        Compression::Gzip => OCI_LAYER_GZIP,
        Compression::Zstd => OCI_LAYER_ZSTD,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layer_types() {
        assert_eq!(layer_compression(OCI_LAYER_GZIP).unwrap(), Compression::Gzip);
        assert_eq!(layer_compression(DOCKER_LAYER_GZIP).unwrap(), Compression::Gzip);
        assert_eq!(layer_compression(OCI_LAYER_ZSTD).unwrap(), Compression::Zstd);
        assert_eq!(layer_compression(OCI_LAYER).unwrap(), Compression::None);
        for bad in [
            "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip",
            "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip",
            "application/vnd.oci.image.layer.v1.tar+gzip+encrypted",
            "application/vnd.wasm.content.layer.v1+wasm",
        ] {
            assert!(matches!(layer_compression(bad), Err(Error::Unsupported(_))), "{bad}");
        }
        assert!(is_index(OCI_INDEX) && is_index(DOCKER_MANIFEST_LIST) && !is_index(OCI_MANIFEST));
        assert!(is_manifest(DOCKER_MANIFEST) && is_config(DOCKER_CONFIG) && !is_config(OCI_MANIFEST));
    }

    #[test]
    fn compression_from_magic() {
        assert_eq!(detect_compression(&[0x1f, 0x8b, 8, 0]), Compression::Gzip);
        assert_eq!(detect_compression(&[0x28, 0xb5, 0x2f, 0xfd]), Compression::Zstd);
        assert_eq!(detect_compression(b"etc/"), Compression::None);
        assert_eq!(detect_compression(&[0x1f]), Compression::None);
        assert_eq!(layer_compression(layer_media_type(Compression::Zstd)).unwrap(), Compression::Zstd);
    }
}

//! Manifests and indexes: the JSON documents that say what an image is.
//!
//! ```text
//!  tag "alpine:latest" ──► index (one entry per platform)
//!                            ├─ linux/amd64 ──► manifest ──► config (JSON: env, cmd, diff_ids…)
//!                            ├─ linux/arm64 ──► …       ├──► layer 0 (tar+gzip)
//!                            └─ …                         └──► layer 1 …
//! ```
//!
//! An **index** (Docker: "manifest list") lists one manifest per platform;
//! single-platform images skip it and the tag points at a manifest directly.
//! A **manifest** names one config and an ordered list of layers, each by
//! descriptor: media type, digest and size. Everything is addressed by
//! digest, so a client that trusts the digest of what it asked for can
//! verify everything else as it arrives.

use oci_spec::image::{Descriptor, ImageIndex, ImageManifest};

use crate::digest::Digest;
use crate::error::{Error, Result};
use crate::media;

/// Manifests and indexes are small; refuse to buffer anything larger
/// (Docker's own limit is 4 MiB too).
pub const MAX_MANIFEST_BYTES: u64 = 4 << 20;

/// A parsed manifest-shaped document.
#[derive(Debug, Clone)]
pub enum Fetched {
    Index(Box<ImageIndex>),
    Manifest(Box<ImageManifest>),
}

/// Parses manifest or index bytes. The kind comes from the document's own
/// `mediaType`, else from the HTTP `Content-Type` (`content_type`), else
/// from its shape (`manifests` vs `layers`): OCI makes `mediaType` optional.
pub fn parse(bytes: &[u8], content_type: Option<&str>) -> Result<Fetched> {
    if bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(Error::invalid(format!("manifest of {} bytes is larger than {MAX_MANIFEST_BYTES}", bytes.len())));
    }
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Peek {
        schema_version: Option<u32>,
        media_type: Option<String>,
        manifests: Option<serde_json::Value>,
        layers: Option<serde_json::Value>,
    }
    let peek: Peek = serde_json::from_slice(bytes).map_err(|e| Error::invalid(format!("manifest JSON: {e}")))?;
    match peek.schema_version {
        Some(2) => {}
        Some(1) => {
            return Err(Error::unsupported("Docker schema 1 manifests are not supported (deprecated since 2017)"));
        }
        v => return Err(Error::invalid(format!("manifest schemaVersion {v:?}, expected 2"))),
    }
    let kind = peek.media_type.or_else(|| content_type.map(|c| c.split(';').next().unwrap_or(c).trim().to_owned()));
    let is_index = match kind.as_deref() {
        Some(m) if media::is_index(m) => true,
        Some(m) if media::is_manifest(m) => false,
        Some(m) if peek.manifests.is_none() && peek.layers.is_none() => {
            return Err(Error::unsupported(format!("{m} is not an image manifest or index")));
        }
        _ => match (peek.manifests.is_some(), peek.layers.is_some()) {
            (true, false) => true,
            (false, true) => false,
            _ => return Err(Error::invalid("document is neither a manifest nor an index")),
        },
    };
    if is_index {
        serde_json::from_slice(bytes)
            .map(|i| Fetched::Index(Box::new(i)))
            .map_err(|e| Error::invalid(format!("image index: {e}")))
    } else {
        let m: ImageManifest =
            serde_json::from_slice(bytes).map_err(|e| Error::invalid(format!("image manifest: {e}")))?;
        check_manifest(&m)?;
        Ok(Fetched::Manifest(Box::new(m)))
    }
}

/// An OS/architecture pair, as in an index entry's `platform`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Platform {
    pub os: String,
    pub architecture: String,
    pub variant: Option<String>,
}

impl Platform {
    /// What this build can run: `linux/amd64` (rustlet-sys is x86_64-only).
    pub fn host() -> Platform {
        Platform { os: "linux".into(), architecture: "amd64".into(), variant: None }
    }

    fn matches(&self, p: &oci_spec::image::Platform) -> bool {
        p.os().to_string() == self.os
            && p.architecture().to_string() == self.architecture
            && (self.variant.is_none() || p.variant() == &self.variant)
    }
}

impl std::fmt::Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.os, self.architecture)?;
        if let Some(v) = &self.variant {
            write!(f, "/{v}")?;
        }
        Ok(())
    }
}

/// Picks the entry for `want` from an index. Entries that aren't image
/// manifests (attestations, signatures: Docker's are listed with platform
/// `unknown/unknown`) never match. Without a wanted variant, an entry with
/// no variant is preferred over one with (amd64 images sometimes add
/// `v2`/`v3` builds next to the baseline).
pub fn select_platform(index: &ImageIndex, want: &Platform) -> Result<Descriptor> {
    let candidates: Vec<&Descriptor> = index
        .manifests()
        .iter()
        .filter(|d| media::is_manifest(d.media_type().as_ref()))
        .filter(|d| d.platform().as_ref().is_some_and(|p| want.matches(p)))
        .collect();
    let best = candidates
        .iter()
        .find(|d| want.variant.is_some() || d.platform().as_ref().is_some_and(|p| p.variant().is_none()))
        .or(candidates.first());
    if let Some(d) = best {
        return Ok((*d).clone());
    }
    let available: Vec<String> = index
        .manifests()
        .iter()
        .filter_map(|d| d.platform().as_ref())
        .map(|p| match p.variant() {
            Some(v) => format!("{}/{}/{v}", p.os(), p.architecture()),
            None => format!("{}/{}", p.os(), p.architecture()),
        })
        .collect();
    Err(Error::NotFound(format!("no {want} image in this index (it has: {})", available.join(", "))))
}

/// Checks what a manifest points at before anything is fetched: a config of
/// a known type and only unpackable layers, all with sha256 digests.
pub fn check_manifest(m: &ImageManifest) -> Result<()> {
    let config_type = m.config().media_type().to_string();
    if !media::is_config(&config_type) {
        return Err(Error::unsupported(format!(
            "config media type {config_type:?}: not a container image (an OCI artifact?)"
        )));
    }
    Digest::from_oci(m.config().digest())?;
    for layer in m.layers() {
        media::layer_compression(layer.media_type().as_ref())?;
        Digest::from_oci(layer.digest())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST_A: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const DIGEST_B: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const DIGEST_C: &str = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    fn manifest_json(media_type: Option<&str>, config_type: &str, layer_type: &str) -> String {
        let mt = media_type.map(|m| format!(r#""mediaType": "{m}","#)).unwrap_or_default();
        format!(
            r#"{{"schemaVersion": 2, {mt}
                "config": {{"mediaType": "{config_type}", "digest": "{DIGEST_A}", "size": 10}},
                "layers": [{{"mediaType": "{layer_type}", "digest": "{DIGEST_B}", "size": 20}}]}}"#
        )
    }

    fn index_json(entries: &[(&str, &str, &str, Option<&str>)]) -> String {
        let manifests: Vec<String> = entries
            .iter()
            .map(|(digest, os, arch, variant)| {
                let v = variant.map(|v| format!(r#","variant":"{v}""#)).unwrap_or_default();
                format!(
                    r#"{{"mediaType":"{}","digest":"{digest}","size":1,"platform":{{"os":"{os}","architecture":"{arch}"{v}}}}}"#,
                    media::OCI_MANIFEST
                )
            })
            .collect();
        format!(r#"{{"schemaVersion":2,"mediaType":"{}","manifests":[{}]}}"#, media::OCI_INDEX, manifests.join(","))
    }

    #[test]
    fn parses_oci_and_docker_manifests() {
        for (mt, config, layer) in [
            (Some(media::OCI_MANIFEST), media::OCI_CONFIG, media::OCI_LAYER_GZIP),
            (Some(media::DOCKER_MANIFEST), media::DOCKER_CONFIG, media::DOCKER_LAYER_GZIP),
            (None, media::OCI_CONFIG, media::OCI_LAYER_ZSTD),
        ] {
            let json = manifest_json(mt, config, layer);
            let Fetched::Manifest(m) = parse(json.as_bytes(), None).unwrap() else { panic!("not a manifest") };
            assert_eq!(m.layers().len(), 1);
        }
        let idx = index_json(&[(DIGEST_A, "linux", "amd64", None)]);
        assert!(matches!(parse(idx.as_bytes(), None).unwrap(), Fetched::Index(_)));
    }

    #[test]
    fn refuses_what_it_cannot_run() {
        let artifact =
            manifest_json(Some(media::OCI_MANIFEST), "application/vnd.cncf.helm.config.v1+json", media::OCI_LAYER);
        assert!(matches!(parse(artifact.as_bytes(), None), Err(Error::Unsupported(_))));
        let wasm = manifest_json(None, media::OCI_CONFIG, "application/vnd.wasm.content.layer.v1+wasm");
        assert!(matches!(parse(wasm.as_bytes(), None), Err(Error::Unsupported(_))));
        assert!(matches!(parse(br#"{"schemaVersion":1,"fsLayers":[]}"#, None), Err(Error::Unsupported(_))));
        assert!(parse(br#"{"schemaVersion":2}"#, None).is_err());
        assert!(parse(&vec![b' '; (MAX_MANIFEST_BYTES + 1) as usize], None).is_err());
    }

    #[test]
    fn selects_the_host_platform() {
        let idx = index_json(&[
            (DIGEST_A, "linux", "arm64", Some("v8")),
            (DIGEST_B, "linux", "amd64", Some("v3")),
            (DIGEST_C, "linux", "amd64", None),
        ]);
        let Fetched::Index(index) = parse(idx.as_bytes(), None).unwrap() else { panic!() };
        let d = select_platform(&index, &Platform::host()).unwrap();
        assert_eq!(d.digest().to_string(), DIGEST_C, "the baseline amd64 build is preferred");

        let only_arm = index_json(&[(DIGEST_A, "linux", "arm64", Some("v8")), (DIGEST_B, "unknown", "unknown", None)]);
        let Fetched::Index(index) = parse(only_arm.as_bytes(), None).unwrap() else { panic!() };
        let e = select_platform(&index, &Platform::host()).unwrap_err().to_string();
        assert!(e.contains("linux/arm64/v8") && e.contains("no linux/amd64"), "{e}");
    }
}

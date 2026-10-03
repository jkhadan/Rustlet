//! Images: `pull`, `images`, `inspect`, `rmi`.

use serde::{Deserialize, Serialize};
use ts_rs::TS;

/// One line of `rustlet images`: `GET /v1/images`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(default)]
pub struct ImageSummary {
    /// The manifest digest (`sha256:…`): the image's id.
    pub id: String,
    /// Every name pointing at it (`docker.io/library/alpine:latest`).
    pub names: Vec<String>,
    /// What the registry called it (an index digest for a multi-platform
    /// image), if it was pulled.
    pub repo_digest: Option<String>,
    /// From the image config, RFC 3339.
    pub created: Option<String>,
    /// Compressed size of config and layers, bytes.
    pub size: u64,
    pub layers: usize,
    /// `os/arch[/variant]`.
    pub platform: String,
}

/// `GET /v1/images/inspect?name=`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, TS)]
#[serde(default)]
pub struct ImageInspect {
    #[serde(flatten)]
    pub summary: ImageSummary,
    /// The image config, as stored (the OCI `config` object and the rest).
    pub config: serde_json::Value,
    /// Per layer, bottom first.
    pub diff_ids: Vec<String>,
    pub chain_ids: Vec<String>,
    /// The layers, bottom first: the manifest's blobs with what they became.
    pub layer_details: Vec<ImageLayer>,
    /// Every layer has been unpacked into a snapshot.
    pub unpacked: bool,
    /// Containers created from it.
    pub containers: Vec<String>,
}

/// One layer of an image.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(default)]
pub struct ImageLayer {
    /// The compressed blob's digest (the manifest's).
    pub digest: String,
    pub media_type: String,
    /// The compressed blob's size, bytes.
    pub size: u64,
    /// The digest of the uncompressed tar stream (the config's
    /// `rootfs.diff_ids`).
    pub diff_id: String,
    /// The digest of this layer together with every layer below it: the
    /// name of its snapshot.
    pub chain_id: String,
    /// Its snapshot exists.
    pub unpacked: bool,
}

/// Query of `GET /v1/images/inspect`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(default)]
pub struct ImageQuery {
    pub name: String,
}

/// Query of `DELETE /v1/images`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(default)]
pub struct ImageDeleteQuery {
    pub name: String,
    /// Remove the name even if containers use the image (they keep working:
    /// their layers stay until nothing uses them).
    pub force: bool,
}

/// The answer of `DELETE /v1/images`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(default)]
pub struct ImageDeleteResponse {
    /// Names removed.
    pub untagged: Vec<String>,
    /// Blobs and snapshots deleted because nothing uses them any more
    /// (digests and chain IDs).
    pub deleted: Vec<String>,
}

/// Query of `POST /v1/images/pull`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(default)]
pub struct PullQuery {
    pub reference: String,
    pub policy: PullPolicy,
}

/// When to contact the registry.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
pub enum PullPolicy {
    /// Only if the store doesn't have the name yet.
    #[default]
    Missing,
    /// Ask the registry what the name points at now (a `HEAD` first).
    Always,
    /// Never; the image must be in the store.
    Never,
}

/// Which blob a pull event is about.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
pub enum BlobKind {
    Config,
    #[default]
    Layer,
}

/// One line of the NDJSON `pull` response, in order: `resolving`,
/// `resolved`, per blob `exists` or `downloading`… `downloaded`, `done`
/// (the name is stored); then per layer, bottom first, `layer_exists` or
/// `unpacking` + `unpacked`; and last `ready`. A failure at any point ends
/// the stream with `error`. With the `missing` policy and an image already
/// stored, the registry is never contacted: `ready` may follow `resolving`
/// directly. The first part is the same JSON `rustlet_image::pull::Progress`
/// writes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum PullEvent {
    Resolving {
        reference: String,
    },
    Resolved {
        reference: String,
        manifest: String,
        repo_digest: String,
        platform: String,
        layers: usize,
        size: u64,
    },
    Exists {
        kind: BlobKind,
        digest: String,
        size: u64,
    },
    Downloading {
        kind: BlobKind,
        digest: String,
        current: u64,
        total: u64,
    },
    Downloaded {
        kind: BlobKind,
        digest: String,
        size: u64,
    },
    Done {
        reference: String,
        manifest: String,
    },
    /// The layer's snapshot already exists.
    LayerExists {
        chain_id: String,
    },
    /// Unpacking the layer `blob` (compressed `size` bytes) into the
    /// snapshot `chain_id`.
    Unpacking {
        chain_id: String,
        blob: String,
        size: u64,
    },
    /// Unpacked and verified (both digests).
    Unpacked {
        chain_id: String,
        entries: u64,
        bytes: u64,
        whiteouts: u64,
        opaque_dirs: u64,
        skipped_devices: u64,
    },
    /// Every layer is unpacked: the image can run.
    Ready {
        reference: String,
        manifest: String,
    },
    Error {
        message: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pull_events_are_tagged_by_status() {
        let e: PullEvent = serde_json::from_str(
            r#"{"status":"downloading","kind":"layer","digest":"sha256:ab","current":1,"total":2}"#,
        )
        .unwrap();
        assert_eq!(
            e,
            PullEvent::Downloading { kind: BlobKind::Layer, digest: "sha256:ab".into(), current: 1, total: 2 }
        );
        let ready = PullEvent::Ready { reference: "r".into(), manifest: "sha256:cd".into() };
        assert_eq!(
            serde_json::to_string(&ready).unwrap(),
            r#"{"status":"ready","reference":"r","manifest":"sha256:cd"}"#
        );
    }

    #[test]
    fn inspect_keeps_the_layer_count_and_the_layers_apart() {
        let i = ImageInspect {
            summary: ImageSummary { layers: 1, ..Default::default() },
            layer_details: vec![ImageLayer { size: 7, ..Default::default() }],
            ..Default::default()
        };
        let json = serde_json::to_string(&i).unwrap();
        assert_eq!(json.matches("\"layers\"").count(), 1, "{json}");
        assert_eq!(serde_json::from_str::<ImageInspect>(&json).unwrap(), i);
    }

    #[test]
    fn inspect_flattens_the_summary() {
        let i = ImageInspect {
            summary: ImageSummary { id: "sha256:x".into(), ..Default::default() },
            ..Default::default()
        };
        let v = serde_json::to_value(&i).unwrap();
        assert_eq!(v["id"], "sha256:x");
        assert_eq!(serde_json::from_value::<ImageInspect>(v).unwrap(), i);
    }
}

//! `commit`: a container's changes as a new image.
//!
//! ```text
//!  containers/<id>/upper ──diff──► one more layer (gzipped, in the store)
//!  image config + the container's options + --change ──► the new config
//!  the image's layers + the new one ──write_image──► a new image, named or kept
//! ```
//!
//! The changes are the overlay's upper directory as it is now (`rustlet_
//! image::diff`), less what the runtime made as mount points (the last
//! run's `config.json` lists them: `/etc/resolv.conf`, `/proc`, a volume's
//! target…): those were never the container's to change, and what is below
//! a mount point was hidden under it. A container that runs is frozen
//! meanwhile (its `cgroup.freeze`, without its state changing to
//! `paused`), unless asked not to be, so that no file is caught half
//! written; a stopped one needs nothing, its upper directory outlives the
//! run. A `--userns=remap` container's upper directory holds host ids,
//! mapped back to the image's.
//!
//! The new config is the image's, with the container's own options over
//! it, as Docker's: `-e` over `Env`, its command and entrypoint, `-u`,
//! `-w`, labels, the ports it publishes as `ExposedPorts`, its healthcheck
//! options and stop signal; then the `--change` instructions, as a
//! Containerfile's would apply (`rustlet_build::config`). The history gains
//! one entry, with `-m` and `-a`. The image is named, or kept unnamed
//! (`rustlet images` lists it as `<none>`).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustlet_build::config::ImageConfigState;
use rustlet_build::op::{HealthcheckOp, Op};
use rustlet_build::parser::{Command, InstructionKind, parse_instruction};
use rustlet_image::diff::{DiffOptions, commit_layer, unmap_remap};
use rustlet_image::{Digest, Image, ImageRef};
use rustlet_shim::protocol::Request;
use rustlet_spec::build::{CommitRequest, CommitResponse};
use rustlet_spec::container::{ContainerStatus, HealthConfig, UsernsMode};
use rustlet_spec::event::EventKind;
use serde_json::{Value, json};

use crate::daemon::Daemon;
use crate::db::Record;
use crate::error::{ApiError, ApiResult};
use crate::lifecycle::{blocking, shim_ok};

/// The instructions `commit --change` takes (Docker's list, and the two
/// it has gained since).
const CHANGES: &str = "CMD, ENTRYPOINT, ENV, EXPOSE, LABEL, ONBUILD, USER, VOLUME, WORKDIR, STOPSIGNAL, HEALTHCHECK";

impl Daemon {
    pub async fn commit(self: &Arc<Self>, req: CommitRequest) -> ApiResult<CommitResponse> {
        let c = self.find(&req.container)?;
        let name = match req.reference.as_deref().filter(|r| !r.is_empty()) {
            Some(r) => Some(ImageRef::parse(r).map_err(|e| ApiError::invalid(format!("{r:?}: {e}")))?.name()),
            None => None,
        };
        let changes = parse_changes(&req.changes)?;
        // No start, stop or removal meanwhile.
        let _op = c.op.lock().await;
        if matches!(c.status(), ContainerStatus::Removing | ContainerStatus::Dead) {
            return Err(ApiError::conflict(format!("container {} is {}", c.record.name, c.status())));
        }
        // From the layer's blob until the image is named or kept, only this
        // keeps garbage collection away from it.
        let _pin = self.images.pin().await;
        let image = self.images.resolve(&c.record.image_id).map_err(|e| e.context("the container's image"))?;
        let dir = self.paths.container_dir(c.id());
        let skip = mount_points(&dir.join("config.json"));
        let lowers = self.images.lowers(&image).await?;
        let remap = c.record.config.userns == UsernsMode::Remap;
        let socket = self.paths.shim(c.id()).socket();
        let freeze = req.pause && c.status() == ContainerStatus::Running;
        if freeze {
            shim_ok(&socket, Request::Pause).await.map_err(|e| e.context("freeze the container"))?;
        }
        let store = self.images.store().clone();
        let upper = dir.join("upper");
        let layer = blocking(move || {
            let identity = |uid, gid| (uid, gid);
            let map_owner: &dyn Fn(u32, u32) -> (u32, u32) = if remap { &unmap_remap } else { &identity };
            commit_layer(
                store.content(),
                &upper,
                &DiffOptions { skip: &skip, map_owner, lowers: &lowers, userxattr: false },
            )
        })
        .await;
        if freeze && let Err(e) = shim_ok(&socket, Request::Resume).await {
            tracing::warn!(id = %c.id(), "thaw the container after its commit: {e}");
        }
        let layer = layer.map_err(|e| e.context(format!("read the changes of {}", c.record.name)))?;
        let content = self.images.store().content();
        let config = commit_config(content, &image, &c.record, &changes, &req, &layer.diff_id)?;
        let mut layers = image.manifest.layers().clone();
        layers.push(layer.descriptor.clone());
        let target = rustlet_image::import::write_image(content, &config, &layers)?;
        let id = Digest::from_oci(target.digest()).map_err(ApiError::from)?;
        let new = Image::from_manifest(content, &id, None, None)?;
        match &name {
            Some(n) => {
                self.images.name_image(&new, n)?;
                self.events.emit(EventKind::Image, "tag", n, [("id".to_owned(), id.to_string())].into());
            }
            None => self.images.keep_image(&new)?,
        }
        self.emit(&c, "commit", &[("new_image", id.to_string())]);
        Ok(CommitResponse { id: id.to_string(), name, layer: Digest::from_oci(layer.descriptor.digest())?.to_string() })
    }
}

/// The `--change` instructions, parsed (and checked to be of the kinds
/// allowed); expanded later, against the config they change.
fn parse_changes(changes: &[String]) -> ApiResult<Vec<InstructionKind>> {
    changes
        .iter()
        .map(|text| {
            let i =
                parse_instruction(text).map_err(|e| ApiError::invalid(format!("--change {text:?}: {}", e.message)))?;
            match i.kind {
                InstructionKind::Cmd(_)
                | InstructionKind::Entrypoint(_)
                | InstructionKind::Env(_)
                | InstructionKind::Expose(_)
                | InstructionKind::Label(_)
                | InstructionKind::Onbuild(_)
                | InstructionKind::User(_)
                | InstructionKind::Volume(_)
                | InstructionKind::Workdir(_)
                | InstructionKind::StopSignal(_)
                | InstructionKind::Healthcheck(_) => Ok(i.kind),
                _ => Err(ApiError::invalid(format!("--change {text:?}: only {CHANGES} can be changed"))),
            }
        })
        .collect()
}

/// The destinations of the last run's mounts (none if it never ran).
pub(crate) fn mount_points(config_json: &Path) -> Vec<PathBuf> {
    let Ok(bytes) = std::fs::read(config_json) else { return Vec::new() };
    let Ok(spec) = serde_json::from_slice::<Value>(&bytes) else { return Vec::new() };
    spec["mounts"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|m| m["destination"].as_str().map(PathBuf::from))
        .collect()
}

/// The new image's config JSON (see the module docs).
fn commit_config(
    content: &rustlet_image::content::ContentStore,
    image: &Image,
    record: &Record,
    changes: &[InstructionKind],
    req: &CommitRequest,
    diff_id: &Digest,
) -> ApiResult<Vec<u8>> {
    let bytes = content.read_blob(&image.config_digest, rustlet_image::config::MAX_CONFIG_BYTES)?;
    let mut json: Value =
        serde_json::from_slice(&bytes).map_err(|e| ApiError::internal(format!("the image's config: {e}")))?;
    let mut state = ImageConfigState::new(json.get("config"));
    if let Some(Value::Array(env)) = state.config.get_mut("Env") {
        env.retain(|entry| {
            let name = entry.as_str().unwrap_or_default().split('=').next().unwrap_or_default();
            !record.config.unset_env.iter().any(|unset| unset == name)
        });
    }
    for op in container_options(record, image) {
        state.apply(&op).map_err(ApiError::internal)?;
    }
    for kind in changes {
        let op = Op::new(kind, '\\', &|name| state.env_var(name))
            .map_err(|e| ApiError::invalid(format!("--change: {e}")))?;
        state.apply(&op).map_err(|e| ApiError::invalid(format!("--change: {e}")))?;
    }
    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Nanos, true);
    let author = req.author.clone().or_else(|| state.author.clone());
    json["config"] = state.to_value();
    json["created"] = json!(now);
    if let Some(a) = &author {
        json["author"] = json!(a);
    }
    match json["rootfs"]["diff_ids"].as_array_mut() {
        Some(ids) => ids.push(json!(diff_id.to_string())),
        None => return Err(ApiError::internal("the image's config has no rootfs.diff_ids")),
    }
    let mut entry = json!({"created": now, "created_by": "rustlet commit"});
    if let Some(comment) = &req.comment {
        entry["comment"] = json!(comment);
    }
    if let Some(a) = &author {
        entry["author"] = json!(a);
    }
    match json["history"].as_array_mut() {
        Some(history) => history.push(entry),
        None => json["history"] = json!([entry]),
    }
    serde_json::to_vec(&json).map_err(|e| ApiError::internal(format!("the new config: {e}")))
}

/// What the container was created with, as the instructions that would
/// give an image the same: its options over its image's config.
fn container_options(record: &Record, image: &Image) -> Vec<Op> {
    let c = &record.config;
    let mut ops = Vec::new();
    let pairs: Vec<(String, String)> =
        c.env.iter().filter_map(|e| e.split_once('=').map(|(k, v)| (k.to_owned(), v.to_owned()))).collect();
    if !pairs.is_empty() {
        ops.push(Op::Env(pairs));
    }
    // The entrypoint first: setting it drops the image's command, as
    // `--entrypoint` does at run; then the container's own command.
    if let Some(entrypoint) = &c.entrypoint {
        ops.push(Op::Entrypoint(Command::Exec(entrypoint.clone())));
    }
    if c.clear_cmd || !c.cmd.is_empty() {
        ops.push(Op::Cmd(Command::Exec(c.cmd.clone())));
    }
    if let Some(user) = c.user.as_ref().filter(|u| !u.is_empty()) {
        ops.push(Op::User(user.clone()));
    }
    if let Some(dir) = c.workdir.as_ref().filter(|w| !w.is_empty()) {
        // As at run: relative to `/`, not to the image's working directory.
        ops.push(Op::Workdir(if dir.starts_with('/') { dir.clone() } else { format!("/{dir}") }));
    }
    if !c.labels.is_empty() {
        ops.push(Op::Label(c.labels.iter().map(|(k, v)| (k.clone(), v.clone())).collect()));
    }
    let ports: Vec<String> = record.ports.iter().map(|p| format!("{}/{}", p.container_port, p.protocol)).collect();
    if !ports.is_empty() {
        ops.push(Op::Expose(ports));
    }
    if let Some(signal) = &c.stop_signal {
        ops.push(Op::StopSignal(signal.clone()));
    }
    if let Some(h) = &c.healthcheck {
        ops.push(Op::Healthcheck(merged_healthcheck(h, image.config.healthcheck.as_ref())));
    }
    ops
}

/// A container's healthcheck options over its image's, as one `HEALTHCHECK`.
fn merged_healthcheck(own: &HealthConfig, image: Option<&rustlet_image::config::Healthcheck>) -> Option<HealthcheckOp> {
    let test = if own.test.is_empty() { image.map(|i| i.test.clone()).unwrap_or_default() } else { own.test.clone() };
    if test.is_empty() || own.is_none() || test.first().is_some_and(|t| t == "NONE") {
        return None;
    }
    let pick = |own: Option<u64>, image: Option<i64>| {
        own.filter(|&n| n > 0)
            .or_else(|| image.and_then(|n| u64::try_from(n).ok()).filter(|&n| n > 0))
            .map(std::time::Duration::from_nanos)
    };
    Some(HealthcheckOp {
        test,
        interval: pick(own.interval, image.and_then(|i| i.interval)),
        timeout: pick(own.timeout, image.and_then(|i| i.timeout)),
        start_period: pick(own.start_period, image.and_then(|i| i.start_period)),
        start_interval: pick(own.start_interval, image.and_then(|i| i.start_interval)),
        retries: own
            .retries
            .filter(|&n| n > 0)
            .or_else(|| image.and_then(|i| i.retries).and_then(|n| u32::try_from(n).ok()).filter(|&n| n > 0)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mount_points_come_from_the_last_runs_config() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("config.json");
        assert!(mount_points(&p).is_empty(), "never ran");
        std::fs::write(
            &p,
            r#"{"mounts":[{"destination":"/proc","type":"proc"},{"destination":"/etc/resolv.conf","type":"bind"}]}"#,
        )
        .unwrap();
        assert_eq!(mount_points(&p), [PathBuf::from("/proc"), PathBuf::from("/etc/resolv.conf")]);
    }
}

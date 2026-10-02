//! The daemon's side of images: listing and inspecting what the store
//! holds, pulls and unpacks through worker children ([`crate::worker`]),
//! and `rmi` with garbage collection.
//!
//! **What is in use** is the daemon's to know, not the store's: the image
//! names in `index.json`, plus the image (manifest digest) of every
//! container. A container keeps its image's blobs and snapshots even after
//! the name is removed or points elsewhere. (mountinfo can't answer this:
//! for a `--userns` container it names the staged `lower/<n>` paths, long
//! gone.) Garbage collection deletes the blobs and snapshots nothing in
//! use reaches, and never while a pull or unpack runs: a pull stores its
//! blobs before the name that makes them reachable.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};

use rustlet_image::snapshot::Snapshot;
use rustlet_image::{Digest, Image, ImageRef, Store};
use rustlet_runtime::cgroups::{Cgroup, CgroupPath, Setting, SystemdDelegated};
use rustlet_spec::image::{ImageDeleteResponse, ImageInspect, ImageSummary, PullEvent, PullPolicy};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::{RwLock, mpsc};

use crate::error::{ApiError, ApiResult};

pub struct Images {
    store: Store,
    worker: WorkerConfig,
    /// Pulls and unpacks share it; garbage collection takes it alone.
    gc: RwLock<()>,
}

/// How workers are started.
pub struct WorkerConfig {
    /// `rustletd` itself.
    pub exe: PathBuf,
    pub data_root: PathBuf,
    /// `<cgroup parent>/workers`.
    pub cgroup_dir: String,
    pub memory_max: u64,
    pub pids_max: u64,
    pub insecure_registries: Vec<String>,
}

impl Images {
    pub fn new(store: Store, worker: WorkerConfig) -> Images {
        Images { store, worker, gc: RwLock::new(()) }
    }

    /// The image `name` means: a name (normalized as `ImageRef` does), a
    /// manifest digest, or a unique prefix of one (`sha256:` optional, at
    /// least 4 hex digits).
    pub fn resolve(&self, name: &str) -> ApiResult<Image> {
        let content = self.store.content();
        if name.starts_with("sha256:") && name.len() == 71 {
            return Image::load(content, name).map_err(|_| ApiError::no_such_image(name));
        }
        if let Ok(r) = ImageRef::parse(name)
            && let Ok(Some(_)) = content.resolve(&r.name())
        {
            return Ok(Image::load(content, &r.name())?);
        }
        let hex = name.strip_prefix("sha256:").unwrap_or(name);
        if hex.len() >= 4 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
            let mut found = BTreeSet::new();
            for r in content.refs()? {
                let d = r.manifest_digest()?;
                if d.hex().starts_with(hex) {
                    found.insert(d);
                }
            }
            match found.len() {
                1 => return Ok(Image::load(content, &found.pop_first().unwrap().to_string())?),
                0 => {}
                _ => return Err(ApiError::invalid(format!("{name} matches more than one image"))),
            }
        }
        Err(ApiError::no_such_image(name))
    }

    /// Does any name point at the manifest `id`?
    pub fn is_named(&self, id: &str) -> ApiResult<bool> {
        for r in self.store.content().refs()? {
            if r.manifest_digest()?.to_string() == id {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Every named image, one entry per manifest.
    pub fn list(&self) -> ApiResult<Vec<ImageSummary>> {
        let mut by_digest: BTreeMap<Digest, Vec<String>> = BTreeMap::new();
        let mut repo: BTreeMap<Digest, String> = BTreeMap::new();
        for r in self.store.content().refs()? {
            let d = r.manifest_digest()?;
            if let Some(rd) = &r.repo_digest {
                repo.insert(d.clone(), rd.to_string());
            }
            by_digest.entry(d).or_default().push(r.name.clone());
        }
        let mut out = Vec::new();
        for (digest, names) in by_digest {
            match Image::from_manifest(self.store.content(), &digest, None, None) {
                Ok(image) => out.push(summary(&image, names, repo.get(&digest).cloned())),
                Err(e) => tracing::warn!("image {digest} ({}): {e}", names.join(", ")),
            }
        }
        out.sort_by(|a, b| b.created.cmp(&a.created).then_with(|| a.names.cmp(&b.names)));
        Ok(out)
    }

    pub fn inspect(&self, name: &str, containers: Vec<String>) -> ApiResult<ImageInspect> {
        let image = self.resolve(name)?;
        let names: Vec<String> = self
            .store
            .content()
            .refs()?
            .into_iter()
            .filter(|r| r.manifest_digest().is_ok_and(|d| d == image.manifest_digest))
            .map(|r| r.name)
            .collect();
        let config_json =
            self.store.content().read_blob(&image.config_digest, rustlet_image::config::MAX_CONFIG_BYTES)?;
        let unpacked = image.layers.iter().all(|l| matches!(self.store.snapshots().get(&l.chain_id), Ok(Some(_))));
        Ok(ImageInspect {
            summary: summary(&image, names, image.repo_digest.as_ref().map(Digest::to_string)),
            config: serde_json::from_slice(&config_json).unwrap_or(serde_json::Value::Null),
            diff_ids: image.layers.iter().map(|l| l.diff_id.to_string()).collect(),
            chain_ids: image.layers.iter().map(|l| l.chain_id.to_string()).collect(),
            unpacked,
            containers,
        })
    }

    /// Pulls `reference` (as `policy` says) and unpacks it, in a worker.
    /// Progress goes to `events`; the result says which image it was.
    pub async fn pull(&self, reference: &str, policy: PullPolicy, events: mpsc::Sender<PullEvent>) -> ApiResult<Image> {
        let r = ImageRef::parse(reference).map_err(|e| ApiError::invalid(e.to_string()))?;
        let policy = match policy {
            PullPolicy::Missing => "missing",
            PullPolicy::Always => "always",
            PullPolicy::Never => "never",
        };
        let mut args = vec![
            "pull".into(),
            "--data-root".into(),
            self.worker.data_root.display().to_string(),
            "--reference".into(),
            r.name(),
            "--policy".into(),
            policy.into(),
        ];
        for reg in &self.worker.insecure_registries {
            args.extend(["--insecure-registry".into(), reg.clone()]);
        }
        let manifest = self.run_worker(args, events).await?;
        Ok(Image::load(self.store.content(), &manifest)?)
    }

    /// The image's snapshots, unpacking (in a worker) whatever is missing.
    pub async fn ensure_unpacked(&self, image: &Image) -> ApiResult<Vec<Snapshot>> {
        if let Some(all) = self.snapshots(image)? {
            return Ok(all);
        }
        let (tx, mut rx) = mpsc::channel(64);
        let log = tokio::spawn(async move {
            while let Some(e) = rx.recv().await {
                tracing::info!(?e, "unpack");
            }
        });
        let args = vec![
            "unpack".into(),
            "--data-root".into(),
            self.worker.data_root.display().to_string(),
            "--image".into(),
            image.manifest_digest.to_string(),
        ];
        let result = self.run_worker(args, tx).await;
        let _ = log.await;
        result?;
        self.snapshots(image)?.ok_or_else(|| ApiError::internal("the unpack finished but layers are missing"))
    }

    /// All of the image's snapshots, if they all exist.
    fn snapshots(&self, image: &Image) -> ApiResult<Option<Vec<Snapshot>>> {
        let mut out = Vec::with_capacity(image.layers.len());
        for l in &image.layers {
            match self.store.snapshots().get(&l.chain_id) {
                Ok(Some(s)) => out.push(s),
                Ok(None) | Err(_) => return Ok(None),
            }
        }
        Ok(Some(out))
    }

    /// Runs `rustletd worker <args>` in a cgroup of its own and forwards its
    /// events. Returns the manifest digest of its `ready` event.
    async fn run_worker(&self, args: Vec<String>, events: mpsc::Sender<PullEvent>) -> ApiResult<String> {
        static N: AtomicU64 = AtomicU64::new(0);
        let _turn = self.gc.read().await;
        let cg = CgroupPath::parse(&format!(
            "{}/{}-{}",
            self.worker.cgroup_dir,
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ))?;
        let settings = vec![
            Setting::new("memory.max", self.worker.memory_max.to_string()),
            Setting::new("memory.swap.max", "0"),
            Setting::new("pids.max", self.worker.pids_max.to_string()),
        ];
        let cgroup = {
            let cg = cg.clone();
            tokio::task::spawn_blocking(move || Cgroup::create(&cg, &settings, &SystemdDelegated))
                .await
                .map_err(|e| ApiError::internal(e.to_string()))??
        };
        let mut cmd = tokio::process::Command::new(&self.worker.exe);
        cmd.arg("worker").args(&args).args(["--cgroup", &cg.as_path().display().to_string()]);
        cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::inherit());
        let result = async {
            let mut child = cmd.spawn().map_err(|e| ApiError::internal(format!("start a worker: {e}")))?;
            let stdout = child.stdout.take().expect("piped");
            let mut lines = BufReader::new(stdout).lines();
            let mut ready = None;
            let mut failed = None;
            while let Some(line) = lines.next_line().await? {
                let Ok(event) = serde_json::from_str::<PullEvent>(&line) else {
                    tracing::warn!("worker: {line}");
                    continue;
                };
                match &event {
                    PullEvent::Ready { manifest, .. } => ready = Some(manifest.clone()),
                    PullEvent::Error { message } => failed = Some(message.clone()),
                    _ => {}
                }
                // A client that went away doesn't stop the work.
                let _ = events.send(event).await;
            }
            let status = child.wait().await?;
            match (ready, failed) {
                (Some(m), None) if status.success() => Ok(m),
                (_, Some(message)) => Err(worker_error(message)),
                _ => {
                    let oom = cgroup.memory_events().is_ok_and(|e| e.oom_kill > 0);
                    let message = if oom {
                        format!(
                            "the worker ran out of memory (limit {} bytes): the image is too large or hostile",
                            self.worker.memory_max
                        )
                    } else {
                        format!("the worker failed ({status})")
                    };
                    let _ = events.send(PullEvent::Error { message: message.clone() }).await;
                    Err(ApiError::internal(message))
                }
            }
        }
        .await;
        let _ = tokio::task::spawn_blocking(move || {
            if let Err(e) = cgroup.remove_tree(std::time::Duration::from_secs(10)) {
                tracing::warn!("remove a worker cgroup: {e}");
            }
        })
        .await;
        result
    }

    /// `rmi`: removes the name (or, for an id, every name of the image),
    /// then deletes what nothing uses any more. `in_use`: image ids (manifest
    /// digests) of containers, and the containers' names per image id.
    pub async fn remove(
        &self,
        name: &str,
        force: bool,
        containers: &BTreeMap<String, Vec<String>>,
    ) -> ApiResult<ImageDeleteResponse> {
        let image = self.resolve(name)?;
        let id = image.manifest_digest.to_string();
        let content = self.store.content();
        let names: Vec<String> = content
            .refs()?
            .into_iter()
            .filter(|r| r.manifest_digest().is_ok_and(|d| d == image.manifest_digest))
            .map(|r| r.name)
            .collect();
        let by_name = ImageRef::parse(name).ok().map(|r| r.name()).filter(|n| names.contains(n));
        let untag: Vec<String> = match by_name {
            Some(n) => vec![n],
            None if names.len() > 1 && !force => {
                return Err(ApiError::conflict(format!(
                    "image {} has several names ({}); remove them one by one, or use --force",
                    image.manifest_digest.short(),
                    names.join(", ")
                )));
            }
            None => names.clone(),
        };
        let last_name = untag.len() == names.len();
        if last_name
            && !force
            && let Some(users) = containers.get(&id)
        {
            return Err(ApiError::conflict(format!(
                "image {name} is used by container{} {}: remove {}, or use --force (the containers keep working)",
                if users.len() == 1 { "" } else { "s" },
                users.join(", "),
                if users.len() == 1 { "it" } else { "them" }
            )));
        }
        let mut response = ImageDeleteResponse::default();
        for n in untag {
            if content.remove_ref(&n)? {
                response.untagged.push(n);
            }
        }
        let in_use: BTreeSet<String> = containers.keys().cloned().collect();
        response.deleted = self.collect_garbage(&in_use).await?;
        Ok(response)
    }

    /// Deletes blobs and snapshots that no name and no container reaches.
    pub async fn collect_garbage(&self, container_images: &BTreeSet<String>) -> ApiResult<Vec<String>> {
        let _alone = self.gc.write().await;
        let content = self.store.content();
        let mut manifests: BTreeSet<Digest> = BTreeSet::new();
        for r in content.refs()? {
            manifests.insert(r.manifest_digest()?);
        }
        for id in container_images {
            if let Ok(d) = Digest::parse(id) {
                manifests.insert(d);
            }
        }
        let mut blobs = BTreeSet::new();
        let mut chains = BTreeSet::new();
        for m in &manifests {
            // A manifest that can't be loaded keeps only itself: deleting
            // what it may name would be a guess.
            blobs.insert(m.clone());
            if let Ok(image) = Image::from_manifest(content, m, None, None) {
                blobs.insert(image.config_digest.clone());
                for l in &image.layers {
                    blobs.insert(l.blob.clone());
                    chains.insert(l.chain_id.clone());
                }
            }
        }
        let mut deleted = Vec::new();
        let blob_dir = content.dir().join("blobs/sha256");
        for entry in
            std::fs::read_dir(&blob_dir).map_err(|e| ApiError::internal(format!("list {}: {e}", blob_dir.display())))?
        {
            let entry = entry?;
            let Some(hex) = entry.file_name().to_str().map(str::to_owned) else { continue };
            let Ok(d) = Digest::from_hex(&hex) else { continue };
            if !blobs.contains(&d) {
                std::fs::remove_file(entry.path())?;
                deleted.push(d.to_string());
            }
        }
        for s in self.store.snapshots().list()? {
            if chains.contains(&s.info.chain_id) {
                continue;
            }
            let dir = s.dir.clone();
            tokio::task::spawn_blocking(move || rustlet_sys::tree::safe_remove_tree(&dir))
                .await
                .map_err(|e| ApiError::internal(e.to_string()))?
                .map_err(|e| ApiError::internal(format!("remove snapshot {}: {e}", s.dir.display())))?;
            let _ = std::fs::remove_file(self.store.snapshots().dir().join(".locks").join(s.info.chain_id.hex()));
            deleted.push(format!("snapshot {}", s.info.chain_id));
        }
        Ok(deleted)
    }
}

fn worker_error(message: String) -> ApiError {
    if message.contains("not in the store") || message.contains("not found") || message.contains("manifest unknown") {
        ApiError::new(rustlet_spec::ErrorKind::NoSuchImage, message)
    } else {
        ApiError::internal(message)
    }
}

fn summary(image: &Image, names: Vec<String>, repo_digest: Option<String>) -> ImageSummary {
    ImageSummary {
        id: image.manifest_digest.to_string(),
        names,
        repo_digest,
        created: image.config.oci.created().clone(),
        size: image.compressed_size() + image.manifest.config().size(),
        layers: image.layers.len(),
        platform: image.config.platform(),
    }
}

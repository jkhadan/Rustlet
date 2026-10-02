//! The daemon's side of images: listing and inspecting what the store
//! holds, pulls and unpacks through worker children ([`crate::worker`]),
//! and `rmi` with garbage collection.
//!
//! **What is in use** is the daemon's to know, not the store's: whatever
//! `index.json` lists (named or not), plus the image (manifest digest) of
//! every container. A container keeps its image's blobs and snapshots even
//! after the name is removed or points elsewhere. (mountinfo can't answer
//! this: for a `--userns` container it names the staged `lower/<n>` paths,
//! long gone.) Garbage collection deletes the blobs and snapshots nothing
//! in use reaches, and never while a pull, an unpack or a create runs: a
//! pull stores its blobs before the name that makes them reachable, and a
//! create has looked up its image before its container is recorded. What
//! it can't read is kept, with whatever it may refer to.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use rustlet_image::content::ContentStore;
use rustlet_image::snapshot::Snapshot;
use rustlet_image::{Digest, Image, ImageRef, Store};
use rustlet_runtime::cgroups::{Cgroup, CgroupPath, Setting, SystemdDelegated};
use rustlet_spec::image::{ImageDeleteResponse, ImageInspect, ImageSummary, PullEvent, PullPolicy};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::{RwLock, RwLockReadGuard, mpsc};

use crate::error::{ApiError, ApiResult};

pub struct Images {
    store: Store,
    worker: WorkerConfig,
    /// Pulls, unpacks and creates share it; garbage collection takes it
    /// alone, and never waits for it in line (see `collect_garbage`).
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

    /// Keeps garbage collection away while held: a create holds it from
    /// looking up its image until its container is recorded.
    pub async fn pin(&self) -> RwLockReadGuard<'_, ()> {
        self.gc.read().await
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
        let made = async {
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
            Ok::<_, ApiError>((cg, cgroup))
        };
        let (cg, cgroup) = match made.await {
            Ok(made) => made,
            Err(e) => {
                drop(_turn);
                let _ = events.send(PullEvent::Error { message: format!("a cgroup for the worker: {e}") }).await;
                return Err(e);
            }
        };
        let mut cmd = tokio::process::Command::new(&self.worker.exe);
        cmd.arg("worker").args(&args).args(["--cgroup", &cg.as_path().display().to_string()]);
        cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::inherit());
        // A worker whose daemon gave up on it (shutting down) goes too:
        // nothing would remove its cgroup, and the next daemon's garbage
        // collection wouldn't know it still writes to the store.
        cmd.kill_on_drop(true);
        // The final event (`ready` or `error`) is sent once the worker is
        // done and the store free again: a client that stops reading holds
        // up neither. Progress it doesn't keep up with is dropped.
        let mut last = None;
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
                    _ => {
                        // A client that went away doesn't stop the work.
                        let _ = events.try_send(event);
                        continue;
                    }
                }
                last = Some(event);
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
                    last = Some(PullEvent::Error { message: message.clone() });
                    Err(ApiError::internal(message))
                }
            }
        }
        .await;
        let _ = tokio::task::spawn_blocking(move || {
            if let Err(e) = cgroup.remove_tree(Duration::from_secs(10)) {
                tracing::warn!("remove a worker cgroup: {e}");
            }
        })
        .await;
        drop(_turn);
        // Every failure ends the stream with an error (the worker may not
        // have got as far as saying one).
        if let (Err(e), None) = (&result, &last) {
            last = Some(PullEvent::Error { message: e.message.clone() });
        }
        if let Some(event) = last {
            let _ = events.send(event).await;
        }
        result
    }

    /// `rmi`: removes the name (or, for an id, every name of the image),
    /// then deletes what nothing uses any more. `containers`: the names of
    /// the containers per image id (manifest digest), asked again for the
    /// collection.
    pub async fn remove(
        &self,
        name: &str,
        force: bool,
        containers: impl Fn() -> BTreeMap<String, Vec<String>>,
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
            && let Some(users) = containers().get(&id)
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
        response.deleted = self.collect_garbage(|| containers().into_keys().collect()).await?;
        Ok(response)
    }

    /// Deletes blobs and snapshots that nothing in `index.json` and no
    /// container reaches, and what killed workers left behind. `in_use`: the
    /// containers' image ids, asked once nothing else can change them.
    pub async fn collect_garbage(&self, in_use: impl FnOnce() -> BTreeSet<String>) -> ApiResult<Vec<String>> {
        // Once no pull, unpack or create runs. Polling rather than waiting
        // in line: tokio's lock is fair, and a collection queued behind a
        // long pull would make every later pull, unpack and create queue
        // behind it.
        let _alone = loop {
            match self.gc.try_write() {
                Ok(guard) => break guard,
                Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
            }
        };
        let content = self.store.content();
        let mut roots = content.index_digests()?;
        roots.extend(in_use().iter().filter_map(|id| Digest::parse(id).ok()));
        let mut keep = Reachable::default();
        for root in &roots {
            keep.add(content, root, 0);
        }
        let mut deleted = Vec::new();
        if keep.every_blob {
            tracing::warn!("garbage collection keeps every blob: a manifest it must keep can't be read");
        } else {
            let blob_dir = content.dir().join("blobs/sha256");
            let entries = std::fs::read_dir(&blob_dir)
                .map_err(|e| ApiError::internal(format!("list {}: {e}", blob_dir.display())))?;
            for entry in entries {
                let entry = entry?;
                let Some(hex) = entry.file_name().to_str().map(str::to_owned) else { continue };
                let Ok(d) = Digest::from_hex(&hex) else { continue };
                if !keep.blobs.contains(&d) {
                    std::fs::remove_file(entry.path())?;
                    deleted.push(d.to_string());
                }
            }
        }
        let snapshots = self.store.snapshots();
        if keep.every_snapshot {
            tracing::warn!("garbage collection keeps every snapshot: an image it must keep can't be read");
        } else {
            let entries = std::fs::read_dir(snapshots.dir())
                .map_err(|e| ApiError::internal(format!("list {}: {e}", snapshots.dir().display())))?;
            for entry in entries {
                let entry = entry?;
                // By name: a snapshot whose snapshot.json is damaged is
                // garbage all the same, unless something reaches it (and
                // the next unpack replaces it then).
                let Some(chain_id) = entry.file_name().to_str().and_then(|n| Digest::from_hex(n).ok()) else {
                    continue;
                };
                if keep.chains.contains(&chain_id) {
                    continue;
                }
                let dir = entry.path();
                let shown = dir.display().to_string();
                tokio::task::spawn_blocking(move || rustlet_sys::tree::safe_remove_tree(&dir))
                    .await
                    .map_err(|e| ApiError::internal(e.to_string()))?
                    .map_err(|e| ApiError::internal(format!("remove snapshot {shown}: {e}")))?;
                let _ = std::fs::remove_file(snapshots.dir().join(".locks").join(chain_id.hex()));
                deleted.push(format!("snapshot {chain_id}"));
            }
        }
        // No worker runs: whatever is half-written was left by a killed one.
        for left in content.remove_partials()?.into_iter().chain(snapshots.remove_leftovers()?) {
            tracing::info!("removed {}, left by an unpack or pull that was killed", left.display());
        }
        Ok(deleted)
    }
}

/// What garbage collection keeps.
#[derive(Debug, Default)]
struct Reachable {
    blobs: BTreeSet<Digest>,
    chains: BTreeSet<Digest>,
    /// Something to keep couldn't be read: no blob is deleted.
    every_blob: bool,
    /// An image to keep has layers that can't be told: no snapshot is
    /// deleted.
    every_snapshot: bool,
}

impl Reachable {
    /// `digest` and everything it refers to. An image (as `Image` loads it)
    /// keeps its config, layers and snapshots; anything else (an index, an
    /// artifact, an image whose config can't be read now) keeps whatever
    /// its JSON names, and every snapshot unless its config says which.
    fn add(&mut self, content: &ContentStore, digest: &Digest, depth: u32) {
        if !self.blobs.insert(digest.clone()) {
            return;
        }
        if let Ok(image) = Image::from_manifest(content, digest, None, None) {
            self.blobs.insert(image.config_digest.clone());
            for l in &image.layers {
                self.blobs.insert(l.blob.clone());
                self.chains.insert(l.chain_id.clone());
            }
            return;
        }
        let Some(json) = read_json(content, digest, rustlet_image::manifest::MAX_MANIFEST_BYTES) else {
            self.every_blob = true;
            self.every_snapshot = true;
            return;
        };
        let digests = |key: &str| -> Vec<Digest> {
            json[key]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|d| Digest::parse(d["digest"].as_str()?).ok())
                .collect()
        };
        self.blobs.extend(digests("layers"));
        if let Some(config) = json["config"]["digest"].as_str().and_then(|d| Digest::parse(d).ok()) {
            self.blobs.insert(config.clone());
            match read_json(content, &config, rustlet_image::config::MAX_CONFIG_BYTES) {
                // An artifact's config has no diff IDs, and no snapshots
                // either.
                Some(c) => match c["rootfs"]["diff_ids"].as_array() {
                    None => {}
                    Some(ids) => {
                        match ids.iter().map(|d| Digest::parse(d.as_str()?).ok()).collect::<Option<Vec<_>>>() {
                            Some(ids) => self.chains.extend(rustlet_image::digest::chain_ids(&ids)),
                            None => self.every_snapshot = true,
                        }
                    }
                },
                None => self.every_snapshot = true,
            }
        }
        // An index: its manifests (not nested deeper than any real one).
        if depth < 4 {
            for m in digests("manifests") {
                self.add(content, &m, depth + 1);
            }
        }
    }
}

fn read_json(content: &ContentStore, digest: &Digest, max: u64) -> Option<serde_json::Value> {
    serde_json::from_slice(&content.read_blob(digest, max).ok()?).ok()
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

#[cfg(test)]
mod tests {
    use super::*;
    use rustlet_image::content::{REF_NAME, RefEntry, manifest_descriptor};
    use rustlet_image::import::{config, import};

    fn images(dir: &std::path::Path) -> Images {
        let root = dir.join("store");
        let worker = WorkerConfig {
            exe: "/nonexistent".into(),
            data_root: root.clone(),
            cgroup_dir: "/nonexistent".into(),
            memory_max: 0,
            pids_max: 0,
            insecure_registries: Vec::new(),
        };
        Images::new(Store::open(&root).unwrap(), worker)
    }

    fn block_on<F: Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(f)
    }

    fn gc(im: &Images, in_use: &[&Digest]) -> Vec<String> {
        let mut deleted = block_on(im.collect_garbage(|| in_use.iter().map(|d| d.to_string()).collect())).unwrap();
        deleted.sort();
        deleted
    }

    /// An imported image with one empty layer (unpacks without root).
    fn image(im: &Images, name: &str, cmd: &[&str]) -> Image {
        let c = im.store.content();
        let i = import(c, name, &[vec![0u8; 1024]], config(cmd, &[], None).unwrap()).unwrap();
        im.store.snapshots().ensure(c, &i, &mut |_| {}).unwrap();
        i
    }

    #[test]
    fn only_what_nothing_reaches_is_deleted() {
        let dir = tempfile::tempdir().unwrap();
        let im = images(dir.path());
        let c = im.store.content();
        // Two images sharing their one layer.
        let a = image(&im, "local/a:1", &["true"]);
        let b = image(&im, "local/b:1", &["false"]);
        let lone = c.write_blob(b"left by a failed pull").unwrap();
        assert!(c.remove_ref("docker.io/local/a:1").unwrap());
        let mut expected = vec![a.manifest_digest.to_string(), a.config_digest.to_string(), lone.to_string()];
        expected.sort();
        assert_eq!(gc(&im, &[]), expected);
        assert!(c.blob_size(&b.layers[0].blob).unwrap().is_some(), "b's layer is a's too");
        // A container's image stays without a name.
        assert!(c.remove_ref("docker.io/local/b:1").unwrap());
        assert!(gc(&im, &[&b.manifest_digest]).is_empty());
        let gone = gc(&im, &[]);
        assert!(gone.contains(&format!("snapshot {}", b.layers[0].chain_id)), "{gone:?}");
        assert!(c.blob_size(&b.layers[0].blob).unwrap().is_none());
    }

    #[test]
    fn a_used_image_whose_config_cant_be_read_keeps_everything() {
        let dir = tempfile::tempdir().unwrap();
        let im = images(dir.path());
        let img = image(&im, "local/a:1", &["true"]);
        let c = im.store.content();
        assert!(c.remove_ref("docker.io/local/a:1").unwrap());
        // Not an image config any more: its layers can't be told.
        std::fs::write(c.blob_path(&img.config_digest), b"{}").unwrap();
        assert_eq!(gc(&im, &[&img.manifest_digest]), Vec::<String>::new(), "deleted what a container uses");
        assert!(im.store.snapshots().get(&img.layers[0].chain_id).unwrap().is_some());
    }

    #[test]
    fn what_a_named_artifact_refers_to_is_kept() {
        let dir = tempfile::tempdir().unwrap();
        let im = images(dir.path());
        let c = im.store.content();
        let cfg = c.write_blob(b"{}").unwrap();
        let data = c.write_blob(b"chart").unwrap();
        let m = serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 2, "mediaType": rustlet_image::media::OCI_MANIFEST,
            "config": {"mediaType": "application/vnd.oci.empty.v1+json", "digest": cfg.to_string(), "size": 2},
            "layers": [{"mediaType": "application/vnd.example.chart.v1", "digest": data.to_string(), "size": 5}],
        }))
        .unwrap();
        let d = c.write_blob(&m).unwrap();
        let target = manifest_descriptor(rustlet_image::media::OCI_MANIFEST, &d, m.len() as u64);
        c.set_ref(&RefEntry { name: "docker.io/local/chart:1".into(), target, repo_digest: None }).unwrap();
        assert_eq!(gc(&im, &[]), Vec::<String>::new());
    }

    #[test]
    fn unnamed_index_entries_are_kept() {
        let dir = tempfile::tempdir().unwrap();
        let im = images(dir.path());
        image(&im, "local/a:1", &["true"]);
        // Another tool's entry: no name.
        let p = im.store.content().dir().join("index.json");
        let mut index: serde_json::Value = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
        index["manifests"][0]["annotations"].as_object_mut().unwrap().remove(REF_NAME);
        std::fs::write(&p, serde_json::to_vec(&index).unwrap()).unwrap();
        assert_eq!(gc(&im, &[]), Vec::<String>::new());
    }

    #[test]
    fn damaged_snapshots_and_killed_workers_leftovers_go() {
        let dir = tempfile::tempdir().unwrap();
        let im = images(dir.path());
        let snapshots = im.store.snapshots().dir().to_owned();
        let damaged = snapshots.join(Digest::of(b"x").hex());
        std::fs::create_dir_all(damaged.join("fs")).unwrap();
        std::fs::write(damaged.join("snapshot.json"), b"{\"chain_id\": \"sha").unwrap();
        std::fs::create_dir_all(snapshots.join(".tmp-abc-1-0/fs")).unwrap();
        std::fs::create_dir_all(snapshots.join(".broken-abc-1-0/fs")).unwrap();
        let ingest = dir.path().join("store/ingest");
        std::fs::write(ingest.join("abc-1-0.partial"), b"half a blob").unwrap();
        assert_eq!(gc(&im, &[]), [format!("snapshot {}", Digest::of(b"x"))]);
        let left: Vec<_> = std::fs::read_dir(&snapshots)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n != ".locks")
            .collect();
        assert!(left.is_empty(), "{left:?}");
        assert_eq!(std::fs::read_dir(&ingest).unwrap().count(), 0);
    }

    #[test]
    fn a_pull_that_fails_before_its_worker_runs_ends_with_an_error() {
        let dir = tempfile::tempdir().unwrap();
        // No such cgroup to put the worker in.
        let im = images(dir.path());
        let (tx, mut rx) = mpsc::channel(8);
        assert!(block_on(im.pull("alpine", PullPolicy::Never, tx)).is_err());
        assert!(matches!(rx.try_recv(), Ok(PullEvent::Error { .. })));
    }

    #[test]
    fn collection_waits_for_pins_without_holding_them_up() {
        let dir = tempfile::tempdir().unwrap();
        let im = images(dir.path());
        let a = image(&im, "local/a:1", &["true"]);
        assert!(im.store.content().remove_ref("docker.io/local/a:1").unwrap());
        block_on(async {
            let pin = im.pin().await;
            let asked = std::sync::atomic::AtomicBool::new(false);
            let collect = im.collect_garbage(|| {
                asked.store(true, Ordering::SeqCst);
                // The container recorded meanwhile.
                [a.manifest_digest.to_string()].into()
            });
            tokio::pin!(collect);
            // Pinned: it waits...
            assert!(tokio::time::timeout(Duration::from_millis(300), &mut collect).await.is_err());
            assert!(!asked.load(Ordering::SeqCst), "what is in use is asked only once it may collect");
            // ...without making another pin wait behind it.
            let second = tokio::time::timeout(Duration::from_millis(300), im.pin()).await;
            assert!(second.is_ok(), "a waiting collection held up a pin");
            drop(second);
            drop(pin);
            assert_eq!(collect.await.unwrap(), Vec::<String>::new());
        });
    }
}

//! Building images: a Containerfile's steps, run by the daemon.
//!
//! ```text
//!  POST /v1/build ── the context (tar) ──► builds/<id>/context/
//!                                           Containerfile → stages (rustlet_build)
//!  per stage the target needs:   FROM: scratch, an earlier stage, or an image (pulled if missing)
//!    RUN        → a container of the image so far; its upper directory → a layer
//!    COPY, ADD  → into a rootfs of the image so far (containers/build-<id>-<n>); its upper → a layer
//!    the rest   → the image's config
//!  the target's image → named (-t) or kept unnamed
//! ```
//!
//! **Each step that changes files is a layer**, made the way `commit` makes
//! one (`rustlet_image::diff`). A `RUN` step runs in an ordinary container,
//! labelled `io.rustlet.build=<build id>` and removed after the step (so
//! `ps -a` shows it while it runs, as Docker's classic builder's): it is
//! created from the image so far (stored unnamed for the purpose), with the
//! entrypoint cleared, the command the shell (`SHELL`) plus the string or
//! the exec form, the image's `ENV` and the stage's `ARG`s as its
//! environment, `USER` and `WORKDIR`, the build's network, and no
//! healthcheck. Its output streams back as the build's output; a non-zero
//! exit fails the build. Like Docker's classic builder, what a `RUN` writes
//! below a `VOLUME` is lost: the container mounts an anonymous volume there.
//! `COPY` and `ADD` need no process: the daemon mounts an overlay of the
//! image so far and writes into it (`rustlet_image::copy`), from the
//! context, from an earlier stage's filesystem, or from an image
//! (`--from`).
//!
//! **The cache.** Every step extends a key: the base (`image:<manifest>`,
//! `scratch`, or the earlier stage's key), then per instruction a SHA-256
//! of the key so far, the instruction as it runs (its variables expanded),
//! and what else decides its result: a `RUN`'s `ARG` values; a `COPY`'s
//! sources (a digest of their contents, names and modes from the context,
//! or the source stage's top layer, or the source image). A step that
//! changes files looks its key up in the store's build cache, an image per
//! step kept in `index.json` (`ContentStore::cache_entry`): a hit whose
//! layers are this build's plus one takes that one layer, and nothing runs.
//! Every such step's result is recorded under its key, `--no-cache` or not.
//! `builder prune` forgets the cache.
//!
//! **What holds what.** The build holds off garbage collection for its whole
//! duration (`Images::pin`): the images it writes for its containers and
//! its layers aren't named until the end. `rmi` waits for running builds,
//! as it does for pulls. A daemon that dies mid-build leaves a context
//! directory, scratch root filesystems and step containers; the next one
//! removes them at startup ([`Daemon::remove_build_leftovers`]).

use std::collections::BTreeMap;
use std::io::Read;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustlet_build::config::{ImageConfigState, created_by};
use rustlet_build::op::{CopyOp, Op};
use rustlet_build::parser::{Command, Containerfile};
use rustlet_build::plan::{ArgScope, Base, FromSource, Plan};
use rustlet_image::copy::CopySpec;
use rustlet_image::diff::{CommittedLayer, DiffOptions, commit_layer};
use rustlet_image::rootfs::ContainerRootfs;
use rustlet_image::unpack::{UnpackOptions, unpack_with};
use rustlet_image::{Digest, Image, ImageRef};
use rustlet_runtime::oci_spec::image::Descriptor;
use rustlet_shim::client::StreamEvent;
use rustlet_spec::build::{BuildEvent, BuildOptions};
use rustlet_spec::container::{ContainerConfig, HealthConfig, WaitCondition};
use rustlet_spec::event::EventKind;
use rustlet_spec::image::PullPolicy;
use rustlet_spec::logs::LogStream;
use rustlet_spec::network::NetworkMode;
use rustlet_sys::fs::{ResolveFlags, openat2};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use tokio::sync::mpsc;

use crate::daemon::Daemon;
use crate::error::{ApiError, ApiResult};
use crate::lifecycle::blocking;

/// The label on a build's `RUN` containers: the build's id.
pub const BUILD_LABEL: &str = "io.rustlet.build";
/// A Containerfile is read whole; refuse anything larger.
const MAX_CONTAINERFILE: u64 = 1 << 20;
/// How context paths are resolved: inside the context.
const IN_CONTEXT: ResolveFlags = ResolveFlags::IN_ROOT.union(ResolveFlags::NO_MAGICLINKS);

/// One layer of a stage: its blob's descriptor and diff ID.
#[derive(Debug, Clone)]
struct LayerRef {
    descriptor: Descriptor,
    diff_id: Digest,
}

/// A stage as the build goes.
#[derive(Debug, Clone)]
struct StageState {
    layers: Vec<LayerRef>,
    config: ImageConfigState,
    /// The image config JSON it started from (architecture, os, …), its
    /// `config`, `rootfs` and `history` replaced as it is written.
    base: Value,
    history: Vec<Value>,
    /// The cache key so far.
    key: String,
    args: ArgScope,
}

impl StageState {
    fn scratch(args: ArgScope) -> StageState {
        StageState {
            layers: Vec::new(),
            config: ImageConfigState::new(None),
            base: json!({"architecture": "amd64", "os": "linux"}),
            history: Vec::new(),
            key: "scratch".into(),
            args,
        }
    }

    /// When its filesystem last changed: its last dated history entry's
    /// time, or its base config's; none if nothing says (an image without
    /// dates, `scratch`).
    fn last_change(&self) -> Option<String> {
        self.history
            .iter()
            .rev()
            .find_map(|h| h["created"].as_str())
            .or_else(|| self.base["created"].as_str())
            .map(str::to_owned)
    }

    /// The chain ID of its top layer: what identifies its filesystem.
    fn top_chain_id(&self) -> String {
        let ids: Vec<Digest> = self.layers.iter().map(|l| l.diff_id.clone()).collect();
        rustlet_image::digest::chain_ids(&ids).last().map_or_else(|| "empty".into(), ToString::to_string)
    }
}

/// A running build.
struct Build {
    d: Arc<Daemon>,
    id: String,
    context: PathBuf,
    options: BuildOptions,
    file: Containerfile,
    plan: Plan,
    events: mpsc::Sender<BuildEvent>,
    step: usize,
    /// Finished stages, by index.
    done: BTreeMap<usize, StageState>,
    /// The global `ARG`s' values, as `FROM` lines saw them.
    global_args: BTreeMap<String, Option<String>>,
}

impl Daemon {
    /// Builds an image from the context `input` reads (a tar archive), as
    /// `options` say, reporting to `events`; the stream ends with `done` or
    /// `error`.
    pub async fn build(
        self: Arc<Self>,
        options: BuildOptions,
        input: impl Read + Send + 'static,
        events: mpsc::Sender<BuildEvent>,
    ) {
        let id = crate::names::new_id(|_| false)[..12].to_owned();
        let dir = self.paths.builds.join(&id);
        let result = self.clone().build_in(&id, &dir, options, input, &events).await;
        // The context, and whatever a failed step left there.
        let removing = dir.clone();
        let _ = blocking(move || match removing.symlink_metadata() {
            Ok(_) => rustlet_sys::tree::safe_remove_tree(&removing).map_err(|e| ApiError::internal(e.to_string())),
            Err(_) => Ok(()),
        })
        .await
        .inspect_err(|e| tracing::warn!(build = %id, "remove the build's directory: {e}"));
        let last = match result {
            Ok((image, names)) => BuildEvent::Done { id: image, names },
            Err(e) => BuildEvent::Error { message: e.message },
        };
        let _ = events.send(last).await;
    }

    async fn build_in(
        self: Arc<Self>,
        id: &str,
        dir: &Path,
        options: BuildOptions,
        input: impl Read + Send + 'static,
        events: &mpsc::Sender<BuildEvent>,
    ) -> ApiResult<(String, Vec<String>)> {
        let tags = check_options(&options)?;
        let context = dir.join("context");
        let mkdir = |d: &Path| std::fs::DirBuilder::new().mode(0o700).create(d);
        match mkdir(&self.paths.builds) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(ApiError::internal(format!("create {}: {e}", self.paths.builds.display()))),
        }
        for d in [dir, context.as_path()] {
            mkdir(d).map_err(|e| ApiError::internal(format!("create {}: {e}", d.display())))?;
        }
        let (files, bytes) = {
            let context = context.clone();
            blocking(move || {
                let fd = open_dir(&context)?;
                let mut input = input;
                let report = unpack_with(
                    &mut input,
                    rustlet_image::media::Compression::None,
                    fd.as_fd(),
                    &UnpackOptions { whiteouts: false },
                )
                .map_err(|e| ApiError::invalid(format!("the build context: {e}")))?;
                Ok::<_, ApiError>((report.entries, report.bytes))
            })
            .await?
        };
        send(events, BuildEvent::Context { files, bytes }).await?;
        let text = read_containerfile(&context, options.dockerfile.as_deref())?;
        let file = rustlet_build::parse(&text).map_err(|e| ApiError::invalid(format!("Containerfile: {e}")))?;
        for w in &file.warnings {
            send(events, BuildEvent::Warning { message: format!("Containerfile: {w}") }).await?;
        }
        let plan = rustlet_build::plan::plan(&file, options.target.as_deref(), &options.build_args)
            .map_err(|e| ApiError::invalid(format!("Containerfile: {e}")))?;
        if !plan.unused_args.is_empty() {
            let message = format!("one or more build args were not consumed: {}", plan.unused_args.join(", "));
            send(events, BuildEvent::Warning { message }).await?;
        }
        let global_args = plan.global_args.clone();
        // From here to the names, only this keeps garbage collection away
        // from what the build writes.
        let _pin = self.images.pin().await;
        let mut b = Build {
            d: self.clone(),
            id: id.to_owned(),
            context,
            options,
            file,
            plan,
            events: events.clone(),
            step: 0,
            done: BTreeMap::new(),
            global_args,
        };
        for index in b.plan.stages.clone() {
            let state = b.stage(index).await?;
            b.done.insert(index, state);
        }
        let target = b.plan.target;
        let mut last = b.done.remove(&target).ok_or_else(|| ApiError::internal("the target stage wasn't built"))?;
        if !b.options.labels.is_empty() {
            let labels = b.options.labels.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
            last.config.apply(&Op::Label(labels)).map_err(ApiError::internal)?;
        }
        let image = b.write_image(&last)?;
        let id = image.manifest_digest.to_string();
        if tags.is_empty() {
            self.images.keep_image(&image)?;
        }
        // One for the image, named or not (clients refresh their lists on
        // image events), then a `tag` per name.
        self.events.emit(EventKind::Image, "build", &id, [("id".to_owned(), id.clone())].into());
        for name in &tags {
            self.images.name_image(&image, name)?;
            self.events.emit(EventKind::Image, "tag", name, [("id".to_owned(), id.clone())].into());
        }
        Ok((id, tags))
    }

    /// What a daemon that died mid-build left: build directories, scratch
    /// root filesystems, step containers.
    pub async fn remove_build_leftovers(self: &Arc<Self>) {
        let builds = self.paths.builds.clone();
        let containers = self.paths.containers.clone();
        let _ = blocking(move || {
            if let Ok(entries) = std::fs::read_dir(&builds) {
                for e in entries.flatten() {
                    let _ = rustlet_sys::tree::unmount_under(&e.path());
                    if let Err(err) = rustlet_sys::tree::safe_remove_tree(&e.path()) {
                        tracing::warn!("remove the build leftover {}: {err}", e.path().display());
                    }
                }
            }
            if let Ok(entries) = std::fs::read_dir(&containers) {
                for e in entries.flatten().filter(|e| e.file_name().to_string_lossy().starts_with("build-")) {
                    if let Err(err) = ContainerRootfs::remove_dir(&e.path()) {
                        tracing::warn!("remove the build leftover {}: {err}", e.path().display());
                    }
                }
            }
            Ok::<_, ApiError>(())
        })
        .await;
        for c in self.all_containers() {
            if c.record.config.labels.contains_key(BUILD_LABEL) {
                tracing::info!(id = %c.id(), "removing a step container of an unfinished build");
                if let Err(e) = self.remove(&c, true, true).await {
                    tracing::warn!(id = %c.id(), "{e}");
                }
            }
        }
    }
}

impl Build {
    async fn emit(&self, event: BuildEvent) -> ApiResult<()> {
        send(&self.events, event).await
    }

    /// Builds stage `index`; returns its final state.
    async fn stage(&mut self, index: usize) -> ApiResult<StageState> {
        let stage = self.file.stages[index].clone();
        let base = self.plan.bases[index].clone();
        let shown_base = match &base {
            Base::Scratch => "scratch".to_owned(),
            Base::Stage(i) => self.file.stages[*i].name.clone().unwrap_or_else(|| i.to_string()),
            Base::Image(r) => r.clone(),
        };
        self.emit(BuildEvent::Stage { index, name: stage.name.clone(), base: shown_base.clone() }).await?;
        self.step += 1;
        let from = match &stage.name {
            Some(n) => format!("FROM {shown_base} AS {n}"),
            None => format!("FROM {shown_base}"),
        };
        self.emit(BuildEvent::Step { step: self.step, total: self.plan.total_steps, instruction: from }).await?;
        let args = ArgScope::new(self.global_args.clone(), self.options.build_args.clone());
        let mut st = match &base {
            Base::Scratch => StageState::scratch(args),
            Base::Stage(i) => {
                let prev = self.done.get(i).ok_or_else(|| ApiError::internal(format!("stage {i} wasn't built")))?;
                StageState { config: ImageConfigState { cmd_set: false, ..prev.config.clone() }, args, ..prev.clone() }
            }
            Base::Image(reference) => {
                let image = self.base_image(reference).await?;
                self.state_of(&image, args)?
            }
        };
        // The base's triggers: in its own config (`ImageConfigState::new`
        // leaves them out, as Docker does once it has run them).
        let triggers = match &base {
            Base::Image(_) => st.base["config"]["OnBuild"].as_array().is_some_and(|a| !a.is_empty()),
            Base::Stage(_) => st.config.config.get("OnBuild").and_then(Value::as_array).is_some_and(|a| !a.is_empty()),
            Base::Scratch => false,
        };
        // As with an image's: not run, and not passed on.
        st.config.config.remove("OnBuild");
        if triggers {
            let message = format!("{shown_base}'s ONBUILD triggers are not run");
            self.emit(BuildEvent::Warning { message }).await?;
        }
        self.emit(BuildEvent::StepDone { step: self.step, layer: None }).await?;
        for instruction in &stage.instructions {
            self.step += 1;
            let step = self.step;
            self.emit(BuildEvent::Step {
                step,
                total: self.plan.total_steps,
                instruction: instruction.original.clone(),
            })
            .await?;
            let at = |e: String| ApiError::invalid(format!("Containerfile line {}: {e}", instruction.line));
            let op = {
                let (config, args) = (&st.config, &st.args);
                Op::new(&instruction.kind, self.file.escape, &|name| config.env_var(name).or_else(|| args.get(name)))
                    .map_err(at)?
            };
            let layer = match &op {
                Op::Arg(decls) => {
                    for (name, default) in decls {
                        st.args.declare(name, default.clone());
                    }
                    let values: Vec<String> =
                        decls.iter().map(|(n, _)| format!("{n}={}", st.args.get(n).unwrap_or_default())).collect();
                    st.key = next_key(&st.key, &format!("ARG {}", values.join(" ")));
                    None
                }
                Op::Run(command) => {
                    Some(self.run(&mut st, &op, command).await.map_err(|e| e.context(format!("step {step}")))?)
                }
                Op::Copy(copy) => {
                    Some(self.copy(&mut st, &op, copy).await.map_err(|e| e.context(format!("step {step}")))?)
                }
                _ => {
                    let line = created_by(&op, &st.config);
                    st.config.apply(&op).map_err(at)?;
                    st.key = next_key(&st.key, &line);
                    // Dated as the last change of the filesystem, so that a
                    // build whose layers all come from the cache makes the
                    // same config, and so the same image, as the one before.
                    let mut entry = json!({"created_by": line, "empty_layer": true});
                    if let Some(time) = st.last_change() {
                        entry["created"] = json!(time);
                    }
                    st.history.push(entry);
                    None
                }
            };
            self.emit(BuildEvent::StepDone { step, layer }).await?;
        }
        Ok(st)
    }

    /// The image a `FROM` (or `COPY --from`) names, pulled as the build's
    /// policy says.
    async fn base_image(&self, reference: &str) -> ApiResult<Image> {
        let images = &self.d.images;
        if self.options.pull == PullPolicy::Missing
            && let Ok(image) = images.resolve(reference)
        {
            return Ok(image);
        }
        let (tx, mut rx) = mpsc::channel(64);
        let events = self.events.clone();
        let forward = tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                if events.send(BuildEvent::Pull { event }).await.is_err() {
                    return;
                }
            }
        });
        let pulled = images.pull(reference, self.options.pull, tx).await;
        let _ = forward.await;
        let image = pulled.map_err(|e| e.context(format!("pull {reference}")))?;
        image.config.check_runnable()?;
        Ok(image)
    }

    /// A stage starting from `image`.
    fn state_of(&self, image: &Image, args: ArgScope) -> ApiResult<StageState> {
        let content = self.d.images.store().content();
        let bytes = content.read_blob(&image.config_digest, rustlet_image::config::MAX_CONFIG_BYTES)?;
        let base: Value =
            serde_json::from_slice(&bytes).map_err(|e| ApiError::internal(format!("the base image's config: {e}")))?;
        let layers = image
            .manifest
            .layers()
            .iter()
            .zip(&image.layers)
            .map(|(d, l)| LayerRef { descriptor: d.clone(), diff_id: l.diff_id.clone() })
            .collect();
        Ok(StageState {
            layers,
            config: ImageConfigState::new(base.get("config")),
            history: base["history"].as_array().cloned().unwrap_or_default(),
            base,
            key: format!("image:{}", image.manifest_digest),
            args,
        })
    }

    /// Stores `st` as an image (unnamed): what a step's container or rootfs
    /// is made from, a cache entry, or the result.
    fn write_image(&self, st: &StageState) -> ApiResult<Image> {
        let content = self.d.images.store().content();
        let mut config = st.base.clone();
        config["architecture"] = json!("amd64");
        config["os"] = json!("linux");
        // Undated when nothing is dated: `now` would make every build of it
        // another image.
        match st.last_change() {
            Some(time) => config["created"] = json!(time),
            None => {
                if let Some(c) = config.as_object_mut() {
                    c.remove("created");
                }
            }
        }
        config["config"] = st.config.to_value();
        config["rootfs"] =
            json!({"type": "layers", "diff_ids": st.layers.iter().map(|l| l.diff_id.to_string()).collect::<Vec<_>>()});
        config["history"] = Value::Array(st.history.clone());
        if let Some(author) = &st.config.author {
            config["author"] = json!(author);
        }
        let bytes = serde_json::to_vec(&config).map_err(|e| ApiError::internal(format!("an image config: {e}")))?;
        let descriptors: Vec<Descriptor> = st.layers.iter().map(|l| l.descriptor.clone()).collect();
        let target = rustlet_image::import::write_image(content, &bytes, &descriptors)?;
        Ok(Image::from_manifest(content, &Digest::from_oci(target.digest())?, None, None)?)
    }

    /// The cache's result for `key`, if it is `st`'s layers plus one: that
    /// layer and its history entry.
    fn cached(&self, st: &StageState, key: &str) -> Option<(LayerRef, Value)> {
        if self.options.no_cache {
            return None;
        }
        let content = self.d.images.store().content();
        let target = content.cache_entry(key).ok()??;
        let image = Image::from_manifest(content, &Digest::from_oci(target.digest()).ok()?, None, None).ok()?;
        let n = st.layers.len();
        if image.layers.len() != n + 1
            || image.layers.iter().zip(&st.layers).any(|(cached, ours)| cached.diff_id != ours.diff_id)
        {
            tracing::debug!(key, "a cache entry whose layers aren't this build's");
            return None;
        }
        let descriptor = image.manifest.layers()[n].clone();
        // Is the layer still in the store (a collection keeps it, but a
        // store edited by hand may not)?
        let digest = Digest::from_oci(descriptor.digest()).ok()?;
        if !content.has_blob(&digest, descriptor.size()).ok()? {
            return None;
        }
        let bytes = content.read_blob(&image.config_digest, rustlet_image::config::MAX_CONFIG_BYTES).ok()?;
        let config: Value = serde_json::from_slice(&bytes).ok()?;
        let entry = config["history"]
            .as_array()
            .and_then(|h| h.iter().rev().find(|e| !e["empty_layer"].as_bool().unwrap_or(false)).cloned())
            .unwrap_or_else(|| json!({"created": now()}));
        Some((LayerRef { descriptor, diff_id: image.layers[n].diff_id.clone() }, entry))
    }

    /// Adds `layer` to `st`, and records the result under `key` (unless it
    /// came from there).
    fn add_layer(
        &self,
        st: &mut StageState,
        key: String,
        layer: LayerRef,
        history: Value,
        record: bool,
    ) -> ApiResult<()> {
        st.layers.push(layer);
        st.history.push(history);
        st.key = key;
        if !record {
            return Ok(());
        }
        let image = self.write_image(st)?;
        let content = self.d.images.store().content();
        let size = content.blob_size(&image.manifest_digest)?.unwrap_or_default();
        let target = rustlet_image::content::manifest_descriptor(
            rustlet_image::media::OCI_MANIFEST,
            &image.manifest_digest,
            size,
        );
        content.set_cache_entry(&st.key, &target)?;
        Ok(())
    }

    /// A `RUN` step.
    async fn run(&mut self, st: &mut StageState, op: &Op, command: &Command) -> ApiResult<String> {
        let line = created_by(op, &st.config);
        let args = st.config.run_args(command);
        let vars = st.args.vars();
        let key = next_key(
            &st.key,
            &format!("{line}\n{}\n{}", serde_json::to_string(&args).unwrap_or_default(), env_lines(&vars)),
        );
        if let Some((layer, history)) = self.cached(st, &key) {
            self.emit(BuildEvent::Cached { step: self.step }).await?;
            let digest = layer.descriptor.digest().to_string();
            self.add_layer(st, key, layer, history, false)?;
            return Ok(digest);
        }
        let parent = self.write_image(st)?;
        // ENV over ARG, as Docker: an ARG named as an ENV isn't passed. The
        // proxy build args (`HTTP_PROXY`…) go to every RUN, undeclared, and
        // not into its cache key, as Docker's predefined args.
        let mut env = st.config.env();
        for (name, value) in vars.iter().chain(&st.args.proxy_env()) {
            if st.config.env_var(name).is_none() {
                env.push(format!("{name}={value}"));
            }
        }
        let config = ContainerConfig {
            image: parent.manifest_digest.to_string(),
            name: Some(format!("build-{}-{}", self.id, self.step)),
            entrypoint: Some(Vec::new()),
            cmd: args.clone(),
            env,
            user: st.config.user(),
            workdir: Some(st.config.workdir()),
            labels: [(BUILD_LABEL.to_owned(), self.id.clone())].into(),
            network: self.options.network.clone(),
            healthcheck: Some(HealthConfig { test: vec!["NONE".into()], ..HealthConfig::default() }),
            ..ContainerConfig::default()
        };
        let d = self.d.clone();
        let created = d.create(config).await.map_err(|e| e.context("create the step's container"))?;
        let c = d.find(&created.id)?;
        let result = self.run_in(&c, &args).await;
        let layer = match result {
            Ok(()) => {
                let skip = crate::commit::mount_points(&d.paths.container_dir(c.id()).join("config.json"));
                let upper = d.paths.container_dir(c.id()).join("upper");
                self.commit(upper, skip).await
            }
            Err(e) => Err(e),
        };
        if let Err(e) = d.remove(&c, true, true).await {
            tracing::warn!(build = %self.id, id = %c.id(), "remove the step's container: {e}");
        }
        let layer = layer?;
        let digest = layer.descriptor.digest().to_string();
        let history = json!({"created": now(), "created_by": line});
        self.add_layer(st, key, LayerRef { descriptor: layer.descriptor, diff_id: layer.diff_id }, history, true)?;
        Ok(digest)
    }

    /// Starts the step's container, streams its output, waits for it.
    async fn run_in(&mut self, c: &Arc<crate::container::Container>, args: &[String]) -> ApiResult<()> {
        let d = self.d.clone();
        self.emit(BuildEvent::Container { step: self.step, id: c.id().to_owned() }).await?;
        let waiting = crate::attach::register(c, false);
        d.start(c).await.map_err(|e| e.context(format!("run {}", shell_words(args))))?;
        let mut stream = waiting.stream().await?;
        let step = self.step;
        let mut gone = false;
        loop {
            let event = match stream.recv().await {
                Ok(Some(event)) => event,
                Ok(None) | Err(_) => break,
            };
            let (stream_kind, bytes) = match event {
                StreamEvent::Stdout(b) => (LogStream::Stdout, b),
                StreamEvent::Stderr(b) => (LogStream::Stderr, b),
                StreamEvent::Exited(_) => break,
            };
            let text = String::from_utf8_lossy(&bytes).into_owned();
            if !gone && self.events.send(BuildEvent::Output { step, stream: stream_kind, text }).await.is_err() {
                // The client went away: the step is stopped, and so is the
                // build.
                gone = true;
                let _ = d.kill(c, Some("KILL")).await;
            }
        }
        let exit = d.wait(c, WaitCondition::NotRunning).await;
        if gone {
            return Err(ApiError::conflict("the build's client went away"));
        }
        if exit.status_code != 0 {
            return Err(ApiError::invalid(format!(
                "the command '{}' returned a non-zero code: {}",
                shell_words(args),
                exit.status_code
            )));
        }
        Ok(())
    }

    /// The changes in `upper` as a layer.
    async fn commit(&self, upper: PathBuf, skip: Vec<PathBuf>) -> ApiResult<CommittedLayer> {
        let store = self.d.images.store().clone();
        blocking(move || {
            let identity = |uid, gid| (uid, gid);
            commit_layer(store.content(), &upper, &DiffOptions { skip: &skip, map_owner: &identity })
        })
        .await
        .map_err(|e| e.context("commit the step's changes"))
    }

    /// A `COPY` or `ADD` step.
    async fn copy(&mut self, st: &mut StageState, op: &Op, copy: &CopyOp) -> ApiResult<String> {
        let line = created_by(op, &st.config);
        let spec = CopySpec {
            sources: copy.sources.clone(),
            dest: copy.dest.clone(),
            workdir: st.config.workdir(),
            owner: (0, 0),
            mode: copy.chmod,
            extract_archives: copy.add,
        };
        // What the copy reads, and what identifies it for the cache.
        let from = match &copy.from {
            Some(from) => Some(
                rustlet_build::plan::resolve_from(&self.file, self.current_stage(), from)
                    .map_err(|e| ApiError::invalid(format!("--from={from}: {e}")))?,
            ),
            None => None,
        };
        let source_key = match &from {
            None => {
                let (context, spec) = (self.context.clone(), spec.clone());
                blocking(move || {
                    let fd = open_dir(&context)?;
                    rustlet_image::copy::digest(fd.as_fd(), &spec).map_err(|e| ApiError::invalid(e.to_string()))
                })
                .await?
                .to_string()
            }
            Some(FromSource::Stage(i)) => {
                // Planned with the global variables only: a --from that only
                // the stage's own ARGs make a stage's name wasn't built.
                let from = copy.from.as_deref().unwrap_or_default();
                let src = self.done.get(i).ok_or_else(|| {
                    ApiError::invalid(format!("COPY --from={from}: stage {i} isn't built before this one"))
                })?;
                format!("stage:{}", src.top_chain_id())
            }
            Some(FromSource::Image(r)) => format!("image:{}", self.base_image(r).await?.manifest_digest),
        };
        let key = next_key(
            &st.key,
            &format!("{line}\nchown={}\nsources={source_key}", copy.chown.as_deref().unwrap_or_default()),
        );
        if let Some((layer, history)) = self.cached(st, &key) {
            self.emit(BuildEvent::Cached { step: self.step }).await?;
            let digest = layer.descriptor.digest().to_string();
            self.add_layer(st, key, layer, history, false)?;
            return Ok(digest);
        }
        // The source's root filesystem, for --from.
        let source = match &from {
            None => None,
            Some(FromSource::Stage(i)) => {
                let src = self.done.get(i).cloned().ok_or_else(|| ApiError::internal("no such stage"))?;
                let image = self.write_image(&src)?;
                Some(self.scratch_rootfs(&image, "from").await?)
            }
            Some(FromSource::Image(r)) => {
                let image = self.base_image(r).await?;
                Some(self.scratch_rootfs(&image, "from").await?)
            }
        };
        let parent = self.write_image(st)?;
        let dest = match self.scratch_rootfs(&parent, "to").await {
            Ok(dest) => dest,
            Err(e) => {
                if let Some(s) = source {
                    s.remove().await;
                }
                return Err(e);
            }
        };
        let copied = {
            let (context, chown) = (self.context.clone(), copy.chown.clone());
            let (src_dir, dest_dir) = (source.as_ref().map(|s| s.rootfs()), dest.rootfs());
            let mut spec = spec.clone();
            blocking(move || {
                let dest_fd = open_dir(&dest_dir)?;
                if let Some(chown) = chown {
                    spec.owner = owner(dest_fd.as_fd(), &chown)?;
                }
                let src_fd = open_dir(src_dir.as_deref().unwrap_or(&context))?;
                rustlet_image::copy::copy(src_fd.as_fd(), dest_fd.as_fd(), &spec).map_err(|e| {
                    ApiError::invalid(format!("{}: {e}", if spec.extract_archives { "ADD" } else { "COPY" }))
                })
            })
            .await
        };
        if let Some(s) = source {
            s.remove().await;
        }
        let upper = dest.upper();
        let layer = match copied {
            Ok(_) => {
                let unmounted = dest.unmount().await;
                match unmounted {
                    Ok(()) => self.commit(upper, Vec::new()).await,
                    Err(e) => Err(e),
                }
            }
            Err(e) => Err(e),
        };
        dest.remove().await;
        let layer = layer?;
        let digest = layer.descriptor.digest().to_string();
        let history = json!({"created": now(), "created_by": line});
        self.add_layer(st, key, LayerRef { descriptor: layer.descriptor, diff_id: layer.diff_id }, history, true)?;
        Ok(digest)
    }

    /// The stage being built: the last one started.
    fn current_stage(&self) -> usize {
        self.plan.stages.iter().copied().find(|i| !self.done.contains_key(i)).unwrap_or(self.plan.target)
    }

    /// `image`'s layers, mounted under `containers/build-<id>-<step>-<what>`
    /// with an empty upper directory.
    async fn scratch_rootfs(&self, image: &Image, what: &str) -> ApiResult<Scratch> {
        let snapshots = self.d.images.ensure_unpacked(image).await?;
        let dir = self.d.paths.containers.join(format!("build-{}-{}-{what}", self.id, self.step));
        blocking(move || {
            let rootfs = ContainerRootfs::mount(&dir, &snapshots, None)?;
            Ok::<_, rustlet_image::Error>(Scratch { dir: rootfs.dir().to_owned(), rootfs: Some(rootfs) })
        })
        .await
    }
}

/// A root filesystem mounted for a `COPY`: unmounted and removed by
/// [`Scratch::remove`].
struct Scratch {
    dir: PathBuf,
    rootfs: Option<ContainerRootfs>,
}

impl Scratch {
    fn rootfs(&self) -> PathBuf {
        self.dir.join("rootfs")
    }

    fn upper(&self) -> PathBuf {
        self.dir.join("upper")
    }

    async fn unmount(&self) -> ApiResult<()> {
        let dir = self.dir.clone();
        blocking(move || ContainerRootfs::open(&dir).and_then(|mut r| r.unmount())).await
    }

    async fn remove(mut self) {
        let dir = self.dir.clone();
        drop(self.rootfs.take());
        if let Err(e) = blocking(move || ContainerRootfs::remove_dir(&dir)).await {
            tracing::warn!("remove {}: {e}", self.dir.display());
        }
    }
}

/// Checks what can be checked before the context arrives; returns the tags,
/// normalized.
pub fn check_options(options: &BuildOptions) -> ApiResult<Vec<String>> {
    if matches!(options.network, NetworkMode::Container(_)) {
        return Err(ApiError::invalid("a build's network can't be another container's"));
    }
    options
        .tags
        .iter()
        .map(|t| ImageRef::parse(t).map(|r| r.name()).map_err(|e| ApiError::invalid(format!("-t {t:?}: {e}"))))
        .collect()
}

/// The next cache key: a SHA-256 of the key so far and the step.
fn next_key(key: &str, step: &str) -> String {
    let mut h = Sha256::new();
    h.update(key.as_bytes());
    h.update(b"\n");
    h.update(step.as_bytes());
    hex::encode(h.finalize())
}

fn env_lines(vars: &[(String, String)]) -> String {
    vars.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("\n")
}

/// `args` as a shell would show them, for messages.
fn shell_words(args: &[String]) -> String {
    args.join(" ")
}

fn now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)
}

async fn send(events: &mpsc::Sender<BuildEvent>, event: BuildEvent) -> ApiResult<()> {
    events.send(event).await.map_err(|_| ApiError::conflict("the build's client went away"))
}

/// The directory `path`, opened for `openat2`.
fn open_dir(path: &Path) -> ApiResult<OwnedFd> {
    nix::fcntl::open(
        path,
        nix::fcntl::OFlag::O_RDONLY
            | nix::fcntl::OFlag::O_DIRECTORY
            | nix::fcntl::OFlag::O_NOFOLLOW
            | nix::fcntl::OFlag::O_CLOEXEC,
        nix::sys::stat::Mode::empty(),
    )
    .map_err(|e| ApiError::internal(format!("open {}: {e}", path.display())))
}

/// The Containerfile: `name` in the context, else `Containerfile`, else
/// `Dockerfile`; read through the context (a symlink can't lead out of it).
fn read_containerfile(context: &Path, name: Option<&str>) -> ApiResult<String> {
    let root = open_dir(context)?;
    let candidates: Vec<&str> = match name.filter(|n| !n.is_empty()) {
        Some(n) => vec![n],
        None => vec!["Containerfile", "Dockerfile"],
    };
    for candidate in &candidates {
        let fd = match openat2(
            Some(root.as_fd()),
            Path::new(candidate),
            nix::fcntl::OFlag::O_RDONLY | nix::fcntl::OFlag::O_NONBLOCK | nix::fcntl::OFlag::O_CLOEXEC,
            nix::sys::stat::Mode::empty(),
            IN_CONTEXT,
        ) {
            Ok(fd) => fd,
            Err(rustlet_sys::Errno::ENOENT) => continue,
            Err(e) => return Err(ApiError::invalid(format!("open the Containerfile {candidate}: {e}"))),
        };
        let file = std::fs::File::from(fd);
        if !file.metadata().is_ok_and(|m| m.is_file()) {
            return Err(ApiError::invalid(format!("the Containerfile {candidate} is not a file")));
        }
        let mut text = String::new();
        file.take(MAX_CONTAINERFILE + 1)
            .read_to_string(&mut text)
            .map_err(|e| ApiError::invalid(format!("read the Containerfile {candidate}: {e}")))?;
        if text.len() as u64 > MAX_CONTAINERFILE {
            return Err(ApiError::invalid(format!("the Containerfile {candidate} is larger than 1 MiB")));
        }
        return Ok(text);
    }
    Err(ApiError::invalid(match name {
        Some(n) => format!("the build context has no Containerfile {n:?}"),
        None => "the build context has no Containerfile or Dockerfile".to_owned(),
    }))
}

/// `--chown=user[:group]`: names from the destination's own `/etc/passwd`
/// and `/etc/group`, or numbers; without a group, the user's number again
/// (Docker's rule for `COPY --chown`).
fn owner(root: std::os::fd::BorrowedFd<'_>, chown: &str) -> ApiResult<(u32, u32)> {
    let (user, group) = match chown.split_once(':') {
        Some((u, g)) => (u, Some(g)),
        None => (chown, None),
    };
    let uid = match user.parse::<u32>() {
        Ok(n) => n,
        Err(_) => {
            rustlet_image::user::resolve(root, Some(user))
                .map_err(|e| ApiError::invalid(format!("--chown={chown}: {e}")))?
                .uid
        }
    };
    let gid = match group {
        None => uid,
        Some(g) => match g.parse::<u32>() {
            Ok(n) => n,
            Err(_) => {
                rustlet_image::user::resolve(root, Some(&format!("0:{g}")))
                    .map_err(|e| ApiError::invalid(format!("--chown={chown}: {e}")))?
                    .gid
            }
        },
    };
    Ok((uid, gid))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_chain() {
        let a = next_key("scratch", "RUN x");
        assert_eq!(a.len(), 64);
        assert_eq!(a, next_key("scratch", "RUN x"));
        assert_ne!(a, next_key("scratch", "RUN y"));
        assert_ne!(next_key(&a, "RUN x"), a);
    }

    #[test]
    fn options_are_checked_before_the_context() {
        let ok = BuildOptions { tags: vec!["app".into(), "registry.example/a/b:1".into()], ..Default::default() };
        assert_eq!(check_options(&ok).unwrap(), ["docker.io/library/app:latest", "registry.example/a/b:1"]);
        assert!(check_options(&BuildOptions { tags: vec!["Bad Name".into()], ..Default::default() }).is_err());
        let joined = BuildOptions { network: NetworkMode::Container("x".into()), ..Default::default() };
        assert!(check_options(&joined).is_err());
    }
}

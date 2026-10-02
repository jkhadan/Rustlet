//! Containers' lifecycle: create, start, stop, kill, restart, pause, rm,
//! wait, the exit monitor, restart policies, and reconciliation at startup.
//!
//! ```text
//!  start:  snapshots (unpack in a worker if needed) → mount the overlay → config.json
//!          → spawn the shim (it runs `rustlet-runc create`, answers Ready on stdout)
//!          → connect waiting attaches, apply their terminal size → Start → running
//!          → the exit monitor: a `Wait` on shim.sock
//!  exit:   shim Delete + Shutdown → unmount → exited (persisted, published)
//!          → restart policy / --rm (takes the container's op lock)
//! ```

use std::collections::BTreeMap;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use rustlet_image::rootfs::{ContainerRootfs, remap};
use rustlet_runtime::cgroups::{Cgroup, CgroupPath};
use rustlet_shim::ShimArgs;
use rustlet_shim::client::{self as shim, ShimClient};
use rustlet_shim::protocol::{ExitStatus, Handshake, Request, Response, ShimState};
use rustlet_spec::container::{
    ContainerConfig, ContainerStatus, CreateResponse, UsernsMode, WaitCondition, WaitResponse,
};
use rustlet_spec::event::EventKind;
use tokio::io::{AsyncBufReadExt, BufReader};

use crate::container::{Container, Shared, cgroup_path, ran_for, should_restart, start_at_boot};
use crate::daemon::Daemon;
use crate::db::{Persisted, Record};
use crate::error::{ApiError, ApiResult};
use crate::spec;

/// How long `create` in the shim may take (it may wait for a memfd copy of
/// a 70 MB debug runtime).
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(120);
/// After SIGKILL, how long a container gets to be gone.
const KILL_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_STOP_TIMEOUT: u32 = 10;

impl Daemon {
    fn emit(&self, c: &Container, action: &str, extra: &[(&str, String)]) {
        let mut attrs =
            BTreeMap::from([("name".to_owned(), c.record.name.clone()), ("image".to_owned(), c.record.image.clone())]);
        for (k, v) in extra {
            attrs.insert((*k).to_owned(), v.clone());
        }
        self.events.emit(EventKind::Container, action, c.id(), attrs);
    }

    // ── create ─────────────────────────────────────────────────────────────

    pub async fn create(self: &Arc<Self>, config: ContainerConfig) -> ApiResult<CreateResponse> {
        spec::check(&config)?;
        let image = self.images.resolve(&config.image)?;
        image.config.check_runnable()?;
        let image_config = image.config.config();
        let options = rustlet_image::runspec::RunOptions {
            args: config.cmd.clone(),
            entrypoint: config.entrypoint.clone(),
            ..Default::default()
        };
        let command = rustlet_image::runspec::process_args(
            image_config.and_then(|c| c.entrypoint().as_deref()),
            image_config.and_then(|c| c.cmd().as_deref()),
            &options,
        )?;
        let stop_signal = config
            .stop_signal
            .clone()
            .or_else(|| spec::image_stop_signal(&image))
            .unwrap_or_else(|| "SIGTERM".to_owned());
        let (id, name) = {
            let all = self.containers.read().unwrap_or_else(|e| e.into_inner());
            let id = crate::names::new_id(|short| all.keys().any(|k| rustlet_spec::short_id(k) == short));
            let name = match &config.name {
                Some(n) => {
                    if all.values().any(|c| &c.record.name == n) {
                        return Err(ApiError::conflict(format!("the container name {n:?} is already in use")));
                    }
                    n.clone()
                }
                None => crate::names::new_name(|n| all.values().any(|c| c.record.name == n)),
            };
            (id, name)
        };
        let hostname =
            config.hostname.clone().filter(|h| !h.is_empty()).unwrap_or_else(|| rustlet_spec::short_id(&id).to_owned());
        let record = Record {
            id: id.clone(),
            name: name.clone(),
            created: rustlet_shim::logfile::now(),
            image: config.image.clone(),
            image_id: image.manifest_digest.to_string(),
            command,
            config,
            stop_signal,
            hostname,
        };
        let dir = self.paths.container_dir(&id);
        blocking(move || ContainerRootfs::create(&dir).map(drop).map_err(ApiError::from)).await?;
        let persisted = Persisted::default();
        if let Err(e) = self.db.insert(&record, &persisted) {
            let dir = self.paths.container_dir(&id);
            let _ = blocking(move || {
                rustlet_sys::tree::safe_remove_tree(&dir).map_err(|e| ApiError::internal(e.to_string()))
            })
            .await;
            return Err(e);
        }
        let c = Arc::new(Container::new(record, persisted));
        self.containers.write().unwrap_or_else(|e| e.into_inner()).insert(id.clone(), c.clone());
        self.emit(&c, "create", &[]);
        Ok(CreateResponse { id, name, warnings: Vec::new() })
    }

    // ── start ──────────────────────────────────────────────────────────────

    /// `start`: a user's start resets what the restart policy counts.
    pub async fn start(self: &Arc<Self>, c: &Arc<Container>) -> ApiResult<()> {
        let _op = c.op.lock().await;
        match c.status() {
            ContainerStatus::Running | ContainerStatus::Paused => return Ok(()),
            ContainerStatus::Removing => {
                return Err(ApiError::conflict(format!("container {} is being removed", c.record.name)));
            }
            ContainerStatus::Restarting => {
                c.cancel_restart();
            }
            _ => {}
        }
        c.update(&self.db, |s| {
            s.manually_stopped = false;
            s.state.restart_count = 0;
        })?;
        c.backoff.lock().unwrap_or_else(|e| e.into_inner()).reset();
        self.start_locked(c).await
    }

    /// Starts the container; the caller holds its op lock.
    async fn start_locked(self: &Arc<Self>, c: &Arc<Container>) -> ApiResult<()> {
        let result = self.start_run(c).await;
        if let Err(e) = &result {
            let message = e.message.clone();
            let _ = c.update(&self.db, |s| {
                s.state.error = Some(message);
                if s.state.status == ContainerStatus::Restarting {
                    s.state.status = ContainerStatus::Exited;
                }
            });
        }
        result
    }

    async fn start_run(self: &Arc<Self>, c: &Arc<Container>) -> ApiResult<()> {
        let r = &c.record;
        let image = self.images.resolve(&r.image_id).map_err(|e| e.context("the container's image"))?;
        let snapshots = self.images.ensure_unpacked(&image).await?;
        self.clear_leftovers(c).await;
        let dir = self.paths.container_dir(&r.id);
        let userns = r.config.userns == UsernsMode::Remap;
        let rootfs = {
            let dir = dir.clone();
            blocking(move || {
                let mut rootfs = ContainerRootfs::open(&dir)?;
                if rootfs.is_mounted()? {
                    rootfs.unmount()?;
                }
                let maps = remap();
                rootfs.mount_layers(&snapshots, userns.then_some(&maps))?;
                Ok::<_, rustlet_image::Error>(rootfs.rootfs())
            })
            .await?
        };
        match self.start_shim(c, &image, &rootfs).await {
            Ok(()) => Ok(()),
            Err(e) => {
                self.unmount(&dir).await;
                Err(e)
            }
        }
    }

    /// What a crashed run may have left: runtime state, a cgroup, a shim
    /// directory. The container isn't running (we hold its op lock and it
    /// isn't live), so all of it can go.
    async fn clear_leftovers(&self, c: &Container) {
        let id = c.id().to_owned();
        if self.paths.runtime_root.join(&id).exists() {
            self.runc_delete(&id).await;
        }
        let mut cgroups = vec![cgroup_path(&self.cgroup_parent, &id)];
        cgroups.extend(c.persisted().cgroup.filter(|cg| cg != &cgroups[0]));
        for cg in cgroups {
            if !Path::new(&format!("/sys/fs/cgroup{cg}")).exists() {
                continue;
            }
            let _ = blocking(move || {
                let cg = Cgroup::open(&CgroupPath::parse(&cg)?)?;
                cg.remove_tree(Duration::from_secs(10)).map_err(ApiError::from)
            })
            .await
            .inspect_err(|e| tracing::warn!(%id, "remove a leftover cgroup: {e}"));
        }
        let shim_dir = self.paths.shim(c.id()).dir().to_owned();
        let _ = std::fs::remove_dir_all(shim_dir);
    }

    /// `rustlet-runc delete --force`, straight from the daemon: for when no
    /// shim is there to do it.
    async fn runc_delete(&self, id: &str) {
        let out = tokio::process::Command::new(&self.runtime)
            .arg("--root")
            .arg(&self.paths.runtime_root)
            .args(["delete", "--force", id])
            .stdin(Stdio::null())
            .output()
            .await;
        match out {
            Ok(o) if !o.status.success() => {
                tracing::debug!(%id, "rustlet-runc delete: {}", String::from_utf8_lossy(&o.stderr).trim())
            }
            Err(e) => tracing::warn!(%id, "run rustlet-runc delete: {e}"),
            _ => {}
        }
    }

    async fn start_shim(
        self: &Arc<Self>,
        c: &Arc<Container>,
        image: &rustlet_image::Image,
        rootfs: &Path,
    ) -> ApiResult<()> {
        let r = &c.record;
        let dir = self.paths.container_dir(&r.id);
        let cgroup = cgroup_path(&self.cgroup_parent, &r.id);
        let spec = spec::build(image, rootfs, &r.config, &r.hostname, &cgroup)?;
        std::fs::write(dir.join("config.json"), rustlet_runtime::spec::to_pretty_json(&spec))?;
        let paths = self.paths.shim(&r.id);
        std::fs::DirBuilder::new()
            .mode(0o700)
            .recursive(true)
            .create(paths.dir())
            .map_err(|e| ApiError::internal(format!("create {}: {e}", paths.dir().display())))?;
        let args = ShimArgs {
            id: r.id.clone(),
            bundle: dir.clone(),
            dir: paths.dir().to_owned(),
            runtime: self.runtime.clone(),
            runtime_root: self.paths.runtime_root.clone(),
            cgroup: Some(format!("{}/shims", self.cgroup_parent)),
            log_path: self.paths.container_log(&r.id),
            log_max_size: self.config.log_max_size,
            log_max_files: self.config.log_max_files,
            stdin: r.config.open_stdin,
            stdin_once: r.config.stdin_once,
        };
        let log = std::fs::OpenOptions::new().create(true).append(true).open(paths.shim_log())?;
        let mut child = tokio::process::Command::new(&self.shim)
            .args(args.to_args())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(log)
            .spawn()
            .map_err(|e| ApiError::internal(format!("start {}: {e}", self.shim.display())))?;
        let stdout = child.stdout.take().expect("piped");
        // The shim outlives this call (and maybe this daemon); collect it
        // when it exits, so it doesn't linger as a zombie.
        tokio::spawn(async move {
            let _ = child.wait().await;
        });
        let mut line = String::new();
        let read = tokio::time::timeout(HANDSHAKE_TIMEOUT, BufReader::new(stdout).read_line(&mut line)).await;
        let handshake = match read {
            Ok(Ok(n)) if n > 0 => serde_json::from_str::<Handshake>(&line)
                .map_err(|e| ApiError::internal(format!("the shim said {line:?}: {e}")))?,
            Ok(_) => {
                let log = std::fs::read_to_string(paths.shim_log()).unwrap_or_default();
                return Err(ApiError::internal(format!("the shim exited without a word: {}", log.trim())));
            }
            Err(_) => return Err(ApiError::internal("the shim didn't finish creating the container in time")),
        };
        let init_pid = match handshake {
            Handshake::Ready { init_pid, .. } => init_pid,
            Handshake::Failed { message, exit_code } => {
                let _ = std::fs::remove_dir_all(paths.dir());
                return Err(ApiError::runtime(message, exit_code));
            }
        };
        let socket = paths.socket();
        match self.attach_and_start(c, &socket).await {
            Ok(()) => {}
            Err(e) => {
                let _ = shim::call(&socket, &Request::Delete { force: true }).await;
                let _ = shim::call(&socket, &Request::Shutdown).await;
                let _ = std::fs::remove_dir_all(paths.dir());
                return Err(e);
            }
        }
        c.update(&self.db, |s| {
            s.cgroup = Some(cgroup.clone());
            s.state.status = ContainerStatus::Running;
            s.state.pid = Some(init_pid);
            s.state.started_at = Some(rustlet_shim::logfile::now());
            s.state.finished_at = None;
            s.state.exit_code = None;
            s.state.oom_killed = false;
            s.state.error = None;
        })?;
        self.emit(c, "start", &[]);
        self.spawn_monitor(c.clone(), socket);
        Ok(())
    }

    /// Connects the attaches that were waiting for this start, applies the
    /// last terminal size they asked for, then lets the program run.
    async fn attach_and_start(&self, c: &Container, socket: &Path) -> ApiResult<()> {
        let pending: Vec<_> = std::mem::take(&mut *c.pending_attach.lock().unwrap_or_else(|e| e.into_inner()));
        let mut size = None;
        for p in pending {
            let opened = async {
                let client = ShimClient::connect(socket).await?;
                client.open_stream(&Request::Attach { stdin: p.stdin }).await
            }
            .await;
            match opened {
                Ok((Response::Ok, Some(stream))) => {
                    if let Some(s) = *p.resize.lock().unwrap_or_else(|e| e.into_inner()) {
                        size = Some(s);
                    }
                    let _ = p.tx.send(Ok(stream));
                }
                Ok((other, _)) => {
                    let _ = p.tx.send(Err(ApiError::internal(format!("attach: the shim said {other:?}"))));
                }
                Err(e) => {
                    let _ = p.tx.send(Err(ApiError::internal(format!("attach: {e}"))));
                }
            }
        }
        if let Some((rows, cols)) = size
            && c.record.config.tty
        {
            shim_ok(socket, Request::Resize { rows, cols }).await?;
        }
        shim_ok(socket, Request::Start).await
    }

    // ── exit ───────────────────────────────────────────────────────────────

    /// Waits for the run to end (a `Wait` on the shim), then handles it.
    fn spawn_monitor(self: &Arc<Self>, c: Arc<Container>, socket: PathBuf) {
        let d = self.clone();
        tokio::spawn(async move {
            let (exit, error) = match shim::call(&socket, &Request::Wait).await {
                Ok(Response::Exited(e)) => (e, None),
                other => {
                    tracing::warn!(id = %c.id(), "lost the shim: {other:?}");
                    (unknown_exit(), Some("the container's shim exited unexpectedly".to_owned()))
                }
            };
            d.handle_exit(&c, exit, error).await;
        });
    }

    /// Cleans up after a run, publishes the exit, then applies the restart
    /// policy. Doesn't take the op lock (see `container`).
    async fn handle_exit(self: &Arc<Self>, c: &Arc<Container>, exit: ExitStatus, error: Option<String>) {
        let id = c.id().to_owned();
        let socket = self.paths.shim(&id).socket();
        let deleted = matches!(shim::call(&socket, &Request::Delete { force: true }).await, Ok(Response::Ok));
        if !deleted {
            self.runc_delete(&id).await;
        }
        let _ = shim::call(&socket, &Request::Shutdown).await;
        let _ = std::fs::remove_dir_all(self.paths.shim(&id).dir());
        let unmounted = self.unmount(&self.paths.container_dir(&id)).await;
        let error = error.or_else(|| (!unmounted).then(|| "the root filesystem could not be unmounted".to_owned()));
        tracing::info!(%id, code = exit.code, oom = exit.oom_killed, "container exited");
        c.finish_run(&self.db, |s| {
            s.state.status = if unmounted { ContainerStatus::Exited } else { ContainerStatus::Dead };
            s.state.pid = None;
            s.state.exit_code = Some(exit.code);
            s.state.oom_killed = exit.oom_killed;
            s.state.finished_at =
                Some(if exit.finished_at.is_empty() { rustlet_shim::logfile::now() } else { exit.finished_at.clone() });
            s.state.error = error;
        });
        if exit.oom_killed {
            self.emit(c, "oom", &[]);
        }
        self.emit(c, "die", &[("exit_code", exit.code.to_string()), ("oom_killed", exit.oom_killed.to_string())]);
        let d = self.clone();
        let c = c.clone();
        tokio::spawn(async move { d.after_exit(&c).await });
    }

    /// Unmounts the container's rootfs; false if it is still mounted.
    async fn unmount(&self, dir: &Path) -> bool {
        let dir = dir.to_owned();
        blocking(move || {
            let mut rootfs = ContainerRootfs::open(&dir)?;
            rootfs.unmount()?;
            Ok::<_, rustlet_image::Error>(())
        })
        .await
        .inspect_err(|e| tracing::warn!("unmount the rootfs in {}: {e}", self.paths.containers.display()))
        .is_ok()
    }

    /// The restart policy, or `--rm`.
    async fn after_exit(self: &Arc<Self>, c: &Arc<Container>) {
        let _op = c.op.lock().await;
        let st = c.persisted();
        if st.state.status != ContainerStatus::Exited || c.subscribe().borrow().removed {
            return;
        }
        if c.record.config.auto_remove {
            if let Err(e) = self.remove_locked(c, false).await {
                tracing::warn!(id = %c.id(), "--rm: {e}");
            }
            return;
        }
        if !should_restart(&c.record.config.restart, &st) {
            return;
        }
        let delay = c.backoff.lock().unwrap_or_else(|e| e.into_inner()).delay(ran_for(&st.state));
        self.schedule_restart(c, delay);
    }

    /// `restarting` now, a start after `delay` (cancelled by start, stop or
    /// rm in between).
    fn schedule_restart(self: &Arc<Self>, c: &Arc<Container>, delay: Duration) {
        if let Err(e) = c.update(&self.db, |s| s.state.status = ContainerStatus::Restarting) {
            tracing::warn!(id = %c.id(), "{e}");
        }
        let d = self.clone();
        let c2 = c.clone();
        let timer = tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            let op = c2.op.lock().await;
            if c2.status() != ContainerStatus::Restarting {
                return;
            }
            c2.restart_timer.lock().unwrap_or_else(|e| e.into_inner()).take();
            let _ = c2.update(&d.db, |s| s.state.restart_count += 1);
            d.emit(&c2, "restart", &[]);
            if let Err(e) = d.start_locked(&c2).await {
                tracing::warn!(id = %c2.id(), "restart: {e}");
                drop(op);
                // Try again as the policy says (with the next delay).
                let d2 = d.clone();
                tokio::spawn(async move { d2.after_exit(&c2).await });
            }
        });
        *c.restart_timer.lock().unwrap_or_else(|e| e.into_inner()) = Some(timer.abort_handle());
    }

    // ── stop, kill, restart, pause ─────────────────────────────────────────

    pub async fn stop(self: &Arc<Self>, c: &Arc<Container>, timeout: Option<u32>) -> ApiResult<()> {
        let _op = c.op.lock().await;
        self.stop_locked(c, timeout).await
    }

    async fn stop_locked(self: &Arc<Self>, c: &Arc<Container>, timeout: Option<u32>) -> ApiResult<()> {
        match c.status() {
            ContainerStatus::Running | ContainerStatus::Paused => {}
            ContainerStatus::Restarting => {
                c.cancel_restart();
                c.update(&self.db, |s| {
                    s.state.status = ContainerStatus::Exited;
                    s.manually_stopped = true;
                })?;
                return Ok(());
            }
            // Not running: nothing to do (Docker answers 304).
            _ => return Ok(()),
        }
        c.update(&self.db, |s| s.manually_stopped = true)?;
        let socket = self.paths.shim(c.id()).socket();
        let mut rx = c.subscribe();
        let exits = rx.borrow().exits;
        if c.status() == ContainerStatus::Paused {
            // A frozen process can't act on its stop signal.
            let _ = shim::call(&socket, &Request::Resume).await;
        }
        let signal = spec::parse_signal(&c.record.stop_signal).unwrap_or(15);
        let _ = shim::call(&socket, &Request::Kill { signal, all: false }).await;
        let timeout =
            Duration::from_secs(u64::from(timeout.or(c.record.config.stop_timeout).unwrap_or(DEFAULT_STOP_TIMEOUT)));
        if wait_exit(&mut rx, exits, timeout).await.is_err() {
            tracing::info!(id = %c.id(), "no exit {timeout:?} after signal {signal}: killing it");
            let _ = shim::call(&socket, &Request::Kill { signal: 9, all: true }).await;
            wait_exit(&mut rx, exits, KILL_TIMEOUT)
                .await
                .map_err(|()| ApiError::internal(format!("container {} survived SIGKILL", c.record.name)))?;
        }
        self.emit(c, "stop", &[]);
        Ok(())
    }

    /// `kill`: any signal (default KILL) to init; KILL to every process.
    /// The stop signal and KILL count as a manual stop, as in Docker.
    pub async fn kill(&self, c: &Container, signal: Option<&str>) -> ApiResult<()> {
        if !c.status().is_live() {
            return Err(ApiError::conflict(format!("container {} is not running", c.record.name)));
        }
        let sig = spec::parse_signal(signal.unwrap_or("KILL"))?;
        if sig == 9 || spec::parse_signal(&c.record.stop_signal).ok() == Some(sig) {
            c.update(&self.db, |s| s.manually_stopped = true)?;
        }
        shim_ok(&self.paths.shim(c.id()).socket(), Request::Kill { signal: sig, all: sig == 9 }).await?;
        self.emit(c, "kill", &[("signal", sig.to_string())]);
        Ok(())
    }

    pub async fn restart(self: &Arc<Self>, c: &Arc<Container>, timeout: Option<u32>) -> ApiResult<()> {
        let _op = c.op.lock().await;
        self.stop_locked(c, timeout).await?;
        c.update(&self.db, |s| {
            s.manually_stopped = false;
            s.state.restart_count = 0;
        })?;
        c.backoff.lock().unwrap_or_else(|e| e.into_inner()).reset();
        self.start_locked(c).await
    }

    pub async fn pause(&self, c: &Container, pause: bool) -> ApiResult<()> {
        let _op = c.op.lock().await;
        let (from, to, request, action) = if pause {
            (ContainerStatus::Running, ContainerStatus::Paused, Request::Pause, "pause")
        } else {
            (ContainerStatus::Paused, ContainerStatus::Running, Request::Resume, "unpause")
        };
        if c.status() != from {
            return Err(ApiError::conflict(format!("container {} is {}, not {from}", c.record.name, c.status())));
        }
        shim_ok(&self.paths.shim(c.id()).socket(), request).await?;
        c.update(&self.db, |s| {
            if s.state.status == from {
                s.state.status = to;
            }
        })?;
        self.emit(c, action, &[]);
        Ok(())
    }

    // ── rm and wait ────────────────────────────────────────────────────────

    pub async fn remove(self: &Arc<Self>, c: &Arc<Container>, force: bool) -> ApiResult<()> {
        let _op = c.op.lock().await;
        self.remove_locked(c, force).await
    }

    async fn remove_locked(self: &Arc<Self>, c: &Arc<Container>, force: bool) -> ApiResult<()> {
        match c.status() {
            ContainerStatus::Running | ContainerStatus::Paused => {
                if !force {
                    return Err(ApiError::conflict(format!(
                        "container {} is {}: stop it first, or use --force",
                        c.record.name,
                        c.status()
                    )));
                }
                c.update(&self.db, |s| s.manually_stopped = true)?;
                let mut rx = c.subscribe();
                let exits = rx.borrow().exits;
                let _ = shim::call(&self.paths.shim(c.id()).socket(), &Request::Kill { signal: 9, all: true }).await;
                wait_exit(&mut rx, exits, KILL_TIMEOUT)
                    .await
                    .map_err(|()| ApiError::internal(format!("container {} survived SIGKILL", c.record.name)))?;
            }
            ContainerStatus::Restarting => {
                c.cancel_restart();
            }
            _ => {}
        }
        c.update(&self.db, |s| s.state.status = ContainerStatus::Removing)?;
        self.clear_leftovers(c).await;
        let dir = self.paths.container_dir(c.id());
        let removed = blocking(move || match ContainerRootfs::open(&dir) {
            Ok(rootfs) => rootfs.remove().map_err(ApiError::from),
            Err(_) if !dir.exists() => Ok(()),
            Err(e) => Err(ApiError::from(e)),
        })
        .await;
        if let Err(e) = removed {
            let _ = c.update(&self.db, |s| {
                s.state.status = ContainerStatus::Dead;
                s.state.error = Some(e.message.clone());
            });
            return Err(e.context(format!("remove container {}", c.record.name)));
        }
        self.db.remove(c.id())?;
        self.containers.write().unwrap_or_else(|e| e.into_inner()).remove(c.id());
        c.mark_removed();
        self.emit(c, "destroy", &[]);
        self.collect_orphaned_image(&c.record.image_id).await;
        Ok(())
    }

    /// An image whose names were all removed while containers used it
    /// (`rmi --force`) has nothing to keep it once the last of them is
    /// gone: collect it then (there is no `image prune` yet).
    async fn collect_orphaned_image(&self, image_id: &str) {
        let users = self.image_users();
        if users.contains_key(image_id) || self.images.is_named(image_id).unwrap_or(true) {
            return;
        }
        let in_use = users.keys().cloned().collect();
        match self.images.collect_garbage(&in_use).await {
            Ok(deleted) => {
                for gone in deleted {
                    self.events.emit(EventKind::Image, "delete", &gone, Default::default());
                }
            }
            Err(e) => tracing::warn!("collect image {image_id}: {e}"),
        }
    }

    pub async fn wait(&self, c: &Container, condition: WaitCondition) -> WaitResponse {
        let mut rx = c.subscribe();
        let (exits, live) = {
            let s = rx.borrow();
            (s.exits, s.persisted.state.status.is_live())
        };
        let done = |s: &Shared| match condition {
            WaitCondition::NotRunning if !live => true,
            WaitCondition::NotRunning | WaitCondition::NextExit => s.exits > exits || s.removed,
            WaitCondition::Removed => s.removed,
        };
        let state = match rx.wait_for(done).await {
            Ok(s) => s.persisted.state.clone(),
            Err(_) => c.persisted().state,
        };
        WaitResponse { status_code: state.exit_code.unwrap_or(0), oom_killed: state.oom_killed, error: state.error }
    }

    // ── startup ────────────────────────────────────────────────────────────

    /// Matches every container's recorded state with what still runs: the
    /// shims that outlived the last daemon are taken over, and runs that
    /// ended meanwhile (or with the host) are handled as exits.
    pub async fn reconcile(self: &Arc<Self>) {
        for c in self.all_containers() {
            let id = c.id().to_owned();
            let socket = self.paths.shim(&id).socket();
            match c.status() {
                ContainerStatus::Running | ContainerStatus::Paused => match shim::call(&socket, &Request::Status).await
                {
                    Ok(Response::Status(st)) => match st.state {
                        ShimState::Running | ShimState::Paused => {
                            let status = if st.state == ShimState::Paused {
                                ContainerStatus::Paused
                            } else {
                                ContainerStatus::Running
                            };
                            let _ = c.update(&self.db, |s| {
                                s.state.status = status;
                                s.state.pid = Some(st.init_pid);
                            });
                            tracing::info!(%id, "took over the running container");
                            self.spawn_monitor(c.clone(), socket);
                        }
                        ShimState::Exited => self.handle_exit(&c, st.exit.unwrap_or_else(unknown_exit), None).await,
                        ShimState::Created => {
                            let error = "the daemon stopped while the container was starting".to_owned();
                            self.handle_exit(&c, unknown_exit(), Some(error)).await
                        }
                    },
                    _ => {
                        // No shim: it was killed, or the host restarted.
                        let saved = std::fs::read(self.paths.shim(&id).exit_json())
                            .ok()
                            .and_then(|b| serde_json::from_slice::<ExitStatus>(&b).ok());
                        let error =
                            saved.is_none().then(|| "the container's shim was gone when the daemon started".to_owned());
                        self.handle_exit(&c, saved.unwrap_or_else(unknown_exit), error).await;
                    }
                },
                ContainerStatus::Restarting => self.schedule_restart(&c, Duration::ZERO),
                ContainerStatus::Removing => {
                    let d = self.clone();
                    let _ = d.remove(&c, true).await;
                }
                ContainerStatus::Created | ContainerStatus::Exited | ContainerStatus::Dead => {
                    self.unmount(&self.paths.container_dir(&id)).await;
                    if start_at_boot(&c.record.config.restart, &c.persisted()) {
                        let _op = c.op.lock().await;
                        // Running again: its next exit is the policy's to judge.
                        let _ = c.update(&self.db, |s| s.manually_stopped = false);
                        if let Err(e) = self.start_locked(&c).await {
                            tracing::warn!(%id, "start at daemon start: {e}");
                        }
                    }
                }
            }
        }
    }
}

/// An exit nobody saw.
fn unknown_exit() -> ExitStatus {
    ExitStatus { code: 255, signal: None, oom_killed: false, finished_at: rustlet_shim::logfile::now() }
}

/// Sends `request`, expecting `Ok`.
async fn shim_ok(socket: &Path, request: Request) -> ApiResult<()> {
    match shim::call(socket, &request).await {
        Ok(Response::Ok) => Ok(()),
        Ok(Response::Error { message, exit_code }) => Err(ApiError::runtime(message, exit_code)),
        Ok(other) => Err(ApiError::internal(format!("{request:?}: the shim said {other:?}"))),
        Err(e) => Err(ApiError::internal(format!("{request:?}: the container's shim: {e}"))),
    }
}

/// Waits until a run that was going when `exits` was read has ended.
async fn wait_exit(rx: &mut tokio::sync::watch::Receiver<Shared>, exits: u64, timeout: Duration) -> Result<(), ()> {
    match tokio::time::timeout(timeout, rx.wait_for(|s| s.exits > exits || s.removed)).await {
        Ok(Ok(_)) => Ok(()),
        _ => Err(()),
    }
}

/// Runs blocking filesystem work (mounts, tree removal) off the async
/// threads.
pub async fn blocking<T, E, F>(f: F) -> ApiResult<T>
where
    F: FnOnce() -> Result<T, E> + Send + 'static,
    T: Send + 'static,
    E: Into<ApiError> + Send + 'static,
{
    match tokio::task::spawn_blocking(move || f().map_err(Into::into)).await {
        Ok(r) => r,
        Err(e) => Err(ApiError::internal(format!("a blocking task failed: {e}"))),
    }
}

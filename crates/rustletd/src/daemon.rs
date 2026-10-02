//! The daemon's shared state and its startup.
//!
//! ```text
//!  rustletd start
//!   1. one daemon per run root: an OFD lock on <run>/rustletd.lock
//!   2. directories: <run> 0711, runtime/ and shims/ 0700; the store (data root)
//!   3. containers/ becomes a private bind mount of itself
//!   4. the cgroup parent (ours, minus /daemon, as DelegateSubgroup=daemon
//!      sets it up), and its shims/ and workers/ cgroups
//!   5. state.db, then every container in it, reconciled with what is still
//!      running (the shims that outlived the last daemon)
//!   6. the API socket; READY=1 to systemd
//! ```

use std::collections::BTreeMap;
use std::fs::File;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};

use anyhow::{Context, bail};
use rustlet_image::Store;
use rustlet_spec::container::ContainerStatus;

use crate::config::{Config, Paths};
use crate::container::Container;
use crate::db::Db;
use crate::error::{ApiError, ApiResult};
use crate::events::EventBus;
use crate::exec::ExecSession;
use crate::images::{Images, WorkerConfig};

pub struct Daemon {
    pub config: Config,
    pub paths: Paths,
    pub db: Db,
    pub events: EventBus,
    pub images: Images,
    pub containers: RwLock<BTreeMap<String, Arc<Container>>>,
    pub execs: Mutex<BTreeMap<String, Arc<ExecSession>>>,
    pub cgroup_parent: String,
    pub runtime: PathBuf,
    pub shim: PathBuf,
    /// Held for the daemon's lifetime (step 1).
    _lock: File,
}

impl Daemon {
    /// Steps 1–5.
    pub async fn open(config: Config) -> anyhow::Result<Arc<Daemon>> {
        let paths = Paths::new(&config);
        make_dir(&paths.run_root, 0o711)?;
        let lock = lock_file(&paths.lock)?;
        make_dir(&paths.runtime_root, 0o700)?;
        make_dir(&paths.shims, 0o700)?;
        let store =
            Store::open(&paths.data_root).with_context(|| format!("open the store {}", paths.data_root.display()))?;
        if config.private_containers_mount {
            private_mount(&paths.containers)?;
        }
        let cgroup_parent = match &config.cgroup_parent {
            Some(p) => p.trim_end_matches('/').to_owned(),
            None => default_cgroup_parent()?,
        };
        for leaf in ["shims", "workers", "containers"] {
            let dir = format!("/sys/fs/cgroup{cgroup_parent}/{leaf}");
            match std::fs::create_dir(&dir) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => bail!("create cgroup {dir}: {e} (is {cgroup_parent} delegated to us?)"),
            }
        }
        let exe = std::env::current_exe().context("locate rustletd")?;
        let beside = |name: &str| exe.with_file_name(name);
        let runtime = config.runtime.clone().unwrap_or_else(|| beside("rustlet-runc"));
        let shim = config.shim.clone().unwrap_or_else(|| beside("rustlet-shim"));
        for (what, p) in [("runtime", &runtime), ("shim", &shim)] {
            if !p.is_file() {
                bail!("the {what} {} doesn't exist (set `{what}` in {})", p.display(), crate::config::CONFIG_FILE);
            }
        }
        let db = Db::open(&paths.db)?;
        let images = Images::new(
            store,
            WorkerConfig {
                exe,
                data_root: paths.data_root.clone(),
                cgroup_dir: format!("{cgroup_parent}/workers"),
                memory_max: config.worker_memory_max,
                pids_max: config.worker_pids_max,
                insecure_registries: config.insecure_registries.clone(),
            },
        );
        let mut containers = BTreeMap::new();
        for (record, persisted) in db.all()? {
            containers.insert(record.id.clone(), Arc::new(Container::new(record, persisted)));
        }
        let daemon = Arc::new(Daemon {
            config,
            paths,
            db,
            events: EventBus::default(),
            images,
            containers: RwLock::new(containers),
            execs: Mutex::new(BTreeMap::new()),
            cgroup_parent,
            runtime,
            shim,
            _lock: lock,
        });
        daemon.reconcile().await;
        Ok(daemon)
    }

    /// The container `key` names: a full id, a name, or a unique id prefix.
    pub fn find(&self, key: &str) -> ApiResult<Arc<Container>> {
        let all = self.containers.read().unwrap_or_else(|e| e.into_inner());
        if let Some(c) = all.get(key) {
            return Ok(c.clone());
        }
        if let Some(c) = all.values().find(|c| c.record.name == key) {
            return Ok(c.clone());
        }
        let matches: Vec<_> = if key.is_empty() {
            Vec::new()
        } else {
            all.range(key.to_owned()..).take_while(|(id, _)| id.starts_with(key)).collect()
        };
        match matches.as_slice() {
            [(_, c)] => Ok((*c).clone()),
            [] => Err(ApiError::no_such_container(key)),
            _ => Err(ApiError::invalid(format!("{key} matches more than one container: give more of the id"))),
        }
    }

    pub fn all_containers(&self) -> Vec<Arc<Container>> {
        self.containers.read().unwrap_or_else(|e| e.into_inner()).values().cloned().collect()
    }

    /// Image id → names of the containers created from it.
    pub fn image_users(&self) -> BTreeMap<String, Vec<String>> {
        let mut m: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for c in self.all_containers() {
            m.entry(c.record.image_id.clone()).or_default().push(c.record.name.clone());
        }
        m
    }

    pub fn counts(&self) -> (usize, usize, usize, usize) {
        let all = self.all_containers();
        let n = |s: ContainerStatus| all.iter().filter(|c| c.status() == s).count();
        (
            all.len(),
            n(ContainerStatus::Running),
            n(ContainerStatus::Paused),
            all.len() - n(ContainerStatus::Running) - n(ContainerStatus::Paused),
        )
    }
}

/// `mkdir` (if missing) with `mode`, and insist on a real directory.
fn make_dir(path: &Path, mode: u32) -> anyhow::Result<()> {
    match std::fs::DirBuilder::new().mode(mode).recursive(true).create(path) {
        Ok(()) => {}
        Err(e) => bail!("create {}: {e}", path.display()),
    }
    let meta = std::fs::symlink_metadata(path)?;
    if !meta.is_dir() {
        bail!("{} must be a directory (not a symlink)", path.display());
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    Ok(())
}

/// An exclusive OFD lock on `path`, without waiting: a second daemon on the
/// same run root would fight the first over every container.
fn lock_file(path: &Path) -> anyhow::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    let whole = libc::flock {
        l_type: libc::F_WRLCK as libc::c_short,
        l_whence: libc::SEEK_SET as libc::c_short,
        l_start: 0,
        l_len: 0,
        l_pid: 0,
    };
    match nix::fcntl::fcntl(&file, nix::fcntl::FcntlArg::F_OFD_SETLK(&whole)) {
        Ok(_) => Ok(file),
        Err(nix::errno::Errno::EAGAIN | nix::errno::Errno::EACCES) => {
            bail!(
                "another rustletd is running on {} (it holds {})",
                path.parent().unwrap_or(path).display(),
                path.display()
            )
        }
        Err(e) => bail!("lock {}: {e}", path.display()),
    }
}

/// Step 3. Under a shared `/` (systemd's default), every mount made below
/// `containers/` would be copied into every mount namespace that is a peer
/// or slave of the host's: other services' private namespaces would hold
/// containers' overlays. A private bind mount of `containers/` onto itself
/// stops that; it is made once and outlives the daemon, like the overlays.
/// Not done if something is already mounted below (a plain bind would hide
/// it).
fn private_mount(dir: &Path) -> anyhow::Result<()> {
    use rustlet_sys::mount::{MsFlags, mount};
    let dir = dir.canonicalize().with_context(|| format!("resolve {}", dir.display()))?;
    let mounts = rustlet_sys::mountinfo::read_self().context("read mountinfo")?;
    let here = mounts.iter().find(|m| m.mount_point == dir);
    if here.is_none() {
        if mounts.iter().any(|m| m.mount_point.starts_with(&dir)) {
            tracing::warn!("not making {} a private mount: something is mounted below it already", dir.display());
            return Ok(());
        }
        mount(Some(&dir), &dir, None::<&str>, MsFlags::MS_BIND, None::<&str>)
            .with_context(|| format!("bind {} onto itself", dir.display()))?;
    }
    mount(None::<&str>, &dir, None::<&str>, MsFlags::MS_PRIVATE, None::<&str>)
        .with_context(|| format!("make {} private", dir.display()))?;
    Ok(())
}

/// Under systemd with `DelegateSubgroup=daemon`, we run in
/// `<unit cgroup>/daemon`; the unit's cgroup (delegated to us) is the parent.
fn default_cgroup_parent() -> anyhow::Result<String> {
    let own = rustlet_runtime::cgroups::own_cgroup()?;
    let own = own.display().to_string();
    match own.strip_suffix("/daemon") {
        Some(parent) if !parent.is_empty() => Ok(parent.to_owned()),
        _ => bail!(
            "rustletd runs in cgroup {own}, not in a `daemon` leaf of a delegated unit: run it as rustletd.service \
             (Delegate=yes, DelegateSubgroup=daemon) or pass --cgroup-parent"
        ),
    }
}

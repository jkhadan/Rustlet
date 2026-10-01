//! Container state on disk: `<root>/<id>/state.json` and `exec.fifo`.
//!
//! The OCI runtime spec defines a container's *state* as a small JSON
//! document (`ociVersion`, `id`, `status`, `pid`, `bundle`, `annotations`),
//! which `rustlet-runc state <id>` prints. Everything else the runtime needs
//! to find the container again later (the start time that guards against
//! PID reuse, the cgroup) is kept next to it in a `rustlet` section.
//!
//! ```text
//! /run/rustlet/runtime/<id>/          (0700, root)
//! ├─ state.json                        written atomically (temp file + rename)
//! └─ exec.fifo                         exists from `create` until `start`
//! ```
//!
//! `state.json` is written *before* anything else is created (a provisional
//! `creating` state naming the cgroup), and updated after each step that
//! creates something (cgroup, init). So whatever a crashed or SIGKILLed
//! `create` left behind, `delete` can always find it again.
//!
//! Apart from `creating`, `status` is never trusted from the file: it is
//! *derived* every time from the live system, so a crash between two steps
//! can't leave a stale answer. Every operation that changes a container
//! holds its lock ([`StateDir::lock`]), so `start`, `delete`, `pause` and a
//! still-running `create` never interleave.
//!
//! | status    | meaning                                                    |
//! |-----------|------------------------------------------------------------|
//! | `creating`| `create` is still setting up (init hasn't reported Ready)  |
//! | `created` | init is alive, blocked on `exec.fifo`                      |
//! | `running` | init is alive and `exec.fifo` is gone (`start` happened)   |
//! | `paused`  | running, and the cgroup is frozen                          |
//! | `stopped` | init is gone (or its PID now belongs to another process)   |

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use nix::unistd::Pid;
use serde::{Deserialize, Serialize};

use rustlet_sys::Errno;

use crate::cgroups::{Cgroup, CgroupPath};
use crate::error::{Context, Error, Result};
use crate::plan::validate_id;

/// Default `--root`, as in `rustlet-runc --root`.
pub const DEFAULT_ROOT: &str = "/run/rustlet/runtime";
const STATE_FILE: &str = "state.json";
const EXEC_FIFO: &str = "exec.fifo";
/// A copy of the bundle's `config.json`, as it was at `create`.
const CONFIG_FILE: &str = "config.json";

/// OCI container status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Creating,
    Created,
    Running,
    Paused,
    Stopped,
}

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Status::Creating => "creating",
            Status::Created => "created",
            Status::Running => "running",
            Status::Paused => "paused",
            Status::Stopped => "stopped",
        };
        // `pad`, not `write_str`, so `{:<10}` in tables is honoured.
        f.pad(s)
    }
}

/// The contents of `state.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    #[serde(rename = "ociVersion")]
    pub oci_version: String,
    pub id: String,
    /// As derived by [`State::refresh`]; the stored value is only a hint.
    pub status: Status,
    /// Host PID of the container's init.
    pub pid: i32,
    pub bundle: PathBuf,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,
    /// runc prints these two as well.
    pub rootfs: PathBuf,
    /// RFC 3339, UTC.
    pub created: String,
    /// Rustlets' own bookkeeping.
    pub rustlet: Private,
}

/// The part of the state only Rustlets reads. Every field has a default, so
/// state files written by older builds stay readable.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Private {
    /// Field 22 of `/proc/<pid>/stat` when init was created. If `pid` is
    /// ever recycled for another process, its start time differs, and the
    /// container counts as stopped instead of the stranger being signalled.
    pub init_start_time: u64,
    /// The container's cgroup, if `linux.cgroupsPath` was set.
    pub cgroup: Option<CgroupPath>,
    /// Inode of that cgroup's directory once created: its identity, checked
    /// before every freeze/kill/remove.
    pub cgroup_ino: Option<u64>,
    /// The id of the device filter attached to that cgroup (`bpftool prog
    /// show id N`). `None`: no filter, because there is no cgroup, or the
    /// container was created before Phase 2c part 2. `exec` allows
    /// `CAP_MKNOD` only with a filter (or a user namespace).
    pub device_filter: Option<u32>,
    /// Created with `--no-new-keyring`: `exec` then keeps its caller's
    /// session keyring too.
    pub no_new_keyring: bool,
    /// For a container without a cgroup of its own: the cgroup init was
    /// born in (the caller's), as `/proc/<pid>/cgroup` showed it. `exec`
    /// joins this one even if init has since moved into a sub-cgroup.
    pub init_cgroup: Option<String>,
}

impl State {
    /// Host PID of init.
    pub fn init_pid(&self) -> Pid {
        Pid::from_raw(self.pid)
    }

    /// Is init still the process we created?
    pub fn init_alive(&self) -> bool {
        rustlet_sys::procfs::is_alive(self.init_pid(), Some(self.rustlet.init_start_time))
    }

    /// The container's cgroup: `None` if it has none or it is already gone.
    /// Fails if the cgroup at that path is not the one this container
    /// created (a different inode), or can't be opened: in neither case may
    /// we freeze, kill or remove it.
    pub fn cgroup(&self) -> Result<Option<Cgroup>> {
        let Some(path) = &self.rustlet.cgroup else { return Ok(None) };
        if !path.host_path().exists() {
            return Ok(None);
        }
        let Some(ino) = self.rustlet.cgroup_ino else {
            // `create` died between writing the provisional state and
            // creating the cgroup: whatever is at that path isn't ours.
            return Ok(None);
        };
        let cg = Cgroup::open(path)?;
        if cg.inode()? != ino {
            return Err(Error::container(format!(
                "cgroup {path} is not the one container {:?} created (it was replaced); refusing to touch it",
                self.id
            )));
        }
        Ok(Some(cg))
    }

    /// Derives `status` from the live system (see the module docs).
    pub fn refresh(&mut self, dir: &StateDir) {
        let creating = self.status == Status::Creating;
        self.status = if self.pid == 0 {
            // init not spawned yet: still creating, unless `create` died.
            if creating { Status::Creating } else { Status::Stopped }
        } else if !self.init_alive() {
            Status::Stopped
        } else if creating {
            Status::Creating
        } else if self.cgroup().ok().flatten().is_some_and(|c| c.is_frozen().unwrap_or(false)) {
            Status::Paused
        } else if dir.fifo().exists() {
            Status::Created
        } else {
            Status::Running
        };
    }

    /// The state as `rustlet-runc state` prints it: like runc, a stopped
    /// container shows `pid` 0, so no caller signals a recycled PID.
    pub fn for_display(&self) -> State {
        let mut s = self.clone();
        if s.status == Status::Stopped {
            s.pid = 0;
        }
        s
    }
}

/// `<root>/<id>`.
#[derive(Debug, Clone)]
pub struct StateDir {
    root: PathBuf,
    id: String,
    dir: PathBuf,
}

impl StateDir {
    /// `root` is made absolute and, if it exists, canonical (symlink-free):
    /// `safe_remove_tree` refuses anything else, and `/var/run` → `/run`
    /// style roots are common.
    pub fn new(root: &Path, id: &str) -> Result<StateDir> {
        validate_id(id)?;
        let root = canonical_root(root)?;
        let dir = root.join(id);
        Ok(StateDir { root, id: id.to_owned(), dir })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn path(&self) -> &Path {
        &self.dir
    }

    /// `exec.fifo`: the gate between `create` and `start`.
    pub fn fifo(&self) -> PathBuf {
        self.dir.join(EXEC_FIFO)
    }

    /// Creates the directory (and the root if needed) and returns the
    /// container's lock. `mkdir` is atomic, so two `create`s with the same id
    /// can't both succeed.
    pub fn create(&mut self) -> Result<Lock> {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&self.root)
            .with_context(|| format!("create state root {}", self.root.display()))?;
        // The root exists now, so it can be made canonical.
        *self = StateDir::new(&self.root, &self.id)?;
        match std::fs::DirBuilder::new().mode(0o700).create(&self.dir) {
            Ok(()) => self.lock(),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                Err(Error::container(format!("container {:?} already exists", self.id)))
            }
            Err(e) => Err(e).with_context(|| format!("create {}", self.dir.display())),
        }
    }

    /// Takes the container's exclusive lock, waiting for whoever holds it.
    /// Released when the [`Lock`] is dropped, or when the holder dies.
    ///
    /// It is a POSIX record lock (`fcntl(F_SETLKW)`) on `<dir>/.lock`, not
    /// an `flock`, on purpose: an `flock` belongs to the *open file*, which
    /// container init shares with `create` after `clone3` (the fd comes along
    /// in the copied address space). A SIGKILLed `create` would then leave
    /// init holding the lock while it waits at the gate, and every `delete`
    /// or `start` would block forever. A record lock belongs to the
    /// *process*: never inherited by children, gone the moment its owner dies.
    /// (Its classic pitfall, that closing *any* fd for the file drops the
    /// lock, doesn't bite: only this function opens `.lock`.)
    pub fn lock(&self) -> Result<Lock> {
        use std::os::unix::fs::OpenOptionsExt;
        let path = self.dir.join(".lock");
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => Error::container(format!("container {:?} does not exist", self.id)),
                _ => Error::Io { context: format!("open {}", path.display()), err: e },
            })?;
        let whole_file = libc::flock {
            l_type: libc::F_WRLCK as libc::c_short,
            l_whence: libc::SEEK_SET as libc::c_short,
            l_start: 0,
            l_len: 0,
            l_pid: 0,
        };
        loop {
            match nix::fcntl::fcntl(&file, nix::fcntl::FcntlArg::F_SETLKW(&whole_file)) {
                Ok(_) => return Ok(Lock(file)),
                Err(Errno::EINTR) => continue,
                Err(e) => return Err(e).with_context(|| format!("lock {}", path.display())),
            }
        }
    }

    pub fn exists(&self) -> bool {
        self.dir.is_dir()
    }

    /// Writes `state.json` atomically.
    pub fn write(&self, state: &State) -> Result<()> {
        let tmp = self.dir.join(".state.json.tmp");
        let json = serde_json::to_vec_pretty(state).expect("State always serializes");
        std::fs::write(&tmp, json).with_context(|| format!("write {}", tmp.display()))?;
        std::fs::rename(&tmp, self.dir.join(STATE_FILE)).with_context(|| format!("rename {}", tmp.display()))
    }

    /// Keeps a copy of the `config.json` the container was created from.
    /// `exec` starts from its `process` and seccomp profile: the bundle's
    /// file may have changed (or be gone) since.
    pub fn write_config(&self, spec: &oci_spec::runtime::Spec) -> Result<()> {
        let path = self.dir.join(CONFIG_FILE);
        let json = serde_json::to_vec(spec).expect("a Spec always serializes");
        std::fs::write(&path, json).with_context(|| format!("write {}", path.display()))
    }

    /// The copy written by [`write_config`](Self::write_config).
    pub fn load_config(&self) -> Result<oci_spec::runtime::Spec> {
        let path = self.dir.join(CONFIG_FILE);
        let text = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
        serde_json::from_slice(&text).map_err(|e| Error::container(format!("{} is unreadable ({e})", path.display())))
    }

    /// Reads `state.json` and refreshes its status.
    pub fn load(&self) -> Result<State> {
        let path = self.dir.join(STATE_FILE);
        let text = match std::fs::read(&path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // The provisional state is written right after mkdir, so
                // this is a create caught in that instant (or a directory
                // that isn't ours).
                return Err(if self.exists() {
                    Error::container(format!("container {:?} is still being created", self.id))
                } else {
                    Error::container(format!("container {:?} does not exist", self.id))
                });
            }
            Err(e) => return Err(e).with_context(|| format!("read {}", path.display())),
        };
        // Unreadable state is an error, never "nothing there": a live init
        // or cgroup may depend on it.
        let mut state: State = serde_json::from_slice(&text)
            .map_err(|e| Error::container(format!("{} is unreadable ({e}); inspect it by hand", path.display())))?;
        state.refresh(self);
        Ok(state)
    }

    /// Deletes the directory (never through a mount; see
    /// `rustlet_sys::tree::safe_remove_tree`).
    pub fn remove(&self) -> Result<()> {
        rustlet_sys::tree::safe_remove_tree(&self.dir)
            .map_err(|e| Error::container(format!("remove state directory {}: {e}", self.dir.display())))
    }
}

/// An exclusive lock on one container's state (see [`StateDir::lock`]).
/// Dropping it closes the file, which releases the lock.
#[derive(Debug)]
pub struct Lock(#[allow(dead_code)] std::fs::File);

fn canonical_root(root: &Path) -> Result<PathBuf> {
    let abs = if root.is_absolute() {
        root.to_owned()
    } else {
        std::env::current_dir().context("current directory")?.join(root)
    };
    match std::fs::canonicalize(&abs) {
        Ok(c) => Ok(c),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(abs),
        Err(e) => Err(e).with_context(|| format!("resolve {}", abs.display())),
    }
}

/// Every container under `root`, sorted by id. Directories without a
/// readable `state.json` show up as `creating`.
pub fn list(root: &Path) -> Result<Vec<State>> {
    let entries = match std::fs::read_dir(root) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("read {}", root.display())),
    };
    let mut out = Vec::new();
    for entry in entries {
        let entry = entry.with_context(|| format!("read {}", root.display()))?;
        let Some(id) = entry.file_name().to_str().map(str::to_owned) else { continue };
        let Ok(dir) = StateDir::new(root, &id) else { continue };
        if !dir.exists() {
            continue;
        }
        match dir.load() {
            Ok(s) => out.push(s),
            Err(_) => out.push(State {
                oci_version: String::new(),
                id,
                status: Status::Creating,
                pid: 0,
                bundle: PathBuf::new(),
                annotations: BTreeMap::new(),
                rootfs: PathBuf::new(),
                created: String::new(),
                rustlet: Private::default(),
            }),
        }
    }
    out.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(out)
}

/// Now, as RFC 3339 UTC with nanoseconds (the format runc uses).
pub fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(pid: i32, start: u64) -> State {
        State {
            oci_version: "1.2.0".into(),
            id: "c1".into(),
            status: Status::Created,
            pid,
            bundle: "/b".into(),
            annotations: BTreeMap::new(),
            rootfs: "/b/rootfs".into(),
            created: now_rfc3339(),
            rustlet: Private { init_start_time: start, ..Default::default() },
        }
    }

    #[test]
    fn status_is_derived_not_trusted() {
        let root = tempfile::tempdir().unwrap();
        let mut dir = StateDir::new(root.path(), "c1").unwrap();
        let _lock = dir.create().unwrap();
        let me = nix::unistd::getpid();
        let start = rustlet_sys::procfs::start_time(me).unwrap();
        dir.write(&sample(me.as_raw(), start)).unwrap();
        // Alive, no fifo: running (whatever the file says).
        assert_eq!(dir.load().unwrap().status, Status::Running);
        // Alive, fifo present: created.
        std::fs::write(dir.fifo(), "").unwrap();
        assert_eq!(dir.load().unwrap().status, Status::Created);
        // Same PID but a different start time = a recycled PID: stopped.
        dir.write(&sample(me.as_raw(), start + 1)).unwrap();
        assert_eq!(dir.load().unwrap().status, Status::Stopped);
    }

    #[test]
    fn create_is_exclusive_and_oci_fields_serialize() {
        let root = tempfile::tempdir().unwrap();
        let mut dir = StateDir::new(root.path(), "c1").unwrap();
        let _lock = dir.create().unwrap();
        assert!(dir.create().unwrap_err().to_string().contains("already exists"));
        let v = serde_json::to_value(sample(1, 1)).unwrap();
        for key in ["ociVersion", "id", "status", "pid", "bundle"] {
            assert!(v.get(key).is_some(), "{key} missing: {v}");
        }
        assert_eq!(v["status"], "created");
    }

    #[test]
    fn list_includes_half_created_containers() {
        let root = tempfile::tempdir().unwrap();
        let _b = StateDir::new(root.path(), "b").unwrap().create().unwrap();
        let mut a = StateDir::new(root.path(), "a").unwrap();
        let _a = a.create().unwrap();
        a.write(&State { id: "a".into(), ..sample(1, 1) }).unwrap();
        let l = list(root.path()).unwrap();
        assert_eq!(
            l.iter().map(|s| (s.id.as_str(), s.status)).collect::<Vec<_>>(),
            [("a", Status::Stopped), ("b", Status::Creating)]
        );
    }
}

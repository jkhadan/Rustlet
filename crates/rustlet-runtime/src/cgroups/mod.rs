//! cgroups v2: placing a container in its own cgroup, limiting it, freezing
//! it, killing it, and reading its statistics. Which devices it may use is
//! an eBPF program attached to the cgroup ([`devices`]).
//!
//! A cgroup is a directory in the `cgroup2` filesystem at `/sys/fs/cgroup`.
//! Everything is done with plain file operations: `mkdir` creates a cgroup,
//! writing a PID to `cgroup.procs` moves a process into it, writing
//! `memory.max` limits it, `rmdir` removes it. The kernel does the rest.
//!
//! ## Where container cgroups may live
//!
//! systemd owns the cgroup tree. It hands a subtree to a unit only when the
//! unit says `Delegate=yes`, and marks that subtree's root with the xattr
//! `trusted.delegate="1"` (systemd ≥ 251). Rustlets only ever creates,
//! freezes, kills or removes cgroups **strictly below such a delegated
//! root** ([`SystemdDelegated`]); anything else is refused before any file is
//! written. On this host that means:
//!
//! * tests: `system.slice/rustlet-itest-….scope/<container>` (the scope comes
//!   from `systemd-run --scope -p Delegate=yes`, see `cargo xtask itest`);
//! * the daemon (Phase 4): `system.slice/rustletd.service/containers/<id>`.
//!
//! Outside a delegated subtree, systemd would sooner or later "correct" our
//! changes (it rewrites `subtree_control` and removes cgroups it doesn't
//! know), and a bug of ours could freeze or kill processes that aren't ours.
//!
//! ## Creating a container cgroup
//!
//! ```text
//! /sys/fs/cgroup/system.slice/rustlet-itest-1.scope    trusted.delegate=1  ← delegated root
//! ├── cgroup.subtree_control   "+cpu +memory +pids"    ← (2) enable controllers
//! ├── harness/                 the test harness itself ← no processes in the root!
//! └── web/                                             ← (3) mkdir, (4) write settings
//!     ├── memory.max           33554432
//!     └── cgroup.procs         ← clone3(CLONE_INTO_CGROUP) puts init here
//! ```
//!
//! [`Cgroup::create`] (1) asks the [`CgroupDriver`] for the delegated root,
//! (2) walks from there down to the new cgroup's parent, creating missing
//! intermediate cgroups and enabling the controllers the container needs in
//! each `cgroup.subtree_control`, (3) creates the cgroup, and (4) writes
//! the [`Setting`]s that [`settings_for`] derived from `linux.resources`.
//!
//! Controllers must be enabled *top-down*: a cgroup's interface files
//! (`memory.max`, …) exist only if its parent lists the controller in
//! `cgroup.subtree_control`, and a parent can only enable what its own
//! parent enabled for it (`cgroup.controllers`).
//!
//! ## The "no internal processes" rule
//!
//! A non-root cgroup can have child cgroups with *domain* controllers
//! (memory, io, cpu weights…) enabled, *or* processes, never both: otherwise
//! the kernel would have to decide how a parent's processes compete with its
//! children for, say, memory. ("Threaded" controllers such as `pids` are
//! exempt, but the container always needs `memory`.) So every
//! cgroup between the delegated root and the container's cgroup must be
//! empty of processes before [`Cgroup::create`] can enable controllers in
//! its `cgroup.subtree_control` (the kernel says `EBUSY`). Callers that
//! live in the delegated root themselves (the test harness) move into a
//! leaf first.
//!
//! ## Lifecycle
//!
//! Freezing (`cgroup.freeze`) and killing (`cgroup.kill`) act on the whole
//! subtree at once, which is what makes them race-free: a process can't fork
//! its way out of a `cgroup.kill` the way it could escape a loop that sends
//! `SIGKILL` PID by PID. Both are asynchronous; the kernel reports progress
//! in `cgroup.events` (`frozen`, `populated`), which we poll.

pub mod devices;
pub mod resources;
pub mod stats;

use std::collections::{BTreeMap, BTreeSet};
use std::os::fd::{AsFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use nix::fcntl::OFlag;
use nix::sys::stat::Mode;
use nix::unistd::Pid;
use rustlet_sys::Errno;
use rustlet_sys::fs::{fs_magic, magic};
use serde::{Deserialize, Serialize};

use crate::error::{Context, Error, Result, Unsupported};

pub use resources::settings_for;
pub use stats::{MemoryEvents, Stats};

/// Where the cgroup2 filesystem is mounted on the host.
pub const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// Controllers every container cgroup gets when the parent offers them,
/// whether or not `linux.resources` sets a limit: without them there is no
/// `memory.current`, `pids.current`, `io.stat` or `cpu.stat` usage breakdown
/// to report, and `memory.events` couldn't tell us about an OOM kill.
pub const DEFAULT_CONTROLLERS: [&str; 4] = ["cpu", "io", "memory", "pids"];

/// The xattr systemd sets on the root of a delegated subtree.
const DELEGATE_XATTR: &str = "trusted.delegate";

/// Marks a cgroup as a container's own (value: the container id). Container
/// cgroups must never nest: `cgroup.kill` and `populated` are recursive, so
/// deleting an outer container would kill an inner one. [`Cgroup::create`]
/// refuses to create below a tagged cgroup, and [`Cgroup::remove_tree`]
/// refuses to remove one.
const CONTAINER_XATTR: &str = "user.rustlet.container";

/// The container id a cgroup is tagged with, if any.
pub fn container_tag(path: &CgroupPath) -> Option<String> {
    rustlet_sys::xattr::lget(&path.host_path(), CONTAINER_XATTR).ok().map(|v| String::from_utf8_lossy(&v).into_owned())
}

/// How often [`Cgroup::freeze`], [`Cgroup::thaw`] and
/// [`Cgroup::wait_empty`] re-read `cgroup.events`.
const POLL_INTERVAL: Duration = Duration::from_millis(10);

/// One write of `value` into the file `file` of a cgroup directory, e.g.
/// `memory.max` ← `33554432`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Setting {
    pub file: String,
    pub value: String,
}

impl Setting {
    pub fn new(file: impl Into<String>, value: impl Into<String>) -> Setting {
        Setting { file: file.into(), value: value.into() }
    }

    /// The controller a file belongs to: `memory` for `memory.max`. Files
    /// of the cgroup core (`cgroup.max.depth`) give `cgroup`, which is not a
    /// controller and needs no enabling.
    pub fn controller(&self) -> &str {
        self.file.split('.').next().unwrap_or("")
    }
}

/// A validated cgroup path, relative to the cgroup2 root, e.g.
/// `/system.slice/rustlet-itest-1.scope/web`. Always absolute, lexically
/// clean (no `.`, `..`, empty or `:`-systemd-syntax components) and never
/// the root itself.
///
/// Deserializing goes through [`CgroupPath::parse`] too, so a tampered
/// state file can't smuggle in a `..`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct CgroupPath(PathBuf);

impl CgroupPath {
    /// Parses OCI `linux.cgroupsPath`. Only absolute paths are accepted
    /// (relative paths have runtime-defined meaning in the OCI spec; we
    /// define none). The systemd driver syntax `slice:prefix:name` is
    /// rejected as unsupported.
    pub fn parse(s: &str) -> Result<CgroupPath> {
        let bad = |why: &str| Error::invalid(format!("linux.cgroupsPath {s:?} {why}"));
        // runc's systemd driver reads `system.slice:rustlet:abc` as "unit
        // rustlet-abc.scope in system.slice"; that needs D-Bus.
        if s.contains(':') {
            return Err(Error::Unsupported(vec![Unsupported {
                field: format!("linux.cgroupsPath {s:?} (systemd `slice:prefix:name` syntax)"),
                when: "not planned",
            }]));
        }
        let Some(rest) = s.strip_prefix('/') else {
            return Err(bad("must be an absolute path (relative paths have no defined meaning in Rustlets)"));
        };
        if rest.is_empty() {
            return Err(bad("is the root cgroup, which belongs to the host"));
        }
        for c in rest.split('/') {
            match c {
                "" => return Err(bad("has an empty component (`//` or a trailing `/`)")),
                "." | ".." => return Err(bad("must not contain `.` or `..` components")),
                // The kernel refuses `\n` in cgroup names; NUL can't reach it.
                _ if c.contains(['\0', '\n']) => return Err(bad("contains a NUL or newline")),
                _ => {}
            }
        }
        Ok(CgroupPath(PathBuf::from(s)))
    }

    /// The path relative to the cgroup2 root, starting with `/`.
    pub fn as_path(&self) -> &Path {
        &self.0
    }

    /// The directory on the host: `/sys/fs/cgroup` + path.
    pub fn host_path(&self) -> PathBuf {
        Path::new(CGROUP_ROOT).join(self.0.strip_prefix("/").unwrap_or(&self.0))
    }

    /// The parent cgroup, or `None` for a top-level cgroup.
    pub fn parent(&self) -> Option<CgroupPath> {
        let p = self.0.parent()?;
        (p != Path::new("/")).then(|| CgroupPath(p.to_owned()))
    }

    /// Is `self` strictly below `ancestor`? (Component-wise: `/a/bc` is not
    /// below `/a/b`.)
    pub fn is_below(&self, ancestor: &CgroupPath) -> bool {
        self.0 != ancestor.0 && self.0.starts_with(&ancestor.0)
    }

    /// `self/name`, for a `name` that is one component of a valid path.
    fn child(&self, name: &std::ffi::OsStr) -> CgroupPath {
        CgroupPath(self.0.join(name))
    }
}

impl TryFrom<String> for CgroupPath {
    type Error = Error;
    fn try_from(s: String) -> Result<CgroupPath> {
        CgroupPath::parse(&s)
    }
}

impl std::fmt::Display for CgroupPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.display())
    }
}

/// The cgroup of the calling process (the `0::` line of `/proc/self/cgroup`).
///
/// Inside a cgroup namespace this is relative to the namespace's root (a
/// container sees `/`).
pub fn own_cgroup() -> Result<PathBuf> {
    let p = rustlet_sys::procfs::cgroup_path(None).context("read /proc/self/cgroup")?;
    Ok(PathBuf::from(p.trim()))
}

/// Decides where cgroups may be created. The seam for rootless mode
/// (Phase 8: systemd *user* scopes over D-Bus).
pub trait CgroupDriver {
    /// Returns the delegated root that `path` lies strictly below, or an
    /// error explaining why Rustlets must not create `path`.
    fn delegated_root(&self, path: &CgroupPath) -> Result<CgroupPath>;
}

/// Every directory below `dir` (child cgroups, recursively).
fn collect_children(dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            let p = entry.path();
            collect_children(&p, out)?;
            out.push(p);
        }
    }
    Ok(())
}

/// cgroups under a systemd-delegated subtree (`trusted.delegate="1"`).
///
/// Reading `trusted.*` xattrs needs `CAP_SYS_ADMIN`; without it the kernel
/// pretends they don't exist, so unprivileged callers are always refused.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemdDelegated;

impl CgroupDriver for SystemdDelegated {
    fn delegated_root(&self, path: &CgroupPath) -> Result<CgroupPath> {
        find_delegated_root(path, |c| {
            // Any error (ENODATA: not set; ENOENT: not created yet; or the
            // kernel hiding `trusted.*` from us) means "not delegated".
            rustlet_sys::xattr::lget(&c.host_path(), DELEGATE_XATTR).is_ok_and(|v| v == b"1")
        })
    }
}

/// Walks up from `path`'s *parent* to the nearest ancestor for which
/// `is_delegated` holds. Starting at the parent is what makes the result
/// *strictly* above `path`: the delegated cgroup itself belongs to the
/// unit (systemd put the unit's processes there), never to a container.
///
/// The xattr lookup is a parameter so the walk can be tested without root.
fn find_delegated_root(path: &CgroupPath, is_delegated: impl Fn(&CgroupPath) -> bool) -> Result<CgroupPath> {
    let mut cur = path.parent();
    while let Some(c) = cur {
        if is_delegated(&c) {
            return Ok(c);
        }
        cur = c.parent();
    }
    Err(Error::invalid(format!(
        "refusing to manage cgroup {path}: it is not inside a subtree that systemd delegated to us (no ancestor \
         carries the xattr {DELEGATE_XATTR}=1). Run under a unit with Delegate=yes (e.g. `systemd-run --scope -p \
         Delegate=yes …`, or rustletd.service) and put container cgroups below that unit's cgroup"
    )))
}

/// Checks that a cgroup file name is a single, plain component, so that
/// writing it can't reach outside the cgroup directory.
fn check_file_name(file: &str) -> Result<()> {
    if file.is_empty() || file == "." || file == ".." || file.contains(['/', '\0']) {
        return Err(Error::invalid(format!("{file:?} is not a cgroup file name")));
    }
    Ok(())
}

/// The errno behind an `io::Error`, if it came from the kernel.
fn errno_of(e: &std::io::Error) -> Option<Errno> {
    e.raw_os_error().map(Errno::from_raw)
}

/// Opens `dir` as a directory and checks that it is on cgroup2.
fn open_cgroup_dir(dir: &Path, what: &CgroupPath) -> Result<OwnedFd> {
    let fd = nix::fcntl::open(dir, OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC, Mode::empty())
        .with_context(|| format!("open cgroup {what} ({})", dir.display()))?;
    if fs_magic(fd.as_fd()).with_context(|| format!("fstatfs {}", dir.display()))? != magic::CGROUP2_SUPER_MAGIC {
        return Err(Error::invalid(format!(
            "{} is not on a cgroup2 filesystem (Rustlets needs the unified cgroup v2 hierarchy)",
            dir.display()
        )));
    }
    Ok(fd)
}

/// Writes `value` to a cgroup file with a single `write(2)`.
///
/// Not `std::fs::write`: that opens with `O_CREAT`, and since cgroupfs
/// doesn't let anyone create files, a missing file (controller not
/// enabled) would report a baffling `EACCES` instead of `ENOENT`. And one
/// `write` call matters: the kernel parses each write as a whole, so a
/// value split over two writes would be two (wrong) values.
fn write_file(path: &Path, value: &str) -> std::result::Result<(), Errno> {
    let fd = nix::fcntl::open(path, OFlag::O_WRONLY | OFlag::O_CLOEXEC, Mode::empty())?;
    let n = nix::unistd::write(&fd, value.as_bytes())?;
    // cgroupfs takes a value (up to a page) in one go or not at all.
    if n != value.len() {
        return Err(Errno::E2BIG);
    }
    Ok(())
}

/// A whitespace-separated word list (`cgroup.controllers`,
/// `cgroup.subtree_control`).
fn read_words(cg: &CgroupPath, file: &str) -> Result<BTreeSet<String>> {
    let text = std::fs::read_to_string(cg.host_path().join(file)).with_context(|| format!("read {cg}/{file}"))?;
    Ok(text.split_whitespace().map(str::to_owned).collect())
}

/// Step (2) of [`Cgroup::create`] for one level: makes sure the children of
/// `level` get the default controllers it offers plus every one in `needed`.
fn enable_controllers(level: &CgroupPath, needed: &BTreeSet<&str>) -> Result<()> {
    let available = read_words(level, "cgroup.controllers")?;
    if let Some(missing) = needed.iter().find(|c| !available.contains(**c)) {
        let offers = available.iter().map(String::as_str).collect::<Vec<_>>().join(" ");
        return Err(Error::Sys {
            context: format!(
                "the container's settings need the {missing} controller, but cgroup {level} doesn't offer it \
                 (it has: {offers}); the systemd unit must delegate it"
            ),
            errno: Errno::ENOENT,
        });
    }
    let enabled = read_words(level, "cgroup.subtree_control")?;
    let mut want: BTreeSet<&str> = DEFAULT_CONTROLLERS.into_iter().filter(|c| available.contains(*c)).collect();
    want.extend(needed);
    let add: Vec<String> = want.into_iter().filter(|c| !enabled.contains(*c)).map(|c| format!("+{c}")).collect();
    if add.is_empty() {
        return Ok(());
    }
    let line = add.join(" ");
    tracing::debug!(cgroup = %level, controllers = %line, "enabling controllers in cgroup.subtree_control");
    write_file(&level.host_path().join("cgroup.subtree_control"), &line).map_err(|errno| Error::Sys {
        context: match errno {
            Errno::EBUSY => format!(
                "enable {line} in {level}/cgroup.subtree_control: cgroup {level} contains processes, and cgroup \
                 v2's \"no internal processes\" rule lets a non-root cgroup either contain processes or enable \
                 controllers for its children, not both (move its processes into a leaf cgroup first)"
            ),
            _ => format!("enable {line} in {level}/cgroup.subtree_control"),
        },
        errno,
    })
}

/// A container's cgroup.
///
/// Only a handle: dropping it leaves the cgroup alone. Use [`kill`],
/// [`wait_empty`] and [`remove`] to get rid of it.
///
/// [`kill`]: Cgroup::kill
/// [`wait_empty`]: Cgroup::wait_empty
/// [`remove`]: Cgroup::remove
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cgroup {
    path: CgroupPath,
}

impl Cgroup {
    /// Creates the cgroup at `path` (which must not exist yet), after
    /// `driver` has approved it: creates missing intermediate cgroups below
    /// the delegated root, enables the controllers the container needs in
    /// every `cgroup.subtree_control` from the delegated root down to the
    /// parent (always `cpu memory pids` when available, plus whatever
    /// `settings` use), then applies `settings` in order. On failure it
    /// removes the cgroup it created (intermediates are left alone: others
    /// may share them).
    pub fn create(path: &CgroupPath, settings: &[Setting], driver: &dyn CgroupDriver) -> Result<Cgroup> {
        // (1) Everything that can be checked without touching the host first.
        let root = driver.delegated_root(path)?;
        if !path.is_below(&root) {
            return Err(Error::invalid(format!("cgroup driver returned {root} as the delegated root of {path}")));
        }
        for s in settings {
            check_file_name(&s.file)?;
        }
        open_cgroup_dir(&root.host_path(), &root)?;
        let leaf = path.host_path();
        match std::fs::symlink_metadata(&leaf) {
            Ok(_) => return Err(exists(path)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("stat cgroup {path}")),
        }

        // (2) Top-down from the delegated root to the parent. `cgroup` is
        // the core (`cgroup.max.depth`, …), not a controller.
        let needed: BTreeSet<&str> = settings.iter().map(Setting::controller).filter(|c| *c != "cgroup").collect();
        let below: Vec<_> = path.as_path().strip_prefix(root.as_path()).unwrap_or(Path::new("")).iter().collect();
        let (_, intermediates) = below.split_last().expect("path is strictly below root");
        // Never nest inside another container's cgroup (see CONTAINER_XATTR).
        let mut ancestor = root.clone();
        for name in intermediates {
            ancestor = ancestor.child(name);
            if let Some(owner) = container_tag(&ancestor) {
                return Err(Error::invalid(format!(
                    "cannot create cgroup {path}: {ancestor} belongs to container {owner:?}, and container cgroups can't be nested"
                )));
            }
        }
        let mut level = root;
        enable_controllers(&level, &needed)?;
        for name in intermediates {
            level = level.child(name);
            match nix::unistd::mkdir(&level.host_path(), Mode::from_bits_truncate(0o755)) {
                // EEXIST: it's there already, or someone created it
                // concurrently; either way we can use it.
                Ok(()) | Err(Errno::EEXIST) => {}
                Err(e) => return Err(e).with_context(|| format!("create intermediate cgroup {level}")),
            }
            enable_controllers(&level, &needed)?;
        }

        // (3) The container's own cgroup. EEXIST here means we lost a race
        // with another creator: it's theirs, so don't remove it.
        match nix::unistd::mkdir(&leaf, Mode::from_bits_truncate(0o755)) {
            Ok(()) => {}
            Err(Errno::EEXIST) => return Err(exists(path)),
            Err(e) => return Err(e).with_context(|| format!("create cgroup {path}")),
        }

        // (4) The limits. From here on, failure removes what we created.
        let cg = Cgroup { path: path.clone() };
        if let Err(e) = cg.apply(settings) {
            if let Err(rm) = std::fs::remove_dir(&leaf) {
                tracing::warn!(cgroup = %path, error = %rm, "could not remove cgroup after a failed create");
            }
            return Err(e);
        }
        Ok(cg)
    }

    /// Handle to an existing cgroup (for state/kill/delete); checks that the
    /// directory exists on cgroup2 and that it is strictly below a
    /// systemd-delegated root, like [`create`](Cgroup::create) does: a
    /// handle can freeze and kill, so it is never given out for cgroups
    /// that aren't ours to manage. Same as
    /// `open_with(path, &SystemdDelegated)`.
    pub fn open(path: &CgroupPath) -> Result<Cgroup> {
        Cgroup::open_with(path, &SystemdDelegated)
    }

    /// [`open`](Cgroup::open), with the delegation check done by `driver`.
    pub fn open_with(path: &CgroupPath, driver: &dyn CgroupDriver) -> Result<Cgroup> {
        let root = driver.delegated_root(path)?;
        if !path.is_below(&root) {
            return Err(Error::invalid(format!("cgroup driver returned {root} as the delegated root of {path}")));
        }
        open_cgroup_dir(&path.host_path(), path)?;
        Ok(Cgroup { path: path.clone() })
    }

    pub fn path(&self) -> &CgroupPath {
        &self.path
    }

    /// Tags this cgroup as container `id`'s own (see `CONTAINER_XATTR`).
    pub fn mark_container(&self, id: &str) -> Result<()> {
        rustlet_sys::xattr::lset(&self.path.host_path(), CONTAINER_XATTR, id.as_bytes())
            .with_context(|| format!("tag cgroup {} as container {id:?}", self.path))
    }

    /// The cgroup directory's inode number: its identity. A cgroup removed
    /// and re-created at the same path gets a new one, so a stale
    /// `state.json` can never act on someone else's cgroup.
    pub fn inode(&self) -> Result<u64> {
        use std::os::unix::fs::MetadataExt;
        Ok(std::fs::metadata(self.path.host_path()).with_context(|| format!("stat cgroup {}", self.path))?.ino())
    }

    /// Kills everything in the cgroup, waits for it to empty, then removes
    /// it together with any child cgroups (which only the container itself
    /// can have made, deepest first). Refuses if a descendant is tagged as
    /// another container's cgroup.
    pub fn remove_tree(&self, timeout: Duration) -> Result<()> {
        let mut dirs = Vec::new();
        collect_children(&self.path.host_path(), &mut dirs)
            .with_context(|| format!("list child cgroups of {}", self.path))?;
        for d in &dirs {
            if let Ok(tag) = rustlet_sys::xattr::lget(d, CONTAINER_XATTR) {
                return Err(Error::invalid(format!(
                    "refusing to remove cgroup {}: {} belongs to container {:?}",
                    self.path,
                    d.display(),
                    String::from_utf8_lossy(&tag)
                )));
            }
        }
        if self.is_populated()? {
            self.kill()?;
        }
        self.wait_empty(timeout)?;
        // Deepest first: a cgroup with children can't be removed.
        dirs.sort_by_key(|d| std::cmp::Reverse(d.components().count()));
        for d in dirs {
            match std::fs::remove_dir(&d) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e).with_context(|| format!("remove child cgroup {}", d.display())),
            }
        }
        self.remove()
    }

    /// The host path of one of the cgroup's files.
    fn file(&self, file: &str) -> Result<PathBuf> {
        check_file_name(file)?;
        Ok(self.path.host_path().join(file))
    }

    /// Writes `settings` (e.g. for a later `update`), in order. The error
    /// names the file, the value and, for the usual errnos, the likely cause.
    pub fn apply(&self, settings: &[Setting]) -> Result<()> {
        for s in settings {
            write_file(&self.file(&s.file)?, &s.value).map_err(|errno| Error::Sys {
                context: format!("write {:?} to {}/{}{}", s.value, self.path, s.file, write_hint(errno)),
                errno,
            })?;
        }
        Ok(())
    }

    /// Reads one file of the cgroup, trimmed.
    pub fn read(&self, file: &str) -> Result<String> {
        let text = std::fs::read_to_string(self.file(file)?).with_context(|| format!("read {}/{file}", self.path))?;
        Ok(text.trim().to_owned())
    }

    /// Like [`read`](Cgroup::read), but a file that doesn't exist (its
    /// controller isn't enabled, or the kernel is too old) is `None`. So is
    /// `EOPNOTSUPP`, which PSI files return when pressure accounting is off.
    fn read_optional(&self, file: &str) -> Result<Option<String>> {
        match std::fs::read_to_string(self.file(file)?) {
            Ok(text) => Ok(Some(text.trim().to_owned())),
            Err(e) if matches!(errno_of(&e), Some(Errno::ENOENT | Errno::EOPNOTSUPP)) => Ok(None),
            Err(e) => Err(e).with_context(|| format!("read {}/{file}", self.path)),
        }
    }

    /// An optional single-number file.
    fn read_u64(&self, file: &str) -> Result<Option<u64>> {
        let Some(text) = self.read_optional(file)? else { return Ok(None) };
        let n = text.parse().map_err(|_| {
            stats::invalid_data(format!("parse {}/{file}", self.path), format!("expected a number, got {text:?}"))
        })?;
        Ok(Some(n))
    }

    /// An optional number-or-`max` file; missing counts as `max`.
    fn read_max(&self, file: &str) -> Result<Option<u64>> {
        let Some(text) = self.read_optional(file)? else { return Ok(None) };
        stats::max_value(&text).ok_or_else(|| {
            stats::invalid_data(
                format!("parse {}/{file}", self.path),
                format!("expected a number or `max`, got {text:?}"),
            )
        })
    }

    /// An `O_RDONLY|O_DIRECTORY` fd for `clone3(CLONE_INTO_CGROUP)`: the
    /// child then *starts* in the cgroup, so there is no window in which
    /// the container runs unlimited, as there is with fork + write
    /// `cgroup.procs`.
    pub fn dir_fd(&self) -> Result<OwnedFd> {
        open_cgroup_dir(&self.path.host_path(), &self.path)
    }

    /// PIDs (host view) of every process in the cgroup (`cgroup.procs`).
    /// Only this cgroup's own processes, not its descendants'.
    pub fn procs(&self) -> Result<Vec<Pid>> {
        self.read("cgroup.procs")?
            .lines()
            .map(|l| {
                l.trim().parse().map(Pid::from_raw).map_err(|_| {
                    stats::invalid_data(format!("parse {}/cgroup.procs", self.path), format!("bad PID {l:?}"))
                })
            })
            .collect()
    }

    /// Moves process `pid` (all its threads) into this cgroup by writing
    /// it to `cgroup.procs`. Children it forks later start here too.
    pub fn add_process(&self, pid: Pid) -> Result<()> {
        self.apply(&[Setting::new("cgroup.procs", pid.to_string())])
    }

    /// `cgroup.events` as key → value (`populated`, `frozen`).
    fn events(&self) -> Result<BTreeMap<String, u64>> {
        Ok(stats::parse_flat_keyed(&self.read("cgroup.events")?))
    }

    /// `populated` from `cgroup.events`: does the cgroup (or a descendant)
    /// contain any live process?
    pub fn is_populated(&self) -> Result<bool> {
        Ok(self.events()?.get("populated").is_some_and(|&v| v != 0))
    }

    /// `cgroup.freeze` ← 1, then waits (up to `timeout`) for `frozen 1` in
    /// `cgroup.events`: freezing is asynchronous. On timeout the cgroup is
    /// left half-frozen; [`thaw`](Cgroup::thaw) or [`kill`](Cgroup::kill) it.
    pub fn freeze(&self, timeout: Duration) -> Result<()> {
        self.apply(&[Setting::new("cgroup.freeze", "1")])?;
        self.wait_until(timeout, "frozen", |cg| cg.is_frozen())
    }

    /// `cgroup.freeze` ← 0, then waits for `frozen 0`.
    pub fn thaw(&self, timeout: Duration) -> Result<()> {
        self.apply(&[Setting::new("cgroup.freeze", "0")])?;
        self.wait_until(timeout, "thawed", |cg| cg.is_frozen().map(|f| !f))
    }

    /// `frozen` from `cgroup.events`. Note that an empty cgroup with
    /// `cgroup.freeze` = 1 counts as frozen, and stays so after its last
    /// process died.
    pub fn is_frozen(&self) -> Result<bool> {
        Ok(self.events()?.get("frozen").is_some_and(|&v| v != 0))
    }

    /// `cgroup.kill` ← 1: SIGKILL to every process in the subtree at once
    /// (Linux 5.14), frozen or not. Asynchronous: follow with [`wait_empty`].
    ///
    /// [`wait_empty`]: Cgroup::wait_empty
    pub fn kill(&self) -> Result<()> {
        self.apply(&[Setting::new("cgroup.kill", "1")])
    }

    /// Waits (up to `timeout`) until `cgroup.events` says `populated 0`.
    /// A cgroup that no longer exists is empty, too.
    pub fn wait_empty(&self, timeout: Duration) -> Result<()> {
        self.wait_until(timeout, "empty", |cg| match cg.is_populated() {
            Ok(populated) => Ok(!populated),
            Err(e) if e.errno() == Some(Errno::ENOENT) => Ok(true),
            Err(e) => Err(e),
        })
    }

    /// Polls `done` every [`POLL_INTERVAL`] until it returns true, or fails
    /// with `ETIMEDOUT` after `timeout`. (inotify on `cgroup.events` would
    /// avoid the polling; for waits of a few milliseconds it isn't worth an
    /// fd and a second code path.)
    fn wait_until(&self, timeout: Duration, what: &str, mut done: impl FnMut(&Cgroup) -> Result<bool>) -> Result<()> {
        let deadline = Instant::now() + timeout;
        loop {
            if done(self)? {
                return Ok(());
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(Error::Sys {
                    context: format!("cgroup {} is not {what} after {timeout:?}", self.path),
                    errno: Errno::ETIMEDOUT,
                });
            }
            std::thread::sleep(POLL_INTERVAL.min(deadline - now));
        }
    }

    /// `rmdir`s the cgroup. Missing is fine; still populated is an error.
    ///
    /// Right after the last process exits, `rmdir` can briefly still say
    /// `EBUSY` while the kernel finishes tearing the task down (runc
    /// retries for the same reason), so an unpopulated cgroup gets a few
    /// retries. A cgroup with child cgroups fails after those.
    pub fn remove(&self) -> Result<()> {
        let dir = self.path.host_path();
        let mut retries = 10;
        loop {
            let e = match std::fs::remove_dir(&dir) {
                Ok(()) => return Ok(()),
                Err(e) => e,
            };
            match errno_of(&e) {
                Some(Errno::ENOENT) => return Ok(()),
                Some(Errno::EBUSY) if retries > 0 && self.is_populated().is_ok_and(|p| !p) => {
                    retries -= 1;
                    std::thread::sleep(POLL_INTERVAL);
                }
                Some(Errno::EBUSY) => {
                    return Err(e).with_context(|| {
                        format!(
                            "remove cgroup {}: still in use (it has processes or child cgroups; kill and wait_empty \
                             first)",
                            self.path
                        )
                    });
                }
                _ => return Err(e).with_context(|| format!("remove cgroup {}", self.path)),
            }
        }
    }

    /// Counters from `memory.events` (`oom_kill` > 0 means the OOM killer
    /// killed a process in this cgroup). Unlike [`stats`](Cgroup::stats)
    /// this fails if the memory controller isn't enabled: "no OOM kill"
    /// must not be reported when we can't know.
    pub fn memory_events(&self) -> Result<MemoryEvents> {
        Ok(stats::parse_memory_events(&self.read("memory.events")?))
    }

    /// Everything `rustlet-runc events --stats` reports, minus network
    /// counters (those come from a PID, see [`stats::net_dev`]).
    ///
    /// Only `cpu.stat` (which every cgroup has) is required; files of
    /// controllers that aren't enabled here, and optional files such as
    /// `memory.peak`, `memory.swap.current` or the PSI files, come back as
    /// 0, `None` or empty.
    pub fn stats(&self) -> Result<Stats> {
        let flat =
            |file: &str| self.read_optional(file).map(|t| t.map(|t| stats::parse_flat_keyed(&t)).unwrap_or_default());
        let mut pressure = BTreeMap::new();
        for resource in ["cpu", "memory", "io"] {
            if let Some(text) = self.read_optional(&format!("{resource}.pressure"))? {
                pressure.insert(resource.to_owned(), stats::parse_pressure(&text));
            }
        }
        Ok(Stats {
            cpu: stats::parse_flat_keyed(&self.read("cpu.stat")?),
            memory_current: self.read_u64("memory.current")?.unwrap_or(0),
            memory_max: self.read_max("memory.max")?,
            memory_peak: self.read_u64("memory.peak")?,
            swap_current: self.read_u64("memory.swap.current")?,
            memory_stat: flat("memory.stat")?,
            memory_events: stats::MemoryEvents::from_map(&flat("memory.events")?),
            pids_current: self.read_u64("pids.current")?.unwrap_or(0),
            pids_max: self.read_max("pids.max")?,
            io: self.read_optional("io.stat")?.map(|t| stats::parse_io_stat(&t)).unwrap_or_default(),
            pressure,
        })
    }
}

/// What an errno from writing a cgroup file usually means.
fn write_hint(errno: Errno) -> &'static str {
    match errno {
        Errno::ENOENT => " (no such file: its controller is not enabled for this cgroup, or the kernel lacks it)",
        Errno::EINVAL | Errno::ERANGE => " (the kernel rejected the value)",
        // Seen for per-device `io.weight` on a device without iocost.
        Errno::EOPNOTSUPP => " (not supported for this cgroup or device)",
        _ => "",
    }
}

fn exists(path: &CgroupPath) -> Error {
    Error::invalid(format!(
        "cgroup {path} already exists (another container, or a leftover: `scripts/cleanup.sh` removes those)"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> CgroupPath {
        CgroupPath::parse(s).unwrap()
    }

    #[test]
    fn parse_accepts_clean_absolute_paths() {
        let c = p("/system.slice/rustlet-itest-1.scope/web");
        assert_eq!(c.as_path(), Path::new("/system.slice/rustlet-itest-1.scope/web"));
        assert_eq!(c.host_path(), Path::new("/sys/fs/cgroup/system.slice/rustlet-itest-1.scope/web"));
        assert_eq!(c.to_string(), "/system.slice/rustlet-itest-1.scope/web");
        assert_eq!(p("/top").host_path(), Path::new("/sys/fs/cgroup/top"));
    }

    #[test]
    fn parse_rejects_unclean_paths() {
        for s in ["", "/", "web", "system.slice/web", "/a//b", "/a/", "/a/./b", "/a/../b", "/..", "/.", "/a\nb"] {
            match CgroupPath::parse(s) {
                Err(Error::InvalidSpec(msg)) => assert!(msg.contains("cgroupsPath"), "{s:?}: {msg}"),
                other => panic!("{s:?} gave {other:?}"),
            }
        }
    }

    #[test]
    fn parse_rejects_systemd_syntax_as_unsupported() {
        for s in ["system.slice:rustlet:abc", "/a:b"] {
            match CgroupPath::parse(s) {
                Err(Error::Unsupported(u)) => {
                    assert_eq!(u.len(), 1);
                    assert!(u[0].field.contains("slice:prefix:name"), "{}", u[0].field);
                    assert_eq!(u[0].when, "not planned");
                }
                other => panic!("{s:?} gave {other:?}"),
            }
        }
    }

    #[test]
    fn parent_and_is_below() {
        let c = p("/a/b/c");
        assert_eq!(c.parent(), Some(p("/a/b")));
        assert_eq!(p("/a").parent(), None);
        assert!(c.is_below(&p("/a")) && c.is_below(&p("/a/b")));
        assert!(!c.is_below(&c));
        assert!(!p("/a/bc").is_below(&p("/a/b")));
    }

    #[test]
    fn serde_round_trip_validates() {
        let c = p("/system.slice/x.scope/web");
        let json = serde_json::to_string(&c).unwrap();
        assert_eq!(json, "\"/system.slice/x.scope/web\"");
        assert_eq!(serde_json::from_str::<CgroupPath>(&json).unwrap(), c);
        for bad in ["\"/a/../../etc\"", "\"relative\"", "\"/\""] {
            assert!(serde_json::from_str::<CgroupPath>(bad).is_err(), "{bad} deserialized");
        }
    }

    #[test]
    fn setting_controller() {
        assert_eq!(Setting::new("memory.max", "1").controller(), "memory");
        assert_eq!(Setting::new("cpu.max.burst", "1").controller(), "cpu");
        assert_eq!(Setting::new("cgroup.max.depth", "1").controller(), "cgroup");
    }

    #[test]
    fn file_names_must_be_one_component() {
        for ok in ["memory.max", "cgroup.procs"] {
            check_file_name(ok).unwrap();
        }
        for bad in ["", ".", "..", "../memory.max", "a/b", "/etc/passwd", "a\0b"] {
            assert!(check_file_name(bad).is_err(), "{bad:?}");
        }
    }

    /// A fake xattr lookup: exactly these cgroups carry `trusted.delegate=1`.
    fn delegated<'a>(roots: &'a [&'a str]) -> impl Fn(&CgroupPath) -> bool + 'a {
        move |c| roots.iter().any(|r| c.as_path() == Path::new(r))
    }

    #[test]
    fn delegated_root_is_the_nearest_marked_ancestor() {
        let scope = "/system.slice/rustlet-itest-1.scope";
        assert_eq!(find_delegated_root(&p(&format!("{scope}/web")), delegated(&[scope])).unwrap(), p(scope));
        // Intermediates in between don't need the mark (and may not exist yet).
        let svc = "/system.slice/rustletd.service";
        assert_eq!(find_delegated_root(&p(&format!("{svc}/containers/abc")), delegated(&[svc])).unwrap(), p(svc));
        // Nested delegation: the nearest one wins.
        let r = find_delegated_root(&p("/a/b/c"), delegated(&["/a", "/a/b"])).unwrap();
        assert_eq!(r, p("/a/b"));
    }

    #[test]
    fn delegated_root_must_be_strictly_above() {
        let scope = "/system.slice/rustlet-itest-1.scope";
        // The delegated cgroup itself is the unit's, not a container's.
        let e = find_delegated_root(&p(scope), delegated(&[scope])).unwrap_err().to_string();
        assert!(e.contains("delegat") && e.contains("Delegate=yes"), "{e}");
        // Nothing marked at all, and a top-level cgroup (no parent to check).
        assert!(find_delegated_root(&p("/system.slice/web"), delegated(&[])).is_err());
        assert!(find_delegated_root(&p("/web"), delegated(&["/web"])).is_err());
    }

    #[test]
    fn delegated_root_walk_asks_parents_only() {
        let asked = std::cell::RefCell::new(Vec::new());
        let r = find_delegated_root(&p("/a/b/c"), |c| {
            asked.borrow_mut().push(c.to_string());
            false
        });
        assert!(r.is_err());
        assert_eq!(*asked.borrow(), ["/a/b", "/a"]);
    }

    #[test]
    fn systemd_driver_refuses_undelegated_paths() {
        // Nothing under this name exists, so no xattr can be found; this also
        // holds unprivileged, where trusted.* is invisible anyway.
        let e = SystemdDelegated.delegated_root(&p("/rustlet-unit-test-nonexistent/web")).unwrap_err();
        assert!(e.to_string().contains("Delegate=yes"), "{e}");
    }

    /// A driver that approves whatever root it was built with.
    struct Approve(&'static str);
    impl CgroupDriver for Approve {
        fn delegated_root(&self, _: &CgroupPath) -> Result<CgroupPath> {
            CgroupPath::parse(self.0)
        }
    }

    #[test]
    fn create_checks_the_driver_answer_before_touching_anything() {
        // A (buggy) driver whose "root" isn't above the path is not trusted.
        for root in ["/elsewhere", "/rustlet-unit-test/web"] {
            let e = Cgroup::create(&p("/rustlet-unit-test/web"), &[], &Approve(root)).unwrap_err();
            assert!(e.to_string().contains("delegated root"), "{e}");
        }
        let e = Cgroup::open_with(&p("/rustlet-unit-test/web"), &Approve("/elsewhere")).unwrap_err();
        assert!(e.to_string().contains("delegated root"), "{e}");
        // Settings that would write outside the cgroup directory.
        let bad = [Setting::new("../cgroup.procs", "1")];
        let e = Cgroup::create(&p("/rustlet-unit-test/web"), &bad, &Approve("/rustlet-unit-test")).unwrap_err();
        assert!(e.to_string().contains("not a cgroup file name"), "{e}");
    }

    #[test]
    fn own_cgroup_is_absolute() {
        assert!(own_cgroup().unwrap().is_absolute());
    }
}

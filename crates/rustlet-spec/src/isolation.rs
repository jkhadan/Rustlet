//! `GET /v1/containers/{id}/isolation`: what separates a running container
//! from the host, read from the kernel and from the `config.json` its run
//! was started with. The desktop app's isolation inspector shows it.
//!
//! - **Namespaces:** the inode of each of the init's namespaces
//!   (`readlink /proc/<pid>/ns/net` is `net:[4026532341]`), compared with
//!   the daemon's own, which are the host's, and with the other running
//!   containers'. Two processes are in the same namespace exactly when the
//!   inodes match.
//! - **User namespace:** its `uid_map` and `gid_map`, and the init's ids as
//!   the container and as the host see them.
//! - **Privileges:** the five capability sets (`/proc/<pid>/status`),
//!   `no_new_privs`, the seccomp mode and the profile it was given.
//! - **Filesystem and devices:** the root filesystem, masked and read-only
//!   paths, the mounts, the rules of the cgroup's eBPF device filter.
//! - **Cgroup:** its limits beside its usage.
//!
//! Only a running (or paused) container has a process to read; for any
//! other the request is a conflict.

use serde::{Deserialize, Serialize};
use ts_rs::TS;

/// The kinds of namespace, in the order the report lists them.
pub const NAMESPACE_KINDS: [&str; 8] = ["mnt", "uts", "ipc", "pid", "net", "cgroup", "user", "time"];

/// The report.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, TS)]
#[serde(default)]
pub struct Isolation {
    pub id: String,
    pub name: String,
    /// Host PID of the container's init.
    pub pid: i32,
    /// One per kind, in [`NAMESPACE_KINDS`] order.
    pub namespaces: Vec<Namespace>,
    /// Its user namespace's `uid_map`, a mapping per line; empty when it has
    /// no user namespace of its own (its ids are the host's).
    pub uid_map: Vec<IdMapping>,
    pub gid_map: Vec<IdMapping>,
    pub credentials: Credentials,
    pub capabilities: Capabilities,
    pub seccomp: Seccomp,
    pub filesystem: Filesystem,
    /// The rules of the cgroup's eBPF device filter, in order: the
    /// configuration's, the runtime's defaults, `m` for the nodes init
    /// creates. Each access (read, write, mknod) of a device is decided by
    /// the last rule that matches it and names that access; one no rule
    /// names is refused.
    pub devices: Vec<DeviceRule>,
    pub cgroup: CgroupUsage,
    /// `/proc/<pid>/oom_score_adj`.
    pub oom_score_adj: i32,
}

/// One namespace of the init.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(default)]
pub struct Namespace {
    /// `mnt`, `uts`, `ipc`, `pid`, `net`, `cgroup`, `user` or `time`.
    pub kind: String,
    /// What `config.json` asked the runtime for.
    pub mode: NamespaceMode,
    /// With [`NamespaceMode::Join`]: the namespace file it joined (a pinned
    /// network namespace, say).
    pub path: Option<String>,
    /// The namespace's inode.
    pub inode: u64,
    /// The inode of the daemon's namespace of this kind: the host's.
    pub host_inode: u64,
    /// `inode == host_inode`.
    pub shared_with_host: bool,
    /// The other running containers in the same namespace (names).
    pub shared_with: Vec<String>,
}

/// How a namespace came to be.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
pub enum NamespaceMode {
    /// A new one, made for the container (`clone3`/`unshare`).
    #[default]
    New,
    /// An existing one, joined (`setns`): `config.json` names its file.
    Join,
    /// None asked for: the runtime's own, which is the host's.
    Host,
}

/// A line of `uid_map`/`gid_map`: ids `container_id..container_id+size`
/// inside are `host_id..host_id+size` outside.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(default)]
pub struct IdMapping {
    pub container_id: u32,
    pub host_id: u32,
    pub size: u32,
}

/// Who the init process is.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(default)]
pub struct Credentials {
    /// Its effective user and group and its supplementary groups now, as
    /// the container sees them: the host's ids mapped back through
    /// `uid_map`/`gid_map` (an id the maps don't cover is 65534). Usually
    /// the user `config.json` started it as, unless it has changed its ids
    /// since (an entrypoint that drops to another user with `su-exec`, say).
    pub uid: u32,
    pub gid: u32,
    pub additional_gids: Vec<u32>,
    /// Its effective ids as the host sees them (`/proc/<pid>/status`): the
    /// same as `uid`/`gid` without a user namespace, mapped with one.
    pub host_uid: u32,
    pub host_gid: u32,
}

/// The init's capability sets, by name (`CAP_CHOWN`, …), from
/// `/proc/<pid>/status`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(default)]
pub struct Capabilities {
    /// What the kernel checks now.
    pub effective: Vec<String>,
    /// The ceiling of `effective`.
    pub permitted: Vec<String>,
    /// What may survive an `execve` (with file or ambient capabilities).
    pub inheritable: Vec<String>,
    /// The ceiling of anything the process or its children can ever gain.
    pub bounding: Vec<String>,
    /// What survives an `execve` of an ordinary binary.
    pub ambient: Vec<String>,
    /// Every capability this kernel knows, in number order, so that the
    /// missing ones can be shown too.
    pub known: Vec<String>,
}

/// Seccomp, as the kernel enforces it and as it was configured.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(default)]
pub struct Seccomp {
    /// `Seccomp:` in `/proc/<pid>/status`.
    pub mode: SeccompMode,
    /// `Seccomp_filters:`: how many filters are attached.
    pub filters: u32,
    /// `NoNewPrivs:`: no `execve` can raise its privileges (setuid bits
    /// and file capabilities are ignored). Unprivileged processes need it to
    /// install a filter.
    pub no_new_privs: bool,
    /// The profile in `config.json`; `None` with `seccomp=unconfined` or
    /// `--privileged`.
    pub profile: Option<SeccompProfile>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
pub enum SeccompMode {
    /// No filter: every system call reaches the kernel.
    #[default]
    Disabled,
    /// `SECCOMP_MODE_STRICT`: only `read`, `write`, `_exit` and
    /// `sigreturn`.
    Strict,
    /// `SECCOMP_MODE_FILTER`: BPF programs decide per call.
    Filter,
}

/// A summary of an OCI seccomp profile.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(default)]
pub struct SeccompProfile {
    /// What happens to a call no rule names (`SCMP_ACT_ERRNO`, …).
    pub default_action: String,
    /// The errno of an `SCMP_ACT_ERRNO` default (`EPERM` is 1).
    pub default_errno: Option<u32>,
    pub architectures: Vec<String>,
    /// Calls allowed whatever their arguments, sorted.
    pub allowed: Vec<String>,
    /// Calls allowed only with certain arguments (`clone` without namespace
    /// flags, `personality` with a few values), sorted.
    pub conditional: Vec<String>,
    /// Rules with an action other than allow.
    pub other: Vec<SeccompRule>,
}

/// A rule of a seccomp profile.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(default)]
pub struct SeccompRule {
    pub names: Vec<String>,
    pub action: String,
    pub errno: Option<u32>,
    /// Some of its conditions are on the arguments.
    pub conditional: bool,
}

/// The container's filesystem view, from `config.json`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(default)]
pub struct Filesystem {
    /// The root filesystem on the host (the overlay's merged directory).
    pub rootfs: String,
    pub read_only: bool,
    /// Paths covered (a file by `/dev/null`, a directory by an empty
    /// read-only tmpfs), so their contents can't be read.
    pub masked_paths: Vec<String>,
    /// Paths remounted read-only.
    pub readonly_paths: Vec<String>,
    /// The mounts in the order the runtime makes them.
    pub mounts: Vec<MountEntry>,
}

/// One mount of `config.json`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(default)]
pub struct MountEntry {
    pub destination: String,
    /// `proc`, `tmpfs`, `bind`, …
    pub kind: String,
    pub source: String,
    pub options: Vec<String>,
}

/// One rule of the device filter.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(default)]
pub struct DeviceRule {
    pub allow: bool,
    /// `c` (character), `b` (block) or `a` (all).
    pub kind: String,
    /// `None`: any.
    pub major: Option<u32>,
    pub minor: Option<u32>,
    /// Some of `r` (read), `w` (write), `m` (mknod).
    pub access: String,
    pub origin: DeviceRuleOrigin,
}

/// Where a device rule comes from.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
pub enum DeviceRuleOrigin {
    /// `linux.resources.devices` of `config.json` (`--device`,
    /// `--privileged`).
    #[default]
    Config,
    /// The runtime's own, after the configuration's: `/dev/null`, `zero`,
    /// `full`, `random`, `urandom`, `tty`, `/dev/ptmx` and the pty slaves.
    Default,
    /// `m` for a node of `linux.devices` that init creates.
    Node,
}

/// The cgroup's limits beside its usage. `None` for a limit means `max`
/// (none).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(default)]
pub struct CgroupUsage {
    /// Below `/sys/fs/cgroup`.
    pub path: String,
    pub memory_current: u64,
    pub memory_max: Option<u64>,
    pub swap_current: Option<u64>,
    pub swap_max: Option<u64>,
    pub pids_current: u64,
    pub pids_max: Option<u64>,
    /// `cpu.max`: at most `cpu_quota` microseconds of CPU time per
    /// `cpu_period` microseconds (`--cpus 1.5` is 150000 per 100000).
    pub cpu_quota: Option<u64>,
    pub cpu_period: u64,
    /// `cpu.weight` (1–10000, 100 by default): its share when CPUs are
    /// contended.
    pub cpu_weight: Option<u64>,
    /// `cpu.stat` `usage_usec`.
    pub cpu_usage_usec: u64,
    /// `memory.events` `oom_kill`.
    pub oom_kills: u64,
}

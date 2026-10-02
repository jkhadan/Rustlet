//! Containers: what `create` takes, what `ps` and `inspect` show.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

use crate::network::{NetworkMode, NetworkSettings, PortMapping, PublishedPort};
use crate::volume::{MountPoint, MountSpec};

/// `POST /v1/containers`: everything `rustlet run`/`create` can say about a
/// container. Fields left out take the image's value (command, environment,
/// user, working directory) or Rustlets' default.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ContainerConfig {
    /// The image, as typed (`alpine`, `nginx:1.27`, `ghcr.io/o/n@sha256:…`).
    pub image: String,
    /// A unique name ([`crate::valid_container_name`]); one is generated
    /// if absent.
    pub name: Option<String>,
    /// Replaces the image's `Cmd` (`IMAGE ARGS…`).
    pub cmd: Vec<String>,
    /// Replaces the image's `Entrypoint`; `Some([])` clears it.
    pub entrypoint: Option<Vec<String>>,
    /// `KEY=VALUE`, over the image's `Env`.
    pub env: Vec<String>,
    /// `user[:group]`, names or ids from the image's `/etc/passwd` and
    /// `/etc/group`.
    pub user: Option<String>,
    pub workdir: Option<String>,
    /// Default: the short id.
    pub hostname: Option<String>,
    /// `-t`: a PTY for the container.
    pub tty: bool,
    /// `-i`: keep the container's stdin open for attach clients.
    pub open_stdin: bool,
    /// Close the container's stdin once the first attached client's input
    /// ends (`run -i`, as Docker's `StdinOnce`).
    pub stdin_once: bool,
    pub labels: BTreeMap<String, String>,
    /// `--read-only`: the root filesystem is mounted read-only.
    pub read_only: bool,
    pub userns: UsernsMode,
    /// `--memory`, bytes. Swap on top is not allowed (the memory+swap limit
    /// is the same value).
    pub memory: Option<u64>,
    /// `--cpus`: CPU time, in CPUs (`1.5`).
    pub cpus: Option<f64>,
    /// `--pids-limit`; `0` or negative means unlimited.
    pub pids_limit: Option<i64>,
    pub restart: RestartPolicy,
    /// `--rm`: remove the container once it has exited (not with a restart
    /// policy other than `no`).
    pub auto_remove: bool,
    /// Signal for `stop` (`SIGTERM`, `TERM` or `15`): the image's
    /// `StopSignal`, else `SIGTERM`.
    pub stop_signal: Option<String>,
    /// Seconds `stop` waits before killing; default 10.
    pub stop_timeout: Option<u32>,
    /// Capability names (`NET_ADMIN`, `CAP_NET_ADMIN`, or `ALL`) to add to
    /// and drop from the default set.
    pub cap_add: Vec<String>,
    pub cap_drop: Vec<String>,
    /// `--privileged`: all capabilities, all host devices, no seccomp, no
    /// masked paths. Not isolation from host root.
    pub privileged: bool,
    /// `--security-opt`: `seccomp=unconfined`, `no-new-privileges[=true|false]`.
    pub security_opt: Vec<String>,
    /// `--device HOST[:CONTAINER[:rwm]]`: a host device node, with access.
    pub devices: Vec<String>,
    /// `--network`: the default network unless given.
    pub network: NetworkMode,
    /// `--network-alias`: more names the embedded DNS server answers for
    /// it, on its (first, user-defined) network.
    pub network_aliases: Vec<String>,
    /// `--ip`: its IPv4 address on its first network (a user-defined one);
    /// default: the next free.
    pub ip: Option<Ipv4Addr>,
    /// `--ip6`: its IPv6 address there (a network with IPv6).
    pub ip6: Option<Ipv6Addr>,
    /// `--network` given again: more networks to connect it to, in order
    /// after the first, with no aliases or addresses of their own (`network
    /// connect` gives those). Only with a bridge network as the first.
    pub extra_networks: Vec<String>,
    /// `-p`: container ports to publish on the host.
    pub ports: Vec<PortMapping>,
    /// `-P`: publish every port the image exposes, each on a free host
    /// port.
    pub publish_all: bool,
    /// `--dns`: name servers for the container's `resolv.conf` (or for the
    /// embedded DNS server to forward to), instead of the host's.
    pub dns: Vec<String>,
    /// `--dns-search`, `--dns-option`: the rest of `resolv.conf`.
    pub dns_search: Vec<String>,
    pub dns_options: Vec<String>,
    /// `--add-host NAME:IP` lines for its `/etc/hosts` (the IP may be
    /// `host-gateway`, [`crate::network::HOST_GATEWAY`]).
    pub extra_hosts: Vec<String>,
    /// `-v`, `--mount`, `--tmpfs`.
    pub mounts: Vec<MountSpec>,
}

/// `--userns`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UsernsMode {
    /// No user namespace: container root is host root (the rootful default).
    #[default]
    Host,
    /// A user namespace in which container ids 0–65535 are host ids
    /// 1000000–1065535.
    Remap,
}

/// When a container that has exited is started again.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RestartPolicy {
    pub name: RestartPolicyName,
    /// For `on-failure`: give up after this many restarts (0 = never).
    pub max_retries: u32,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RestartPolicyName {
    #[default]
    No,
    /// Whenever it exits, unless it was stopped by `stop`/`kill`; and when
    /// the daemon starts (even after such a stop).
    Always,
    /// Like `always`, except that a container stopped by hand stays stopped
    /// when the daemon starts.
    UnlessStopped,
    /// Only when it exits with a non-zero status.
    OnFailure,
}

impl RestartPolicy {
    /// Parses Docker's syntax: `no`, `always`, `unless-stopped`,
    /// `on-failure` or `on-failure:N`.
    pub fn parse(s: &str) -> Result<RestartPolicy, String> {
        let (name, count) = match s.split_once(':') {
            Some((n, c)) => (n, Some(c)),
            None => (s, None),
        };
        let name = match name {
            "no" | "" => RestartPolicyName::No,
            "always" => RestartPolicyName::Always,
            "unless-stopped" => RestartPolicyName::UnlessStopped,
            "on-failure" => RestartPolicyName::OnFailure,
            other => {
                return Err(format!(
                    "unknown restart policy {other:?} (no, always, unless-stopped, on-failure[:max-retries])"
                ));
            }
        };
        let max_retries = match count {
            None => 0,
            Some(_) if name != RestartPolicyName::OnFailure => {
                return Err(format!("restart policy {s:?}: only on-failure takes a maximum retry count"));
            }
            Some(c) => c.parse().map_err(|_| format!("restart policy {s:?}: {c:?} is not a retry count"))?,
        };
        Ok(RestartPolicy { name, max_retries })
    }
}

impl std::fmt::Display for RestartPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (self.name, self.max_retries) {
            (RestartPolicyName::No, _) => f.write_str("no"),
            (RestartPolicyName::Always, _) => f.write_str("always"),
            (RestartPolicyName::UnlessStopped, _) => f.write_str("unless-stopped"),
            (RestartPolicyName::OnFailure, 0) => f.write_str("on-failure"),
            (RestartPolicyName::OnFailure, n) => write!(f, "on-failure:{n}"),
        }
    }
}

/// `201` from `POST /v1/containers`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CreateResponse {
    pub id: String,
    pub name: String,
    pub warnings: Vec<String>,
}

/// A container's lifecycle state.
///
/// ```text
///  created ──start──► running ⇄ paused
///     ▲                  │ exits (or is stopped/killed)
///     │                  ▼
///     │   start      exited ──(restart policy)──► restarting ──► running
///     └───────────────── │
///                        ▼ rm
///                     removing ──► (gone)
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainerStatus {
    /// Created and never started.
    #[default]
    Created,
    Running,
    Paused,
    /// Exited, waiting for the restart policy's delay to pass.
    Restarting,
    Exited,
    /// `rm` is in progress.
    Removing,
    /// Something went wrong that the daemon couldn't clean up; `rm -f`
    /// tries again.
    Dead,
}

impl ContainerStatus {
    /// Running or paused: the container's processes exist.
    pub fn is_live(self) -> bool {
        matches!(self, ContainerStatus::Running | ContainerStatus::Paused)
    }
}

impl std::fmt::Display for ContainerStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ContainerStatus::Created => "created",
            ContainerStatus::Running => "running",
            ContainerStatus::Paused => "paused",
            ContainerStatus::Restarting => "restarting",
            ContainerStatus::Exited => "exited",
            ContainerStatus::Removing => "removing",
            ContainerStatus::Dead => "dead",
        };
        f.pad(s)
    }
}

/// The part of a container that changes as it runs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ContainerState {
    pub status: ContainerStatus,
    /// Host PID of the container's init, while it is live.
    pub pid: Option<i32>,
    /// The last exit status, shell-style (128 + signal for a signal).
    pub exit_code: Option<i32>,
    /// The kernel's OOM killer killed a process of the container during
    /// its last run.
    pub oom_killed: bool,
    /// Why the last start failed or the last run ended abnormally.
    pub error: Option<String>,
    /// RFC 3339, UTC.
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    /// Restarts by the restart policy since the last `start`/`restart`.
    pub restart_count: u32,
}

/// One line of `rustlet ps`: `GET /v1/containers`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ContainerSummary {
    pub id: String,
    pub name: String,
    /// As given at create.
    pub image: String,
    /// The image's manifest digest (`sha256:…`).
    pub image_id: String,
    /// What runs: entrypoint + command, resolved against the image.
    pub command: Vec<String>,
    /// RFC 3339, UTC.
    pub created: String,
    pub state: ContainerState,
    pub labels: BTreeMap<String, String>,
    /// While it runs: its published ports.
    pub ports: Vec<PublishedPort>,
}

/// `GET /v1/containers/{id}`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ContainerInspect {
    pub id: String,
    pub name: String,
    pub created: String,
    pub image: String,
    pub image_id: String,
    pub command: Vec<String>,
    /// What it was created with.
    pub config: ContainerConfig,
    pub state: ContainerState,
    pub hostname: String,
    /// The merged root filesystem on the host, while it is mounted (the
    /// container is live).
    pub rootfs: Option<String>,
    /// The container directory: rootfs, upper (its writable layer), logs.
    pub dir: String,
    pub log_path: String,
    /// Its cgroup, as a path below `/sys/fs/cgroup`.
    pub cgroup: String,
    /// `uid_map` of its user namespace (`0 1000000 65536`), if it has one.
    pub uid_map: Option<String>,
    pub network: NetworkSettings,
    /// Its volumes, bind mounts and tmpfs mounts.
    pub mounts: Vec<MountPoint>,
}

/// `POST /v1/containers/{id}/wait?condition=`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WaitCondition {
    /// Return at once if the container isn't live, else when it exits
    /// (Docker's default).
    #[default]
    NotRunning,
    /// Wait for the next exit, even if it isn't running now (`run`
    /// waits like this before `start`).
    NextExit,
    /// Wait until the container is removed (`run --rm`), or dead: its
    /// removal (or the cleanup after its exit) failed, and `error` says why.
    Removed,
}

/// The answer of `wait`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct WaitResponse {
    /// Shell-style exit status.
    pub status_code: i32,
    pub oom_killed: bool,
    pub error: Option<String>,
}

/// Query of `GET /v1/containers`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ListQuery {
    /// Include containers that aren't running.
    pub all: bool,
}

/// Query of `DELETE /v1/containers/{id}`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RemoveQuery {
    /// Kill it first if it is live.
    pub force: bool,
    /// Remove its anonymous volumes too (`rm -v`).
    pub volumes: bool,
}

/// Query of `stop` and `restart`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct StopQuery {
    /// Seconds to wait after the stop signal before killing.
    pub timeout: Option<u32>,
}

/// Query of `kill`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct KillQuery {
    /// `KILL`, `SIGKILL` or `9`; default `KILL`.
    pub signal: Option<String>,
}

/// Query of `wait`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct WaitQuery {
    pub condition: WaitCondition,
}

/// Query of `attach`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AttachQuery {
    /// Send this client's input to the container (it must have been
    /// created with `open_stdin`).
    pub stdin: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restart_policies_parse_like_docker() {
        let p = |s| RestartPolicy::parse(s).unwrap();
        assert_eq!(p("no"), RestartPolicy::default());
        assert_eq!(p("always").name, RestartPolicyName::Always);
        assert_eq!(p("unless-stopped").name, RestartPolicyName::UnlessStopped);
        assert_eq!(p("on-failure"), RestartPolicy { name: RestartPolicyName::OnFailure, max_retries: 0 });
        assert_eq!(p("on-failure:3"), RestartPolicy { name: RestartPolicyName::OnFailure, max_retries: 3 });
        for bad in ["sometimes", "always:3", "on-failure:x", "on-failure:-1"] {
            assert!(RestartPolicy::parse(bad).is_err(), "{bad}");
        }
        for s in ["no", "always", "unless-stopped", "on-failure", "on-failure:5"] {
            assert_eq!(p(s).to_string(), s);
        }
    }

    #[test]
    fn config_takes_defaults_for_missing_fields() {
        let c: ContainerConfig = serde_json::from_str(r#"{"image":"alpine","restart":{"name":"on-failure"}}"#).unwrap();
        assert_eq!(c.image, "alpine");
        assert!(c.cmd.is_empty() && !c.tty && c.userns == UsernsMode::Host);
        assert_eq!(c.restart.name, RestartPolicyName::OnFailure);
        let json = serde_json::to_value(&c).unwrap();
        assert_eq!(json["restart"]["name"], "on-failure");
        assert_eq!(json["userns"], "host");
    }

    #[test]
    fn wait_conditions_are_kebab_case() {
        let q: WaitQuery = serde_json::from_str(r#"{"condition":"next-exit"}"#).unwrap();
        assert_eq!(q.condition, WaitCondition::NextExit);
        assert_eq!(serde_json::to_value(WaitCondition::NotRunning).unwrap(), "not-running");
    }
}

//! The daemon's settings: `/etc/rustlet/daemon.toml` (optional), then the
//! command line on top.
//!
//! ```toml
//! # /etc/rustlet/daemon.toml: every key is optional
//! socket = "/run/rustlet/rustlet.sock"
//! socket_group = "rustlet"        # 0660 root:rustlet if the group exists, else 0600
//! data_root = "/var/lib/rustlet"
//! run_root = "/run/rustlet"
//! cgroup_parent = "/system.slice/rustletd.service"   # default: the parent of our own cgroup
//! log_max_size = 10485760         # per container log file
//! log_max_files = 3
//! worker_memory_max = 1073741824  # pulls and unpacks run in a child limited to this
//! default_subnet = "10.89.0.0/24" # the `bridge` network, on default_bridge
//! network_pool = "10.89.0.0/16"   # user-defined networks get /24s from here
//! network_pool_v6 = "fd52:…::/48" # IPv6 networks get /64s; default: a ULA /48 from the machine id
//! default_bridge = "rustlet0"
//! nft_table = "rustlet"           # inet rustlet
//! resolv_conf = "/etc/resolv.conf" # the host's (systemd-resolved's real list replaces its stub)
//! manage_ufw = true               # keep ufw's route rules for the bridges, if ufw is installed
//! ```

use std::path::{Path, PathBuf};

use serde::Deserialize;

/// The default configuration file.
pub const CONFIG_FILE: &str = "/etc/rustlet/daemon.toml";

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub socket: PathBuf,
    /// The group that may use the socket. Membership is root-equivalent:
    /// whoever can create containers can mount the host's `/` into one.
    pub socket_group: Option<String>,
    pub data_root: PathBuf,
    pub run_root: PathBuf,
    /// Where `daemon`, `shims`, `workers/<n>` and `containers/<id>` cgroups
    /// go: a cgroup systemd delegated to us (a path below `/sys/fs/cgroup`).
    pub cgroup_parent: Option<String>,
    /// `rustlet-runc` and `rustlet-shim`; default: next to `rustletd`.
    pub runtime: Option<PathBuf>,
    pub shim: Option<PathBuf>,
    pub log_max_size: u64,
    pub log_max_files: u32,
    /// Limits of the child process a pull or unpack runs in.
    pub worker_memory_max: u64,
    pub worker_pids_max: u64,
    /// Registries (`host[:port]`) to pull from over plain HTTP.
    pub insecure_registries: Vec<String>,
    /// Make `containers/` a private bind mount of itself at startup, so the
    /// containers' overlay mounts don't propagate into other mount
    /// namespaces.
    pub private_containers_mount: bool,
    /// The default network's subnet; its first address is the bridge's.
    pub default_subnet: String,
    /// Where user-defined networks get a subnet when not given one.
    pub network_pool: String,
    /// Where networks created with `--ipv6` get an IPv6 subnet (a `/64`)
    /// when not given one; default: a `/48` of unique local addresses
    /// derived from the host's machine id (`rustlet_net::ipam::Subnet6::ula`).
    pub network_pool_v6: Option<String>,
    /// The default network's bridge.
    pub default_bridge: String,
    /// The nftables table (`inet <name>`).
    pub nft_table: String,
    /// The host's resolver configuration, for containers' `resolv.conf`.
    pub resolv_conf: PathBuf,
    /// Keep ufw's `route allow in/out on <bridge>` rules for every network,
    /// if ufw is installed and the daemon runs in the host's network
    /// namespace (`rustlet_net::ufw`).
    pub manage_ufw: bool,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            socket: rustlet_spec::DEFAULT_SOCKET.into(),
            socket_group: Some("rustlet".into()),
            data_root: rustlet_image::Store::DEFAULT_ROOT.into(),
            run_root: "/run/rustlet".into(),
            cgroup_parent: None,
            runtime: None,
            shim: None,
            log_max_size: rustlet_shim::DEFAULT_LOG_MAX_SIZE,
            log_max_files: rustlet_shim::DEFAULT_LOG_MAX_FILES,
            worker_memory_max: 1 << 30,
            worker_pids_max: 256,
            insecure_registries: Vec::new(),
            private_containers_mount: true,
            default_subnet: "10.89.0.0/24".into(),
            network_pool: "10.89.0.0/16".into(),
            network_pool_v6: None,
            default_bridge: "rustlet0".into(),
            nft_table: rustlet_net::firewall::TABLE.into(),
            resolv_conf: "/etc/resolv.conf".into(),
            manage_ufw: true,
        }
    }
}

impl Config {
    /// Reads `path`; a missing default file is the default configuration.
    pub fn load(path: Option<&Path>) -> anyhow::Result<Config> {
        let (path, required) = match path {
            Some(p) => (p.to_owned(), true),
            None => (PathBuf::from(CONFIG_FILE), false),
        };
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && !required => return Ok(Config::default()),
            Err(e) => return Err(anyhow::anyhow!("read {}: {e}", path.display())),
        };
        toml::from_str(&text).map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))
    }
}

/// Where everything lives, derived from the configuration.
#[derive(Debug, Clone)]
pub struct Paths {
    pub data_root: PathBuf,
    pub run_root: PathBuf,
    /// `rustlet-runc --root`.
    pub runtime_root: PathBuf,
    pub shims: PathBuf,
    pub containers: PathBuf,
    pub db: PathBuf,
    /// Held locked while the daemon runs: one daemon per run root and per
    /// data root.
    pub run_lock: PathBuf,
    pub data_lock: PathBuf,
    /// Network namespace pins (`<run>/netns/<id>`).
    pub netns: PathBuf,
    /// `<data>/volumes/<name>/_data`.
    pub volumes: PathBuf,
    /// The host sysctls' values from before Rustlets changed them, for
    /// `scripts/cleanup.sh`.
    pub sysctl_record: PathBuf,
}

impl Paths {
    pub fn new(config: &Config) -> Paths {
        Paths {
            data_root: config.data_root.clone(),
            run_root: config.run_root.clone(),
            runtime_root: config.run_root.join("runtime"),
            shims: config.run_root.join("shims"),
            containers: config.data_root.join("containers"),
            db: config.data_root.join("state.db"),
            run_lock: config.run_root.join("rustletd.lock"),
            data_lock: config.data_root.join("rustletd.lock"),
            netns: config.run_root.join("netns"),
            volumes: config.data_root.join("volumes"),
            sysctl_record: config.run_root.join("host-sysctl.orig"),
        }
    }

    /// The pin of a container's network namespace.
    pub fn netns_pin(&self, id: &str) -> PathBuf {
        self.netns.join(id)
    }

    /// `containers/<id>`: rootfs, upper, work, config.json, logs.
    pub fn container_dir(&self, id: &str) -> PathBuf {
        self.containers.join(id)
    }

    pub fn container_log(&self, id: &str) -> PathBuf {
        self.container_dir(id).join("container.log")
    }

    pub fn shim(&self, id: &str) -> rustlet_shim::paths::ShimPaths {
        rustlet_shim::paths::ShimPaths::for_container(&self.run_root, id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_overrides() {
        let c: Config =
            toml::from_str("socket = \"/tmp/s.sock\"\nlog_max_files = 5\nsocket_group = \"wheel\"").unwrap();
        assert_eq!(c.socket, Path::new("/tmp/s.sock"));
        assert_eq!(c.log_max_files, 5);
        assert_eq!(c.socket_group.as_deref(), Some("wheel"));
        assert_eq!(c.data_root, Path::new("/var/lib/rustlet"));
        assert!(toml::from_str::<Config>("no_such_key = 1").is_err(), "typos are errors");
        let p = Paths::new(&c);
        assert_eq!(p.runtime_root, Path::new("/run/rustlet/runtime"));
        assert_eq!(p.container_log("abc"), Path::new("/var/lib/rustlet/containers/abc/container.log"));
        assert_eq!(p.netns_pin("abc"), Path::new("/run/rustlet/netns/abc"));
        assert_eq!(p.sysctl_record, Path::new("/run/rustlet/host-sysctl.orig"), "where cleanup.sh reads it");
        assert_eq!(c.default_bridge, "rustlet0");
    }

    #[test]
    fn a_missing_default_file_is_fine_but_an_explicit_one_is_not() {
        let dir = tempfile::tempdir().unwrap();
        assert!(Config::load(Some(&dir.path().join("nope.toml"))).is_err());
    }
}

//! `GET /v1/version` and `GET /v1/info`.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Version {
    /// The daemon's version (`CARGO_PKG_VERSION`).
    pub version: String,
    pub api_version: String,
    pub os: String,
    pub arch: String,
    /// `uname -r`.
    pub kernel: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Info {
    pub containers: usize,
    pub running: usize,
    pub paused: usize,
    pub stopped: usize,
    pub images: usize,
    pub networks: usize,
    pub volumes: usize,
    /// `/var/lib/rustlet`.
    pub data_root: String,
    /// `/run/rustlet`.
    pub run_root: String,
    /// Where container cgroups go (`…/rustletd.service`).
    pub cgroup_parent: String,
    pub storage_driver: String,
    /// The OCI runtime binary.
    pub runtime: String,
    pub shim: String,
    pub kernel: String,
    pub cpus: usize,
    /// Bytes of RAM.
    pub memory: u64,
}

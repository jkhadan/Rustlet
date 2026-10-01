//! `GET /v1/containers/{id}/stats`: resource usage from the container's
//! cgroup (and its network namespace's interfaces).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// One sample. The cgroup fields are what `rustlet-runc events --stats`
/// reports (`rustlet_runtime::cgroups::stats::Stats`), with the same names.
/// Counters are cumulative: a CPU percentage is the difference of
/// `cpu["usage_usec"]` between two samples, over the time between their
/// `read`s, divided by `cpus_online` (or not, for Docker's "100% per CPU").
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct StatsSample {
    pub id: String,
    pub name: String,
    /// When the sample was taken: RFC 3339 with nanoseconds, UTC.
    pub read: String,
    /// CPUs online on the host.
    pub cpus_online: u32,
    /// `cpu.stat`: `usage_usec`, `user_usec`, `system_usec`, `nr_periods`,
    /// `nr_throttled`, `throttled_usec`, …
    pub cpu: BTreeMap<String, u64>,
    /// `memory.current`, bytes.
    pub memory_current: u64,
    /// `memory.max`; `None` = unlimited.
    pub memory_max: Option<u64>,
    pub memory_peak: Option<u64>,
    pub swap_current: Option<u64>,
    /// `memory.stat`: `anon`, `file`, `kernel`, `inactive_file`, …
    pub memory_stat: BTreeMap<String, u64>,
    pub memory_events: MemoryEvents,
    pub pids_current: u64,
    /// `None` = unlimited.
    pub pids_max: Option<u64>,
    /// `io.stat` per device ("major:minor"): `rbytes`, `wbytes`, `rios`, `wios`, …
    pub io: BTreeMap<String, BTreeMap<String, u64>>,
    /// PSI, per resource (`cpu`, `memory`, `io`) and line (`some`, `full`).
    pub pressure: BTreeMap<String, BTreeMap<String, Pressure>>,
    /// The container's interfaces (its network namespace's `/proc/net/dev`).
    pub network: Vec<NetDev>,
}

/// `memory.events`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MemoryEvents {
    pub low: u64,
    pub high: u64,
    pub max: u64,
    pub oom: u64,
    pub oom_kill: u64,
    pub oom_group_kill: u64,
}

/// One PSI line: shares of time (percent) stalled, averaged over 10, 60 and
/// 300 seconds, and the total stall time in microseconds.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Pressure {
    pub avg10: f64,
    pub avg60: f64,
    pub avg300: f64,
    pub total: u64,
}

/// One interface.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NetDev {
    pub name: String,
    pub rx_bytes: u64,
    pub rx_packets: u64,
    pub rx_errors: u64,
    pub rx_dropped: u64,
    pub tx_bytes: u64,
    pub tx_packets: u64,
    pub tx_errors: u64,
    pub tx_dropped: u64,
}

/// Query of `GET /v1/containers/{id}/stats`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct StatsQuery {
    /// A sample every second until the client hangs up (or the container
    /// stops); `false`: one sample, as a plain JSON response.
    pub stream: bool,
}

impl Default for StatsQuery {
    fn default() -> StatsQuery {
        StatsQuery { stream: true }
    }
}

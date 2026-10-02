//! `GET /v1/containers/{id}/stats`: a sample of the container cgroup's
//! counters (what `rustlet-runc events --stats` reports, through the same
//! library code) and of its network namespace's interfaces.

use rustlet_runtime::cgroups::{Cgroup, CgroupPath, stats};
use rustlet_spec::stats::{NetDev, StatsSample};

use crate::container::Container;
use crate::error::{ApiError, ApiResult};

pub fn sample(c: &Container, cgroup_parent: &str) -> ApiResult<StatsSample> {
    let path = CgroupPath::parse(&c.cgroup(cgroup_parent))?;
    let cg = Cgroup::open(&path)
        .map_err(|e| ApiError::conflict(format!("container {} has no cgroup: {e}", c.record.name)))?;
    let value = serde_json::to_value(cg.stats()?).map_err(|e| ApiError::internal(e.to_string()))?;
    let mut s: StatsSample = serde_json::from_value(value).map_err(|e| ApiError::internal(format!("stats: {e}")))?;
    s.id = c.id().to_owned();
    s.name = c.record.name.clone();
    s.read = rustlet_shim::logfile::now();
    s.cpus_online = cpus_online();
    if let Some(pid) = c.persisted().state.pid {
        s.network = stats::net_dev(nix::unistd::Pid::from_raw(pid))
            .map(|devs| {
                devs.into_iter()
                    .map(|d| {
                        serde_json::to_value(d)
                            .ok()
                            .and_then(|v| serde_json::from_value::<NetDev>(v).ok())
                            .unwrap_or_default()
                    })
                    .collect()
            })
            .unwrap_or_default();
    }
    Ok(s)
}

/// CPUs online on the host (`/sys/devices/system/cpu/online`, e.g. `0-3`).
pub fn cpus_online() -> u32 {
    std::fs::read_to_string("/sys/devices/system/cpu/online")
        .ok()
        .and_then(|s| parse_cpu_list(s.trim()))
        .unwrap_or_else(|| std::thread::available_parallelism().map_or(1, |n| n.get() as u32))
}

fn parse_cpu_list(s: &str) -> Option<u32> {
    let mut n = 0;
    for part in s.split(',') {
        n += match part.split_once('-') {
            Some((a, b)) => b.parse::<u32>().ok()? - a.parse::<u32>().ok()? + 1,
            None => {
                part.parse::<u32>().ok()?;
                1
            }
        };
    }
    Some(n)
}

/// Bytes of RAM (`MemTotal` in `/proc/meminfo`).
pub fn host_memory() -> u64 {
    std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|t| {
            let line = t.lines().find(|l| l.starts_with("MemTotal:"))?;
            line.split_whitespace().nth(1)?.parse::<u64>().ok().map(|kib| kib * 1024)
        })
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_lists() {
        assert_eq!(parse_cpu_list("0-3"), Some(4));
        assert_eq!(parse_cpu_list("0,2-3,7"), Some(4));
        assert_eq!(parse_cpu_list("0"), Some(1));
        assert_eq!(parse_cpu_list("x"), None);
        assert!(cpus_online() >= 1);
    }
}

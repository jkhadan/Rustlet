//! Parsing cgroup v2 statistics files (and `/proc/<pid>/net/dev`).
//!
//! The parsers are pure functions over file contents, so they can be
//! unit-tested with fixture strings copied from a real host. They are
//! deliberately *lenient*: a line they don't understand is skipped instead
//! of failing the whole read. Kernels add new keys to `memory.stat` or
//! `cpu.stat` all the time (`core_sched.force_idle_usec` appeared in 5.14,
//! `zswpwb` in 6.8, …), and `rustlet-runc events --stats` should keep
//! working on the next kernel, not break on it.
//!
//! cgroup v2 uses only a handful of file formats (see "Interface Files" in
//! the kernel's `Documentation/admin-guide/cgroup-v2.rst`):
//!
//! | format        | example                          | parser               |
//! |---------------|----------------------------------|----------------------|
//! | single value  | `memory.current`: `4096`         | `str::parse`         |
//! | value or max  | `memory.max`: `max`              | [`parse_max`]        |
//! | flat keyed    | `cpu.stat`: `usage_usec 1234`    | [`parse_flat_keyed`] |
//! | nested keyed  | `io.stat`: `8:0 rbytes=1 wios=2` | [`parse_io_stat`]    |
//!
//! PSI files (`*.pressure`) are nested keyed too, with decimal values.

use std::collections::BTreeMap;

use nix::unistd::Pid;
use serde::Serialize;

use crate::error::{Context, Error, Result};

/// `memory.events` counters. Each counts *events*, not bytes:
///
/// * `low`/`high`: reclaim happened although usage was below `memory.low`,
///   or throttling because usage went over `memory.high`;
/// * `max`: usage hit `memory.max` (the kernel then reclaims, and if that
///   fails, invokes the OOM killer);
/// * `oom`: the cgroup ran out of memory; `oom_kill`: a process in it was
///   killed for that; `oom_group_kill`: the whole group was (with
///   `memory.oom.group` = 1, Linux 5.17).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct MemoryEvents {
    pub low: u64,
    pub high: u64,
    pub max: u64,
    pub oom: u64,
    pub oom_kill: u64,
    pub oom_group_kill: u64,
}

impl MemoryEvents {
    /// Picks the known counters out of parsed `memory.events` lines;
    /// missing ones (older kernels) are 0, unknown ones ignored.
    pub fn from_map(m: &BTreeMap<String, u64>) -> MemoryEvents {
        let get = |k: &str| m.get(k).copied().unwrap_or(0);
        MemoryEvents {
            low: get("low"),
            high: get("high"),
            max: get("max"),
            oom: get("oom"),
            oom_kill: get("oom_kill"),
            oom_group_kill: get("oom_group_kill"),
        }
    }
}

/// One cgroup's statistics, as `rustlet-runc events --stats` prints them.
///
/// Files that belong to a controller which is not enabled in the cgroup
/// (say `io.stat` without the `io` controller) or that this kernel doesn't
/// have (`memory.peak` before 5.19) read as 0, `None` or empty.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Stats {
    /// `cpu.stat` (usage_usec, user_usec, system_usec, nr_periods, …).
    pub cpu: BTreeMap<String, u64>,
    /// `memory.current`, bytes.
    pub memory_current: u64,
    /// `memory.max`, bytes; `None` = "max" (unlimited).
    pub memory_max: Option<u64>,
    /// `memory.peak`, if the kernel has it.
    pub memory_peak: Option<u64>,
    /// `memory.swap.current`, if swap accounting is on.
    pub swap_current: Option<u64>,
    /// `memory.stat` (anon, file, kernel, …).
    pub memory_stat: BTreeMap<String, u64>,
    pub memory_events: MemoryEvents,
    pub pids_current: u64,
    /// `pids.max`; `None` = "max".
    pub pids_max: Option<u64>,
    /// `io.stat`, keyed by "major:minor".
    pub io: BTreeMap<String, BTreeMap<String, u64>>,
    /// `cpu.pressure`, `memory.pressure`, `io.pressure` (PSI), keyed by
    /// resource ("cpu"/"memory"/"io") then line ("some"/"full").
    pub pressure: BTreeMap<String, BTreeMap<String, Pressure>>,
}

/// One PSI ("pressure stall information") line:
/// `some avg10=0.00 avg60=0.00 avg300=0.00 total=0`.
///
/// `some` is the share of time in which *at least one* task was stalled
/// waiting for the resource, `full` the share in which *all* non-idle tasks
/// were, as percentages averaged over 10 s, 60 s and 300 s. A container
/// that is slow "for no reason" usually shows up here first.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize)]
pub struct Pressure {
    pub avg10: f64,
    pub avg60: f64,
    pub avg300: f64,
    /// Total stall time, microseconds.
    pub total: u64,
}

/// One interface from `/proc/<pid>/net/dev`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
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

/// "key value" per line (`cpu.stat`, `memory.stat`, `memory.events`,
/// `cgroup.events`). Lines without a numeric value are skipped.
pub fn parse_flat_keyed(text: &str) -> BTreeMap<String, u64> {
    text.lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            let (key, value) = (words.next()?, words.next()?.parse().ok()?);
            Some((key.to_owned(), value))
        })
        .collect()
}

/// `memory.events` contents → counters.
pub fn parse_memory_events(text: &str) -> MemoryEvents {
    MemoryEvents::from_map(&parse_flat_keyed(text))
}

/// A single number, or `max` → `None` (`memory.max`, `pids.max`).
pub fn parse_max(text: &str) -> Result<Option<u64>> {
    max_value(text)
        .ok_or_else(|| invalid_data("parse cgroup value", format!("expected a number or `max`, got {text:?}")))
}

/// [`parse_max`] without the error, for callers that add their own context.
pub(super) fn max_value(text: &str) -> Option<Option<u64>> {
    match text.trim() {
        "max" => Some(None),
        n => n.parse().ok().map(Some),
    }
}

/// An error for a kernel file whose contents we could not make sense of.
pub(super) fn invalid_data(context: impl Into<String>, msg: String) -> Error {
    Error::Io { context: context.into(), err: std::io::Error::new(std::io::ErrorKind::InvalidData, msg) }
}

/// `io.stat`: `8:0 rbytes=1 wbytes=2 rios=3 wios=4 dbytes=0 dios=0` per line.
/// Only devices the cgroup has done I/O on are listed.
pub fn parse_io_stat(text: &str) -> BTreeMap<String, BTreeMap<String, u64>> {
    text.lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            let device = words.next()?;
            let counters = words
                .filter_map(|kv| {
                    let (k, v) = kv.split_once('=')?;
                    Some((k.to_owned(), v.parse().ok()?))
                })
                .collect();
            Some((device.to_owned(), counters))
        })
        .collect()
}

/// A PSI file (`some …` and, except for `cpu.pressure` on old kernels,
/// `full …`).
pub fn parse_pressure(text: &str) -> BTreeMap<String, Pressure> {
    text.lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            let kind = words.next()?;
            let mut p = Pressure::default();
            for kv in words {
                let Some((k, v)) = kv.split_once('=') else { continue };
                match k {
                    "avg10" => p.avg10 = v.parse().ok()?,
                    "avg60" => p.avg60 = v.parse().ok()?,
                    "avg300" => p.avg300 = v.parse().ok()?,
                    "total" => p.total = v.parse().ok()?,
                    _ => {}
                }
            }
            Some((kind.to_owned(), p))
        })
        .collect()
}

/// `/proc/<pid>/net/dev` contents → interfaces.
///
/// After two header lines, each line is `name: ` followed by 8 receive
/// counters (bytes packets errs drop fifo frame compressed multicast) and
/// 8 transmit counters (bytes packets errs drop fifo colls carrier
/// compressed). We split at the colon rather than at whitespace: with a
/// long name or a big counter the kernel's `%6s:%8lu` format leaves no space
/// after it (`ens18:399359737`). Interface names can't contain `:`.
pub fn parse_net_dev(text: &str) -> Vec<NetDev> {
    text.lines()
        .filter_map(|line| {
            let (name, counters) = line.split_once(':')?;
            let n: Vec<u64> = counters.split_whitespace().map(str::parse).collect::<Result<_, _>>().ok()?;
            if n.len() < 16 {
                return None;
            }
            Some(NetDev {
                name: name.trim().to_owned(),
                rx_bytes: n[0],
                rx_packets: n[1],
                rx_errors: n[2],
                rx_dropped: n[3],
                tx_bytes: n[8],
                tx_packets: n[9],
                tx_errors: n[10],
                tx_dropped: n[11],
            })
        })
        .collect()
}

/// Reads `/proc/<pid>/net/dev`: the network counters of the network
/// namespace `pid` is in. (The file sits under `/proc/<pid>/` but describes
/// the *namespace*, so any process of the container will do.)
pub fn net_dev(pid: Pid) -> Result<Vec<NetDev>> {
    let path = format!("/proc/{pid}/net/dev");
    let text = std::fs::read_to_string(&path).with_context(|| format!("read {path}"))?;
    Ok(parse_net_dev(&text))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Fixtures copied from /sys/fs/cgroup/system.slice/ on the dev host
    // (kernel 7.0, systemd 255).

    const CPU_STAT: &str = "usage_usec 143705640
user_usec 25237222
system_usec 118468417
nice_usec 8000
core_sched.force_idle_usec 0
nr_periods 0
nr_throttled 0
throttled_usec 0
nr_bursts 0
burst_usec 0
";

    const MEMORY_STAT_HEAD: &str = "anon 117321728
file 338522112
kernel 58060800
kernel_stack 884736
pagetables 3751936
sec_pagetables 0
percpu 556536
sock 16384
vmalloc 1294336
shmem 5251072
zswap 0
file_mapped 147300352
pgfault 935157
pgmajfault 534
";

    const MEMORY_EVENTS: &str = "low 0
high 0
max 3
oom 1
oom_kill 1
oom_group_kill 0
sock_throttled 0
";

    const IO_STAT: &str = "8:0 rbytes=7184384 wbytes=4132864 rios=56 wios=715 dbytes=0 dios=0\n";

    const CPU_PRESSURE: &str = "some avg10=0.00 avg60=0.00 avg300=0.00 total=8322141
full avg10=0.00 avg60=0.00 avg300=0.00 total=7413640
";

    const NET_DEV: &str = "Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:  309768    2877    0    0    0     0          0         0   309768    2877    0    0    0     0       0          0
 ens18: 399359737  134952    0 5957    0     0          0         0 37143523   93516    0    0    0     0       0          0
";

    #[test]
    fn cpu_stat() {
        let m = parse_flat_keyed(CPU_STAT);
        assert_eq!(m.len(), 10);
        assert_eq!(m["usage_usec"], 143705640);
        assert_eq!(m["user_usec"], 25237222);
        assert_eq!(m["system_usec"], 118468417);
        assert_eq!(m["core_sched.force_idle_usec"], 0);
    }

    #[test]
    fn memory_stat() {
        let m = parse_flat_keyed(MEMORY_STAT_HEAD);
        assert_eq!(m["anon"], 117321728);
        assert_eq!(m["file"], 338522112);
        assert_eq!(m["pgmajfault"], 534);
    }

    #[test]
    fn flat_keyed_skips_junk_lines() {
        let m = parse_flat_keyed("a 1\n\nnot-a-number x\nlonely\n b  2 \n");
        assert_eq!(m, BTreeMap::from([("a".into(), 1), ("b".into(), 2)]));
    }

    #[test]
    fn memory_events_ignore_unknown_keys() {
        let e = parse_memory_events(MEMORY_EVENTS);
        assert_eq!(e, MemoryEvents { low: 0, high: 0, max: 3, oom: 1, oom_kill: 1, oom_group_kill: 0 });
        // An old kernel without oom_group_kill still parses.
        assert_eq!(parse_memory_events("oom 2\noom_kill 2\n").oom_group_kill, 0);
    }

    #[test]
    fn max_values() {
        assert_eq!(parse_max("max\n").unwrap(), None);
        assert_eq!(parse_max("517455872\n").unwrap(), Some(517455872));
        let e = parse_max("lots").unwrap_err().to_string();
        assert!(e.contains("\"lots\""), "{e}");
    }

    #[test]
    fn io_stat() {
        let m = parse_io_stat(IO_STAT);
        assert_eq!(m.len(), 1);
        let d = &m["8:0"];
        assert_eq!(d["rbytes"], 7184384);
        assert_eq!(d["wbytes"], 4132864);
        assert_eq!(d["rios"], 56);
        assert_eq!(d["wios"], 715);
        assert_eq!(d["dios"], 0);
        assert!(parse_io_stat("").is_empty());
    }

    #[test]
    fn pressure() {
        let m = parse_pressure(CPU_PRESSURE);
        assert_eq!(m["some"], Pressure { avg10: 0.0, avg60: 0.0, avg300: 0.0, total: 8322141 });
        assert_eq!(m["full"].total, 7413640);
        let busy = parse_pressure("some avg10=12.50 avg60=3.25 avg300=0.75 total=42\n");
        assert_eq!(busy["some"], Pressure { avg10: 12.5, avg60: 3.25, avg300: 0.75, total: 42 });
        assert!(!busy.contains_key("full"));
    }

    #[test]
    fn net_dev_counters() {
        let v = parse_net_dev(NET_DEV);
        assert_eq!(v.len(), 2, "header lines must be skipped: {v:?}");
        assert_eq!(
            v[0],
            NetDev {
                name: "lo".into(),
                rx_bytes: 309768,
                rx_packets: 2877,
                rx_errors: 0,
                rx_dropped: 0,
                tx_bytes: 309768,
                tx_packets: 2877,
                tx_errors: 0,
                tx_dropped: 0,
            }
        );
        assert_eq!(v[1].name, "ens18");
        assert_eq!((v[1].rx_bytes, v[1].rx_packets, v[1].rx_dropped), (399359737, 134952, 5957));
        assert_eq!((v[1].tx_bytes, v[1].tx_packets), (37143523, 93516));
    }

    #[test]
    fn net_dev_without_space_after_colon() {
        let v = parse_net_dev("veth1234567:1234567890 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15\n");
        assert_eq!(v.len(), 1);
        assert_eq!(
            (v[0].name.as_str(), v[0].rx_bytes, v[0].tx_bytes, v[0].tx_dropped),
            ("veth1234567", 1234567890, 8, 11)
        );
    }

    #[test]
    fn net_dev_of_self() {
        // Every network namespace has `lo`.
        let v = net_dev(nix::unistd::getpid()).unwrap();
        assert!(v.iter().any(|d| d.name == "lo"), "{v:?}");
    }
}

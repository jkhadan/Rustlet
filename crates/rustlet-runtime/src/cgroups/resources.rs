//! OCI `linux.resources` → cgroup v2 files.
//!
//! The OCI runtime spec was written when cgroup v1 was all there was, so its
//! `linux.resources` is v1-shaped: `cpu.shares` instead of `cpu.weight`,
//! `memory.swap` as *memory+swap*, `blockIO` weights on a 10–1000 scale.
//! This module translates each field into the v2 file that implements it
//! (table in `docs/architecture.md` §2.2.3), converting units where the two
//! versions disagree. It is a pure function from the spec to a list of
//! [`Setting`]s; [`Cgroup::create`](super::Cgroup::create) writes them.
//!
//! ## Rules that apply throughout
//!
//! * **v1-only fields are errors, not no-ops.** `memory.kernel`,
//!   `memory.swappiness`, `cpu.realtimeRuntime`, `network`, … have no v2
//!   file. Silently skipping them would run the container with limits its
//!   author believes are in place.
//! * **0 means "unset" where runc says so.** runc converts the spec into an
//!   internal Go struct in which 0 is the "not set" value for most limits;
//!   so under runc `"limit": 0` means *no* memory limit, not a 0-byte one.
//!   We do the same, so a bundle behaves identically under both runtimes.
//! * **`-1` means unlimited** and becomes the v2 keyword `max`.
//! * **Order matters** within a controller (e.g. `cpu.weight` is refused
//!   once `cpu.idle` is 1), so the output order is fixed, and `unified`
//!   comes last: it is the escape hatch that may override anything above.

use std::collections::HashMap;

use oci_spec::runtime::{
    LinuxBlockIo, LinuxCpu, LinuxHugepageLimit, LinuxMemory, LinuxPids, LinuxResources, LinuxThrottleDevice,
};

use super::Setting;
use crate::error::{Error, Result, Unsupported};

/// `cpu.max`'s period when the spec gives only a quota: the kernel's own
/// default (100 ms), so "quota 50000" means half a CPU.
pub const DEFAULT_CPU_PERIOD: u64 = 100_000;

/// `unified` keys that are not resource limits but control knobs of the
/// cgroup itself. Writing them from a spec would let `config.json` move
/// processes around (`cgroup.procs`, `cgroup.threads`), kill or freeze the
/// container behind the runtime's back, change which controllers children
/// get, or turn the cgroup threaded.
const FORBIDDEN_UNIFIED: [&str; 6] =
    ["cgroup.procs", "cgroup.threads", "cgroup.kill", "cgroup.freeze", "cgroup.subtree_control", "cgroup.type"];

/// Converts `linux.resources` into the file writes that implement it, in a
/// deterministic order. `devices` is ignored here (the eBPF device filter is
/// Phase 2c and `plan` rejects device rules). Fields that only exist in
/// cgroup v1 (`memory.kernel`, `kernelTCP`, `swappiness`,
/// `disableOOMKiller`, `cpu.realtime*`, `blockIO.leafWeight`, `network`)
/// are rejected with an error rather than ignored; `rdma` is unsupported.
pub fn settings_for(r: &LinuxResources) -> Result<Vec<Setting>> {
    let mut out = Vec::new();
    if let Some(m) = r.memory() {
        memory(m, &mut out)?;
    }
    if let Some(c) = r.cpu() {
        cpu(c, &mut out)?;
    }
    if let Some(p) = r.pids() {
        pids(p, &mut out);
    }
    if let Some(b) = r.block_io() {
        block_io(b, &mut out)?;
    }
    if let Some(h) = r.hugepage_limits() {
        hugepages(h, &mut out)?;
    }
    // net_cls/net_prio were v1 controllers; v2 has no equivalent (the
    // replacement is eBPF attached to the cgroup).
    if let Some(n) = r.network()
        && (n.class_id().is_some() || n.priorities().as_ref().is_some_and(|p| !p.is_empty()))
    {
        return Err(v1_only("network"));
    }
    if let Some(rdma) = r.rdma()
        && !rdma.is_empty()
    {
        return Err(Error::Unsupported(vec![Unsupported {
            field: "linux.resources.rdma".into(),
            when: "not planned",
        }]));
    }
    if let Some(u) = r.unified() {
        unified(u, &mut out)?;
    }
    Ok(out)
}

/// runc's log-scale conversion of v1 `cpu.shares` (2..=262144, default
/// 1024) to v2 `cpu.weight` (1..=10000, default 100); 0 means unset.
///
/// The obvious linear mapping `1 + (shares - 2) * 9999 / 262142` sends the
/// v1 default 1024 to 39, not to the v2 default 100: every container would
/// quietly get less CPU than an unconfigured process next to it. The
/// quadratic in log2 space (from crun, adopted by runc 1.3) passes through
/// all three anchor points: 2 → 1, 1024 → 100, 262144 → 10000.
pub fn cpu_shares_to_weight(shares: u64) -> u64 {
    match shares {
        0 => 0,
        1..=2 => 1,
        262_144.. => 10_000,
        _ => {
            let l = (shares as f64).log2();
            let exponent = (l * l + 125.0 * l) / 612.0 - 7.0 / 34.0;
            10f64.powf(exponent).ceil() as u64
        }
    }
}

/// runc's linear conversion of a v1 `blkio.weight` (10..=1000) to a v2
/// `io.weight` (1..=10000). Unlike CPU shares, both scales have their
/// default in the same place relative to the range, so linear is fine.
pub fn blkio_weight_to_io_weight(weight: u16) -> Result<u64> {
    if !(10..=1000).contains(&weight) {
        return Err(Error::invalid(format!("blockIO weight {weight} is out of range (10..=1000)")));
    }
    Ok(1 + (u64::from(weight) - 10) * 9999 / 990)
}

fn v1_only(field: &str) -> Error {
    Error::invalid(format!(
        "linux.resources.{field} only exists in cgroup v1; this host uses cgroup v2 (remove it from config.json)"
    ))
}

/// A byte count, with `-1` meaning unlimited (`max`).
fn bytes_or_max(field: &str, v: i64) -> Result<String> {
    match v {
        -1 => Ok("max".into()),
        v if v < 0 => Err(Error::invalid(format!("linux.resources.{field} must be -1 or a byte count, not {v}"))),
        v => Ok(v.to_string()),
    }
}

fn memory(m: &LinuxMemory, out: &mut Vec<Setting>) -> Result<()> {
    // Kernel memory is always accounted in v2 (and `memory.kmem.*` was
    // removed from v1 too, in 5.4).
    #[allow(deprecated)]
    let kernel = m.kernel();
    if kernel.is_some_and(|k| k != 0) {
        return Err(v1_only("memory.kernel"));
    }
    if m.kernel_tcp().is_some_and(|k| k != 0) {
        return Err(v1_only("memory.kernelTCP"));
    }
    // v2 has a single, global swappiness.
    if m.swappiness().is_some() {
        return Err(v1_only("memory.swappiness"));
    }
    // v2 has no way to make a cgroup hang instead of OOM-killing; the
    // closest is `memory.high` (throttle) in `unified`.
    if m.disable_oom_killer() == Some(true) {
        return Err(v1_only("memory.disableOOMKiller"));
    }
    // `useHierarchy` is ignored: v2 is always hierarchical.

    let limit = m.limit().filter(|&l| l != 0);
    if let Some(l) = limit {
        out.push(Setting::new("memory.max", bytes_or_max("memory.limit", l)?));
    }
    if let Some(swap) = swap_max(limit, m.swap())? {
        out.push(Setting::new("memory.swap.max", swap));
    }
    // A reservation ("soft limit") protects memory from reclaim while the
    // cgroup stays below it: that is `memory.low` in v2.
    if let Some(r) = m.reservation().filter(|&r| r != 0) {
        out.push(Setting::new("memory.low", bytes_or_max("memory.reservation", r)?));
    }
    Ok(())
}

/// `memory.swap.max` for a v1-style `swap`, following runc's
/// `ConvertMemorySwapToCgroupV2Value`.
///
/// In v1, `memory.memsw.limit_in_bytes` limits memory **plus** swap; in v2,
/// `memory.swap.max` limits swap alone. So limit 64M + swap 96M (v1) means
/// "up to 32M of swap" (v2). Swap equal to the limit means no swap at all.
fn swap_max(limit: Option<i64>, swap: Option<i64>) -> Result<Option<String>> {
    let (limit, swap) = (limit.unwrap_or(0), swap.unwrap_or(0));
    // v1 compatibility: unlimited memory and no swap setting meant "memory
    // and swap both unlimited". (A fresh cgroup's `memory.swap.max` is
    // `max` anyway; this matters for `update`.)
    if limit == -1 && swap == 0 {
        return Ok(Some("max".into()));
    }
    match swap {
        0 => Ok(None),
        -1 => Ok(Some("max".into())),
        s if s < 0 => Err(Error::invalid(format!("linux.resources.memory.swap must be -1 or a byte count, not {s}"))),
        _ if limit == 0 || limit == -1 => Err(Error::invalid(
            "linux.resources.memory.swap needs a memory.limit: in the OCI spec (as in cgroup v1) swap counts \
             memory+swap, so it only has a meaning relative to the memory limit",
        )),
        s if s < limit => Err(Error::invalid(format!(
            "linux.resources.memory.swap ({s}) is memory+swap and must be >= memory.limit ({limit})"
        ))),
        s => Ok(Some((s - limit).to_string())),
    }
}

fn cpu(c: &LinuxCpu, out: &mut Vec<Setting>) -> Result<()> {
    // v2's cpu controller only handles SCHED_OTHER (fair) tasks; RT
    // bandwidth is global (`/proc/sys/kernel/sched_rt_*`).
    if c.realtime_runtime().is_some_and(|v| v != 0) {
        return Err(v1_only("cpu.realtimeRuntime"));
    }
    if c.realtime_period().is_some_and(|v| v != 0) {
        return Err(v1_only("cpu.realtimePeriod"));
    }
    // Weight before idle: the kernel refuses a weight for an idle group.
    if let Some(shares) = c.shares() {
        let w = cpu_shares_to_weight(shares);
        if w != 0 {
            out.push(Setting::new("cpu.weight", w.to_string()));
        }
    }
    if c.quota().is_some() || c.period().is_some() {
        let period = c.period().filter(|&p| p != 0).unwrap_or(DEFAULT_CPU_PERIOD);
        let quota = match c.quota() {
            Some(q) if q > 0 => q.to_string(),
            _ => "max".into(),
        };
        out.push(Setting::new("cpu.max", format!("{quota} {period}")));
    }
    // After cpu.max: the kernel checks that burst <= quota.
    if let Some(b) = c.burst() {
        out.push(Setting::new("cpu.max.burst", b.to_string()));
    }
    if let Some(i) = c.idle() {
        out.push(Setting::new("cpu.idle", i.to_string()));
    }
    if let Some(cpus) = c.cpus().as_deref().filter(|s| !s.is_empty()) {
        out.push(Setting::new("cpuset.cpus", cpus));
    }
    if let Some(mems) = c.mems().as_deref().filter(|s| !s.is_empty()) {
        out.push(Setting::new("cpuset.mems", mems));
    }
    Ok(())
}

fn pids(p: &LinuxPids, out: &mut Vec<Setting>) {
    let v = if p.limit() > 0 { p.limit().to_string() } else { "max".into() };
    out.push(Setting::new("pids.max", v));
}

/// `major:minor`, the way `io.*` files name a block device.
fn device(field: &str, major: i64, minor: i64) -> Result<String> {
    if major < 0 || minor < 0 {
        return Err(Error::invalid(format!("linux.resources.blockIO.{field}: bad device {major}:{minor}")));
    }
    Ok(format!("{major}:{minor}"))
}

fn block_io(b: &LinuxBlockIo, out: &mut Vec<Setting>) -> Result<()> {
    // Leaf weights belonged to the CFQ I/O scheduler, removed in 5.0.
    if b.leaf_weight().is_some_and(|w| w != 0) {
        return Err(v1_only("blockIO.leafWeight"));
    }
    if let Some(w) = b.weight().filter(|&w| w != 0) {
        out.push(Setting::new("io.weight", format!("default {}", blkio_weight_to_io_weight(w)?)));
    }
    for d in b.weight_device().iter().flatten() {
        if d.leaf_weight().is_some_and(|w| w != 0) {
            return Err(v1_only("blockIO.weightDevice[].leafWeight"));
        }
        if let Some(w) = d.weight().filter(|&w| w != 0) {
            let dev = device("weightDevice", d.major(), d.minor())?;
            out.push(Setting::new("io.weight", format!("{dev} {}", blkio_weight_to_io_weight(w)?)));
        }
    }
    // One write per device and key: `io.max` merges a line into the
    // device's existing limits, leaving the other keys alone.
    let throttles: [(&str, &str, &Option<Vec<LinuxThrottleDevice>>); 4] = [
        ("throttleReadBpsDevice", "rbps", b.throttle_read_bps_device()),
        ("throttleWriteBpsDevice", "wbps", b.throttle_write_bps_device()),
        ("throttleReadIOPSDevice", "riops", b.throttle_read_iops_device()),
        ("throttleWriteIOPSDevice", "wiops", b.throttle_write_iops_device()),
    ];
    for (field, key, list) in throttles {
        for d in list.iter().flatten() {
            let dev = device(field, d.major(), d.minor())?;
            // In v1 a rate of 0 removed the limit; v2 spells that `max`
            // (and refuses 0 with ERANGE).
            let rate = if d.rate() == 0 { "max".into() } else { d.rate().to_string() };
            out.push(Setting::new("io.max", format!("{dev} {key}={rate}")));
        }
    }
    Ok(())
}

/// Is `s` a hugepage size as the kernel names it in `hugetlb.<size>.max`:
/// digits and a unit, e.g. `2MB`, `1GB`, `64KB`? Checked strictly because
/// it becomes part of a file name.
fn is_page_size(s: &str) -> bool {
    let digits = s.trim_end_matches(|c: char| c.is_ascii_alphabetic());
    let unit = &s[digits.len()..];
    !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) && matches!(unit, "KB" | "MB" | "GB")
}

fn hugepages(limits: &[LinuxHugepageLimit], out: &mut Vec<Setting>) -> Result<()> {
    for h in limits {
        let size = h.page_size();
        if !is_page_size(size) {
            return Err(Error::invalid(format!(
                "linux.resources.hugepageLimits: bad pageSize {size:?} (expected e.g. \"2MB\" or \"1GB\")"
            )));
        }
        out.push(Setting::new(format!("hugetlb.{size}.max"), bytes_or_max("hugepageLimits[].limit", h.limit())?));
    }
    Ok(())
}

/// Checks a `unified` key: a plain `<controller>.<name>` file name, and not
/// one of the [`FORBIDDEN_UNIFIED`] control files.
fn check_unified_key(key: &str) -> Result<()> {
    let bad = |why: &str| Err(Error::invalid(format!("linux.resources.unified key {key:?}: {why}")));
    if key.contains('/') || key.contains("..") {
        return bad("must be a file name in the container's cgroup, not a path");
    }
    let Some((controller, _)) = key.split_once('.') else {
        return bad("is not a cgroup v2 file name (expected <controller>.<name>, e.g. memory.high)");
    };
    if controller.is_empty() || !key.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')) {
        return bad("is not a cgroup v2 file name (expected <controller>.<name>, e.g. memory.high)");
    }
    if FORBIDDEN_UNIFIED.contains(&key) {
        return bad("controls the cgroup itself rather than a resource limit, and is managed by the runtime");
    }
    Ok(())
}

/// `unified`: raw v2 key/values, passed through. A `HashMap` has no stable
/// order, so we sort by key: the same spec always yields the same writes.
fn unified(u: &HashMap<String, String>, out: &mut Vec<Setting>) -> Result<()> {
    let mut entries: Vec<_> = u.iter().collect();
    entries.sort();
    for (k, v) in entries {
        check_unified_key(k)?;
        out.push(Setting::new(k.as_str(), v.as_str()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use oci_spec::runtime::{
        LinuxBlockIoBuilder, LinuxCpuBuilder, LinuxHugepageLimitBuilder, LinuxMemoryBuilder, LinuxNetworkBuilder,
        LinuxPidsBuilder, LinuxRdma, LinuxResourcesBuilder, LinuxThrottleDeviceBuilder, LinuxWeightDeviceBuilder,
    };

    fn pairs(v: &[Setting]) -> Vec<(&str, &str)> {
        v.iter().map(|s| (s.file.as_str(), s.value.as_str())).collect()
    }

    fn mem(m: LinuxMemoryBuilder) -> Result<Vec<Setting>> {
        settings_for(&LinuxResourcesBuilder::default().memory(m.build().unwrap()).build().unwrap())
    }

    fn cpu_of(c: LinuxCpuBuilder) -> Result<Vec<Setting>> {
        settings_for(&LinuxResourcesBuilder::default().cpu(c.build().unwrap()).build().unwrap())
    }

    fn err(r: Result<Vec<Setting>>) -> String {
        r.unwrap_err().to_string()
    }

    #[test]
    fn empty_resources_write_nothing() {
        assert!(settings_for(&LinuxResources::default()).unwrap().is_empty());
    }

    #[test]
    fn shares_to_weight_anchor_points() {
        assert_eq!(cpu_shares_to_weight(0), 0);
        assert_eq!(cpu_shares_to_weight(1), 1);
        assert_eq!(cpu_shares_to_weight(2), 1);
        assert_eq!(cpu_shares_to_weight(512), 59);
        assert_eq!(cpu_shares_to_weight(1024), 100);
        assert_eq!(cpu_shares_to_weight(2048), 174);
        assert_eq!(cpu_shares_to_weight(262_143), 10_000);
        assert_eq!(cpu_shares_to_weight(262_144), 10_000);
        assert_eq!(cpu_shares_to_weight(u64::MAX), 10_000);
    }

    #[test]
    fn shares_to_weight_is_monotonic_and_in_range() {
        let mut prev = 1;
        for s in 2..=262_144 {
            let w = cpu_shares_to_weight(s);
            assert!((1..=10_000).contains(&w) && w >= prev, "shares {s} -> {w} (prev {prev})");
            prev = w;
        }
    }

    #[test]
    fn memory_limit_reservation_and_max() {
        let s = mem(LinuxMemoryBuilder::default().limit(33_554_432).reservation(16_777_216)).unwrap();
        assert_eq!(pairs(&s), [("memory.max", "33554432"), ("memory.low", "16777216")]);
        let s = mem(LinuxMemoryBuilder::default().limit(-1).reservation(-1).swap(-1)).unwrap();
        assert_eq!(pairs(&s), [("memory.max", "max"), ("memory.swap.max", "max"), ("memory.low", "max")]);
        // 0 = unset, as in runc.
        assert!(mem(LinuxMemoryBuilder::default().limit(0).reservation(0)).unwrap().is_empty());
        assert!(err(mem(LinuxMemoryBuilder::default().limit(-2))).contains("memory.limit"));
    }

    #[test]
    fn swap_is_memory_plus_swap() {
        let m = 64 << 20;
        let s = mem(LinuxMemoryBuilder::default().limit(m).swap(m + (32 << 20))).unwrap();
        assert_eq!(pairs(&s), [("memory.max", "67108864"), ("memory.swap.max", "33554432")]);
        // swap == limit: no swap at all (what the OOM tests use).
        let s = mem(LinuxMemoryBuilder::default().limit(m).swap(m)).unwrap();
        assert_eq!(pairs(&s)[1], ("memory.swap.max", "0"));
    }

    #[test]
    fn swap_special_values() {
        assert_eq!(swap_max(Some(100), Some(-1)).unwrap().as_deref(), Some("max"));
        assert_eq!(swap_max(Some(100), Some(0)).unwrap(), None);
        assert_eq!(swap_max(Some(100), None).unwrap(), None);
        assert_eq!(swap_max(None, None).unwrap(), None);
        // runc: unlimited memory with no swap setting = both unlimited.
        assert_eq!(swap_max(Some(-1), None).unwrap().as_deref(), Some("max"));
        assert_eq!(swap_max(Some(-1), Some(-1)).unwrap().as_deref(), Some("max"));
    }

    #[test]
    fn swap_errors() {
        // Set without a (finite) memory limit.
        assert!(swap_max(None, Some(100)).unwrap_err().to_string().contains("needs a memory.limit"));
        assert!(swap_max(Some(-1), Some(100)).is_err());
        // Less than the limit: memory+swap can't be smaller than memory.
        let e = swap_max(Some(200), Some(100)).unwrap_err().to_string();
        assert!(e.contains(">= memory.limit"), "{e}");
        assert!(swap_max(Some(200), Some(-5)).is_err());
        // Through settings_for too.
        assert!(mem(LinuxMemoryBuilder::default().swap(1 << 20)).is_err());
    }

    #[test]
    fn memory_v1_only_fields_are_rejected() {
        #[allow(deprecated)]
        let kernel = LinuxMemoryBuilder::default().kernel(1 << 20);
        for (m, field) in [
            (kernel, "memory.kernel"),
            (LinuxMemoryBuilder::default().kernel_tcp(1 << 20), "memory.kernelTCP"),
            (LinuxMemoryBuilder::default().swappiness(10u64), "memory.swappiness"),
            (LinuxMemoryBuilder::default().disable_oom_killer(true), "memory.disableOOMKiller"),
        ] {
            let e = err(mem(m));
            assert!(e.contains(field) && e.contains("cgroup v1"), "{e}");
        }
        // The harmless values older tools write are accepted.
        assert!(mem(LinuxMemoryBuilder::default().disable_oom_killer(false).use_hierarchy(true)).unwrap().is_empty());
    }

    #[test]
    fn cpu_max_forms() {
        let one = |c| pairs(&cpu_of(c).unwrap()).into_iter().map(|(f, v)| format!("{f}={v}")).collect::<Vec<_>>();
        assert_eq!(one(LinuxCpuBuilder::default().quota(50_000i64).period(200_000u64)), ["cpu.max=50000 200000"]);
        assert_eq!(one(LinuxCpuBuilder::default().quota(50_000i64)), ["cpu.max=50000 100000"]);
        assert_eq!(one(LinuxCpuBuilder::default().period(200_000u64)), ["cpu.max=max 200000"]);
        assert_eq!(one(LinuxCpuBuilder::default().quota(-1i64)), ["cpu.max=max 100000"]);
        assert_eq!(one(LinuxCpuBuilder::default().quota(0i64)), ["cpu.max=max 100000"]);
        assert!(one(LinuxCpuBuilder::default()).is_empty());
    }

    #[test]
    fn cpu_everything_in_order() {
        let c =
            LinuxCpuBuilder::default().shares(512u64).quota(20_000i64).burst(5_000u64).idle(0i64).cpus("0-1").mems("0");
        assert_eq!(
            pairs(&cpu_of(c).unwrap()),
            [
                ("cpu.weight", "59"),
                ("cpu.max", "20000 100000"),
                ("cpu.max.burst", "5000"),
                ("cpu.idle", "0"),
                ("cpuset.cpus", "0-1"),
                ("cpuset.mems", "0"),
            ]
        );
        // shares 0 = unset; empty cpuset strings = unset.
        assert!(cpu_of(LinuxCpuBuilder::default().shares(0u64).cpus("")).unwrap().is_empty());
    }

    #[test]
    fn cpu_realtime_is_v1_only() {
        assert!(err(cpu_of(LinuxCpuBuilder::default().realtime_runtime(1000i64))).contains("cpu.realtimeRuntime"));
        assert!(err(cpu_of(LinuxCpuBuilder::default().realtime_period(1000u64))).contains("cpu.realtimePeriod"));
    }

    #[test]
    fn pids_limit() {
        let p = |n: i64| {
            let r = LinuxResourcesBuilder::default().pids(LinuxPidsBuilder::default().limit(n).build().unwrap());
            pairs(&settings_for(&r.build().unwrap()).unwrap())
                .into_iter()
                .map(|(_, v)| v.to_owned())
                .collect::<Vec<_>>()
        };
        assert_eq!(p(64), ["64"]);
        assert_eq!(p(-1), ["max"]);
        assert_eq!(p(0), ["max"]);
    }

    #[test]
    fn block_io_weights_and_throttles() {
        let t = |major: i64, minor: i64, rate: u64| {
            LinuxThrottleDeviceBuilder::default().major(major).minor(minor).rate(rate).build().unwrap()
        };
        let b = LinuxBlockIoBuilder::default()
            .weight(500u16)
            .weight_device(vec![LinuxWeightDeviceBuilder::default().major(8).minor(0).weight(1000u16).build().unwrap()])
            .throttle_read_bps_device(vec![t(8, 0, 1_048_576)])
            .throttle_write_bps_device(vec![t(8, 0, 0)])
            .throttle_read_iops_device(vec![t(8, 16, 100)])
            .throttle_write_iops_device(vec![t(8, 16, 200)])
            .build()
            .unwrap();
        let s = settings_for(&LinuxResourcesBuilder::default().block_io(b).build().unwrap()).unwrap();
        assert_eq!(
            pairs(&s),
            [
                ("io.weight", "default 4950"),
                ("io.weight", "8:0 10000"),
                ("io.max", "8:0 rbps=1048576"),
                ("io.max", "8:0 wbps=max"),
                ("io.max", "8:16 riops=100"),
                ("io.max", "8:16 wiops=200"),
            ]
        );
    }

    #[test]
    fn blkio_weight_conversion() {
        assert_eq!(blkio_weight_to_io_weight(10).unwrap(), 1);
        assert_eq!(blkio_weight_to_io_weight(500).unwrap(), 4950);
        assert_eq!(blkio_weight_to_io_weight(1000).unwrap(), 10_000);
        assert!(blkio_weight_to_io_weight(9).is_err());
        assert!(blkio_weight_to_io_weight(1001).is_err());
    }

    #[test]
    fn block_io_errors() {
        let r = |b: LinuxBlockIoBuilder| {
            settings_for(&LinuxResourcesBuilder::default().block_io(b.build().unwrap()).build().unwrap())
        };
        assert!(err(r(LinuxBlockIoBuilder::default().leaf_weight(100u16))).contains("leafWeight"));
        let leaf = LinuxWeightDeviceBuilder::default().major(8).minor(0).leaf_weight(100u16).build().unwrap();
        assert!(err(r(LinuxBlockIoBuilder::default().weight_device(vec![leaf]))).contains("leafWeight"));
        let bad = LinuxThrottleDeviceBuilder::default().major(-1).minor(0).rate(1u64).build().unwrap();
        assert!(err(r(LinuxBlockIoBuilder::default().throttle_read_bps_device(vec![bad]))).contains("bad device"));
    }

    #[test]
    fn hugepage_limits() {
        let h =
            |size: &str, limit: i64| LinuxHugepageLimitBuilder::default().page_size(size).limit(limit).build().unwrap();
        let r = |v| settings_for(&LinuxResourcesBuilder::default().hugepage_limits(v).build().unwrap());
        let s = r(vec![h("2MB", 1 << 30), h("1GB", -1)]).unwrap();
        assert_eq!(pairs(&s), [("hugetlb.2MB.max", "1073741824"), ("hugetlb.1GB.max", "max")]);
        for bad in ["", "2", "MB", "2mb", "2MB/../x", "1.5GB"] {
            assert!(err(r(vec![h(bad, 1)])).contains("pageSize"), "{bad:?} accepted");
        }
    }

    #[test]
    fn network_is_v1_only_and_rdma_unsupported() {
        let n = LinuxNetworkBuilder::default().class_id(7u32).build().unwrap();
        let e = err(settings_for(&LinuxResourcesBuilder::default().network(n).build().unwrap()));
        assert!(e.contains("network") && e.contains("cgroup v1"), "{e}");
        // An empty network object is fine.
        let empty = LinuxNetworkBuilder::default().build().unwrap();
        assert!(settings_for(&LinuxResourcesBuilder::default().network(empty).build().unwrap()).unwrap().is_empty());

        let rdma = HashMap::from([("mlx5_0".to_owned(), LinuxRdma::default())]);
        let e = settings_for(&LinuxResourcesBuilder::default().rdma(rdma).build().unwrap()).unwrap_err();
        match e {
            Error::Unsupported(u) => {
                assert_eq!((u[0].field.as_str(), u[0].when), ("linux.resources.rdma", "not planned"))
            }
            e => panic!("{e}"),
        }
    }

    fn with_unified(kv: &[(&str, &str)]) -> Result<Vec<Setting>> {
        let u: HashMap<String, String> = kv.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        settings_for(&LinuxResourcesBuilder::default().unified(u).build().unwrap())
    }

    #[test]
    fn unified_is_sorted_and_last() {
        let u: HashMap<String, String> =
            [("pids.max", "7"), ("memory.high", "1G"), ("cgroup.max.depth", "2"), ("hugetlb.2MB.max", "0")]
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
                .into();
        let r = LinuxResourcesBuilder::default()
            .pids(LinuxPidsBuilder::default().limit(64).build().unwrap())
            .unified(u)
            .build()
            .unwrap();
        assert_eq!(
            pairs(&settings_for(&r).unwrap()),
            [
                ("pids.max", "64"),
                ("cgroup.max.depth", "2"),
                ("hugetlb.2MB.max", "0"),
                ("memory.high", "1G"),
                ("pids.max", "7"),
            ]
        );
    }

    #[test]
    fn unified_rejects_paths_and_control_files() {
        for key in [
            "../memory.max",
            "memory.max/..",
            "sub/memory.max",
            "/memory.max",
            "memory..max",
            "memorymax",
            ".max",
            "",
            "memory.max ",
            "memory.max\n",
            "cgroup.procs",
            "cgroup.threads",
            "cgroup.kill",
            "cgroup.freeze",
            "cgroup.subtree_control",
            "cgroup.type",
        ] {
            let e = err(with_unified(&[(key, "1")]));
            assert!(e.contains("unified key"), "{key:?}: {e}");
        }
    }
}

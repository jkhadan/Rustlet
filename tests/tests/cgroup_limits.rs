//! Phase 2a: cgroup v2 limits, containment and accounting through
//! `rustlet-runc`: the OCI → v2 mapping, the cgroup namespace, delegation
//! checks, OOM, a fork bomb, pause/resume, `ps` and `events --stats`.
//!
//! Container cgroups live in this test binary's delegated systemd scope (see
//! `cargo xtask itest`), which caps the whole binary at 4096 tasks and 4 GiB.
//! Run with `cargo xtask itest -- cg_`.

use std::process::Command;
use std::time::{Duration, Instant};

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use rustlet_itests::e2e::*;
use rustlet_itests::*;
use rustlet_runtime::oci_spec::runtime::{
    LinuxCpuBuilder, LinuxMemoryBuilder, LinuxPidsBuilder, LinuxResources, LinuxResourcesBuilder,
};

const MIB: i64 = 1 << 20;

/// `memory.limit = memory.swap = bytes` (OCI's swap counts memory + swap, so
/// this means no swap at all) and, optionally, `pids.limit`.
fn limits(memory: Option<i64>, pids: Option<i64>) -> LinuxResources {
    let mut r = LinuxResourcesBuilder::default();
    if let Some(bytes) = memory {
        r = r.memory(LinuxMemoryBuilder::default().limit(bytes).swap(bytes).build().unwrap());
    }
    if let Some(n) = pids {
        r = r.pids(LinuxPidsBuilder::default().limit(n).build().unwrap());
    }
    r.build().unwrap()
}

/// `dd` allocates its 64 MiB buffer and fills it from /dev/zero.
fn oom_spec(name: &str) -> (rustlet_runtime::oci_spec::runtime::Spec, String) {
    let mut s = spec(&["dd", "if=/dev/zero", "of=/dev/null", "bs=64M", "count=1"]);
    let cg = set_cgroup(&mut s, name);
    set_resources(&mut s, limits(Some(32 * MIB), None));
    (s, cg)
}

// ── the OCI → cgroup v2 mapping ──────────────────────────────────────────────

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn cg_limits_map_to_cgroup_v2_files() {
    let mut s = spec(&["true"]);
    let cg = set_cgroup(&mut s, "cg-mapping");
    let cpu = LinuxCpuBuilder::default().quota(50_000).period(100_000u64).shares(1024u64).build().unwrap();
    let mut r = limits(Some(32 * MIB), Some(64));
    r.set_cpu(Some(cpu));
    set_resources(&mut s, r);
    let c = Container::created(&s);

    for (file, want) in [
        ("memory.max", "33554432"),
        ("memory.swap.max", "0"),
        ("pids.max", "64"),
        ("cpu.max", "50000 100000"),
        ("cpu.weight", "100"),
    ] {
        assert_eq!(cgroup_read(&cg, file), want, "{file}");
    }
    // Init is in it already, waiting to exec.
    assert_eq!(cgroup_procs(&cg), [c.pid()]);

    c.delete(false).ok();
    c.assert_gone();
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn cg_cgroup_namespace_is_rooted_at_the_container() {
    let mut s = spec(&["cat", "/proc/self/cgroup"]);
    let cg = set_cgroup(&mut s, "cg-namespace");
    let c = Container::created(&s);
    // The host sees init in the container's cgroup…
    let host_view = std::fs::read_to_string(format!("/proc/{}/cgroup", c.pid())).unwrap();
    assert_eq!(host_view.trim(), format!("0::{cg}"));
    // …and the container sees that cgroup as its root.
    c.start().ok();
    c.wait_for_status("stopped", PROMPT);
    assert_eq!(c.stdout().trim(), "0::/", "stderr: {}", c.stderr());
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn cg_cgroupfs_inside_is_read_only_and_shows_its_own_limits() {
    let mut s = sh("cat /sys/fs/cgroup/memory.max /sys/fs/cgroup/pids.max; \
                    echo 1000 > /sys/fs/cgroup/pids.max && echo writable || echo refused; \
                    grep ' /sys/fs/cgroup ' /proc/self/mountinfo");
    let cg = set_cgroup(&mut s, "cg-cgroupfs");
    set_resources(&mut s, limits(Some(32 * MIB), Some(64)));
    let c = Container::started(&s);
    c.wait_for_status("stopped", PROMPT);

    let out = c.stdout();
    let lines: Vec<&str> = out.lines().collect();
    assert!(lines.len() >= 4, "{out}\nstderr: {}", c.stderr());
    assert_eq!(lines[..3], ["33554432", "64", "refused"], "{out}\nstderr: {}", c.stderr());
    let (left, right) = lines[3].split_once(" - ").unwrap();
    assert!(right.starts_with("cgroup2 "), "{}", lines[3]);
    let options = left.split(' ').nth(5).unwrap_or("");
    assert!(options.split(',').any(|o| o == "ro"), "/sys/fs/cgroup is not read-only: {}", lines[3]);
    assert_eq!(cgroup_read(&cg, "pids.max"), "64", "the container raised its own limit");
}

// ── where a container cgroup may be ──────────────────────────────────────────

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn cg_refuses_cgroups_outside_the_delegated_subtree() {
    let pid = std::process::id();

    // Directly under the root, which systemd owns.
    let top = format!("/rustlet-not-delegated-{pid}");
    let _top_guard = CgroupGuard(cgroup_dir(&top));
    let mut s = spec(&["true"]);
    set_cgroups_path(&mut s, &top);
    let mut c = Container::new(&s);
    c.create(&[]).refused("delegat");
    c.assert_gone();
    assert!(!cgroup_dir(&top).exists(), "created {top}");

    // Elsewhere in system.slice (through `run` this time).
    let bogus = format!("/system.slice/rustlet-bogus-{pid}");
    let _bogus_guard = CgroupGuard(cgroup_dir(&bogus));
    let mut s = spec(&["true"]);
    set_cgroups_path(&mut s, &format!("{bogus}/c"));
    let mut c = Container::new(&s);
    c.run_foreground(&[], None, TIMEOUT).refused("delegat");
    c.assert_gone();
    assert!(!cgroup_dir(&bogus).exists(), "created {bogus}");
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn cg_refuses_escaping_and_relative_cgroups_paths() {
    let pid = std::process::id();
    let scope = itest_scope();
    let (slice, _) = scope.rsplit_once('/').unwrap();

    // `..` climbing out of the scope: a string-prefix check would pass this.
    let escaped = format!("{slice}/rustlet-escape-{pid}");
    let _escape_guard = CgroupGuard(cgroup_dir(&escaped));
    let mut s = spec(&["true"]);
    set_cgroups_path(&mut s, &format!("{scope}/../rustlet-escape-{pid}"));
    let mut c = Container::new(&s);
    c.create(&[]).failed();
    c.assert_gone();
    assert!(!cgroup_dir(&escaped).exists(), "created {escaped}");

    // A relative path (runc would resolve it against its own cgroup).
    let name = format!("rustlet-relative-{pid}");
    let own = own_cgroup().unwrap();
    let candidates = [format!("/{name}"), format!("{scope}/{name}"), format!("{own}/{name}")];
    let _guards: Vec<CgroupGuard> = candidates.iter().map(|p| CgroupGuard(cgroup_dir(p))).collect();
    let mut s = spec(&["true"]);
    set_cgroups_path(&mut s, &format!("{name}/c"));
    let mut c = Container::new(&s);
    c.create(&[]).failed();
    c.assert_gone();
    for p in &candidates {
        assert!(!cgroup_dir(p).exists(), "created {p}");
    }
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn cg_refuses_the_delegated_scope_itself() {
    // Container cgroups must be strictly *inside* the delegated subtree.
    // Careful: the scope holds this test binary, so if the runtime accepts
    // it, `delete --force` (cgroup.kill) must not be let loose on it.
    let mut s = spec(&["true"]);
    set_cgroups_path(&mut s, itest_scope());
    let mut c = Container::new(&s);
    let out = c.create(&[]);
    if out.status == 0 {
        // Point the drop guard at an id that doesn't exist, then kill init by
        // hand. The state directory is left for `scripts/cleanup.sh`.
        let decoy = format!("{}-not-deleted", c.id());
        let id = std::mem::replace(&mut c.bundle.id, decoy);
        let st = runc_out(&["state", &id]);
        let pid = Json::parse(st.stdout.trim()).ok().and_then(|j| j["pid"].as_i64());
        if let Some(pid) = pid.and_then(|p| i32::try_from(p).ok()).filter(|&p| p > 1) {
            let _ = kill(Pid::from_raw(pid), Signal::SIGKILL);
        }
        panic!("`create` accepted the delegated scope itself as cgroupsPath: {out:#?}");
    }
    out.refused("delegat");
    c.assert_gone();
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn cg_resources_need_a_cgroups_path() {
    let mut s = spec(&["true"]);
    set_resources(&mut s, limits(None, Some(64)));
    let mut c = Container::new(&s);
    c.create(&[]).refused("cgroupsPath");
    c.assert_gone();
    let mut c = Container::new(&s);
    c.run_foreground(&[], None, TIMEOUT).refused("cgroupsPath");
    c.assert_gone();
}

// ── containment ──────────────────────────────────────────────────────────────

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn cg_oom_kill_is_reported_by_run() {
    let (s, _) = oom_spec("cg-oom-run");
    let mut c = Container::new(&s);
    let out = c.run_foreground(&[], None, TIMEOUT);
    assert_ne!(out.status, 0, "dd should have been OOM-killed (expected 137): {out:#?}");
    assert!(out.stderr.lines().any(|l| l.contains("OOM")), "no line about the OOM kill on stderr: {out:#?}");
    c.assert_gone();
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn cg_oom_kill_shows_in_stats() {
    let (s, cg) = oom_spec("cg-oom-stats");
    let c = Container::started(&s);
    c.wait_for_status("stopped", PROMPT);
    // What the kernel counted (if this fails, the test setup is at fault)…
    let events = cgroup_read(&cg, "memory.events");
    assert!(flat_key(&events, "oom_kill").is_some_and(|n| n >= 1), "the kernel saw no OOM kill: {events}");
    // …is what `events --stats` reports.
    let stats = c.stats();
    let n = stats["data"]["memory_events"]["oom_kill"].as_u64();
    assert!(n.is_some_and(|n| n >= 1), "oom_kill should be >= 1: {stats:?}");
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn cg_fork_bomb_is_contained() {
    // `bomb` forks itself forever; init then execs (no fork needed) and waits.
    // Its "can't fork" complaints would fill the stderr file: drop them.
    let mut s = sh("exec 2>/dev/null; bomb() { bomb | bomb & }; bomb; exec sleep 3600");
    let cg = set_cgroup(&mut s, "cg-fork-bomb");
    set_resources(&mut s, limits(None, Some(64)));
    let c = Container::created(&s);
    // The project's rule for fork-bomb tests: the limit must be in place
    // before the bomb goes off.
    assert_eq!(cgroup_read(&cg, "pids.max"), "64", "refusing to start a fork bomb without pids.max = 64");

    c.start().ok();
    wait_until("the bomb to hit pids.max", PROMPT, || {
        flat_key(&cgroup_read(&cg, "pids.events"), "max").is_some_and(|n| n > 0)
    });
    let until = Instant::now() + Duration::from_secs(1);
    while Instant::now() < until {
        let n: u64 = cgroup_read(&cg, "pids.current").parse().unwrap();
        assert!(n <= 64, "pids.current = {n}");
        std::thread::sleep(Duration::from_millis(50));
    }
    if let Ok(peak) = std::fs::read_to_string(cgroup_dir(&cg).join("pids.peak")) {
        assert!(peak.trim().parse::<u64>().unwrap() <= 64, "pids.peak = {peak}");
    }
    // The host is fine: the harness can still fork.
    let t = Command::new("/bin/true").status().expect("the harness can't fork any more");
    assert!(t.success());

    c.delete(true).ok();
    wait_until("the bomb's cgroup to vanish", Duration::from_secs(5), || !cgroup_dir(&cg).exists());
    c.assert_gone();
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn cg_pause_freezes_and_resume_thaws() {
    let mut s = sh("while :; do echo x >> /mnt/count; sleep 0.1; done");
    let host = bind_host_dir(&mut s, "/mnt");
    let cg = set_cgroup(&mut s, "cg-pause");
    let c = Container::started(&s);
    let count = || std::fs::read_to_string(host.path().join("count")).map_or(0, |t| t.lines().count());
    let frozen = || flat_key(&cgroup_read(&cg, "cgroup.events"), "frozen");
    wait_until("the counter to tick", PROMPT, || count() >= 3);

    c.cmd(&["pause"]).ok();
    assert_eq!(c.status(), "paused");
    wait_until("the cgroup to be frozen", PROMPT, || frozen() == Some(1));
    let at_pause = count();
    std::thread::sleep(Duration::from_secs(1));
    assert_eq!(count(), at_pause, "the counter kept going while paused");

    c.cmd(&["resume"]).ok();
    assert_eq!(c.status(), "running");
    wait_until("the counter to tick again", PROMPT, || count() > at_pause);
    assert_eq!(frozen(), Some(0));

    // A paused container is only deleted with --force.
    c.cmd(&["pause"]).ok();
    c.wait_for_status("paused", PROMPT);
    c.delete(false).failed();
    assert_eq!(c.status(), "paused");
    c.delete(true).ok();
    c.assert_gone();
}

// ── introspection ────────────────────────────────────────────────────────────

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn cg_ps_lists_the_container_processes() {
    let mut s = sh("sleep 3600 & sleep 3600 & wait");
    let cg = set_cgroup(&mut s, "cg-ps");
    let c = Container::started(&s);
    wait_until("init and its two children", PROMPT, || cgroup_procs(&cg).len() == 3);
    let init = c.pid();

    let out = c.cmd(&["ps", "--format", "json"]);
    let json = parse_json(out.ok(), "ps --format json");
    let arr = json.as_array().unwrap_or_else(|| panic!("`ps --format json` is not an array: {json:?}"));
    let mut pids: Vec<i32> = arr
        .iter()
        .map(|p| p.as_i64().and_then(|p| i32::try_from(p).ok()).unwrap_or_else(|| panic!("not a pid: {p:?}")))
        .collect();
    pids.sort();
    assert!(pids.contains(&init), "init {init} missing from {pids:?}");
    assert_eq!(pids, cgroup_procs(&cg), "`ps` doesn't match cgroup.procs");

    for args in [&["ps"][..], &["ps", "--format", "table"]] {
        let out = c.cmd(args);
        assert!(out.ok().split_whitespace().any(|w| w == init.to_string()), "{args:?}: {out:#?}");
    }
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn cg_events_stats_are_sane() {
    let mut s = spec(&["sleep", "3600"]);
    set_cgroup(&mut s, "cg-stats");
    set_resources(&mut s, limits(Some(64 * MIB), Some(64)));
    let c = Container::started(&s);
    let st = c.stats();
    let d = &st["data"];
    assert!(d["memory_current"].as_u64().is_some_and(|n| n > 0), "memory_current: {st:?}");
    assert_eq!(d["memory_max"].as_u64(), Some(64 << 20), "memory_max: {st:?}");
    assert!(d["pids_current"].as_u64().is_some_and(|n| n >= 1), "pids_current: {st:?}");
    assert_eq!(d["pids_max"].as_u64(), Some(64), "pids_max: {st:?}");
    assert_eq!(d["memory_events"]["oom_kill"].as_u64(), Some(0), "memory_events.oom_kill: {st:?}");
    assert!(d["cpu"].as_object().is_some() && d["cpu"]["usage_usec"].as_u64().is_some(), "cpu: {st:?}");
    let net = d["network"].as_array().unwrap_or_else(|| panic!("network is not an array: {st:?}"));
    let lo = net.iter().find(|i| i["name"].as_str() == Some("lo")).unwrap_or_else(|| panic!("no `lo`: {st:?}"));
    assert!(lo["rx_bytes"].as_u64().is_some(), "lo.rx_bytes: {st:?}");

    // No memory limit: memory_max is null.
    let mut s = spec(&["sleep", "3600"]);
    set_cgroup(&mut s, "cg-stats-unlimited");
    let c = Container::started(&s);
    let st = c.stats();
    assert_eq!(st["data"].get("memory_max"), Some(&Json::Null), "memory_max: {st:?}");
}

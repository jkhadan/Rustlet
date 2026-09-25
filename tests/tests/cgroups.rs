//! Phase 2a: the cgroups v2 API (`rustlet_runtime::cgroups`) against the
//! real kernel, without a container around it.
//!
//! Run with `cargo xtask itest -- cgroup_` (as root, in a delegated systemd
//! scope). Every cgroup lives inside this test binary's scope
//! ([`itest_cgroup`]), and a [`Cleanup`] guard kills and removes it even
//! when an assertion fails halfway.

use std::collections::HashMap;
use std::os::fd::AsRawFd;
use std::os::unix::process::ExitStatusExt;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use nix::unistd::Pid;
use rustlet_itests::{itest_cgroup, itest_scope};
use rustlet_runtime::cgroups::{Cgroup, CgroupDriver, CgroupPath, Setting, SystemdDelegated, settings_for};
use rustlet_runtime::oci_spec::runtime::{
    LinuxBlockIoBuilder, LinuxCpuBuilder, LinuxHugepageLimitBuilder, LinuxMemoryBuilder, LinuxPidsBuilder,
    LinuxResourcesBuilder,
};

/// Generous: freezing and killing take milliseconds.
const TIMEOUT: Duration = Duration::from_secs(5);

/// `<scope>/<name>`, parsed.
fn path(name: &str) -> CgroupPath {
    CgroupPath::parse(&itest_cgroup(name)).unwrap()
}

/// Kills, empties and removes cgroups (deepest first, so list parents
/// before children) and reaps child processes, also when the test panics.
/// Only ever touches cgroups below this binary's scope.
#[derive(Default)]
struct Cleanup {
    cgroups: Vec<CgroupPath>,
    children: Vec<Child>,
}

impl Cleanup {
    fn new(cgroups: &[&CgroupPath]) -> Cleanup {
        let scope = CgroupPath::parse(itest_scope()).unwrap();
        assert!(cgroups.iter().all(|c| c.is_below(&scope)), "test cgroups must be inside {scope}");
        Cleanup { cgroups: cgroups.iter().map(|&c| c.clone()).collect(), children: Vec::new() }
    }

    /// Starts `sleep 30` and moves it into `cg` from the outside.
    fn sleeper(&mut self, cg: &Cgroup) -> Pid {
        let child = Command::new("sleep").arg("30").stdin(Stdio::null()).spawn().unwrap();
        let pid = Pid::from_raw(child.id() as i32);
        self.children.push(child);
        cg.add_process(pid).unwrap();
        pid
    }

    /// Starts `sleep 30` as a process that moves *itself* into `cg` and only
    /// then execs, so its memory is charged to `cg`. Returns once it has.
    fn charged_sleeper(&mut self, cg: &Cgroup) -> Pid {
        let procs = cg.path().host_path().join("cgroup.procs");
        let script = format!("echo $$ > {} && exec sleep 30", procs.display());
        let child = Command::new("sh").args(["-c", &script]).stdin(Stdio::null()).spawn().unwrap();
        let pid = Pid::from_raw(child.id() as i32);
        self.children.push(child);
        let comm = format!("/proc/{pid}/comm");
        for _ in 0..500 {
            if cg.procs().unwrap() == [pid] && std::fs::read_to_string(&comm).unwrap_or_default().trim() == "sleep" {
                return pid;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("{pid} did not move into {} and exec sleep", cg.path());
    }
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        let open: Vec<Cgroup> = self.cgroups.iter().rev().filter_map(|p| Cgroup::open(p).ok()).collect();
        for cg in &open {
            let _ = cg.kill();
        }
        for child in &mut self.children {
            let _ = child.kill();
            let _ = child.wait();
        }
        for cg in &open {
            let _ = cg.wait_empty(TIMEOUT);
            if let Err(e) = cg.remove() {
                eprintln!("cleanup: {e}");
            }
        }
    }
}

/// Removes directories that a test expected *not* to be created, should a
/// bug create them anyway (they would be empty cgroups).
struct RemoveStrays(Vec<std::path::PathBuf>);

impl Drop for RemoveStrays {
    fn drop(&mut self) {
        for dir in self.0.iter().rev() {
            if dir.exists() {
                let _ = std::fs::remove_dir(dir);
            }
        }
    }
}

fn words(s: &str) -> Vec<&str> {
    s.split_whitespace().collect()
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn cgroup_create_applies_settings() {
    let p = path("settings");
    let _cleanup = Cleanup::new(&[&p]);
    let r = LinuxResourcesBuilder::default()
        .memory(LinuxMemoryBuilder::default().limit(32 << 20).swap(32 << 20).reservation(8 << 20).build().unwrap())
        .cpu(
            LinuxCpuBuilder::default()
                .shares(512u64)
                .quota(50_000i64)
                .period(100_000u64)
                .cpus("0")
                .mems("0")
                .build()
                .unwrap(),
        )
        .pids(LinuxPidsBuilder::default().limit(64).build().unwrap())
        .block_io(LinuxBlockIoBuilder::default().weight(500u16).build().unwrap())
        .unified(HashMap::from([("memory.high".to_owned(), "16777216".to_owned())]))
        .build()
        .unwrap();
    let cg = Cgroup::create(&p, &settings_for(&r).unwrap(), &SystemdDelegated).unwrap();

    for (file, want) in [
        ("memory.max", "33554432"),
        ("memory.swap.max", "0"),
        ("memory.low", "8388608"),
        ("memory.high", "16777216"),
        ("cpu.weight", "59"),
        ("cpu.max", "50000 100000"),
        ("cpuset.cpus", "0"),
        ("cpuset.mems", "0"),
        ("pids.max", "64"),
        ("io.weight", "default 4950"),
    ] {
        assert_eq!(cg.read(file).unwrap(), want, "{file}");
    }
    // The defaults plus what the settings needed (cpuset, io) reached it.
    let controllers = cg.read("cgroup.controllers").unwrap();
    for c in ["cpu", "cpuset", "io", "memory", "pids"] {
        assert!(words(&controllers).contains(&c), "{c} missing from {controllers:?}");
    }
    assert_eq!(cg, Cgroup::open(&p).unwrap());
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn cgroup_create_makes_intermediates() {
    let (nest, mid, leaf) = (path("nest"), path("nest/a"), path("nest/a/leaf"));
    let _cleanup = Cleanup::new(&[&nest, &mid, &leaf]);
    let cg = Cgroup::create(&leaf, &[Setting::new("pids.max", "5")], &SystemdDelegated).unwrap();
    assert_eq!(cg.read("pids.max").unwrap(), "5");
    for level in [&nest, &mid] {
        let enabled = std::fs::read_to_string(level.host_path().join("cgroup.subtree_control")).unwrap();
        for c in ["cpu", "memory", "pids"] {
            assert!(words(&enabled).contains(&c), "{c} not enabled in {level}: {enabled:?}");
        }
    }
    // A sibling reuses the intermediates.
    let sibling = path("nest/a/sibling");
    let _cleanup2 = Cleanup::new(&[&sibling]);
    Cgroup::create(&sibling, &[], &SystemdDelegated).unwrap();
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn cgroup_create_refuses_non_delegated_paths() {
    let root_subtree = std::fs::read_to_string("/sys/fs/cgroup/cgroup.subtree_control").unwrap();
    let pid = std::process::id();
    let scope = CgroupPath::parse(itest_scope()).unwrap();
    let paths = [
        format!("/rustlet-not-delegated-{pid}"),
        format!("/system.slice/rustlet-not-delegated-{pid}"),
        format!("/system.slice/rustlet-not-delegated-{pid}/web"),
    ]
    .map(|p| CgroupPath::parse(&p).unwrap());
    // Checked before the guard exists, so it can only ever remove our own strays.
    assert!(paths.iter().all(|p| !p.host_path().exists()), "leftovers from an earlier run: {paths:?}");
    let _strays = RemoveStrays(paths.iter().map(CgroupPath::host_path).collect());
    for p in paths {
        // Belt and braces: only call create() once we know the driver says no,
        // so a bug in the walk can't make this test create a host cgroup.
        let e = SystemdDelegated.delegated_root(&p).unwrap_err().to_string();
        assert!(e.contains("delegat"), "{e}");
        let e = Cgroup::create(&p, &[Setting::new("pids.max", "10")], &SystemdDelegated).unwrap_err();
        assert!(e.to_string().contains("Delegate=yes"), "{e}");
        assert!(!p.host_path().exists(), "create() made {p} although it refused");
        assert!(Cgroup::open(&p).is_err());
    }
    // The scope itself is the unit's, not a container's; its children are fine.
    assert!(SystemdDelegated.delegated_root(&scope).is_err());
    assert_eq!(SystemdDelegated.delegated_root(&path("web")).unwrap(), scope);
    assert_eq!(std::fs::read_to_string("/sys/fs/cgroup/cgroup.subtree_control").unwrap(), root_subtree);
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn cgroup_create_refuses_existing_path() {
    let p = path("exists");
    let _cleanup = Cleanup::new(&[&p]);
    let cg = Cgroup::create(&p, &[Setting::new("pids.max", "10")], &SystemdDelegated).unwrap();
    let e = Cgroup::create(&p, &[Setting::new("pids.max", "20")], &SystemdDelegated).unwrap_err();
    assert!(e.to_string().contains("already exists"), "{e}");
    // The failed create neither removed nor changed the existing cgroup.
    assert_eq!(cg.read("pids.max").unwrap(), "10");
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn cgroup_create_rolls_back_on_a_bad_setting() {
    let p = path("rollback");
    let _cleanup = Cleanup::new(&[&p]);
    let settings = [Setting::new("pids.max", "10"), Setting::new("memory.max", "lots")];
    let e = Cgroup::create(&p, &settings, &SystemdDelegated).unwrap_err();
    assert!(e.to_string().contains("memory.max"), "{e}");
    assert_eq!(e.errno(), Some(nix::errno::Errno::EINVAL));
    assert!(!p.host_path().exists(), "the half-configured cgroup was left behind");
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn cgroup_create_refuses_unavailable_controller() {
    let scope = std::fs::read_to_string(format!("/sys/fs/cgroup{}/cgroup.controllers", itest_scope())).unwrap();
    if words(&scope).contains(&"hugetlb") {
        eprintln!("skipped: this systemd delegates hugetlb");
        return;
    }
    let p = path("hugetlb");
    let _cleanup = Cleanup::new(&[&p]);
    let h = LinuxHugepageLimitBuilder::default().page_size("2MB").limit(0).build().unwrap();
    let settings = settings_for(&LinuxResourcesBuilder::default().hugepage_limits(vec![h]).build().unwrap()).unwrap();
    let e = Cgroup::create(&p, &settings, &SystemdDelegated).unwrap_err().to_string();
    assert!(e.contains("hugetlb") && e.contains("delegate"), "{e}");
    assert!(!p.host_path().exists());
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn cgroup_create_refuses_internal_processes() {
    let (busy, child) = (path("busy"), path("busy/child"));
    let mut cleanup = Cleanup::new(&[&busy, &child]);
    let cg = Cgroup::create(&busy, &[], &SystemdDelegated).unwrap();
    cleanup.sleeper(&cg);
    // `busy` has a process, so it can't enable controllers for a child.
    let e = Cgroup::create(&child, &[], &SystemdDelegated).unwrap_err();
    assert_eq!(e.errno(), Some(nix::errno::Errno::EBUSY), "{e}");
    let msg = e.to_string();
    assert!(msg.contains("no internal processes") && msg.contains(&busy.to_string()), "{msg}");
    assert!(!child.host_path().exists());
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn cgroup_dir_fd_is_the_cgroup_directory() {
    let p = path("dirfd");
    let _cleanup = Cleanup::new(&[&p]);
    let cg = Cgroup::create(&p, &[], &SystemdDelegated).unwrap();
    let fd = cg.dir_fd().unwrap();
    let fs = nix::sys::statfs::fstatfs(&fd).unwrap();
    assert_eq!(fs.filesystem_type(), nix::sys::statfs::CGROUP2_SUPER_MAGIC);
    assert_eq!(std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd())).unwrap(), p.host_path());
    // It is a real directory fd: files open relative to it.
    let procs = nix::fcntl::openat(&fd, "cgroup.procs", nix::fcntl::OFlag::O_RDONLY, nix::sys::stat::Mode::empty());
    assert!(procs.is_ok(), "{procs:?}");
    // And it is not inherited by children.
    let flags = nix::fcntl::fcntl(&fd, nix::fcntl::FcntlArg::F_GETFD).unwrap();
    assert!(nix::fcntl::FdFlag::from_bits_truncate(flags).contains(nix::fcntl::FdFlag::FD_CLOEXEC));
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn cgroup_lifecycle_freeze_thaw_kill_remove() {
    let p = path("lifecycle");
    let mut cleanup = Cleanup::new(&[&p]);
    let cg = Cgroup::create(&p, &[], &SystemdDelegated).unwrap();
    assert!(!cg.is_populated().unwrap());
    assert!(cg.procs().unwrap().is_empty());

    let pid = cleanup.sleeper(&cg);
    assert_eq!(cg.procs().unwrap(), [pid]);
    assert!(cg.is_populated().unwrap());
    let e = cg.remove().unwrap_err();
    assert!(e.to_string().contains("still in use"), "{e}");
    assert!(p.host_path().exists());

    cg.freeze(TIMEOUT).unwrap();
    assert!(cg.is_frozen().unwrap());
    // Frozen processes don't exit, so waiting for "empty" times out.
    let e = cg.wait_empty(Duration::from_millis(50)).unwrap_err();
    assert_eq!(e.errno(), Some(nix::errno::Errno::ETIMEDOUT));
    assert!(e.to_string().contains(&p.to_string()), "{e}");

    cg.thaw(TIMEOUT).unwrap();
    assert!(!cg.is_frozen().unwrap());

    // cgroup.kill works on a frozen cgroup too.
    cg.freeze(TIMEOUT).unwrap();
    cg.kill().unwrap();
    cg.wait_empty(TIMEOUT).unwrap();
    assert!(!cg.is_populated().unwrap());
    assert!(cg.procs().unwrap().is_empty());
    let status = cleanup.children[0].wait().unwrap();
    assert_eq!(status.signal(), Some(nix::sys::signal::Signal::SIGKILL as i32), "{status:?}");

    cg.remove().unwrap();
    assert!(!p.host_path().exists());
    // Removing or waiting on a cgroup that is gone is fine.
    cg.remove().unwrap();
    cg.wait_empty(TIMEOUT).unwrap();
    assert!(Cgroup::open(&p).is_err());
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn cgroup_oom_kill_shows_in_memory_events() {
    let p = path("oom");
    let _cleanup = Cleanup::new(&[&p]);
    // 16M of memory and no swap (OCI swap is memory+swap: equal = none).
    let mem = LinuxMemoryBuilder::default().limit(16 << 20).swap(16 << 20).build().unwrap();
    let settings = settings_for(&LinuxResourcesBuilder::default().memory(mem).build().unwrap()).unwrap();
    let cg = Cgroup::create(&p, &settings, &SystemdDelegated).unwrap();
    assert_eq!(cg.read("memory.swap.max").unwrap(), "0");
    assert_eq!(cg.memory_events().unwrap().oom_kill, 0);

    // The shell moves itself in first; dd's 64M buffer is then charged here.
    let procs = p.host_path().join("cgroup.procs");
    let script = format!("echo $$ > {} && exec dd if=/dev/zero of=/dev/null bs=64M count=1", procs.display());
    let status = Command::new("sh")
        .args(["-c", &script])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert_eq!(status.signal(), Some(nix::sys::signal::Signal::SIGKILL as i32), "dd was not OOM-killed: {status:?}");
    let ev = cg.memory_events().unwrap();
    assert!(ev.oom_kill >= 1 && ev.oom >= 1 && ev.max >= 1, "{ev:?}");
    assert_eq!(cg.stats().unwrap().memory_events, ev);
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn cgroup_stats_reports_usage() {
    let p = path("stats");
    let mut cleanup = Cleanup::new(&[&p]);
    let settings = [Setting::new("memory.max", (64 << 20).to_string()), Setting::new("pids.max", "32")];
    let cg = Cgroup::create(&p, &settings, &SystemdDelegated).unwrap();
    cleanup.charged_sleeper(&cg);

    let s = cg.stats().unwrap();
    assert!(s.cpu.contains_key("usage_usec") && s.cpu.contains_key("nr_throttled"), "{:?}", s.cpu);
    assert!(s.memory_current > 0, "{s:?}");
    assert_eq!(s.memory_max, Some(64 << 20));
    assert!(s.memory_peak.is_some_and(|peak| peak >= s.memory_current), "{s:?}");
    assert!(s.memory_stat.contains_key("anon") && s.memory_stat.contains_key("file"), "{:?}", s.memory_stat);
    assert_eq!(s.memory_events, Default::default());
    assert_eq!((s.pids_current, s.pids_max), (1, Some(32)));
    for resource in ["cpu", "memory", "io"] {
        assert!(s.pressure.get(resource).is_some_and(|p| p.contains_key("some")), "{resource}: {:?}", s.pressure);
    }

    // An unlimited cgroup reports `max` as None.
    let q = path("stats-unlimited");
    let _cleanup2 = Cleanup::new(&[&q]);
    let s = Cgroup::create(&q, &[], &SystemdDelegated).unwrap().stats().unwrap();
    assert_eq!((s.memory_max, s.pids_max, s.pids_current), (None, None, 0));
}

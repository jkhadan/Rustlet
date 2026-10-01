//! Phase 1: `rustlet-runc run` on the Alpine rootfs.
//!
//! Run with `cargo xtask itest` (as root, in a limited systemd scope).
//! A plain `cargo nextest run` skips these: they are `#[ignore]`d.

use std::io::{BufRead, BufReader};
use std::time::{Duration, Instant};

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use rustlet_itests::*;
use rustlet_runtime::oci_spec::runtime::{
    LinuxNamespaceBuilder, LinuxNamespaceType, PosixRlimitBuilder, PosixRlimitType,
};

// ── the Phase 1 milestone: PID 1, own hostname, own mount table ─────────────

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn init_is_pid_1() {
    assert_eq!(run(&sh("echo $$")).ok().trim(), "1");
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn proc_lists_only_the_container() {
    // `ls` is PID 1 itself here, so it is the only process there is.
    let out = run(&spec(&["ls", "/proc"]));
    let pids: Vec<&str> = out.ok().split_whitespace().filter(|e| e.chars().all(|c| c.is_ascii_digit())).collect();
    assert_eq!(pids, ["1"]);
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn hostname_is_private() {
    let host_before = nix::unistd::gethostname().unwrap();
    let mut s = spec(&["hostname"]);
    s.set_hostname(Some("itest-host".into()));
    assert_eq!(run(&s).ok().trim(), "itest-host");
    assert_eq!(nix::unistd::gethostname().unwrap(), host_before);
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn mount_table_is_exactly_the_specs() {
    let s = spec(&["cat", "/proc/self/mountinfo"]);
    let out = run(&s);
    let points: Vec<&str> = out.ok().lines().filter_map(|l| l.split(' ').nth(4)).collect();
    let (spec_mounts, rest) = points.split_at(points.len().min(8));
    assert_eq!(spec_mounts, ["/", "/proc", "/dev", "/dev/pts", "/dev/shm", "/dev/mqueue", "/sys", "/sys/fs/cgroup"]);
    // After them come only the masked and read-only paths (Phase 2b).
    let linux = s.linux().as_ref().unwrap();
    let listed = |p: &str| {
        [linux.masked_paths(), linux.readonly_paths()]
            .iter()
            .any(|l| l.as_ref().is_some_and(|l| l.iter().any(|m| m == p)))
    };
    for p in rest {
        assert!(listed(p), "{p} is a mount point but neither a spec mount nor a masked/read-only path: {points:?}");
    }
    // No propagation to or from the host on any of them.
    assert!(!out.stdout.contains("shared:") && !out.stdout.contains("master:"), "{}", out.stdout);
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn default_namespaces_all_differ_from_the_host() {
    let kinds = ["cgroup", "ipc", "mnt", "net", "pid", "uts"];
    let script = kinds.map(|k| format!("readlink /proc/self/ns/{k}")).join("; ");
    let out = run(&sh(&script));
    for (kind, line) in kinds.iter().zip(out.ok().lines()) {
        assert_ne!(line, host_ns(kind), "{kind} namespace is shared with the host");
    }
    // Not requested, so shared: user (Phase 2c) and time.
    let out = run(&sh("readlink /proc/self/ns/user; readlink /proc/self/ns/time"));
    assert_eq!(out.ok().lines().collect::<Vec<_>>(), [host_ns("user"), host_ns("time")]);
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn cgroup_namespace_is_rooted_at_the_container() {
    assert_eq!(run(&spec(&["cat", "/proc/self/cgroup"])).ok().trim(), "0::/");
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn new_network_namespace_has_only_loopback() {
    assert_eq!(run(&spec(&["ls", "/sys/class/net"])).ok().trim(), "lo");
}

// ── namespace modes: omitted = shared, path = joined ─────────────────────────

fn without_ns(
    mut s: rustlet_runtime::oci_spec::runtime::Spec,
    t: LinuxNamespaceType,
) -> rustlet_runtime::oci_spec::runtime::Spec {
    let linux = s.linux_mut().as_mut().unwrap();
    let ns = linux.namespaces().clone().unwrap().into_iter().filter(|n| n.typ() != t).collect();
    linux.set_namespaces(Some(ns));
    s
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn omitted_pid_namespace_means_host_pids() {
    let out = run(&without_ns(sh("echo $$; readlink /proc/self/ns/pid"), LinuxNamespaceType::Pid));
    let lines: Vec<&str> = out.ok().lines().collect();
    assert_ne!(lines[0], "1");
    assert_eq!(lines[1], host_ns("pid"));
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn joins_a_namespace_by_path() {
    // Join the host's network namespace through PID 1's ns file, the way
    // `--net=host` could be expressed (Docker simply omits the type).
    let mut s = without_ns(sh("readlink /proc/self/ns/net; ls /sys/class/net"), LinuxNamespaceType::Network);
    let net = LinuxNamespaceBuilder::default().typ(LinuxNamespaceType::Network).path("/proc/1/ns/net").build().unwrap();
    s.linux_mut().as_mut().unwrap().namespaces_mut().as_mut().unwrap().push(net);
    let out = run(&s);
    let lines: Vec<&str> = out.ok().lines().collect();
    assert_eq!(lines[0], host_ns("net"));
    assert!(lines.len() > 2, "expected host interfaces besides lo: {lines:?}");
}

// ── filesystem ───────────────────────────────────────────────────────────────

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn rootfs_is_read_only() {
    let out = run(&spec(&["touch", "/should-not-exist"]));
    assert_ne!(out.status, 0);
    assert!(out.stderr.contains("Read-only file system"), "{out:#?}");
    assert!(!alpine_rootfs().join("should-not-exist").exists());
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn dev_has_the_default_devices_and_links() {
    let out =
        run(&sh("echo x > /dev/null && head -c 16 /dev/urandom | wc -c && test -c /dev/zero && test -c /dev/full \
         && test -c /dev/tty && readlink /dev/ptmx && readlink /dev/fd && test -c /dev/pts/ptmx && echo ok"));
    assert_eq!(out.ok().split_whitespace().collect::<Vec<_>>(), ["16", "pts/ptmx", "/proc/self/fd", "ok"]);
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn bind_mount_read_only() {
    let host_dir = tempfile::tempdir().unwrap();
    std::fs::write(host_dir.path().join("hello"), "from the host\n").unwrap();
    // Mount points that don't exist are created in the rootfs (before it is
    // made read-only), so tests use directories Alpine already has.
    let mut s = sh("cat /mnt/hello; touch /mnt/nope 2>&1 || echo refused");
    add_mount(&mut s, "/mnt", "bind", host_dir.path().to_str().unwrap(), &["rbind", "ro", "nosuid"]);
    let out = run(&s);
    assert!(out.ok().starts_with("from the host\n"), "{out:#?}");
    assert!(out.stdout.contains("refused"));
    assert!(!host_dir.path().join("nope").exists());
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn tmpfs_options_reach_the_filesystem() {
    let mut s = sh("stat -c %a /tmp; grep ' /tmp ' /proc/self/mountinfo");
    add_mount(&mut s, "/tmp", "tmpfs", "scratch", &["nosuid", "nodev", "mode=700", "size=1m"]);
    let out = run(&s);
    let lines: Vec<&str> = out.ok().lines().collect();
    assert_eq!(lines[0], "700");
    assert!(lines[1].contains("size=1024k") && lines[1].contains("nosuid,nodev"), "{}", lines[1]);
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn cwd_is_created_and_entered() {
    // Under /dev (a tmpfs), so nothing is created in the shared rootfs.
    let mut s = spec(&["pwd"]);
    let mut p = s.process().clone().unwrap();
    p.set_cwd("/dev/work/dir".into());
    s.set_process(Some(p));
    assert_eq!(run(&s).ok().trim(), "/dev/work/dir");
}

// ── process ──────────────────────────────────────────────────────────────────

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn exit_status_is_propagated() {
    assert_eq!(run(&sh("exit 42")).status, 42);
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn env_and_umask() {
    let mut s = sh("echo $GREETING; umask");
    let mut p = s.process().clone().unwrap();
    p.set_env(Some(vec!["PATH=/bin:/usr/bin".into(), "GREETING=hi".into()]));
    s.set_process(Some(p));
    assert_eq!(run(&s).ok().split_whitespace().collect::<Vec<_>>(), ["hi", "0022"]);
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn user_switch_drops_all_capabilities() {
    // `Groups:` is the kernel's supplementary list, exactly what setgroups set
    // (`id -G` would also print the primary gid first).
    let mut s = sh("id -u; id -g; grep -E '^(Groups|CapEff)' /proc/self/status");
    let mut p = s.process().clone().unwrap();
    let mut u = p.user().clone();
    u.set_uid(1000);
    u.set_gid(1000);
    u.set_additional_gids(Some(vec![10, 1000]));
    p.set_user(u);
    s.set_process(Some(p));
    let out = run(&s);
    let lines: Vec<&str> = out.ok().lines().collect();
    assert_eq!(lines[..2], ["1000", "1000"]);
    assert_eq!(lines[2].split_whitespace().collect::<Vec<_>>(), ["Groups:", "10", "1000"]);
    assert_eq!(lines[3].split_whitespace().last(), Some("0000000000000000"));
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn rlimits_are_applied() {
    let mut s = sh("ulimit -n; ulimit -c");
    let mut p = s.process().clone().unwrap();
    let rl = |t, n: u64| PosixRlimitBuilder::default().typ(t).soft(n).hard(n).build().unwrap();
    p.set_rlimits(Some(vec![rl(PosixRlimitType::RlimitNofile, 512), rl(PosixRlimitType::RlimitCore, 0)]));
    s.set_process(Some(p));
    assert_eq!(run(&s).ok().split_whitespace().collect::<Vec<_>>(), ["512", "0"]);
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn nothing_leaks_into_the_container() {
    // fds: only stdio, plus the directory `ls` opens itself (3).
    let out = run(&spec(&["ls", "/proc/self/fd"]));
    assert_eq!(out.ok().split_whitespace().collect::<Vec<_>>(), ["0", "1", "2", "3"]);
    // Signals: nothing ignored (Rust's SIGPIPE) or blocked (our forwarding mask).
    let out = run(&spec(&["grep", "-E", "^Sig(Ign|Blk)", "/proc/self/status"]));
    for line in out.ok().lines() {
        assert!(line.ends_with("0000000000000000"), "{line}");
    }
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn no_new_privileges_is_set() {
    assert_eq!(run(&spec(&["grep", "NoNewPrivs", "/proc/self/status"])).ok().split_whitespace().last(), Some("1"));
}

// ── signals ──────────────────────────────────────────────────────────────────

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn pid_1_ignores_unhandled_signals_from_inside() {
    // Inside its own PID namespace, init only receives signals it has a
    // handler for, even SIGKILL. This is why `docker run --init` exists.
    assert_eq!(run(&sh("kill -TERM $$; kill -KILL $$; echo still-here")).ok().trim(), "still-here");
}

/// Spawns `script` (which must print "ready") and waits for that line.
fn spawn_ready(script: &str, extra: &[&str]) -> Running {
    let mut r = TestBundle::new(&sh(script)).spawn(extra);
    let mut line = String::new();
    BufReader::new(r.child.stdout.as_mut().unwrap()).read_line(&mut line).unwrap();
    assert_eq!(line.trim(), "ready");
    r
}

fn wait_status(child: &mut std::process::Child) -> i32 {
    let start = Instant::now();
    loop {
        if let Some(s) = child.try_wait().unwrap() {
            return s.code().unwrap_or(-1);
        }
        if start.elapsed() > Duration::from_secs(10) {
            let _ = child.kill();
            panic!("container did not exit within 10s");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn sigterm_to_runc_is_forwarded_to_init() {
    let mut r = spawn_ready("trap 'exit 7' TERM; echo ready; while :; do sleep 0.1; done", &[]);
    kill(Pid::from_raw(r.child.id() as i32), Signal::SIGTERM).unwrap();
    assert_eq!(wait_status(&mut r.child), 7);
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn sigkill_from_the_host_gives_137_and_pid_file_is_right() {
    let pid_file = tempfile::tempdir().unwrap();
    let pid_path = pid_file.path().join("init.pid");
    let mut r = spawn_ready("echo ready; while :; do sleep 0.1; done", &["--pid-file", pid_path.to_str().unwrap()]);
    // The pid file is written once rustlet-runc sees execve succeed, which
    // can be a moment after the program has already printed "ready".
    let start = Instant::now();
    let pid: i32 = loop {
        if let Ok(s) = std::fs::read_to_string(&pid_path) {
            break s.trim().parse().unwrap();
        }
        assert!(start.elapsed() < Duration::from_secs(5), "pid file never appeared");
        std::thread::sleep(Duration::from_millis(10));
    };
    // The pid file holds the *host* PID of the container's init.
    let nspid = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    assert!(nspid.lines().any(|l| l.starts_with("NSpid:") && l.trim_end().ends_with("\t1")), "{nspid}");
    kill(Pid::from_raw(pid), Signal::SIGKILL).unwrap();
    assert_eq!(wait_status(&mut r.child), 137);
}

// ── refusals ─────────────────────────────────────────────────────────────────

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn missing_program_exits_127() {
    let out = run(&spec(&["no-such-program"]));
    assert_eq!(out.status, 127, "{out:#?}");
    assert!(out.stderr.contains("not found"), "{}", out.stderr);
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn setup_failures_are_not_mistaken_for_command_not_found() {
    // ENOENT from a mount must exit 1 with the mount in the message; only a
    // failed execve of the program maps to 127/126.
    let mut s = spec(&["true"]);
    add_mount(&mut s, "/mnt", "bind", "/nonexistent-rustlet-source", &["bind"]);
    let out = run(&s);
    assert_eq!(out.status, 1, "{out:#?}");
    assert!(
        out.stderr.contains("/nonexistent-rustlet-source") && out.stderr.contains("No such file"),
        "{}",
        out.stderr
    );
    // A directory is found in $PATH-less lookup but can't be executed: 126.
    let out = run(&spec(&["/etc"]));
    assert_eq!(out.status, 126, "{out:#?}");
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn unsupported_features_are_refused_up_front() {
    let mut s = spec(&["true"]);
    s.set_hooks(Some(Default::default()));
    let out = run(&s);
    assert_eq!(out.status, 1);
    assert!(out.stderr.contains("hooks (not planned)"), "{}", out.stderr);
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn refuses_the_host_root_and_mounts_over_proc() {
    let mut s = spec(&["true"]);
    let mut r = s.root().clone().unwrap();
    r.set_path("/".into());
    s.set_root(Some(r));
    let out = run(&s);
    assert_eq!(out.status, 1);
    assert!(out.stderr.contains("host"), "{}", out.stderr);

    let mut s = spec(&["true"]);
    add_mount(&mut s, "/proc/sys", "tmpfs", "tmpfs", &[]);
    let out = run(&s);
    assert_eq!(out.status, 1);
    assert!(out.stderr.contains("not allowed"), "{}", out.stderr);
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn container_dies_with_rustlet_runc() {
    // Foreground `run` sets PR_SET_PDEATHSIG(SIGKILL) in init, so SIGKILLing
    // rustlet-runc (which is what dropping `Running` does) takes the whole
    // container with it instead of leaving an orphan.
    let pid_file = tempfile::tempdir().unwrap();
    let pid_path = pid_file.path().join("init.pid");
    let r = spawn_ready("echo ready; while :; do sleep 0.1; done", &["--pid-file", pid_path.to_str().unwrap()]);
    let start = Instant::now();
    let init = loop {
        if let Ok(s) = std::fs::read_to_string(&pid_path) {
            break Pid::from_raw(s.trim().parse().unwrap());
        }
        assert!(start.elapsed() < Duration::from_secs(5), "pid file never appeared");
        std::thread::sleep(Duration::from_millis(10));
    };
    drop(r);
    let start = Instant::now();
    // kill(pid, 0) succeeds as long as the process exists, zombies included;
    // ESRCH means init died and whoever adopted it has reaped it.
    while kill(init, None).is_ok() {
        assert!(start.elapsed() < Duration::from_secs(5), "container init {init} outlived rustlet-runc");
        std::thread::sleep(Duration::from_millis(20));
    }
}

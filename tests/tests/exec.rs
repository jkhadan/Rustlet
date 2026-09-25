//! Phase 2b: `rustlet-runc exec`, a new process in an existing container.
//!
//! It must end up exactly where the container's init is (all of its
//! namespaces, its cgroup, its root filesystem) with the container's process
//! settings (user, env, cwd, rlimits, capabilities, no_new_privs, seccomp)
//! unless the command line overrides them. Run with `cargo xtask itest -- ex_`.

use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::os::fd::AsFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::Stdio;
use std::time::{Duration, Instant};

use rustlet_itests::e2e::*;
use rustlet_itests::*;
use rustlet_runtime::oci_spec::runtime::{
    LinuxNamespaceType, LinuxPidsBuilder, LinuxResourcesBuilder, LinuxSeccompAction, LinuxSeccompBuilder,
    LinuxSyscallBuilder, PosixRlimitBuilder, PosixRlimitType, Spec,
};
use rustlet_runtime::spec::to_pretty_json;

/// `grep -E '^(Cap|NoNewPrivs|Seccomp)' /proc/self/status`.
const STATUS: &str = "grep -E '^(Cap|NoNewPrivs|Seccomp)' /proc/self/status";

/// A started container whose init is `sleep 3600`, in its own cgroup.
#[track_caller]
fn sleeper(cgroup: &str) -> Container {
    sleeper_with(spec(&["sleep", "3600"]), cgroup)
}

/// `s` (whose program should keep running), started in its own cgroup.
#[track_caller]
fn sleeper_with(mut s: Spec, cgroup: &str) -> Container {
    set_cgroup(&mut s, cgroup);
    Container::started(&s)
}

#[track_caller]
fn read_pid_file(path: &std::path::Path) -> i32 {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("pid file {}: {e}", path.display()));
    text.trim().parse().unwrap_or_else(|e| panic!("pid file {} holds {text:?}: {e}", path.display()))
}

/// Starts `exec -d --pid-file … <argv…>` and returns the new process's host
/// pid and start time.
#[track_caller]
fn exec_detached(c: &Container, opts: &[&str], argv: &[&str]) -> (i32, u64) {
    let dir = tempfile::tempdir().unwrap();
    let pid_file = dir.path().join("exec.pid");
    let mut all = vec!["--detach", "--pid-file", pid_file.to_str().unwrap()];
    all.extend(opts);
    c.exec_in(&all, argv).ok();
    let pid = read_pid_file(&pid_file);
    let start = starttime(pid).unwrap_or_else(|| panic!("the exec'd process {pid} is not running"));
    (pid, start)
}

/// Runs `f` (which makes `rustlet-runc` connect to `listener`) while
/// accepting on the listener; returns `f`'s result and the connection.
fn accept_during<T: Send>(listener: &UnixListener, f: impl FnOnce() -> T + Send) -> (T, UnixStream) {
    listener.set_nonblocking(true).unwrap();
    std::thread::scope(|scope| {
        let task = scope.spawn(f);
        let deadline = Instant::now() + TIMEOUT;
        let stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => panic!("accept on the console socket: {e}"),
            }
            if task.is_finished() {
                // It may have connected just before exiting.
                if let Ok((stream, _)) = listener.accept() {
                    break stream;
                }
                panic!("rustlet-runc never connected to the console socket");
            }
            assert!(Instant::now() < deadline, "rustlet-runc never connected to the console socket");
            std::thread::sleep(Duration::from_millis(20));
        };
        (task.join().unwrap(), stream)
    })
}

// ── where the process ends up ────────────────────────────────────────────────

/// The basics: the command runs, its output comes back, and the container
/// (and its init) keep running afterwards.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn ex_runs_a_command_and_the_container_keeps_running() {
    let c = sleeper("ex-basic");
    let (pid, start) = (c.pid(), starttime(c.pid()).unwrap());
    assert_eq!(c.exec_in(&[], &["echo", "hello"]).ok(), "hello\n");
    assert_eq!(c.status(), "running");
    assert!(alive(pid, start), "init died");
    // And again: exec leaves nothing behind that breaks the next one.
    assert_eq!(c.exec_in(&[], &["echo", "again"]).ok(), "again\n");
}

/// The process joins every one of init's namespaces (inode for inode), and
/// shares the host's user and time namespaces just as init does.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn ex_joins_every_namespace_of_init() {
    let c = sleeper("ex-namespaces");
    let kinds = ["cgroup", "ipc", "mnt", "net", "pid", "uts", "user", "time"];
    let script = format!("for k in {}; do readlink /proc/self/ns/$k; done", kinds.join(" "));
    let out = c.exec_in(&[], &["sh", "-c", &script]);
    let inside: Vec<&str> = out.ok().lines().collect();
    assert_eq!(inside.len(), kinds.len(), "{out:#?}");
    for (kind, got) in kinds.iter().zip(inside) {
        let init = std::fs::read_link(format!("/proc/{}/ns/{kind}", c.pid())).unwrap();
        assert_eq!(got, init.to_str().unwrap(), "{kind} namespace differs from init's");
    }
}

/// The process is in the container's cgroup: inside, its cgroup namespace
/// root (`0::/`); on the host, in the container cgroup's `cgroup.procs`.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn ex_is_placed_in_the_container_cgroup() {
    let c = sleeper("ex-cgroup");
    assert_eq!(c.exec_in(&[], &["cat", "/proc/self/cgroup"]).ok().trim(), "0::/");
    let (pid, _) = exec_detached(&c, &[], &["sleep", "3600"]);
    let host_view = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).unwrap();
    assert_eq!(host_view.trim(), format!("0::{}", c.cgroup()));
    assert!(cgroup_procs(c.cgroup()).contains(&pid), "{pid} is not in {}", c.cgroup());
}

/// Inside, the process sees the container's world: not PID 1 but init is
/// there, the container's hostname and the container's root filesystem.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn ex_sees_the_container_pid_namespace_hostname_and_rootfs() {
    let mut s = spec(&["sleep", "3600"]);
    s.set_hostname(Some("exec-host".into()));
    let c = sleeper_with(s, "ex-world");
    let out = c.exec_in(
        &[],
        &["sh", "-c", "echo $$; tr '\\0' ' ' < /proc/1/cmdline; echo; hostname; cat /etc/alpine-release"],
    );
    let lines: Vec<&str> = out.ok().lines().collect();
    assert_eq!(lines.len(), 4, "{out:#?}");
    assert_ne!(lines[0], "1", "the exec'd process is PID 1");
    assert!(lines[0].parse::<u32>().is_ok_and(|p| p > 1), "{out:#?}");
    assert_eq!(lines[1].trim(), "sleep 3600");
    assert_eq!(lines[2], "exec-host");
    let release = std::fs::read_to_string(alpine_rootfs().join("etc/alpine-release")).unwrap();
    assert_eq!(lines[3], release.trim());
}

/// A container that shares the host's PID, network and IPC namespaces: exec
/// joins only what differs from the caller (setns into one's own namespace
/// isn't needed), and still ends up with init's.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn ex_works_when_the_container_shares_host_namespaces() {
    let mut s = spec(&["sleep", "3600"]);
    for t in [LinuxNamespaceType::Pid, LinuxNamespaceType::Network, LinuxNamespaceType::Ipc] {
        without_namespace(&mut s, t);
    }
    let c = sleeper_with(s, "ex-host-namespaces");
    let kinds = ["pid", "net", "ipc", "mnt", "uts", "cgroup"];
    let script = format!("for k in {}; do readlink /proc/self/ns/$k; done", kinds.join(" "));
    let out = c.exec_in(&[], &["sh", "-c", &script]);
    let inside: Vec<&str> = out.ok().lines().collect();
    assert_eq!(inside.len(), kinds.len(), "{out:#?}");
    for (kind, got) in kinds.iter().zip(inside) {
        let init = std::fs::read_link(format!("/proc/{}/ns/{kind}", c.pid())).unwrap();
        assert_eq!(got, init.to_str().unwrap(), "{kind} namespace differs from init's");
    }
    assert_eq!(c.exec_in(&[], &["hostname"]).ok().trim(), "rustlet");
}

/// A created container's init is still the runtime (waiting for `start`),
/// and it is not dumpable: a process exec'd into the container can't read
/// its exe link, environment or memory (the CVE-2019-5736 route in). After
/// `start` init is the container's program and the link is readable.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn ex_a_created_init_cannot_be_inspected_from_inside() {
    let mut s = spec(&["sleep", "3600"]);
    set_cgroup(&mut s, "ex-created-dumpable");
    let c = Container::created(&s);
    let script = "readlink /proc/1/exe || echo exe-denied; cat /proc/1/environ >/dev/null || echo environ-denied; \
                  head -c1 /proc/1/mem >/dev/null || echo mem-denied";
    let out = c.exec_in(&[], &["sh", "-c", script]);
    assert_eq!(out.ok().lines().collect::<Vec<_>>(), ["exe-denied", "environ-denied", "mem-denied"], "{out:#?}");
    c.start().ok();
    let out = c.exec_in(&[], &["readlink", "/proc/1/exe"]);
    assert_eq!(out.ok().trim(), "/bin/busybox", "{out:#?}");
}

// ── exit status and stdio ────────────────────────────────────────────────────

/// The exit status is the process's, shell-style: its code, 128+signal, 127
/// for a program that doesn't exist and 126 for one that can't be executed.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn ex_exit_status_is_the_processes() {
    let c = sleeper("ex-status");
    assert_eq!(c.exec_in(&[], &["sh", "-c", "exit 7"]).status, 7);
    assert_eq!(c.exec_in(&[], &["sh", "-c", "kill -KILL $$"]).status, 137);
    let out = c.exec_in(&[], &["no-such-program"]);
    out.failed_with(127);
    assert!(out.stderr.contains("no-such-program"), "{out:#?}");
    c.exec_in(&[], &["/etc"]).failed_with(126);
    assert_eq!(c.status(), "running");
}

/// stdin, stdout and stderr are the caller's.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn ex_stdio_flows_through() {
    let c = sleeper("ex-stdio");
    let out = c.exec_in(&[], &["sh", "-c", "echo out; echo err >&2"]);
    assert_eq!(out.ok(), "out\n");
    assert!(out.stderr.lines().any(|l| l == "err"), "{out:#?}");
    let out = exec_input(c.exec_command(&[], &["cat"]), Some(b"from stdin\n"), TIMEOUT);
    assert_eq!(out.ok(), "from stdin\n");
}

// ── inherited from the container ─────────────────────────────────────────────

/// Without overrides the process runs as the container's user, with its
/// supplementary groups, env, cwd, rlimits and umask.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn ex_inherits_user_env_cwd_and_rlimits() {
    let mut s = spec(&["sleep", "3600"]);
    set_user(&mut s, 1000, 1000, &[10]);
    set_env(&mut s, &["PATH=/usr/bin:/bin", "GREETING=hi"]);
    edit_process(&mut s, |p| {
        p.set_cwd("/dev/shm".into());
        let rl = PosixRlimitBuilder::default().typ(PosixRlimitType::RlimitNofile).soft(512u64).hard(512u64);
        p.set_rlimits(Some(vec![rl.build().unwrap()]));
    });
    let c = sleeper_with(s, "ex-inherit-process");
    let out = c.exec_in(
        &[],
        &[
            "sh",
            "-c",
            "id -u; id -g; grep ^Groups: /proc/self/status; echo $GREETING; pwd; ulimit -n; umask; echo $PATH",
        ],
    );
    assert_eq!(
        norm_lines(out.ok()),
        ["1000", "1000", "Groups: 10", "hi", "/dev/shm", "512", "0022", "/usr/bin:/bin"],
        "{out:#?}"
    );
}

/// The default container's security settings carry over: the capability
/// masks, no_new_privs, one seccomp filter (and it works: unshare fails).
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn ex_inherits_capabilities_no_new_privs_and_seccomp() {
    let c = sleeper("ex-inherit-security");
    let out = c.exec_in(&[], &["sh", "-c", &format!("{STATUS}; unshare -U true || echo unshare-denied")]);
    let text = out.ok();
    for set in ["CapPrm", "CapEff", "CapBnd"] {
        assert_eq!(status_hex(text, set), DEFAULT_CAP_MASK, "{set}: {out:#?}");
    }
    assert_eq!(status_hex(text, "CapInh"), 0, "{out:#?}");
    assert_eq!(status_hex(text, "CapAmb"), 0, "{out:#?}");
    assert_eq!(status_field(text, "NoNewPrivs"), Some("1"), "{out:#?}");
    assert_eq!(status_field(text, "Seccomp"), Some("2"), "{out:#?}");
    assert_eq!(status_field(text, "Seccomp_filters"), Some("1"), "{out:#?}");
    assert!(text.lines().any(|l| l == "unshare-denied"), "{out:#?}");
}

/// It is the *container's* settings that carry over, not the defaults: a
/// container with its own capability sets and seccomp profile passes those on.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn ex_inherits_the_containers_own_capabilities_and_profile() {
    let mut s = spec(&["sleep", "3600"]);
    let bounding = ["CAP_CHOWN", "CAP_KILL", "CAP_NET_RAW"];
    let granted = ["CAP_KILL", "CAP_NET_RAW"];
    set_capabilities(
        &mut s,
        CapSets { bounding: &bounding, effective: &granted, permitted: &granted, ..CapSets::default() },
    );
    let mkdir = LinuxSyscallBuilder::default()
        .names(vec!["mkdir".to_string(), "mkdirat".to_string()])
        .action(LinuxSeccompAction::ScmpActErrno)
        .errno_ret(1u32)
        .build()
        .unwrap();
    let profile = LinuxSeccompBuilder::default()
        .default_action(LinuxSeccompAction::ScmpActAllow)
        .syscalls(vec![mkdir])
        .build()
        .unwrap();
    edit_linux(&mut s, |l| {
        l.set_seccomp(Some(profile));
    });
    let c = sleeper_with(s, "ex-inherit-custom");
    let out = c.exec_in(&[], &["sh", "-c", &format!("{STATUS}; mkdir /dev/shm/d || echo mkdir-denied")]);
    let text = out.ok();
    assert_eq!(status_hex(text, "CapBnd"), cap_mask(&bounding), "{out:#?}");
    assert_eq!(status_hex(text, "CapEff"), cap_mask(&granted), "{out:#?}");
    assert_eq!(status_field(text, "Seccomp"), Some("2"), "{out:#?}");
    assert!(text.lines().any(|l| l == "mkdir-denied"), "{out:#?}");
    assert!(out.stderr.contains("Operation not permitted"), "{out:#?}");
}

/// Without no_new_privs, a filter can only be loaded while CAP_SYS_ADMIN is
/// still held, i.e. before the switch to a non-root user: the exec'd process
/// of such a container still gets it.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn ex_filter_is_loaded_without_no_new_privs_for_a_non_root_user() {
    let mut s = spec(&["sleep", "3600"]);
    set_no_new_privileges(&mut s, false);
    set_user(&mut s, 1000, 1000, &[]);
    let c = sleeper_with(s, "ex-no-nnp-user");
    let out = c.exec_in(&[], &["sh", "-c", STATUS]);
    let text = out.ok();
    assert_eq!(status_field(text, "NoNewPrivs"), Some("0"), "{out:#?}");
    assert_eq!(status_field(text, "Seccomp"), Some("2"), "{out:#?}");
    assert_eq!(status_field(text, "Seccomp_filters"), Some("1"), "{out:#?}");
}

/// The base process is the config.json of `create` time: editing the bundle
/// afterwards changes nothing for exec.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn ex_uses_the_config_from_create_time() {
    let mut s = spec(&["sleep", "3600"]);
    set_env(&mut s, &["PATH=/usr/bin:/bin", "GREETING=before"]);
    let c = sleeper_with(s.clone(), "ex-config-copy");
    set_env(&mut s, &["PATH=/usr/bin:/bin", "GREETING=after"]);
    set_user(&mut s, 1000, 1000, &[]);
    std::fs::write(c.bundle_dir().join("config.json"), to_pretty_json(&s)).unwrap();
    let out = c.exec_in(&[], &["sh", "-c", "echo $GREETING; id -u"]);
    assert_eq!(out.ok().lines().collect::<Vec<_>>(), ["before", "0"], "{out:#?}");
}

// ── overrides ────────────────────────────────────────────────────────────────

/// `-e` overrides and extends the env (PATH stays), `--cwd`, `-u UID:GID` and
/// `-g` replace the rest.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn ex_overrides_env_cwd_user_and_groups() {
    let mut s = spec(&["sleep", "3600"]);
    set_env(&mut s, &["PATH=/usr/bin:/bin", "GREETING=hi"]);
    let c = sleeper_with(s, "ex-overrides");
    let out = c.exec_in(
        &["-e", "GREETING=bye", "-e", "EXTRA=1", "--cwd", "/etc", "-u", "1000:1000", "-g", "10", "-g", "20"],
        &[
            "sh",
            "-c",
            "echo $GREETING $EXTRA; echo $PATH; pwd; id -u; id -g; grep ^Groups: /proc/self/status; \
             env | grep -c ^GREETING=",
        ],
    );
    // The last line: GREETING was replaced, not added a second time.
    assert_eq!(
        norm_lines(out.ok()),
        ["bye 1", "/usr/bin:/bin", "/etc", "1000", "1000", "Groups: 10 20", "1"],
        "{out:#?}"
    );
}

/// `-u UID` without a GID changes only the uid; the gid stays the
/// container's (as with runc).
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn ex_user_without_a_gid_keeps_the_containers_gid() {
    let mut s = spec(&["sleep", "3600"]);
    set_user(&mut s, 0, 100, &[]);
    let c = sleeper_with(s, "ex-user-uid-only");
    let out = c.exec_in(&["-u", "1000"], &["sh", "-c", "id -u; id -g"]);
    assert_eq!(out.ok().lines().collect::<Vec<_>>(), ["1000", "100"], "{out:#?}");
}

/// `--cap` adds to bounding, effective and permitted for root (not to
/// inheritable or ambient).
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn ex_cap_adds_a_capability_for_root() {
    let c = sleeper("ex-cap-root");
    let out = c.exec_in(&["--cap", "CAP_NET_RAW"], &["sh", "-c", STATUS]);
    let want = DEFAULT_CAP_MASK | cap_bit("CAP_NET_RAW");
    for set in ["CapPrm", "CapEff", "CapBnd"] {
        assert_eq!(status_hex(out.ok(), set), want, "{set}: {out:#?}");
    }
    assert_eq!(status_hex(out.ok(), "CapInh"), 0, "{out:#?}");
    assert_eq!(status_hex(out.ok(), "CapAmb"), 0, "{out:#?}");
}

/// `--cap` never touches the inheritable set (runc's fix for
/// CVE-2022-29162), so for a non-root user, whose capabilities only survive
/// `execve` through ambient, it adds nothing: uid 1000 still can't listen on
/// port 80.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn ex_cap_never_adds_inheritable_so_a_non_root_user_gains_nothing() {
    let c = sleeper("ex-cap-user");
    let out = c.exec_in(
        &["-u", "1000:1000", "--cap", "CAP_NET_BIND_SERVICE"],
        &["sh", "-c", &format!("{STATUS}; {LISTEN_ON_80}")],
    );
    let text = out.ok();
    for set in ["CapInh", "CapPrm", "CapEff", "CapAmb"] {
        assert_eq!(status_hex(text, set), 0, "{set}: {out:#?}");
    }
    assert_eq!(status_hex(text, "CapBnd"), DEFAULT_CAP_MASK | cap_bit("CAP_NET_BIND_SERVICE"), "{out:#?}");
    assert!(!text.lines().any(|l| l == "listening"), "{out:#?}");
}

/// `--cap CAP_MKNOD` would sidestep the create-time refusal (no device
/// filter before Phase 2c), so exec refuses it too.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn ex_cap_mknod_is_refused() {
    let c = sleeper("ex-cap-mknod");
    c.exec_in(&["--cap", "CAP_MKNOD"], &["true"]).refused("Phase 2c");
    assert_eq!(c.status(), "running");
}

/// `--no-new-privs` sets the flag for a container that doesn't have it.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn ex_no_new_privs_flag() {
    let mut s = spec(&["sleep", "3600"]);
    set_no_new_privileges(&mut s, false);
    let c = sleeper_with(s, "ex-nnp");
    let nnp = |opts: &[&str]| {
        let out = c.exec_in(opts, &["grep", "NoNewPrivs", "/proc/self/status"]);
        status_field(out.ok(), "NoNewPrivs").map(str::to_owned)
    };
    assert_eq!(nnp(&[]).as_deref(), Some("0"));
    assert_eq!(nnp(&["--no-new-privs"]).as_deref(), Some("1"));
}

/// `-p process.json` runs that process as written (args, env, user, cwd).
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn ex_process_json_is_used() {
    let c = sleeper("ex-process-json");
    let mut s = spec(&["sh", "-c", "echo $FOO; id -u; pwd"]);
    set_env(&mut s, &["PATH=/usr/bin:/bin", "FOO=from-json"]);
    set_user(&mut s, 1000, 1000, &[]);
    edit_process(&mut s, |p| {
        p.set_cwd("/tmp".into());
    });
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("process.json");
    std::fs::write(&file, serde_json::to_string_pretty(s.process().as_ref().unwrap()).unwrap()).unwrap();
    let out = c.exec_in(&["-p", file.to_str().unwrap()], &[]);
    assert_eq!(out.ok().lines().collect::<Vec<_>>(), ["from-json", "1000", "/tmp"], "{out:#?}");
}

/// A process.json without `capabilities` must not come out with more than
/// the container could have: either it is refused (as `create` refuses
/// such a process) or it gets at most the container's set.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn ex_process_json_without_capabilities_gains_nothing() {
    let c = sleeper("ex-process-json-nocaps");
    let mut s = spec(&["sh", "-c", STATUS]);
    edit_process(&mut s, |p| {
        p.set_capabilities(None);
    });
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("process.json");
    std::fs::write(&file, serde_json::to_string_pretty(s.process().as_ref().unwrap()).unwrap()).unwrap();
    let out = c.exec_in(&["-p", file.to_str().unwrap()], &[]);
    if out.status != 0 {
        out.refused("capabilities");
        eprintln!("refused: {}", out.stderr.trim());
        return;
    }
    for set in ["CapPrm", "CapEff", "CapBnd", "CapInh", "CapAmb"] {
        let mask = status_hex(&out.stdout, set);
        assert_eq!(mask & !DEFAULT_CAP_MASK, 0, "{set} {mask:#x} exceeds the container's capabilities: {out:#?}");
    }
}

/// CAP_MKNOD in a process.json is refused like `--cap CAP_MKNOD`.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn ex_process_json_with_cap_mknod_is_refused() {
    let c = sleeper("ex-process-json-mknod");
    let mut s = spec(&["true"]);
    let caps: Vec<&str> = DEFAULT_CAPS.iter().copied().chain(["CAP_MKNOD"]).collect();
    set_capabilities(&mut s, CapSets::root(&caps));
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("process.json");
    std::fs::write(&file, serde_json::to_string_pretty(s.process().as_ref().unwrap()).unwrap()).unwrap();
    c.exec_in(&["-p", file.to_str().unwrap()], &[]).refused("Phase 2c");
}

// ── detached, and the container's state ──────────────────────────────────────

/// `-d` returns as soon as the process runs, and `--pid-file` holds its host
/// pid: a process in the container's PID namespace that isn't init.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn ex_detach_returns_at_once_and_writes_the_pid_file() {
    let c = sleeper("ex-detach");
    let t = Instant::now();
    let (pid, start) = exec_detached(&c, &[], &["sleep", "3600"]);
    assert!(t.elapsed() < PROMPT, "exec -d took {:?}", t.elapsed());
    assert!(alive(pid, start));
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    let nspid: Vec<&str> = status_field(&status, "NSpid").unwrap().split_whitespace().collect();
    assert_eq!(nspid.len(), 2, "{status}");
    assert_eq!(nspid[0], pid.to_string());
    assert_ne!(nspid[1], "1", "the exec'd process is PID 1 in the container");
}

/// exec works on a `created` container too (init is waiting for `start`),
/// and doesn't start it.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn ex_works_on_a_created_container() {
    let mut s = spec(&["sleep", "3600"]);
    set_cgroup(&mut s, "ex-created");
    let c = Container::created(&s);
    assert_eq!(c.exec_in(&[], &["echo", "hi"]).ok(), "hi\n");
    assert_eq!(c.status(), "created");
    c.start().ok();
    assert_eq!(c.status(), "running");
}

/// A paused container can't run anything new: refused, and fine again after
/// `resume`.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn ex_is_refused_while_paused() {
    let c = sleeper("ex-paused");
    c.cmd(&["pause"]).ok();
    c.wait_for_status("paused", PROMPT);
    c.exec_in(&[], &["true"]).refused("paused");
    c.cmd(&["resume"]).ok();
    c.wait_for_status("running", PROMPT);
    assert_eq!(c.exec_in(&[], &["echo", "ok"]).ok(), "ok\n");
}

/// A stopped container, or an id nobody knows, is refused.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn ex_is_refused_for_stopped_and_unknown_containers() {
    let mut s = spec(&["true"]);
    set_cgroup(&mut s, "ex-stopped");
    let c = Container::started(&s);
    c.wait_for_status("stopped", PROMPT);
    c.exec_in(&[], &["true"]).failed();
    assert_eq!(c.status(), "stopped");

    let mut cmd = runc(&["exec"]);
    cmd.arg(format!("ex-no-such-container-{}", std::process::id())).arg("true");
    exec(cmd).failed();
}

/// A full pids.max makes the exec fail cleanly (clone into the cgroup
/// fails with EAGAIN) instead of hanging, and the container carries on.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn ex_fails_cleanly_when_the_pids_limit_is_reached() {
    let mut s = spec(&["sleep", "3600"]);
    let pids = LinuxPidsBuilder::default().limit(1i64).build().unwrap();
    set_resources(&mut s, LinuxResourcesBuilder::default().pids(pids).build().unwrap());
    let c = sleeper_with(s, "ex-pids-full");
    c.exec_in(&[], &["true"]).failed();
    assert_eq!(c.status(), "running");
}

/// Several execs at once all work (no lock or state file is held for the
/// lifetime of an exec).
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn ex_concurrent_execs_all_work() {
    let c = sleeper("ex-concurrent");
    let outs: Vec<CmdOut> = std::thread::scope(|scope| {
        let c = &c;
        let handles: Vec<_> = (0..6).map(|i| scope.spawn(move || c_exec_echo(c, i))).collect::<Vec<_>>();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    for (i, out) in outs.iter().enumerate() {
        assert_eq!(out.ok(), format!("exec {i}\n"), "{out:#?}");
    }
}

/// `sh -c 'sleep 0.3; echo exec <i>'` through exec.
fn c_exec_echo(c: &Container, i: usize) -> CmdOut {
    c.exec_in(&[], &["sh", "-c", &format!("sleep 0.3; echo exec {i}")])
}

/// When init dies, the PID namespace goes with it: exec'd processes die too.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn ex_processes_die_with_init() {
    let c = sleeper("ex-die-with-init");
    let (pid, start) = exec_detached(&c, &[], &["sleep", "3600"]);
    c.kill(false, Some("KILL")).ok();
    wait_until("the exec'd process to die with init", PROMPT, || !alive(pid, start));
    c.wait_for_status("stopped", PROMPT);
}

// ── terminals ────────────────────────────────────────────────────────────────

/// `-t -d --console-socket` sends the new process's PTY master over the
/// socket (the same protocol as `create`); both directions work.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn ex_tty_master_goes_to_the_console_socket() {
    let c = sleeper("ex-tty-socket");
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("console.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let (out, stream) = accept_during(&listener, || {
        c.exec_in(
            &["-t", "-d", "--console-socket", sock.to_str().unwrap()],
            &["sh", "-c", "tty; echo ready; read x; echo got-$x; sleep 1"],
        )
    });
    out.ok();
    stream.set_read_timeout(Some(PROMPT)).unwrap();
    let master = rustlet_runtime::console::receive_master(stream.as_fd()).expect("no PTY master on the console socket");
    let master = File::from(master);
    let mut seen = String::new();
    pty_read_until(&master, &mut seen, "ready", PROMPT);
    assert!(seen.contains("/dev/pts/"), "{seen:?}");
    (&master).write_all(b"ping\n").unwrap();
    pty_read_until(&master, &mut seen, "got-ping", PROMPT);
}

/// The container's own `terminal: true` belongs to init: an exec without
/// `-t` gets the caller's stdio, not a PTY (and needs no console socket).
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn ex_without_tty_the_containers_terminal_setting_is_not_used() {
    let mut s = spec(&["sleep", "3600"]);
    set_terminal(&mut s, None);
    set_cgroup(&mut s, "ex-container-tty");
    let mut c = Container::new(&s);
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("console.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let (created, stream) = accept_during(&listener, || c.create(&["--console-socket", sock.to_str().unwrap()]));
    created.ok();
    // Keep init's PTY master open for the rest of the test.
    stream.set_read_timeout(Some(PROMPT)).unwrap();
    let _master = rustlet_runtime::console::receive_master(stream.as_fd()).expect("no PTY master for init");
    c.start().ok();

    let out = c.exec_in(&[], &["sh", "-c", "tty; echo out; echo err >&2"]);
    assert_eq!(out.stdout, "not a tty\nout\n", "{out:#?}");
    assert!(out.stderr.lines().any(|l| l == "err"), "{out:#?}");
}

/// A detached process with a PTY needs somewhere to send the master.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn ex_detached_tty_needs_a_console_socket() {
    let c = sleeper("ex-tty-no-socket");
    c.exec_in(&["-t", "-d"], &["true"]).refused("console");
}

/// Foreground `-t` relays the caller's stdio through a new PTY, like `run`.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn ex_foreground_tty_relays_through_a_pty() {
    let c = sleeper("ex-tty-fg");
    let out = exec_input(c.exec_command(&["-t"], &["sh"]), Some(b"tty; exit 5\n"), TIMEOUT);
    assert_eq!(out.status, 5, "{out:#?}");
    assert!(out.stdout.contains("/dev/pts/"), "{out:#?}");
}

// ── fds and the binary ───────────────────────────────────────────────────────

/// `--preserve-fds 1` passes the caller's fd 3, and only that.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn ex_preserve_fds_passes_the_callers_fds() {
    let c = sleeper("ex-preserve");
    let dir = tempfile::tempdir().unwrap();
    let (a, b) = (dir.path().join("a"), dir.path().join("b"));
    std::fs::write(&a, "from fd 3\n").unwrap();
    std::fs::write(&b, "b\n").unwrap();
    let cmd = c.exec_command(&["--preserve-fds", "1"], &["sh", "-c", "cat <&3; ls /proc/self/fd | tr '\\n' ' '"]);
    let out = exec(with_extra_fds(&cmd, &[ExtraFd::Read(&a), ExtraFd::Read(&b)]));
    // 3 is the preserved fd, 4 the directory `ls` reads.
    assert_eq!(out.ok(), "from fd 3\n0 1 2 3 4 ", "{out:#?}");
}

/// No runtime fd leaks into the exec'd process.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn ex_leaks_no_fds() {
    let c = sleeper("ex-fds");
    let out = c.exec_in(&[], &["ls", "/proc/self/fd"]);
    // stdio, and the directory `ls` reads.
    assert_eq!(out.ok().split_whitespace().collect::<Vec<_>>(), ["0", "1", "2", "3"]);
}

/// CVE-2019-5736 is about exec above all (a malicious container overwrites
/// the runtime binary while it joins): a foreground `rustlet-runc exec` runs
/// from a sealed memfd copy too.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn ex_foreground_exec_runs_from_a_sealed_memfd() {
    let c = sleeper("ex-memfd");
    let mut cmd = c.exec_command(&[], &["sh", "-c", "echo ready; exec sleep 3600"]);
    let mut child = cmd.stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
    let mut line = String::new();
    BufReader::new(child.stdout.as_mut().unwrap()).read_line(&mut line).unwrap();
    assert_eq!(line.trim(), "ready");
    let pid = child.id() as i32;
    let checked = std::panic::catch_unwind(|| assert_sealed_memfd_exe(pid));
    let _ = child.kill();
    let _ = child.wait();
    if let Err(e) = checked {
        std::panic::resume_unwind(e);
    }
}

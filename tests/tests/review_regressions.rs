//! Regression tests for the Phase 2a code review findings. Each test names
//! the failure it pins down. Run with `cargo xtask itest -- rr_`.

use std::time::{Duration, Instant};

use rustlet_itests::e2e::*;
use rustlet_itests::*;

/// A `create` SIGKILLed after init was spawned but before it wrote the final
/// state leaves `status: creating` with a live init and cgroup. `delete` must
/// kill and remove them (it used to report success and orphan both).
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn rr_delete_of_an_unfinished_create_kills_init() {
    let mut s = sh("true");
    let cg = set_cgroup(&mut s, "rr-unfinished");
    let c = Container::created(&s);
    let (pid, start) = (c.pid(), starttime(c.pid()).unwrap());
    // Simulate the crash: the last state.json write never happened.
    let state = c.state_dir().join("state.json");
    let text = std::fs::read_to_string(&state).unwrap();
    std::fs::write(&state, text.replace("\"status\": \"created\"", "\"status\": \"creating\"")).unwrap();
    assert_eq!(c.status(), "creating");

    c.delete(false).ok();
    wait_until("init to die", PROMPT, || !alive(pid, start));
    assert!(!cgroup_dir(&cg).exists(), "cgroup {cg} was left behind");
    c.assert_gone();
}

/// Unreadable state must never be "deleted" silently, even with --force:
/// that would orphan a live init and its cgroup.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn rr_unreadable_state_is_never_silently_deleted() {
    let mut s = sh("true");
    set_cgroup(&mut s, "rr-unreadable");
    let c = Container::created(&s);
    let (pid, start) = (c.pid(), starttime(c.pid()).unwrap());
    let state = c.state_dir().join("state.json");
    let good = std::fs::read(&state).unwrap();
    std::fs::write(&state, b"{ not json").unwrap();

    c.delete(true).refused("unreadable");
    assert!(alive(pid, start), "delete --force killed init although it failed");
    assert!(c.state_dir().exists());

    std::fs::write(&state, good).unwrap();
    c.delete(true).ok();
    c.assert_gone();
}

/// A container cgroup inside another container's cgroup used to be allowed,
/// and deleting the outer (even stopped) container then killed the inner one
/// through the recursive cgroup.kill.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn rr_container_cgroups_cannot_nest() {
    let mut outer = sh("while :; do sleep 0.1; done");
    let outer_cg = set_cgroup(&mut outer, "rr-outer");
    let a = Container::started(&outer);

    let mut inner = sh("true");
    set_cgroups_path(&mut inner, &format!("{outer_cg}/inner"));
    let mut b = Container::new(&inner);
    b.create(&[]).refused("nested");
    b.assert_gone();
    assert_eq!(a.status(), "running", "the refused create disturbed the outer container");
}

/// A second `start` must fail promptly (it used to spin at 100% CPU when two
/// starts raced for the FIFO).
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn rr_second_start_fails_fast() {
    let mut s = sh("while :; do sleep 0.1; done");
    set_cgroup(&mut s, "rr-double-start");
    let c = Container::created(&s);
    c.start().ok();
    let t = Instant::now();
    c.start().failed();
    assert!(t.elapsed() < Duration::from_secs(2), "second start took {:?}", t.elapsed());
    assert_eq!(c.status(), "running");
}

/// `--root` through a symlink (like Docker's /var/run/...) used to make every
/// state-directory removal fail, since safe_remove_tree insists on
/// canonical paths.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn rr_symlinked_root_works() {
    let real = runtime_root().join("rr-real-root");
    std::fs::create_dir_all(&real).unwrap();
    let alias = std::path::PathBuf::from(format!("/run/rustlet/itest-{}-alias", std::process::id()));
    let _ = std::fs::remove_file(&alias);
    std::os::unix::fs::symlink(&real, &alias).unwrap();
    let root = alias.to_str().unwrap();

    let bundle = TestBundle::new(&sh("true"));
    let dir = bundle.dir.path().to_str().unwrap();
    let id = "rr-alias";
    let run = |args: &[&str]| {
        let mut c = std::process::Command::new(runc_binary());
        c.arg("--root").arg(root).args(args).stdin(std::process::Stdio::null());
        exec(c)
    };
    run(&["create", "--bundle", dir, id]).ok();
    run(&["start", id]).ok();
    wait_until("the container to stop", PROMPT, || {
        let st = run(&["state", id]);
        st.stdout.contains("\"stopped\"")
    });
    run(&["delete", id]).ok();
    assert!(!real.join(id).exists(), "state dir survived delete");
    std::fs::remove_file(&alias).unwrap();
    std::fs::remove_dir(&real).unwrap();
}

/// Like runc, a stopped container's state shows pid 0, so nobody signals a
/// recycled PID from it.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn rr_stopped_state_shows_pid_0() {
    let mut s = sh("true");
    set_cgroup(&mut s, "rr-pid0");
    let c = Container::started(&s);
    c.wait_for_status("stopped", PROMPT);
    assert_eq!(c.state()["pid"].as_i64(), Some(0));
}

/// The PID file is written through a private temp file and renamed into
/// place: a symlink at the target path is replaced, never followed.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn rr_pid_file_never_follows_symlinks() {
    let tmp = tempfile::tempdir().unwrap();
    let victim = tmp.path().join("victim");
    std::fs::write(&victim, "precious").unwrap();
    let pid_file = tmp.path().join("init.pid");
    std::os::unix::fs::symlink(&victim, &pid_file).unwrap();

    let mut s = sh("true");
    set_cgroup(&mut s, "rr-pidfile");
    let mut c = Container::new(&s);
    c.create(&["--pid-file", pid_file.to_str().unwrap()]).ok();
    assert_eq!(std::fs::read_to_string(&victim).unwrap(), "precious");
    assert!(!std::fs::symlink_metadata(&pid_file).unwrap().file_type().is_symlink());
    assert_eq!(std::fs::read_to_string(&pid_file).unwrap().trim(), c.pid().to_string());
}

/// Container init used to inherit `create`'s lock fd (an `flock` shares its
/// lock with every copy of the open file). If `create` then died before
/// unlocking, init held the lock at the gate and `delete` hung forever. Init
/// must hold no fd for the state directory or its lock file.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn rr_init_holds_no_lock_or_state_dir_fd() {
    let mut s = sh("true");
    set_cgroup(&mut s, "rr-lockfd");
    let c = Container::created(&s);
    let dir = c.state_dir().canonicalize().unwrap();
    let fds: Vec<_> = std::fs::read_dir(format!("/proc/{}/fd", c.pid()))
        .unwrap()
        .filter_map(|e| std::fs::read_link(e.unwrap().path()).ok())
        .collect();
    for target in &fds {
        assert!(target != &dir && !target.ends_with(".lock"), "init holds {} (all fds: {fds:?})", target.display());
    }
    // And the lock is free: start and delete don't block.
    c.start().ok();
    c.wait_for_status("stopped", PROMPT);
    c.delete(false).ok();
    c.assert_gone();
}

/// An explicit program path is checked at `create`, as runc does: missing
/// is 127, not executable is 126 (it used to pass `create` and only fail
/// after `start`).
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn rr_explicit_paths_are_checked_at_create() {
    let mut s = spec(&["/nope"]);
    set_cgroup(&mut s, "rr-nope");
    let mut c = Container::new(&s);
    c.create(&[]).failed_with(127);
    c.assert_gone();

    let mut s = spec(&["/etc/passwd"]);
    set_cgroup(&mut s, "rr-passwd");
    let mut c = Container::new(&s);
    c.create(&[]).failed_with(126);
    c.assert_gone();
}

// ── Phase 2b review ──────────────────────────────────────────────────────────

/// `exec` must fail, not report success, when its process dies before it
/// reaches `execve`. EOF on the sync socket used to count as "execve
/// succeeded". Here the process is placed in a frozen cgroup
/// (`--ignore-paused`) and killed there, so it never runs an instruction.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn rr_exec_killed_before_execve_fails() {
    let mut s = sh("while :; do sleep 0.1; done");
    let cg = set_cgroup(&mut s, "rr-exec-killed");
    let c = Container::started(&s);
    c.cmd(&["pause"]).ok();
    let before = cgroup_procs(&cg).len();
    let child = c
        .exec_command(&["--ignore-paused", "-d"], &["true"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    wait_until("the exec'd process to be placed in the frozen cgroup", PROMPT, || cgroup_procs(&cg).len() > before);
    c.kill(true, Some("KILL")).ok();
    let out = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "exec reported success for a process that never ran: {stderr}");
    assert!(stderr.contains("died before it could run the program"), "{stderr}");
}

/// A seccomp profile that doesn't allow `close_range` must not break the
/// container when the filter is loaded early (`noNewPrivileges: false`):
/// the runtime's own `close_range` now runs before the filter.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn rr_profile_without_close_range_still_starts() {
    let mut s = sh("echo started; while :; do sleep 0.1; done");
    set_cgroup(&mut s, "rr-no-close-range");
    let mut p = s.process().clone().unwrap();
    p.set_no_new_privileges(Some(false));
    s.set_process(Some(p));
    let linux = s.linux_mut().as_mut().unwrap();
    let mut seccomp = linux.seccomp().clone().unwrap();
    let rules = seccomp
        .syscalls()
        .clone()
        .unwrap()
        .into_iter()
        .map(|mut r| {
            let names: Vec<String> = r.names().iter().filter(|n| *n != "close_range").cloned().collect();
            r.set_names(names);
            r
        })
        .filter(|r| !r.names().is_empty())
        .collect();
    seccomp.set_syscalls(Some(rules));
    linux.set_seccomp(Some(seccomp));
    let c = Container::started(&s);
    wait_until("the container to print", PROMPT, || c.stdout().contains("started"));
    assert_eq!(c.exec_in(&[], &["echo", "exec too"]).ok(), "exec too\n");
}

/// `HOME` comes from the container's `/etc/passwd`, which the image
/// controls: a FIFO there must not hang `create` (it used to block in open).
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn rr_fifo_passwd_does_not_hang() {
    let dir = tempfile::tempdir().unwrap();
    let fifo = dir.path().join("passwd");
    assert!(std::process::Command::new("mkfifo").arg(&fifo).status().unwrap().success());
    let mut s = sh("echo HOME=$HOME");
    set_cgroup(&mut s, "rr-fifo-passwd");
    add_mount(&mut s, "/etc/passwd", "bind", fifo.to_str().unwrap(), &["bind"]);
    let mut c = Container::new(&s);
    assert_eq!(c.run_foreground(&[], None, PROMPT).ok(), "HOME=/\n");
}

/// `exec -t` opens the container's devpts `ptmx` directly, never whatever
/// the container put at `/dev/ptmx` (here: a FIFO).
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn rr_exec_tty_ignores_a_replaced_dev_ptmx() {
    let mut s = sh("rm /dev/ptmx && mkfifo /dev/ptmx && while :; do sleep 0.1; done");
    set_cgroup(&mut s, "rr-fake-ptmx");
    let c = Container::started(&s);
    wait_until("/dev/ptmx to be a FIFO", PROMPT, || c.exec_in(&[], &["test", "-p", "/dev/ptmx"]).status == 0);
    let out = exec_input(c.exec_command(&["-t"], &["tty"]), None, PROMPT);
    assert!(out.stdout.contains("/dev/pts/"), "{out:#?}");
}

//! Phase 2a: the container lifecycle through `rustlet-runc`'s runc-compatible
//! CLI: `create`, `start`, `state`, `kill`, `delete`, `list` and `run`.
//!
//! Black-box: the tests drive the binary and look only at the host (files a
//! container writes into a bind mount, `/proc`, `/sys/fs/cgroup`, the state
//! directory). Run with `cargo xtask itest -- lc_`.
//!
//! Every container but one gets a `linux.cgroupsPath` in the test scope, so
//! that the drop guard can always clean up after a failed test.

use std::os::unix::fs::FileTypeExt;
use std::path::Path;
use std::time::Duration;

use rustlet_itests::e2e::*;
use rustlet_itests::*;

/// Reads a pid file.
#[track_caller]
fn read_pid_file(path: &Path) -> i32 {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("pid file {}: {e}", path.display()));
    text.trim().parse().unwrap_or_else(|e| panic!("pid file {} holds {text:?}: {e}", path.display()))
}

/// The bundle path in a state object, checked to be absolute and to be ours.
#[track_caller]
fn assert_bundle(st: &Json, c: &Container) {
    let bundle = st["bundle"].as_str().unwrap_or_else(|| panic!("no string `bundle`: {st:?}"));
    assert!(Path::new(bundle).is_absolute(), "bundle {bundle:?} is not absolute");
    assert_eq!(Path::new(bundle).canonicalize().unwrap(), c.bundle_dir().canonicalize().unwrap(), "{st:?}");
}

// ── the whole lifecycle ──────────────────────────────────────────────────────

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn lc_create_start_stop_delete() {
    let mut s = sh("touch /mnt/started; while [ ! -e /mnt/stop ]; do sleep 0.05; done");
    let host = bind_host_dir(&mut s, "/mnt");
    let cg = set_cgroup(&mut s, "lc-lifecycle");
    let c = Container::created(&s);

    // created: everything is set up, init waits before execve.
    let st = c.state();
    assert_eq!(st["status"].as_str(), Some("created"), "{st:?}");
    assert_eq!(st["id"].as_str(), Some(c.id()), "{st:?}");
    assert!(st["ociVersion"].as_str().is_some_and(|v| !v.is_empty()), "{st:?}");
    assert!(st["pid"].as_i64().is_some_and(|p| p > 1), "{st:?}");
    assert_bundle(&st, &c);
    for key in ["rootfs", "created"] {
        if let Some(v) = st.get(key) {
            assert!(v.as_str().is_some(), "`{key}` is not a string: {st:?}");
        }
    }
    if let Some(a) = st.get("annotations") {
        assert!(a.as_object().is_some(), "`annotations` is not an object: {st:?}");
    }
    assert!(c.state_dir().join("state.json").is_file(), "no state.json in {}", c.state_dir().display());
    let fifo = std::fs::metadata(c.state_dir().join("exec.fifo")).expect("no exec.fifo after create");
    assert!(fifo.file_type().is_fifo(), "exec.fifo is not a FIFO");
    std::thread::sleep(Duration::from_millis(300));
    assert!(!host.path().join("started").exists(), "the program ran before `start`");

    // start: the program runs.
    c.start().ok();
    wait_until("the program to run after `start`", PROMPT, || host.path().join("started").exists());
    assert_eq!(c.status(), "running");

    // The program exits: stopped.
    std::fs::write(host.path().join("stop"), "").unwrap();
    c.wait_for_status("stopped", PROMPT);

    // delete: nothing left, and the id is unknown again.
    c.delete(false).ok();
    c.assert_gone();
    assert!(!cgroup_dir(&cg).exists());
    c.try_state().failed();
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn lc_lifecycle_without_a_cgroups_path() {
    // No cgroupsPath and no resources: the container doesn't need a cgroup.
    let mut s = sh("touch /mnt/ran");
    let host = bind_host_dir(&mut s, "/mnt");
    let c = Container::created(&s);
    assert_eq!(c.status(), "created");
    c.start().ok();
    c.wait_for_status("stopped", PROMPT);
    assert!(host.path().join("ran").exists(), "the program never ran");
    c.delete(false).ok();
    c.assert_gone();
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn lc_pid_file_holds_the_host_pid_of_init() {
    let dir = tempfile::tempdir().unwrap();
    let pid_file = dir.path().join("init.pid");
    let mut s = spec(&["true"]);
    set_cgroup(&mut s, "lc-pidfile");
    let mut c = Container::new(&s);
    c.create(&["--pid-file", pid_file.to_str().unwrap()]).ok();
    let pid = read_pid_file(&pid_file);
    assert_eq!(pid, c.pid(), "the pid file and `state` disagree");
    // A host PID whose innermost (container) PID is 1.
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    assert!(status.lines().any(|l| l.starts_with("NSpid:") && l.trim_end().ends_with("\t1")), "{status}");
}

// ── refusals ─────────────────────────────────────────────────────────────────

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn lc_duplicate_id_is_refused() {
    let mut s = spec(&["sleep", "3600"]);
    set_cgroup(&mut s, "lc-dup-first");
    let first = Container::created(&s);
    let pid = first.pid();

    // A second bundle (and cgroup) under the same id.
    let mut s = spec(&["true"]);
    let cg = set_cgroup(&mut s, "lc-dup-second");
    let mut second = Container::new(&s);
    second.bundle.id = first.id().to_owned();
    let out = second.create(&[]);
    out.failed();
    assert!(out.stderr.contains(first.id()) || out.stderr.to_lowercase().contains("exist"), "{out:#?}");
    assert!(!cgroup_dir(&cg).exists(), "the refused create made cgroup {cg}");

    // The first container is untouched and still works.
    assert_eq!(first.status(), "created");
    assert_eq!(first.pid(), pid);
    first.start().ok();
    assert_eq!(first.status(), "running");
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn lc_failed_create_leaves_nothing_behind() {
    // A program that doesn't exist, which `create` must find out before it
    // reports success.
    let mut s = spec(&["no-such-program"]);
    set_cgroup(&mut s, "lc-fail-exec");
    let mut c = Container::new(&s);
    // Not found in $PATH: a shell's 127 (checked in `create`, before init
    // reports ready, just as runc does).
    let out = c.create(&[]);
    out.failed_with(127);
    assert!(out.stderr.contains("no-such-program"), "{out:#?}");
    c.assert_gone();

    // A bind mount whose source doesn't exist.
    let source = format!("/nonexistent-rustlet-source-{}", std::process::id());
    let mut s = spec(&["true"]);
    add_mount(&mut s, "/mnt", "bind", &source, &["rbind"]);
    set_cgroup(&mut s, "lc-fail-mount");
    let mut c = Container::new(&s);
    c.create(&[]).refused(&source);
    c.assert_gone();
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn lc_unknown_ids_are_refused() {
    let id = format!("lc-no-such-container-{}", std::process::id());
    let commands: [&[&str]; 8] =
        [&["state"], &["start"], &["kill"], &["delete"], &["pause"], &["resume"], &["ps"], &["events", "--stats"]];
    for args in commands {
        let mut cmd = runc(args);
        cmd.arg(&id);
        let out = exec(cmd);
        assert!(
            out.status == 1 && out.stderr.lines().any(|l| l.starts_with("rustlet-runc: ")),
            "`{} <unknown id>` should fail with status 1 and a `rustlet-runc: ` error: {out:#?}",
            args.join(" ")
        );
    }
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn lc_start_is_only_valid_when_created() {
    let mut s = spec(&["sleep", "3600"]);
    set_cgroup(&mut s, "lc-start-twice");
    let c = Container::started(&s);
    c.start().failed();
    assert_eq!(c.status(), "running");

    c.kill(false, Some("KILL")).ok();
    c.wait_for_status("stopped", PROMPT);
    c.start().failed();
    assert_eq!(c.status(), "stopped");
}

// ── delete ───────────────────────────────────────────────────────────────────

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn lc_delete_refuses_a_running_container_unless_forced() {
    let mut s = spec(&["sleep", "3600"]);
    set_cgroup(&mut s, "lc-delete-running");
    let c = Container::started(&s);
    let pid = c.pid();
    let start = starttime(pid).expect("init is not running");

    c.delete(false).failed();
    assert_eq!(c.status(), "running");
    assert!(alive(pid, start), "a refused delete killed init");

    c.delete(true).ok();
    c.assert_gone();
    wait_until("init to die", PROMPT, || !alive(pid, start));
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn lc_delete_of_a_created_container_kills_init() {
    let mut s = sh("touch /mnt/started");
    let host = bind_host_dir(&mut s, "/mnt");
    set_cgroup(&mut s, "lc-delete-created");
    let c = Container::created(&s);
    let pid = c.pid();
    let start = starttime(pid).expect("init is not there");

    c.delete(false).ok();
    c.assert_gone();
    wait_until("init to die", PROMPT, || !alive(pid, start));
    assert!(!host.path().join("started").exists(), "the program ran although the container was never started");
}

// ── kill ─────────────────────────────────────────────────────────────────────

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn lc_kill_defaults_to_term_which_reaches_a_trap() {
    let mut s = sh("trap 'echo TERM > /mnt/trapped; exit 0' TERM; touch /mnt/ready; while :; do sleep 0.1; done");
    let host = bind_host_dir(&mut s, "/mnt");
    set_cgroup(&mut s, "lc-kill-term");
    let c = Container::started(&s);
    wait_until("the trap to be set", PROMPT, || host.path().join("ready").exists());

    c.kill(false, None).ok();
    c.wait_for_status("stopped", PROMPT);
    let trapped = std::fs::read_to_string(host.path().join("trapped")).expect("the TERM trap never ran");
    assert_eq!(trapped.trim(), "TERM");
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn lc_kill_takes_signal_names_and_numbers() {
    for signal in ["KILL", "SIGKILL", "9"] {
        let mut s = spec(&["sleep", "3600"]);
        set_cgroup(&mut s, "lc-kill-signal");
        let c = Container::started(&s);
        c.kill(false, Some(signal)).ok();
        c.wait_for_status("stopped", PROMPT);
    }
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn lc_kill_all_signals_every_process() {
    // Init (a shell with no TERM handler) ignores TERM, as PID 1 does; its two
    // children don't. Once both are gone, `wait` returns and init says so.
    let mut s = sh("sleep 3600 & sleep 3600 & wait; touch /mnt/children-gone; while :; do sleep 0.1; done");
    let host = bind_host_dir(&mut s, "/mnt");
    let cg = set_cgroup(&mut s, "lc-kill-all");
    let c = Container::started(&s);
    wait_until("init and its two children", PROMPT, || cgroup_procs(&cg).len() == 3);

    // Without --all, only init is signalled, so nothing happens.
    c.kill(false, Some("TERM")).ok();
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(cgroup_procs(&cg).len(), 3, "plain `kill` reached more than init");
    assert!(!host.path().join("children-gone").exists());

    // With --all the children get it too.
    c.kill(true, Some("TERM")).ok();
    wait_until("the children to die", PROMPT, || host.path().join("children-gone").exists());
    assert_eq!(c.status(), "running", "init has no TERM handler and should have survived");

    c.kill(true, Some("KILL")).ok();
    c.wait_for_status("stopped", PROMPT);
}

// ── list ─────────────────────────────────────────────────────────────────────

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn lc_list_shows_the_containers() {
    let mut s = spec(&["sleep", "3600"]);
    set_cgroup(&mut s, "lc-list-created");
    let created = Container::created(&s);
    let mut s = spec(&["sleep", "3600"]);
    set_cgroup(&mut s, "lc-list-running");
    let running = Container::started(&s);

    let out = runc_out(&["list", "--format", "json"]);
    let list = parse_json(out.ok(), "list --format json");
    let entries = list.as_array().unwrap_or_else(|| panic!("`list --format json` is not an array: {list:?}"));
    for (c, status) in [(&created, "created"), (&running, "running")] {
        let e = entries
            .iter()
            .find(|e| e["id"].as_str() == Some(c.id()))
            .unwrap_or_else(|| panic!("{} is missing from `list`: {}", c.id(), out.stdout));
        assert_eq!(e["status"].as_str(), Some(status), "{e:?}");
        assert_eq!(e["pid"].as_i64(), Some(i64::from(c.pid())), "{e:?}");
        assert_bundle(e, c);
    }

    for args in [&["list"][..], &["list", "--format", "table"]] {
        let out = runc_out(args);
        assert!(out.ok().contains(created.id()) && out.stdout.contains(running.id()), "{args:?}: {out:#?}");
    }
}

// ── run ──────────────────────────────────────────────────────────────────────

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn lc_run_detach_leaves_the_container_running() {
    let dir = tempfile::tempdir().unwrap();
    let pid_file = dir.path().join("init.pid");
    let mut s = sh("touch /mnt/started; while :; do sleep 0.1; done");
    let host = bind_host_dir(&mut s, "/mnt");
    set_cgroup(&mut s, "lc-run-detach");
    let mut c = Container::new(&s);
    c.run_detached(&["--pid-file", pid_file.to_str().unwrap()]).ok();

    assert_eq!(c.status(), "running");
    wait_until("the program to run", PROMPT, || host.path().join("started").exists());
    assert_eq!(read_pid_file(&pid_file), c.pid());

    c.delete(true).ok();
    c.assert_gone();
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn lc_run_deletes_the_container_when_it_exits() {
    let mut s = sh("echo hi; exit 3");
    set_cgroup(&mut s, "lc-run-fg");
    let mut c = Container::new(&s);
    let out = c.run_foreground(&[], None, TIMEOUT);
    assert_eq!(out.status, 3, "{out:#?}");
    assert_eq!(out.stdout.trim(), "hi");
    c.assert_gone();
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn lc_run_is_visible_to_the_other_commands_and_reports_signals() {
    // A foreground `run` registers the container like `create` does, so
    // `state` and `kill` work on it; death by signal N exits 128+N.
    let mut s = spec(&["sleep", "3600"]);
    set_cgroup(&mut s, "lc-run-killed");
    let mut c = Container::new(&s);
    let id = c.id().to_owned();
    let out = std::thread::scope(|scope| {
        let run = scope.spawn(|| c.run_foreground(&[], None, TIMEOUT));
        let state = || {
            let out = runc_out(&["state", &id]);
            Json::parse(out.stdout.trim()).ok().and_then(|j| j["status"].as_str().map(str::to_owned))
        };
        wait_until("`state` to show the foreground container running", PROMPT, || {
            run.is_finished() || state().as_deref() == Some("running")
        });
        assert!(!run.is_finished(), "`run` exited early: {:#?}", run.join());
        runc_out(&["kill", &id, "KILL"]).ok();
        run.join().unwrap()
    });
    assert_eq!(out.status, 137, "{out:#?}");
    c.assert_gone();
}

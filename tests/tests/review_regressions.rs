//! Regression tests for the code review findings (Phases 2a, 2b, 2c and
//! 3). Each test names the failure it pins down. Run with
//! `cargo xtask itest -- rr_`.

use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, Instant};

use rustlet_itests::e2e::*;
use rustlet_itests::*;
use rustlet_runtime::oci_spec::runtime::{
    LinuxDeviceBuilder, LinuxDeviceType, LinuxIdMappingBuilder, LinuxNamespaceType, PosixRlimitBuilder,
    PosixRlimitType, Spec,
};

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

// ── Phase 2c part 1 review ───────────────────────────────────────────────────

fn set_nofile(s: &mut Spec, limit: u64) {
    edit_process(s, |p| {
        let rl = PosixRlimitBuilder::default().typ(PosixRlimitType::RlimitNofile).soft(limit).hard(limit);
        p.set_rlimits(Some(vec![rl.build().unwrap()]));
    });
}

/// A small `RLIMIT_NOFILE` must not break init's own setup. The parent used
/// to set the limits before init mounted anything, so init's fds (one per
/// bind mount, …) counted against it: with 8, `mount devpts` failed with
/// EMFILE. Now init asks for its limits once its setup as root is done.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn rr_rlimits_are_set_after_init_setup() {
    let dirs: Vec<tempfile::TempDir> = (0..4).map(|_| tempfile::tempdir().unwrap()).collect();
    for userns in [false, true] {
        let mut s = if userns { userns_sh("ulimit -n") } else { sh("ulimit -n") };
        set_nofile(&mut s, 8);
        for (i, d) in dirs.iter().enumerate() {
            std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
            add_mount(&mut s, &format!("/mnt/{i}"), "bind", d.path().to_str().unwrap(), &["bind", "ro"]);
        }
        assert_eq!(run(&s).ok(), "8\n", "userns: {userns}");
    }
}

/// When the parent fails to set init's limits, `create` reports that one
/// error. The parent's end of the sync socket used to close before init was
/// killed, so init, waiting on it, could print a second, misleading
/// "rustlet-runc went away during create". That race was narrow (it never
/// showed in these runs); this pins down the property, and the socket is
/// now created before the guard, so the guard's kill comes first by
/// construction.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn rr_a_failed_prlimit_reports_one_error() {
    for _ in 0..5 {
        let mut s = sh("true");
        // Above fs.nr_open: even root's prlimit gets EPERM.
        set_nofile(&mut s, 1 << 30);
        let mut c = Container::new(&s);
        let out = c.create(&[]);
        out.refused("prlimit");
        let errors = out.stderr.lines().filter(|l| l.starts_with("rustlet-runc")).count();
        assert_eq!(errors, 1, "{}", out.stderr);
        c.assert_gone();
    }
}

/// With a user namespace, the kernel refuses a new proc or sysfs whose
/// atime mode differs from the host's, and any flag change on the host's
/// sysfs copied in without a network namespace (its mounts' flags are
/// locked). These failed halfway through init with EPERM; now `create`
/// refuses them up front.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn rr_locked_proc_and_sysfs_flags_are_refused_up_front() {
    let with_option = |dest: &str, word: &str, own_netns: bool| {
        let mut s = userns_sh("true");
        if !own_netns {
            without_namespace(&mut s, LinuxNamespaceType::Network);
        }
        let mut mounts = s.mounts().clone().unwrap();
        let m = mounts.iter_mut().find(|m| m.destination().to_str() == Some(dest)).unwrap();
        let mut options = m.options().clone().unwrap_or_default();
        options.push(word.to_owned());
        m.set_options(Some(options));
        s.set_mounts(Some(mounts));
        s
    };
    let cases = [
        ("/proc", "noatime", true, "a new proc or sysfs must keep the host's atime mode"),
        ("/sys", "strictatime", true, "a new proc or sysfs must keep the host's atime mode"),
        ("/sys", "exec", false, "`suid`, `dev` and `exec`"),
        ("/sys", "noatime", false, "atime options"),
    ];
    for (dest, word, own_netns, needle) in cases {
        let mut c = Container::new(&with_option(dest, word, own_netns));
        c.create(&[]).refused(needle);
        c.assert_gone();
    }
    // What the kernel does allow still works.
    run(&with_option("/proc", "relatime", true)).ok();
    run(&with_option("/sys", "ro", false)).ok();
}

/// A map the kernel can't take in one write (a page or more of text) is
/// refused at `create`, not by an EINVAL from writing `uid_map`.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn rr_a_map_longer_than_a_page_is_refused() {
    let mut s = userns_sh("true");
    let long: Vec<_> = std::iter::once((0u32, 1_000_000u32, 1u32))
        .chain((0..199).map(|i| (1_000_000_000 + 2 * i, 2_000_000_000 + 2 * i, 1)))
        .map(|(c, h, n)| LinuxIdMappingBuilder::default().container_id(c).host_id(h).size(n).build().unwrap())
        .collect();
    edit_linux(&mut s, |l| {
        l.set_uid_mappings(Some(long));
    });
    let mut c = Container::new(&s);
    c.create(&[]).refused("at most 4095");
    c.assert_gone();
}

/// An idmapped mount's own `uidMappings` may be the container's mapping
/// written as different lines; it used to be compared line by line and
/// refused as "not planned".
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn rr_idmap_accepts_the_containers_mapping_in_other_lines() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::write(dir.path().join("f"), "x").unwrap();
    let mut s = userns_sh("stat -c '%u' /mnt/f");
    add_mount(&mut s, "/mnt", "bind", dir.path().to_str().unwrap(), &["bind", "idmap"]);
    let split = [(0u32, 1_000_000u32, 100u32), (100, 1_000_100, 65_436)]
        .map(|(c, h, n)| LinuxIdMappingBuilder::default().container_id(c).host_id(h).size(n).build().unwrap());
    let mut mounts = s.mounts().clone().unwrap();
    let m = mounts.last_mut().unwrap();
    m.set_uid_mappings(Some(split.to_vec()));
    m.set_gid_mappings(Some(split.to_vec()));
    s.set_mounts(Some(mounts));
    assert_eq!(run(&s).ok(), "0\n");
}

// ── Phase 2c part 2 review ───────────────────────────────────────────────────

/// A spec with a writable bind of a host tmpfs directory on `/mnt` and one
/// requested device node, over a disposable rootfs in which `/dev` and
/// `/mnt` are aliased by a symlink. Returns the rootfs and the bind source,
/// which must stay empty.
fn dev_alias_spec(dev_is_symlink: bool) -> (Spec, tempfile::TempDir, tempfile::TempDir) {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir().unwrap();
    if dev_is_symlink {
        std::fs::create_dir(root.path().join("mnt")).unwrap();
        symlink("/mnt", root.path().join("dev")).unwrap();
    } else {
        std::fs::create_dir(root.path().join("dev")).unwrap();
        symlink("/dev", root.path().join("mnt")).unwrap();
    }
    let source = tempfile::Builder::new().prefix("rustlet-rr-dev-alias-").tempdir_in("/dev/shm").unwrap();
    let mut s = spec(&["/does-not-exist"]);
    s.root_mut().as_mut().unwrap().set_path(root.path().to_owned());
    add_mount(&mut s, "/mnt", "bind", source.path().to_str().unwrap(), &["bind", "rw"]);
    edit_linux(&mut s, |linux| {
        let node = LinuxDeviceBuilder::default()
            .path("/dev/rr-node")
            .typ(LinuxDeviceType::C)
            .major(1)
            .minor(3)
            .file_mode(0o640u32)
            .uid(12u32)
            .gid(34u32)
            .build()
            .unwrap();
        linux.set_devices(Some(vec![node]));
    });
    set_cgroup(&mut s, "rr-dev-alias");
    (s, root, source)
}

fn assert_untouched(source: &tempfile::TempDir) {
    let left: Vec<_> = std::fs::read_dir(source.path()).unwrap().map(|e| e.unwrap().file_name()).collect();
    assert!(left.is_empty(), "/dev population wrote into the host's bind source: {left:?}");
}

/// Phase 2c part 2 review. With `/dev -> /mnt` in the image, the tmpfs for
/// `/dev` followed the link to `/mnt`, a bind mount of a host tmpfs
/// directory then covered it, and `/dev` was populated by path, inside the
/// host directory (`dev::populate` only checked the filesystem type). A
/// symlinked `/dev` is now refused, as for `/proc` and `/sys`.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn rr_dev_symlink_cannot_redirect_device_population() {
    let (s, _root, source) = dev_alias_spec(true);
    let mut c = Container::new(&s);
    c.create(&[]).refused("/dev is a symlink in the rootfs");
    c.assert_gone();
    assert_untouched(&source);
}

/// The reverse alias, with a real `/dev`: `/mnt -> /dev` sent the bind
/// mount for `/mnt` on top of the fresh `/dev` tmpfs. `/dev` is now
/// populated through the fd of the tmpfs mount itself, and only while the
/// path `/dev` still leads to that mount.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn rr_mount_through_a_symlink_cannot_cover_dev() {
    let (s, _root, source) = dev_alias_spec(false);
    let mut c = Container::new(&s);
    c.create(&[]).refused("a later mount covers it");
    c.assert_gone();
    assert_untouched(&source);
}

/// Phase 3 review. Without a terminal, a foreground process in a user
/// namespace gets stdio pipes that `rustlet-runc` relays. One that closes
/// its stdout and stderr and only then gets input must still receive it,
/// and then EOF. The relay used to stop altogether once both outputs had
/// ended, leaving the process blocked on its stdin forever.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn rr_userns_input_outlives_closed_output() {
    use std::io::{Read, Write};
    use std::process::Stdio;
    let script =
        "echo closing; exec >/dev/null 2>&1; read line; [ \"$line\" = hello ] || exit 1; cat >/dev/null; exit 7";
    let bundle = TestBundle::new(&userns_sh(script));
    let mut cmd = bundle.command();
    let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
    let (mut stdin, mut stdout) = (child.stdin.take().unwrap(), child.stdout.take().unwrap());
    // Input only once the container has closed both outputs: after its
    // last line, and a moment for the relay to see both pipes end.
    let mut said = Vec::new();
    let mut byte = [0u8; 1];
    while !said.ends_with(b"closing\n") {
        stdout.read_exact(&mut byte).expect("the container exited before closing its outputs");
        said.push(byte[0]);
    }
    std::thread::sleep(Duration::from_millis(300));
    stdin.write_all(b"hello\nmore input\n").unwrap();
    drop(stdin);
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the container never got its input (or its EOF)");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(status.code(), Some(7));
}

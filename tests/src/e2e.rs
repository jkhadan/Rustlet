//! Shared helpers for the end-to-end tests of the `rustlet-runc` CLI
//! (`tests/tests/{lifecycle,cgroup_limits,terminal}.rs` for Phase 2a,
//! `{hardening,exec,differential}.rs` for Phase 2b). Black-box: they only
//! drive the binary and look at the host.
//!
//! - [`exec`] runs a command with a timeout and captures its output in
//!   *files*, never pipes: `create` and `run --detach` hand their stdout and
//!   stderr to the container, which would hold a pipe open and hang a reader.
//! - [`Container`] drives one container through the CLI. Dropping it runs
//!   `delete --force`, then kills whatever that left behind (its cgroup, its
//!   init), so a failed test can't leak a container.
//! - cgroup helpers read the host's view under `/sys/fs/cgroup`.
//! - [`Json`] is a small JSON parser (this crate has no `serde_json`), for the
//!   output of `state`, `list`, `ps` and `events`.

use std::ffi::OsString;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::os::unix::process::ExitStatusExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::str::FromStr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use nix::errno::Errno;
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use rustlet_runtime::oci_spec::runtime::{
    BoxBuilder, Capabilities, Capability, Linux, LinuxCapabilitiesBuilder, LinuxNamespaceBuilder, LinuxNamespaceType,
    LinuxResources, Process, Spec,
};

use crate::{
    TestBundle, add_mount, alpine_rootfs, assert_host_mounts_unchanged, host_mounts, itest_cgroup, itest_scope,
    remap_rootfs, runc, runtime_root,
};

/// Upper bound for any one `rustlet-runc` invocation.
pub const TIMEOUT: Duration = Duration::from_secs(30);
/// How long to wait for something that should happen promptly: a state
/// change, a process exiting, a file appearing.
pub const PROMPT: Duration = Duration::from_secs(10);

// ── running commands ─────────────────────────────────────────────────────────

/// What a command did.
#[derive(Debug)]
pub struct CmdOut {
    /// Exit code, or 128+signal.
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

impl CmdOut {
    /// Asserts exit status 0 and returns stdout.
    #[track_caller]
    pub fn ok(&self) -> &str {
        assert_eq!(self.status, 0, "command failed: {self:#?}");
        &self.stdout
    }

    /// Asserts a runtime error: exit status 1, with an error line on stderr
    /// prefixed `rustlet-runc: `.
    #[track_caller]
    pub fn failed(&self) {
        self.failed_with(1);
    }

    /// Fails with exactly `status` and a `rustlet-runc: ` error line. (127 =
    /// program not found, 126 = not executable, like a shell; 1 otherwise.)
    #[track_caller]
    pub fn failed_with(&self, status: i32) {
        assert_eq!(self.status, status, "expected the command to fail with status {status}: {self:#?}");
        assert!(
            self.stderr.lines().any(|l| l.starts_with("rustlet-runc: ")),
            "no `rustlet-runc: ` error line on stderr: {self:#?}"
        );
    }

    /// [`failed`](Self::failed), and stderr mentions `needle` (ignoring case).
    #[track_caller]
    pub fn refused(&self, needle: &str) {
        self.failed();
        assert!(
            self.stderr.to_lowercase().contains(&needle.to_lowercase()),
            "the error doesn't mention {needle:?}: {self:#?}"
        );
    }
}

fn exit_code(s: ExitStatus) -> i32 {
    s.code().unwrap_or_else(|| 128 + s.signal().unwrap_or(0))
}

/// Waits up to `timeout` for `child`; after that SIGKILLs it and returns `None`.
fn wait_child(child: &mut Child, timeout: Duration) -> Option<ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(s)) => return Some(s),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
}

fn read_lossy(path: &Path) -> String {
    String::from_utf8_lossy(&std::fs::read(path).unwrap_or_default()).into_owned()
}

/// Runs `cmd` with stdout/stderr going to the files `out`/`err` and `input`
/// (if any) on a stdin pipe that is then closed. `Err` means it timed out
/// (and was killed); either way the output so far is returned.
fn run_captured(
    cmd: &mut Command,
    input: Option<&[u8]>,
    out: &Path,
    err: &Path,
    timeout: Duration,
) -> Result<CmdOut, CmdOut> {
    cmd.stdout(File::create(out).unwrap()).stderr(File::create(err).unwrap());
    if input.is_some() {
        cmd.stdin(Stdio::piped());
    }
    let mut child = cmd.spawn().unwrap_or_else(|e| panic!("spawn {cmd:?}: {e}"));
    if let (Some(input), Some(mut stdin)) = (input, child.stdin.take()) {
        // A child that exits early closes its end; that's not our problem.
        let _ = stdin.write_all(input);
        // Dropping `stdin` here is the EOF.
    }
    let status = wait_child(&mut child, timeout);
    let o = CmdOut { status: status.map_or(-1, exit_code), stdout: read_lossy(out), stderr: read_lossy(err) };
    if status.is_some() { Ok(o) } else { Err(o) }
}

/// Runs `cmd` to completion (within [`TIMEOUT`]); see [`exec_input`].
#[track_caller]
pub fn exec(cmd: Command) -> CmdOut {
    exec_input(cmd, None, TIMEOUT)
}

/// Runs `cmd` with `input` on stdin, capturing output in files; panics if it
/// takes longer than `timeout`.
#[track_caller]
pub fn exec_input(mut cmd: Command, input: Option<&[u8]>, timeout: Duration) -> CmdOut {
    // Before the first spawn: see `Container::new`.
    itest_scope();
    let dir = tempfile::tempdir().unwrap();
    match run_captured(&mut cmd, input, &dir.path().join("out"), &dir.path().join("err"), timeout) {
        Ok(o) => o,
        Err(o) => panic!("{cmd:?} did not finish within {timeout:?}: {o:#?}"),
    }
}

/// `rustlet-runc --root … <args…>`, within [`TIMEOUT`].
#[track_caller]
pub fn runc_out(args: &[&str]) -> CmdOut {
    exec(runc(args))
}

/// `rustlet-runc --root … <args…>` built without asserting anything (for
/// `Drop`, which must never panic). `None` if the binary isn't there.
fn runc_quiet(args: &[&str]) -> Option<Command> {
    let exe = std::env::current_exe().ok()?;
    let bin = exe.parent()?.parent()?.join("rustlet-runc");
    bin.exists().then(|| {
        let mut c = Command::new(bin);
        c.arg("--root").arg(runtime_root()).args(args);
        c
    })
}

/// Runs `cmd` with all stdio on /dev/null; `None` if it can't be spawned or
/// times out. Never panics.
fn quiet(cmd: &mut Command, timeout: Duration) -> Option<i32> {
    let mut child = cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().ok()?;
    wait_child(&mut child, timeout).map(exit_code)
}

/// Polls `done` every 20 ms; panics if it isn't true within `timeout`.
#[track_caller]
pub fn wait_until(what: &str, timeout: Duration, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + timeout;
    while !done() {
        assert!(Instant::now() < deadline, "timed out after {timeout:?} waiting for {what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The host's mount table and the shared rootfs's top-level entries, to
/// check that a `rustlet-runc` invocation changed neither (the same guard
/// `rustlet_itests::run` applies).
struct HostSnapshot {
    mounts: Vec<(String, String, String)>,
    rootfs: Vec<OsString>,
}

impl HostSnapshot {
    fn take() -> HostSnapshot {
        HostSnapshot { mounts: host_mounts(), rootfs: rootfs_entries() }
    }

    #[track_caller]
    fn assert_unchanged(&self) {
        assert_host_mounts_unchanged(&self.mounts, &host_mounts());
        assert_eq!(self.rootfs, rootfs_entries(), "a test created entries in the shared rootfs");
    }
}

/// Top-level entries of both shared rootfs trees (plain and remapped), as
/// full paths, sorted.
fn rootfs_entries() -> Vec<OsString> {
    let mut v = Vec::new();
    for root in [alpine_rootfs(), remap_rootfs()] {
        v.extend(std::fs::read_dir(&root).unwrap().map(|e| root.join(e.unwrap().file_name()).into_os_string()));
    }
    v.sort();
    v
}

// ── spec helpers ─────────────────────────────────────────────────────────────

/// Sets `linux.cgroupsPath` to a fresh cgroup `<name>-<n>` inside this test
/// binary's delegated scope, and returns that path.
pub fn set_cgroup(spec: &mut Spec, name: &str) -> String {
    static N: AtomicU32 = AtomicU32::new(0);
    let path = itest_cgroup(&format!("{name}-{}", N.fetch_add(1, Ordering::Relaxed)));
    set_cgroups_path(spec, &path);
    path
}

/// Sets `linux.cgroupsPath` verbatim.
pub fn set_cgroups_path(spec: &mut Spec, path: &str) {
    spec.linux_mut().as_mut().unwrap().set_cgroups_path(Some(path.into()));
}

/// Sets `linux.resources`.
pub fn set_resources(spec: &mut Spec, resources: LinuxResources) {
    spec.linux_mut().as_mut().unwrap().set_resources(Some(resources));
}

/// Sets `process.terminal: true`, and `process.consoleSize` if given as
/// `(height, width)`.
pub fn set_terminal(spec: &mut Spec, size: Option<(u64, u64)>) {
    let mut p = spec.process().clone().unwrap();
    p.set_terminal(Some(true));
    if let Some((height, width)) = size {
        p.set_console_size(Some(BoxBuilder::default().height(height).width(width).build().unwrap()));
    }
    spec.set_process(Some(p));
}

/// Bind-mounts a fresh host temp dir read-write onto `dest`, which must
/// already exist in Alpine (`/mnt`, `/tmp`), and returns the host dir.
pub fn bind_host_dir(spec: &mut Spec, dest: &str) -> tempfile::TempDir {
    let dir = tempfile::Builder::new().prefix("rustlet-e2e-").tempdir().unwrap();
    add_mount(spec, dest, "bind", dir.path().to_str().unwrap(), &["rbind", "rw"]);
    dir
}

// ── cgroups (host view) ──────────────────────────────────────────────────────

/// `/sys/fs/cgroup<cgroups_path>`.
pub fn cgroup_dir(cgroups_path: &str) -> PathBuf {
    PathBuf::from(format!("/sys/fs/cgroup{cgroups_path}"))
}

/// A cgroup interface file, trimmed. Panics if it can't be read.
#[track_caller]
pub fn cgroup_read(cgroups_path: &str, file: &str) -> String {
    let p = cgroup_dir(cgroups_path).join(file);
    match std::fs::read_to_string(&p) {
        Ok(s) => s.trim().to_owned(),
        Err(e) => panic!("read {}: {e}", p.display()),
    }
}

/// The number after `key ` in a flat-keyed file (`memory.events`,
/// `pids.events`, `cgroup.events`, `cpu.stat`, …).
pub fn flat_key(text: &str, key: &str) -> Option<u64> {
    text.lines().find_map(|l| l.strip_prefix(key)?.strip_prefix(' ')?.trim().parse().ok())
}

/// The PIDs in a cgroup's `cgroup.procs`, sorted (empty if it's gone).
pub fn cgroup_procs(cgroups_path: &str) -> Vec<i32> {
    let text = std::fs::read_to_string(cgroup_dir(cgroups_path).join("cgroup.procs")).unwrap_or_default();
    let mut v: Vec<i32> = text.lines().filter_map(|l| l.trim().parse().ok()).collect();
    v.sort();
    v
}

/// This process's own cgroup (`<scope>/harness` once [`itest_scope`] ran).
pub fn own_cgroup() -> Option<String> {
    let text = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    text.lines().find_map(|l| l.strip_prefix("0::")).map(|p| p.trim().to_owned())
}

/// Whether `dir` (under `/sys/fs/cgroup`) is this process's cgroup or one of
/// its ancestors: killing or removing that would take the harness with it.
fn contains_us(dir: &Path) -> bool {
    own_cgroup().is_none_or(|own| cgroup_dir(&own).starts_with(dir))
}

/// Last-resort cleanup of a cgroup a test (or a buggy runtime) left behind:
/// `cgroup.kill`, wait for `populated 0`, then `rmdir` children first.
/// Refuses anything that isn't a plain path under `/sys/fs/cgroup` or that
/// contains this process. Returns whether it found something to clean.
/// Never panics.
pub fn force_remove_cgroup(dir: &Path) -> bool {
    if !dir.is_dir() {
        return false;
    }
    let plain = dir.components().all(|c| matches!(c, Component::RootDir | Component::Normal(_)));
    if !plain || !dir.starts_with("/sys/fs/cgroup") || dir == Path::new("/sys/fs/cgroup") || contains_us(dir) {
        eprintln!("e2e: refusing to clean up cgroup {}", dir.display());
        return false;
    }
    let _ = std::fs::write(dir.join("cgroup.kill"), "1");
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        let events = std::fs::read_to_string(dir.join("cgroup.events")).unwrap_or_default();
        if flat_key(&events, "populated") != Some(1) {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    rmdir_tree(dir);
    true
}

fn rmdir_tree(dir: &Path) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            if e.file_type().is_ok_and(|t| t.is_dir()) {
                rmdir_tree(&e.path());
            }
        }
    }
    if let Err(e) = std::fs::remove_dir(dir) {
        eprintln!("e2e: rmdir {}: {e}", dir.display());
    }
}

/// Removes a cgroup directory on drop, if a test (or a runtime bug) made it.
pub struct CgroupGuard(pub PathBuf);

impl Drop for CgroupGuard {
    fn drop(&mut self) {
        if force_remove_cgroup(&self.0) {
            eprintln!("e2e: cleaned up leftover cgroup {}", self.0.display());
        }
    }
}

// ── processes (host view) ────────────────────────────────────────────────────

/// The fields of a `/proc/<pid>/stat` line after `(comm)`: index 0 is the
/// state (field 3 in proc(5)), 1 ppid, 2 pgrp, 3 session, 4 tty_nr, 5 tpgid,
/// 19 starttime. `comm` can contain spaces and parentheses, hence the last `)`.
pub fn stat_fields(stat: &str) -> Vec<&str> {
    stat.rsplit_once(')').map_or(Vec::new(), |(_, rest)| rest.split_whitespace().collect())
}

/// `/proc/<pid>/stat`'s starttime (clock ticks after boot), which tells a
/// process apart from a later one with a reused PID.
pub fn starttime(pid: i32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    stat_fields(&stat).get(19)?.parse().ok()
}

/// Whether `pid` is still the process that started at `start` and hasn't
/// exited (zombies count as dead).
pub fn alive(pid: i32, start: u64) -> bool {
    let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else { return false };
    let f = stat_fields(&stat);
    !matches!(f.first(), Some(&("Z" | "X"))) && f.get(19).and_then(|s| s.parse().ok()) == Some(start)
}

// ── containers ───────────────────────────────────────────────────────────────

/// One container, driven through the `rustlet-runc` CLI.
///
/// Its bundle is written by [`Container::new`]; nothing runs until
/// [`create`](Self::create) or [`run_detached`](Self::run_detached) (or
/// [`run_foreground`](Self::run_foreground)). Those give the container files
/// as stdout/stderr, readable with [`stdout`](Self::stdout).
///
/// Dropping it runs `delete --force <id>`, then (if anything survived) kills
/// its cgroup and its init.
pub struct Container {
    /// The bundle and the container id (`bundle.id`, which a test may change
    /// before launching, e.g. to reuse an id).
    pub bundle: TestBundle,
    /// `linux.cgroupsPath`, if it's a plain absolute path that doesn't
    /// contain this process (only such a path is safe to clean up).
    cgroup: Option<String>,
    /// The container's stdout/stderr files.
    io: tempfile::TempDir,
    /// `(pid, starttime)` of init after a successful create, for cleanup.
    init: Option<(i32, u64)>,
}

impl Container {
    /// Writes the bundle for `spec`.
    pub fn new(spec: &Spec) -> Container {
        // Put the harness in its leaf cgroup before this binary spawns
        // anything, even in tests without cgroups: a child spawned earlier
        // would stay in the scope itself, and cgroup v2's "no internal
        // processes" rule would then keep controllers off every container
        // cgroup in the scope.
        itest_scope();
        let cgroup =
            spec.linux().as_ref().and_then(|l| l.cgroups_path().as_ref()).map(|p| p.display().to_string()).filter(
                |p| p.starts_with('/') && !p.split('/').any(|c| c == "." || c == "..") && !contains_us(&cgroup_dir(p)),
            );
        Container { bundle: TestBundle::new(spec), cgroup, io: tempfile::tempdir().unwrap(), init: None }
    }

    /// [`new`](Self::new) + `create`, asserting success.
    #[track_caller]
    pub fn created(spec: &Spec) -> Container {
        let mut c = Container::new(spec);
        c.create(&[]).ok();
        c
    }

    /// [`created`](Self::created) + `start`, asserting success.
    #[track_caller]
    pub fn started(spec: &Spec) -> Container {
        let c = Container::created(spec);
        c.start().ok();
        c
    }

    pub fn id(&self) -> &str {
        &self.bundle.id
    }

    pub fn bundle_dir(&self) -> &Path {
        self.bundle.dir.path()
    }

    /// `<runtime root>/<id>`.
    pub fn state_dir(&self) -> PathBuf {
        runtime_root().join(self.id())
    }

    /// The container's `linux.cgroupsPath`.
    #[track_caller]
    pub fn cgroup(&self) -> &str {
        self.cgroup.as_deref().expect("this container has no (cleanable) cgroupsPath")
    }

    /// `create --bundle <dir> [extra…] <id>`.
    #[track_caller]
    pub fn create(&mut self, extra: &[&str]) -> CmdOut {
        self.launch(&["create"], extra, &[], None, TIMEOUT)
    }

    /// `create --bundle <dir> [extra…] <id>`, started with `fds` open as fds
    /// 3, 4, … (for `--preserve-fds`).
    #[track_caller]
    pub fn create_with_fds(&mut self, extra: &[&str], fds: &[ExtraFd<'_>]) -> CmdOut {
        self.launch(&["create"], extra, fds, None, TIMEOUT)
    }

    /// `run --detach --bundle <dir> [extra…] <id>`.
    #[track_caller]
    pub fn run_detached(&mut self, extra: &[&str]) -> CmdOut {
        self.launch(&["run", "--detach"], extra, &[], None, TIMEOUT)
    }

    /// Foreground `run --bundle <dir> [extra…] <id>`, with `input` on a stdin
    /// pipe (closed after writing it) or /dev/null; panics after `timeout`.
    #[track_caller]
    pub fn run_foreground(&mut self, extra: &[&str], input: Option<&[u8]>, timeout: Duration) -> CmdOut {
        self.launch(&["run"], extra, &[], input, timeout)
    }

    /// Foreground `run --bundle <dir> [extra…] <id>` (stdin /dev/null),
    /// started with `fds` open as fds 3, 4, … (for `--preserve-fds`).
    #[track_caller]
    pub fn run_foreground_with_fds(&mut self, extra: &[&str], fds: &[ExtraFd<'_>]) -> CmdOut {
        self.launch(&["run"], extra, fds, None, TIMEOUT)
    }

    #[track_caller]
    fn launch(
        &mut self,
        sub: &[&str],
        extra: &[&str],
        fds: &[ExtraFd<'_>],
        input: Option<&[u8]>,
        timeout: Duration,
    ) -> CmdOut {
        let mut cmd = runc(sub);
        cmd.arg("--bundle").arg(self.bundle.dir.path()).args(extra).arg(&self.bundle.id);
        if !fds.is_empty() {
            cmd = with_extra_fds(&cmd, fds);
        }
        let before = HostSnapshot::take();
        let (out, err) = (self.io.path().join("stdout"), self.io.path().join("stderr"));
        let o = match run_captured(&mut cmd, input, &out, &err, timeout) {
            Ok(o) => o,
            Err(o) => panic!("{cmd:?} did not finish within {timeout:?}: {o:#?}"),
        };
        before.assert_unchanged();
        if o.status == 0 && sub != ["run"] {
            self.remember_init();
        }
        o
    }

    /// Records init's pid and start time for `Drop`, but only if the pid is
    /// plausible: in the container's cgroup, or (without one) in ours.
    fn remember_init(&mut self) {
        let out = self.try_state();
        let Some(pid) = Json::parse(out.stdout.trim()).ok().and_then(|j| j["pid"].as_i64()) else { return };
        let Ok(pid) = i32::try_from(pid) else { return };
        if pid <= 1 || pid == std::process::id() as i32 {
            return;
        }
        let cg = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).unwrap_or_default();
        let cg = cg.lines().find_map(|l| l.strip_prefix("0::")).map(str::trim);
        let expected = self.cgroup.clone().or_else(own_cgroup);
        if cg.is_some()
            && cg == expected.as_deref()
            && let Some(start) = starttime(pid)
        {
            self.init = Some((pid, start));
        }
    }

    /// `rustlet-runc <args…> <id>`.
    #[track_caller]
    pub fn cmd(&self, args: &[&str]) -> CmdOut {
        exec(self.bundle.runc_with_id(args))
    }

    #[track_caller]
    pub fn start(&self) -> CmdOut {
        self.cmd(&["start"])
    }

    /// `rustlet-runc exec [opts…] <id> [argv…]`, not yet started.
    pub fn exec_command(&self, opts: &[&str], argv: &[&str]) -> Command {
        let mut c = runc(&["exec"]);
        c.args(opts).arg(self.id()).args(argv);
        c
    }

    /// `rustlet-runc exec [opts…] <id> [argv…]`, run to completion.
    #[track_caller]
    pub fn exec_in(&self, opts: &[&str], argv: &[&str]) -> CmdOut {
        exec(self.exec_command(opts, argv))
    }

    /// `delete [--force] <id>`.
    #[track_caller]
    pub fn delete(&self, force: bool) -> CmdOut {
        self.cmd(if force { &["delete", "--force"][..] } else { &["delete"][..] })
    }

    /// `kill [--all] <id> [SIGNAL]`.
    #[track_caller]
    pub fn kill(&self, all: bool, signal: Option<&str>) -> CmdOut {
        let mut c = runc(&["kill"]);
        if all {
            c.arg("--all");
        }
        c.arg(self.id()).args(signal);
        exec(c)
    }

    /// `state <id>`, whatever it says.
    #[track_caller]
    pub fn try_state(&self) -> CmdOut {
        self.cmd(&["state"])
    }

    /// `state <id>`, asserting success, parsed.
    #[track_caller]
    pub fn state(&self) -> Json {
        let out = self.try_state();
        parse_json(out.ok(), "state")
    }

    /// `state`'s `status`.
    #[track_caller]
    pub fn status(&self) -> String {
        let st = self.state();
        st["status"].as_str().unwrap_or_else(|| panic!("`state` has no string `status`: {st:?}")).to_owned()
    }

    /// `state`'s `pid`.
    #[track_caller]
    pub fn pid(&self) -> i32 {
        let st = self.state();
        st["pid"].as_i64().and_then(|p| i32::try_from(p).ok()).unwrap_or_else(|| panic!("`state` has no pid: {st:?}"))
    }

    /// Polls `state` until `status` is `want`.
    #[track_caller]
    pub fn wait_for_status(&self, want: &str, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        loop {
            let out = self.try_state();
            let json = Json::parse(out.stdout.trim()).ok();
            if json.as_ref().and_then(|j| j["status"].as_str()) == Some(want) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "{} is not {want:?} after {timeout:?}; last `state`: {out:#?}",
                self.id()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// `events --stats <id>`, asserting it prints one stats object for us.
    #[track_caller]
    pub fn stats(&self) -> Json {
        let out = self.cmd(&["events", "--stats"]);
        let j = parse_json(out.ok(), "events --stats");
        assert_eq!(j["type"].as_str(), Some("stats"), "{j:?}");
        assert_eq!(j["id"].as_str(), Some(self.id()), "{j:?}");
        j
    }

    /// Everything written to the container's stdout (and the launching
    /// command's) so far.
    pub fn stdout(&self) -> String {
        read_lossy(&self.io.path().join("stdout"))
    }

    /// Everything written to the container's stderr (and the launching
    /// command's) so far.
    pub fn stderr(&self) -> String {
        read_lossy(&self.io.path().join("stderr"))
    }

    /// Asserts nothing of the container is left: no state directory, no
    /// cgroup, and `state` fails.
    #[track_caller]
    pub fn assert_gone(&self) {
        assert!(!self.state_dir().exists(), "{} still exists", self.state_dir().display());
        if let Some(cg) = &self.cgroup {
            assert!(!cgroup_dir(cg).exists(), "cgroup {cg} still exists");
        }
        let out = self.try_state();
        assert_ne!(out.status, 0, "`state` still knows {}: {out:#?}", self.id());
    }
}

impl Drop for Container {
    fn drop(&mut self) {
        // This also runs while a failed test unwinds, so it must not panic.
        if let Some(mut cmd) = runc_quiet(&["delete", "--force", self.id()])
            && quiet(&mut cmd, TIMEOUT).is_none()
        {
            eprintln!("e2e: `delete --force {}` hung; cleaning up by hand", self.id());
        }
        if let Some(cg) = &self.cgroup
            && force_remove_cgroup(&cgroup_dir(cg))
        {
            eprintln!("e2e: `delete --force {}` left cgroup {cg} behind; removed it", self.id());
        }
        if let Some((pid, start)) = self.init
            && alive(pid, start)
        {
            eprintln!("e2e: `delete --force {}` left init {pid} running; killing it", self.id());
            let _ = kill(Pid::from_raw(pid), Signal::SIGKILL);
        }
    }
}

// ── Phase 2b: security settings ──────────────────────────────────────────────

/// Docker's masked paths: the default spec's `linux.maskedPaths`.
pub const MASKED_PATHS: [&str; 12] = [
    "/proc/asound",
    "/proc/acpi",
    "/proc/interrupts",
    "/proc/kcore",
    "/proc/keys",
    "/proc/latency_stats",
    "/proc/timer_list",
    "/proc/timer_stats",
    "/proc/sched_debug",
    "/proc/scsi",
    "/sys/firmware",
    "/sys/devices/virtual/powercap",
];

/// The default spec's `linux.readonlyPaths`.
pub const READONLY_PATHS: [&str; 5] = ["/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger"];

/// Podman's default capabilities, which the default spec grants.
pub const DEFAULT_CAPS: [&str; 11] = [
    "CAP_CHOWN",
    "CAP_DAC_OVERRIDE",
    "CAP_FOWNER",
    "CAP_FSETID",
    "CAP_KILL",
    "CAP_NET_BIND_SERVICE",
    "CAP_SETFCAP",
    "CAP_SETGID",
    "CAP_SETPCAP",
    "CAP_SETUID",
    "CAP_SYS_CHROOT",
];

/// [`DEFAULT_CAPS`] as the kernel's bit mask (`CapEff:` in `/proc/<pid>/status`).
pub const DEFAULT_CAP_MASK: u64 = 0x0000_0000_8004_05fb;

/// capabilities(7) names in bit order.
const CAP_NAMES: [&str; 41] = [
    "CHOWN",
    "DAC_OVERRIDE",
    "DAC_READ_SEARCH",
    "FOWNER",
    "FSETID",
    "KILL",
    "SETGID",
    "SETUID",
    "SETPCAP",
    "LINUX_IMMUTABLE",
    "NET_BIND_SERVICE",
    "NET_BROADCAST",
    "NET_ADMIN",
    "NET_RAW",
    "IPC_LOCK",
    "IPC_OWNER",
    "SYS_MODULE",
    "SYS_RAWIO",
    "SYS_CHROOT",
    "SYS_PTRACE",
    "SYS_PACCT",
    "SYS_ADMIN",
    "SYS_BOOT",
    "SYS_NICE",
    "SYS_RESOURCE",
    "SYS_TIME",
    "SYS_TTY_CONFIG",
    "MKNOD",
    "LEASE",
    "AUDIT_WRITE",
    "AUDIT_CONTROL",
    "SETFCAP",
    "MAC_OVERRIDE",
    "MAC_ADMIN",
    "SYSLOG",
    "WAKE_ALARM",
    "BLOCK_SUSPEND",
    "AUDIT_READ",
    "PERFMON",
    "BPF",
    "CHECKPOINT_RESTORE",
];

/// The mask bit of a capability (`CAP_` prefix optional).
#[track_caller]
pub fn cap_bit(name: &str) -> u64 {
    let short = name.strip_prefix("CAP_").unwrap_or(name);
    let n = CAP_NAMES.iter().position(|c| *c == short).unwrap_or_else(|| panic!("unknown capability {name}"));
    1 << n
}

/// The mask of a list of capabilities.
pub fn cap_mask(names: &[&str]) -> u64 {
    names.iter().map(|n| cap_bit(n)).fold(0, |a, b| a | b)
}

/// Capability names (`CAP_` prefix optional) as an oci-spec set.
#[track_caller]
pub fn cap_set(names: &[&str]) -> Capabilities {
    names
        .iter()
        .map(|n| {
            let short = n.strip_prefix("CAP_").unwrap_or(n);
            Capability::from_str(short).unwrap_or_else(|e| panic!("capability {n}: {e}"))
        })
        .collect()
}

/// The five capability sets of `process.capabilities`.
#[derive(Debug, Clone, Copy, Default)]
pub struct CapSets<'a> {
    pub bounding: &'a [&'a str],
    pub effective: &'a [&'a str],
    pub permitted: &'a [&'a str],
    pub inheritable: &'a [&'a str],
    pub ambient: &'a [&'a str],
}

impl<'a> CapSets<'a> {
    /// `caps` in bounding, effective and permitted (what root gets by
    /// default); inheritable and ambient empty.
    pub fn root(caps: &'a [&'a str]) -> CapSets<'a> {
        CapSets { bounding: caps, effective: caps, permitted: caps, ..CapSets::default() }
    }

    /// `caps` in all five sets (what a non-root user needs to keep them
    /// across execve).
    pub fn all(caps: &'a [&'a str]) -> CapSets<'a> {
        CapSets { bounding: caps, effective: caps, permitted: caps, inheritable: caps, ambient: caps }
    }
}

/// Sets `process.capabilities`.
pub fn set_capabilities(spec: &mut Spec, sets: CapSets<'_>) {
    let caps = LinuxCapabilitiesBuilder::default()
        .bounding(cap_set(sets.bounding))
        .effective(cap_set(sets.effective))
        .permitted(cap_set(sets.permitted))
        .inheritable(cap_set(sets.inheritable))
        .ambient(cap_set(sets.ambient))
        .build()
        .unwrap();
    edit_process(spec, |p| {
        p.set_capabilities(Some(caps));
    });
}

/// Changes `spec.process` in place.
pub fn edit_process(spec: &mut Spec, f: impl FnOnce(&mut Process)) {
    let mut p = spec.process().clone().unwrap();
    f(&mut p);
    spec.set_process(Some(p));
}

/// Changes `spec.linux` in place.
pub fn edit_linux(spec: &mut Spec, f: impl FnOnce(&mut Linux)) {
    f(spec.linux_mut().as_mut().unwrap());
}

/// Sets `process.user`.
pub fn set_user(spec: &mut Spec, uid: u32, gid: u32, additional_gids: &[u32]) {
    edit_process(spec, |p| {
        let mut u = p.user().clone();
        u.set_uid(uid);
        u.set_gid(gid);
        u.set_additional_gids((!additional_gids.is_empty()).then(|| additional_gids.to_vec()));
        p.set_user(u);
    });
}

/// Sets `process.env`.
pub fn set_env(spec: &mut Spec, env: &[&str]) {
    edit_process(spec, |p| {
        p.set_env(Some(env.iter().map(|s| s.to_string()).collect()));
    });
}

/// Sets `process.noNewPrivileges`.
pub fn set_no_new_privileges(spec: &mut Spec, on: bool) {
    edit_process(spec, |p| {
        p.set_no_new_privileges(Some(on));
    });
}

/// Removes a namespace from `linux.namespaces`: the container shares the
/// caller's.
pub fn without_namespace(spec: &mut Spec, typ: LinuxNamespaceType) {
    edit_linux(spec, |l| {
        let ns = l.namespaces().clone().unwrap_or_default().into_iter().filter(|n| n.typ() != typ).collect();
        l.set_namespaces(Some(ns));
    });
}

/// Makes the container join the namespace at `path` instead of a new one.
pub fn join_namespace(spec: &mut Spec, typ: LinuxNamespaceType, path: &str) {
    without_namespace(spec, typ);
    let ns = LinuxNamespaceBuilder::default().typ(typ).path(path).build().unwrap();
    edit_linux(spec, |l| l.namespaces_mut().get_or_insert_with(Vec::new).push(ns));
}

/// Lines with runs of whitespace (tabs from /proc files) collapsed to one
/// space.
pub fn norm_lines(text: &str) -> Vec<String> {
    text.lines().map(|l| l.split_whitespace().collect::<Vec<_>>().join(" ")).collect()
}

/// The value of `Key:` in `/proc/<pid>/status`-style text.
pub fn status_field<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    text.lines().find_map(|l| l.strip_prefix(key)?.strip_prefix(':')).map(str::trim)
}

/// A hex field such as `CapEff:` in `/proc/<pid>/status`-style text.
#[track_caller]
pub fn status_hex(text: &str, key: &str) -> u64 {
    let v = status_field(text, key).unwrap_or_else(|| panic!("no {key}: in {text:?}"));
    u64::from_str_radix(v, 16).unwrap_or_else(|e| panic!("{key}: {v:?}: {e}"))
}

/// A script that listens on TCP port 80 with busybox `nc` and prints
/// `listening` once the socket is bound, or `nc-exited` if nc gave up
/// (e.g. `bind: Permission denied`).
pub const LISTEN_ON_80: &str = "nc -l -p 80 </dev/null & pid=$!; i=0; \
    while [ $i -lt 200 ]; do \
      if netstat -ltn | grep -q ':80 '; then echo listening; break; fi; \
      if ! kill -0 $pid 2>/dev/null; then echo nc-exited; break; fi; \
      sleep 0.05; i=$((i+1)); \
    done; kill $pid 2>/dev/null; wait";

/// Asserts that `/proc/<pid>/exe` is a sealed memfd copy of rustlet-runc
/// that can't be written through: the attack in CVE-2019-5736 overwrites
/// the runtime binary through exactly this link.
#[track_caller]
pub fn assert_sealed_memfd_exe(pid: i32) {
    let link = format!("/proc/{pid}/exe");
    let exe = std::fs::read_link(&link).unwrap_or_else(|e| panic!("readlink {link}: {e}"));
    assert!(exe.to_string_lossy().starts_with("/memfd:rustlet-runc"), "{link} -> {}", exe.display());
    // Only now that it is known not to be the binary in target/: try to write.
    let f = File::open(&link).unwrap();
    let seals = nix::fcntl::fcntl(&f, nix::fcntl::FcntlArg::F_GET_SEALS).unwrap();
    // F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE
    let wanted = 0x1 | 0x2 | 0x4 | 0x8;
    assert_eq!(seals & wanted, wanted, "memfd seals {seals:#x}, want at least {wanted:#x} (SEAL|SHRINK|GROW|WRITE)");
    match std::fs::OpenOptions::new().write(true).open(&link) {
        Err(e) => eprintln!("e2e: opening {link} for writing failed: {e}"),
        Ok(mut f) => match f.write_all(b"x").and_then(|()| f.flush()) {
            Ok(()) => panic!("wrote to {link}"),
            Err(e) => eprintln!("e2e: {link} opened for writing, but writing failed: {e}"),
        },
    }
}

// ── extra file descriptors (--preserve-fds) ──────────────────────────────────

/// A file that a command gets as an extra fd (3, 4, …).
#[derive(Debug, Clone, Copy)]
pub enum ExtraFd<'a> {
    /// Opened for reading.
    Read(&'a Path),
    /// Created/truncated for writing.
    Write(&'a Path),
}

/// `cmd`, started by the host's `/bin/sh` with `fds` open as fds 3, 4, …
/// (`exec 3<"$1" 4>"$2"; shift 2; exec "$@"`). That hands a program extra
/// fds without `pre_exec`, which would need unsafe code. The Rust side's own
/// fds are all close-on-exec, so nothing else is passed along.
pub fn with_extra_fds(cmd: &Command, fds: &[ExtraFd<'_>]) -> Command {
    assert!(fds.len() <= 9, "at most 9 extra fds");
    let mut script = String::from("exec");
    for (i, fd) in fds.iter().enumerate() {
        let op = if matches!(fd, ExtraFd::Read(_)) { '<' } else { '>' };
        script.push_str(&format!(" {}{op}\"${}\"", 3 + i, i + 1));
    }
    script.push_str(&format!(" || exit 99; shift {}; exec \"$@\"", fds.len()));
    let mut c = Command::new("/bin/sh");
    c.arg("-c").arg(script).arg("sh");
    for fd in fds {
        let (ExtraFd::Read(p) | ExtraFd::Write(p)) = fd;
        c.arg(p);
    }
    c.arg(cmd.get_program()).args(cmd.get_args()).stdin(Stdio::null());
    c
}

// ── terminals ────────────────────────────────────────────────────────────────

/// Reads a PTY master into `buf` until `buf` contains `needle`. Panics after
/// `timeout`, or if the pty closes first (EIO once the container is gone).
#[track_caller]
pub fn pty_read_until(pty: &File, buf: &mut String, needle: &str, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while !buf.contains(needle) {
        let left = deadline.saturating_duration_since(Instant::now());
        assert!(!left.is_zero(), "timed out waiting for {needle:?} on the pty; got {buf:?}");
        let mut fds = [PollFd::new(pty.as_fd(), PollFlags::POLLIN)];
        match poll(&mut fds, PollTimeout::try_from(left).unwrap_or(PollTimeout::MAX)) {
            Ok(0) | Err(Errno::EINTR) => continue,
            Ok(_) => {}
            Err(e) => panic!("poll on the pty: {e}"),
        }
        let mut chunk = [0u8; 4096];
        let mut reader = pty;
        match reader.read(&mut chunk) {
            Ok(0) => panic!("EOF on the pty before {needle:?}; got {buf:?}"),
            Ok(n) => buf.push_str(&String::from_utf8_lossy(&chunk[..n])),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => panic!("the pty closed ({e}) before {needle:?}; got {buf:?}"),
        }
    }
}

// ── JSON ─────────────────────────────────────────────────────────────────────

/// A parsed JSON value. Numbers keep their text, so 64-bit counters survive
/// exactly; [`as_u64`](Self::as_u64) and friends parse on demand.
#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Number(String),
    String(String),
    Array(Vec<Json>),
    Object(Vec<(String, Json)>),
}

static NULL: Json = Json::Null;

/// `obj["key"]`: the member, or `Null` if absent (use [`Json::get`] to tell
/// the two apart).
impl std::ops::Index<&str> for Json {
    type Output = Json;
    fn index(&self, key: &str) -> &Json {
        self.get(key).unwrap_or(&NULL)
    }
}

impl Json {
    /// Parses exactly one JSON value (surrounding whitespace allowed).
    pub fn parse(text: &str) -> Result<Json, String> {
        let mut p = Parser { s: text.as_bytes(), i: 0 };
        let v = p.value()?;
        p.ws();
        if p.i != p.s.len() {
            return p.err("trailing data after the JSON value");
        }
        Ok(v)
    }

    /// An object member.
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Object(fields) => fields.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        if let Json::String(s) = self { Some(s) } else { None }
    }

    pub fn as_i64(&self) -> Option<i64> {
        if let Json::Number(n) = self { n.parse().ok() } else { None }
    }

    pub fn as_u64(&self) -> Option<u64> {
        if let Json::Number(n) = self { n.parse().ok() } else { None }
    }

    pub fn as_f64(&self) -> Option<f64> {
        if let Json::Number(n) = self { n.parse().ok() } else { None }
    }

    pub fn as_bool(&self) -> Option<bool> {
        if let Json::Bool(b) = self { Some(*b) } else { None }
    }

    pub fn as_array(&self) -> Option<&[Json]> {
        if let Json::Array(a) = self { Some(a) } else { None }
    }

    pub fn as_object(&self) -> Option<&[(String, Json)]> {
        if let Json::Object(o) = self { Some(o) } else { None }
    }

    pub fn is_null(&self) -> bool {
        matches!(self, Json::Null)
    }
}

/// Parses a command's JSON output, panicking with the text if it isn't
/// exactly one JSON value.
#[track_caller]
pub fn parse_json(text: &str, what: &str) -> Json {
    match Json::parse(text) {
        Ok(j) => j,
        Err(e) => panic!("`{what}` did not print one JSON value ({e}): {text:?}"),
    }
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
}

impl Parser<'_> {
    fn err<T>(&self, what: &str) -> Result<T, String> {
        Err(format!("{what} at byte {}", self.i))
    }

    fn ws(&mut self) {
        while matches!(self.s.get(self.i), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }

    fn eat(&mut self, lit: &str) -> bool {
        let hit = self.s[self.i..].starts_with(lit.as_bytes());
        if hit {
            self.i += lit.len();
        }
        hit
    }

    fn value(&mut self) -> Result<Json, String> {
        self.ws();
        match self.s.get(self.i) {
            None => self.err("unexpected end of input"),
            Some(b'{') => {
                self.i += 1;
                let mut fields = Vec::new();
                self.ws();
                if self.eat("}") {
                    return Ok(Json::Object(fields));
                }
                loop {
                    self.ws();
                    let key = self.string()?;
                    self.ws();
                    if !self.eat(":") {
                        return self.err("expected ':'");
                    }
                    fields.push((key, self.value()?));
                    self.ws();
                    if self.eat("}") {
                        return Ok(Json::Object(fields));
                    }
                    if !self.eat(",") {
                        return self.err("expected ',' or '}'");
                    }
                }
            }
            Some(b'[') => {
                self.i += 1;
                let mut items = Vec::new();
                self.ws();
                if self.eat("]") {
                    return Ok(Json::Array(items));
                }
                loop {
                    items.push(self.value()?);
                    self.ws();
                    if self.eat("]") {
                        return Ok(Json::Array(items));
                    }
                    if !self.eat(",") {
                        return self.err("expected ',' or ']'");
                    }
                }
            }
            Some(b'"') => Ok(Json::String(self.string()?)),
            Some(b't') if self.eat("true") => Ok(Json::Bool(true)),
            Some(b'f') if self.eat("false") => Ok(Json::Bool(false)),
            Some(b'n') if self.eat("null") => Ok(Json::Null),
            Some(b'-' | b'0'..=b'9') => {
                let start = self.i;
                self.i += 1;
                while matches!(self.s.get(self.i), Some(b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-')) {
                    self.i += 1;
                }
                let text = std::str::from_utf8(&self.s[start..self.i]).unwrap();
                if text.parse::<f64>().is_err() {
                    return self.err(&format!("bad number {text:?}"));
                }
                Ok(Json::Number(text.to_owned()))
            }
            Some(_) => self.err("unexpected character"),
        }
    }

    fn string(&mut self) -> Result<String, String> {
        if !self.eat("\"") {
            return self.err("expected a string");
        }
        let mut out = Vec::new();
        loop {
            match self.s.get(self.i) {
                None => return self.err("unterminated string"),
                Some(b'"') => {
                    self.i += 1;
                    return String::from_utf8(out).map_err(|e| format!("invalid UTF-8 in a string: {e}"));
                }
                Some(b'\\') => {
                    self.i += 1;
                    let c = match self.s.get(self.i) {
                        Some(b'"') => '"',
                        Some(b'\\') => '\\',
                        Some(b'/') => '/',
                        Some(b'b') => '\u{8}',
                        Some(b'f') => '\u{c}',
                        Some(b'n') => '\n',
                        Some(b'r') => '\r',
                        Some(b't') => '\t',
                        Some(b'u') => {
                            self.i += 1;
                            let hi = self.hex4()?;
                            let code = if (0xD800..0xDC00).contains(&hi) {
                                if !self.eat("\\u") {
                                    return self.err("unpaired surrogate");
                                }
                                let lo = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&lo) {
                                    return self.err("unpaired surrogate");
                                }
                                0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                            } else {
                                hi
                            };
                            let Some(c) = char::from_u32(code) else { return self.err("bad \\u escape") };
                            out.extend_from_slice(c.encode_utf8(&mut [0; 4]).as_bytes());
                            continue;
                        }
                        _ => return self.err("bad escape"),
                    };
                    self.i += 1;
                    out.extend_from_slice(c.encode_utf8(&mut [0; 4]).as_bytes());
                }
                Some(&b) => {
                    out.push(b);
                    self.i += 1;
                }
            }
        }
    }

    fn hex4(&mut self) -> Result<u32, String> {
        let h = self.s.get(self.i..self.i + 4).and_then(|h| std::str::from_utf8(h).ok());
        let Some(n) = h.and_then(|h| u32::from_str_radix(h, 16).ok()) else { return self.err("bad \\u escape") };
        self.i += 4;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn e2e_json_parses_runtime_style_output() {
        let j = Json::parse(
            r#" {"ociVersion":"1.2.0","id":"a\"bé😀","pid":1234,"big":18446744073709551615,
                 "neg":-5,"f":1.5e3,"ok":true,"no":false,"none":null,"list":[1,[],{}]} "#,
        )
        .unwrap();
        assert_eq!(j["id"].as_str(), Some("a\"b\u{e9}\u{1F600}"));
        assert_eq!(j["pid"].as_i64(), Some(1234));
        assert_eq!(j["big"].as_u64(), Some(u64::MAX));
        assert_eq!(j["neg"].as_i64(), Some(-5));
        assert_eq!(j["f"].as_f64(), Some(1500.0));
        assert_eq!(j["ok"].as_bool(), Some(true));
        assert_eq!(j.get("none"), Some(&Json::Null));
        assert_eq!(j.get("missing"), None);
        assert!(j["missing"].is_null());
        assert_eq!(j["list"].as_array().map(<[Json]>::len), Some(3));
        assert!(Json::parse("{} {}").is_err());
        assert!(Json::parse("[1,]").is_err());
        assert!(Json::parse("").is_err());
    }

    #[test]
    fn e2e_stat_fields_survive_awkward_comm() {
        let f = stat_fields("42 (a) b (c)) S 1 42 42 34816 42 0");
        assert_eq!(f[..6], ["S", "1", "42", "42", "34816", "42"]);
    }

    #[test]
    fn e2e_flat_key_reads_cgroup_files() {
        let t = "low 0\nhigh 0\nmax 3\noom 1\noom_kill 1\noom_group_kill 0\n";
        assert_eq!(flat_key(t, "oom"), Some(1));
        assert_eq!(flat_key(t, "oom_kill"), Some(1));
        assert_eq!(flat_key(t, "max"), Some(3));
        assert_eq!(flat_key(t, "nope"), None);
    }
}

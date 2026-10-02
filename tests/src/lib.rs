//! Helpers for the privileged integration tests (run with `cargo xtask itest`).
//!
//! Each test builds a throwaway bundle in a temp dir whose `root.path`
//! points at the shared Alpine rootfs from `cargo xtask rootfs` (always
//! read-only, so tests can't change it or each other), runs the real
//! `rustlet-runc` binary on it, and checks what the container printed.
//! User-namespace tests use [`userns_spec`] instead, on the copy from
//! `cargo xtask rootfs --remap` whose files are owned by the mapped host ids.
//!
//! Every run also asserts the host's mount table is unchanged afterwards:
//! nothing a container mounts may ever show up on the host.
#![forbid(unsafe_code)]

pub mod daemon;
pub mod e2e;
pub mod images;
pub mod net;
pub mod shim;

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};

use rustlet_runtime::oci_spec::runtime::{Mount, MountBuilder, Spec};
use rustlet_runtime::spec::{REMAP_HOST_ID, REMAP_SIZE, default_spec, to_pretty_json, with_user_namespace};

/// Reason string for `#[ignore]` on every privileged test.
pub const PRIVILEGED: &str = "needs root: run with `cargo xtask itest`";

/// The Alpine rootfs made by `cargo xtask rootfs`.
pub fn alpine_rootfs() -> PathBuf {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.rustlet-dev/bundles/alpine/rootfs");
    assert!(p.join("bin/busybox").exists(), "missing {}: run `cargo xtask rootfs`", p.display());
    p.canonicalize().unwrap()
}

/// The Alpine rootfs made by `cargo xtask rootfs --remap`: the same files,
/// owned by host ids `REMAP_HOST_ID` + their ids in the tarball, so that
/// container root in a [`userns_spec`] container owns what it should.
pub fn remap_rootfs() -> PathBuf {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.rustlet-dev/bundles/alpine-remap/rootfs");
    assert!(p.join("bin/busybox").exists(), "missing {}: run `cargo xtask rootfs --remap`", p.display());
    p.canonicalize().unwrap()
}

/// `target/debug/rustlet-runc`, next to this test binary's `deps/` directory.
pub fn runc_binary() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    let p = exe.parent().and_then(Path::parent).unwrap().join("rustlet-runc");
    assert!(p.exists(), "missing {}: run via `cargo xtask itest` (it builds rustlet-runc)", p.display());
    p
}

/// `target/debug/<name>`: a binary of this workspace, built by `cargo xtask
/// itest` next to `rustlet-runc`.
pub fn workspace_binary(name: &str) -> PathBuf {
    let p = runc_binary().with_file_name(name);
    assert!(p.exists(), "missing {}: run via `cargo xtask itest` (it builds it)", p.display());
    p
}

/// The state directory (`rustlet-runc --root`) for this test binary. Under
/// `/run/rustlet`, so `scripts/cleanup.sh` sweeps anything a failed run left.
pub fn runtime_root() -> PathBuf {
    PathBuf::from(format!("/run/rustlet/itest-{}", std::process::id()))
}

/// `rustlet-runc --root <runtime_root> <args…>` with stdin from /dev/null.
pub fn runc(args: &[&str]) -> Command {
    // Move into the harness leaf before spawning anything: a child spawned
    // while we still sit in the scope itself would stay there and block
    // controllers for every container cgroup ("no internal processes").
    itest_scope();
    let mut c = Command::new(runc_binary());
    c.arg("--root").arg(runtime_root()).args(args).stdin(Stdio::null());
    c
}

/// The systemd scope this test binary runs in (from `cargo xtask itest`),
/// as a cgroup path such as `/system.slice/rustlet-itest-123-0.scope`.
///
/// On first use the harness moves itself into the leaf `<scope>/harness`:
/// cgroup v2's "no internal processes" rule means the scope can only get
/// container child cgroups (with controllers) once no process sits in the
/// scope itself.
pub fn itest_scope() -> &'static str {
    static SCOPE: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    SCOPE.get_or_init(|| {
        require_root();
        let own = std::fs::read_to_string("/proc/self/cgroup").unwrap();
        let own = own.lines().find_map(|l| l.strip_prefix("0::")).unwrap().trim().to_owned();
        let scope = own.strip_suffix("/harness").unwrap_or(&own).to_owned();
        let name = scope.rsplit('/').next().unwrap_or("");
        assert!(
            name.starts_with("rustlet-itest-") && name.ends_with(".scope"),
            "not in a `cargo xtask itest` scope (cgroup {own}); run the privileged tests with `cargo xtask itest`"
        );
        let leaf = format!("/sys/fs/cgroup{scope}/harness");
        match std::fs::create_dir(&leaf) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => panic!("mkdir {leaf}: {e}"),
        }
        // "0" means "the writing process" (the whole thread group moves).
        std::fs::write(format!("{leaf}/cgroup.procs"), "0").unwrap();
        scope
    })
}

/// An absolute `linux.cgroupsPath` for a container cgroup inside this test
/// binary's delegated scope.
pub fn itest_cgroup(name: &str) -> String {
    format!("{}/{name}", itest_scope())
}

fn require_root() {
    assert!(nix::unistd::geteuid().is_root(), "{PRIVILEGED}");
}

/// The default spec, running `args`, on the shared read-only Alpine rootfs.
pub fn spec(args: &[&str]) -> Spec {
    let mut spec = default_spec();
    let mut root = spec.root().clone().unwrap();
    root.set_path(alpine_rootfs());
    root.set_readonly(Some(true));
    spec.set_root(Some(root));
    let mut process = spec.process().clone().unwrap();
    process.set_args(Some(args.iter().map(|s| s.to_string()).collect()));
    // Tests capture output through pipes; the terminal tests opt in.
    process.set_terminal(Some(false));
    spec.set_process(Some(process));
    spec
}

/// Shorthand: `spec(["sh", "-c", script])`.
pub fn sh(script: &str) -> Spec {
    spec(&["sh", "-c", script])
}

/// [`spec`], but in a new user namespace (container ids `0..REMAP_SIZE` are
/// host ids `REMAP_HOST_ID..`), on the matching read-only [`remap_rootfs`].
pub fn userns_spec(args: &[&str]) -> Spec {
    let mut spec = spec(args);
    let mut root = spec.root().clone().unwrap();
    root.set_path(remap_rootfs());
    spec.set_root(Some(root));
    with_user_namespace(&mut spec, REMAP_HOST_ID, REMAP_SIZE);
    spec
}

/// Shorthand: `userns_spec(["sh", "-c", script])`.
pub fn userns_sh(script: &str) -> Spec {
    userns_spec(&["sh", "-c", script])
}

/// Appends a mount to a spec.
pub fn add_mount(spec: &mut Spec, dest: &str, typ: &str, source: &str, options: &[&str]) {
    let m: Mount = MountBuilder::default()
        .destination(dest)
        .typ(typ)
        .source(source)
        .options(options.iter().map(|s| s.to_string()).collect::<Vec<_>>())
        .build()
        .unwrap();
    spec.mounts_mut().get_or_insert_with(Vec::new).push(m);
}

/// What a container run produced.
#[derive(Debug)]
pub struct Output {
    /// rustlet-runc's exit status (the container's, shell-style).
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

impl Output {
    /// Asserts exit status 0 and returns stdout.
    #[track_caller]
    pub fn ok(&self) -> &str {
        assert_eq!(self.status, 0, "container failed: {self:#?}");
        &self.stdout
    }
}

/// A bundle on disk; removed on drop.
pub struct TestBundle {
    pub dir: tempfile::TempDir,
    pub id: String,
}

impl TestBundle {
    pub fn new(spec: &Spec) -> TestBundle {
        require_root();
        static N: AtomicU32 = AtomicU32::new(0);
        let dir = tempfile::Builder::new().prefix("rustlet-itest-").tempdir().unwrap();
        std::fs::write(dir.path().join("config.json"), to_pretty_json(spec)).unwrap();
        let id = format!("itest-{}-{}", std::process::id(), N.fetch_add(1, Ordering::Relaxed));
        TestBundle { dir, id }
    }

    /// `rustlet-runc run --bundle <dir> <id>`, stdin from /dev/null.
    pub fn command(&self) -> Command {
        let dir = self.dir.path().to_str().unwrap();
        runc(&["run", "--bundle", dir, &self.id])
    }

    /// `rustlet-runc --root … <subcommand> [--bundle <dir>] <id>`-style
    /// helper: runs `args` with the bundle's id appended.
    pub fn runc_with_id(&self, args: &[&str]) -> Command {
        let mut c = runc(args);
        c.arg(&self.id);
        c
    }

    /// Starts the container with piped stdout/stderr.
    pub fn spawn(self, extra_args: &[&str]) -> Running {
        let mut c = self.command();
        let child = c.args(extra_args).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
        Running { child, _bundle: self }
    }
}

/// A container started with [`TestBundle::spawn`]. Dropping it SIGKILLs
/// rustlet-runc, and the container follows (init has `PR_SET_PDEATHSIG`),
/// so a test that panics halfway can't leave a container running.
pub struct Running {
    pub child: Child,
    _bundle: TestBundle,
}

impl Drop for Running {
    fn drop(&mut self) {
        if let Ok(None) = self.child.try_wait() {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
        // A SIGKILLed rustlet-runc can't delete its container (runc leaves a
        // stopped container behind in the same situation), so do it here.
        let _ = runc(&["delete", "--force", &self._bundle.id]).stdout(Stdio::null()).stderr(Stdio::null()).status();
    }
}

/// Runs `spec` to completion and checks the host mount table afterwards.
pub fn run(spec: &Spec) -> Output {
    let bundle = TestBundle::new(spec);
    // `root.path` may be relative to the bundle; `join` keeps absolute ones.
    let rootfs = bundle.dir.path().join(spec.root().as_ref().unwrap().path());
    let before = host_mounts();
    let rootfs_before = rootfs_entries(&rootfs);
    let out = bundle.command().output().unwrap();
    let after = host_mounts();
    assert_host_mounts_unchanged(&before, &after);
    // The rootfs is shared by every test; a mount point created in it (as
    // root, before the read-only remount) would leak into later runs.
    assert_eq!(rootfs_before, rootfs_entries(&rootfs), "a test created entries in the shared rootfs");
    Output {
        status: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// Top-level names in a (shared) rootfs, sorted.
fn rootfs_entries(rootfs: &Path) -> Vec<std::ffi::OsString> {
    let mut v: Vec<_> = std::fs::read_dir(rootfs).unwrap().map(|e| e.unwrap().file_name()).collect();
    v.sort();
    v
}

/// The host's mounts as `(mount point, fs type, source)`, sorted.
pub fn host_mounts() -> Vec<(String, String, String)> {
    let text = std::fs::read_to_string("/proc/self/mountinfo").unwrap();
    let mut v: Vec<_> = text
        .lines()
        .filter_map(|l| {
            let (left, right) = l.split_once(" - ")?;
            let mp = left.split(' ').nth(4)?.to_owned();
            let mut r = right.split(' ');
            Some((mp, r.next()?.to_owned(), r.next()?.to_owned()))
        })
        .collect();
    v.sort();
    v
}

#[track_caller]
pub fn assert_host_mounts_unchanged(before: &[(String, String, String)], after: &[(String, String, String)]) {
    let added: Vec<_> = after.iter().filter(|m| !before.contains(m)).collect();
    let removed: Vec<_> = before.iter().filter(|m| !after.contains(m)).collect();
    assert!(
        added.is_empty() && removed.is_empty(),
        "host mount table changed!\nadded: {added:#?}\nremoved: {removed:#?}"
    );
}

/// `readlink /proc/self/ns/<kind>` of the test process (the host view).
pub fn host_ns(kind: &str) -> String {
    std::fs::read_link(format!("/proc/self/ns/{kind}")).unwrap().display().to_string()
}

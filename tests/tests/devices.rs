//! Phase 2c: the eBPF device filter (`rustlet_runtime::cgroups::devices`).
//!
//! First the program against the kernel itself, with no container:
//! the verifier accepts what the compiler makes, its cost stays well
//! inside the verifier's limit, and in a real cgroup the kernel decides
//! exactly as the reference semantics (`devices::decide`) says.
//! Run with `cargo xtask itest -- dv_`.

use std::collections::BTreeMap;
use std::os::fd::AsFd;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

use nix::errno::Errno;
use nix::sys::stat::{Mode, SFlag, makedev, mknod};
use rustlet_itests::e2e::*;
use rustlet_itests::*;
use rustlet_runtime::cgroups::devices::{Access, DevType, DeviceFilter, MAX_RULES, Origin, Request, Rule, decide};
use rustlet_runtime::oci_spec::runtime::{
    LinuxDevice, LinuxDeviceBuilder, LinuxDeviceCgroup, LinuxDeviceCgroupBuilder, LinuxDeviceType,
    LinuxResourcesBuilder, Spec,
};
use rustlet_sys::bpf;

// ── helpers ──────────────────────────────────────────────────────────────────

/// xorshift64*: deterministic, good enough to pick test cases.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn pick<T: Copy>(&mut self, xs: &[T]) -> T {
        xs[self.below(xs.len())]
    }
}

/// Numbers rules and nodes share often enough to match. No 0:0: the kernel
/// skips the device check for it (it is the overlayfs whiteout).
const MAJORS: [u32; 4] = [1, 8, 136, 4095];
const MINORS: [u32; 4] = [0, 3, 229, 0xf_ffff];

fn random_rules(rng: &mut Rng, n: usize) -> Vec<Rule> {
    (0..n)
        .map(|_| {
            let allow = rng.below(2) == 0;
            if rng.below(12) == 0 {
                return Rule {
                    allow,
                    typ: None,
                    major: None,
                    minor: None,
                    access: Access::ALL,
                    origin: Origin::Default,
                };
            }
            let any = |rng: &mut Rng| rng.below(3) == 0;
            Rule {
                allow,
                typ: Some(rng.pick(&[DevType::Block, DevType::Char])),
                major: if any(rng) { None } else { Some(rng.pick(&MAJORS)) },
                minor: if any(rng) { None } else { Some(rng.pick(&MINORS)) },
                access: Access::from_bits(1 + rng.below(7) as u32),
                origin: Origin::Default,
            }
        })
        .collect()
}

/// A scratch cgroup in this test binary's scope. Dropping it removes the
/// cgroup: quietly if it is empty, else by force (with a message).
struct Scratch {
    path: String,
    _guard: CgroupGuard,
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir(cgroup_dir(&self.path));
    }
}

fn scratch_cgroup(name: &str) -> Scratch {
    static N: AtomicU32 = AtomicU32::new(0);
    let path = itest_cgroup(&format!("{name}-{}", N.fetch_add(1, Ordering::Relaxed)));
    let dir = cgroup_dir(&path);
    std::fs::create_dir(&dir).unwrap_or_else(|e| panic!("mkdir {}: {e}", dir.display()));
    Scratch { path, _guard: CgroupGuard(dir) }
}

fn attach(filter: &DeviceFilter, cgroups_path: &str) -> u32 {
    let dir = std::fs::File::open(cgroup_dir(cgroups_path)).unwrap();
    filter.attach(dir.as_fd()).unwrap_or_else(|e| panic!("{e}\n{}", filter.disassemble()))
}

fn letter(t: DevType) -> char {
    match t {
        DevType::Block => 'b',
        DevType::Char => 'c',
    }
}

/// What the kernel decides for `requests` in a cgroup with `filter`
/// attached.
///
/// A shell in a private mount namespace mounts a tmpfs, makes one node per
/// device there (as root, still outside the filtered cgroup), moves itself
/// into the cgroup and then runs `rustlet-probe`. An `access` probe runs
/// the device check without opening the device (`access(2)`), a `mknod`
/// probe creates a fresh node. Nothing is ever opened.
fn kernel_decisions(filter: &DeviceFilter, requests: &[Request]) -> Vec<bool> {
    let scratch = scratch_cgroup("dv-kernel");
    let cg = scratch.path.as_str();
    attach(filter, cg);
    let mut nodes: BTreeMap<(DevType, u32, u32), String> = BTreeMap::new();
    let mut script = String::from("set -e\nmount -t tmpfs -o mode=0700 dv \"$D\"\ncd \"$D\"\n");
    let mut probes = Vec::new();
    for (i, r) in requests.iter().enumerate() {
        let (t, maj, min) = (letter(r.typ), r.major, r.minor);
        if r.access == Access::MKNOD {
            probes.push(format!("mknod:m{i}:{t}:{maj}:{min}"));
            continue;
        }
        let n = nodes.len();
        let node = nodes.entry((r.typ, maj, min)).or_insert_with(|| {
            script.push_str(&format!("mknod n{n} {t} {maj} {min}\n"));
            format!("n{n}")
        });
        let mode = match (r.access.contains(Access::READ), r.access.contains(Access::WRITE)) {
            (false, false) => "f",
            (true, false) => "r",
            (false, true) => "w",
            (true, true) => "rw",
        };
        probes.push(format!("access:{node}:{mode}"));
    }
    script.push_str(&format!("echo $$ > {}/cgroup.procs\n", cgroup_dir(cg).display()));
    script.push_str(&format!("exec {} \"$@\"\n", env!("CARGO_BIN_EXE_rustlet-probe")));
    let dir = tempfile::tempdir().unwrap();
    let out = Command::new("unshare")
        .args(["--mount", "--propagation", "private", "/bin/sh", "-c", &script, "sh"])
        .args(&probes)
        .env("D", dir.path())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{:?}\n{stdout}{}", out.status, String::from_utf8_lossy(&out.stderr));
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), probes.len(), "{stdout}");
    lines
        .iter()
        .zip(&probes)
        .map(|(line, probe)| match line.strip_prefix(probe.as_str()).map(str::trim) {
            Some("ok") => true,
            Some("EPERM") => false,
            _ => panic!("{probe}: unexpected {line:?}"),
        })
        .collect()
}

/// The verifier's `processed N insns` from a `BPF_LOG_STATS` log.
fn processed_insns(log: &str) -> u64 {
    let n = log.split("processed ").nth(1).and_then(|s| s.split_whitespace().next());
    n.and_then(|n| n.parse().ok()).unwrap_or_else(|| panic!("no instruction count in {log:?}"))
}

// ── the verifier ─────────────────────────────────────────────────────────────

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn dv_verifier_accepts_random_programs() {
    let mut rng = Rng(0xde71_0000_0000_5eed);
    for _ in 0..300 {
        let n = rng.below(40);
        let filter = DeviceFilter::from_rules(random_rules(&mut rng, n)).unwrap();
        if let Err(e) = filter.load() {
            panic!("{e}\n{}", filter.disassemble());
        }
    }
    // The defaults, and a filter with every kind of rule in it.
    DeviceFilter::build(&[], &[]).unwrap().load().unwrap();
}

/// Rules that give the verifier the most paths to follow: every one
/// distinct and partial, alternating allow and deny, so the allowed bits
/// differ from path to path, and every one with all three comparisons (the
/// verifier keeps one pending state per comparison, at most 8192). The cost
/// must grow about linearly and stay far below the verifier's limit (a
/// million instructions processed) at `MAX_RULES`.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn dv_verifier_cost_stays_linear() {
    let worst = |n: usize| -> Vec<Rule> {
        (0..n)
            .map(|i| Rule {
                allow: i % 2 == 0,
                typ: Some(if i % 3 == 0 { DevType::Block } else { DevType::Char }),
                major: Some((i % 4096) as u32),
                minor: Some(i as u32),
                access: Access::from_bits(1 + (i % 7) as u32),
                origin: Origin::Default,
            })
            .collect()
    };
    let mut costs = Vec::new();
    for n in [100, 500, 1000, MAX_RULES] {
        let filter = DeviceFilter::from_rules(worst(n)).unwrap();
        assert_eq!(filter.compiled.len(), n);
        let (_, log) =
            bpf::prog_load_with_log(bpf::PROG_TYPE_CGROUP_DEVICE, &filter.program, "rustlet_test", bpf::LOG_STATS)
                .unwrap_or_else(|(e, log)| panic!("{n} rules: {e}\n{log}"));
        costs.push((n, filter.program.len(), processed_insns(&log)));
    }
    eprintln!("rules, instructions, processed: {costs:?}");
    let &(_, len, processed) = costs.last().unwrap();
    assert!(processed < 250_000, "{costs:?}");
    // "About linearly": at most a small multiple of the program length.
    assert!(processed < 20 * len as u64, "{costs:?}");
}

// ── the kernel against the reference ─────────────────────────────────────────

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn dv_kernel_agrees_with_the_reference() {
    let mut rng = Rng(0x0dd_ba11_c0ff_ee00);
    let mut checked = 0;
    for round in 0..24 {
        let n = 1 + rng.below(10);
        let rules = random_rules(&mut rng, n);
        let filter = DeviceFilter::from_rules(rules.clone()).unwrap();
        let mut requests = Vec::new();
        for typ in [DevType::Block, DevType::Char] {
            for major in MAJORS {
                for minor in MINORS {
                    for bits in [0, 1, 2, 4, 6] {
                        requests.push(Request { typ, major, minor, access: Access::from_bits(bits) });
                    }
                }
            }
        }
        let kernel = kernel_decisions(&filter, &requests);
        for (r, got) in requests.iter().zip(kernel) {
            assert_eq!(got, decide(&rules, r), "round {round}: {r:?} under {rules:?}\n{}", filter.disassemble());
            checked += 1;
        }
    }
    assert!(checked > 3000, "{checked}");
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn dv_the_milestone_without_a_container() {
    // The defaults: mknod of /dev/null works, of a disk doesn't, even for
    // root with every capability.
    let filter = DeviceFilter::build(&[], &[]).unwrap();
    let requests = [
        Request { typ: DevType::Char, major: 1, minor: 3, access: Access::MKNOD },
        Request { typ: DevType::Block, major: 8, minor: 0, access: Access::MKNOD },
        Request { typ: DevType::Char, major: 1, minor: 3, access: Access::READ.union(Access::WRITE) },
        Request { typ: DevType::Block, major: 8, minor: 0, access: Access::READ },
    ];
    assert_eq!(kernel_decisions(&filter, &requests), [true, false, true, false]);
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn dv_attached_with_allow_multi() {
    let scratch = scratch_cgroup("dv-attach");
    let id = attach(&DeviceFilter::build(&[], &[]).unwrap(), &scratch.path);
    let dir = std::fs::File::open(cgroup_dir(&scratch.path)).unwrap();
    let (ids, flags) = bpf::prog_query_with(dir.as_fd(), bpf::ATTACH_CGROUP_DEVICE, 0).unwrap();
    assert_eq!((ids, flags), (vec![id], bpf::F_ALLOW_MULTI));
    let (effective, _) = bpf::prog_query_with(dir.as_fd(), bpf::ATTACH_CGROUP_DEVICE, bpf::F_QUERY_EFFECTIVE).unwrap();
    assert!(effective.contains(&id), "{effective:?}");
}

// ── attachment and container lifecycle ──────────────────────────────────────

/// Run the syscall probe in Alpine through the host glibc loader. The
/// writable /mnt bind also holds device nodes for access(2) probes.
fn device_probe_spec(script: &str) -> (rustlet_runtime::oci_spec::runtime::Spec, tempfile::TempDir) {
    let lib = "/usr/lib/x86_64-linux-gnu";
    let dir = tempfile::tempdir().unwrap();
    std::fs::copy(env!("CARGO_BIN_EXE_rustlet-probe"), dir.path().join("probe")).unwrap();
    let mut s = sh(&format!("PROBE='/opt/ld-linux-x86-64.so.2 --library-path /opt /mnt/probe'; {script}"));
    add_mount(&mut s, "/mnt", "bind", dir.path().to_str().unwrap(), &["bind", "rw", "nosuid"]);
    add_mount(&mut s, "/opt", "bind", lib, &["bind", "ro", "nosuid", "nodev"]);
    (s, dir)
}

fn wait_for_program_release(id: u32) {
    wait_until("device program released", PROMPT, || match bpf::prog_fd_by_id(id) {
        Err(Errno::ENOENT) => true,
        Ok(fd) => {
            drop(fd);
            false
        }
        Err(e) => panic!("BPF_PROG_GET_FD_BY_ID {id}: {e}"),
    });
}

fn saved_program(c: &Container) -> u32 {
    let state: rustlet_runtime::state::State =
        serde_json::from_slice(&std::fs::read(runtime_root().join(c.id()).join("state.json")).unwrap()).unwrap();
    state.rustlet.device_filter.expect("no saved device filter")
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn dv_default_devices_work() {
    let script = r#"set -e
for d in null zero full random urandom tty ptmx; do
    test -r /dev/$d; test -w /dev/$d
done
for d in null zero random urandom; do
    dd if=/dev/$d of=/dev/null bs=1 count=1 2>/dev/null
    printf x > /dev/$d
done
dd if=/dev/full of=/dev/null bs=1 count=1 2>/dev/null
if printf x > /dev/full 2>/dev/null; then exit 1; fi
echo defaults-ok"#;
    for terminal in [false, true] {
        let mut s = sh(script);
        set_cgroup(&mut s, "dv-defaults");
        if terminal {
            set_terminal(&mut s, None);
        }
        let mut c = Container::new(&s);
        let out = c.run_foreground(&[], Some(b""), TIMEOUT);
        assert!(out.ok().contains("defaults-ok"), "{out:#?}");
        c.assert_gone();
    }
    let mut s = spec(&["sleep", "3600"]);
    set_cgroup(&mut s, "dv-default-exec");
    let c = Container::started(&s);
    let out = exec_input(
        c.exec_command(&["-t"], &["sh", "-c", &format!("{script}; echo tty-ok >/dev/tty; tty")]),
        Some(b""),
        TIMEOUT,
    );
    assert!(out.ok().contains("defaults-ok") && out.stdout.contains("tty-ok"), "{out:#?}");
    assert!(out.stdout.contains("/dev/pts/"), "{out:#?}");
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn dv_one_program_attached_and_freed_on_delete() {
    let mut s = spec(&["sleep", "3600"]);
    let path = set_cgroup(&mut s, "dv-lifetime");
    let c = Container::created(&s);
    let id = saved_program(&c);
    {
        let dir = std::fs::File::open(cgroup_dir(&path)).unwrap();
        let (ids, flags) = bpf::prog_query_with(dir.as_fd(), bpf::ATTACH_CGROUP_DEVICE, 0).unwrap();
        assert_eq!((ids, flags), (vec![id], bpf::F_ALLOW_MULTI));
        drop(bpf::prog_fd_by_id(id).unwrap());
    }
    c.delete(true).ok();
    c.assert_gone();
    wait_for_program_release(id);
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn dv_failed_create_frees_the_program() {
    // Both parent-side and init-side failures happen after attachment.
    // The debug event gives the id even though CreateGuard removes state.
    for parent_failure in [false, true] {
        let mut s = spec(&[if parent_failure { "true" } else { "no-such-dv-program" }]);
        if parent_failure {
            add_mount(&mut s, "/mnt", "bind", "/no-such-dv-source", &["bind"]);
        }
        set_cgroup(&mut s, "dv-failed-create");
        let mut c = Container::new(&s);
        let out = c.create(&["--debug", "--log-format", "json"]);
        out.failed_with(if parent_failure { 1 } else { 127 });
        let id = out
            .stderr
            .lines()
            .find_map(|line| {
                let event: serde_json::Value = serde_json::from_str(line).ok()?;
                event["fields"]["program_id"].as_u64().map(|id| id as u32)
            })
            .unwrap_or_else(|| panic!("no attachment event: {out:#?}"));
        c.assert_gone();
        wait_for_program_release(id);
    }
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn dv_exec_process_is_filtered() {
    let (mut s, nodes) = device_probe_spec("exec sleep 3600");
    mknod(&nodes.path().join("fuse"), SFlag::S_IFCHR, Mode::from_bits_truncate(0o666), makedev(10, 229)).unwrap();
    set_cgroup(&mut s, "dv-exec-filtered");
    let c = Container::started(&s);
    // access(2), not an open of the host device. A bound device cannot
    // bypass the cgroup check, including in an exec process.
    let out = c.exec_in(
        &[],
        &[
            "/opt/ld-linux-x86-64.so.2",
            "--library-path",
            "/opt",
            "/mnt/probe",
            "access:/mnt/fuse:r",
            "access:/mnt/fuse:w",
            "access:/mnt/fuse:rw",
            "access:/dev/null:rw",
        ],
    );
    assert_eq!(
        out.ok(),
        "access:/mnt/fuse:r EPERM\naccess:/mnt/fuse:w EPERM\naccess:/mnt/fuse:rw EPERM\naccess:/dev/null:rw ok\n"
    );
}

// ── OCI device rules and CAP_MKNOD ──────────────────────────────────────────

fn device_rule(
    allow: bool,
    typ: LinuxDeviceType,
    major: Option<i64>,
    minor: Option<i64>,
    access: &str,
) -> LinuxDeviceCgroup {
    let mut b = LinuxDeviceCgroupBuilder::default().allow(allow).typ(typ).access(access);
    if let Some(n) = major {
        b = b.major(n);
    }
    if let Some(n) = minor {
        b = b.minor(n);
    }
    b.build().unwrap()
}

fn set_device_rules(s: &mut Spec, rules: Vec<LinuxDeviceCgroup>) {
    let linux = s.linux_mut().as_mut().unwrap();
    let mut resources = linux.resources().clone().unwrap_or_else(|| LinuxResourcesBuilder::default().build().unwrap());
    resources.set_devices(Some(rules));
    linux.set_resources(Some(resources));
}

fn give_mknod(s: &mut Spec) {
    let caps: Vec<&str> = DEFAULT_CAPS.iter().copied().chain(["CAP_MKNOD"]).collect();
    set_capabilities(s, CapSets::root(&caps));
    // Isolate the device-cgroup decision from the default seccomp profile,
    // which was resolved for capabilities without MKNOD.
    edit_linux(s, |l| {
        l.set_seccomp(None);
    });
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn dv_mknod_of_a_block_device_is_denied_even_with_cap_mknod() {
    let (mut s, _dir) =
        device_probe_spec("grep CapEff /proc/self/status; $PROBE mknod:/dev/disk:b:8:0 mknod:/dev/n:c:1:3");
    give_mknod(&mut s);
    set_cgroup(&mut s, "dv-milestone");
    let out = run(&s);
    let stdout = out.ok();
    assert_ne!(status_hex(stdout, "CapEff") & (1 << 27), 0);
    assert!(stdout.contains("mknod:/dev/disk:b:8:0 EPERM\nmknod:/dev/n:c:1:3 ok\n"), "{out:#?}");
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn dv_mknod_of_other_char_devices_is_denied() {
    let (mut s, _dir) = device_probe_spec("$PROBE mknod:/dev/fuse:c:10:229 mknod:/dev/tun:c:10:200");
    give_mknod(&mut s);
    set_cgroup(&mut s, "dv-other-char");
    assert_eq!(run(&s).ok(), "mknod:/dev/fuse:c:10:229 EPERM\nmknod:/dev/tun:c:10:200 EPERM\n");
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn dv_deny_wins_per_bit() {
    let (mut s, nodes) = device_probe_spec(
        "$PROBE access:/mnt/fuse:r access:/mnt/fuse:w access:/mnt/fuse:rw access:/mnt/fuse:f access:/dev/null:rw",
    );
    mknod(&nodes.path().join("fuse"), SFlag::S_IFCHR, Mode::from_bits_truncate(0o666), makedev(10, 229)).unwrap();
    set_device_rules(
        &mut s,
        vec![
            device_rule(true, LinuxDeviceType::C, Some(10), Some(229), "rw"),
            device_rule(false, LinuxDeviceType::C, Some(10), Some(229), "w"),
            // Built-in defaults are appended last, so this deny is overridden.
            device_rule(false, LinuxDeviceType::C, Some(1), Some(3), "rwm"),
        ],
    );
    set_cgroup(&mut s, "dv-per-bit");
    assert_eq!(
        run(&s).ok(),
        "access:/mnt/fuse:r ok\naccess:/mnt/fuse:w EPERM\naccess:/mnt/fuse:rw EPERM\naccess:/mnt/fuse:f ok\naccess:/dev/null:rw ok\n"
    );
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn dv_device_rules_need_a_cgroup_and_bad_rules_are_refused() {
    let mut s = spec(&["true"]);
    set_device_rules(&mut s, vec![device_rule(true, LinuxDeviceType::C, Some(10), Some(229), "rw")]);
    let mut c = Container::new(&s);
    c.create(&[]).refused("set linux.cgroupsPath");
    c.assert_gone();
    set_cgroup(&mut s, "dv-bad-rules");
    for rule in [
        device_rule(true, LinuxDeviceType::A, Some(1), None, "rwm"),
        device_rule(true, LinuxDeviceType::C, Some(-2), None, "r"),
        device_rule(true, LinuxDeviceType::C, Some(4096), None, "r"),
        device_rule(true, LinuxDeviceType::C, Some(10), Some(229), ""),
        device_rule(true, LinuxDeviceType::C, Some(10), Some(229), "x"),
    ] {
        set_device_rules(&mut s, vec![rule]);
        let mut c = Container::new(&s);
        c.create(&[]).refused("linux.resources.devices[0]");
        c.assert_gone();
    }
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn dv_mknod_in_a_user_namespace_needs_no_filter() {
    let mut s = userns_sh("if mknod /dev/n c 1 3 2>/dev/null; then exit 1; fi; echo denied");
    give_mknod(&mut s);
    assert_eq!(run(&s).ok(), "denied\n");
}

// ── OCI nodes ───────────────────────────────────────────────────────────────

fn device_node(path: &str, typ: LinuxDeviceType, major: i64, minor: i64) -> LinuxDevice {
    LinuxDeviceBuilder::default().path(path).typ(typ).major(major).minor(minor).build().unwrap()
}

fn set_nodes(s: &mut Spec, nodes: Vec<LinuxDevice>) {
    edit_linux(s, |l| {
        l.set_devices(Some(nodes));
    });
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn dv_spec_device_needs_a_rule() {
    let (mut s, _dir) = device_probe_spec("$PROBE access:/dev/fuse:r access:/dev/fuse:w access:/dev/fuse:rw");
    set_cgroup(&mut s, "dv-spec-fuse");
    set_nodes(&mut s, vec![device_node("/dev/fuse", LinuxDeviceType::C, 10, 229)]);
    assert_eq!(run(&s).ok(), "access:/dev/fuse:r EPERM\naccess:/dev/fuse:w EPERM\naccess:/dev/fuse:rw EPERM\n");
    set_device_rules(&mut s, vec![device_rule(true, LinuxDeviceType::C, Some(10), Some(229), "rw")]);
    assert_eq!(run(&s).ok(), "access:/dev/fuse:r ok\naccess:/dev/fuse:w ok\naccess:/dev/fuse:rw ok\n");
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn dv_nested_device_path() {
    let mut s = sh("stat -c '%F %t:%T %a %u:%g' /dev/net/tun; stat -c '%a' /dev/net");
    set_cgroup(&mut s, "dv-nested");
    set_nodes(&mut s, vec![device_node("/dev/net/tun", LinuxDeviceType::U, 10, 200)]);
    assert_eq!(run(&s).ok(), "character special file a:c8 666 0:0\n755\n");
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn dv_file_mode_and_owner() {
    let mut s = sh("stat -c '%F %a %u:%g' /dev/fuse /dev/null /dev/events /dev/disk");
    set_cgroup(&mut s, "dv-metadata");
    let mut fuse = device_node("/dev/fuse", LinuxDeviceType::C, 10, 229);
    fuse.set_file_mode(Some(0o2640));
    fuse.set_uid(Some(12));
    fuse.set_gid(Some(34));
    let mut null = device_node("/dev/null", LinuxDeviceType::U, 1, 3);
    null.set_file_mode(Some(0o600));
    null.set_uid(Some(56));
    null.set_gid(Some(78));
    set_nodes(
        &mut s,
        vec![
            fuse,
            null,
            device_node("/dev/events", LinuxDeviceType::P, 0, 0),
            device_node("/dev/disk", LinuxDeviceType::B, 8, 0),
        ],
    );
    assert_eq!(
        run(&s).ok(),
        "character special file 2640 12:34\ncharacter special file 600 56:78\nfifo 666 0:0\nblock special file 666 0:0\n"
    );
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn dv_bad_device_paths_are_refused() {
    let mut s = spec(&["true"]);
    set_nodes(&mut s, vec![device_node("/dev/fuse", LinuxDeviceType::C, 10, 229)]);
    let mut c = Container::new(&s);
    c.create(&[]).refused("set linux.cgroupsPath");
    c.assert_gone();
    set_cgroup(&mut s, "dv-bad-paths");
    for path in [
        "dev/x",
        "/dev",
        "/dev/",
        "/dev/../x",
        "/dev/./x",
        "/dev//x",
        "/dev/x/",
        "/mnt/x",
        "/dev/console",
        "/dev/ptmx",
        "/dev/fd/x",
        "/dev/pts/x",
        "/dev/shm/x",
    ] {
        set_nodes(&mut s, vec![device_node(path, LinuxDeviceType::C, 10, 229)]);
        let mut c = Container::new(&s);
        c.create(&[]).refused("linux.devices[0]");
        c.assert_gone();
    }
    for nodes in [
        vec![device_node("/dev/null", LinuxDeviceType::C, 1, 5)],
        vec![device_node("/dev/x", LinuxDeviceType::A, 0, 0)],
        vec![device_node("/dev/x", LinuxDeviceType::C, -1, 0)],
        vec![device_node("/dev/x", LinuxDeviceType::C, 4096, 0)],
        vec![device_node("/dev/x", LinuxDeviceType::C, 1, 0x10_0000)],
        vec![device_node("/dev/x", LinuxDeviceType::C, 1, 3), device_node("/dev/x", LinuxDeviceType::C, 1, 3)],
        vec![device_node("/dev/x", LinuxDeviceType::C, 1, 3), device_node("/dev/x/y", LinuxDeviceType::C, 1, 3)],
    ] {
        set_nodes(&mut s, nodes);
        let mut c = Container::new(&s);
        c.create(&[]).refused("linux.devices[");
        c.assert_gone();
    }
    // A mount below the node also conflicts, including if mounted first.
    set_nodes(&mut s, vec![device_node("/dev/x", LinuxDeviceType::C, 1, 3)]);
    add_mount(&mut s, "/dev/x/child", "tmpfs", "tmpfs", &[]);
    let mut c = Container::new(&s);
    c.create(&[]).refused("conflicts with a mount");
    c.assert_gone();
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn dv_existing_spec_node_is_refused() {
    // /dev is itself a new tmpfs. A nested spec node cannot replace its
    // already-created parent directory, even if they share a device id.
    let mut s = spec(&["true"]);
    set_cgroup(&mut s, "dv-existing");
    set_nodes(
        &mut s,
        vec![
            device_node("/dev/parent/child", LinuxDeviceType::C, 1, 3),
            device_node("/dev/parent", LinuxDeviceType::C, 1, 3),
        ],
    );
    let mut c = Container::new(&s);
    c.create(&[]).refused("parent of another device");
    c.assert_gone();
}

// ── privileged-shaped specs and host-device translation ─────────────────────

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn dv_privileged_spec_runs() {
    let script = "set -e; grep -E '^(CapEff|CapInh|CapAmb|NoNewPrivs|Seccomp):' /proc/self/status; \
        stat -c '%F %t:%T' /dev/fuse; dd if=/dev/fuse of=/dev/null bs=1 count=0 2>/dev/null; \
        awk '$5 == \"/sys\" || $5 == \"/sys/fs/cgroup\" { print $5, $6 }' /proc/self/mountinfo";
    for userns in [false, true] {
        let mut s = if userns { userns_sh(script) } else { sh(script) };
        set_cgroup(&mut s, "dv-privileged");
        rustlet_runtime::spec::privileged(&mut s).unwrap();
        let bundle = TestBundle::new(&s);
        let plan =
            rustlet_runtime::plan::Plan::new(&bundle.id, &rustlet_runtime::Bundle::load(bundle.dir.path()).unwrap())
                .unwrap();
        let filter = plan.cgroup.unwrap().devices;
        assert!(filter.compiled.is_empty());
        assert_eq!(filter.initial, Access::ALL);
        assert_eq!(filter.program.len(), 2);
        let out = run(&s);
        let stdout = out.ok();
        assert_eq!(status_hex(stdout, "CapEff"), rustlet_sys::caps::CapSet::all(rustlet_sys::caps::last_cap()).0);
        assert_eq!(status_hex(stdout, "CapInh"), 0);
        assert_eq!(status_hex(stdout, "CapAmb"), 0);
        assert_eq!(status_field(stdout, "Seccomp"), Some("0"));
        assert_eq!(status_field(stdout, "NoNewPrivs"), Some("1"));
        assert!(stdout.contains("character special file a:e5"), "{out:#?}");
        for mount in ["/sys", "/sys/fs/cgroup"] {
            let options = stdout.lines().find_map(|l| l.strip_prefix(&format!("{mount} "))).unwrap();
            assert!(options.split(',').any(|o| o == "rw"), "{mount}: {options}");
        }
    }
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn dv_host_device_helper_translates_node_and_rule() {
    let (mut s, _dir) = device_probe_spec("$PROBE access:/dev/custom/fuse:rw");
    set_cgroup(&mut s, "dv-host-device");
    rustlet_runtime::spec::add_host_device(
        &mut s,
        std::path::Path::new("/dev/fuse"),
        std::path::Path::new("/dev/custom/fuse"),
        "rw",
    )
    .unwrap();
    assert_eq!(run(&s).ok(), "access:/dev/custom/fuse:rw ok\n");
    let nodes = rustlet_runtime::spec::host_devices().unwrap();
    assert!(nodes.windows(2).all(|pair| pair[0].path() < pair[1].path()));
    assert!(nodes.iter().any(|n| n.path() == std::path::Path::new("/dev/fuse")));
    assert!(!nodes.iter().any(|n| n.path().starts_with("/dev/pts") || n.path().starts_with("/dev/shm")));
    let before = s.clone();
    assert!(
        rustlet_runtime::spec::add_host_device(
            &mut s,
            std::path::Path::new("/dev/fuse"),
            std::path::Path::new("/dev/x"),
            ""
        )
        .is_err()
    );
    assert_eq!(s, before);
    assert!(
        rustlet_runtime::spec::add_host_device(
            &mut s,
            std::path::Path::new("/etc/hostname"),
            std::path::Path::new("/dev/x"),
            "r"
        )
        .is_err()
    );
    assert_eq!(s, before);
}

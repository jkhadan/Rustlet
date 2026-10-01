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

//! Tests of the whole compiler: Docker's profile run through the
//! interpreter, a reference evaluator against random profiles, long jumps,
//! errors, a listing, and finally the real kernel.

use oci_spec::runtime::LinuxSeccomp;
use rustlet_sys::caps::CapSet;
use rustlet_sys::seccomp::{AUDIT_ARCH_I386, AUDIT_ARCH_X86_64, SockFilter, X32_SYSCALL_BIT, op, ret};
use serde_json::{Value, json};

use super::docker::{self, Cap, KernelVersion};
use super::interp::{self, SeccompData};
use super::{Filter, compile, compile_with_stats, syscalls};
use crate::error::Error;

const KERNEL: KernelVersion = KernelVersion { major: 7, minor: 0 };
const ALLOW: u32 = ret::ALLOW;
const EPERM: u32 = ret::ERRNO | 1;
const ENOSYS: u32 = ret::ERRNO | 38;

fn spec(v: Value) -> LinuxSeccomp {
    serde_json::from_value(v).expect("a valid linux.seccomp")
}

fn docker_spec(caps: CapSet) -> LinuxSeccomp {
    docker::resolve(docker::DEFAULT_PROFILE, caps, KERNEL).unwrap()
}

fn run(f: &Filter, d: SeccompData) -> u32 {
    interp::run(&f.program, &d).unwrap_or_else(|e| panic!("{e}\n{}", f.disassemble()))
}

/// The verdict for syscall `name` with first argument `arg0`.
fn verdict(f: &Filter, name: &str, arg0: u64) -> u32 {
    let nr = syscalls::number(name).unwrap_or_else(|| panic!("{name} is not a syscall"));
    run(f, SeccompData::x86_64(nr, [arg0, 0, 0, 0, 0, 0]))
}

fn expect(f: &Filter, cases: &[(&str, u64, u32)]) {
    for &(name, arg0, want) in cases {
        let got = verdict(f, name, arg0);
        assert_eq!(
            super::disasm::action_name(got),
            super::disasm::action_name(want),
            "{name}({arg0:#x}) should be {}",
            super::disasm::action_name(want)
        );
    }
}

const CLONE_NEWNS: u64 = 0x0002_0000;
const CLONE_NEWUSER: u64 = 0x1000_0000;
const CLONE_NEWNET: u64 = 0x4000_0000;

#[test]
fn docker_profile_for_the_default_caps() {
    let (f, stats) = compile_with_stats(&docker_spec(crate::caps::default_set())).unwrap();
    expect(
        &f,
        &[
            ("read", 0, ALLOW),
            ("write", 1, ALLOW),
            ("openat", 0, ALLOW),
            ("exit_group", 0, ALLOW),
            ("name_to_handle_at", 0, ALLOW),
            ("chroot", 0, ALLOW), // CAP_SYS_CHROOT is a default cap
            ("ptrace", 0, ALLOW), // minKernel 4.8
            ("mount", 0, EPERM),
            ("umount2", 0, EPERM),
            ("unshare", CLONE_NEWUSER, EPERM),
            ("setns", 0, EPERM),
            ("pivot_root", 0, EPERM),
            ("bpf", 0, EPERM),
            ("keyctl", 0, EPERM),
            ("kexec_load", 0, EPERM),
            ("open_by_handle_at", 0, EPERM), // needs CAP_DAC_READ_SEARCH
            // clone: only without namespace flags, `(flags & 0x7E020000) == 0`.
            ("clone", 0x11, ALLOW),
            ("clone", 0x0001_0000_0011, ALLOW), // the mask's high word is 0
            ("clone", CLONE_NEWUSER | 0x11, EPERM),
            ("clone", CLONE_NEWNS, EPERM),
            ("clone", CLONE_NEWNET, EPERM),
            ("clone3", 0, ENOSYS),
            // socket: families below 38, and 39, 41..=45.
            ("socket", 1, ALLOW),
            ("socket", 2, ALLOW),
            ("socket", 37, ALLOW),
            ("socket", 38, EPERM), // AF_ALG
            ("socket", 39, ALLOW),
            ("socket", 40, EPERM), // AF_VSOCK
            ("socket", 45, ALLOW),
            ("socket", 46, EPERM),
            ("socket", 0x1_0000_0002, EPERM), // a 64-bit comparison: garbage high word
            ("personality", 0, ALLOW),
            ("personality", 8, ALLOW),
            ("personality", 0xffff_ffff, ALLOW),
            ("personality", 1, EPERM),
            ("personality", 0x0004_0000, EPERM), // ADDR_NO_RANDOMIZE
            ("personality", 0x0040_0000, EPERM), // READ_IMPLIES_EXEC
            ("personality", 0xffff_ffff_ffff_ffff, EPERM),
        ],
    );

    let highest = stats.enosys_above.expect("the profile gets an ENOSYS stub");
    assert!(highest >= syscalls::number("mseal").unwrap(), "{highest}");
    let at = |nr: u32| run(&f, SeccompData::x86_64(nr, [0; 6]));
    assert_eq!(at(highest + 1), ENOSYS);
    assert_eq!(at(1000), ENOSYS);
    assert_eq!(at(400), EPERM, "a gap below the highest number gets the default");
    assert_eq!(at(u32::MAX), ENOSYS, "-1 passes the x32 check and hits the stub");
    assert_eq!(at(X32_SYSCALL_BIT | 39), ret::KILL_PROCESS);
    assert_eq!(at(X32_SYSCALL_BIT | 1000), ret::KILL_PROCESS);
    let i386 = SeccompData { arch: AUDIT_ARCH_I386, ..SeccompData::x86_64(20, [0; 6]) };
    assert_eq!(run(&f, i386), ret::KILL_PROCESS);

    // Small and shallow: 310 syscall numbers with rules, but in long runs of
    // ALLOW.
    assert!(stats.instructions < 400, "{stats:?}");
    assert!(stats.dispatch_depth <= 8, "{stats:?}");
    assert_eq!(stats.trampolines, 0, "{stats:?}");
    // The profile lists every architecture's names in one entry; ~60 of
    // them (`socketcall`, `chown32`, `_llseek`, …) are i386-only.
    assert!(stats.syscalls > 300, "{stats:?}");
    assert!(stats.skipped.iter().any(|n| n == "socketcall"), "{stats:?}");
    assert!(!stats.skipped.iter().any(|n| n == "arm_fadvise64_64"), "arm-only entries are resolved away");
}

#[test]
fn docker_profile_with_sys_admin() {
    let mut caps = crate::caps::default_set();
    caps.insert(Cap::SYS_ADMIN);
    let f = compile(&docker_spec(caps)).unwrap();
    expect(
        &f,
        &[
            ("mount", 0, ALLOW),
            ("umount2", 0, ALLOW),
            ("unshare", CLONE_NEWUSER, ALLOW),
            ("setns", 0, ALLOW),
            ("clone", CLONE_NEWUSER | 0x11, ALLOW),
            ("clone3", 0, ALLOW),
            ("bpf", 0, ALLOW),
            ("kexec_load", 0, EPERM),
        ],
    );
}

// ---------------------------------------------------------------------------
// A reference evaluator: the semantics, straight from the OCI rules.
// ---------------------------------------------------------------------------

fn action_value(action: oci_spec::runtime::LinuxSeccompAction, errno: Option<u32>) -> u32 {
    use oci_spec::runtime::LinuxSeccompAction as A;
    match action {
        A::ScmpActKill | A::ScmpActKillThread => ret::KILL_THREAD,
        A::ScmpActKillProcess => ret::KILL_PROCESS,
        A::ScmpActTrap => ret::TRAP,
        A::ScmpActErrno => ret::ERRNO | errno.unwrap_or(1),
        A::ScmpActTrace => ret::TRACE | errno.unwrap_or(1),
        A::ScmpActLog => ret::LOG,
        A::ScmpActAllow => ret::ALLOW,
        A::ScmpActNotify => unreachable!(),
    }
}

fn holds(a: &oci_spec::runtime::LinuxSeccompArg, v: u64) -> bool {
    use oci_spec::runtime::LinuxSeccompOperator as O;
    let x = a.value();
    match a.op() {
        O::ScmpCmpEq => v == x,
        O::ScmpCmpNe => v != x,
        O::ScmpCmpLt => v < x,
        O::ScmpCmpLe => v <= x,
        O::ScmpCmpGt => v > x,
        O::ScmpCmpGe => v >= x,
        O::ScmpCmpMaskedEq => v & x == a.value_two().unwrap_or(0),
    }
}

/// What the filter compiled from `s` must return for `d`, computed without
/// any of the compiler's machinery.
fn reference(s: &LinuxSeccomp, d: &SeccompData) -> u32 {
    if d.arch != AUDIT_ARCH_X86_64 {
        return ret::KILL_PROCESS;
    }
    let nr = d.nr as u32;
    if nr & X32_SYSCALL_BIT != 0 && nr != u32::MAX {
        return ret::KILL_PROCESS;
    }
    let default = action_value(s.default_action(), s.default_errno_ret());
    let entries = s.syscalls().clone().unwrap_or_default();
    let permissive = matches!(default & ret::ACTION_FULL_MASK, ret::ALLOW | ret::LOG | ret::TRACE);
    if !permissive && default != ENOSYS {
        let highest = entries.iter().flat_map(|e| e.names()).filter_map(|n| syscalls::number(n)).max();
        if highest.is_some_and(|h| nr > h) {
            return ENOSYS;
        }
    }
    for e in &entries {
        let named = e.names().iter().any(|n| syscalls::number(n) == Some(nr));
        if named && e.args().iter().flatten().all(|a| holds(a, d.args[a.index()])) {
            return action_value(e.action(), e.errno_ret());
        }
    }
    default
}

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

/// Values where 64-bit comparisons built from 32-bit halves go wrong if
/// they are going to: around 0, the 32-bit boundary, and the top.
const EDGES: [u64; 16] = [
    0,
    1,
    2,
    0x7fff_ffff,
    0x8000_0000,
    0xffff_fffe,
    0xffff_ffff,
    0x1_0000_0000,
    0x1_0000_0001,
    0x1_ffff_ffff,
    0x2_0000_0000,
    0xffff_ffff_0000_0000,
    0xffff_ffff_7fff_ffff,
    0xffff_ffff_ffff_fffe,
    u64::MAX,
    0x7E02_0000,
];

const POOL: [&str; 12] = [
    "read",
    "write",
    "openat",
    "close",
    "socket",
    "personality",
    "clone",
    "mmap",
    "futex",
    "getpid",
    "arm_fadvise64_64",
    "rseq_slice_yield",
];

const ACTIONS: [&str; 7] = [
    "SCMP_ACT_ALLOW",
    "SCMP_ACT_ERRNO",
    "SCMP_ACT_KILL_PROCESS",
    "SCMP_ACT_TRAP",
    "SCMP_ACT_LOG",
    "SCMP_ACT_TRACE",
    "SCMP_ACT_KILL",
];
const OPS: [&str; 7] =
    ["SCMP_CMP_EQ", "SCMP_CMP_NE", "SCMP_CMP_LT", "SCMP_CMP_LE", "SCMP_CMP_GT", "SCMP_CMP_GE", "SCMP_CMP_MASKED_EQ"];

fn random_value(rng: &mut Rng) -> u64 {
    match rng.below(4) {
        0 => rng.next(),
        1 => rng.next() & 0xffff,
        _ => rng.pick(&EDGES),
    }
}

fn random_profile(rng: &mut Rng) -> Value {
    let mut entries = Vec::new();
    for _ in 0..1 + rng.below(12) {
        let names: Vec<&str> = (0..1 + rng.below(3)).map(|_| rng.pick(&POOL)).collect();
        let args: Vec<Value> = (0..rng.below(4))
            .map(|_| {
                let op = rng.pick(&OPS);
                let value = random_value(rng);
                let mut a = json!({"index": rng.below(3), "value": value, "op": op});
                if op == "SCMP_CMP_MASKED_EQ" && rng.below(3) > 0 {
                    // Mostly a value that can match, sometimes one that can't.
                    a["valueTwo"] = json!(if rng.below(4) > 0 { random_value(rng) & value } else { random_value(rng) });
                }
                a
            })
            .collect();
        let mut e = json!({"names": names, "action": rng.pick(&ACTIONS), "args": args});
        if rng.below(2) == 0 {
            e["errnoRet"] = json!(rng.below(100));
        }
        entries.push(e);
    }
    let mut s = json!({"defaultAction": rng.pick(&ACTIONS), "syscalls": entries});
    if rng.below(2) == 0 {
        s["defaultErrnoRet"] = json!(rng.pick(&[1, 38, 13]));
    }
    s
}

/// Many random profiles, many syscalls each, arguments around the edges:
/// the compiled program must agree with [`reference`] every time.
#[test]
fn compiled_programs_agree_with_the_reference() {
    let mut rng = Rng(0x5eed_cafe_f00d_d00d);
    let extra_nrs = [400, 1000, syscalls::HIGHEST, syscalls::HIGHEST + 1, u32::MAX, X32_SYSCALL_BIT | 1];
    let mut checked = 0;
    for _ in 0..400 {
        let s = spec(random_profile(&mut rng));
        let f = compile(&s).unwrap_or_else(|e| panic!("{e}: {}", serde_json::to_string(&s).unwrap()));
        let nrs = POOL.iter().filter_map(|n| syscalls::number(n)).chain(extra_nrs);
        for nr in nrs {
            for _ in 0..25 {
                let args = std::array::from_fn(|_| random_value(&mut rng));
                let d = SeccompData::x86_64(nr, args);
                let (got, want) = (run(&f, d), reference(&s, &d));
                assert_eq!(
                    got,
                    want,
                    "nr {nr} args {args:x?}\nspec: {}\n{}",
                    serde_json::to_string_pretty(&s).unwrap(),
                    f.disassemble()
                );
                checked += 1;
            }
        }
        let i386 = SeccompData { arch: AUDIT_ARCH_I386, ..SeccompData::x86_64(0, [0; 6]) };
        assert_eq!(run(&f, i386), ret::KILL_PROCESS);
    }
    assert!(checked > 100_000);
}

/// Each operator right at the edges, one argument at a time (the random
/// test covers combinations; this makes sure no single case is missed).
#[test]
fn every_operator_at_every_edge() {
    for op in OPS {
        for &value in &EDGES {
            for two in [0, value, value & 0xffff_ffff, value & !0xffff_ffff] {
                let s = spec(json!({
                    "defaultAction": "SCMP_ACT_ERRNO",
                    "syscalls": [{"names": ["read"], "action": "SCMP_ACT_ALLOW",
                                  "args": [{"index": 1, "value": value, "valueTwo": two, "op": op}]}]
                }));
                let f = compile(&s).unwrap();
                for &arg in &EDGES {
                    for arg in [arg, arg.wrapping_add(1), arg.wrapping_sub(1)] {
                        let d = SeccompData::x86_64(0, [0, arg, 0, 0, 0, 0]);
                        assert_eq!(run(&f, d), reference(&s, &d), "{op} {value:#x} (two {two:#x}) vs {arg:#x}");
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Long jumps and the size limit
// ---------------------------------------------------------------------------

/// Every syscall with its own rule (`arg0 == nr`), so the blocks together
/// are far longer than 255 instructions: the dispatch tree needs `ja`
/// trampolines to reach them, and failing rules need copies of the default
/// `ret`.
#[test]
fn long_jumps_through_trampolines() {
    let entries: Vec<Value> = syscalls::all()
        .map(|(nr, name)| {
            json!({"names": [name], "action": "SCMP_ACT_ALLOW",
                   "args": [{"index": 0, "value": nr, "op": "SCMP_CMP_EQ"}]})
        })
        .collect();
    let (f, stats) =
        compile_with_stats(&spec(json!({"defaultAction": "SCMP_ACT_ERRNO", "syscalls": entries}))).unwrap();
    assert!(stats.instructions > 1500, "{stats:?}");
    assert!(stats.trampolines > 0, "{stats:?}");
    let ja = op::BPF_JMP | op::BPF_JA;
    let far_jumps = f.program.iter().filter(|i| i.code == ja).count();
    assert!(far_jumps > 0, "no ja in the program");
    // At least one ja really jumps farther than a conditional jump could.
    assert!(f.program.iter().any(|i| i.code == ja && i.k > 255));
    for (nr, name) in syscalls::all() {
        let at = |arg0| run(&f, SeccompData::x86_64(nr, [arg0, 0, 0, 0, 0, 0]));
        assert_eq!(at(u64::from(nr)), ALLOW, "{name}");
        assert_eq!(at(u64::from(nr) + 1), EPERM, "{name}");
        assert_eq!(at(u64::from(nr) | 1 << 32), EPERM, "{name}: high word");
    }
}

#[test]
fn too_large_is_an_error() {
    let entries: Vec<Value> = (0..1000u64)
        .map(|v| json!({"names": ["read"], "action": "SCMP_ACT_ALLOW", "args": [{"index": 0, "value": v, "op": "SCMP_CMP_EQ"}]}))
        .collect();
    let err = compile(&spec(json!({"defaultAction": "SCMP_ACT_ERRNO", "syscalls": entries}))).unwrap_err();
    assert!(matches!(&err, Error::InvalidSpec(m) if m.contains("too large")), "{err}");
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

fn compile_json(v: Value) -> crate::Result<Filter> {
    compile(&spec(v))
}

#[test]
fn unsupported_features() {
    let cases = [
        json!({"defaultAction": "SCMP_ACT_NOTIFY"}),
        json!({"defaultAction": "SCMP_ACT_ALLOW", "listenerPath": "/run/agent.sock"}),
        json!({"defaultAction": "SCMP_ACT_ALLOW", "syscalls": [{"names": ["read"], "action": "SCMP_ACT_NOTIFY"}]}),
        json!({"defaultAction": "SCMP_ACT_ALLOW", "flags": ["SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV"]}),
    ];
    for c in cases {
        let err = compile_json(c.clone()).unwrap_err();
        assert!(matches!(&err, Error::Unsupported(u) if u[0].when == "Phase 8"), "{c}: {err}");
    }
}

#[test]
fn invalid_profiles() {
    let cases = [
        (json!({"defaultAction": "SCMP_ACT_ERRNO", "defaultErrnoRet": 5000}), "defaultErrnoRet"),
        (
            json!({"defaultAction": "SCMP_ACT_ALLOW", "syscalls": [{"names": ["read"], "action": "SCMP_ACT_ERRNO", "errnoRet": 4096}]}),
            "errnoRet",
        ),
        (
            json!({"defaultAction": "SCMP_ACT_ALLOW", "syscalls": [{"names": ["read"], "action": "SCMP_ACT_ALLOW",
                   "args": [{"index": 6, "value": 0, "op": "SCMP_CMP_EQ"}]}]}),
            "index 6",
        ),
        (json!({"defaultAction": "SCMP_ACT_ALLOW", "architectures": ["SCMP_ARCH_AARCH64", "SCMP_ARCH_ARM"]}), "X86_64"),
    ];
    for (c, what) in cases {
        let err = compile_json(c.clone()).unwrap_err();
        assert!(matches!(&err, Error::InvalidSpec(m) if m.contains(what)), "{c}: {err}");
    }
}

#[test]
fn accepted_architectures_and_flags() {
    for archs in
        [json!([]), json!(["SCMP_ARCH_NATIVE"]), json!(["SCMP_ARCH_AARCH64", "SCMP_ARCH_X86_64", "SCMP_ARCH_X86"])]
    {
        compile_json(json!({"defaultAction": "SCMP_ACT_ALLOW", "architectures": archs})).unwrap();
    }
    let f = compile_json(json!({"defaultAction": "SCMP_ACT_ALLOW",
        "flags": ["SECCOMP_FILTER_FLAG_LOG", "SECCOMP_FILTER_FLAG_SPEC_ALLOW", "SECCOMP_FILTER_FLAG_TSYNC"]}))
    .unwrap();
    use rustlet_sys::seccomp::flags;
    assert_eq!(f.flags, flags::LOG | flags::SPEC_ALLOW | flags::TSYNC);
}

#[test]
fn actions_and_their_data() {
    let f = compile_json(json!({"defaultAction": "SCMP_ACT_KILL_PROCESS", "syscalls": [
        {"names": ["read"], "action": "SCMP_ACT_ERRNO", "errnoRet": 13},
        {"names": ["write"], "action": "SCMP_ACT_TRACE", "errnoRet": 7},
        {"names": ["close"], "action": "SCMP_ACT_TRACE"},
        {"names": ["getpid"], "action": "SCMP_ACT_KILL"},
        {"names": ["getppid"], "action": "SCMP_ACT_KILL_THREAD"},
        {"names": ["gettid"], "action": "SCMP_ACT_LOG"},
        {"names": ["futex"], "action": "SCMP_ACT_TRAP"},
        {"names": ["not_a_syscall", "openat"], "action": "SCMP_ACT_ALLOW"}
    ]}))
    .unwrap();
    expect(
        &f,
        &[
            ("read", 0, ret::ERRNO | 13),
            ("write", 0, ret::TRACE | 7),
            ("close", 0, ret::TRACE | 1),
            ("getpid", 0, ret::KILL_THREAD),
            ("getppid", 0, ret::KILL_THREAD),
            ("gettid", 0, ret::LOG),
            ("futex", 0, ret::TRAP),
            ("openat", 0, ALLOW),
            ("mmap", 0, ret::KILL_PROCESS),
        ],
    );
}

/// Rules of one syscall across entries: the first match wins, whatever
/// entry it comes from.
#[test]
fn first_matching_rule_wins() {
    let f = compile_json(json!({"defaultAction": "SCMP_ACT_ALLOW", "syscalls": [
        {"names": ["ioctl"], "action": "SCMP_ACT_ERRNO", "errnoRet": 1, "args": [{"index": 0, "value": 3, "op": "SCMP_CMP_EQ"}]},
        {"names": ["read", "ioctl"], "action": "SCMP_ACT_ERRNO", "errnoRet": 2, "args": [{"index": 0, "value": 10, "op": "SCMP_CMP_LT"}]},
        {"names": ["ioctl"], "action": "SCMP_ACT_ERRNO", "errnoRet": 3}
    ]}))
    .unwrap();
    expect(
        &f,
        &[
            ("ioctl", 3, ret::ERRNO | 1),
            ("ioctl", 4, ret::ERRNO | 2),
            ("ioctl", 10, ret::ERRNO | 3),
            ("read", 4, ret::ERRNO | 2),
            ("read", 10, ALLOW),
            ("write", 0, ALLOW),
        ],
    );
}

/// Only permissive profiles and no-rule profiles go without the stub.
#[test]
fn enosys_stub_placement() {
    let stub = |v: Value| compile_with_stats(&spec(v)).unwrap().1.enosys_above;
    let read_allowed = json!([{"names": ["read", "arm_fadvise64_64"], "action": "SCMP_ACT_ALLOW"}]);
    assert_eq!(stub(json!({"defaultAction": "SCMP_ACT_ERRNO", "syscalls": read_allowed})), Some(0));
    assert_eq!(stub(json!({"defaultAction": "SCMP_ACT_ALLOW", "syscalls": read_allowed})), None);
    assert_eq!(stub(json!({"defaultAction": "SCMP_ACT_ERRNO"})), None);
    assert_eq!(stub(json!({"defaultAction": "SCMP_ACT_ERRNO", "defaultErrnoRet": 38, "syscalls": read_allowed})), None);
}

#[test]
fn trivial_profiles() {
    // Nothing but a default: dispatch is a single `ret`.
    let f = compile_json(json!({"defaultAction": "SCMP_ACT_ALLOW"})).unwrap();
    assert_eq!(run(&f, SeccompData::x86_64(0, [0; 6])), ALLOW);
    assert_eq!(run(&f, SeccompData::x86_64(u32::MAX, [0; 6])), ALLOW);
    // Rules that all say what the default says compile to the same program.
    let noisy = compile_json(json!({"defaultAction": "SCMP_ACT_ALLOW",
        "syscalls": [{"names": ["read", "write"], "action": "SCMP_ACT_ALLOW"}]}))
    .unwrap();
    assert_eq!(noisy.program.len(), f.program.len());
}

// ---------------------------------------------------------------------------
// The listing
// ---------------------------------------------------------------------------

/// The small profile from the module documentation, whose listing is shown
/// there (and in the learn chapter). Update both if this changes.
#[test]
fn disassembly_of_a_small_profile() {
    let f = compile_json(json!({"defaultAction": "SCMP_ACT_ERRNO", "syscalls": [
        {"names": ["read", "write", "close", "exit_group"], "action": "SCMP_ACT_ALLOW"},
        {"names": ["socket"], "action": "SCMP_ACT_ALLOW", "args": [{"index": 0, "value": 1, "op": "SCMP_CMP_EQ"}]}
    ]}))
    .unwrap();
    let expected = "\
0000  ld    [4]                             ; arch
0001  jeq   #0xc000003e  jt 0003  jf 0002   ; AUDIT_ARCH_X86_64
0002  ret   KILL_PROCESS
0003  ld    [0]                             ; nr
0004  jset  #0x40000000  jt 0005  jf 0007   ; __X32_SYSCALL_BIT
0005  jeq   #0xffffffff  jt 0007  jf 0006   ; nr == -1 (skipped by a tracer)
0006  ret   KILL_PROCESS
0007  jgt   #231         jt 0008  jf 0009   ; exit_group
0008  ret   ERRNO(38)                       ; ENOSYS
0009  jge   #4           jt 0011  jf 0010   ; stat
0010  jeq   #2           jt 0019  jf 0020   ; open
0011  jge   #42          jt 0013  jf 0012   ; connect
0012  jge   #41          jt 0014  jf 0019   ; socket
0013  jge   #231         jt 0020  jf 0019   ; exit_group
0014  ld    [20]                            ; args[0] hi
0015  jeq   #0           jt 0016  jf 0019
0016  ld    [16]                            ; args[0] lo
0017  jeq   #1           jt 0018  jf 0019
0018  ret   ALLOW
0019  ret   ERRNO(1)                        ; EPERM
0020  ret   ALLOW
";
    assert_eq!(f.disassemble(), expected, "\n{}", f.disassemble());
}

#[test]
fn debug_shows_only_the_size() {
    let f = Filter { program: vec![SockFilter::stmt(op::BPF_RET | op::BPF_K, ALLOW); 3], flags: 4 };
    assert_eq!(format!("{f:?}"), "Filter { instructions: 3, flags: 0x4 }");
}

// ---------------------------------------------------------------------------
// The real kernel
// ---------------------------------------------------------------------------

/// A filter can't be removed, and the test harness is multithreaded (so
/// `fork` is out, see `rustlet_sys::process::fork`). So these tests run
/// the test binary again, as a separate process, with only
/// [`kernel::child`] selected and an environment variable that tells it
/// what to do. Without the variable, `child` does nothing.
mod kernel {
    use std::os::unix::process::ExitStatusExt;
    use std::process::{Command, ExitStatus};

    use nix::sched::CloneFlags;
    use nix::sys::socket::{AddressFamily, SockFlag, SockType, socket};
    use rustlet_sys::Errno;

    use super::*;

    const MODE: &str = "RUSTLET_SECCOMP_TEST_CHILD";

    fn run_child(mode: &str) -> ExitStatus {
        let exe = std::env::current_exe().unwrap();
        Command::new(exe)
            .args(["--exact", "seccomp::tests::kernel::child", "--nocapture", "--test-threads=1"])
            .env(MODE, mode)
            .status()
            .unwrap()
    }

    /// Docker's profile for the default caps, loaded into this thread.
    fn load_default_profile() {
        let f = compile(&docker::default_for(crate::caps::default_set()).unwrap()).unwrap();
        rustlet_sys::prctl::set_no_new_privs().unwrap();
        f.load().unwrap();
        assert_eq!(rustlet_sys::prctl::seccomp_mode().unwrap(), 2, "SECCOMP_MODE_FILTER");
    }

    #[test]
    fn docker_profile_in_the_kernel() {
        let status = run_child("docker");
        assert!(status.success(), "{status:?}");
    }

    #[test]
    fn i386_syscalls_are_killed() {
        if !run_child("i386-probe").success() {
            eprintln!("skipped: this kernel doesn't run i386 syscalls (no IA-32 emulation)");
            return;
        }
        let status = run_child("i386");
        assert_eq!(status.signal(), Some(libc::SIGSYS), "{status:?}");
    }

    #[test]
    fn child() {
        let Ok(mode) = std::env::var(MODE) else { return };
        match mode.as_str() {
            "docker" => {
                load_default_profile();
                assert_eq!(nix::unistd::getpid().as_raw() as u32, std::process::id());
                // Blocked by the filter, whatever the kernel would have said.
                assert_eq!(nix::sched::unshare(CloneFlags::CLONE_NEWUSER), Err(Errno::EPERM));
                let mount =
                    nix::mount::mount(Some("none"), "/tmp", Some("tmpfs"), nix::mount::MsFlags::empty(), None::<&str>);
                assert_eq!(mount, Err(Errno::EPERM));
                let vsock = socket(AddressFamily::Vsock, SockType::Stream, SockFlag::SOCK_CLOEXEC, None);
                assert_eq!(vsock.map(drop), Err(Errno::EPERM));
                // Allowed by an argument rule.
                assert!(socket(AddressFamily::Unix, SockType::Stream, SockFlag::SOCK_CLOEXEC, None).is_ok());
                // Above the profile's highest syscall: the ENOSYS stub.
                assert_eq!(rustlet_sys::seccomp::syscall_unassigned(1000), Err(Errno::ENOSYS));
                // glibc's posix_spawn tries clone3 first, gets ENOSYS from
                // the profile and falls back to clone, which the profile
                // allows (no namespace flags). With EPERM it would fail.
                let status = Command::new("/bin/true").status().unwrap();
                assert!(status.success(), "{status:?}");
            }
            "i386-probe" => {
                assert_eq!(rustlet_sys::seccomp::i386_getpid(), i64::from(std::process::id()));
            }
            "i386" => {
                // No core dump for the expected SIGSYS.
                rustlet_sys::prctl::set_dumpable(false).unwrap();
                load_default_profile();
                rustlet_sys::seccomp::i386_getpid();
                panic!("an i386 syscall got past the filter");
            }
            other => panic!("unknown {MODE} {other:?}"),
        }
    }
}

use oci_spec::runtime::{LinuxDeviceCgroup, LinuxDeviceCgroupBuilder, LinuxDeviceType};

use super::*;

fn req(typ: DevType, major: u32, minor: u32, access: Access) -> Request {
    Request { typ, major, minor, access }
}

fn spec_rule(
    allow: bool,
    typ: Option<LinuxDeviceType>,
    major: Option<i64>,
    minor: Option<i64>,
    access: Option<&str>,
) -> LinuxDeviceCgroup {
    let mut b = LinuxDeviceCgroupBuilder::default().allow(allow);
    if let Some(t) = typ {
        b = b.typ(t);
    }
    if let Some(m) = major {
        b = b.major(m);
    }
    if let Some(m) = minor {
        b = b.minor(m);
    }
    if let Some(a) = access {
        b = b.access(a);
    }
    b.build().unwrap()
}

/// `allow c 1:3 rw` and friends, for readable tests.
fn rule(text: &str) -> Rule {
    let w: Vec<&str> = text.split_whitespace().collect();
    let (major, minor) = w[2].split_once(':').unwrap();
    let num = |s: &str| if s == "*" { None } else { Some(s.parse().unwrap()) };
    Rule {
        allow: w[0] == "allow",
        typ: match w[1] {
            "a" => None,
            "b" => Some(DevType::Block),
            _ => Some(DevType::Char),
        },
        major: num(major),
        minor: num(minor),
        access: Access::parse(w[3]).unwrap(),
        origin: Origin::Default,
    }
}

fn filter(rules: &[&str]) -> DeviceFilter {
    DeviceFilter::from_rules(rules.iter().map(|r| rule(r)).collect()).unwrap()
}

const RW: Access = Access::READ.union(Access::WRITE);

// ── semantics ───────────────────────────────────────────────────────────

#[test]
fn default_deny() {
    let f = filter(&[]);
    for access in [Access::READ, Access::WRITE, Access::MKNOD, Access::ALL] {
        assert!(!f.allows(&req(DevType::Char, 1, 3, access)));
    }
    // A check for no access bits at all (access(X_OK)) is always allowed.
    assert!(f.allows(&req(DevType::Char, 1, 3, Access::NONE)));
}

#[test]
fn the_defaults() {
    let f = DeviceFilter::build(&[], &[]).unwrap();
    for (major, minor) in [(1, 3), (1, 5), (1, 7), (1, 8), (1, 9), (5, 0), (5, 2), (136, 0), (136, 77)] {
        assert!(f.allows(&req(DevType::Char, major, minor, Access::ALL)), "c {major}:{minor}");
    }
    // Not /dev/console (5:1), not tun, not any block device, not even mknod.
    for (typ, major, minor) in
        [(DevType::Char, 5, 1), (DevType::Char, 10, 200), (DevType::Block, 8, 0), (DevType::Block, 1, 3)]
    {
        for access in [Access::READ, Access::WRITE, Access::MKNOD] {
            assert!(!f.allows(&req(typ, major, minor, access)), "{typ:?} {major}:{minor} {access}");
        }
    }
}

/// The spec's rules come first, so the usual leading `deny a rwm` doesn't
/// take away the defaults; and a spec can't deny a default device.
#[test]
fn defaults_come_after_the_spec() {
    let deny_all = spec_rule(false, None, None, None, Some("rwm"));
    let deny_null = spec_rule(false, Some(LinuxDeviceType::C), Some(1), Some(3), Some("rwm"));
    let f = DeviceFilter::build(&[deny_all, deny_null], &[]).unwrap();
    assert!(f.allows(&req(DevType::Char, 1, 3, RW)));
}

#[test]
fn node_rules_allow_only_mknod() {
    let f = DeviceFilter::build(&[], &[(0, DevType::Char, 10, 229)]).unwrap();
    assert!(f.allows(&req(DevType::Char, 10, 229, Access::MKNOD)));
    assert!(!f.allows(&req(DevType::Char, 10, 229, Access::READ)));
    assert_eq!(f.rules.last().unwrap().origin, Origin::Node(0));
}

/// Last match wins, bit by bit. Each row is a case where runc (and cgroup
/// v1) decide differently or refuse the spec.
#[test]
fn last_match_per_bit() {
    let cases: &[(&[&str], Request, bool)] = &[
        // A deny punches a hole into an earlier wildcard allow.
        (&["allow c *:* rwm", "deny c 10:229 rwm"], req(DevType::Char, 10, 229, Access::READ), false),
        (&["allow c *:* rwm", "deny c 10:229 rwm"], req(DevType::Char, 10, 228, Access::READ), true),
        // A wildcard deny takes a bit from an earlier exact allow.
        (&["allow c 1:3 rwm", "deny c *:* w"], req(DevType::Char, 1, 3, Access::WRITE), false),
        (&["allow c 1:3 rwm", "deny c *:* w"], req(DevType::Char, 1, 3, Access::READ), true),
        // A partial deny applies to any request that includes its bits.
        (&["allow a *:* rwm", "deny c 10:229 w"], req(DevType::Char, 10, 229, RW), false),
        (&["allow a *:* rwm", "deny c 10:229 w"], req(DevType::Char, 10, 229, Access::READ), true),
        // Two allows together can cover one request.
        (&["allow c *:* r", "allow c 1:3 w"], req(DevType::Char, 1, 3, RW), true),
        // A later wildcard allow wins over an earlier deny.
        (&["allow a *:* rwm", "deny c 10:229 rwm", "allow c *:* rwm"], req(DevType::Char, 10, 229, RW), true),
        // Types are separate.
        (&["allow b *:* rwm"], req(DevType::Char, 8, 0, Access::READ), false),
        (&["allow b 8:* r"], req(DevType::Block, 8, 17, Access::READ), true),
        (&["allow b 8:* r"], req(DevType::Block, 8, 17, Access::MKNOD), false),
    ];
    for (rules, r, want) in cases {
        let f = filter(rules);
        let rs: Vec<Rule> = rules.iter().map(|t| rule(t)).collect();
        assert_eq!(decide(&rs, r), *want, "decide {rules:?} {r:?}");
        assert_eq!(f.allows(r), *want, "program {rules:?} {r:?}\n{}", f.disassemble());
    }
}

// ── the optimiser ───────────────────────────────────────────────────────

#[test]
fn a_reset_drops_everything_before_it() {
    let f = filter(&["allow c 1:3 rwm", "deny b *:* r", "allow a *:* rwm", "deny c 10:229 w"]);
    assert_eq!(f.initial, Access::ALL);
    assert_eq!(f.compiled, [rule("deny c 10:229 w")]);
}

#[test]
fn a_privileged_spec_compiles_to_almost_nothing() {
    let allow_all = spec_rule(true, None, None, None, Some("rwm"));
    let nodes: Vec<_> = (0..300).map(|i| (i, DevType::Block, 8, i as u32)).collect();
    let f = DeviceFilter::build(&[allow_all], &nodes).unwrap();
    assert_eq!(f.rules.len(), 1 + default_rules().len() + 300);
    assert!(f.compiled.is_empty(), "{:?}", f.compiled);
    assert_eq!(f.program.len(), 2);
    assert!(f.allows(&req(DevType::Block, 8, 0, Access::ALL)));
}

#[test]
fn leading_denies_are_dropped() {
    let f = filter(&["deny c 1:3 rwm", "deny a *:* rwm", "deny b 8:0 m", "allow c 1:3 r", "deny c 1:3 r"]);
    assert_eq!(f.initial, Access::NONE);
    assert_eq!(f.compiled, [rule("allow c 1:3 r"), rule("deny c 1:3 r")]);
}

// ── validation ──────────────────────────────────────────────────────────

#[test]
fn spec_rules_are_validated() {
    use LinuxDeviceType::*;
    let bad: &[(LinuxDeviceCgroup, &str)] = &[
        (spec_rule(true, Some(C), Some(1), Some(3), None), "access is missing"),
        (spec_rule(true, Some(C), Some(1), Some(3), Some("")), "access is missing"),
        (spec_rule(true, Some(C), Some(1), Some(3), Some("rx")), "letters from rwm"),
        (spec_rule(true, Some(U), Some(1), Some(3), Some("rwm")), "is not a, b or c"),
        (spec_rule(true, Some(P), None, None, Some("rwm")), "is not a, b or c"),
        (spec_rule(true, Some(C), Some(4096), None, Some("r")), "major 4096 is out of range"),
        (spec_rule(true, Some(C), Some(-2), None, Some("r")), "major -2 is out of range"),
        (spec_rule(true, Some(C), Some(1), Some(0x10_0000), Some("r")), "minor 1048576 is out of range"),
        (spec_rule(true, None, Some(8), None, Some("rwm")), "exactly `a *:* rwm`"),
        (spec_rule(false, Some(A), None, None, Some("r")), "exactly `a *:* rwm`"),
    ];
    for (r, needle) in bad {
        let e = rules_from_spec(std::slice::from_ref(r)).unwrap_err().to_string();
        assert!(e.contains(needle) && e.contains("linux.resources.devices[0]"), "{r}: {e}");
    }
    let good = [
        spec_rule(true, Some(C), Some(-1), Some(-1), Some("mrw")),
        spec_rule(false, None, Some(-1), None, Some("rwm")),
        spec_rule(true, Some(B), Some(4095), Some(0xf_ffff), Some("rr")),
    ];
    let rules = rules_from_spec(&good).unwrap();
    assert_eq!(rules[0], Rule { origin: Origin::Spec(0), ..rule("allow c *:* rwm") });
    assert_eq!(rules[1], Rule { origin: Origin::Spec(1), ..rule("deny a *:* rwm") });
    assert_eq!(rules[2], Rule { origin: Origin::Spec(2), ..rule("allow b 4095:1048575 r") });
}

#[test]
fn access_strings() {
    assert_eq!(Access::parse("rwm"), Some(Access::ALL));
    assert_eq!(Access::parse("m"), Some(Access::MKNOD));
    assert_eq!(Access::parse(""), None);
    assert_eq!(Access::parse("rwx"), None);
    assert_eq!(Access::ALL.to_string(), "rwm");
    assert_eq!(Access::MKNOD.union(Access::READ).to_string(), "rm");
    assert_eq!(Access::NONE.to_string(), "-");
}

#[test]
fn too_many_rules() {
    let rules: Vec<Rule> =
        (0..=MAX_RULES as u32).map(|i| Rule { allow: i % 2 == 0, ..rule("allow c 1:3 r") }).collect();
    let rules: Vec<Rule> = rules.into_iter().enumerate().map(|(i, r)| Rule { minor: Some(i as u32), ..r }).collect();
    assert!(DeviceFilter::from_rules(rules).unwrap_err().to_string().contains("too many"));
}

// ── the program, against the reference ──────────────────────────────────

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

/// Numbers that rules and requests share often enough to match, plus the
/// edges of the ranges.
const MAJORS: [u32; 6] = [0, 1, 5, 8, 136, MAX_MAJOR];
const MINORS: [u32; 6] = [0, 1, 2, 3, 0xffff, MAX_MINOR];

fn random_rules(rng: &mut Rng) -> Vec<Rule> {
    let n = rng.below(12);
    (0..n)
        .map(|_| {
            if rng.below(10) == 0 {
                return Rule { allow: rng.below(2) == 0, ..rule("allow a *:* rwm") };
            }
            let any = |rng: &mut Rng| rng.below(3) == 0;
            Rule {
                allow: rng.below(2) == 0,
                typ: Some(rng.pick(&[DevType::Block, DevType::Char])),
                major: if any(rng) { None } else { Some(rng.pick(&MAJORS)) },
                minor: if any(rng) { None } else { Some(rng.pick(&MINORS)) },
                access: Access::from_bits(1 + rng.below(7) as u32),
                origin: Origin::Default,
            }
        })
        .collect()
}

#[test]
fn compiled_programs_agree_with_the_reference() {
    let mut rng = Rng(0x5eed_de71_ce50_0001);
    let mut checks = 0;
    for _ in 0..400 {
        let rules = random_rules(&mut rng);
        let f = DeviceFilter::from_rules(rules.clone()).unwrap();
        // Without the optimiser too: it must not change a decision.
        let plain = compile::compile(Access::NONE, &rules);
        for typ in [DevType::Block, DevType::Char] {
            for major in MAJORS.into_iter().chain([7]) {
                for minor in MINORS.into_iter().chain([4]) {
                    for bits in 0..8 {
                        let r = req(typ, major, minor, Access::from_bits(bits));
                        let want = decide(&rules, &r);
                        let ctx = interp::Ctx::from(r);
                        assert_eq!(f.allows(&r), want, "{rules:?} {r:?}\n{}", f.disassemble());
                        assert_eq!(interp::run(&plain, &ctx) == Ok(1), want, "unoptimised {rules:?} {r:?}");
                        checks += 1;
                    }
                }
            }
        }
    }
    assert!(checks > 100_000, "{checks}");
}

/// Numbers above 2^31 are compared as 32-bit values: a 64-bit comparison
/// would sign-extend the immediate. (The kernel never passes such numbers,
/// but the compiler must not care.)
#[test]
fn comparisons_are_32_bit() {
    let r = Rule { major: Some(0x8000_0001), ..rule("allow c 1:3 r") };
    let f = DeviceFilter::from_rules(vec![r]).unwrap();
    assert!(f.allows(&req(DevType::Char, 0x8000_0001, 3, Access::READ)));
    assert!(!f.allows(&req(DevType::Char, 1, 3, Access::READ)));
}

#[test]
fn disassembly_of_the_defaults() {
    let f = DeviceFilter::build(&[spec_rule(false, None, None, None, Some("rwm"))], &[(0, DevType::Char, 10, 229)])
        .unwrap();
    let listing = f.disassemble();
    let want = "   0: (61) r2 = *(u32 *)(r1 +0)       ; access_type
   1: (bc) w3 = w2
   2: (74) w3 >>= 16                  ; w3 = access
   3: (54) w2 &= 65535                ; w2 = type
   4: (61) r4 = *(u32 *)(r1 +4)       ; w4 = major
   5: (61) r5 = *(u32 *)(r1 +8)       ; w5 = minor
   6: (b4) w6 = 0                     ; allowed: -
   7: (bc) w7 = w2                    ; type
   8: (a4) w7 ^= 2
   9: (56) if w7 != 0x0 goto pc+7     ; not char
  10: (bc) w7 = w4                    ; major
  11: (a4) w7 ^= 1
  12: (56) if w7 != 0x0 goto pc+4     ; major != 1
  13: (bc) w7 = w5                    ; minor
  14: (a4) w7 ^= 3
  15: (56) if w7 != 0x0 goto pc+1     ; minor != 3
  16: (44) w6 |= 7                    ; allow rwm
";
    assert!(listing.starts_with(want), "{listing}");
    let tail = "  77: (bc) w7 = w2                    ; type
  78: (a4) w7 ^= 2
  79: (56) if w7 != 0x0 goto pc+4     ; not char
  80: (bc) w7 = w4                    ; major
  81: (a4) w7 ^= 136
  82: (56) if w7 != 0x0 goto pc+1     ; major != 136
  83: (44) w6 |= 7                    ; allow rwm
  84: (bc) w7 = w2                    ; type
  85: (a4) w7 ^= 2
  86: (56) if w7 != 0x0 goto pc+7     ; not char
  87: (bc) w7 = w4                    ; major
  88: (a4) w7 ^= 10
  89: (56) if w7 != 0x0 goto pc+4     ; major != 10
  90: (bc) w7 = w5                    ; minor
  91: (a4) w7 ^= 229
  92: (56) if w7 != 0x0 goto pc+1     ; minor != 229
  93: (44) w6 |= 1                    ; allow m
  94: (5c) w6 &= w3                   ; the requested bits that are allowed
  95: (b4) w0 = 0                     ; deny
  96: (5e) if w6 != w3 goto pc+1      ; a requested bit isn't allowed
  97: (b4) w0 = 1                     ; allow
  98: (95) exit
";
    assert!(listing.ends_with(tail), "{listing}");
}

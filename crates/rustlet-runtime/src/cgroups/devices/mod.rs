//! The device filter: which device nodes a container may open or create.
//!
//! cgroup v1 had a `devices` controller with `devices.allow` and
//! `devices.deny` files. cgroup v2 has no such files. Instead, a
//! `BPF_PROG_TYPE_CGROUP_DEVICE` eBPF program is attached to the cgroup,
//! and the kernel runs it for every device check a process in the cgroup
//! (or below it) causes: opening a device node, `mknod` of one, `access()`
//! on one. The program gets a `struct bpf_cgroup_dev_ctx`:
//!
//! ```text
//! access_type  (access << 16) | type     access: m=1 r=2 w=4   type: b=1 c=2
//! major, minor                           of the node
//! ```
//!
//! and returns 1 (allow) or 0 (the syscall fails with `EPERM`). Opening a
//! node for reading and writing is one check with both bits set.
//!
//! ## The rules
//!
//! [`DeviceFilter::build`] turns this list into a program:
//!
//! 1. the spec's `linux.resources.devices`, in order;
//! 2. the [defaults](default_rules): `/dev/null`, `zero`, `full`, `random`,
//!    `urandom` and `tty` (`rwm`), `/dev/ptmx` (5:2) and the pty slaves
//!    (136:\*). They come *after* the spec's rules, as in runc, so the
//!    `deny a rwm` that starts most specs doesn't take away `/dev/null`.
//!    It also means a spec can't deny a default device;
//! 3. `m` for each char or block node in `linux.devices` that init creates
//!    with `mknod`. Init runs inside the filtered cgroup too. Reading and
//!    writing such a node still needs a rule of its own, as in runc.
//!
//! **Default deny; the last matching rule wins, separately for each access
//! bit.** For a request, each of its bits (`m`, `r`, `w`) is looked up on
//! its own: the last rule that matches the device and has that bit decides
//! it. A request is allowed only if all its bits are. [`decide`] is exactly
//! that, and the tests check the compiled program against it.
//!
//! There are no `c *:* m` and `b *:* m` rules, which runc adds. Even with
//! `CAP_MKNOD`, a container can create only the nodes listed above, never
//! `/dev/sda`. The rootfs is mounted `nodev`, but `/dev` is a tmpfs of the
//! container's own, and without the filter a node made there would work.
//!
//! ## The program
//!
//! Straight-line code, one block per rule. `w6` holds the allowed bits;
//! a block that matches ORs its bits in (allow) or clears them (deny):
//!
//! ```text
//!    0: (61) r2 = *(u32 *)(r1 +0)       ; access_type
//!    1: (bc) w3 = w2
//!    2: (74) w3 >>= 16                  ; w3 = access
//!    3: (54) w2 &= 65535                ; w2 = type
//!    4: (61) r4 = *(u32 *)(r1 +4)       ; w4 = major
//!    5: (61) r5 = *(u32 *)(r1 +8)       ; w5 = minor
//!    6: (b4) w6 = 0                     ; allowed: -
//!    7: (bc) w7 = w2                    ; type
//!    8: (a4) w7 ^= 2
//!    9: (56) if w7 != 0x0 goto pc+7     ; not char
//!   10: (bc) w7 = w4                    ; major
//!   11: (a4) w7 ^= 1
//!   12: (56) if w7 != 0x0 goto pc+4     ; major != 1
//!   13: (bc) w7 = w5                    ; minor
//!   14: (a4) w7 ^= 3
//!   15: (56) if w7 != 0x0 goto pc+1     ; minor != 3
//!   16: (44) w6 |= 7                    ; allow rwm
//!  ...
//!   83: (44) w6 |= 7                    ; allow rwm
//!   84: (5c) w6 &= w3                   ; the requested bits that are allowed
//!   85: (b4) w0 = 0                     ; deny
//!   86: (5e) if w6 != w3 goto pc+1      ; a requested bit isn't allowed
//!   87: (b4) w0 = 1                     ; allow
//!   88: (95) exit
//! ```
//!
//! Each comparison goes through the scratch register `w7` rather than
//! `if w4 != 1`, which keeps the verifier's work linear in the number of
//! rules (`compile.rs` explains why).
//! (The defaults alone: `cargo xtask devices --disasm`.)
//!
//! All arithmetic and comparisons are 32-bit (`w` registers), so an
//! immediate is never sign-extended to 64 bits. Before compiling, an
//! optimiser drops the rules that can't matter. A rule `a *:* rwm` is a
//! reset, so everything before the last one goes, and it sets the start
//! value of `w6`. After an allow-all, allows change nothing until a deny
//! comes, and after a deny-all, denies change nothing until an allow
//! comes. So a privileged spec (`allow a` followed by hundreds of host
//! devices) compiles to a handful of instructions.
//!
//! The program is attached with `BPF_PROG_ATTACH` and `BPF_F_ALLOW_MULTI`.
//! Such an attachment belongs to the cgroup: it outlives the process that
//! made it (`rustlet-runc create` exits right away) and goes when the
//! cgroup is removed. With `ALLOW_MULTI`, programs on ancestor cgroups (for
//! example systemd's, for a unit with `DevicePolicy=`) still run as well,
//! and every one of them must allow.
//!
//! ## Deliberate differences from runc
//!
//! runc first runs the rules through an emulation of cgroup v1's
//! allow/deny lists. There, a deny can't punch a hole into an earlier
//! wildcard allow (runc refuses the spec), and a deny only matches a
//! request that is a subset of its access. So `allow a` then `deny c 10:229 w`
//! still lets `open(O_RDWR)` through. Here a deny always takes its bits
//! away. runc also reads any rule of type `a` as "allow/deny everything",
//! whatever its numbers and access say. Such rules are refused here unless
//! they are exactly `a *:* rwm`. Numbers the kernel can't have (major above
//! 4095, minor above 0xfffff) and negative numbers other than -1 (runc's
//! wildcard) are refused as well.

mod compile;
pub mod disasm;
pub mod interp;

#[cfg(test)]
mod tests;

use std::fmt;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use oci_spec::runtime::{LinuxDeviceCgroup, LinuxDeviceType};
use rustlet_sys::Errno;
use rustlet_sys::bpf::{self, BpfInsn};

use crate::error::{Error, Result};

/// The largest major number the kernel has (`MAJOR()` is 12 bits).
pub const MAX_MAJOR: u32 = 0xfff;
/// The largest minor number (`MINOR()` is 20 bits).
pub const MAX_MINOR: u32 = 0xf_ffff;

/// At most this many rules survive the optimiser. Two verifier limits set
/// it (both measured by `dv_verifier_cost_stays_linear`):
///
/// * it follows each conditional jump's fall-through first and keeps the
///   other branch on a stack of at most 8192 pending states
///   (`BPF_COMPLEXITY_LIMIT_JMP_SEQ`): in straight-line code, one per
///   comparison, and a rule has up to three;
/// * the instructions it processes (about twice the program's length) must
///   stay below a million.
pub const MAX_RULES: usize = 2000;

/// The program's name in `bpftool prog` (at most 15 bytes).
pub const PROG_NAME: &str = "rustlet_devices";

/// A device node's type, as the low 16 bits of `access_type` encode it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DevType {
    /// `BPF_DEVCG_DEV_BLOCK`
    Block,
    /// `BPF_DEVCG_DEV_CHAR`
    Char,
}

impl DevType {
    /// The kernel's value.
    pub const fn bits(self) -> u32 {
        match self {
            DevType::Block => 1,
            DevType::Char => 2,
        }
    }

    /// `b` or `c`, as in `ls -l` and OCI.
    pub const fn letter(self) -> char {
        match self {
            DevType::Block => 'b',
            DevType::Char => 'c',
        }
    }
}

/// A set of access bits (`BPF_DEVCG_ACC_*`).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Access(u8);

impl Access {
    pub const NONE: Access = Access(0);
    /// `mknod`
    pub const MKNOD: Access = Access(1);
    pub const READ: Access = Access(2);
    pub const WRITE: Access = Access(4);
    pub const ALL: Access = Access(7);

    /// The kernel's bits.
    pub const fn bits(self) -> u32 {
        self.0 as u32
    }

    /// Only the three bits there are.
    pub const fn from_bits(bits: u32) -> Access {
        Access((bits & 7) as u8)
    }

    pub const fn union(self, other: Access) -> Access {
        Access(self.0 | other.0)
    }

    pub const fn contains(self, other: Access) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// OCI's access string: letters from `rwm`, at least one.
    pub fn parse(s: &str) -> Option<Access> {
        if s.is_empty() {
            return None;
        }
        s.chars().try_fold(Access::NONE, |acc, c| {
            Some(acc.union(match c {
                'r' => Access::READ,
                'w' => Access::WRITE,
                'm' => Access::MKNOD,
                _ => return None,
            }))
        })
    }
}

/// `rwm` order, as OCI writes it; `-` for none.
impl fmt::Display for Access {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            return f.write_str("-");
        }
        for (bit, c) in [(Access::READ, 'r'), (Access::WRITE, 'w'), (Access::MKNOD, 'm')] {
            if self.contains(bit) {
                write!(f, "{c}")?;
            }
        }
        Ok(())
    }
}

impl fmt::Debug for Access {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// Where a rule came from, for `cargo xtask devices` and error messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// `linux.resources.devices[i]`.
    Spec(usize),
    /// One of the [defaults](default_rules).
    Default,
    /// `m` for `linux.devices[i]`, so init can create it.
    Node(usize),
}

/// One rule, validated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rule {
    pub allow: bool,
    /// `None`: every type (`a`).
    pub typ: Option<DevType>,
    /// `None`: any major.
    pub major: Option<u32>,
    /// `None`: any minor.
    pub minor: Option<u32>,
    pub access: Access,
    pub origin: Origin,
}

impl Rule {
    /// An allow rule for exactly one device.
    pub const fn allow(typ: DevType, major: u32, minor: Option<u32>, access: Access, origin: Origin) -> Rule {
        Rule { allow: true, typ: Some(typ), major: Some(major), minor, access, origin }
    }

    /// Does the rule apply to this device (for some access)?
    pub fn matches(&self, typ: DevType, major: u32, minor: u32) -> bool {
        self.typ.is_none_or(|t| t == typ)
            && self.major.is_none_or(|m| m == major)
            && self.minor.is_none_or(|m| m == minor)
    }

    /// `a *:* rwm`: sets every bit of every device, whatever came before.
    pub fn is_reset(&self) -> bool {
        self.typ.is_none() && self.major.is_none() && self.minor.is_none() && self.access == Access::ALL
    }
}

/// `allow c 1:3 rwm`, `deny a *:* rwm`.
impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let num = |n: Option<u32>| n.map_or_else(|| "*".to_owned(), |n| n.to_string());
        write!(
            f,
            "{} {} {}:{} {}",
            if self.allow { "allow" } else { "deny" },
            self.typ.map_or('a', DevType::letter),
            num(self.major),
            num(self.minor),
            self.access
        )
    }
}

/// One device check, as the kernel asks the program.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Request {
    pub typ: DevType,
    pub major: u32,
    pub minor: u32,
    pub access: Access,
}

/// The reference semantics: each requested bit is decided by the last rule
/// that matches the device and has that bit (none: denied). Allowed if every
/// requested bit is; a request for no bits at all (`access(X_OK)`) always is.
pub fn decide(rules: &[Rule], req: &Request) -> bool {
    [Access::READ, Access::WRITE, Access::MKNOD].into_iter().filter(|&bit| req.access.contains(bit)).all(|bit| {
        rules
            .iter()
            .rev()
            .find(|r| r.access.contains(bit) && r.matches(req.typ, req.major, req.minor))
            .is_some_and(|r| r.allow)
    })
}

/// Devices every container may use, created by init in its `/dev`, plus
/// `/dev/ptmx` and the pty slaves. `/dev/console` is a bind mount of a pty
/// slave (136:N), so it needs no rule of its own.
pub fn default_rules() -> Vec<Rule> {
    let mut rules: Vec<Rule> = crate::dev::DEFAULT_DEVICES
        .into_iter()
        .map(|(_, major, minor)| Rule::allow(DevType::Char, major, Some(minor), Access::ALL, Origin::Default))
        .collect();
    rules.push(Rule::allow(DevType::Char, 5, Some(2), Access::ALL, Origin::Default));
    rules.push(Rule::allow(DevType::Char, 136, None, Access::ALL, Origin::Default));
    rules
}

/// Validates `linux.resources.devices`.
pub fn rules_from_spec(spec: &[LinuxDeviceCgroup]) -> Result<Vec<Rule>> {
    spec.iter().enumerate().map(|(i, d)| rule_from_spec(i, d)).collect()
}

fn rule_from_spec(i: usize, d: &LinuxDeviceCgroup) -> Result<Rule> {
    let bad = |why: String| Error::invalid(format!("linux.resources.devices[{i}] ({d}): {why}"));
    let typ = match d.typ().unwrap_or_default() {
        LinuxDeviceType::A => None,
        LinuxDeviceType::B => Some(DevType::Block),
        LinuxDeviceType::C => Some(DevType::Char),
        t => return Err(bad(format!("type {:?} is not a, b or c", t.as_str()))),
    };
    let number = |what: &str, n: Option<i64>, max: u32| match n {
        None | Some(-1) => Ok(None),
        Some(n) if (0..=i64::from(max)).contains(&n) => Ok(Some(n as u32)),
        Some(n) => Err(bad(format!("{what} {n} is out of range (0 to {max}, or -1 for any)"))),
    };
    let major = number("major", d.major(), MAX_MAJOR)?;
    let minor = number("minor", d.minor(), MAX_MINOR)?;
    let access = match d.access().as_deref() {
        None | Some("") => return Err(bad("access is missing (write rwm for all of read, write and mknod)".into())),
        Some(s) => Access::parse(s).ok_or_else(|| bad(format!("access {s:?} must be letters from rwm")))?,
    };
    let rule = Rule { allow: d.allow(), typ, major, minor, access, origin: Origin::Spec(i) };
    if typ.is_none() && !rule.is_reset() {
        // runc would read this as "allow/deny everything", whatever the
        // numbers and access say; better to refuse than to guess.
        return Err(bad("a rule for all device types must be exactly `a *:* rwm`".into()));
    }
    Ok(rule)
}

/// A compiled device filter, ready to attach.
#[derive(Clone, PartialEq, Eq)]
pub struct DeviceFilter {
    /// Every rule, in order: the spec's, the defaults, the node rules.
    pub rules: Vec<Rule>,
    /// What the optimiser left: the start value of the allowed bits, and
    /// the rules that still matter.
    pub initial: Access,
    pub compiled: Vec<Rule>,
    /// The eBPF program.
    pub program: Vec<BpfInsn>,
}

/// Just the sizes: the plan is logged at debug level. Use
/// [`DeviceFilter::disassemble`] to see the program.
impl fmt::Debug for DeviceFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceFilter")
            .field("rules", &self.rules.len())
            .field("compiled", &self.compiled.len())
            .field("instructions", &self.program.len())
            .finish()
    }
}

impl DeviceFilter {
    /// The filter for a container: `spec` (`linux.resources.devices`), then
    /// the defaults, then `m` for each device node init will `mknod`
    /// (`nodes`: index into `linux.devices`, type, major, minor).
    pub fn build(spec: &[LinuxDeviceCgroup], nodes: &[(usize, DevType, u32, u32)]) -> Result<DeviceFilter> {
        let mut rules = rules_from_spec(spec)?;
        rules.extend(default_rules());
        rules.extend(
            nodes
                .iter()
                .map(|&(i, typ, major, minor)| Rule::allow(typ, major, Some(minor), Access::MKNOD, Origin::Node(i))),
        );
        DeviceFilter::from_rules(rules)
    }

    /// Compiles an already validated rule list, exactly as given (no
    /// defaults added).
    pub fn from_rules(rules: Vec<Rule>) -> Result<DeviceFilter> {
        let (initial, compiled) = optimise(&rules);
        if compiled.len() > MAX_RULES {
            return Err(Error::invalid(format!(
                "linux.resources.devices: {} device rules are too many for the filter (at most {MAX_RULES})",
                compiled.len()
            )));
        }
        let program = compile::compile(initial, &compiled);
        // A program the kernel's verifier would refuse is our bug, not the
        // spec's; say so before anything exists.
        if let Err(e) = interp::check(&program) {
            return Err(Error::container(format!("the device filter compiled to a bad program: {e}")));
        }
        Ok(DeviceFilter { rules, initial, compiled, program })
    }

    /// Loads the program into the kernel (needs `CAP_BPF`, or
    /// `CAP_SYS_ADMIN`). Returns its fd; dropping it unloads the program
    /// unless it is attached somewhere.
    pub fn load(&self) -> Result<OwnedFd> {
        bpf::prog_load(bpf::PROG_TYPE_CGROUP_DEVICE, &self.program, PROG_NAME).map_err(|(errno, log)| Error::Sys {
            context: if log.is_empty() {
                "load the device filter (bpf BPF_PROG_LOAD)".to_owned()
            } else {
                format!("load the device filter (bpf BPF_PROG_LOAD); the verifier said:\n{}", log.trim_end())
            },
            errno,
        })
    }

    /// Loads the program and attaches it to `cgroup` (a directory fd in
    /// cgroupfs), with `BPF_F_ALLOW_MULTI`. The attachment lasts as long as
    /// the cgroup. Returns the program's id, for `bpftool prog show id N`.
    pub fn attach(&self, cgroup: BorrowedFd<'_>) -> Result<u32> {
        let prog = self.load()?;
        bpf::prog_attach(cgroup, prog.as_fd(), bpf::ATTACH_CGROUP_DEVICE, bpf::F_ALLOW_MULTI).map_err(|errno| {
            Error::Sys {
                context: format!(
                    "attach the device filter to the container's cgroup{}",
                    if errno == Errno::EPERM {
                        " (an ancestor cgroup has a device program attached without BPF_F_ALLOW_MULTI)"
                    } else {
                        ""
                    }
                ),
                errno,
            }
        })?;
        bpf::prog_id(prog.as_fd()).map_err(|errno| Error::Sys { context: "read the device filter's id".into(), errno })
    }

    /// One instruction per line, for tests, `cargo xtask devices` and the
    /// learn chapter.
    pub fn disassemble(&self) -> String {
        disasm::disassemble(&self.program)
    }

    /// Runs the program the way the kernel would (in [`interp`]).
    pub fn allows(&self, req: &Request) -> bool {
        interp::run(&self.program, &interp::Ctx::from(*req)).expect("DeviceFilter::from_rules checked the program") == 1
    }
}

/// Drops the rules that can't change any decision. Returns the allowed
/// bits the program starts with, and the rules left.
///
/// * The last `a *:* rwm` sets every bit of every device, so the rules
///   before it don't matter and it becomes the start value.
/// * While every device has all bits (after an allow-all), an allow changes
///   nothing; while none has any (at the start, or after a deny-all), a deny
///   changes nothing. The first rule that does change something ends that.
fn optimise(rules: &[Rule]) -> (Access, Vec<Rule>) {
    let (initial, rest) = match rules.iter().rposition(Rule::is_reset) {
        Some(i) => (if rules[i].allow { Access::ALL } else { Access::NONE }, &rules[i + 1..]),
        None => (Access::NONE, rules),
    };
    let mut uniform = Some(initial);
    let mut kept = Vec::new();
    for r in rest {
        let no_op = match uniform {
            Some(Access::ALL) => r.allow,
            Some(Access::NONE) => !r.allow,
            _ => false,
        };
        if !no_op {
            kept.push(*r);
            uniform = None;
        }
    }
    (initial, kept)
}

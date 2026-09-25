//! From OCI `linux.seccomp` to a BPF program, in three passes:
//!
//! 1. [`resolve`] validates the spec and turns it into numbers: actions into
//!    `SECCOMP_RET_*` values, syscall names into x86_64 numbers, and gathers
//!    each syscall's rules in spec order.
//! 2. [`simplify`] drops rules that can never decide anything, so that
//!    syscalls whose rules mean the same end up with *equal* rule lists and
//!    can share one block of code.
//! 3. [`Gen`] writes the program (header, dispatch tree, rule blocks)
//!    with symbolic labels; [`super::asm`] assembles it.
//!
//! See the module documentation of [`super`] for the program's shape.

use std::collections::{BTreeMap, HashMap};

use oci_spec::runtime::{
    Arch, LinuxSeccomp, LinuxSeccompAction, LinuxSeccompArg, LinuxSeccompFilterFlag, LinuxSeccompOperator,
};
use rustlet_sys::seccomp::{AUDIT_ARCH_X86_64, X32_SYSCALL_BIT, data, flags, op, ret};

use super::asm::{Label, Program, To};
use super::{Filter, Stats, syscalls};
use crate::error::{Error, Result, Unsupported};

const EPERM: u32 = libc::EPERM as u32;
const ENOSYS: u32 = libc::ENOSYS as u32;
/// The largest errno the kernel returns (`MAX_ERRNO`); `-4095..-1` are the
/// error values of a syscall's return register.
const MAX_ERRNO: u32 = 4095;

/// One comparison of a syscall argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct Cond {
    /// Argument index, 0..=5.
    pub index: u32,
    pub op: Cmp,
    /// The value compared against; the mask for [`Cmp::MaskedEq`].
    pub value: u64,
    /// The expected value for [`Cmp::MaskedEq`]: `(arg & value) == value_two`.
    pub value_two: u64,
}

/// `SCMP_CMP_*`. All comparisons are unsigned and 64 bits wide.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Cmp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    MaskedEq,
}

/// "If all `conds` hold, return `action`."
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct Rule {
    pub conds: Vec<Cond>,
    /// A `SECCOMP_RET_*` value, errno or trace message included.
    pub action: u32,
}

/// `linux.seccomp`, validated and turned into numbers.
#[derive(Debug)]
pub(crate) struct Resolved {
    /// `defaultAction` (with `defaultErrnoRet`) as a `SECCOMP_RET_*` value.
    pub default: u32,
    /// `SECCOMP_FILTER_FLAG_*`.
    pub flags: u32,
    /// Each syscall's rules, in the order the spec lists them. Rules for
    /// the same name accumulate across entries.
    pub rules: BTreeMap<u32, Vec<Rule>>,
    /// The ENOSYS stub: numbers above this return `ENOSYS` (see [`stub_wanted`]).
    pub enosys_above: Option<u32>,
    /// Names that aren't x86_64 syscalls.
    pub skipped: Vec<String>,
}

/// Pass 1: validation and name resolution.
pub(crate) fn resolve(spec: &LinuxSeccomp) -> Result<Resolved> {
    let mut unsupported = Vec::new();
    if spec.listener_path().is_some() {
        unsupported.push(Unsupported { field: "linux.seccomp.listenerPath".into(), when: "Phase 8" });
    }
    check_architectures(spec.architectures().as_deref().unwrap_or_default())?;
    let flags = filter_flags(spec.flags().as_deref().unwrap_or_default(), &mut unsupported);
    let default = action(
        spec.default_action(),
        spec.default_errno_ret(),
        ("linux.seccomp.defaultAction", "linux.seccomp.defaultErrnoRet"),
        &mut unsupported,
    )?;

    let mut rules: BTreeMap<u32, Vec<Rule>> = BTreeMap::new();
    let mut skipped = Vec::new();
    let mut highest = None;
    for (i, entry) in spec.syscalls().as_deref().unwrap_or_default().iter().enumerate() {
        let field = format!("linux.seccomp.syscalls[{i}]");
        let action =
            action(entry.action(), entry.errno_ret(), (&field, &format!("{field}.errnoRet")), &mut unsupported)?;
        let conds =
            entry.args().as_deref().unwrap_or_default().iter().map(|a| cond(a, &field)).collect::<Result<Vec<_>>>()?;
        for name in entry.names() {
            match syscalls::number(name) {
                Some(nr) => {
                    rules.entry(nr).or_default().push(Rule { conds: conds.clone(), action });
                    highest = highest.max(Some(nr));
                }
                // What libseccomp (and so runc) does, too: Docker's profile
                // lists syscalls of every architecture in one file.
                None if !skipped.contains(name) => {
                    tracing::debug!(syscall = %name, "seccomp: not an x86_64 syscall, rule skipped");
                    skipped.push(name.clone());
                }
                None => {}
            }
        }
    }
    if !unsupported.is_empty() {
        return Err(Error::Unsupported(unsupported));
    }
    let enosys_above = if stub_wanted(default) { highest } else { None };
    Ok(Resolved { default, flags, rules, enosys_above, skipped })
}

/// `architectures` lists the ABIs the filter is meant for. We only ever
/// run x86_64 programs, so the list must include x86_64 (or "native"); an
/// empty list means native, too. Everything else is accepted and ignored:
///
/// * `SCMP_ARCH_X86` / `SCMP_ARCH_X32` (Docker lists both): **still killed**
///   by the arch check at the top of the program. Supporting them would
///   mean a second syscall table and dispatch tree per ABI; that is a stretch
///   goal, and a deliberate difference from Docker (docs/architecture.md §2.2.2).
/// * other architectures (arm64, …): only make sense on other hosts.
fn check_architectures(archs: &[Arch]) -> Result<()> {
    if archs.is_empty() || archs.iter().any(|a| matches!(a, Arch::ScmpArchNative | Arch::ScmpArchX86_64)) {
        return Ok(());
    }
    let list: Vec<String> = archs.iter().map(ToString::to_string).collect();
    Err(Error::invalid(format!(
        "linux.seccomp.architectures [{}] doesn't include SCMP_ARCH_X86_64 (or SCMP_ARCH_NATIVE), \
         the only architecture this runtime runs",
        list.join(", ")
    )))
}

fn filter_flags(list: &[LinuxSeccompFilterFlag], unsupported: &mut Vec<Unsupported>) -> u32 {
    use LinuxSeccompFilterFlag as F;
    list.iter().fold(0, |bits, f| {
        bits | match f {
            // Log every action except ALLOW (in the audit log).
            F::SeccompFilterFlagLog => flags::LOG,
            // Don't force the Spectre v4 mitigation on the container.
            F::SeccompFilterFlagSpecAllow => flags::SPEC_ALLOW,
            // Install on all threads. Container init is single-threaded, so
            // it changes nothing, but it isn't wrong either.
            F::SeccompFilterFlagTsync => flags::TSYNC,
            // Only meaningful for user notification (SCMP_ACT_NOTIFY).
            F::SeccompFilterFlagWaitKillableRecv => {
                unsupported.push(Unsupported {
                    field: "linux.seccomp.flags: SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV".into(),
                    when: "Phase 8",
                });
                0
            }
        }
    })
}

/// An OCI action as a `SECCOMP_RET_*` value. `fields` names the action and
/// errno fields for error messages.
fn action(
    act: LinuxSeccompAction,
    errno_ret: Option<u32>,
    fields: (&str, &str),
    unsupported: &mut Vec<Unsupported>,
) -> Result<u32> {
    use LinuxSeccompAction as A;
    // The low 16 bits of the return value (SECCOMP_RET_DATA): the errno for
    // ERRNO, a message for the tracer for TRACE. EPERM unless the spec
    // says otherwise, as in runc (for TRACE, too).
    let data = || -> Result<u32> {
        let v = errno_ret.unwrap_or(EPERM);
        if v > MAX_ERRNO {
            return Err(Error::invalid(format!("{} {v} is larger than the largest errno ({MAX_ERRNO})", fields.1)));
        }
        Ok(v)
    };
    Ok(match act {
        // SCMP_ACT_KILL is the old name of KILL_THREAD: only the thread dies,
        // which leaves a process in a strange half-dead state.
        A::ScmpActKill | A::ScmpActKillThread => ret::KILL_THREAD,
        A::ScmpActKillProcess => ret::KILL_PROCESS,
        A::ScmpActTrap => ret::TRAP,
        A::ScmpActErrno => ret::ERRNO | data()?,
        A::ScmpActTrace => ret::TRACE | data()?,
        A::ScmpActLog => ret::LOG,
        A::ScmpActAllow => ret::ALLOW,
        // Needs a listener fd handed to a supervisor (`listenerPath`).
        A::ScmpActNotify => {
            unsupported.push(Unsupported { field: format!("{}: SCMP_ACT_NOTIFY", fields.0), when: "Phase 8" });
            ret::USER_NOTIF
        }
    })
}

fn cond(a: &LinuxSeccompArg, field: &str) -> Result<Cond> {
    use LinuxSeccompOperator as O;
    if a.index() > 5 {
        return Err(Error::invalid(format!(
            "{field}: argument index {} doesn't exist (syscalls have 6 arguments, 0 to 5)",
            a.index()
        )));
    }
    let op = match a.op() {
        O::ScmpCmpEq => Cmp::Eq,
        O::ScmpCmpNe => Cmp::Ne,
        O::ScmpCmpLt => Cmp::Lt,
        O::ScmpCmpLe => Cmp::Le,
        O::ScmpCmpGt => Cmp::Gt,
        O::ScmpCmpGe => Cmp::Ge,
        O::ScmpCmpMaskedEq => Cmp::MaskedEq,
    };
    Ok(Cond { index: a.index() as u32, op, value: a.value(), value_two: a.value_two().unwrap_or(0) })
}

/// Should syscalls newer than the profile return `ENOSYS` (runc's "ENOSYS
/// stub")?
///
/// A profile is an allowlist written at some point in time. A syscall added
/// to the kernel later isn't in it, so it gets the default action, EPERM.
/// But libcs probe new syscalls and fall back to old ones **only on
/// ENOSYS** ("this kernel doesn't have it"): glibc tries `clone3` and falls
/// back to `clone`, tries `faccessat2` before `faccessat`, `statx` before
/// `newfstatat`. EPERM makes them fail instead. So numbers above the
/// highest syscall the profile mentions return ENOSYS; everything below
/// still gets the default action.
///
/// Not for permissive defaults (ALLOW/LOG allow new syscalls anyway; a
/// tracer handles them itself for TRACE), nor if the default already is
/// ENOSYS.
fn stub_wanted(default: u32) -> bool {
    match default & ret::ACTION_FULL_MASK {
        ret::ALLOW | ret::LOG | ret::TRACE => false,
        ret::ERRNO => default & ret::DATA_MASK != ENOSYS,
        _ => true,
    }
}

impl Cond {
    /// `Some(b)` if the condition is `b` whatever the argument's value.
    fn constant(&self) -> Option<bool> {
        match self.op {
            Cmp::Lt if self.value == 0 => Some(false),
            Cmp::Ge if self.value == 0 => Some(true),
            Cmp::Gt if self.value == u64::MAX => Some(false),
            Cmp::Le if self.value == u64::MAX => Some(true),
            // A bit outside the mask can never be set in `arg & mask`.
            Cmp::MaskedEq if self.value_two & !self.value != 0 => Some(false),
            // `(arg & 0) == 0`.
            Cmp::MaskedEq if self.value == 0 => Some(true),
            _ => None,
        }
    }
}

/// Pass 2: the shortest rule list with the same verdicts. "First match
/// wins", so:
///
/// 1. conditions that always hold are dropped, and rules with one that
///    never holds;
/// 2. a rule identical to an earlier one can never be the first match;
/// 3. nothing after an unconditional rule is ever reached;
/// 4. trailing rules whose action is the default change nothing: whether
///    they match or not, the result is the default.
///
/// A syscall that ends up with no rules is simply handled by the default.
pub(crate) fn simplify(rules: &[Rule], default: u32) -> Vec<Rule> {
    let mut out: Vec<Rule> = Vec::new();
    for rule in rules {
        let mut conds = Vec::new();
        let mut never = false;
        for c in &rule.conds {
            match c.constant() {
                Some(true) => {}
                Some(false) => never = true,
                None if !conds.contains(c) => conds.push(*c),
                None => {}
            }
        }
        let rule = Rule { conds, action: rule.action };
        if never || out.contains(&rule) {
            continue;
        }
        let unconditional = rule.conds.is_empty();
        out.push(rule);
        if unconditional {
            break;
        }
    }
    while out.last().is_some_and(|r| r.action == default) {
        out.pop();
    }
    out
}

/// A range of syscall numbers, `lo..=hi`, that all go to the same block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Run {
    lo: u32,
    hi: u32,
    block: usize,
}

/// Cuts `0..=top` into maximal runs of numbers with the same block.
/// `targets` is sorted by number; numbers it doesn't list go to `default`.
fn runs(targets: &[(u32, usize)], default: usize, top: u32) -> Vec<Run> {
    let mut runs: Vec<Run> = Vec::new();
    let mut push = |lo: u32, hi: u32, block: usize| match runs.last_mut() {
        Some(last) if last.block == block => last.hi = hi,
        _ => runs.push(Run { lo, hi, block }),
    };
    let mut next = 0; // the lowest number not covered yet
    for &(nr, block) in targets {
        if nr > next {
            push(next, nr - 1, default);
        }
        push(nr, nr, block);
        next = nr + 1; // no overflow: syscall numbers are small
    }
    if next <= top {
        push(next, top, default);
    }
    runs
}

/// At most this many `jeq`s in a row replace a subtree (see [`jeq_chain`]).
const MAX_CHAIN: usize = 3;

/// Is `runs` a few single syscalls on a common background, like
/// `[default, 165, default, 166, default]`? Then a chain of `jeq`s is both
/// shorter and no deeper than a subtree of `jge`s: 2 instructions instead of
/// 4 here. Returns the background block and the `(nr, block)` singles.
fn jeq_chain(runs: &[Run]) -> Option<(usize, Vec<(u32, usize)>)> {
    if runs.len().is_multiple_of(2) || runs.len() > 2 * MAX_CHAIN + 1 {
        return None;
    }
    let background = runs[0].block;
    let shape_ok = runs.iter().enumerate().all(|(i, r)| if i % 2 == 0 { r.block == background } else { r.lo == r.hi });
    shape_ok.then(|| (background, runs.iter().skip(1).step_by(2).map(|r| (r.lo, r.block)).collect()))
}

/// Pass 3: code generation.
struct Gen {
    p: Program,
    /// Distinct rule lists ("blocks"). Block 0 is the empty list: the
    /// default action.
    blocks: Vec<Vec<Rule>>,
    ids: HashMap<Vec<Rule>, usize>,
    labels: Vec<Label>,
    default: u32,
}

impl Gen {
    /// The block for `rules`, shared with every syscall that has the same.
    fn block(&mut self, rules: Vec<Rule>) -> usize {
        if let Some(&id) = self.ids.get(&rules) {
            return id;
        }
        let id = self.blocks.len();
        self.ids.insert(rules.clone(), id);
        self.blocks.push(rules);
        let label = self.p.label();
        self.labels.push(label);
        id
    }

    /// If a block is a single `ret`, the `ret` value.
    fn single_ret(&self, id: usize) -> Option<u32> {
        match self.blocks[id].as_slice() {
            [] => Some(self.default),
            [rule] if rule.conds.is_empty() => Some(rule.action),
            _ => None,
        }
    }

    /// Where the dispatch over `runs` starts: the block itself if there is
    /// only one run, else a new tree node.
    fn entry(&mut self, runs: &[Run]) -> Label {
        if let [run] = runs { self.labels[run.block] } else { self.p.label() }
    }

    /// Emits the dispatch over `runs` (a binary search on the syscall
    /// number in `A`), starting at `entry`. Returns its depth: the most
    /// jumps a syscall goes through before it reaches its block.
    ///
    /// ```text
    ///   runs:  0..=8 ALLOW | 9..=11 B | 12..=165 ALLOW | 166..=200 default
    ///
    ///   jge #12   ──true──►  jge #166  ──true──►  default
    ///     │false                 └─false──►  ALLOW
    ///     ▼
    ///   jge #9    ──true──►  B          (jge #9 falls through to the left half)
    ///     └─false──►  ALLOW
    /// ```
    fn tree(&mut self, runs: &[Run], entry: Label) -> usize {
        if runs.len() == 1 {
            return 0;
        }
        self.p.place(entry);
        if let Some((background, singles)) = jeq_chain(runs) {
            for (i, &(nr, block)) in singles.iter().enumerate() {
                let jf = if i + 1 == singles.len() { To::L(self.labels[background]) } else { To::Next };
                self.p.jeq(nr, self.labels[block], jf);
            }
            return singles.len();
        }
        let (left, right) = runs.split_at(runs.len() / 2);
        let (l, r) = (self.entry(left), self.entry(right));
        // Left subtree first, right behind it: the false branch falls through.
        self.p.jge(right[0].lo, r, l);
        let depth_left = self.tree(left, l);
        let depth_right = self.tree(right, r);
        1 + depth_left.max(depth_right)
    }

    /// A rule block: the rules in order, each a sequence of conditions that
    /// jump to the next rule as soon as one fails; the last rule's failure
    /// goes to the default action.
    fn rules(&mut self, id: usize) {
        let rules = self.blocks[id].clone();
        let default = self.labels[0];
        for (i, rule) in rules.iter().enumerate() {
            let last = i + 1 == rules.len();
            let fail = if last { default } else { self.p.label() };
            for c in &rule.conds {
                self.cond(c, fail);
            }
            self.p.ret(rule.action);
            if !last {
                self.p.place(fail);
            }
        }
    }

    /// One 64-bit comparison, from 32-bit loads: `seccomp_data.args[i]` is
    /// a little-endian `u64`, so its low word is at `ARGS + 8*i` and its
    /// high word 4 bytes later. Falls through when the condition holds,
    /// jumps to `fail` when it doesn't.
    ///
    /// Ordered comparisons decide on the high words unless they are equal;
    /// only then do the low words matter (like comparing two-digit numbers
    /// digit by digit). For `arg > v`:
    ///
    /// ```text
    ///   ld  [hi]
    ///   jgt #v.hi  → pass            hi > v.hi: certainly greater
    ///   jeq #v.hi  → (next) : fail   hi < v.hi: certainly not
    ///   ld  [lo]                     hi == v.hi: the low words decide
    ///   jgt #v.lo  → (next) : fail
    /// ```
    ///
    /// When `v.hi` is 0 the `jeq` is dropped: not greater than 0 is equal.
    fn cond(&mut self, c: &Cond, fail: Label) {
        let lo = data::ARGS + 8 * c.index;
        let hi = lo + 4;
        let (vh, vl) = halves(c.value);
        let pass = self.p.label();
        let p = &mut self.p;
        match c.op {
            Cmp::Eq => {
                p.ld(hi);
                p.jeq(vh, To::Next, fail);
                p.ld(lo);
                p.jeq(vl, To::Next, fail);
            }
            Cmp::Ne => {
                p.ld(hi);
                p.jeq(vh, To::Next, pass);
                p.ld(lo);
                p.jeq(vl, fail, To::Next);
            }
            Cmp::Gt | Cmp::Ge => {
                p.ld(hi);
                p.jgt(vh, pass, To::Next);
                if vh != 0 {
                    p.jeq(vh, To::Next, fail);
                }
                p.ld(lo);
                if c.op == Cmp::Gt { p.jgt(vl, To::Next, fail) } else { p.jge(vl, To::Next, fail) }
            }
            Cmp::Lt | Cmp::Le => {
                p.ld(hi);
                p.jgt(vh, fail, To::Next);
                if vh != 0 {
                    p.jeq(vh, To::Next, pass);
                }
                p.ld(lo);
                if c.op == Cmp::Lt { p.jge(vl, fail, To::Next) } else { p.jgt(vl, fail, To::Next) }
            }
            // `(arg & mask) == want`, word by word. A word whose mask is 0
            // is skipped (then `want`'s word is 0 too: `simplify` removed
            // rules where it isn't), and an all-ones mask needs no `and`.
            Cmp::MaskedEq => {
                let (mh, ml) = halves(c.value);
                let (wh, wl) = halves(c.value_two);
                for (offset, mask, want) in [(hi, mh, wh), (lo, ml, wl)] {
                    if mask == 0 {
                        continue;
                    }
                    p.ld(offset);
                    if mask != u32::MAX {
                        p.and(mask);
                    }
                    p.jeq(want, To::Next, fail);
                }
            }
        }
        p.place(pass);
    }
}

fn halves(v: u64) -> (u32, u32) {
    ((v >> 32) as u32, v as u32)
}

/// All three passes, plus the kernel's size limit.
pub(crate) fn compile(spec: &LinuxSeccomp) -> Result<(Filter, Stats)> {
    let r = resolve(spec)?;
    let mut g =
        Gen { p: Program::default(), blocks: Vec::new(), ids: HashMap::new(), labels: Vec::new(), default: r.default };
    let default_block = g.block(Vec::new());
    let targets: Vec<(u32, usize)> =
        r.rules.iter().map(|(&nr, rules)| (nr, g.block(simplify(rules, r.default)))).collect();
    let runs = runs(&targets, default_block, r.enosys_above.unwrap_or(u32::MAX));

    // 1. The architecture. The same syscall number means different things
    //    in different ABIs (i386 `int 0x80`: 11 is execve; x86_64: munmap),
    //    so the numbers below are only meaningful for x86_64.
    let p = &mut g.p;
    p.ld(data::ARCH);
    let arch_ok = p.label();
    p.jeq(AUDIT_ARCH_X86_64, arch_ok, To::Next);
    p.ret(ret::KILL_PROCESS);
    p.place(arch_ok);

    // 2. x32 syscalls come in on x86_64's arch value with bit 30 set in the
    //    number. The exception is -1 (all bits set): a tracer that wants a
    //    syscall skipped sets its number to -1, and the kernel then runs the
    //    filter again; libseccomp lets that through as well (the kernel
    //    answers ENOSYS for -1).
    p.ld(data::NR);
    let nr_ok = p.label();
    p.jset(X32_SYSCALL_BIT, To::Next, nr_ok);
    p.jeq(u32::MAX, nr_ok, To::Next);
    p.ret(ret::KILL_PROCESS);
    p.place(nr_ok);

    // 3. The ENOSYS stub (see `stub_wanted`).
    if let Some(highest) = r.enosys_above {
        let known = p.label();
        p.jgt(highest, To::Next, known);
        p.ret(ret::ERRNO | ENOSYS);
        p.place(known);
    }

    // 4. Dispatch on the number.
    let entry = g.entry(&runs);
    let depth = g.tree(&runs, entry);
    if runs.len() == 1 {
        g.p.ja(entry);
    }

    // 5. Rule blocks, then the blocks that are a single `ret` (the default
    //    action among them). Everything jumps forward, so the `ret`s go last.
    for id in 0..g.blocks.len() {
        if g.single_ret(id).is_none() {
            g.p.place(g.labels[id]);
            g.rules(id);
        }
    }
    for id in 0..g.blocks.len() {
        if let Some(action) = g.single_ret(id) {
            g.p.place(g.labels[id]);
            g.p.ret(action);
        }
    }

    let asm = g.p.assemble();
    if asm.insns.len() > op::BPF_MAXINSNS {
        return Err(Error::invalid(format!(
            "linux.seccomp: the compiled filter is too large: {} BPF instructions, the kernel's limit is {}",
            asm.insns.len(),
            op::BPF_MAXINSNS
        )));
    }
    let stats = Stats {
        instructions: asm.insns.len(),
        syscalls: r.rules.len(),
        skipped: r.skipped,
        default_action: r.default,
        enosys_above: r.enosys_above,
        ranges: runs.len(),
        dispatch_depth: depth,
        blocks: g.blocks.len(),
        trampolines: asm.trampolines,
    };
    Ok((Filter { program: asm.insns, flags: r.flags }, stats))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eq(index: u32, value: u64) -> Cond {
        Cond { index, op: Cmp::Eq, value, value_two: 0 }
    }

    const ALLOW: u32 = ret::ALLOW;
    const EPERM_RET: u32 = ret::ERRNO | EPERM;

    #[test]
    fn simplify_stops_at_the_first_unconditional_rule() {
        let rules = vec![
            Rule { conds: vec![eq(0, 1)], action: ALLOW },
            Rule { conds: vec![], action: ret::TRAP },
            Rule { conds: vec![eq(0, 2)], action: ALLOW },
        ];
        assert_eq!(simplify(&rules, EPERM_RET), rules[..2]);
    }

    #[test]
    fn simplify_drops_duplicates_constants_and_default_tails() {
        let never = Cond { index: 0, op: Cmp::Lt, value: 0, value_two: 0 };
        let always = Cond { index: 1, op: Cmp::MaskedEq, value: 0, value_two: 0 };
        let rules = vec![
            Rule { conds: vec![eq(0, 1), always], action: ALLOW },
            Rule { conds: vec![eq(0, 1)], action: ALLOW },
            Rule { conds: vec![never], action: ALLOW },
            Rule { conds: vec![eq(0, 3)], action: EPERM_RET },
            Rule { conds: vec![], action: EPERM_RET },
        ];
        assert_eq!(simplify(&rules, EPERM_RET), vec![Rule { conds: vec![eq(0, 1)], action: ALLOW }]);
    }

    #[test]
    fn runs_cover_everything_up_to_top() {
        let r = runs(&[(0, 1), (1, 1), (3, 2), (4, 0)], 0, 10);
        assert_eq!(
            r,
            vec![
                Run { lo: 0, hi: 1, block: 1 },
                Run { lo: 2, hi: 2, block: 0 },
                Run { lo: 3, hi: 3, block: 2 },
                Run { lo: 4, hi: 10, block: 0 }
            ]
        );
    }

    #[test]
    fn jeq_chains_only_for_singles_on_one_background() {
        let run = |lo, hi, block| Run { lo, hi, block };
        assert_eq!(jeq_chain(&[run(0, 4, 0), run(5, 5, 1), run(6, 9, 0)]), Some((0, vec![(5, 1)])));
        assert_eq!(jeq_chain(&[run(0, 4, 0), run(5, 6, 1), run(7, 9, 0)]), None, "5..=6 is not a single");
        assert_eq!(jeq_chain(&[run(0, 4, 0), run(5, 5, 1), run(6, 9, 2)]), None, "two backgrounds");
    }

    #[test]
    fn stub_only_for_restrictive_defaults() {
        assert!(stub_wanted(EPERM_RET));
        assert!(stub_wanted(ret::KILL_PROCESS));
        assert!(stub_wanted(ret::KILL_THREAD));
        assert!(!stub_wanted(ret::ERRNO | ENOSYS));
        assert!(!stub_wanted(ret::ALLOW));
        assert!(!stub_wanted(ret::LOG));
        assert!(!stub_wanted(ret::TRACE | 1));
    }
}

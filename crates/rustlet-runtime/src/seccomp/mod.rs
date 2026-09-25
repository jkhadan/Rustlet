//! Seccomp: compiling OCI `linux.seccomp` to classic BPF, by hand.
//!
//! ## What seccomp does
//!
//! Once a thread has a seccomp filter, **every syscall it makes first runs
//! the filter**, a small program in *classic BPF* (the 1992 packet-filter
//! language, not eBPF). The program sees `struct seccomp_data`:
//!
//! ```text
//!   offset  field                    notes
//!   0       int   nr                 the syscall number, x86_64 numbering
//!   4       __u32 arch               AUDIT_ARCH_X86_64 (AUDIT_ARCH_I386 for `int 0x80`)
//!   8       __u64 instruction_pointer
//!   16      __u64 args[6]            args[i]: low word at 16+8i, high word at 20+8i
//! ```
//!
//! and returns a verdict, a `SECCOMP_RET_*` value: `ALLOW`, `ERRNO | e` (fail
//! with errno `e` without running the syscall), `KILL_PROCESS`, `TRAP`
//! (SIGSYS), `TRACE`, `LOG`, … The machine is tiny: a 32-bit accumulator
//! `A`, an index register `X`, 16 words of scratch memory, loads that can
//! only read `seccomp_data`, and **jumps that only go forward**. So every
//! program terminates, and the kernel can check it in one pass. At most
//! 4096 instructions; conditional jumps skip at most 255.
//!
//! A filter can't be removed and survives `fork` and `execve`. Installing
//! one needs `no_new_privs` (or `CAP_SYS_ADMIN`): otherwise a filter could
//! make a setuid binary fail in ways its author never expected, and exploit
//! that. See `process` for where container init installs it.
//!
//! ## The shape of our programs
//!
//! Compiled from a small profile (ERRNO by default; `read`, `write`,
//! `close` and `exit_group` allowed; `socket` only for `AF_UNIX`),
//! `Filter::disassemble` prints the listing below. Jump targets are
//! absolute; comments name the `seccomp_data` word a load reads, and the
//! syscall a number stands for when `A` holds the number (`jge #4 ; stat`:
//! "is nr at least 4, `stat`'s number?").
//!
//! ```text
//! 0000  ld    [4]                             ; arch
//! 0001  jeq   #0xc000003e  jt 0003  jf 0002   ; AUDIT_ARCH_X86_64
//! 0002  ret   KILL_PROCESS
//! 0003  ld    [0]                             ; nr
//! 0004  jset  #0x40000000  jt 0005  jf 0007   ; __X32_SYSCALL_BIT
//! 0005  jeq   #0xffffffff  jt 0007  jf 0006   ; nr == -1 (skipped by a tracer)
//! 0006  ret   KILL_PROCESS
//! 0007  jgt   #231         jt 0008  jf 0009   ; exit_group
//! 0008  ret   ERRNO(38)                       ; ENOSYS
//! 0009  jge   #4           jt 0011  jf 0010   ; stat
//! 0010  jeq   #2           jt 0019  jf 0020   ; open
//! 0011  jge   #42          jt 0013  jf 0012   ; connect
//! 0012  jge   #41          jt 0014  jf 0019   ; socket
//! 0013  jge   #231         jt 0020  jf 0019   ; exit_group
//! 0014  ld    [20]                            ; args[0] hi
//! 0015  jeq   #0           jt 0016  jf 0019
//! 0016  ld    [16]                            ; args[0] lo
//! 0017  jeq   #1           jt 0018  jf 0019
//! 0018  ret   ALLOW
//! 0019  ret   ERRNO(1)                        ; EPERM
//! 0020  ret   ALLOW
//! ```
//!
//! 1. **Architecture** (0–2). Syscall numbers are per ABI (`int 0x80` 11
//!    is `execve`, x86_64 11 is `munmap`), so anything but x86_64 is killed.
//! 2. **x32** (3–6). x32 programs use x86_64's arch value but set bit 30 of
//!    the number; killed too. The exception is -1, which is how a tracer
//!    skips a syscall; libseccomp lets it through as well.
//! 3. **ENOSYS stub** (7–8). Numbers above the highest syscall the profile
//!    mentions return ENOSYS, not the default EPERM, so libcs fall back
//!    from syscalls newer than the profile (see `compile::stub_wanted`).
//! 4. **Dispatch** (9–13): a binary search on the number over *ranges* of
//!    numbers that share a verdict: 0–3 are allowed except 2 (`open`),
//!    4–40 are not, 41 has rules, … Docker's profile allows about 300 x86_64
//!    syscalls, mostly in long runs, so its tree has 65 ranges and is 7
//!    comparisons deep.
//! 5. **Rule blocks** (14–18): a syscall's argument rules, first match
//!    wins, each 64-bit comparison done on two 32-bit halves.
//! 6. **Verdicts** (19–20): the `ret`s that many syscalls share, the
//!    default action among them. They come last because jumps only go
//!    forward.
//!
//! ## Modules
//!
//! | module     | what it does                                               |
//! |------------|------------------------------------------------------------|
//! | `syscalls` | x86_64 name ↔ number, generated from the kernel's table    |
//! | `compile`  | validation, rule simplification, code generation (private) |
//! | `asm`      | labels → jump offsets, trampolines for far jumps (private)  |
//! | `disasm`   | the listing above                                          |
//! | `interp`   | a classic-BPF interpreter, so tests can run filters        |
//! | `docker`   | Docker's default profile, resolved for a container's caps  |
//!
//! ## Semantics, and where they differ from runc
//!
//! * Rules for one syscall are tried in spec order (entries that name the
//!   same syscall accumulate); a rule's `args` conditions are ANDed; the
//!   first matching rule's action wins; no match means `defaultAction`.
//!   Comparisons are unsigned 64-bit; `SCMP_CMP_MASKED_EQ` is
//!   `(arg & value) == valueTwo`.
//! * Names that aren't x86_64 syscalls are skipped, as runc does.
//! * Differences: i386 and x32 programs are killed (Docker allows them;
//!   supporting them is a stretch goal), and `SCMP_ACT_NOTIFY` /
//!   `listenerPath` are rejected until Phase 8.
//! * Two smaller differences from runc: runc loads every filter with
//!   `SECCOMP_FILTER_FLAG_SPEC_ALLOW` (turning off the Speculative Store
//!   Bypass mitigation for the container) even when the profile lists no
//!   flags; Rustlets passes only the flags the profile asks for. And for an
//!   x86_64-only profile runc's wrong-architecture action is `KILL_THREAD`,
//!   ours `KILL_PROCESS`.
//! * Argument rules compare all 64 bits, as libseccomp does, but many
//!   syscalls take an `int` and the kernel ignores the high half. So a
//!   *deny* rule such as "`socket` with arg0 == 40 → EPERM" is bypassed with
//!   `0x1_0000_0028`, which the kernel still reads as 40. Allow-lists (what
//!   Docker's profile uses: "`socket` only if arg0 < 38, …") fail safe, since
//!   the odd value simply matches no allow rule.
//! * Precedence differs from libseccomp (and so runc) in one corner: a
//!   syscall with an argument rule *followed by* an unconditional rule with
//!   a different action, e.g. `[{x, ALLOW, arg0 == 1}, {x, ERRNO}]`. Here
//!   the first match wins, so `x(1)` is allowed; libseccomp lets the
//!   unconditional rule replace the conditional one and denies it. Docker's
//!   profile never does this (every syscall with several rules uses one
//!   action throughout), and a profile that does is ambiguous anyway: write
//!   the rules in the order you mean them.

mod asm;
mod compile;
pub mod disasm;
pub mod docker;
pub mod interp;
pub mod syscalls;

#[cfg(test)]
mod tests;

use std::fmt;

use oci_spec::runtime::LinuxSeccomp;
use rustlet_sys::seccomp::SockFilter;

use crate::error::{Context, Result};

/// A compiled seccomp filter, ready to load.
#[derive(Clone, PartialEq, Eq)]
pub struct Filter {
    /// The classic-BPF program (at most `BPF_MAXINSNS` instructions).
    pub program: Vec<SockFilter>,
    /// `SECCOMP_FILTER_FLAG_*` bits for `seccomp(SECCOMP_SET_MODE_FILTER)`.
    pub flags: u32,
}

/// Just the size: the plan is logged at debug level, and a few hundred
/// instructions would drown everything else. Use [`Filter::disassemble`]
/// to see the program.
impl fmt::Debug for Filter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Filter")
            .field("instructions", &self.program.len())
            .field("flags", &format_args!("{:#x}", self.flags))
            .finish()
    }
}

/// What the compiler made of a profile, for `cargo xtask seccomp` and tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stats {
    /// Instructions in the program.
    pub instructions: usize,
    /// Syscall numbers the profile has rules for.
    pub syscalls: usize,
    /// Names in the profile that aren't x86_64 syscalls (and were skipped).
    pub skipped: Vec<String>,
    /// `defaultAction` as a `SECCOMP_RET_*` value.
    pub default_action: u32,
    /// Numbers above this return ENOSYS (the ENOSYS stub), if there is one.
    pub enosys_above: Option<u32>,
    /// Ranges of syscall numbers the dispatch tree tells apart.
    pub ranges: usize,
    /// The most comparisons the dispatch makes before a syscall reaches its
    /// rule block.
    pub dispatch_depth: usize,
    /// Distinct blocks: syscalls with identical rules share one.
    pub blocks: usize,
    /// Trampolines inserted for jumps farther than 255 instructions.
    pub trampolines: usize,
}

/// Validates and compiles `linux.seccomp`. Runs in the parent at plan time,
/// so a bad profile fails `create` before anything exists.
pub fn compile(spec: &LinuxSeccomp) -> Result<Filter> {
    compile::compile(spec).map(|(filter, _)| filter)
}

/// [`compile`], plus what the compiler did.
pub fn compile_with_stats(spec: &LinuxSeccomp) -> Result<(Filter, Stats)> {
    compile::compile(spec)
}

impl Filter {
    /// Installs the filter on the calling thread (and so on everything it
    /// `execve`s). Needs `no_new_privs` or `CAP_SYS_ADMIN`.
    pub fn load(&self) -> Result<()> {
        rustlet_sys::seccomp::set_mode_filter(&self.program, self.flags)
            .map(drop)
            .context("seccomp(SECCOMP_SET_MODE_FILTER)")
    }

    /// One instruction per line, for tests, `cargo xtask seccomp` and the
    /// learn chapter.
    pub fn disassemble(&self) -> String {
        disasm::disassemble(&self.program)
    }
}

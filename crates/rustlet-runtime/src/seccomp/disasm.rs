//! A disassembler for seccomp programs: one line per instruction, with
//! absolute jump targets and comments that say what is being compared.
//!
//! ```text
//! 0003  ld    [0]                             ; nr
//! 0009  jge   #257         jt 0040  jf 0010   ; openat
//! 0013  ld    [20]                            ; args[0] hi
//! 0018  ret   ERRNO(1)                        ; EPERM
//! ```
//!
//! Comments on comparisons need to know *what is in the accumulator*: 257
//! means `openat` if `A` holds the syscall number, and nothing in particular
//! if it holds an argument. Jumps only go forward, so one pass in program
//! order finds that out for every instruction: each instruction passes what
//! it leaves in `A` on to its successors, and where two paths meet with
//! different contents, the contents are unknown.

use std::fmt::Write as _;

use rustlet_sys::seccomp::{AUDIT_ARCH_I386, AUDIT_ARCH_X86_64, SockFilter, X32_SYSCALL_BIT, data, op, ret};

use super::syscalls;

/// What `A` holds before an instruction runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Acc {
    /// The 32-bit word at this offset of `seccomp_data`, unchanged.
    Field(u32),
    Unknown,
}

/// The listing of `program`, one line per instruction.
pub fn disassemble(program: &[SockFilter]) -> String {
    let acc = accumulator(program);
    let mut out = String::new();
    for (pc, insn) in program.iter().enumerate() {
        let (text, comment) = line(pc, insn, acc[pc]);
        let text = format!("{pc:04}  {text}");
        match comment {
            Some(c) => writeln!(out, "{text:<44}; {c}"),
            None => writeln!(out, "{}", text.trim_end()),
        }
        .expect("writing to a String");
    }
    out
}

/// A `SECCOMP_RET_*` value by name: `ALLOW`, `ERRNO(1)`, `KILL_PROCESS`.
pub fn action_name(value: u32) -> String {
    let data = value & ret::DATA_MASK;
    let with_data = |name: &str| if data == 0 { name.to_owned() } else { format!("{name}({data})") };
    match value & ret::ACTION_FULL_MASK {
        ret::KILL_PROCESS => "KILL_PROCESS".into(),
        ret::KILL_THREAD => "KILL_THREAD".into(),
        ret::TRAP => with_data("TRAP"),
        ret::ERRNO => format!("ERRNO({data})"),
        ret::USER_NOTIF => "USER_NOTIF".into(),
        ret::TRACE => format!("TRACE({data})"),
        ret::LOG => "LOG".into(),
        ret::ALLOW => "ALLOW".into(),
        _ => format!("#{value:#x}"),
    }
}

/// The name of a `seccomp_data` word: `nr`, `arch`, `args[2] hi`.
pub fn field_name(offset: u32) -> Option<String> {
    Some(match offset {
        data::NR => "nr".into(),
        data::ARCH => "arch".into(),
        8 => "instruction_pointer lo".into(),
        12 => "instruction_pointer hi".into(),
        16..=60 if offset.is_multiple_of(4) => {
            let i = (offset - data::ARGS) / 8;
            format!("args[{i}] {}", if offset.is_multiple_of(8) { "lo" } else { "hi" })
        }
        _ => return None,
    })
}

const LD_ABS: u16 = op::BPF_LD | op::BPF_W | op::BPF_ABS;
const RET_K: u16 = op::BPF_RET | op::BPF_K;

/// The accumulator's contents before each instruction.
fn accumulator(program: &[SockFilter]) -> Vec<Acc> {
    // `None`: no path reaches the instruction (yet).
    let mut before: Vec<Option<Acc>> = vec![None; program.len()];
    if let Some(first) = before.first_mut() {
        *first = Some(Acc::Unknown);
    }
    // `acc` flows into instruction `to`: where paths meet, they must agree.
    fn flow(before: &mut [Option<Acc>], to: usize, acc: Acc) {
        if let Some(slot) = before.get_mut(to) {
            *slot = Some(match *slot {
                None => acc,
                Some(old) if old == acc => acc,
                Some(_) => Acc::Unknown,
            });
        }
    }
    for (pc, insn) in program.iter().enumerate() {
        let acc = before[pc].unwrap_or(Acc::Unknown);
        let class = insn.code & 0x07;
        if insn.code == op::BPF_JMP | op::BPF_JA {
            flow(&mut before, pc + 1 + insn.k as usize, acc);
        } else if class == op::BPF_JMP {
            flow(&mut before, pc + 1 + insn.jt as usize, acc);
            flow(&mut before, pc + 1 + insn.jf as usize, acc);
        } else if class != op::BPF_RET {
            let after = match insn.code {
                LD_ABS => Acc::Field(insn.k),
                // Stores and X-register loads leave A alone.
                c if c == op::BPF_ST || c == op::BPF_ST | 1 || c & 0x07 == op::BPF_LDX => acc,
                c if c == op::BPF_MISC | op::BPF_TAX => acc,
                _ => Acc::Unknown,
            };
            flow(&mut before, pc + 1, after);
        }
    }
    before.into_iter().map(|a| a.unwrap_or(Acc::Unknown)).collect()
}

/// An immediate: syscall numbers and small values in decimal, masks and
/// other large values in hex.
fn imm(k: u32) -> String {
    if k < 4096 { format!("#{k}") } else { format!("#{k:#x}") }
}

/// The text of one instruction and its comment, if any.
fn line(pc: usize, insn: &SockFilter, acc: Acc) -> (String, Option<String>) {
    let k = insn.k;
    let target = |off: u32| pc + 1 + off as usize;
    let class = insn.code & 0x07;
    let src_x = insn.code & op::BPF_X != 0;
    match class {
        op::BPF_LD | op::BPF_LDX => {
            let mn = if class == op::BPF_LD { "ld" } else { "ldx" };
            match insn.code & 0xe0 {
                op::BPF_ABS if class == op::BPF_LD && insn.code & 0x18 == op::BPF_W => {
                    (format!("{mn:<5} [{k}]"), field_name(k))
                }
                0x00 => (format!("{mn:<5} {}", imm(k)), None),
                op::BPF_MEM => (format!("{mn:<5} M[{k}]"), None),
                0x80 => (format!("{mn:<5} #len"), Some("sizeof(struct seccomp_data) = 64".into())),
                _ => unknown(insn),
            }
        }
        op::BPF_ST => (format!("{:<5} M[{k}]", "st"), None),
        0x03 => (format!("{:<5} M[{k}]", "stx"), None),
        op::BPF_ALU => {
            let mn = match insn.code & 0xf0 {
                0x00 => "add",
                0x10 => "sub",
                0x20 => "mul",
                0x30 => "div",
                0x40 => "or",
                op::BPF_AND => "and",
                0x60 => "lsh",
                0x70 => "rsh",
                0x80 => return ("neg".into(), None),
                0x90 => "mod",
                0xa0 => "xor",
                _ => return unknown(insn),
            };
            (format!("{mn:<5} {}", if src_x { "x".into() } else { imm(k) }), None)
        }
        op::BPF_JMP if insn.code & 0xf0 == op::BPF_JA => (format!("{:<5} {:04}", "ja", target(k)), None),
        op::BPF_JMP => {
            let (mn, cmp) = match insn.code & 0xf0 {
                op::BPF_JEQ => ("jeq", Cmp::Eq),
                op::BPF_JGT => ("jgt", Cmp::Ordered),
                op::BPF_JGE => ("jge", Cmp::Ordered),
                op::BPF_JSET => ("jset", Cmp::Set),
                _ => return unknown(insn),
            };
            let operand = if src_x { "x".into() } else { imm(k) };
            let text =
                format!("{mn:<5} {operand:<12} jt {:04}  jf {:04}", target(insn.jt.into()), target(insn.jf.into()));
            (text, if src_x { None } else { jump_comment(acc, cmp, k) })
        }
        op::BPF_RET if insn.code == RET_K => {
            let comment = if k & ret::ACTION_FULL_MASK == ret::ERRNO { errno_name(k & ret::DATA_MASK) } else { None };
            (format!("{:<5} {}", "ret", action_name(k)), comment)
        }
        op::BPF_RET if insn.code & 0x18 == op::BPF_A => (format!("{:<5} a", "ret"), None),
        op::BPF_MISC if insn.code == op::BPF_MISC | op::BPF_TAX => ("tax".into(), None),
        op::BPF_MISC if insn.code == op::BPF_MISC | op::BPF_TXA => ("txa".into(), None),
        _ => unknown(insn),
    }
}

#[derive(Clone, Copy)]
enum Cmp {
    Eq,
    Ordered,
    Set,
}

/// What a comparison of `A` with `k` means, given what `A` holds.
fn jump_comment(acc: Acc, cmp: Cmp, k: u32) -> Option<String> {
    match (acc, cmp) {
        (Acc::Field(data::ARCH), Cmp::Eq) => match k {
            AUDIT_ARCH_X86_64 => Some("AUDIT_ARCH_X86_64".into()),
            AUDIT_ARCH_I386 => Some("AUDIT_ARCH_I386".into()),
            _ => None,
        },
        (Acc::Field(data::NR), Cmp::Set) if k == X32_SYSCALL_BIT => Some("__X32_SYSCALL_BIT".into()),
        (Acc::Field(data::NR), Cmp::Eq) if k == u32::MAX => Some("nr == -1 (skipped by a tracer)".into()),
        (Acc::Field(data::NR), Cmp::Eq | Cmp::Ordered) => syscalls::name(k).map(str::to_owned),
        _ => None,
    }
}

fn errno_name(e: u32) -> Option<String> {
    match rustlet_sys::Errno::from_raw(e as i32) {
        rustlet_sys::Errno::UnknownErrno => None,
        errno => Some(format!("{errno:?}")),
    }
}

fn unknown(insn: &SockFilter) -> (String, Option<String>) {
    (format!(".insn code={:#06x} jt={} jf={} k={:#x}", insn.code, insn.jt, insn.jf, insn.k), None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_names() {
        assert_eq!(action_name(ret::ALLOW), "ALLOW");
        assert_eq!(action_name(ret::ERRNO | 38), "ERRNO(38)");
        assert_eq!(action_name(ret::KILL_PROCESS), "KILL_PROCESS");
        assert_eq!(action_name(ret::KILL_THREAD), "KILL_THREAD");
        assert_eq!(action_name(ret::TRACE | 1), "TRACE(1)");
        assert_eq!(action_name(ret::TRAP), "TRAP");
        assert_eq!(action_name(0x1234_0000), "#0x12340000");
    }

    #[test]
    fn field_names() {
        assert_eq!(field_name(0).as_deref(), Some("nr"));
        assert_eq!(field_name(16).as_deref(), Some("args[0] lo"));
        assert_eq!(field_name(60).as_deref(), Some("args[5] hi"));
        assert_eq!(field_name(64), None);
        assert_eq!(field_name(2), None);
    }

    /// Where two paths meet with different things in `A`, the listing
    /// doesn't pretend to know: 257 after the join is not called `openat`.
    #[test]
    fn comments_follow_the_accumulator() {
        let jeq = |k, jt, jf| SockFilter::jump(op::BPF_JMP | op::BPF_JEQ | op::BPF_K, k, jt, jf);
        let program = [
            SockFilter::stmt(LD_ABS, data::NR), // 0
            jeq(257, 0, 1),                     // 1: → 2 or 3
            SockFilter::stmt(LD_ABS, 16),       // 2: A = args[0] lo, falls into 3
            jeq(257, 0, 0),                     // 3: reached with nr or args[0]
            SockFilter::stmt(RET_K, ret::ALLOW),
        ];
        let listing = disassemble(&program);
        let lines: Vec<&str> = listing.lines().collect();
        assert!(lines[1].ends_with("; openat"), "{listing}");
        assert!(!lines[3].contains(';'), "{listing}");
    }

    #[test]
    fn unknown_opcodes_are_shown_raw() {
        let listing = disassemble(&[SockFilter::stmt(0xff, 7)]);
        assert_eq!(listing, "0000  .insn code=0x00ff jt=0 jf=0 k=0x7\n");
    }
}

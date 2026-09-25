//! A classic-BPF interpreter for seccomp programs, in safe Rust.
//!
//! Loading a filter into the kernel is one-way, and a process can't very
//! well try thousands of syscall and argument combinations on itself. So
//! tests run compiled filters here, the way the kernel would:
//!
//! * [`check`] is what the kernel does when a filter is loaded
//!   (`bpf_check_classic` and `seccomp_check_filter` in the kernel sources):
//!   only instructions seccomp allows, loads inside `seccomp_data` and
//!   32-bit aligned, jumps inside the program, a `ret` at the end, no
//!   division by a constant zero, scratch memory written before it is read.
//! * [`run`] then executes the program for one syscall and returns the raw
//!   `SECCOMP_RET_*` value.
//!
//! The machine: a 32-bit accumulator `A`, an index register `X`, 16 words
//! of scratch memory `M[]`, all starting at 0; arithmetic wraps around.

use rustlet_sys::seccomp::{AUDIT_ARCH_X86_64, SockFilter, op};

/// `struct seccomp_data`: what a filter sees of a syscall.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SeccompData {
    pub nr: i32,
    pub arch: u32,
    pub instruction_pointer: u64,
    pub args: [u64; 6],
}

impl SeccompData {
    /// `sizeof(struct seccomp_data)`.
    pub const SIZE: u32 = 64;

    /// An x86_64 syscall.
    pub fn x86_64(nr: u32, args: [u64; 6]) -> SeccompData {
        SeccompData { nr: nr as i32, arch: AUDIT_ARCH_X86_64, instruction_pointer: 0, args }
    }

    /// The 32-bit word `ld [offset]` reads. The 64-bit fields are
    /// little-endian, so their low word comes first.
    pub fn word(&self, offset: u32) -> Option<u32> {
        let lo_hi = |v: u64, high: bool| if high { (v >> 32) as u32 } else { v as u32 };
        match offset {
            0 => Some(self.nr as u32),
            4 => Some(self.arch),
            8 | 12 => Some(lo_hi(self.instruction_pointer, offset == 12)),
            16..=60 if offset.is_multiple_of(4) => Some(lo_hi(self.args[(offset as usize - 16) / 8], offset % 8 == 4)),
            _ => None,
        }
    }
}

/// Opcode parts that `rustlet_sys::seccomp::op` doesn't need to define.
const BPF_IMM: u16 = 0x00;
const BPF_LEN: u16 = 0x80;
const BPF_STX: u16 = 0x03;
/// Words of scratch memory, `M[0..16]`.
const BPF_MEMWORDS: u32 = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Src {
    K(u32),
    X,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Alu {
    Add,
    Sub,
    Mul,
    Div,
    And,
    Or,
    Xor,
    Lsh,
    Rsh,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Jmp {
    Eq,
    Gt,
    Ge,
    Set,
}

/// One decoded instruction: exactly the ones `seccomp_check_filter`
/// accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Insn {
    /// `ld [k]`: A = the word at offset `k` of `seccomp_data`.
    LdAbs(u32),
    /// `ld #k` (and `ld #len`, which the kernel turns into `ld #64`).
    LdImm(u32),
    LdxImm(u32),
    LdMem(u32),
    LdxMem(u32),
    St(u32),
    Stx(u32),
    Alu(Alu, Src),
    Neg,
    Tax,
    Txa,
    Ja(u32),
    Jmp(Jmp, Src, u8, u8),
    RetK(u32),
    RetA,
}

fn decode(insn: &SockFilter) -> Option<Insn> {
    use op::*;
    let k = insn.k;
    let src = if insn.code & BPF_X != 0 { Src::X } else { Src::K(k) };
    Some(match insn.code {
        c if c == BPF_LD | BPF_W | BPF_ABS => Insn::LdAbs(k),
        c if c == BPF_LD | BPF_W | BPF_LEN => Insn::LdImm(SeccompData::SIZE),
        c if c == BPF_LDX | BPF_W | BPF_LEN => Insn::LdxImm(SeccompData::SIZE),
        c if c == BPF_LD | BPF_IMM => Insn::LdImm(k),
        c if c == BPF_LDX | BPF_IMM => Insn::LdxImm(k),
        c if c == BPF_LD | BPF_MEM => Insn::LdMem(k),
        c if c == BPF_LDX | BPF_MEM => Insn::LdxMem(k),
        c if c == BPF_ST => Insn::St(k),
        c if c == BPF_STX => Insn::Stx(k),
        c if c == BPF_MISC | BPF_TAX => Insn::Tax,
        c if c == BPF_MISC | BPF_TXA => Insn::Txa,
        c if c == BPF_ALU | 0x80 => Insn::Neg,
        c if c & 0x07 == BPF_ALU && c & !0xf8 == BPF_ALU => Insn::Alu(
            match c & 0xf0 {
                0x00 => Alu::Add,
                0x10 => Alu::Sub,
                0x20 => Alu::Mul,
                0x30 => Alu::Div,
                0x40 => Alu::Or,
                BPF_AND => Alu::And,
                0x60 => Alu::Lsh,
                0x70 => Alu::Rsh,
                0xa0 => Alu::Xor,
                // BPF_MOD (0x90) exists in classic BPF, but seccomp refuses it.
                _ => return None,
            },
            src,
        ),
        c if c == BPF_JMP | BPF_JA => Insn::Ja(k),
        c if c & 0x07 == BPF_JMP => Insn::Jmp(
            match c & !BPF_X {
                x if x == BPF_JMP | BPF_JEQ => Jmp::Eq,
                x if x == BPF_JMP | BPF_JGT => Jmp::Gt,
                x if x == BPF_JMP | BPF_JGE => Jmp::Ge,
                x if x == BPF_JMP | BPF_JSET => Jmp::Set,
                _ => return None,
            },
            src,
            insn.jt,
            insn.jf,
        ),
        c if c == BPF_RET | BPF_K => Insn::RetK(k),
        c if c == BPF_RET | BPF_A => Insn::RetA,
        _ => return None,
    })
}

/// The kernel's load-time checks. `Err` says which instruction is wrong
/// and why.
pub fn check(program: &[SockFilter]) -> Result<(), String> {
    let len = program.len();
    if len == 0 || len > op::BPF_MAXINSNS {
        return Err(format!("{len} instructions: a program has 1 to {}", op::BPF_MAXINSNS));
    }
    for (pc, raw) in program.iter().enumerate() {
        let insn = decode(raw).ok_or_else(|| format!("{pc}: opcode {:#06x} is not allowed in seccomp", raw.code))?;
        let in_program = |off: usize| pc + 1 + off < len;
        match insn {
            Insn::LdAbs(k) if k >= SeccompData::SIZE || k % 4 != 0 => {
                return Err(format!("{pc}: ld [{k}] is outside seccomp_data or not 32-bit aligned"));
            }
            Insn::LdMem(k) | Insn::LdxMem(k) | Insn::St(k) | Insn::Stx(k) if k >= BPF_MEMWORDS => {
                return Err(format!("{pc}: scratch memory M[{k}] doesn't exist"));
            }
            Insn::Alu(Alu::Div, Src::K(0)) => return Err(format!("{pc}: division by zero")),
            Insn::Alu(Alu::Lsh | Alu::Rsh, Src::K(k)) if k >= 32 => {
                return Err(format!("{pc}: shift by {k}"));
            }
            Insn::Ja(k) if !in_program(k as usize) => return Err(format!("{pc}: ja jumps past the end")),
            Insn::Jmp(_, _, jt, jf) if !in_program(jt.into()) || !in_program(jf.into()) => {
                return Err(format!("{pc}: jump past the end"));
            }
            _ => {}
        }
    }
    if !matches!(decode(&program[len - 1]), Some(Insn::RetK(_) | Insn::RetA)) {
        return Err("the last instruction must be a ret".into());
    }
    check_memory(program)
}

/// Every path must write a scratch word before reading it (the kernel's
/// `check_load_and_stores`). One pass suffices because jumps go forward:
/// `valid_at[pc]` is the set of words written on *every* path to `pc`
/// seen so far.
fn check_memory(program: &[SockFilter]) -> Result<(), String> {
    let mut valid_at = vec![u16::MAX; program.len()];
    let mut valid: u16 = 0;
    for (pc, raw) in program.iter().enumerate() {
        valid &= valid_at[pc];
        match decode(raw) {
            Some(Insn::St(k) | Insn::Stx(k)) => valid |= 1 << k,
            Some(Insn::LdMem(k) | Insn::LdxMem(k)) if valid & (1 << k) == 0 => {
                return Err(format!("{pc}: M[{k}] may be read before it is written"));
            }
            Some(Insn::Ja(k)) => {
                valid_at[pc + 1 + k as usize] &= valid;
                valid = u16::MAX;
            }
            Some(Insn::Jmp(_, _, jt, jf)) => {
                valid_at[pc + 1 + jt as usize] &= valid;
                valid_at[pc + 1 + jf as usize] &= valid;
                valid = u16::MAX;
            }
            _ => {}
        }
    }
    Ok(())
}

/// Runs `program` for one syscall: [`check`], then execute. Returns the
/// `SECCOMP_RET_*` value, action and data together.
pub fn run(program: &[SockFilter], data: &SeccompData) -> Result<u32, String> {
    check(program)?;
    let (mut a, mut x) = (0u32, 0u32);
    let mut mem = [0u32; BPF_MEMWORDS as usize];
    let mut pc = 0;
    loop {
        let raw = program.get(pc).ok_or_else(|| format!("fell off the end of the program at {pc}"))?;
        let insn = decode(raw).expect("check() accepted it");
        pc += 1;
        match insn {
            Insn::LdAbs(k) => a = data.word(k).ok_or_else(|| format!("{}: ld [{k}] out of range", pc - 1))?,
            Insn::LdImm(k) => a = k,
            Insn::LdxImm(k) => x = k,
            Insn::LdMem(k) => a = mem[k as usize],
            Insn::LdxMem(k) => x = mem[k as usize],
            Insn::St(k) => mem[k as usize] = a,
            Insn::Stx(k) => mem[k as usize] = x,
            Insn::Alu(alu, src) => {
                let v = match src {
                    Src::K(k) => k,
                    Src::X => x,
                };
                a = match alu {
                    Alu::Add => a.wrapping_add(v),
                    Alu::Sub => a.wrapping_sub(v),
                    Alu::Mul => a.wrapping_mul(v),
                    // Classic BPF's answer to a division by X == 0: the
                    // program returns 0 (which for seccomp is KILL_THREAD).
                    Alu::Div if v == 0 => return Ok(0),
                    Alu::Div => a / v,
                    Alu::And => a & v,
                    Alu::Or => a | v,
                    Alu::Xor => a ^ v,
                    // Shift counts are taken mod 32, as the kernel does.
                    Alu::Lsh => a.wrapping_shl(v),
                    Alu::Rsh => a.wrapping_shr(v),
                };
            }
            Insn::Neg => a = a.wrapping_neg(),
            Insn::Tax => x = a,
            Insn::Txa => a = x,
            Insn::Ja(k) => pc += k as usize,
            Insn::Jmp(jmp, src, jt, jf) => {
                let v = match src {
                    Src::K(k) => k,
                    Src::X => x,
                };
                let taken = match jmp {
                    Jmp::Eq => a == v,
                    Jmp::Gt => a > v,
                    Jmp::Ge => a >= v,
                    Jmp::Set => a & v != 0,
                };
                pc += usize::from(if taken { jt } else { jf });
            }
            Insn::RetK(k) => return Ok(k),
            Insn::RetA => return Ok(a),
        }
    }
}

#[cfg(test)]
mod tests {
    use rustlet_sys::seccomp::{data, ret};

    use super::*;

    const LD: u16 = op::BPF_LD | op::BPF_W | op::BPF_ABS;
    const RET: u16 = op::BPF_RET | op::BPF_K;
    const JEQ: u16 = op::BPF_JMP | op::BPF_JEQ | op::BPF_K;

    #[test]
    fn words_of_seccomp_data() {
        let d = SeccompData {
            nr: -1,
            arch: 7,
            instruction_pointer: 0x1111_2222_3333_4444,
            args: [0x5555_6666_7777_8888; 6],
        };
        assert_eq!(d.word(0), Some(u32::MAX));
        assert_eq!(d.word(4), Some(7));
        assert_eq!(d.word(8), Some(0x3333_4444));
        assert_eq!(d.word(12), Some(0x1111_2222));
        assert_eq!(d.word(16), Some(0x7777_8888));
        assert_eq!(d.word(60), Some(0x5555_6666));
        assert_eq!(d.word(64), None);
        assert_eq!(d.word(18), None);
    }

    #[test]
    fn runs_a_small_filter() {
        let prog = [
            SockFilter::stmt(LD, data::NR),
            SockFilter::jump(JEQ, 39, 0, 1),
            SockFilter::stmt(RET, ret::ALLOW),
            SockFilter::stmt(RET, ret::ERRNO | 1),
        ];
        assert_eq!(run(&prog, &SeccompData::x86_64(39, [0; 6])), Ok(ret::ALLOW));
        assert_eq!(run(&prog, &SeccompData::x86_64(40, [0; 6])), Ok(ret::ERRNO | 1));
    }

    #[test]
    fn scratch_memory_alu_and_x() {
        let prog = [
            SockFilter::stmt(LD, 16),                            // A = args[0] lo
            SockFilter::stmt(op::BPF_ALU | op::BPF_K, 10),       // A += 10 (BPF_ADD is 0)
            SockFilter::stmt(op::BPF_ST, 3),                     // M[3] = A
            SockFilter::stmt(op::BPF_LDX | op::BPF_MEM, 3),      // X = M[3]
            SockFilter::stmt(op::BPF_MISC | op::BPF_TXA, 0),     // A = X
            SockFilter::stmt(op::BPF_ALU | 0x60 | op::BPF_K, 1), // A <<= 1
            SockFilter::stmt(op::BPF_RET | op::BPF_A, 0),        // ret A
        ];
        assert_eq!(run(&prog, &SeccompData::x86_64(0, [5, 0, 0, 0, 0, 0])), Ok(30));
    }

    #[test]
    fn rejects_what_the_kernel_rejects() {
        let ret_allow = SockFilter::stmt(RET, ret::ALLOW);
        let bad: [(&str, Vec<SockFilter>); 8] = [
            ("empty", vec![]),
            ("unaligned load", vec![SockFilter::stmt(LD, 2), ret_allow]),
            ("load past the end", vec![SockFilter::stmt(LD, 64), ret_allow]),
            ("jump past the end", vec![SockFilter::jump(JEQ, 0, 1, 0), ret_allow]),
            ("ja past the end", vec![SockFilter::stmt(op::BPF_JMP | op::BPF_JA, 1), ret_allow]),
            ("no ret at the end", vec![ret_allow, SockFilter::stmt(LD, 0)]),
            ("uninitialized memory", vec![SockFilter::stmt(op::BPF_LD | op::BPF_MEM, 0), ret_allow]),
            ("BPF_MOD", vec![SockFilter::stmt(op::BPF_ALU | 0x90 | op::BPF_K, 3), ret_allow]),
        ];
        for (what, prog) in bad {
            assert!(check(&prog).is_err(), "{what} was accepted");
        }
        assert!(check(&vec![ret_allow; op::BPF_MAXINSNS + 1]).is_err());
        assert!(check(&vec![ret_allow; op::BPF_MAXINSNS]).is_ok());
    }

    /// Memory written on only one of two paths is not initialized where
    /// the paths meet.
    #[test]
    fn memory_must_be_written_on_every_path() {
        let prog = [
            SockFilter::stmt(LD, data::NR),
            SockFilter::jump(JEQ, 1, 0, 1),
            SockFilter::stmt(op::BPF_ST, 0), // only if nr == 1
            SockFilter::stmt(op::BPF_LD | op::BPF_MEM, 0),
            SockFilter::stmt(op::BPF_RET | op::BPF_A, 0),
        ];
        assert!(check(&prog).unwrap_err().contains("M[0]"));
    }

    #[test]
    fn division_by_x_zero_returns_zero() {
        let prog = [SockFilter::stmt(op::BPF_ALU | 0x30 | op::BPF_X, 0), SockFilter::stmt(RET, ret::ALLOW)];
        assert_eq!(run(&prog, &SeccompData::default()), Ok(ret::KILL_THREAD));
    }
}

//! An interpreter for device-filter programs, in safe Rust.
//!
//! The kernel can't be asked what a program *would* decide: there is no
//! `BPF_PROG_TEST_RUN` for cgroup device programs, and trying real devices
//! takes root and a cgroup per program. So the unit tests run programs
//! here:
//!
//! * [`check`] is a (stricter) subset of what the verifier checks: only the
//!   instructions the compiler uses, context loads at the three fields of
//!   `struct bpf_cgroup_dev_ctx`, `r1` never overwritten, jumps forward and
//!   inside the program, no unreachable instruction, every register written
//!   before it is read on every path, an `exit` at the end.
//! * [`run`] executes a checked program for one device check and returns
//!   `r0`, which must be 0 or 1.
//!
//! The machine: eleven 64-bit registers. `r1` points to the context, and
//! `r10` (the frame pointer) is never used. The 32-bit (`BPF_ALU`) operations
//! zero-extend their result into the full register, as the kernel does.

use rustlet_sys::bpf::BpfInsn;
use rustlet_sys::bpf::op::*;

use super::Request;
use super::compile::{CTX_ACCESS_TYPE, CTX_MAJOR, CTX_MINOR, R_CTX};

/// The verifier's limit on instructions (`BPF_COMPLEXITY_LIMIT_INSNS`).
pub const MAX_INSNS: usize = 1_000_000;

/// The frame pointer, read-only.
const R_FP: u8 = 10;

/// `struct bpf_cgroup_dev_ctx`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ctx {
    /// `(access << 16) | type`
    pub access_type: u32,
    pub major: u32,
    pub minor: u32,
}

impl From<Request> for Ctx {
    fn from(r: Request) -> Ctx {
        Ctx { access_type: (r.access.bits() << 16) | r.typ.bits(), major: r.major, minor: r.minor }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Src {
    K(i32),
    X(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Alu {
    Mov,
    And,
    Or,
    Xor,
    Rsh,
    Lsh,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Jmp {
    Eq,
    Ne,
}

/// One decoded instruction: the ones this interpreter knows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Insn {
    /// `dst = *(u32 *)(src + off)`
    Ldxw {
        dst: u8,
        src: u8,
        off: i16,
    },
    /// 32-bit ALU.
    Alu {
        op: Alu,
        dst: u8,
        src: Src,
    },
    /// 32-bit conditional jump.
    Jmp32 {
        op: Jmp,
        dst: u8,
        src: Src,
        off: i16,
    },
    Ja(i16),
    Exit,
}

fn decode(i: &BpfInsn) -> Option<Insn> {
    let src = if i.code & BPF_X != 0 { Src::X(i.src()) } else { Src::K(i.imm) };
    let class = i.code & 0x07;
    let op = i.code & 0xf0;
    Some(match class {
        BPF_LDX if i.code == BPF_LDX | BPF_W | BPF_MEM => Insn::Ldxw { dst: i.dst(), src: i.src(), off: i.off },
        BPF_ALU => Insn::Alu {
            op: match op {
                BPF_MOV => Alu::Mov,
                BPF_AND => Alu::And,
                BPF_OR => Alu::Or,
                BPF_XOR => Alu::Xor,
                BPF_RSH => Alu::Rsh,
                0x60 => Alu::Lsh,
                _ => return None,
            },
            dst: i.dst(),
            src,
        },
        BPF_JMP32 => Insn::Jmp32 {
            op: match op {
                BPF_JEQ => Jmp::Eq,
                BPF_JNE => Jmp::Ne,
                _ => return None,
            },
            dst: i.dst(),
            src,
            off: i.off,
        },
        BPF_JMP if i.code == BPF_JMP | BPF_JA => Insn::Ja(i.off),
        BPF_JMP if i.code == BPF_JMP | BPF_EXIT => Insn::Exit,
        _ => return None,
    })
}

/// Registers an instruction reads, and the one it writes.
fn regs(insn: Insn) -> (u16, Option<u8>) {
    let bit = |r: u8| 1u16 << r;
    let src_bit = |s: Src| if let Src::X(r) = s { bit(r) } else { 0 };
    match insn {
        Insn::Ldxw { dst, src, .. } => (bit(src), Some(dst)),
        Insn::Alu { op: Alu::Mov, dst, src } => (src_bit(src), Some(dst)),
        Insn::Alu { dst, src, .. } => (bit(dst) | src_bit(src), Some(dst)),
        Insn::Jmp32 { dst, src, .. } => (bit(dst) | src_bit(src), None),
        Insn::Ja(_) => (0, None),
        Insn::Exit => (bit(0), None),
    }
}

/// The load-time checks. `Err` says which instruction is wrong and why.
pub fn check(program: &[BpfInsn]) -> Result<(), String> {
    let len = program.len();
    if len == 0 || len > MAX_INSNS {
        return Err(format!("{len} instructions: a program has 1 to {MAX_INSNS}"));
    }
    let mut decoded = Vec::with_capacity(len);
    for (pc, raw) in program.iter().enumerate() {
        let insn = decode(raw).ok_or_else(|| format!("{pc}: opcode {:#04x} is not one the filter uses", raw.code))?;
        let (reads, writes) = regs(insn);
        if reads & !0x7ff != 0 {
            return Err(format!("{pc}: reads a register that doesn't exist"));
        }
        match writes {
            Some(R_CTX) => return Err(format!("{pc}: overwrites r1, the context pointer")),
            Some(r) if r >= R_FP => return Err(format!("{pc}: writes r{r}")),
            _ => {}
        }
        match insn {
            Insn::Ldxw { src, off, .. } if src != R_CTX || ![CTX_ACCESS_TYPE, CTX_MAJOR, CTX_MINOR].contains(&off) => {
                return Err(format!("{pc}: loads from r{src}{off:+}, not a field of bpf_cgroup_dev_ctx"));
            }
            Insn::Alu { op: Alu::Rsh | Alu::Lsh, src: Src::K(k), .. } if !(0..32).contains(&k) => {
                return Err(format!("{pc}: shift by {k}"));
            }
            Insn::Jmp32 { off, .. } | Insn::Ja(off) if off < 0 || pc + 1 + off as usize >= len => {
                return Err(format!("{pc}: jump to {} is backwards or past the end", pc as i64 + 1 + i64::from(off)));
            }
            _ => {}
        }
        decoded.push(insn);
    }
    if decoded[len - 1] != Insn::Exit {
        return Err("the last instruction must be an exit".into());
    }
    check_paths(&decoded)
}

/// Every instruction is reachable, and every register it reads was written
/// on every path to it (`r1` and `r10` are set on entry). One pass suffices
/// because jumps go forward: `known[pc]` is the set of registers written on
/// every path to `pc` seen so far (`None`: no path yet).
fn check_paths(program: &[Insn]) -> Result<(), String> {
    let mut known: Vec<Option<u16>> = vec![None; program.len()];
    known[0] = Some(1 << R_CTX | 1 << R_FP);
    for (pc, &insn) in program.iter().enumerate() {
        let here = known[pc].ok_or_else(|| format!("{pc}: unreachable instruction"))?;
        let (reads, writes) = regs(insn);
        if reads & !here != 0 {
            let r = (reads & !here).trailing_zeros();
            return Err(format!("{pc}: r{r} may be read before it is written"));
        }
        let after = here | writes.map_or(0, |r| 1 << r);
        let mut reach = |to: usize| known[to] = Some(known[to].map_or(after, |k| k & after));
        match insn {
            Insn::Exit => {}
            Insn::Ja(off) => reach(pc + 1 + off as usize),
            Insn::Jmp32 { off, .. } => {
                reach(pc + 1);
                reach(pc + 1 + off as usize);
            }
            _ => reach(pc + 1),
        }
    }
    Ok(())
}

/// Runs `program` for one device check: [`check`], then execute. Returns
/// `r0`: 1 allows, 0 denies.
pub fn run(program: &[BpfInsn], ctx: &Ctx) -> Result<u32, String> {
    check(program)?;
    let program: Vec<Insn> = program.iter().map(|i| decode(i).expect("check() accepted it")).collect();
    let mut r = [0u64; 11];
    let lo = |v: u64| v as u32;
    let mut pc = 0;
    loop {
        let insn = program[pc];
        pc += 1;
        match insn {
            Insn::Ldxw { dst, off, .. } => {
                r[dst as usize] = u64::from(match off {
                    CTX_ACCESS_TYPE => ctx.access_type,
                    CTX_MAJOR => ctx.major,
                    _ => ctx.minor,
                });
            }
            Insn::Alu { op, dst, src } => {
                let v = match src {
                    Src::K(k) => k as u32,
                    Src::X(s) => lo(r[s as usize]),
                };
                let d = lo(r[dst as usize]);
                r[dst as usize] = u64::from(match op {
                    Alu::Mov => v,
                    Alu::And => d & v,
                    Alu::Or => d | v,
                    Alu::Xor => d ^ v,
                    Alu::Rsh => d.wrapping_shr(v),
                    Alu::Lsh => d.wrapping_shl(v),
                });
            }
            Insn::Jmp32 { op, dst, src, off } => {
                let v = match src {
                    Src::K(k) => k as u32,
                    Src::X(s) => lo(r[s as usize]),
                };
                let d = lo(r[dst as usize]);
                if (op == Jmp::Eq) == (d == v) {
                    pc += off as usize;
                }
            }
            Insn::Ja(off) => pc += off as usize,
            Insn::Exit => {
                return match r[0] {
                    v @ (0 | 1) => Ok(v as u32),
                    v => Err(format!("{}: returns {v}; a device program must return 0 or 1", pc - 1)),
                };
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::compile::{EXIT, alu32_k, alu32_x, jne32_k, ldxw};
    use super::*;

    const R0_IS_1: BpfInsn = alu32_k(BPF_MOV, 0, 1);

    #[test]
    fn runs_a_small_program() {
        // Allow only major 1.
        let prog = [ldxw(2, 1, CTX_MAJOR), alu32_k(BPF_MOV, 0, 0), jne32_k(2, 1, 1), R0_IS_1, EXIT];
        let ctx = |major| Ctx { access_type: 0, major, minor: 0 };
        assert_eq!(run(&prog, &ctx(1)), Ok(1));
        assert_eq!(run(&prog, &ctx(2)), Ok(0));
    }

    #[test]
    fn alu_is_32_bit_and_zero_extends() {
        // w2 = 0xffffffff; w2 >>= 28 → 0xf, not a sign-extended 64-bit value.
        let prog = [
            alu32_k(BPF_MOV, 2, -1),
            alu32_k(BPF_RSH, 2, 28),
            alu32_k(BPF_MOV, 0, 0),
            jne32_k(2, 0xf, 1),
            R0_IS_1,
            EXIT,
        ];
        assert_eq!(run(&prog, &Ctx { access_type: 0, major: 0, minor: 0 }), Ok(1));
    }

    #[test]
    fn rejects_what_the_verifier_rejects() {
        let bad: [(&str, Vec<BpfInsn>); 9] = [
            ("empty", vec![]),
            ("no exit at the end", vec![R0_IS_1]),
            ("r0 unset", vec![EXIT]),
            ("read before write", vec![alu32_x(BPF_MOV, 0, 7), EXIT]),
            ("ctx overwritten", vec![alu32_k(BPF_MOV, 1, 0), R0_IS_1, EXIT]),
            ("load past the ctx", vec![ldxw(2, 1, 12), R0_IS_1, EXIT]),
            ("jump past the end", vec![R0_IS_1, jne32_k(0, 0, 1), EXIT]),
            ("unreachable", vec![R0_IS_1, BpfInsn::new(BPF_JMP | BPF_JA, 0, 0, 1, 0), R0_IS_1, EXIT]),
            ("set on one path only", vec![ldxw(2, 1, 0), jne32_k(2, 0, 1), R0_IS_1, EXIT]),
        ];
        for (what, prog) in bad {
            assert!(check(&prog).is_err(), "{what} was accepted");
        }
        assert!(check(&[R0_IS_1, EXIT]).is_ok());
    }

    #[test]
    fn return_value_must_be_0_or_1() {
        let prog = [alu32_k(BPF_MOV, 0, 2), EXIT];
        assert!(run(&prog, &Ctx { access_type: 0, major: 0, minor: 0 }).unwrap_err().contains("returns 2"));
    }
}

//! Rules → eBPF. The program's shape is in the [module docs](super).
//!
//! Registers: `r1` the context (never written), `w2` the device type,
//! `w3` the requested access bits, `w4` the major, `w5` the minor, `w6` the
//! allowed bits, `w7` scratch for comparisons, `w0` the verdict.
//!
//! **Why compare through `w7`.** After `if w4 != 136 goto next` falls
//! through, the verifier knows `w4` is exactly 136, and a path that knows
//! that can't be merged with one that doesn't. So every rule's fall-through
//! path carried its own state through the rest of the program, and the
//! verifier's work grew with the square of the rule count: 1000 rules took
//! 895,269 of its 1,000,000 instructions (`dv_verifier_cost_stays_linear`).
//! `w7 = w4; w7 ^= 136; if w7 != 0` tests the same thing, but only teaches
//! the verifier something about `w7`, which is dead at the next rule, so the
//! paths merge there again.

use rustlet_sys::bpf::BpfInsn;
use rustlet_sys::bpf::op::*;

use super::{Access, Rule};

pub(super) const R_CTX: u8 = 1;
pub(super) const R_TYPE: u8 = 2;
pub(super) const R_ACCESS: u8 = 3;
pub(super) const R_MAJOR: u8 = 4;
pub(super) const R_MINOR: u8 = 5;
pub(super) const R_ALLOWED: u8 = 6;
pub(super) const R_SCRATCH: u8 = 7;

/// Offsets in `struct bpf_cgroup_dev_ctx`.
pub(super) const CTX_ACCESS_TYPE: i16 = 0;
pub(super) const CTX_MAJOR: i16 = 4;
pub(super) const CTX_MINOR: i16 = 8;

/// `dst = *(u32 *)(src + off)`
pub(super) const fn ldxw(dst: u8, src: u8, off: i16) -> BpfInsn {
    BpfInsn::new(BPF_LDX | BPF_W | BPF_MEM, dst, src, off, 0)
}

/// 32-bit `dst op= imm`.
pub(super) const fn alu32_k(op: u8, dst: u8, imm: i32) -> BpfInsn {
    BpfInsn::new(BPF_ALU | op | BPF_K, dst, 0, 0, imm)
}

/// 32-bit `dst op= src`.
pub(super) const fn alu32_x(op: u8, dst: u8, src: u8) -> BpfInsn {
    BpfInsn::new(BPF_ALU | op | BPF_X, dst, src, 0, 0)
}

/// `if wdst != imm goto pc+off` (a 32-bit comparison).
pub(super) const fn jne32_k(dst: u8, imm: u32, off: i16) -> BpfInsn {
    BpfInsn::new(BPF_JMP32 | BPF_JNE | BPF_K, dst, 0, off, imm as i32)
}

/// `if wdst != wsrc goto pc+off`.
pub(super) const fn jne32_x(dst: u8, src: u8, off: i16) -> BpfInsn {
    BpfInsn::new(BPF_JMP32 | BPF_JNE | BPF_X, dst, src, off, 0)
}

pub(super) const EXIT: BpfInsn = BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0);

/// The program for `rules` (already optimised), with `w6` starting at
/// `initial`.
pub(super) fn compile(initial: Access, rules: &[Rule]) -> Vec<BpfInsn> {
    let mut p = vec![
        ldxw(R_TYPE, R_CTX, CTX_ACCESS_TYPE),
        alu32_x(BPF_MOV, R_ACCESS, R_TYPE),
        alu32_k(BPF_RSH, R_ACCESS, 16),
        alu32_k(BPF_AND, R_TYPE, 0xffff),
        ldxw(R_MAJOR, R_CTX, CTX_MAJOR),
        ldxw(R_MINOR, R_CTX, CTX_MINOR),
        alu32_k(BPF_MOV, R_ALLOWED, initial.bits() as i32),
    ];
    for rule in rules {
        let checks: Vec<(u8, u32)> =
            [rule.typ.map(|t| (R_TYPE, t.bits())), rule.major.map(|m| (R_MAJOR, m)), rule.minor.map(|m| (R_MINOR, m))]
                .into_iter()
                .flatten()
                .collect();
        // Each check is three instructions and jumps past the rest of the
        // block: the other checks and the one ALU instruction.
        for (i, &(reg, value)) in checks.iter().enumerate() {
            let rest = 3 * (checks.len() - 1 - i) + 1;
            p.extend([
                alu32_x(BPF_MOV, R_SCRATCH, reg),
                alu32_k(BPF_XOR, R_SCRATCH, value as i32),
                jne32_k(R_SCRATCH, 0, rest as i16),
            ]);
        }
        p.push(if rule.allow {
            alu32_k(BPF_OR, R_ALLOWED, rule.access.bits() as i32)
        } else {
            alu32_k(BPF_AND, R_ALLOWED, (!rule.access.bits() & Access::ALL.bits()) as i32)
        });
    }
    p.extend([
        alu32_x(BPF_AND, R_ALLOWED, R_ACCESS),
        alu32_k(BPF_MOV, 0, 0),
        jne32_x(R_ALLOWED, R_ACCESS, 1),
        alu32_k(BPF_MOV, 0, 1),
        EXIT,
    ]);
    p
}

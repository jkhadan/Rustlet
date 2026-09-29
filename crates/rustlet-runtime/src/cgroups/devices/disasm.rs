//! A disassembler for device-filter programs. The instruction text is the
//! kernel's own format (`kernel/bpf/disasm.c`), which is also what
//! `bpftool prog dump xlated` prints, so the two listings can be compared
//! line by line. A comment then says what the instruction means, following
//! the register conventions of the [compiler](super::compile):
//!
//! ```text
//!    7: (bc) w7 = w2                    ; type
//!    8: (a4) w7 ^= 2
//!    9: (56) if w7 != 0x0 goto pc+7     ; not char
//!   16: (44) w6 |= 7                    ; allow rwm
//! ```

use std::fmt::Write as _;

use rustlet_sys::bpf::BpfInsn;
use rustlet_sys::bpf::op::*;

use super::compile::{CTX_ACCESS_TYPE, CTX_MAJOR, CTX_MINOR, R_ACCESS, R_ALLOWED, R_MAJOR, R_MINOR, R_SCRATCH, R_TYPE};
use super::{Access, DevType};

/// The listing of `program`, one line per instruction.
pub fn disassemble(program: &[BpfInsn]) -> String {
    let mut out = String::new();
    // What the scratch register holds: a copy of this register, XORed with
    // this value. Straight-line code, so the previous instructions tell.
    let mut scratch: (Option<u8>, u32) = (None, 0);
    for (pc, insn) in program.iter().enumerate() {
        let text = format!("{pc:4}: ({:02x}) {}", insn.code, text(insn));
        match comment(insn, &mut scratch) {
            Some(c) => writeln!(out, "{text:<38}; {c}"),
            None => writeln!(out, "{text}"),
        }
        .expect("writing to a String");
    }
    out
}

fn alu_op(op: u8) -> Option<&'static str> {
    Some(match op {
        BPF_MOV => "=",
        BPF_AND => "&=",
        BPF_OR => "|=",
        BPF_XOR => "^=",
        BPF_RSH => ">>=",
        0x60 => "<<=",
        _ => return None,
    })
}

fn jmp_op(op: u8) -> Option<&'static str> {
    Some(match op {
        BPF_JEQ => "==",
        BPF_JNE => "!=",
        _ => return None,
    })
}

fn text(i: &BpfInsn) -> String {
    let (class, op, x) = (i.code & 0x07, i.code & 0xf0, i.code & BPF_X != 0);
    let (d, s) = (i.dst(), i.src());
    match class {
        BPF_LDX if i.code == BPF_LDX | BPF_W | BPF_MEM => format!("r{d} = *(u32 *)(r{s} {:+})", i.off),
        BPF_ALU => match alu_op(op) {
            Some(o) if x => format!("w{d} {o} w{s}"),
            Some(o) => format!("w{d} {o} {}", i.imm),
            None => unknown(i),
        },
        BPF_JMP32 => match jmp_op(op) {
            Some(o) if x => format!("if w{d} {o} w{s} goto pc{:+}", i.off),
            Some(o) => format!("if w{d} {o} {:#x} goto pc{:+}", i.imm as u32, i.off),
            None => unknown(i),
        },
        BPF_JMP if i.code == BPF_JMP | BPF_JA => format!("goto pc{:+}", i.off),
        BPF_JMP if i.code == BPF_JMP | BPF_EXIT => "exit".to_owned(),
        _ => unknown(i),
    }
}

fn unknown(i: &BpfInsn) -> String {
    format!("(unknown) dst r{} src r{} off {} imm {}", i.dst(), i.src(), i.off, i.imm)
}

/// What the instruction means in a program from our compiler.
fn comment(i: &BpfInsn, scratch: &mut (Option<u8>, u32)) -> Option<String> {
    let (op, x, d, k) = (i.code & 0xf0, i.code & BPF_X != 0, i.dst(), i.imm as u32);
    let access = |bits: u32| Access::from_bits(bits).to_string();
    Some(match (i.code & 0x07, op, x) {
        (BPF_ALU, BPF_MOV, true) if d == R_SCRATCH => {
            *scratch = (Some(i.src()), 0);
            match i.src() {
                R_TYPE => "type".into(),
                R_MAJOR => "major".into(),
                R_MINOR => "minor".into(),
                _ => return None,
            }
        }
        (BPF_ALU, BPF_XOR, false) if d == R_SCRATCH => {
            scratch.1 ^= k;
            return None;
        }
        (BPF_JMP32, BPF_JNE, false) if d == R_SCRATCH && k == 0 => match *scratch {
            (Some(R_TYPE), t) if t == DevType::Block.bits() => "not block".into(),
            (Some(R_TYPE), t) if t == DevType::Char.bits() => "not char".into(),
            (Some(R_MAJOR), m) => format!("major != {m}"),
            (Some(R_MINOR), m) => format!("minor != {m}"),
            _ => return None,
        },
        (BPF_LDX, _, _) => match i.off {
            CTX_ACCESS_TYPE => "access_type".into(),
            CTX_MAJOR => format!("w{d} = major"),
            CTX_MINOR => format!("w{d} = minor"),
            _ => return None,
        },
        (BPF_ALU, BPF_RSH, false) if d == R_ACCESS && k == 16 => format!("w{d} = access"),
        (BPF_ALU, BPF_AND, false) if d == R_TYPE && k == 0xffff => format!("w{d} = type"),
        (BPF_ALU, BPF_MOV, false) if d == R_ALLOWED => format!("allowed: {}", access(k)),
        (BPF_ALU, BPF_OR, false) if d == R_ALLOWED => format!("allow {}", access(k)),
        (BPF_ALU, BPF_AND, false) if d == R_ALLOWED => format!("deny {}", access(!k)),
        (BPF_ALU, BPF_AND, true) if d == R_ALLOWED && i.src() == R_ACCESS => {
            "the requested bits that are allowed".into()
        }
        (BPF_ALU, BPF_MOV, false) if d == 0 => (if k == 1 { "allow" } else { "deny" }).into(),
        (BPF_JMP32, BPF_JNE, false) => match d {
            R_TYPE if k == DevType::Block.bits() => "not block".into(),
            R_TYPE if k == DevType::Char.bits() => "not char".into(),
            R_MAJOR => format!("major != {k}"),
            R_MINOR => format!("minor != {k}"),
            _ => return None,
        },
        (BPF_JMP32, BPF_JNE, true) if d == R_ALLOWED && i.src() == R_ACCESS => "a requested bit isn't allowed".into(),
        _ => return None,
    })
}

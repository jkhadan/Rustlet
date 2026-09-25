//! A tiny assembler for classic BPF: symbolic labels in, jump offsets out.
//!
//! A classic-BPF conditional jump doesn't name its targets; it says "if
//! true skip `jt` instructions, else skip `jf`", and both offsets are a
//! `u8`. Jumps can only go *forward* (that is how the kernel knows every
//! filter terminates) and at most 255 instructions far. An unconditional
//! `ja` has a 32-bit offset `k`, so it can reach anywhere.
//!
//! The compiler therefore doesn't count instructions. It writes a
//! [`Program`] of instructions that jump to [`Label`]s, and
//! [`Program::assemble`] turns labels into offsets.
//!
//! ## Why backwards
//!
//! The distance from a jump to its target depends only on what lies
//! *between* them, i.e. after the jump. So the assembler walks the program
//! from the last instruction to the first: when it reaches a jump,
//! everything after it is final and the distance is known exactly. If a
//! target is more than 255 instructions away, it inserts a **trampoline**
//! directly behind the jump (emitting backwards, that means: first) and
//! lets the conditional jump land there instead:
//!
//! ```text
//!   jeq #42, far, next            jeq #42  jt +0  jf +1
//!   next: ...            ==>      ja  far                 <- trampoline
//!   ... 300 instructions ...      next: ...
//!   far: ld [16]                  ...
//! ```
//!
//! If the far target is a `ret`, the trampoline is simply a *copy* of that
//! `ret`: same size, and one instruction less to execute. Later jumps to the
//! same label (earlier in the program) reuse the nearest trampoline while it
//! is within reach, so a busy target like `ret ALLOW` needs only a few.

use rustlet_sys::seccomp::{SockFilter, op};

/// A jump target. Created by [`Program::label`], positioned by
/// [`Program::place`]: it then refers to the next instruction emitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Label(usize);

/// Where a conditional jump goes: a label, or simply the next instruction
/// (offset 0), which saves inventing a label for every "fall through".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum To {
    Next,
    L(Label),
}

impl From<Label> for To {
    fn from(l: Label) -> To {
        To::L(l)
    }
}

#[derive(Debug, Clone, Copy)]
enum Item {
    /// Marks the position of the next instruction.
    Label(Label),
    /// An instruction without targets: `ld`, `and`, `ret`.
    Stmt(SockFilter),
    /// A conditional jump, `BPF_JMP | BPF_JEQ/JGT/JGE/JSET | BPF_K`.
    Jump { code: u16, k: u32, jt: To, jf: To },
    /// `ja`.
    Ja(Label),
}

/// An assembled program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assembled {
    pub insns: Vec<SockFilter>,
    /// How many trampolines (`ja` or copied `ret`) had to be inserted.
    pub trampolines: usize,
}

/// A program under construction, in program order.
#[derive(Debug, Default)]
pub struct Program {
    items: Vec<Item>,
    labels: usize,
}

impl Program {
    /// A fresh, not yet placed label.
    pub fn label(&mut self) -> Label {
        self.labels += 1;
        Label(self.labels - 1)
    }

    /// Positions `l` at the next instruction.
    pub fn place(&mut self, l: Label) {
        self.items.push(Item::Label(l));
    }

    /// `ld [offset]`: loads the 32-bit word at `offset` of `struct seccomp_data`.
    pub fn ld(&mut self, offset: u32) {
        self.stmt(op::BPF_LD | op::BPF_W | op::BPF_ABS, offset);
    }

    /// `and #mask`.
    pub fn and(&mut self, mask: u32) {
        self.stmt(op::BPF_ALU | op::BPF_AND | op::BPF_K, mask);
    }

    /// `ret #action`: the verdict, a `SECCOMP_RET_*` value.
    pub fn ret(&mut self, action: u32) {
        self.stmt(op::BPF_RET | op::BPF_K, action);
    }

    fn stmt(&mut self, code: u16, k: u32) {
        self.items.push(Item::Stmt(SockFilter::stmt(code, k)));
    }

    /// `jeq #k`: `A == k`.
    pub fn jeq(&mut self, k: u32, jt: impl Into<To>, jf: impl Into<To>) {
        self.jump(op::BPF_JEQ, k, jt.into(), jf.into());
    }

    /// `jgt #k`: `A > k`, unsigned.
    pub fn jgt(&mut self, k: u32, jt: impl Into<To>, jf: impl Into<To>) {
        self.jump(op::BPF_JGT, k, jt.into(), jf.into());
    }

    /// `jge #k`: `A >= k`, unsigned.
    pub fn jge(&mut self, k: u32, jt: impl Into<To>, jf: impl Into<To>) {
        self.jump(op::BPF_JGE, k, jt.into(), jf.into());
    }

    /// `jset #k`: `A & k != 0`.
    pub fn jset(&mut self, k: u32, jt: impl Into<To>, jf: impl Into<To>) {
        self.jump(op::BPF_JSET, k, jt.into(), jf.into());
    }

    fn jump(&mut self, cmp: u16, k: u32, jt: To, jf: To) {
        self.items.push(Item::Jump { code: op::BPF_JMP | cmp | op::BPF_K, k, jt, jf });
    }

    /// `ja label`.
    pub fn ja(&mut self, l: Label) {
        self.items.push(Item::Ja(l));
    }

    /// Resolves labels into offsets, inserting trampolines for targets out of
    /// `u8` reach. Doesn't check the kernel's size limit; the caller does.
    ///
    /// # Panics
    ///
    /// If a label is jumped to but placed *before* the jump (or never): BPF
    /// can't jump backwards, so that is a bug in the code generator.
    pub fn assemble(&self) -> Assembled {
        Backwards::default().run(&self.items, self.labels)
    }
}

/// State of the backward pass. Positions are *reverse* indices: `rev[0]`
/// is the program's last instruction. A jump emitted at reverse index `n`
/// to the instruction at reverse index `t` has offset `n - t - 1`,
/// whatever the final length of the program.
#[derive(Default)]
struct Backwards {
    rev: Vec<SockFilter>,
    /// Per label: the reverse index of the instruction it marks.
    at: Vec<Option<usize>>,
    /// Per label: the nearest instruction that *acts like* the label, i.e.
    /// the label's own instruction or the latest trampoline to it.
    nearest: Vec<Option<usize>>,
    trampolines: usize,
}

const MAX_OFFSET: usize = u8::MAX as usize;

impl Backwards {
    fn run(mut self, items: &[Item], labels: usize) -> Assembled {
        self.at = vec![None; labels];
        self.nearest = vec![None; labels];
        for item in items.iter().rev() {
            match *item {
                Item::Label(l) => {
                    let pos = self.rev.len().checked_sub(1).expect("a label placed after the last instruction");
                    self.at[l.0] = Some(pos);
                    self.nearest[l.0] = Some(pos);
                }
                Item::Stmt(s) => self.rev.push(s),
                Item::Ja(l) => {
                    let t = self.target(l);
                    let insn = self.far_jump_to(t);
                    self.rev.push(insn);
                }
                Item::Jump { code, k, jt, jf } => self.jump(code, k, jt, jf),
            }
        }
        self.rev.reverse();
        Assembled { insns: self.rev, trampolines: self.trampolines }
    }

    /// Emits a conditional jump, first emitting trampolines for targets that
    /// are out of reach. Each trampoline pushes the jump one further away
    /// from the *other* target, hence the loop.
    fn jump(&mut self, code: u16, k: u32, jt: To, jf: To) {
        let next = self.rev.len().checked_sub(1).expect("a jump as the last instruction");
        loop {
            let n = self.rev.len();
            let t = self.resolve(jt, next);
            let f = self.resolve(jf, next);
            if n - t - 1 > MAX_OFFSET {
                self.trampoline(jt);
            } else if n - f - 1 > MAX_OFFSET {
                self.trampoline(jf);
            } else {
                self.rev.push(SockFilter::jump(code, k, (n - t - 1) as u8, (n - f - 1) as u8));
                return;
            }
        }
    }

    fn resolve(&self, to: To, next: usize) -> usize {
        match to {
            To::Next => next,
            To::L(l) => self.nearest[l.0].unwrap_or_else(|| self.undefined(l)),
        }
    }

    fn target(&self, l: Label) -> usize {
        self.at[l.0].unwrap_or_else(|| self.undefined(l))
    }

    fn undefined(&self, l: Label) -> ! {
        panic!("seccomp assembler: label {} is used before (or without) being placed", l.0)
    }

    /// Emits a trampoline to `to` (always a label: `Next` is never far).
    fn trampoline(&mut self, to: To) {
        let To::L(l) = to else { unreachable!("the next instruction is never out of reach") };
        let insn = self.far_jump_to(self.target(l));
        self.nearest[l.0] = Some(self.rev.len());
        self.rev.push(insn);
        self.trampolines += 1;
    }

    /// An instruction, to be emitted next, that continues at reverse index
    /// `t`: a copy of it if it is a `ret`, else a `ja` (32-bit offset).
    fn far_jump_to(&self, t: usize) -> SockFilter {
        let target = self.rev[t];
        if target.code == op::BPF_RET | op::BPF_K {
            target
        } else {
            let offset = self.rev.len() - t - 1;
            SockFilter::stmt(op::BPF_JMP | op::BPF_JA, offset as u32)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const JEQ: u16 = op::BPF_JMP | op::BPF_JEQ | op::BPF_K;
    const RET: u16 = op::BPF_RET | op::BPF_K;
    const JA: u16 = op::BPF_JMP | op::BPF_JA;

    #[test]
    fn near_jumps_get_plain_offsets() {
        let mut p = Program::default();
        let (yes, no) = (p.label(), p.label());
        p.ld(0);
        p.jeq(1, yes, To::Next);
        p.jeq(2, yes, no);
        p.place(no);
        p.ret(0);
        p.place(yes);
        p.ret(1);
        let a = p.assemble();
        assert_eq!(a.trampolines, 0);
        assert_eq!(a.insns[1], SockFilter::jump(JEQ, 1, 2, 0));
        assert_eq!(a.insns[2], SockFilter::jump(JEQ, 2, 1, 0));
    }

    /// 300 filler instructions between a jump and its targets: one target
    /// is a `ret` (copied), the other a `ld` (reached through `ja`).
    #[test]
    fn far_targets_get_trampolines() {
        let mut p = Program::default();
        let (to_ret, to_ld) = (p.label(), p.label());
        p.ld(0);
        p.jeq(7, to_ret, to_ld);
        for _ in 0..300 {
            p.ld(4);
        }
        p.place(to_ld);
        p.ld(16);
        p.place(to_ret);
        p.ret(0x7fff_0000);
        let a = p.assemble();
        assert_eq!(a.trampolines, 2);
        // Emitting backwards, the jt trampoline (a copy of the ret) comes
        // first, then the jf one (a ja), then the jeq: in program order,
        // jeq, the ja, the copy.
        assert_eq!(a.insns[1], SockFilter::jump(JEQ, 7, 1, 0));
        assert_eq!(a.insns[2].code, JA);
        assert_eq!(a.insns[3], SockFilter::stmt(RET, 0x7fff_0000));
        let ja_target = 2 + 1 + a.insns[2].k as usize;
        assert_eq!(a.insns[ja_target], SockFilter::stmt(op::BPF_LD | op::BPF_W | op::BPF_ABS, 16));
    }

    /// Many far jumps to one label share trampolines instead of each
    /// getting its own.
    #[test]
    fn trampolines_are_shared() {
        let mut p = Program::default();
        let far = p.label();
        p.ld(0);
        for i in 0..1000 {
            p.jeq(i, far, To::Next);
        }
        p.ret(0);
        for _ in 0..300 {
            p.ld(4);
        }
        p.place(far);
        p.ld(8);
        p.ret(1);
        let a = p.assemble();
        assert!(a.trampolines <= 6, "{} trampolines", a.trampolines);
        for (i, insn) in a.insns.iter().enumerate() {
            if insn.code == JEQ {
                let t = i + 1 + insn.jt as usize;
                assert!(a.insns[t].code == JA || a.insns[t].k == 8, "jeq at {i} lands on {:?}", a.insns[t]);
            }
        }
    }

    #[test]
    #[should_panic(expected = "used before")]
    fn backward_jumps_are_a_bug() {
        let mut p = Program::default();
        let back = p.label();
        p.place(back);
        p.ld(0);
        p.jeq(0, back, To::Next);
        p.ret(0);
        p.assemble();
    }
}

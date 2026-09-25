//! Classic BPF instruction encoding and the `seccomp(2)` syscall.
//!
//! The *compiler* (OCI profile → BPF) lives in `rustlet_runtime::seccomp`,
//! which is safe code; this module only defines the kernel ABI types and loads
//! a finished program.

use std::os::fd::OwnedFd;

use crate::{Result, check, owned_fd};

/// One classic-BPF instruction (`struct sock_filter`).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SockFilter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

impl SockFilter {
    pub const fn stmt(code: u16, k: u32) -> Self {
        SockFilter { code, jt: 0, jf: 0, k }
    }
    pub const fn jump(code: u16, k: u32, jt: u8, jf: u8) -> Self {
        SockFilter { code, jt, jf, k }
    }
}

/// Opcode building blocks from `<linux/filter.h>` / `<linux/bpf_common.h>`.
pub mod op {
    pub const BPF_LD: u16 = 0x00;
    pub const BPF_LDX: u16 = 0x01;
    pub const BPF_ST: u16 = 0x02;
    pub const BPF_ALU: u16 = 0x04;
    pub const BPF_JMP: u16 = 0x05;
    pub const BPF_RET: u16 = 0x06;
    pub const BPF_MISC: u16 = 0x07;

    pub const BPF_W: u16 = 0x00;
    pub const BPF_ABS: u16 = 0x20;
    pub const BPF_MEM: u16 = 0x60;

    pub const BPF_AND: u16 = 0x50;

    pub const BPF_JA: u16 = 0x00;
    pub const BPF_JEQ: u16 = 0x10;
    pub const BPF_JGT: u16 = 0x20;
    pub const BPF_JGE: u16 = 0x30;
    pub const BPF_JSET: u16 = 0x40;

    pub const BPF_K: u16 = 0x00;
    pub const BPF_X: u16 = 0x08;
    pub const BPF_A: u16 = 0x10;

    pub const BPF_TAX: u16 = 0x00;
    pub const BPF_TXA: u16 = 0x80;

    /// Maximum instructions per classic BPF program (`BPF_MAXINSNS`).
    pub const BPF_MAXINSNS: usize = 4096;
}

/// `SECCOMP_RET_*` actions (upper 16 bits) and the data mask.
pub mod ret {
    pub const KILL_PROCESS: u32 = 0x8000_0000;
    pub const KILL_THREAD: u32 = 0x0000_0000;
    pub const TRAP: u32 = 0x0003_0000;
    pub const ERRNO: u32 = 0x0005_0000;
    pub const USER_NOTIF: u32 = 0x7fc0_0000;
    pub const TRACE: u32 = 0x7ff0_0000;
    pub const LOG: u32 = 0x7ffc_0000;
    pub const ALLOW: u32 = 0x7fff_0000;
    pub const DATA_MASK: u32 = 0x0000_ffff;
    pub const ACTION_FULL_MASK: u32 = 0xffff_0000;
}

/// Layout of `struct seccomp_data` (what the filter reads with `ld [k]`).
pub mod data {
    /// `int nr` — the syscall number.
    pub const NR: u32 = 0;
    /// `__u32 arch` — an `AUDIT_ARCH_*` value.
    pub const ARCH: u32 = 4;
    /// `__u64 instruction_pointer`.
    pub const IP: u32 = 8;
    /// `__u64 args[6]` start here; arg *i* is at `ARGS + 8*i`.
    pub const ARGS: u32 = 16;
}

/// `AUDIT_ARCH_X86_64` (`EM_X86_64 | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE`).
pub const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
/// `AUDIT_ARCH_I386`.
pub const AUDIT_ARCH_I386: u32 = 0x4000_0003;
/// Bit 30 marks the x32 ABI on x86_64 (`__X32_SYSCALL_BIT`).
pub const X32_SYSCALL_BIT: u32 = 0x4000_0000;

/// `SECCOMP_FILTER_FLAG_*`.
pub mod flags {
    pub const TSYNC: u32 = 1 << 0;
    pub const LOG: u32 = 1 << 1;
    pub const SPEC_ALLOW: u32 = 1 << 2;
    pub const NEW_LISTENER: u32 = 1 << 3;
    pub const TSYNC_ESRCH: u32 = 1 << 4;
    pub const WAIT_KILLABLE_RECV: u32 = 1 << 5;
}

const SECCOMP_SET_MODE_FILTER: libc::c_uint = 1;
const SECCOMP_GET_ACTION_AVAIL: libc::c_uint = 2;

#[repr(C)]
struct SockFprog {
    len: libc::c_ushort,
    filter: *const SockFilter,
}

/// Installs a seccomp filter for the calling thread (and its future children).
///
/// Requires either `no_new_privs` or `CAP_SYS_ADMIN` in the caller's user
/// namespace. Filters stack: once installed, a filter can never be removed.
/// If `flags` contains [`flags::NEW_LISTENER`] the kernel returns a
/// user-notification fd, which is handed back to the caller.
pub fn set_mode_filter(program: &[SockFilter], flags: u32) -> Result<Option<OwnedFd>> {
    if program.is_empty() || program.len() > op::BPF_MAXINSNS {
        return Err(crate::Errno::EINVAL);
    }
    let prog = SockFprog { len: program.len() as libc::c_ushort, filter: program.as_ptr() };
    // SAFETY: `prog` points to `program`, which is valid for `len`
    // instructions and outlives the call; the kernel copies the program.
    let ret = unsafe { libc::syscall(libc::SYS_seccomp, SECCOMP_SET_MODE_FILTER, flags, &raw const prog) };
    let v = check(ret)?;
    Ok((flags & self::flags::NEW_LISTENER != 0).then(|| owned_fd(v)))
}

/// `SECCOMP_GET_ACTION_AVAIL`: does the kernel support this return action?
pub fn action_available(action: u32) -> bool {
    let a = action;
    // SAFETY: the kernel reads a single u32 from the pointer.
    let ret = unsafe { libc::syscall(libc::SYS_seccomp, SECCOMP_GET_ACTION_AVAIL, 0, &raw const a) };
    ret == 0
}

/// Makes syscall number `nr` with no arguments, for tests of what a filter
/// does with numbers **no syscall has** (the ENOSYS stub of
/// `rustlet_runtime::seccomp`). Returns what the kernel returned.
///
/// Refuses (with `EINVAL`, without calling anything) unless `nr` is in
/// `1000..=4095`: x86_64 syscalls end below 500 (x32 ones have bit 30
/// set), so these numbers are unassigned and the kernel only ever answers
/// `ENOSYS` (or whatever a filter says). That's what makes this safe.
pub fn syscall_unassigned(nr: u32) -> Result<libc::c_long> {
    if !(1000..=4095).contains(&nr) {
        return Err(crate::Errno::EINVAL);
    }
    // SAFETY: `nr` is not a syscall on x86_64 (checked above), so the kernel
    // does nothing with it and reads no arguments.
    let ret = unsafe { libc::syscall(libc::c_long::from(nr)) };
    check(ret)
}

/// `getpid` through the **i386** syscall ABI (`int 0x80`, `eax` = 20), from
/// this 64-bit process. The kernel runs it as a 32-bit syscall, so a
/// seccomp filter sees `arch == AUDIT_ARCH_I386` and i386 numbering (20 is
/// `getpid` there, `lseek` on x86_64). Tests use it to check that a filter
/// kills foreign-ABI syscalls; it returns the pid if nothing stops it.
///
/// On a kernel without IA-32 emulation (`CONFIG_IA32_EMULATION=n`, or
/// `ia32_emulation=0` on the command line) `int 0x80` raises SIGSEGV, so
/// call it in a child process.
pub fn i386_getpid() -> i64 {
    let ret: i32;
    // SAFETY: i386 getpid takes no arguments and touches no user memory.
    // `int 0x80` returns the result in eax; the 64-bit kernel's compat entry
    // may clobber r8-r11, which are declared as such. It doesn't use the
    // user stack (the interrupt switches to the kernel stack).
    unsafe {
        core::arch::asm!(
            "int 0x80",
            inlateout("eax") 20i32 => ret,
            out("r8") _, out("r9") _, out("r10") _, out("r11") _,
        );
    }
    i64::from(ret)
}

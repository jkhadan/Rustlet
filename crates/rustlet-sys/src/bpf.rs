//! The `bpf(2)` syscall: just enough to load a `BPF_PROG_TYPE_CGROUP_DEVICE`
//! program and attach it to a cgroup.
//!
//! cgroup v2 has no `devices.allow` file. Device access control is an eBPF
//! program attached to the cgroup, which the kernel runs for every
//! `open`/`mknod` of a device node. The runtime hand-assembles that program
//! (`rustlet_runtime::cgroups::devices`); this module is the ABI.

use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd};

use crate::{Errno, Result, check, cstr, owned_fd};

/// One eBPF instruction (`struct bpf_insn`, 8 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BpfInsn {
    pub code: u8,
    /// `dst_reg:4 | src_reg:4` (low nibble = dst on little-endian).
    pub regs: u8,
    pub off: i16,
    pub imm: i32,
}

impl BpfInsn {
    pub const fn new(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> Self {
        BpfInsn { code, regs: (src << 4) | (dst & 0x0f), off, imm }
    }
    pub fn dst(&self) -> u8 {
        self.regs & 0x0f
    }
    pub fn src(&self) -> u8 {
        self.regs >> 4
    }
}

/// eBPF opcode pieces (`<linux/bpf.h>`).
pub mod op {
    // classes
    pub const BPF_LDX: u8 = 0x01;
    pub const BPF_ALU: u8 = 0x04;
    pub const BPF_JMP: u8 = 0x05;
    pub const BPF_JMP32: u8 = 0x06;
    pub const BPF_ALU64: u8 = 0x07;
    // size / mode
    pub const BPF_W: u8 = 0x00;
    pub const BPF_MEM: u8 = 0x60;
    // source
    pub const BPF_K: u8 = 0x00;
    pub const BPF_X: u8 = 0x08;
    // alu ops
    pub const BPF_AND: u8 = 0x50;
    pub const BPF_RSH: u8 = 0x70;
    pub const BPF_MOV: u8 = 0xb0;
    // jmp ops
    pub const BPF_JA: u8 = 0x00;
    pub const BPF_JEQ: u8 = 0x10;
    pub const BPF_JNE: u8 = 0x50;
    pub const BPF_JSET: u8 = 0x40;
    pub const BPF_EXIT: u8 = 0x90;
}

/// `BPF_PROG_TYPE_CGROUP_DEVICE`.
pub const PROG_TYPE_CGROUP_DEVICE: u32 = 15;
/// `BPF_CGROUP_DEVICE` attach type.
pub const ATTACH_CGROUP_DEVICE: u32 = 6;
/// `BPF_F_ALLOW_MULTI`: several programs may be attached; all must allow.
pub const F_ALLOW_MULTI: u32 = 1 << 1;

const BPF_PROG_LOAD: libc::c_int = 5;
const BPF_PROG_ATTACH: libc::c_int = 8;
const BPF_PROG_DETACH: libc::c_int = 9;
const BPF_PROG_GET_FD_BY_ID: libc::c_int = 13;
const BPF_PROG_QUERY: libc::c_int = 16;

#[repr(C)]
#[derive(Default)]
struct ProgLoadAttr {
    prog_type: u32,
    insn_cnt: u32,
    insns: u64,
    license: u64,
    log_level: u32,
    log_size: u32,
    log_buf: u64,
    kern_version: u32,
    prog_flags: u32,
    prog_name: [u8; 16],
    prog_ifindex: u32,
    expected_attach_type: u32,
}

#[repr(C)]
#[derive(Default)]
struct ProgAttachAttr {
    target_fd: u32,
    attach_bpf_fd: u32,
    attach_type: u32,
    attach_flags: u32,
    replace_bpf_fd: u32,
}

#[repr(C)]
#[derive(Default)]
struct ProgQueryAttr {
    target_fd: u32,
    attach_type: u32,
    query_flags: u32,
    attach_flags: u32,
    prog_ids: u64,
    prog_cnt: u32,
}

#[repr(C)]
#[derive(Default)]
struct GetFdByIdAttr {
    id: u32,
    next_id: u32,
    open_flags: u32,
}

fn bpf<T>(cmd: libc::c_int, attr: &mut T) -> Result<libc::c_long> {
    // SAFETY: `attr` is one of the repr(C) prefixes of `union bpf_attr`
    // defined above; the kernel reads/writes at most `size_of::<T>()`
    // bytes and zero-extends the rest.
    let ret = unsafe { libc::syscall(libc::SYS_bpf, cmd, std::ptr::from_mut(attr), std::mem::size_of::<T>()) };
    check(ret)
}

/// Loads a program. On a verifier rejection the error carries the
/// verifier log, which is the only way to find out *why*.
pub fn prog_load(prog_type: u32, insns: &[BpfInsn], name: &str) -> std::result::Result<OwnedFd, (Errno, String)> {
    let license = cstr("Apache-2.0").map_err(|e| (e, String::new()))?;
    let mut log = vec![0u8; 64 * 1024];
    let mut prog_name = [0u8; 16];
    let n = name.len().min(15);
    prog_name[..n].copy_from_slice(&name.as_bytes()[..n]);
    let mut attr = ProgLoadAttr {
        prog_type,
        insn_cnt: insns.len() as u32,
        insns: insns.as_ptr() as u64,
        license: license.as_ptr() as u64,
        log_level: 1,
        log_size: log.len() as u32,
        log_buf: log.as_mut_ptr() as u64,
        prog_name,
        ..Default::default()
    };
    match bpf(BPF_PROG_LOAD, &mut attr) {
        Ok(fd) => Ok(owned_fd(fd)),
        Err(e) => {
            let end = log.iter().position(|&b| b == 0).unwrap_or(log.len());
            Err((e, String::from_utf8_lossy(&log[..end]).into_owned()))
        }
    }
}

/// `BPF_PROG_ATTACH`: attach `prog` to the cgroup directory `cgroup`.
///
/// An attachment made this way belongs to the cgroup and survives the
/// process that made it (unlike a `BPF_LINK_CREATE` link, which dies with
/// its fd). That matters because `rustlet-runc create` exits right away.
pub fn prog_attach(cgroup: BorrowedFd<'_>, prog: BorrowedFd<'_>, attach_type: u32, flags: u32) -> Result<()> {
    let mut attr = ProgAttachAttr {
        target_fd: cgroup.as_raw_fd() as u32,
        attach_bpf_fd: prog.as_raw_fd() as u32,
        attach_type,
        attach_flags: flags,
        replace_bpf_fd: 0,
    };
    bpf(BPF_PROG_ATTACH, &mut attr).map(drop)
}

/// `BPF_PROG_DETACH` of one specific program.
pub fn prog_detach(cgroup: BorrowedFd<'_>, prog: BorrowedFd<'_>, attach_type: u32) -> Result<()> {
    let mut attr = ProgAttachAttr {
        target_fd: cgroup.as_raw_fd() as u32,
        attach_bpf_fd: prog.as_raw_fd() as u32,
        attach_type,
        ..Default::default()
    };
    bpf(BPF_PROG_DETACH, &mut attr).map(drop)
}

/// `BPF_PROG_QUERY`: IDs of the programs attached directly to `cgroup`.
pub fn prog_query(cgroup: BorrowedFd<'_>, attach_type: u32) -> Result<Vec<u32>> {
    let mut ids = vec![0u32; 64];
    let mut attr = ProgQueryAttr {
        target_fd: cgroup.as_raw_fd() as u32,
        attach_type,
        prog_ids: ids.as_mut_ptr() as u64,
        prog_cnt: ids.len() as u32,
        ..Default::default()
    };
    bpf(BPF_PROG_QUERY, &mut attr)?;
    ids.truncate(attr.prog_cnt as usize);
    Ok(ids)
}

/// `BPF_PROG_GET_FD_BY_ID`.
pub fn prog_fd_by_id(id: u32) -> Result<OwnedFd> {
    let mut attr = GetFdByIdAttr { id, ..Default::default() };
    bpf(BPF_PROG_GET_FD_BY_ID, &mut attr).map(owned_fd)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insn_is_eight_bytes() {
        assert_eq!(std::mem::size_of::<BpfInsn>(), 8);
    }

    #[test]
    fn register_nibbles() {
        let i = BpfInsn::new(0, 3, 1, 0, 0);
        assert_eq!((i.dst(), i.src()), (3, 1));
    }
}

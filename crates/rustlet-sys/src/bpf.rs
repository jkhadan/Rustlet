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
    pub const BPF_OR: u8 = 0x40;
    pub const BPF_AND: u8 = 0x50;
    pub const BPF_RSH: u8 = 0x70;
    pub const BPF_XOR: u8 = 0xa0;
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
/// `BPF_F_QUERY_EFFECTIVE`: list the programs that run for the cgroup,
/// its ancestors' included, not just the ones attached to it.
pub const F_QUERY_EFFECTIVE: u32 = 1 << 0;

/// `log_level` bits: `BPF_LOG_LEVEL1` (every instruction the verifier
/// looks at) and `BPF_LOG_STATS` (only the totals at the end).
pub const LOG_LEVEL1: u32 = 1;
pub const LOG_STATS: u32 = 4;

const BPF_PROG_LOAD: libc::c_int = 5;
const BPF_PROG_ATTACH: libc::c_int = 8;
const BPF_PROG_DETACH: libc::c_int = 9;
const BPF_PROG_GET_FD_BY_ID: libc::c_int = 13;
const BPF_OBJ_GET_INFO_BY_FD: libc::c_int = 15;
const BPF_PROG_QUERY: libc::c_int = 16;

/// The verifier log starts at 1 MiB and grows up to 16 MiB: the kernel says
/// `ENOSPC` when a log doesn't fit, even if the program was fine.
const LOG_START: usize = 1 << 20;
const LOG_MAX: usize = 16 << 20;

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

#[repr(C)]
#[derive(Default)]
struct InfoByFdAttr {
    bpf_fd: u32,
    /// Bytes of `info` the kernel may write.
    info_len: u32,
    info: u64,
}

/// The first two fields of `struct bpf_prog_info`. The kernel fills in
/// only as much of the struct as `info_len` says.
#[repr(C)]
#[derive(Default)]
struct ProgInfoHead {
    prog_type: u32,
    id: u32,
}

fn bpf<T>(cmd: libc::c_int, attr: &mut T) -> Result<libc::c_long> {
    // SAFETY: `attr` is one of the repr(C) prefixes of `union bpf_attr`
    // defined above; the kernel reads/writes at most `size_of::<T>()`
    // bytes and zero-extends the rest. Every pointer inside it (program,
    // license, log, id or info buffer) comes from a live borrow in the
    // caller, with the length field set to that buffer's size.
    let ret = unsafe { libc::syscall(libc::SYS_bpf, cmd, std::ptr::from_mut(attr), std::mem::size_of::<T>()) };
    check(ret)
}

/// A program name as the kernel takes it: at most 15 bytes of
/// `[A-Za-z0-9_.]` (anything else is `EINVAL`), NUL-padded.
fn prog_name(name: &str) -> Option<[u8; 16]> {
    let ok = name.len() < 16 && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.');
    ok.then(|| {
        let mut buf = [0u8; 16];
        buf[..name.len()].copy_from_slice(name.as_bytes());
        buf
    })
}

/// One `BPF_PROG_LOAD`, with a verifier log of `log.len()` bytes at
/// `log_level` if `log` isn't empty.
fn load_once(prog_type: u32, insns: &[BpfInsn], name: [u8; 16], log_level: u32, log: &mut [u8]) -> Result<OwnedFd> {
    let license = cstr("Apache-2.0")?;
    let with_log = !log.is_empty();
    let mut attr = ProgLoadAttr {
        prog_type,
        insn_cnt: insns.len() as u32,
        insns: insns.as_ptr() as u64,
        license: license.as_ptr() as u64,
        log_level: if with_log { log_level } else { 0 },
        log_size: log.len() as u32,
        log_buf: if with_log { log.as_mut_ptr() as u64 } else { 0 },
        prog_name: name,
        ..Default::default()
    };
    bpf(BPF_PROG_LOAD, &mut attr).map(owned_fd)
}

fn log_text(log: &[u8]) -> String {
    let end = log.iter().position(|&b| b == 0).unwrap_or(log.len());
    String::from_utf8_lossy(&log[..end]).into_owned()
}

/// Loads with a log at `log_level`, growing the buffer while the kernel
/// says it is too small.
fn load_logged(prog_type: u32, insns: &[BpfInsn], name: [u8; 16], log_level: u32) -> (Result<OwnedFd>, String) {
    let mut size = LOG_START;
    loop {
        let mut log = vec![0u8; size];
        match load_once(prog_type, insns, name, log_level, &mut log) {
            Err(Errno::ENOSPC) if size < LOG_MAX => size *= 4,
            res => return (res, log_text(&log)),
        }
    }
}

/// Loads a program. On a rejection the error carries the verifier log,
/// which is the only way to find out *why*.
///
/// The first attempt has no log at all: with a log, the kernel fails a
/// program that verified fine if the log didn't fit. Only when that fails
/// is it loaded again with a log, and the first attempt's errno is the one
/// returned.
pub fn prog_load(prog_type: u32, insns: &[BpfInsn], name: &str) -> std::result::Result<OwnedFd, (Errno, String)> {
    let name = prog_name(name).ok_or((Errno::EINVAL, format!("bad program name {name:?}")))?;
    match load_once(prog_type, insns, name, 0, &mut []) {
        Ok(fd) => Ok(fd),
        Err(first) => match load_logged(prog_type, insns, name, LOG_LEVEL1) {
            // Loaded the second time: whatever failed was transient.
            (Ok(fd), _) => Ok(fd),
            (Err(_), log) => Err((first, log)),
        },
    }
}

/// Loads a program with a verifier log at `log_level` ([`LOG_LEVEL1`],
/// [`LOG_STATS`] or both), and returns the log whether or not it loaded.
/// For tests that want the verifier's statistics (`processed N insns`).
pub fn prog_load_with_log(
    prog_type: u32,
    insns: &[BpfInsn],
    name: &str,
    log_level: u32,
) -> std::result::Result<(OwnedFd, String), (Errno, String)> {
    let name = prog_name(name).ok_or((Errno::EINVAL, format!("bad program name {name:?}")))?;
    match load_logged(prog_type, insns, name, log_level) {
        (Ok(fd), log) => Ok((fd, log)),
        (Err(e), log) => Err((e, log)),
    }
}

/// The kernel's id of a loaded program (what `bpftool prog show id N` and
/// [`prog_query`] use).
pub fn prog_id(prog: BorrowedFd<'_>) -> Result<u32> {
    let mut info = ProgInfoHead::default();
    let mut attr = InfoByFdAttr {
        bpf_fd: prog.as_raw_fd() as u32,
        info_len: std::mem::size_of::<ProgInfoHead>() as u32,
        info: std::ptr::from_mut(&mut info) as u64,
    };
    bpf(BPF_OBJ_GET_INFO_BY_FD, &mut attr)?;
    Ok(info.id)
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
    prog_query_with(cgroup, attach_type, 0).map(|(ids, _)| ids)
}

/// `BPF_PROG_QUERY` with `query_flags` (e.g. [`F_QUERY_EFFECTIVE`]).
/// Returns the program IDs and the attach flags of the cgroup's own
/// attachment (`BPF_F_ALLOW_MULTI` and so on).
pub fn prog_query_with(cgroup: BorrowedFd<'_>, attach_type: u32, query_flags: u32) -> Result<(Vec<u32>, u32)> {
    let mut ids = vec![0u32; 64];
    loop {
        let mut attr = ProgQueryAttr {
            target_fd: cgroup.as_raw_fd() as u32,
            attach_type,
            query_flags,
            prog_ids: ids.as_mut_ptr() as u64,
            prog_cnt: ids.len() as u32,
            ..Default::default()
        };
        match bpf(BPF_PROG_QUERY, &mut attr) {
            // Too many for the buffer: `prog_cnt` now says how many there are.
            Err(Errno::ENOSPC) if attr.prog_cnt as usize > ids.len() => ids.resize(attr.prog_cnt as usize, 0),
            Err(e) => return Err(e),
            Ok(_) => {
                ids.truncate(attr.prog_cnt as usize);
                return Ok((ids, attr.attach_flags));
            }
        }
    }
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

    #[test]
    fn program_names() {
        assert_eq!(&prog_name("rustlet_devices").unwrap()[..16], b"rustlet_devices\0");
        assert!(prog_name("a.b_C9").is_some());
        assert!(prog_name("sixteen_bytes_xx").is_none());
        assert!(prog_name("no-dashes").is_none());
        assert!(prog_name("").is_some());
    }
}

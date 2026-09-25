//! Linux capabilities: `capget`/`capset` (v3 ABI) and the bounding/ambient
//! sets (via `prctl`).
//!
//! A process has five capability sets:
//!
//! | set         | meaning                                                   |
//! |-------------|-----------------------------------------------------------|
//! | effective   | what the kernel checks right now                          |
//! | permitted   | the ceiling for effective                                 |
//! | inheritable | may survive `execve` (only together with file/ambient)    |
//! | bounding    | the ceiling for *any* future gain, e.g. via setuid files  |
//! | ambient     | survives `execve` of a non-privileged binary (4.3+)       |
//!
//! Order matters when dropping privileges; see
//! `rustlet_runtime::caps` for the sequence the runtime uses.

use std::fmt;
use std::str::FromStr;

use crate::{Errno, Result, check_int};

/// Every capability the kernel knows as of 6.x (0..=40).
pub const CAP_NAMES: [&str; 41] = [
    "CAP_CHOWN",
    "CAP_DAC_OVERRIDE",
    "CAP_DAC_READ_SEARCH",
    "CAP_FOWNER",
    "CAP_FSETID",
    "CAP_KILL",
    "CAP_SETGID",
    "CAP_SETUID",
    "CAP_SETPCAP",
    "CAP_LINUX_IMMUTABLE",
    "CAP_NET_BIND_SERVICE",
    "CAP_NET_BROADCAST",
    "CAP_NET_ADMIN",
    "CAP_NET_RAW",
    "CAP_IPC_LOCK",
    "CAP_IPC_OWNER",
    "CAP_SYS_MODULE",
    "CAP_SYS_RAWIO",
    "CAP_SYS_CHROOT",
    "CAP_SYS_PTRACE",
    "CAP_SYS_PACCT",
    "CAP_SYS_ADMIN",
    "CAP_SYS_BOOT",
    "CAP_SYS_NICE",
    "CAP_SYS_RESOURCE",
    "CAP_SYS_TIME",
    "CAP_SYS_TTY_CONFIG",
    "CAP_MKNOD",
    "CAP_LEASE",
    "CAP_AUDIT_WRITE",
    "CAP_AUDIT_CONTROL",
    "CAP_SETFCAP",
    "CAP_MAC_OVERRIDE",
    "CAP_MAC_ADMIN",
    "CAP_SYSLOG",
    "CAP_WAKE_ALARM",
    "CAP_BLOCK_SUSPEND",
    "CAP_AUDIT_READ",
    "CAP_PERFMON",
    "CAP_BPF",
    "CAP_CHECKPOINT_RESTORE",
];

/// A capability number (`CAP_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Cap(pub u8);

impl Cap {
    pub const CHOWN: Cap = Cap(0);
    pub const DAC_OVERRIDE: Cap = Cap(1);
    pub const FOWNER: Cap = Cap(3);
    pub const FSETID: Cap = Cap(4);
    pub const KILL: Cap = Cap(5);
    pub const SETGID: Cap = Cap(6);
    pub const SETUID: Cap = Cap(7);
    pub const SETPCAP: Cap = Cap(8);
    pub const NET_BIND_SERVICE: Cap = Cap(10);
    pub const NET_ADMIN: Cap = Cap(12);
    pub const NET_RAW: Cap = Cap(13);
    pub const SYS_CHROOT: Cap = Cap(18);
    pub const SYS_PTRACE: Cap = Cap(19);
    pub const SYS_ADMIN: Cap = Cap(21);
    pub const MKNOD: Cap = Cap(27);
    pub const AUDIT_WRITE: Cap = Cap(29);
    pub const SETFCAP: Cap = Cap(31);
    pub const BPF: Cap = Cap(39);

    /// The kernel's name, e.g. `CAP_SYS_ADMIN` (or `CAP_<n>` if unknown).
    pub fn name(self) -> String {
        CAP_NAMES.get(self.0 as usize).map_or_else(|| format!("CAP_{}", self.0), |s| (*s).to_owned())
    }
}

impl fmt::Display for Cap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name())
    }
}

impl FromStr for Cap {
    type Err = String;
    /// Accepts `CAP_SYS_ADMIN`, `SYS_ADMIN`, `sys_admin`.
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let up = s.trim().to_ascii_uppercase();
        let full = if up.starts_with("CAP_") { up } else { format!("CAP_{up}") };
        CAP_NAMES
            .iter()
            .position(|n| *n == full)
            .map(|i| Cap(i as u8))
            .ok_or_else(|| format!("unknown capability {s:?}"))
    }
}

/// A set of capabilities, stored as the kernel's 64-bit mask.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct CapSet(pub u64);

impl CapSet {
    pub const EMPTY: CapSet = CapSet(0);

    /// All capabilities up to and including `last` (see [`last_cap`]).
    pub fn all(last: Cap) -> CapSet {
        CapSet(if last.0 >= 63 { u64::MAX } else { (1u64 << (last.0 + 1)) - 1 })
    }
    pub fn contains(self, c: Cap) -> bool {
        self.0 & (1 << c.0) != 0
    }
    pub fn insert(&mut self, c: Cap) {
        self.0 |= 1 << c.0;
    }
    pub fn remove(&mut self, c: Cap) {
        self.0 &= !(1 << c.0);
    }
    pub fn iter(self) -> impl Iterator<Item = Cap> {
        (0..64u8).filter(move |i| self.0 & (1 << i) != 0).map(Cap)
    }
    /// Human-readable list, e.g. for the isolation inspector.
    pub fn names(self) -> Vec<String> {
        self.iter().map(Cap::name).collect()
    }
}

impl FromIterator<Cap> for CapSet {
    fn from_iter<I: IntoIterator<Item = Cap>>(iter: I) -> Self {
        let mut s = CapSet::EMPTY;
        for c in iter {
            s.insert(c);
        }
        s
    }
}

/// Effective, permitted and inheritable sets of the calling thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CapState {
    pub effective: CapSet,
    pub permitted: CapSet,
    pub inheritable: CapSet,
}

const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: libc::c_int,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

/// `capget(2)` for the calling thread.
pub fn capget() -> Result<CapState> {
    let mut hdr = CapHeader { version: LINUX_CAPABILITY_VERSION_3, pid: 0 };
    let mut data = [CapData::default(); 2];
    // SAFETY: v3 capget writes exactly two `CapData` structs, which `data`
    // provides; both pointers are valid for the call.
    let ret = unsafe { libc::syscall(libc::SYS_capget, &raw mut hdr, data.as_mut_ptr()) };
    crate::check(ret)?;
    let join = |lo: u32, hi: u32| CapSet(u64::from(lo) | (u64::from(hi) << 32));
    Ok(CapState {
        effective: join(data[0].effective, data[1].effective),
        permitted: join(data[0].permitted, data[1].permitted),
        inheritable: join(data[0].inheritable, data[1].inheritable),
    })
}

/// `capset(2)` for the calling thread.
pub fn capset(state: &CapState) -> Result<()> {
    let mut hdr = CapHeader { version: LINUX_CAPABILITY_VERSION_3, pid: 0 };
    let split = |s: CapSet| (s.0 as u32, (s.0 >> 32) as u32);
    let (e0, e1) = split(state.effective);
    let (p0, p1) = split(state.permitted);
    let (i0, i1) = split(state.inheritable);
    let data = [
        CapData { effective: e0, permitted: p0, inheritable: i0 },
        CapData { effective: e1, permitted: p1, inheritable: i1 },
    ];
    // SAFETY: v3 capset reads exactly two `CapData` structs from `data`.
    let ret = unsafe { libc::syscall(libc::SYS_capset, &raw mut hdr, data.as_ptr()) };
    crate::check(ret).map(drop)
}

/// Highest capability the running kernel supports
/// (`/proc/sys/kernel/cap_last_cap`).
pub fn last_cap() -> Cap {
    std::fs::read_to_string("/proc/sys/kernel/cap_last_cap")
        .ok()
        .and_then(|s| s.trim().parse::<u8>().ok())
        .map_or(Cap(40), Cap)
}

fn prctl2(option: libc::c_int, arg2: libc::c_ulong, arg3: libc::c_ulong) -> Result<libc::c_int> {
    // SAFETY: the capability prctls used here take only integer arguments.
    let ret = unsafe { libc::prctl(option, arg2, arg3, 0 as libc::c_ulong, 0 as libc::c_ulong) };
    check_int(ret)
}

/// `PR_CAPBSET_READ`: is `cap` in the bounding set?
pub fn bounding_contains(cap: Cap) -> Result<bool> {
    prctl2(libc::PR_CAPBSET_READ, cap.0.into(), 0).map(|v| v == 1)
}

/// `PR_CAPBSET_DROP`: remove `cap` from the bounding set. Needs
/// `CAP_SETPCAP` in the effective set. `EINVAL` means the kernel doesn't
/// know the capability, which we treat as already dropped.
pub fn bounding_drop(cap: Cap) -> Result<()> {
    match prctl2(libc::PR_CAPBSET_DROP, cap.0.into(), 0) {
        Ok(_) | Err(Errno::EINVAL) => Ok(()),
        Err(e) => Err(e),
    }
}

/// The current bounding set.
pub fn bounding_set() -> Result<CapSet> {
    let mut s = CapSet::EMPTY;
    for i in 0..=last_cap().0 {
        if bounding_contains(Cap(i))? {
            s.insert(Cap(i));
        }
    }
    Ok(s)
}

/// `PR_CAP_AMBIENT_RAISE`. The cap must be in both permitted and inheritable.
pub fn ambient_raise(cap: Cap) -> Result<()> {
    prctl2(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_RAISE as libc::c_ulong, cap.0.into()).map(drop)
}

/// `PR_CAP_AMBIENT_CLEAR_ALL`.
pub fn ambient_clear_all() -> Result<()> {
    // SAFETY: integer-only prctl; CLEAR_ALL requires arg3..5 to be zero.
    let ret = unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        )
    };
    check_int(ret).map(drop)
}

/// Decodes a hex mask like the `CapEff:` line of `/proc/<pid>/status`.
pub fn parse_hex_mask(hex: &str) -> Option<CapSet> {
    u64::from_str_radix(hex.trim(), 16).ok().map(CapSet)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_names() {
        assert_eq!("CAP_SYS_ADMIN".parse::<Cap>().unwrap(), Cap::SYS_ADMIN);
        assert_eq!("net_raw".parse::<Cap>().unwrap(), Cap::NET_RAW);
        assert!("CAP_BOGUS".parse::<Cap>().is_err());
    }

    #[test]
    fn full_set_mask() {
        assert_eq!(CapSet::all(Cap(40)).0, 0x1ff_ffff_ffff);
    }

    #[test]
    fn capget_works_unprivileged() {
        let s = capget().unwrap();
        // Whatever we hold, effective ⊆ permitted.
        assert_eq!(s.effective.0 & !s.permitted.0, 0);
    }

    #[test]
    fn decode_status_mask() {
        let s = parse_hex_mask("00000000a80425fb").unwrap();
        assert!(s.contains(Cap::CHOWN));
        assert!(s.contains(Cap::NET_RAW));
        assert!(!s.contains(Cap::SYS_ADMIN));
    }
}

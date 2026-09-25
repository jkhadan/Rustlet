//! Docker's default seccomp profile, resolved into OCI `linux.seccomp`.
//!
//! Docker ships one profile for every container on every architecture, in
//! its own format: OCI's `linux.seccomp` plus two additions.
//!
//! * `archMap`: which ABIs belong to the host's architecture. For x86_64
//!   that is x86_64 itself plus i386 and x32 (which we kill anyway, see
//!   `compile::check_architectures`).
//! * `includes` / `excludes` on each entry, with `caps` (capabilities the
//!   container must hold / must not hold), `arches` (Go's `GOARCH` names:
//!   `amd64`, `arm64`, …) and `minKernel` (`"4.8"`).
//!
//! The capability conditions exist because a syscall's danger depends on
//! the capabilities that come with it. Without `CAP_SYS_ADMIN`, `mount`
//! would fail anyway, so seccomp blocks it and keeps the kernel's mount
//! code out of reach; a container *given* `CAP_SYS_ADMIN` is meant to
//! mount, so for it the profile allows `mount`. The same goes for `reboot`
//! and `CAP_SYS_BOOT`, `ptrace`-like calls and `CAP_SYS_PTRACE`, and so on.
//!
//! [`resolve`] evaluates those conditions once, when the container is
//! created, the way moby does (`setupSeccomp` in
//! `github.com/moby/profiles/seccomp/seccomp_linux.go`), and the runtime
//! only ever sees plain OCI. For the default capabilities (no
//! `CAP_SYS_ADMIN`) that means, among other things:
//!
//! * `clone` only without namespace flags: `(flags & 0x7E020000) == 0`,
//!   i.e. none of `CLONE_NEWNS|NEWCGROUP|NEWUTS|NEWIPC|NEWUSER|NEWPID|NEWNET`.
//! * `clone3` returns `ENOSYS`: its flags live in a struct in memory, which
//!   seccomp can't read, so it can't be checked like `clone`; ENOSYS makes
//!   glibc fall back to `clone`, which can.
//! * `socket` only for the address families the profile lists: those
//!   below 38, then 39 and 41–45. Not `AF_ALG` (38), not `AF_VSOCK` (40,
//!   host↔VM sockets, which no namespace isolates), and nothing newer than
//!   the profile.
//! * `personality` only for a few harmless values: arbitrary personality
//!   flags could, e.g., switch off address-space randomization.

use std::path::PathBuf;

use oci_spec::runtime::{
    Arch, LinuxSeccomp, LinuxSeccompAction, LinuxSeccompArg, LinuxSeccompFilterFlag, LinuxSyscall,
};
pub use rustlet_sys::caps::{Cap, CapSet};
use serde::Deserialize;

use crate::error::{Context, Error, Result};

/// Docker's default profile (Docker's own JSON format, with `includes` and
/// `excludes`), vendored in `profiles/seccomp-default.json`.
pub const DEFAULT_PROFILE: &str = include_str!("../../../../profiles/seccomp-default.json");

/// What `includes.arches` / `excludes.arches` call x86_64: Go's `GOARCH`.
const GOARCH: &str = "amd64";
/// The `archMap` entry for this host.
const NATIVE: &str = "SCMP_ARCH_X86_64";

/// A kernel version as `minKernel` compares it: major and minor only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KernelVersion {
    pub major: u32,
    pub minor: u32,
}

impl KernelVersion {
    /// The running kernel, from `/proc/sys/kernel/osrelease` (`uname -r`).
    pub fn running() -> Result<KernelVersion> {
        const PATH: &str = "/proc/sys/kernel/osrelease";
        let release = std::fs::read_to_string(PATH).context(format!("read {PATH}"))?;
        KernelVersion::from_release(&release).ok_or_else(|| Error::Io {
            context: format!("read {PATH}"),
            err: std::io::Error::new(std::io::ErrorKind::InvalidData, format!("unexpected release {release:?}")),
        })
    }

    /// The first two numbers of a kernel release such as `7.0.0-34-generic`.
    pub fn from_release(release: &str) -> Option<KernelVersion> {
        let mut numbers = release.trim().split(['.', '-']);
        let major = numbers.next()?.parse().ok()?;
        let minor = numbers.next()?.parse().ok()?;
        Some(KernelVersion { major, minor })
    }

    /// A profile's `minKernel`: exactly `<major>.<minor>`, as moby requires.
    fn from_min_kernel(s: &str) -> Result<KernelVersion> {
        let parsed = s
            .split_once('.')
            .and_then(|(major, minor)| Some(KernelVersion { major: major.parse().ok()?, minor: minor.parse().ok()? }));
        parsed.ok_or_else(|| Error::invalid(format!("seccomp profile: minKernel {s:?} is not <major>.<minor>")))
    }
}

impl std::fmt::Display for KernelVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

/// Docker's profile format (moby's `seccomp.Seccomp`). Unknown fields
/// (`comment`) are ignored, as Go's JSON decoder does.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Profile {
    default_action: LinuxSeccompAction,
    default_errno_ret: Option<u32>,
    architectures: Option<Vec<Arch>>,
    arch_map: Option<Vec<ArchMap>>,
    flags: Option<Vec<LinuxSeccompFilterFlag>>,
    listener_path: Option<PathBuf>,
    listener_metadata: Option<String>,
    syscalls: Option<Vec<Entry>>,
}

/// Architecture names stay strings until we pick ours, so a profile that
/// mentions an architecture oci-spec doesn't know still loads.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ArchMap {
    architecture: String,
    sub_architectures: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Entry {
    name: Option<String>,
    names: Option<Vec<String>>,
    action: LinuxSeccompAction,
    errno_ret: Option<u32>,
    args: Option<Vec<LinuxSeccompArg>>,
    includes: Option<Condition>,
    excludes: Option<Condition>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Condition {
    caps: Option<Vec<String>>,
    arches: Option<Vec<String>>,
    min_kernel: Option<String>,
}

/// Resolves a Docker-format `profile` for a container whose bounding set is
/// `caps`, on x86_64 and `kernel`.
pub fn resolve(profile: &str, caps: CapSet, kernel: KernelVersion) -> Result<LinuxSeccomp> {
    let p: Profile = serde_json::from_str(profile).map_err(|e| Error::invalid(format!("seccomp profile: {e}")))?;
    let arch_map = p.arch_map.unwrap_or_default();
    let mut architectures = p.architectures.unwrap_or_default();
    if !architectures.is_empty() && !arch_map.is_empty() {
        return Err(Error::invalid("seccomp profile: use either `architectures` or `archMap`, not both"));
    }
    if let Some(native) = arch_map.iter().find(|m| m.architecture == NATIVE) {
        architectures.push(arch(&native.architecture)?);
        for sub in native.sub_architectures.iter().flatten() {
            architectures.push(arch(sub)?);
        }
    }

    let mut syscalls = Vec::new();
    for (i, entry) in p.syscalls.unwrap_or_default().into_iter().enumerate() {
        let names = match (entry.name.filter(|n| !n.is_empty()), entry.names) {
            (Some(_), Some(names)) if !names.is_empty() => {
                return Err(Error::invalid(format!("seccomp profile: syscalls[{i}] has both `name` and `names`")));
            }
            (Some(name), _) => vec![name],
            (None, names) => names.unwrap_or_default(),
        };
        if !applies(entry.includes.as_ref(), entry.excludes.as_ref(), caps, kernel)? {
            continue;
        }
        let mut s = LinuxSyscall::default();
        s.set_names(names).set_action(entry.action).set_errno_ret(entry.errno_ret).set_args(entry.args);
        syscalls.push(s);
    }

    let mut out = LinuxSeccomp::default();
    out.set_default_action(p.default_action)
        .set_default_errno_ret(p.default_errno_ret)
        .set_architectures((!architectures.is_empty()).then_some(architectures))
        .set_flags(p.flags.filter(|f| !f.is_empty()))
        .set_listener_path(p.listener_path)
        .set_listener_metadata(p.listener_metadata)
        .set_syscalls(Some(syscalls));
    Ok(out)
}

/// [`DEFAULT_PROFILE`] resolved for a container holding `caps` (its bounding
/// set), on x86_64 and the running kernel.
pub fn default_for(caps: CapSet) -> Result<LinuxSeccomp> {
    resolve(DEFAULT_PROFILE, caps, KernelVersion::running()?)
}

fn arch(name: &str) -> Result<Arch> {
    serde_json::from_value(serde_json::Value::String(name.to_owned()))
        .map_err(|_| Error::invalid(format!("seccomp profile: unknown architecture {name:?}")))
}

/// Does an entry apply to this container? Excludes first, then includes,
/// as in moby. A capability name we don't know is one the container
/// doesn't have.
fn applies(
    includes: Option<&Condition>,
    excludes: Option<&Condition>,
    caps: CapSet,
    kernel: KernelVersion,
) -> Result<bool> {
    let held = |name: &String| name.parse::<Cap>().is_ok_and(|c| caps.contains(c));
    let min_kernel =
        |c: &Condition| c.min_kernel.as_deref().filter(|s| !s.is_empty()).map(KernelVersion::from_min_kernel);
    if let Some(ex) = excludes {
        if ex.arches.iter().flatten().any(|a| a == GOARCH) || ex.caps.iter().flatten().any(held) {
            return Ok(false);
        }
        if let Some(min) = min_kernel(ex).transpose()?
            && kernel >= min
        {
            return Ok(false);
        }
    }
    if let Some(inc) = includes {
        let arches = inc.arches.as_deref().unwrap_or_default();
        if !arches.is_empty() && !arches.iter().any(|a| a == GOARCH) {
            return Ok(false);
        }
        if !inc.caps.iter().flatten().all(held) {
            return Ok(false);
        }
        if let Some(min) = min_kernel(inc).transpose()?
            && kernel < min
        {
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KERNEL: KernelVersion = KernelVersion { major: 7, minor: 0 };

    fn names_of(s: &LinuxSeccomp) -> Vec<String> {
        s.syscalls().iter().flatten().flat_map(|e| e.names().clone()).collect()
    }

    #[test]
    fn kernel_versions() {
        assert_eq!(KernelVersion::from_release("7.0.0-34-generic\n"), Some(KernelVersion { major: 7, minor: 0 }));
        assert_eq!(KernelVersion::from_release("6.12-rc1"), Some(KernelVersion { major: 6, minor: 12 }));
        assert_eq!(KernelVersion::from_release("garbage"), None);
        assert!(KernelVersion { major: 4, minor: 8 } < KernelVersion { major: 4, minor: 10 });
        assert!(KernelVersion::from_min_kernel("4.8").is_ok());
        assert!(KernelVersion::from_min_kernel("4").is_err());
        assert!(KernelVersion::from_min_kernel("4.8.1").is_err());
        let running = KernelVersion::running().unwrap();
        assert!(running >= KernelVersion { major: 6, minor: 8 }, "{running}");
    }

    #[test]
    fn default_profile_for_the_default_caps() {
        let s = resolve(DEFAULT_PROFILE, crate::caps::default_set(), KERNEL).unwrap();
        assert_eq!(s.default_action(), LinuxSeccompAction::ScmpActErrno);
        assert_eq!(s.default_errno_ret(), Some(1));
        assert_eq!(
            s.architectures().as_deref(),
            Some(&[Arch::ScmpArchX86_64, Arch::ScmpArchX86, Arch::ScmpArchX32][..])
        );
        let names = names_of(&s);
        assert!(names.iter().any(|n| n == "chroot"), "CAP_SYS_CHROOT is a default cap");
        assert!(names.iter().any(|n| n == "ptrace"), "minKernel 4.8 <= 7.0");
        assert!(names.iter().any(|n| n == "arch_prctl"), "amd64-only entry");
        assert!(!names.iter().any(|n| n == "mount"), "needs CAP_SYS_ADMIN");
        assert!(!names.iter().any(|n| n == "riscv_flush_icache"), "riscv64-only entry");
        // The CAP_SYS_ADMIN-less clone rule, and the s390 variant excluded.
        let clones: Vec<_> = s.syscalls().iter().flatten().filter(|e| e.names() == &["clone"]).collect();
        assert_eq!(clones.len(), 1);
        let arg = clones[0].args().as_ref().unwrap()[0];
        assert_eq!((arg.index(), arg.value()), (0, 0x7E02_0000));
    }

    #[test]
    fn sys_admin_flips_the_clone_rules() {
        let mut caps = crate::caps::default_set();
        caps.insert(Cap::SYS_ADMIN);
        let s = resolve(DEFAULT_PROFILE, caps, KERNEL).unwrap();
        let names = names_of(&s);
        assert!(names.iter().any(|n| n == "mount"));
        assert!(!s.syscalls().iter().flatten().any(|e| e.names() == &["clone3"]), "no clone3 → ENOSYS rule");
        assert!(!s.syscalls().iter().flatten().any(|e| e.names() == &["clone"] && e.args().is_some()));
    }

    #[test]
    fn min_kernel_is_honoured() {
        let old = resolve(DEFAULT_PROFILE, CapSet::EMPTY, KernelVersion { major: 4, minor: 4 }).unwrap();
        assert!(!names_of(&old).iter().any(|n| n == "ptrace"));
    }

    #[test]
    fn excludes_by_min_kernel_and_errors() {
        let profile = r#"{"defaultAction": "SCMP_ACT_ALLOW", "syscalls": [
            {"name": "getpid", "action": "SCMP_ACT_ERRNO", "excludes": {"minKernel": "5.0"}},
            {"names": ["getppid"], "action": "SCMP_ACT_ERRNO", "excludes": {"caps": ["CAP_BOGUS"]}}
        ]}"#;
        let s = resolve(profile, CapSet::EMPTY, KERNEL).unwrap();
        assert_eq!(names_of(&s), ["getppid"]);
        assert_eq!(s.architectures(), &None);

        let both = r#"{"defaultAction": "SCMP_ACT_ALLOW", "syscalls": [{"name": "a", "names": ["b"], "action": "SCMP_ACT_ALLOW"}]}"#;
        assert!(matches!(resolve(both, CapSet::EMPTY, KERNEL), Err(Error::InvalidSpec(_))));
        let bad_kernel = r#"{"defaultAction": "SCMP_ACT_ALLOW", "syscalls": [{"name": "a", "action": "SCMP_ACT_ALLOW", "includes": {"minKernel": "four"}}]}"#;
        assert!(matches!(resolve(bad_kernel, CapSet::EMPTY, KERNEL), Err(Error::InvalidSpec(_))));
    }
}

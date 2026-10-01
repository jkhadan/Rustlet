//! Validating `config.json` into a [`Plan`], before anything is created.
//!
//! The container's init process runs in a half-built world (new namespaces,
//! mounts in flux, no terminal of its own), which is a bad place to discover
//! that a field was misspelled. So `rustlet-runc` checks everything that can
//! be checked statically *first*, in the parent, and hands the child a
//! [`Plan`]: plain data, already validated, where every remaining step is a
//! system call.
//!
//! Features this build doesn't implement yet are rejected with the phase that
//! will add them, rather than silently ignored.

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use nix::sys::resource::Resource;
use oci_spec::runtime::{PosixRlimitType, Process, Spec};

use crate::bundle::Bundle;
use crate::caps::CapsPlan;
use crate::cgroups::devices::DeviceFilter;
use crate::cgroups::{self, CgroupPath, Setting};
use crate::error::{Context, Error, Result, Unsupported};
use crate::mounts::{self, MountEntry};
use crate::namespaces::{self, NamespacePlan};
use crate::paths::{self, PathRules};
use crate::seccomp::{self, Filter};
use crate::sysctl::{self, Sysctl};
use crate::userns::{self, UsernsPlan};

/// A validated container configuration.
#[derive(Debug, Clone)]
pub struct Plan {
    pub id: String,
    /// The container's `/`: absolute and canonical.
    pub root: PathBuf,
    pub root_readonly: bool,
    pub namespaces: NamespacePlan,
    pub mounts: Vec<MountEntry>,
    pub hostname: Option<String>,
    pub domainname: Option<String>,
    pub process: ProcessPlan,
    /// The container's cgroup (`linux.cgroupsPath`), the file writes that
    /// implement `linux.resources`, and its device filter. `None`: the
    /// container stays in the caller's cgroup (only allowed without resource
    /// limits), and has no device filter.
    pub cgroup: Option<CgroupPlan>,
    /// `linux.maskedPaths` and `linux.readonlyPaths`.
    pub paths: PathRules,
    /// `linux.sysctl`, validated against the namespaces.
    pub sysctls: Vec<Sysctl>,
    /// `linux.seccomp`, compiled to BPF. `None`: no filter (unconfined).
    pub seccomp: Option<Filter>,
    /// The new user namespace's maps (`linux.uidMappings`/`gidMappings`).
    /// `None`: the container stays in the runtime's user namespace.
    pub userns: Option<UsernsPlan>,
}

/// Where the container's cgroup goes and what gets written into it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CgroupPlan {
    pub path: CgroupPath,
    pub settings: Vec<Setting>,
    /// Attached to the cgroup before init exists, for every container that
    /// has one: without device rules in the spec, it allows the defaults.
    pub devices: DeviceFilter,
}

/// The process to run, and how.
#[derive(Debug, Clone)]
pub struct ProcessPlan {
    /// `args[0]` is looked up in the container's `$PATH` unless it has a `/`.
    pub args: Vec<String>,
    pub env: Vec<String>,
    /// Absolute path inside the container.
    pub cwd: PathBuf,
    pub uid: u32,
    pub gid: u32,
    pub additional_gids: Vec<u32>,
    /// Defaults to 0o022 when `config.json` doesn't say.
    pub umask: u32,
    pub rlimits: Vec<Rlimit>,
    pub no_new_privileges: bool,
    pub oom_score_adj: Option<i32>,
    /// Give the container a PTY of its own (`process.terminal`).
    pub terminal: bool,
    /// `process.consoleSize`, applied to that PTY.
    pub console_size: Option<rustlet_sys::term::WinSize>,
    /// `process.capabilities`.
    pub caps: CapsPlan,
}

/// One `setrlimit` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rlimit {
    pub resource: Resource,
    pub soft: u64,
    pub hard: u64,
}

/// Container IDs end up in paths (`/run/rustlet/runtime/<id>`), so they are
/// restricted to a safe alphabet, the same one runc uses.
pub fn validate_id(id: &str) -> Result<()> {
    let ok = !id.is_empty()
        && id.len() <= 1024
        && id.chars().next().is_some_and(|c| c.is_ascii_alphanumeric())
        && id.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'));
    if ok {
        Ok(())
    } else {
        Err(Error::invalid(format!("invalid container id {id:?}: use [A-Za-z0-9][A-Za-z0-9_.-]*")))
    }
}

impl Plan {
    /// Validates `bundle` for a container called `id`.
    pub fn new(id: &str, bundle: &Bundle) -> Result<Plan> {
        validate_id(id)?;
        let spec = &bundle.spec;
        if !spec.version().starts_with("1.") {
            return Err(Error::invalid(format!("unsupported ociVersion {:?} (expected 1.x)", spec.version())));
        }
        reject_unsupported(spec)?;

        let linux = spec.linux().as_ref().ok_or_else(|| Error::invalid("missing `linux` section"))?;
        let namespaces = namespaces::plan(linux.namespaces().as_deref().unwrap_or_default())?;

        let root_cfg = spec.root().as_ref().ok_or_else(|| Error::invalid("missing `root`"))?;
        let root = resolve_root(&bundle.resolve(root_cfg.path()))?;

        let mut mounts =
            spec.mounts().iter().flatten().map(|m| mounts::parse(m, bundle)).collect::<Result<Vec<_>>>()?;
        let userns = userns::plan(linux, &namespaces)?;
        userns::check_mounts(&mut mounts, userns.as_ref(), &namespaces)?;
        // Init uses /proc after pivot_root (the exec.fifo reopen, oom_score_adj).
        // Without our own procfs there, those paths would resolve inside the
        // image's `proc/` directory, which the image controls.
        let has_proc = mounts.iter().any(|m| {
            m.destination == Path::new("/proc")
                && matches!(&m.kind, mounts::MountKind::Fs { fstype, .. } if fstype == "proc")
        });
        if !has_proc {
            return Err(Error::invalid("the spec must mount procfs on /proc"));
        }

        let hostname = spec.hostname().clone().filter(|h| !h.is_empty());
        let domainname = spec.domainname().clone().filter(|d| !d.is_empty());
        if (hostname.is_some() || domainname.is_some()) && !namespaces.new_uts() {
            return Err(Error::invalid(
                "hostname/domainname require a new `uts` namespace (otherwise they would change the host's)",
            ));
        }

        let process = spec.process().as_ref().ok_or_else(|| Error::invalid("missing `process`"))?;
        let sysctls = sysctl::plan(&linux.sysctl().clone().unwrap_or_default(), &namespaces)?;
        let paths = paths::plan(
            linux.masked_paths().as_deref().unwrap_or_default(),
            linux.readonly_paths().as_deref().unwrap_or_default(),
        )?;
        let seccomp = linux.seccomp().as_ref().map(seccomp::compile).transpose()?;
        let process = process_plan(process)?;
        if let Some(u) = &userns {
            u.check_process(&process)?;
        }
        Ok(Plan {
            id: id.to_owned(),
            root,
            root_readonly: root_cfg.readonly().unwrap_or(false),
            namespaces,
            mounts,
            hostname,
            domainname,
            process,
            cgroup: cgroup_plan(linux)?,
            paths,
            sysctls,
            seccomp,
            userns,
        })
    }
}

/// Canonicalizes `root.path` and refuses the host's own `/`.
///
/// The comparison is by (device, inode), not by string: `/proc/1/root`, a
/// symlink, or a bind mount of `/` all canonicalize to something that isn't
/// the string "/" but *is* the host root directory.
fn resolve_root(path: &Path) -> Result<PathBuf> {
    let root = std::fs::canonicalize(path).with_context(|| format!("root.path {}", path.display()))?;
    let meta = std::fs::metadata(&root).with_context(|| format!("root.path {}", root.display()))?;
    if !meta.is_dir() {
        return Err(Error::invalid(format!("root.path {} is not a directory", root.display())));
    }
    let host = std::fs::metadata("/").context("stat /")?;
    if root == Path::new("/") || (meta.dev(), meta.ino()) == (host.dev(), host.ino()) {
        return Err(Error::invalid("root.path is the host's `/`; refusing to run a container on the host root"));
    }
    Ok(root)
}

/// `linux.cgroupsPath` + `linux.resources`. Limits need a cgroup to live in:
/// asking for `memory.limit` without saying where the cgroup goes is an
/// error, not a silently unlimited container.
fn cgroup_plan(linux: &oci_spec::runtime::Linux) -> Result<Option<CgroupPlan>> {
    let settings = match linux.resources() {
        Some(r) => cgroups::settings_for(r)?,
        None => Vec::new(),
    };
    match linux.cgroups_path() {
        Some(p) => {
            let path = CgroupPath::parse(&p.to_string_lossy())?;
            Ok(Some(CgroupPlan { path, settings, devices: DeviceFilter::build(&[], &[])? }))
        }
        None if settings.is_empty() => Ok(None),
        None => Err(Error::invalid(
            "linux.resources sets limits but linux.cgroupsPath is missing: limits need a cgroup to live in",
        )),
    }
}

/// Validates `process` (also used by `exec` for the process it starts).
pub(crate) fn process_plan(p: &Process) -> Result<ProcessPlan> {
    reject_unsupported_process(p)?;
    let args = p.args().clone().unwrap_or_default();
    if args.is_empty() || args[0].is_empty() {
        return Err(Error::invalid("process.args must name a program"));
    }
    if args.iter().any(|a| a.contains('\0')) {
        return Err(Error::invalid("process.args contains a NUL byte"));
    }
    let env = p.env().clone().unwrap_or_default();
    if let Some(bad) = env.iter().find(|e| !e.contains('=') || e.starts_with('=') || e.contains('\0')) {
        return Err(Error::invalid(format!("process.env entry {bad:?} is not KEY=value")));
    }
    if !p.cwd().is_absolute() {
        return Err(Error::invalid(format!("process.cwd {} must be absolute", p.cwd().display())));
    }
    let user = p.user();
    let rlimits = p
        .rlimits()
        .iter()
        .flatten()
        .map(|r| {
            if r.soft() > r.hard() {
                return Err(Error::invalid(format!("rlimit {:?}: soft limit exceeds hard limit", r.typ())));
            }
            Ok(Rlimit { resource: resource(r.typ()), soft: r.soft(), hard: r.hard() })
        })
        .collect::<Result<Vec<_>>>()?;
    // Without a list we would have to guess, and "all of them" (what a
    // missing list meant before this phase) includes CAP_MKNOD and
    // CAP_SYS_ADMIN. Make the choice explicit instead.
    let caps = p.capabilities().as_ref().ok_or_else(|| {
        Error::invalid(
            "process.capabilities is missing: list the capabilities the container keeps \
             (`rustlet-runc spec` writes a safe default set)",
        )
    })?;
    let caps = CapsPlan::from_spec(caps, rustlet_sys::caps::last_cap())?;
    Ok(ProcessPlan {
        args,
        env,
        cwd: p.cwd().clone(),
        uid: user.uid(),
        gid: user.gid(),
        additional_gids: user.additional_gids().clone().unwrap_or_default(),
        umask: user.umask().unwrap_or(0o022),
        rlimits,
        no_new_privileges: p.no_new_privileges().unwrap_or(false),
        oom_score_adj: p.oom_score_adj(),
        terminal: p.terminal().unwrap_or(false),
        console_size: p
            .console_size()
            .map(|b| {
                let fit = |v: u64| {
                    u16::try_from(v).map_err(|_| Error::invalid(format!("process.consoleSize {v} is too large")))
                };
                Ok::<_, Error>(rustlet_sys::term::WinSize { rows: fit(b.height())?, cols: fit(b.width())? })
            })
            .transpose()?,
        caps,
    })
}

fn resource(t: PosixRlimitType) -> Resource {
    use PosixRlimitType as T;
    match t {
        T::RlimitCpu => Resource::RLIMIT_CPU,
        T::RlimitFsize => Resource::RLIMIT_FSIZE,
        T::RlimitData => Resource::RLIMIT_DATA,
        T::RlimitStack => Resource::RLIMIT_STACK,
        T::RlimitCore => Resource::RLIMIT_CORE,
        T::RlimitRss => Resource::RLIMIT_RSS,
        T::RlimitNproc => Resource::RLIMIT_NPROC,
        T::RlimitNofile => Resource::RLIMIT_NOFILE,
        T::RlimitMemlock => Resource::RLIMIT_MEMLOCK,
        T::RlimitAs => Resource::RLIMIT_AS,
        T::RlimitLocks => Resource::RLIMIT_LOCKS,
        T::RlimitSigpending => Resource::RLIMIT_SIGPENDING,
        T::RlimitMsgqueue => Resource::RLIMIT_MSGQUEUE,
        T::RlimitNice => Resource::RLIMIT_NICE,
        T::RlimitRtprio => Resource::RLIMIT_RTPRIO,
        T::RlimitRttime => Resource::RLIMIT_RTTIME,
    }
}

fn some_vec<T>(v: &Option<Vec<T>>) -> bool {
    v.as_ref().is_some_and(|v| !v.is_empty())
}

/// Collects every field this build can't honour yet.
fn reject_unsupported(spec: &Spec) -> Result<()> {
    let mut missing = Vec::new();
    let mut need = |cond: bool, field: &str, when: &'static str| {
        if cond {
            missing.push(Unsupported { field: field.to_owned(), when });
        }
    };
    let non_empty = |s: &Option<String>| s.as_deref().is_some_and(|s| !s.is_empty());

    need(spec.hooks().is_some(), "hooks", "not planned");
    need(spec.solaris().is_some() || spec.windows().is_some() || spec.vm().is_some(), "non-Linux sections", "never");

    if let Some(l) = spec.linux() {
        if let Some(r) = l.resources() {
            // Without the eBPF device filter, device rules would be silently
            // unenforced. (Limits are handled by `cgroups::settings_for`.)
            need(some_vec(r.devices()), "linux.resources.devices", "Phase 2c");
        }
        need(some_vec(l.devices()), "linux.devices", "Phase 2c");
        need(
            l.rootfs_propagation().as_deref().is_some_and(|p| !matches!(p, "" | "private" | "rprivate")),
            "linux.rootfsPropagation other than private",
            "not planned",
        );
        need(non_empty(l.mount_label()), "linux.mountLabel", "not planned");
        need(l.intel_rdt().is_some(), "linux.intelRdt", "not planned");
        need(l.memory_policy().is_some(), "linux.memoryPolicy", "not planned");
        need(l.personality().is_some(), "linux.personality", "not planned");
        need(l.net_devices().as_ref().is_some_and(|d| !d.is_empty()), "linux.netDevices", "not planned");
        need(l.time_offsets().as_ref().is_some_and(|t| !t.is_empty()), "linux.timeOffsets", "stretch goal");
    }

    if missing.is_empty() { Ok(()) } else { Err(Error::Unsupported(missing)) }
}

/// The `process` fields this build can't honour (checked for `create` and
/// for every `exec`).
fn reject_unsupported_process(p: &Process) -> Result<()> {
    let non_empty = |s: &Option<String>| s.as_deref().is_some_and(|s| !s.is_empty());
    let missing: Vec<_> = [
        (non_empty(p.apparmor_profile()), "process.apparmorProfile", "Phase 8"),
        (non_empty(p.selinux_label()), "process.selinuxLabel", "not planned"),
        (p.scheduler().is_some(), "process.scheduler", "not planned"),
        (p.io_priority().is_some(), "process.ioPriority", "not planned"),
        (p.exec_cpu_affinity().is_some(), "process.execCPUAffinity", "not planned"),
    ]
    .into_iter()
    .filter(|(cond, ..)| *cond)
    .map(|(_, field, when)| Unsupported { field: field.to_owned(), when })
    .collect();
    if missing.is_empty() { Ok(()) } else { Err(Error::Unsupported(missing)) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::default_spec;
    use oci_spec::runtime::ProcessBuilder;

    fn bundle_with(spec: Spec) -> (tempfile::TempDir, Bundle) {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("rootfs")).unwrap();
        let b = Bundle::from_spec(dir.path().canonicalize().unwrap(), spec);
        (dir, b)
    }

    #[test]
    fn default_spec_is_runnable_by_this_phase() {
        let (dir, b) = bundle_with(default_spec());
        let plan = Plan::new("demo", &b).unwrap();
        assert_eq!(plan.root, dir.path().canonicalize().unwrap().join("rootfs"));
        assert!(plan.root_readonly);
        assert_eq!(plan.process.args, ["sh"]);
        assert_eq!(plan.process.umask, 0o022);
        assert_eq!(plan.mounts.len(), 7);
        assert_eq!(plan.hostname.as_deref(), Some("rustlet"));
    }

    #[test]
    fn ids_are_path_safe() {
        for good in ["a", "web-1", "x.y_z", "0abc"] {
            validate_id(good).unwrap();
        }
        for bad in ["", "-a", "../x", "a/b", "a b", ".hidden"] {
            assert!(validate_id(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn refuses_the_host_root() {
        let mut spec = default_spec();
        spec.root_mut().as_mut().unwrap().set_path("/".into());
        let (_d, b) = bundle_with(spec);
        assert!(Plan::new("x", &b).unwrap_err().to_string().contains("host"));
    }

    #[test]
    fn unsupported_features_name_their_phase() {
        let mut spec = default_spec();
        let linux = spec.linux_mut().as_mut().unwrap();
        linux.set_devices(Some(vec![Default::default()]));
        linux.set_intel_rdt(Some(Default::default()));
        let (_d, b) = bundle_with(spec);
        let msg = Plan::new("x", &b).unwrap_err().to_string();
        assert!(msg.contains("linux.devices (Phase 2c)"), "{msg}");
        assert!(msg.contains("linux.intelRdt (not planned)"), "{msg}");
    }

    fn remapped() -> Spec {
        let mut spec = default_spec();
        crate::spec::with_user_namespace(&mut spec, crate::spec::REMAP_HOST_ID, crate::spec::REMAP_SIZE);
        spec
    }

    #[test]
    fn user_namespace_plan() {
        let (_d, b) = bundle_with(remapped());
        let plan = Plan::new("x", &b).unwrap();
        let u = plan.userns.as_ref().unwrap();
        assert_eq!(u.uid_to_host(0), Some(1_000_000));
        assert!(plan.namespaces.new_user());
        // With a new network namespace, sysfs stays sysfs.
        assert!(
            plan.mounts.iter().any(|m| matches!(&m.kind, mounts::MountKind::Fs { fstype, .. } if fstype == "sysfs"))
        );

        // Without one, it becomes a bind of the host's /sys.
        let mut spec = remapped();
        let linux = spec.linux_mut().as_mut().unwrap();
        let ns = linux.namespaces().clone().unwrap();
        linux.set_namespaces(Some(
            ns.into_iter().filter(|n| n.typ() != oci_spec::runtime::LinuxNamespaceType::Network).collect(),
        ));
        let (_d, b) = bundle_with(spec);
        let plan = Plan::new("x", &b).unwrap();
        let sys = plan.mounts.iter().find(|m| m.destination == Path::new("/sys")).unwrap();
        assert_eq!(sys.kind, mounts::MountKind::HostSysfs);
    }

    #[test]
    fn user_namespace_refusals() {
        let refused = |spec: Spec, why: &str| {
            let (_d, b) = bundle_with(spec);
            let msg = Plan::new("x", &b).unwrap_err().to_string();
            assert!(msg.contains(why), "expected {why:?} in: {msg}");
        };
        // Maps without a user namespace, and the other way round.
        let mut spec = remapped();
        let linux = spec.linux_mut().as_mut().unwrap();
        let ns = linux.namespaces().clone().unwrap();
        linux.set_namespaces(Some(
            ns.into_iter().filter(|n| n.typ() != oci_spec::runtime::LinuxNamespaceType::User).collect(),
        ));
        refused(spec, "no new `user` namespace");
        let mut spec = remapped();
        spec.linux_mut().as_mut().unwrap().set_gid_mappings(None);
        refused(spec, "needs both");
        // The process's ids must be mapped.
        let mut spec = remapped();
        let mut p = spec.process().clone().unwrap();
        let mut user = p.user().clone();
        user.set_additional_gids(Some(vec![70000]));
        p.set_user(user);
        spec.set_process(Some(p));
        refused(spec, "additionalGids 70000 is not mapped");
        // So must devpts' gid=5.
        let mut spec = remapped();
        let map = oci_spec::runtime::LinuxIdMappingBuilder::default().host_id(2_000_000u32).size(1u32).build().unwrap();
        spec.linux_mut().as_mut().unwrap().set_gid_mappings(Some(vec![map]));
        refused(spec, "`gid=5`");
        // A shared PID namespace can't get a procfs from the user namespace.
        let mut spec = remapped();
        let linux = spec.linux_mut().as_mut().unwrap();
        let ns = linux.namespaces().clone().unwrap();
        linux.set_namespaces(Some(
            ns.into_iter().filter(|n| n.typ() != oci_spec::runtime::LinuxNamespaceType::Pid).collect(),
        ));
        refused(spec, "new `pid` namespace");
    }

    #[test]
    fn capabilities_must_be_listed() {
        let mut spec = default_spec();
        let mut p = spec.process().clone().unwrap();
        p.set_capabilities(None);
        spec.set_process(Some(p));
        let (_d, b) = bundle_with(spec);
        assert!(Plan::new("x", &b).unwrap_err().to_string().contains("process.capabilities is missing"));
    }

    #[test]
    fn hostname_needs_uts_namespace() {
        let mut spec = default_spec();
        let linux = spec.linux_mut().as_mut().unwrap();
        let ns = linux.namespaces().clone().unwrap();
        linux.set_namespaces(Some(
            ns.into_iter().filter(|n| n.typ() != oci_spec::runtime::LinuxNamespaceType::Uts).collect(),
        ));
        let (_d, b) = bundle_with(spec);
        assert!(Plan::new("x", &b).unwrap_err().to_string().contains("uts"));
    }

    #[test]
    fn process_checks() {
        let mut spec = default_spec();
        spec.set_process(Some(ProcessBuilder::default().args(vec![]).cwd("/").build().unwrap()));
        let (_d, b) = bundle_with(spec);
        assert!(Plan::new("x", &b).is_err(), "empty args");

        let mut spec = default_spec();
        spec.set_process(Some(ProcessBuilder::default().args(vec!["sh".to_string()]).cwd("tmp").build().unwrap()));
        let (_d, b) = bundle_with(spec);
        assert!(Plan::new("x", &b).is_err(), "relative cwd");
    }
}

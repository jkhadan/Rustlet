//! User namespaces: a container root that is nobody on the host.
//!
//! Without a user namespace, root in a container *is* root on the host: uid
//! 0, held back only by the capabilities it lost, the seccomp filter and the
//! mounts it can't see. A user namespace changes who the process is. Its
//! `uid_map` says which host ids the namespace's ids stand for:
//!
//! ```text
//!   /proc/<init>/uid_map:   0 1000000 65536
//!                           │ │       └ this many ids
//!                           │ └ are host ids 1000000…
//!                           └ container ids 0…
//! ```
//!
//! so container root is host uid 1000000, a user that owns nothing on the
//! host. Capabilities become relative too: init has every capability, but
//! only over what its user namespace *owns*, and that is the namespaces
//! created together with it (`clone3` creates the user namespace first and
//! the others inside it). Toward everything else (the host's files, a
//! network namespace it merely joined, the kernel's global knobs) it is an
//! unprivileged process.
//!
//! That relativity is what the rest of the runtime works around, and what
//! [`plan`] and [`check_mounts`] check before anything exists:
//!
//! * **procfs** can only be mounted by the owner of the PID namespace, so a
//!   user namespace needs a new PID namespace too;
//! * **sysfs** needs an owned network namespace; without one (`--net=host`)
//!   init binds the host's `/sys` instead ([`MountKind::HostSysfs`]);
//! * **mqueue** needs an owned IPC namespace, **cgroup2** an owned cgroup
//!   namespace, and `net.*` and IPC sysctls theirs (see `sysctl`);
//! * **device nodes** can't be created at all (`mknod` needs `CAP_MKNOD` in
//!   the initial user namespace), so `/dev` gets bind mounts of the host's
//!   nodes (see `rootfs::populate_dev`);
//! * **every id the container uses must be mapped**: uid and gid 0 (init
//!   becomes root of the namespace), the process's user and groups, the
//!   `uid=`/`gid=` options of filesystems such as devpts.
//!
//! One thing OCI permits is refused here: mapping host uid or gid 0 into the
//! container. Container root would then be host root to everything that
//! checks *ids* rather than capabilities (sysctl files, for one, are
//! writable by host uid 0, and a read-only `/proc/sys` is one mount option
//! away for a container with `CAP_SYS_ADMIN`), and the point of the remap is
//! that it isn't.
//!
//! ## The order of events
//!
//! ```text
//!  parent (host root)                        container init
//!  ──────────────────                        ──────────────
//!  clone3(CLONE_NEWUSER | CLONE_NEW* …) ───► born in the new user namespace,
//!                                            still host uid 0, which the
//!                                            namespace doesn't map ("nobody")
//!  write /proc/<pid>/uid_map, gid_map        waits for Proceed
//!  idmap the pre-opened bind mounts
//!  prlimit + oom_score_adj on init
//!  send Proceed ───────────────────────────► become_root(): setresgid/setresuid(0)
//!                                            … the usual setup …
//! ```
//!
//! The parent writes the maps because only a process in the *parent* user
//! namespace, with `CAP_SETUID`/`CAP_SETGID` there, may map host ids it isn't
//! itself. Rootless mode (Phase 8) will hand the same job to the setuid
//! helpers `newuidmap`/`newgidmap`: that is the [`IdMapper`] seam.
//! `setgroups` is left at `allow`, which the kernel keeps for a privileged
//! writer, so the container's supplementary groups still work.

use std::path::Path;

use nix::fcntl::OFlag;
use nix::sys::stat::Mode;
use nix::unistd::{Gid, Pid, Uid};
use oci_spec::runtime::{Linux, LinuxIdMapping};
use rustlet_sys::process::CloneFlags;

use crate::error::{Context, Error, Result, Unsupported};
use crate::mounts::{FsOption, MountEntry, MountKind};
use crate::namespaces::NamespacePlan;
use crate::plan::ProcessPlan;

/// One line of a `uid_map` or `gid_map`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdMap {
    /// The first id inside the namespace.
    pub container: u32,
    /// The host id it stands for.
    pub host: u32,
    /// How many consecutive ids the line maps.
    pub size: u32,
}

impl IdMap {
    fn from_spec(m: &LinuxIdMapping) -> IdMap {
        IdMap { container: m.container_id(), host: m.host_id(), size: m.size() }
    }

    fn to_host(self, id: u32) -> Option<u32> {
        let offset = id.checked_sub(self.container)?;
        (offset < self.size).then(|| self.host + offset)
    }
}

/// Converts OCI mappings (unvalidated: `validate` checks them).
pub(crate) fn from_spec(maps: &[LinuxIdMapping]) -> Vec<IdMap> {
    maps.iter().map(IdMap::from_spec).collect()
}

/// The container's user namespace: its uid and gid maps, validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsernsPlan {
    pub uids: Vec<IdMap>,
    pub gids: Vec<IdMap>,
}

impl UsernsPlan {
    /// The host uid that container uid `id` stands for, if it is mapped.
    pub fn uid_to_host(&self, id: u32) -> Option<u32> {
        self.uids.iter().find_map(|m| m.to_host(id))
    }

    /// The host gid that container gid `id` stands for, if it is mapped.
    pub fn gid_to_host(&self, id: u32) -> Option<u32> {
        self.gids.iter().find_map(|m| m.to_host(id))
    }

    /// The process's user and groups must exist in the namespace: the kernel
    /// refuses to switch to an unmapped id (`EINVAL`), and this says which
    /// one, before the container exists. `exec` checks its process too.
    pub fn check_process(&self, p: &ProcessPlan) -> Result<()> {
        if self.uid_to_host(p.uid).is_none() {
            return Err(Error::invalid(format!(
                "process.user.uid {} is not mapped in the container's user namespace (linux.uidMappings: {})",
                p.uid,
                map_text(&self.uids).trim_end().replace('\n', ", ")
            )));
        }
        for (what, gid) in
            std::iter::once(("gid", p.gid)).chain(p.additional_gids.iter().map(|g| ("additionalGids", *g)))
        {
            if self.gid_to_host(gid).is_none() {
                return Err(Error::invalid(format!(
                    "process.user.{what} {gid} is not mapped in the container's user namespace (linux.gidMappings: {})",
                    map_text(&self.gids).trim_end().replace('\n', ", ")
                )));
            }
        }
        Ok(())
    }
}

/// The most lines a map may have (the kernel's `UID_GID_MAP_MAX_EXTENTS`).
const MAX_EXTENTS: usize = 340;

/// Parent side, at plan time: `linux.uidMappings` and `gidMappings`, checked
/// against whether `linux.namespaces` asks for a new user namespace. `None`:
/// the container stays in the runtime's user namespace.
pub fn plan(linux: &Linux, ns: &NamespacePlan) -> Result<Option<UsernsPlan>> {
    let uids = linux.uid_mappings().as_deref().unwrap_or_default();
    let gids = linux.gid_mappings().as_deref().unwrap_or_default();
    if !ns.new_user() {
        if !uids.is_empty() || !gids.is_empty() {
            return Err(Error::invalid(
                "linux.uidMappings/gidMappings are set, but linux.namespaces has no new `user` namespace to apply \
                 them to (add {\"type\": \"user\"})",
            ));
        }
        return Ok(None);
    }
    if uids.is_empty() || gids.is_empty() {
        return Err(Error::invalid(
            "a new user namespace needs both linux.uidMappings and linux.gidMappings (without them every id in the \
             container would be `nobody`)",
        ));
    }
    let plan = UsernsPlan {
        uids: validate("uidMappings", &from_spec(uids))?,
        gids: validate("gidMappings", &from_spec(gids))?,
    };
    if plan.uid_to_host(0).is_none() || plan.gid_to_host(0).is_none() {
        return Err(Error::invalid(
            "linux.uidMappings and gidMappings must map id 0: container init becomes root of the user namespace to \
             set the container up",
        ));
    }
    if !ns.clone_flags.contains(CloneFlags::NEWPID) {
        return Err(Error::invalid(
            "a new user namespace needs a new `pid` namespace too: only the owner of a PID namespace may mount \
             its procfs, and the container's /proc must be one",
        ));
    }
    Ok(Some(plan))
}

/// Checks one map the way the kernel will, plus the host-root rule (see the
/// module docs), so that a bad map fails `create` with a reason rather than
/// an `EINVAL` from writing `/proc/<pid>/uid_map`.
fn validate(field: &str, maps: &[IdMap]) -> Result<Vec<IdMap>> {
    let bad = |why: String| Error::invalid(format!("linux.{field}: {why}"));
    if maps.len() > MAX_EXTENTS {
        return Err(bad(format!("{} lines; the kernel allows at most {MAX_EXTENTS}", maps.len())));
    }
    for m in maps {
        let line = format!("{} {} {}", m.container, m.host, m.size);
        if m.size == 0 {
            return Err(bad(format!("`{line}` maps no ids (size 0)")));
        }
        // u32::MAX is "no id" ((uid_t)-1), so a range may not reach it.
        if [m.container, m.host].iter().any(|first| u64::from(*first) + u64::from(m.size) > u64::from(u32::MAX)) {
            return Err(bad(format!("`{line}` runs past the largest id, {}", u32::MAX - 1)));
        }
        if m.host == 0 {
            return Err(bad(format!(
                "`{line}` maps host id 0, the host's root, into the container; map unused host ids instead \
                 (e.g. `0 {} {}`)",
                crate::spec::REMAP_HOST_ID,
                crate::spec::REMAP_SIZE
            )));
        }
    }
    let overlap = |a: u32, b: u32, a_size: u32, b_size: u32| {
        u64::from(a) < u64::from(b) + u64::from(b_size) && u64::from(b) < u64::from(a) + u64::from(a_size)
    };
    for (i, a) in maps.iter().enumerate() {
        for b in &maps[i + 1..] {
            for (side, x, y) in [("container", a.container, b.container), ("host", a.host, b.host)] {
                if overlap(x, y, a.size, b.size) {
                    return Err(bad(format!(
                        "`{} {} {}` and `{} {} {}` overlap on the {side} side",
                        a.container, a.host, a.size, b.container, b.host, b.size
                    )));
                }
            }
        }
    }
    Ok(maps.to_vec())
}

/// Plan time, for a container with a new user namespace (`userns` is
/// `Some`): the mounts that need an owned namespace get one, or a fallback,
/// or an error; ids in filesystem options must be mapped. For every
/// container: idmapped mounts need a user namespace to take the mapping from.
pub(crate) fn check_mounts(mounts: &mut [MountEntry], userns: Option<&UsernsPlan>, ns: &NamespacePlan) -> Result<()> {
    for m in mounts.iter_mut() {
        if let Some(idmap) = &m.idmap {
            let Some(u) = userns else {
                return Err(Error::invalid(format!(
                    "mount {}: `idmap` needs a new user namespace (the mount is idmapped with the container's \
                     uidMappings/gidMappings)",
                    m.describe()
                )));
            };
            let own = |given: &[IdMap], ours: &[IdMap]| given.is_empty() || given == ours;
            if !own(&idmap.uids, &u.uids) || !own(&idmap.gids, &u.gids) {
                return Err(Error::Unsupported(vec![Unsupported {
                    field: format!("mount {}: uidMappings/gidMappings other than the container's own", m.describe()),
                    when: "not planned",
                }]));
            }
        }
        let Some(u) = userns else { continue };
        let MountKind::Fs { fstype, options, .. } = &m.kind else { continue };
        let refuse = |why: &str| Err(Error::invalid(format!("mount {}: {why}", m.describe())));
        match fstype.as_str() {
            "mqueue" if !ns.clone_flags.contains(CloneFlags::NEWIPC) => {
                return refuse(
                    "with a user namespace, mqueue can only be mounted in a new `ipc` namespace (the kernel wants \
                     the IPC namespace's owner)",
                );
            }
            "cgroup2" if !ns.new_cgroup => {
                return refuse(
                    "with a user namespace, cgroup2 can only be mounted in a new `cgroup` namespace (the kernel \
                     wants the cgroup namespace's owner)",
                );
            }
            // Nothing to check but the ids below.
            _ => {}
        }
        for o in options {
            let FsOption::Value(key, value) = o else { continue };
            let key = key.as_str();
            if !matches!(key, "uid" | "gid") {
                continue;
            }
            let Ok(id) = value.parse::<u32>() else { continue };
            let mapped = if key == "uid" { u.uid_to_host(id) } else { u.gid_to_host(id) };
            if mapped.is_none() {
                return refuse(&format!(
                    "option `{key}={id}`: {key} {id} is not mapped in the container's user namespace (map it, or \
                     drop the option)"
                ));
            }
        }
        if fstype == "sysfs" && !ns.clone_flags.contains(CloneFlags::NEWNET) {
            // The kernel lets only the network namespace's owner mount sysfs.
            m.kind = MountKind::HostSysfs;
        }
    }
    Ok(())
}

/// The text of a map file: one `container host size` line per range.
fn map_text(maps: &[IdMap]) -> String {
    maps.iter().map(|m| format!("{} {} {}\n", m.container, m.host, m.size)).collect()
}

/// Writes the maps of a new user namespace, from the parent side.
///
/// A trait, because *who* may write them differs: the rootful runtime
/// writes the files itself ([`DirectIdMapper`]); rootless mode (Phase 8)
/// will ask `newuidmap`/`newgidmap`, which check `/etc/subuid` first.
pub trait IdMapper {
    /// Writes `pid`'s uid and gid maps. `pid` must be in a user namespace
    /// whose maps haven't been written yet (each can be written once).
    fn write(&self, pid: Pid, maps: &UsernsPlan) -> Result<()>;
}

/// Writes `/proc/<pid>/uid_map` and `gid_map` directly. Needs `CAP_SETUID`
/// and `CAP_SETGID` in the parent user namespace: a rootful runtime.
#[derive(Debug, Clone, Copy, Default)]
pub struct DirectIdMapper;

impl IdMapper for DirectIdMapper {
    fn write(&self, pid: Pid, maps: &UsernsPlan) -> Result<()> {
        write_map(pid, "uid_map", &maps.uids)?;
        write_map(pid, "gid_map", &maps.gids)
    }
}

/// One `write(2)` with every line: the kernel takes a map exactly once, in
/// one piece, at offset 0.
fn write_map(pid: Pid, file: &str, maps: &[IdMap]) -> Result<()> {
    let text = map_text(maps);
    let path = format!("/proc/{pid}/{file}");
    let shown = || format!("write {path} ({})", text.trim_end().replace('\n', ", "));
    let fd = nix::fcntl::open(Path::new(&path), OFlag::O_WRONLY | OFlag::O_CLOEXEC, Mode::empty())
        .with_context(|| format!("open {path}"))?;
    let n = nix::unistd::write(&fd, text.as_bytes()).with_context(shown)?;
    if n != text.len() {
        return Err(Error::Init {
            message: format!("{}: short write ({n} of {} bytes)", shown(), text.len()),
            errno: None,
        });
    }
    Ok(())
}

/// In a user namespace just created (`clone3`) or joined (`setns`): become
/// its root.
///
/// Until now the process kept its host ids, and host 0 isn't mapped: to the
/// namespace we are the overflow id, `nobody`, and a file we created would
/// have an owner the kernel can't write down (`EOVERFLOW`). The namespace's
/// capabilities (all of them, from `clone3` or `setns`) allow switching to
/// ids that *are* mapped, and moving to the namespace's root keeps them. The
/// host's supplementary groups go too: they aren't mapped either.
pub(crate) fn become_root() -> Result<()> {
    nix::unistd::setgroups(&[]).context("setgroups([]) in the user namespace")?;
    let (gid, uid) = (Gid::from_raw(0), Uid::from_raw(0));
    nix::unistd::setresgid(gid, gid, gid).context("setresgid(0) in the user namespace")?;
    nix::unistd::setresuid(uid, uid, uid).context("setresuid(0) in the user namespace")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(container: u32, host: u32, size: u32) -> IdMap {
        IdMap { container, host, size }
    }

    #[test]
    fn ids_map_through_the_ranges() {
        let u =
            UsernsPlan { uids: vec![m(0, 1_000_000, 1000), m(1000, 2_000_000, 1)], gids: vec![m(0, 1_000_000, 65536)] };
        assert_eq!(u.uid_to_host(0), Some(1_000_000));
        assert_eq!(u.uid_to_host(999), Some(1_000_999));
        assert_eq!(u.uid_to_host(1000), Some(2_000_000));
        assert_eq!(u.uid_to_host(1001), None);
        assert_eq!(u.gid_to_host(65535), Some(1_065_535));
        assert_eq!(u.gid_to_host(65536), None);
        assert_eq!(map_text(&u.uids), "0 1000000 1000\n1000 2000000 1\n");
    }

    #[test]
    fn maps_are_checked_like_the_kernel_does() {
        validate("uidMappings", &[m(0, 1_000_000, 65536)]).unwrap();
        validate("uidMappings", &[m(0, 1_000_000, 1), m(1, 2_000_000, 10)]).unwrap();
        // The last usable id is u32::MAX - 1 ((uid_t)-1 means "none").
        validate("uidMappings", &[m(0, 1_000_000, 1), m(u32::MAX - 1, 5, 1)]).unwrap();
        let bad = [
            (vec![m(0, 1_000_000, 0)], "size 0"),
            (vec![m(0, u32::MAX - 10, 11)], "largest id"),
            (vec![m(u32::MAX - 1, 5, 2)], "largest id"),
            (vec![m(0, 0, 65536)], "host id 0"),
            (vec![m(0, 1_000_000, 10), m(5, 2_000_000, 10)], "container side"),
            (vec![m(0, 1_000_000, 10), m(100, 1_000_005, 10)], "host side"),
            ((0..341).map(|i| m(i, 1_000_000 + i, 1)).collect(), "at most 340"),
        ];
        for (maps, why) in bad {
            let msg = validate("uidMappings", &maps).unwrap_err().to_string();
            assert!(msg.contains(why), "{maps:?}: {msg}");
        }
    }
}

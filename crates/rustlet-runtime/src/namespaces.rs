//! Namespaces: which ones to create, which ones to join, and the safety
//! check that guards every mount the runtime makes.
//!
//! In `config.json`, `linux.namespaces` lists namespace *types*:
//!
//! ```json
//! [ {"type": "pid"}, {"type": "network", "path": "/run/netns/web"}, {"type": "mount"} ]
//! ```
//!
//! * listed without `path`: the container gets a **new** namespace of that type;
//! * listed with `path`: the container **joins** that existing namespace
//!   (`setns`), e.g. `--net=container:web`;
//! * not listed: the container **shares** the runtime's namespace, e.g.
//!   `--pid=host`.
//!
//! Three types get special treatment:
//!
//! * **mount** must always be new. Joining one, or sharing the host's, would
//!   let `pivot_root` and the container's mounts land in someone else's
//!   mount table. `rustlet-runc` refuses such specs up front, and container
//!   init re-checks at run time ([`assert_new_mount_ns`]) before touching a
//!   single mount.
//! * **cgroup** is not passed to `clone3`. A new cgroup namespace is rooted at
//!   the cgroup the process is in *when the namespace is created*, so the
//!   child calls `unshare(CLONE_NEWCGROUP)` itself, after `CLONE_INTO_CGROUP`
//!   has placed it. (runc reasons that `clone3` would copy namespaces before
//!   placing the child; on this 7.0 kernel a combined `clone3` gets it right
//!   too, see `docs/learn/04-cgroups-v2.md`. Unsharing after placement is
//!   correct on every kernel either way.)
//! * **user** can only be new (see `userns`). `clone3` creates it *first*,
//!   so every other new namespace is owned by it, which is what gives
//!   container root its capabilities over them. Joining one by path is
//!   refused: the parent would have to `setns` into it before `clone3`, and
//!   would lose its host privileges for everything it still has to do.

use std::os::fd::AsFd;
use std::path::PathBuf;

use oci_spec::runtime::{LinuxNamespace, LinuxNamespaceType};
use rustlet_sys::process::{self, CloneFlags};
use rustlet_sys::procfs;

use crate::error::{Context, Error, Result, Unsupported};

/// A namespace to join by path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Join {
    pub kind: CloneFlags,
    pub path: PathBuf,
}

/// The namespace part of a [`Plan`](crate::Plan).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespacePlan {
    /// New namespaces for `clone3`. Never contains `NEWCGROUP`.
    pub clone_flags: CloneFlags,
    /// Whether the child should `unshare(CLONE_NEWCGROUP)`.
    pub new_cgroup: bool,
    /// Namespaces the parent joins with `setns` before `clone3`.
    pub joins: Vec<Join>,
}

impl NamespacePlan {
    /// Whether the container gets its own hostname.
    pub fn new_uts(&self) -> bool {
        self.clone_flags.contains(CloneFlags::NEWUTS)
    }

    /// Whether the container gets a user namespace of its own.
    pub fn new_user(&self) -> bool {
        self.clone_flags.contains(CloneFlags::NEWUSER)
    }
}

fn flag(t: LinuxNamespaceType) -> CloneFlags {
    match t {
        LinuxNamespaceType::Mount => CloneFlags::NEWNS,
        LinuxNamespaceType::Cgroup => CloneFlags::NEWCGROUP,
        LinuxNamespaceType::Uts => CloneFlags::NEWUTS,
        LinuxNamespaceType::Ipc => CloneFlags::NEWIPC,
        LinuxNamespaceType::User => CloneFlags::NEWUSER,
        LinuxNamespaceType::Pid => CloneFlags::NEWPID,
        LinuxNamespaceType::Network => CloneFlags::NEWNET,
        LinuxNamespaceType::Time => CloneFlags::NEWTIME,
    }
}

/// Validates `linux.namespaces` and splits it into "create" and "join".
pub fn plan(namespaces: &[LinuxNamespace]) -> Result<NamespacePlan> {
    let mut seen = CloneFlags::empty();
    let mut out = NamespacePlan { clone_flags: CloneFlags::empty(), new_cgroup: false, joins: Vec::new() };
    for ns in namespaces {
        let t = ns.typ();
        let f = flag(t);
        if seen.contains(f) {
            return Err(Error::invalid(format!("namespace `{t}` is listed twice")));
        }
        seen |= f;
        match (t, ns.path()) {
            (LinuxNamespaceType::User, Some(_)) => {
                return Err(Error::Unsupported(vec![Unsupported {
                    field: "linux.namespaces: joining a user namespace by path".into(),
                    when: "not planned",
                }]));
            }
            (LinuxNamespaceType::Mount, Some(_)) => {
                return Err(Error::invalid(
                    "joining a mount namespace by path is not allowed: the container's mounts and \
                     pivot_root would land in that namespace",
                ));
            }
            (LinuxNamespaceType::Cgroup, None) => out.new_cgroup = true,
            (_, None) => out.clone_flags |= f,
            (_, Some(path)) => out.joins.push(Join { kind: f, path: path.clone() }),
        }
    }
    if !seen.contains(CloneFlags::NEWNS) {
        return Err(Error::invalid(
            "linux.namespaces must include a new `mount` namespace: rustlets never runs a container in the \
             runtime's own mount namespace",
        ));
    }
    Ok(out)
}

/// Parent side: joins every namespace given by path. Must run before
/// `clone3` (a PID-namespace join only affects children created afterwards)
/// and while the process is single-threaded.
pub fn join_all(plan: &NamespacePlan) -> Result<()> {
    for j in &plan.joins {
        let fd = process::open_ns(&j.path).with_context(|| format!("open namespace {}", j.path.display()))?;
        // Passing the expected type makes the kernel check that `path`
        // really is a namespace of that kind (EINVAL otherwise).
        process::setns(fd.as_fd(), j.kind).with_context(|| format!("setns {:?} {}", j.kind, j.path.display()))?;
    }
    Ok(())
}

/// Identity of the calling process's mount namespace.
pub fn current_mnt_ns() -> Result<(u64, u64)> {
    procfs::ns_id(None, "mnt").context("read /proc/self/ns/mnt")
}

/// Identity of host init's mount namespace (`/proc/1/ns/mnt`), read by the
/// parent: container init, in a user namespace, may not look at PID 1's
/// namespaces.
pub fn host_init_mnt_ns() -> Result<(u64, u64)> {
    procfs::ns_id(Some(nix::unistd::Pid::from_raw(1)), "mnt").context("read /proc/1/ns/mnt")
}

/// Child side, **before any mount**: proves that this process is in a new
/// mount namespace, different both from the one `rustlet-runc` started in
/// and from host init's (both read by the parent). This check runs in
/// release builds too; it is the last line of defence for the host's mount
/// table.
pub fn assert_new_mount_ns(parent: (u64, u64), host_init: (u64, u64)) -> Result<()> {
    let me = current_mnt_ns()?;
    if me == parent || me == host_init {
        return Err(Error::Init {
            message: format!(
                "refusing to set up mounts: still in the host mount namespace (ns {me:?}, parent {parent:?}, pid 1 {host_init:?})"
            ),
            errno: None,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use oci_spec::runtime::{LinuxNamespaceBuilder, get_default_namespaces};

    fn ns(t: LinuxNamespaceType, path: Option<&str>) -> LinuxNamespace {
        let b = LinuxNamespaceBuilder::default().typ(t);
        match path {
            Some(p) => b.path(p).build().unwrap(),
            None => b.build().unwrap(),
        }
    }

    #[test]
    fn default_namespaces_are_all_new_and_cgroup_is_deferred() {
        let p = plan(&get_default_namespaces()).unwrap();
        assert_eq!(
            p.clone_flags,
            CloneFlags::NEWPID | CloneFlags::NEWNET | CloneFlags::NEWIPC | CloneFlags::NEWUTS | CloneFlags::NEWNS
        );
        assert!(p.new_cgroup);
        assert!(p.joins.is_empty());
        assert!(p.new_uts());
    }

    #[test]
    fn paths_become_joins_and_missing_types_are_shared() {
        let p = plan(&[ns(LinuxNamespaceType::Mount, None), ns(LinuxNamespaceType::Network, Some("/proc/1/ns/net"))])
            .unwrap();
        assert_eq!(p.clone_flags, CloneFlags::NEWNS);
        assert_eq!(p.joins, vec![Join { kind: CloneFlags::NEWNET, path: "/proc/1/ns/net".into() }]);
        assert!(!p.new_uts());
    }

    #[test]
    fn mount_namespace_rules() {
        assert!(plan(&[ns(LinuxNamespaceType::Pid, None)]).is_err(), "no mount ns");
        assert!(plan(&[ns(LinuxNamespaceType::Mount, Some("/proc/1/ns/mnt"))]).is_err(), "join mount ns");
        assert!(plan(&[ns(LinuxNamespaceType::Mount, None), ns(LinuxNamespaceType::Mount, None)]).is_err(), "dup");
    }

    #[test]
    fn user_namespaces_are_new_or_refused() {
        let p = plan(&[ns(LinuxNamespaceType::Mount, None), ns(LinuxNamespaceType::User, None)]).unwrap();
        assert!(p.new_user());
        assert_eq!(p.clone_flags, CloneFlags::NEWNS | CloneFlags::NEWUSER);
        let e = plan(&[ns(LinuxNamespaceType::Mount, None), ns(LinuxNamespaceType::User, Some("/proc/1/ns/user"))])
            .unwrap_err();
        assert!(matches!(e, Error::Unsupported(_)), "{e}");
    }
}

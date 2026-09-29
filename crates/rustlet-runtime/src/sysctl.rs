//! `linux.sysctl`: kernel parameters for the container's namespaces.
//!
//! A sysctl is a file under `/proc/sys`: `net.ipv4.ip_forward` is
//! `/proc/sys/net/ipv4/ip_forward`. Most of them are **global**, one value
//! for the whole machine (`vm.swappiness`, `kernel.core_pattern`), and a
//! container that sets one changes the host. A few are **per namespace**:
//! the kernel looks the value up in the *writer's* namespace of some type,
//! so a container with its own namespace of that type gets its own copy.
//! Only those are allowed here, the same list runc allows:
//!
//! | keys                                              | namespace |
//! |---------------------------------------------------|-----------|
//! | `kernel.msgmax`, `msgmnb`, `msgmni`, `sem`, `shmall`, `shmmax`, `shmmni`, `shm_rmid_forced`; `fs.mqueue.*` | IPC |
//! | `net.*`                                           | network   |
//! | `kernel.domainname`                               | UTS       |
//!
//! `kernel.hostname` is per-UTS too, but the spec has a `hostname` field for
//! it, and two sources for one value is one too many.
//!
//! `net.*` is allowed as a prefix even though some `net.core.*` knobs are
//! global. The kernel protects those itself: inside a new network namespace
//! they are either missing (`bpf_jit_enable`, `netdev_max_backlog`: the write
//! fails with `ENOENT`) or shown read-only (`rmem_max`, mode 0444 on Linux
//! 7.0: `EACCES`), so the write fails instead of reaching the host.
//!
//! With a user namespace, "its own" gets stricter: the kernel lets container
//! root write a namespaced sysctl only if its user namespace *owns* that
//! namespace, which only the new ones are (a joined network namespace
//! belongs to whoever created it). And `kernel.domainname` can't be set at
//! all: UTS sysctls check for *host* root, which container root isn't (the
//! spec's `domainname` field still works; it is a syscall).
//!
//! [`plan`] checks all this in `rustlet-runc`, before the container exists.
//! [`apply`] then writes the values from container init (which is in the
//! container's namespaces, so the kernel picks the container's copy),
//! through a [`ProcHandle`] rather than the container's `/proc`.

use std::collections::HashMap;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use rustlet_sys::process::CloneFlags;
use rustlet_sys::procfs;

use crate::error::{Context, Error, Result};
use crate::namespaces::NamespacePlan;
use crate::proc_handle::ProcHandle;

/// One validated sysctl.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sysctl {
    /// As written in `config.json`, e.g. `net.ipv4.ip_forward`.
    pub key: String,
    /// Relative to `/proc/sys`, e.g. `net/ipv4/ip_forward`.
    pub path: PathBuf,
    pub value: String,
}

/// Parent side, at plan time: validates every key against the namespaces
/// the container gets, sorted by key.
///
/// Keys are checked in sorted order too, so the error for a config with
/// several bad keys is always about the same one.
pub fn plan(sysctl: &HashMap<String, String>, ns: &NamespacePlan) -> Result<Vec<Sysctl>> {
    let mut keys: Vec<&String> = sysctl.keys().collect();
    keys.sort();
    let mut out = Vec::with_capacity(keys.len());
    for key in keys {
        let value = &sysctl[key];
        let parts = components(key)?;
        if value.contains('\0') {
            return Err(Error::invalid(format!("sysctl {key}: the value contains a NUL byte")));
        }
        let kind = namespace_of(key, &parts)?;
        check_own_namespace(key, kind, ns)?;
        out.push(Sysctl { key: key.clone(), path: parts.iter().collect(), value: value.clone() });
    }
    Ok(out)
}

/// Container init, after `pivot_root` and before `/proc/sys` becomes
/// read-only: writes each value through the private procfs handle.
///
/// (Strictly, the order no longer matters: `readonlyPaths` makes the
/// *container's* `/proc/sys` mount read-only, while the handle is a mount of
/// its own. But init must still be root, and in the container's namespaces.)
pub(crate) fn apply(proc: &ProcHandle, list: &[Sysctl]) -> Result<()> {
    for s in list {
        proc.write(&Path::new("sys").join(&s.path), &s.value)
            .map_err(|e| with_prefix(e, &format!("sysctl {}={}", s.key, s.value)))?;
    }
    Ok(())
}

/// Puts `prefix` in front of an error's context ("sysctl a.b=1: write
/// /proc/sys/a/b: EINVAL"), keeping the errno.
fn with_prefix(e: Error, prefix: &str) -> Error {
    match e {
        Error::Sys { context, errno } => Error::Sys { context: format!("{prefix}: {context}"), errno },
        Error::Io { context, err } => Error::Io { context: format!("{prefix}: {context}"), err },
        other => other,
    }
}

/// Splits a key into path components, the way `sysctl(8)` does: on `/` if
/// the key has one, else on `.`. The slash form exists for names that
/// contain dots themselves, like a VLAN interface in
/// `net/ipv4/conf/eth0.100/forwarding` (as dots, that would be
/// `.../eth0/100/...`, a different and non-existent file).
///
/// Every component must be a plain name: `..` would climb out of
/// `/proc/sys` (`net/../kernel/core_pattern` *looks* like a network sysctl),
/// and empty or `.` components mean the key isn't what it seems either.
fn components(key: &str) -> Result<Vec<&str>> {
    if key.contains('\0') {
        return Err(Error::invalid(format!("sysctl {key:?}: the key contains a NUL byte")));
    }
    let sep = if key.contains('/') { '/' } else { '.' };
    let parts: Vec<&str> = key.split(sep).collect();
    if let Some(bad) = parts.iter().find(|p| matches!(**p, "" | "." | "..")) {
        return Err(Error::invalid(format!(
            "sysctl {key:?}: invalid key (component {bad:?}; keys look like net.ipv4.ip_forward or net/ipv4/ip_forward)"
        )));
    }
    Ok(parts)
}

/// A namespace type a sysctl can belong to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Ipc,
    Net,
    Uts,
}

impl Kind {
    fn flag(self) -> CloneFlags {
        match self {
            Kind::Ipc => CloneFlags::NEWIPC,
            Kind::Net => CloneFlags::NEWNET,
            Kind::Uts => CloneFlags::NEWUTS,
        }
    }

    /// The name in `/proc/<pid>/ns/`.
    fn proc_name(self) -> &'static str {
        match self {
            Kind::Ipc => "ipc",
            Kind::Net => "net",
            Kind::Uts => "uts",
        }
    }

    /// The `type` in `linux.namespaces`.
    fn spec_name(self) -> &'static str {
        match self {
            Kind::Ipc => "ipc",
            Kind::Net => "network",
            Kind::Uts => "uts",
        }
    }
}

/// The System V IPC sysctls, which live in each IPC namespace.
const IPC_KERNEL_KEYS: [&str; 8] =
    ["msgmax", "msgmnb", "msgmni", "sem", "shmall", "shmmax", "shmmni", "shm_rmid_forced"];

/// Which namespace makes `key` (split into `parts`) per-container, or why
/// it can't be set at all.
fn namespace_of(key: &str, parts: &[&str]) -> Result<Kind> {
    match parts {
        ["kernel", k] if IPC_KERNEL_KEYS.contains(k) => Ok(Kind::Ipc),
        ["fs", "mqueue", _, ..] => Ok(Kind::Ipc),
        ["net", _, ..] => Ok(Kind::Net),
        ["kernel", "domainname"] => Ok(Kind::Uts),
        ["kernel", "hostname"] => {
            Err(Error::invalid(format!("sysctl {key} is not allowed: set the spec's `hostname` field instead")))
        }
        _ => Err(Error::invalid(format!(
            "sysctl {key} is not allowed: it is not namespaced, so setting it would change the host's kernel \
             for everyone (only IPC sysctls (kernel.msg*, kernel.sem, kernel.shm*, fs.mqueue.*), net.* and \
             kernel.domainname can be set per container)"
        ))),
    }
}

/// Refuses `key` unless the container gets a `kind` namespace of its own.
///
/// "Its own" means: a new one, or one joined by path that is not the one
/// `rustlet-runc` itself runs in; with a user namespace, only a new one (see
/// the module docs). (Like runc, "the host" here is the
/// *current* namespace, not the initial one: nested inside another container
/// that is the right notion, since it is the namespace we would be changing.)
/// A type not listed in `linux.namespaces` at all is shared with us.
fn check_own_namespace(key: &str, kind: Kind, ns: &NamespacePlan) -> Result<()> {
    if ns.new_user() && kind == Kind::Uts {
        return Err(Error::invalid(format!(
            "sysctl {key} can't be set in a container with a user namespace: the kernel only lets host root write \
             UTS sysctls (set the spec's `domainname` field instead)"
        )));
    }
    if ns.clone_flags.contains(kind.flag()) {
        return Ok(());
    }
    let name = kind.spec_name();
    if ns.new_user() {
        return Err(Error::invalid(format!(
            "sysctl {key} needs a new {name} namespace: with a user namespace, container root may only change \
             sysctls of namespaces created with it (add {{\"type\": \"{name}\"}} to linux.namespaces, without a path)"
        )));
    }
    let Some(join) = ns.joins.iter().find(|j| j.kind == kind.flag()) else {
        return Err(Error::invalid(format!(
            "sysctl {key} needs the container to have its own {name} namespace, but it shares the host's \
             (add {{\"type\": \"{name}\"}} to linux.namespaces)"
        )));
    };
    // A namespace's identity is the (device, inode) of its nsfs file.
    // `metadata` follows the `/proc/<pid>/ns/*` link to that file.
    let joined = std::fs::metadata(&join.path).with_context(|| format!("stat namespace {}", join.path.display()))?;
    let ours =
        procfs::ns_id(None, kind.proc_name()).with_context(|| format!("read /proc/self/ns/{}", kind.proc_name()))?;
    if (joined.dev(), joined.ino()) == ours {
        return Err(Error::invalid(format!(
            "sysctl {key} needs the container to have its own {name} namespace, but {} is the host's",
            join.path.display()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::namespaces::Join;

    /// Namespaces: a new mount namespace plus `extra`.
    fn ns(extra: CloneFlags, joins: Vec<Join>) -> NamespacePlan {
        NamespacePlan { clone_flags: CloneFlags::NEWNS | extra, new_cgroup: false, joins }
    }

    fn all_new() -> NamespacePlan {
        ns(CloneFlags::NEWIPC | CloneFlags::NEWNET | CloneFlags::NEWUTS | CloneFlags::NEWPID, vec![])
    }

    fn one(key: &str, value: &str, ns: &NamespacePlan) -> Result<Vec<Sysctl>> {
        plan(&HashMap::from([(key.to_owned(), value.to_owned())]), ns)
    }

    #[test]
    fn allowed_with_their_own_namespaces() {
        let n = all_new();
        for key in [
            "kernel.msgmax",
            "kernel.shm_rmid_forced",
            "fs.mqueue.msg_max",
            "net.ipv4.ip_forward",
            "net.core.somaxconn",
            "kernel.domainname",
        ] {
            one(key, "1", &n).unwrap_or_else(|e| panic!("{key}: {e}"));
        }
    }

    #[test]
    fn refused_when_the_namespace_is_shared() {
        let none = ns(CloneFlags::empty(), vec![]);
        for (key, kind) in [
            ("kernel.sem", "ipc"),
            ("fs.mqueue.queues_max", "ipc"),
            ("net.ipv4.ip_forward", "network"),
            ("kernel.domainname", "uts"),
        ] {
            let msg = one(key, "1", &none).unwrap_err().to_string();
            assert!(msg.contains(key) && msg.contains(&format!("own {kind} namespace")), "{msg}");
        }
        // Having *other* namespaces doesn't help.
        let only_net = ns(CloneFlags::NEWNET, vec![]);
        assert!(one("kernel.shmmax", "1", &only_net).is_err());
        one("net.ipv4.ip_forward", "1", &only_net).unwrap();
    }

    #[test]
    fn never_allowed() {
        let n = all_new();
        for key in [
            "vm.swappiness",
            "kernel.core_pattern",
            "kernel/core_pattern",
            "fs.file-max",
            "kernel.msg",
            "net",
            "fs.mqueue",
        ] {
            let msg = one(key, "1", &n).unwrap_err().to_string();
            assert!(msg.contains("not namespaced"), "{key}: {msg}");
        }
        let msg = one("kernel.hostname", "x", &n).unwrap_err().to_string();
        assert!(msg.contains("`hostname` field"), "{msg}");
    }

    #[test]
    fn joined_namespaces_count_only_if_they_are_not_ours() {
        // Joining our own network namespace is sharing it with the host.
        let host = ns(CloneFlags::empty(), vec![Join { kind: CloneFlags::NEWNET, path: "/proc/self/ns/net".into() }]);
        let msg = one("net.ipv4.ip_forward", "1", &host).unwrap_err().to_string();
        assert!(msg.contains("/proc/self/ns/net is the host's"), "{msg}");
        // Any other nsfs file stands in for "some other network namespace"
        // here (it is the wrong type, which `setns` would catch later).
        let other = ns(CloneFlags::empty(), vec![Join { kind: CloneFlags::NEWNET, path: "/proc/self/ns/ipc".into() }]);
        one("net.ipv4.ip_forward", "1", &other).unwrap();
        // A join path that doesn't exist is an error, not "not the host".
        let gone = ns(CloneFlags::empty(), vec![Join { kind: CloneFlags::NEWNET, path: "/nonexistent/ns".into() }]);
        assert!(one("net.ipv4.ip_forward", "1", &gone).is_err());
    }

    #[test]
    fn with_a_user_namespace_only_new_namespaces_count() {
        let user = ns(CloneFlags::NEWUSER | CloneFlags::NEWIPC | CloneFlags::NEWUTS, vec![]);
        one("kernel.shmmax", "1024", &user).unwrap();
        // A joined network namespace belongs to someone else's user namespace.
        let joined = NamespacePlan {
            joins: vec![Join { kind: CloneFlags::NEWNET, path: "/proc/self/ns/ipc".into() }],
            ..user.clone()
        };
        let msg = one("net.ipv4.ip_forward", "1", &joined).unwrap_err().to_string();
        assert!(msg.contains("needs a new network namespace"), "{msg}");
        // UTS sysctls check for host root.
        let msg = one("kernel.domainname", "example", &user).unwrap_err().to_string();
        assert!(msg.contains("`domainname` field"), "{msg}");
    }

    #[test]
    fn keys_map_to_paths_and_come_out_sorted() {
        let list = plan(
            &HashMap::from([
                ("net.ipv4.ip_forward".to_owned(), "1".to_owned()),
                ("net/ipv4/conf/eth0.100/forwarding".to_owned(), "0".to_owned()),
                ("kernel.shmmax".to_owned(), "65536".to_owned()),
                ("net.ipv4.ip_local_port_range".to_owned(), "1024 65000".to_owned()),
            ]),
            &all_new(),
        )
        .unwrap();
        let got: Vec<(&str, &Path, &str)> =
            list.iter().map(|s| (s.key.as_str(), s.path.as_path(), s.value.as_str())).collect();
        assert_eq!(
            got,
            [
                ("kernel.shmmax", Path::new("kernel/shmmax"), "65536"),
                ("net.ipv4.ip_forward", Path::new("net/ipv4/ip_forward"), "1"),
                ("net.ipv4.ip_local_port_range", Path::new("net/ipv4/ip_local_port_range"), "1024 65000"),
                // Slash form: the dot in `eth0.100` is part of the name.
                ("net/ipv4/conf/eth0.100/forwarding", Path::new("net/ipv4/conf/eth0.100/forwarding"), "0"),
            ]
        );
    }

    #[test]
    fn bad_keys_and_values() {
        let n = all_new();
        for key in [
            "",
            "net..ipv4",
            "net.ipv4.",
            ".net.ipv4",
            "net/../kernel/core_pattern",
            "net/./ipv4",
            "/net/ipv4/ip_forward",
            "net.ip\0v4",
        ] {
            let msg = one(key, "1", &n).unwrap_err().to_string();
            assert!(msg.contains("invalid key") || msg.contains("NUL"), "{key:?}: {msg}");
        }
        assert!(one("net.ipv4.ip_forward", "1\0", &n).unwrap_err().to_string().contains("NUL"));
    }
}

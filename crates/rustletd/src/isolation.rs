//! `GET /v1/containers/{id}/isolation`: what separates a running container
//! from the host (`rustlet_spec::isolation`), for the desktop app's isolation
//! inspector.
//!
//! Three sources, read in this order:
//!
//! 1. **The kernel's view of the init process** (`/proc/<pid>`): `ns/*` (the
//!    namespaces' inodes), `status` (capability sets, ids, `NoNewPrivs`,
//!    seccomp mode), `uid_map`/`gid_map`, `oom_score_adj`. The pid comes
//!    from the container's state, so first `/proc/<pid>/cgroup` must name
//!    the container's cgroup: a pid the kernel has given to another process
//!    since the container exited would describe something else.
//! 2. **The run's `config.json`**, as the daemon wrote it for the runtime:
//!    which namespaces were made and which joined, the seccomp profile,
//!    masked and read-only paths, the mounts, the device rules.
//! 3. **The cgroup**: limits beside usage.
//!
//! "The host" is the daemon's own namespaces (`/proc/self/ns/*`): what
//! `--network host` means. The installed service runs in the host's; a test
//! daemon in a network namespace of its own compares against that one.

use std::collections::BTreeMap;

use rustlet_runtime::cgroups::devices::{DevType, DeviceFilter, Origin};
use rustlet_runtime::cgroups::{Cgroup, CgroupPath, stats};
use rustlet_runtime::oci_spec::runtime::{Linux, LinuxDeviceType, LinuxSeccomp, Spec};
use rustlet_spec::isolation::{
    Capabilities, CgroupUsage, Credentials, DeviceRule, DeviceRuleOrigin, Filesystem, IdMapping, Isolation, MountEntry,
    NAMESPACE_KINDS, Namespace, NamespaceMode, Seccomp, SeccompMode, SeccompProfile, SeccompRule,
};
use rustlet_sys::caps::{Cap, CapSet};

use crate::container::Container;
use crate::daemon::Daemon;
use crate::error::{ApiError, ApiResult};

pub fn report(d: &Daemon, c: &Container) -> ApiResult<Isolation> {
    let st = c.persisted().state;
    let not_running = || ApiError::conflict(format!("container {} is not running", c.record.name));
    let pid = match st.pid {
        Some(pid) if st.status.is_live() => pid,
        _ => return Err(not_running()),
    };
    let proc_dir = format!("/proc/{pid}");
    let cgroup = c.cgroup(&d.cgroup_parent);
    let read = |file: &str| std::fs::read_to_string(format!("{proc_dir}/{file}")).map_err(|_| not_running());
    if !in_cgroup(&read("cgroup")?, &cgroup) {
        return Err(not_running());
    }
    let status = parse_status(&read("status")?);
    let spec: Spec = {
        let path = d.paths.container_dir(c.id()).join("config.json");
        let bytes = std::fs::read(&path).map_err(|e| ApiError::internal(format!("read {}: {e}", path.display())))?;
        serde_json::from_slice(&bytes).map_err(|e| ApiError::internal(format!("parse {}: {e}", path.display())))?
    };

    // Every other running container's namespaces, to say who shares which.
    let others: Vec<(String, BTreeMap<&str, u64>)> = d
        .all_containers()
        .into_iter()
        .filter(|o| o.id() != c.id())
        .filter_map(|o| {
            let st = o.persisted().state;
            let pid = st.pid.filter(|_| st.status.is_live())?;
            Some((o.record.name.clone(), namespace_inodes(&format!("/proc/{pid}"))))
        })
        .collect();
    let own = namespace_inodes(&proc_dir);
    let host = namespace_inodes("/proc/self");
    let modes = namespace_modes(&spec);
    let namespaces: Vec<Namespace> = NAMESPACE_KINDS
        .iter()
        .map(|&kind| {
            let inode = own.get(kind).copied().unwrap_or(0);
            let host_inode = host.get(kind).copied().unwrap_or(0);
            let (mode, path) = modes.get(kind).cloned().unwrap_or((NamespaceMode::Host, None));
            Namespace {
                kind: kind.to_owned(),
                mode,
                path,
                inode,
                host_inode,
                shared_with_host: inode != 0 && inode == host_inode,
                shared_with: others
                    .iter()
                    .filter(|(_, ns)| inode != 0 && ns.get(kind) == Some(&inode))
                    .map(|(name, _)| name.clone())
                    .collect(),
            }
        })
        .collect();
    let own_userns = namespaces.iter().any(|n| n.kind == "user" && !n.shared_with_host);
    let (uid_map, gid_map) = if own_userns {
        (parse_id_map(&read("uid_map")?), parse_id_map(&read("gid_map")?))
    } else {
        (Vec::new(), Vec::new())
    };

    // The process's ids now, not config.json's user: an entrypoint may have
    // dropped to another (`su-exec`, `gosu`). `status` shows them as the
    // daemon, so the host, sees them.
    let effective =
        |key: &str| status.get(key).and_then(|v| v.split_whitespace().nth(1)).and_then(|v| v.parse().ok()).unwrap_or(0);
    let (host_uid, host_gid) = (effective("Uid"), effective("Gid"));
    let groups = status.get("Groups").map(String::as_str).unwrap_or_default();
    let credentials = Credentials {
        uid: inside(host_uid, &uid_map),
        gid: inside(host_gid, &gid_map),
        additional_gids: groups
            .split_whitespace()
            .filter_map(|g| g.parse().ok())
            .map(|g| inside(g, &gid_map))
            .collect(),
        host_uid,
        host_gid,
    };
    let caps = |key: &str| cap_names(status.get(key).map(String::as_str).unwrap_or("0"));
    let capabilities = Capabilities {
        effective: caps("CapEff"),
        permitted: caps("CapPrm"),
        inheritable: caps("CapInh"),
        bounding: caps("CapBnd"),
        ambient: caps("CapAmb"),
        known: (0..=rustlet_sys::caps::last_cap().0).map(|n| Cap(n).name()).collect(),
    };
    let linux = spec.linux().clone().unwrap_or_default();
    let seccomp = Seccomp {
        mode: match status.get("Seccomp").map(String::as_str) {
            Some("1") => SeccompMode::Strict,
            Some("2") => SeccompMode::Filter,
            _ => SeccompMode::Disabled,
        },
        filters: status.get("Seccomp_filters").and_then(|v| v.parse().ok()).unwrap_or(0),
        no_new_privs: status.get("NoNewPrivs").map(String::as_str) == Some("1"),
        profile: linux.seccomp().as_ref().map(seccomp_profile),
    };
    let root = spec.root().clone().unwrap_or_default();
    let filesystem = Filesystem {
        rootfs: root.path().display().to_string(),
        read_only: root.readonly().unwrap_or(false),
        masked_paths: linux.masked_paths().clone().unwrap_or_default(),
        readonly_paths: linux.readonly_paths().clone().unwrap_or_default(),
        mounts: spec
            .mounts()
            .iter()
            .flatten()
            .map(|m| MountEntry {
                destination: m.destination().display().to_string(),
                kind: m.typ().clone().unwrap_or_default(),
                source: m.source().as_ref().map(|s| s.display().to_string()).unwrap_or_default(),
                options: m.options().clone().unwrap_or_default(),
            })
            .collect(),
    };
    let devices = device_rules(&linux, own_userns);
    Ok(Isolation {
        id: c.id().to_owned(),
        name: c.record.name.clone(),
        pid,
        namespaces,
        uid_map,
        gid_map,
        credentials,
        capabilities,
        seccomp,
        filesystem,
        devices,
        cgroup: cgroup_usage(&cgroup),
        oom_score_adj: read("oom_score_adj")?.trim().parse().unwrap_or(0),
    })
}

/// The rules of the filter the runtime built for `linux`
/// (`DeviceFilter::build`, the same call): the configuration's, then the
/// defaults, then `m` for each char or block node init creates (none in a
/// user namespace, where nodes are bind mounts of the host's).
fn device_rules(linux: &Linux, userns: bool) -> Vec<DeviceRule> {
    let config = linux.resources().as_ref().and_then(|r| r.devices().clone()).unwrap_or_default();
    let nodes: Vec<(usize, DevType, u32, u32)> = if userns {
        Vec::new()
    } else {
        linux
            .devices()
            .iter()
            .flatten()
            .enumerate()
            .filter_map(|(i, d)| {
                let typ = match d.typ() {
                    LinuxDeviceType::B => DevType::Block,
                    LinuxDeviceType::C | LinuxDeviceType::U => DevType::Char,
                    _ => return None,
                };
                Some((i, typ, u32::try_from(d.major()).ok()?, u32::try_from(d.minor()).ok()?))
            })
            .collect()
    };
    let Ok(filter) = DeviceFilter::build(&config, &nodes) else {
        return Vec::new();
    };
    filter
        .rules
        .iter()
        .map(|r| DeviceRule {
            allow: r.allow,
            kind: r.typ.map_or('a', DevType::letter).to_string(),
            major: r.major,
            minor: r.minor,
            access: r.access.to_string(),
            origin: match r.origin {
                Origin::Spec(_) => DeviceRuleOrigin::Config,
                Origin::Default => DeviceRuleOrigin::Default,
                Origin::Node(_) => DeviceRuleOrigin::Node,
            },
        })
        .collect()
}

/// Does `/proc/<pid>/cgroup` (`0::/path`) put the process in `cgroup` or
/// below it?
fn in_cgroup(text: &str, cgroup: &str) -> bool {
    text.lines()
        .filter_map(|l| l.strip_prefix("0::"))
        .any(|path| path == cgroup || path.strip_prefix(cgroup).is_some_and(|rest| rest.starts_with('/')))
}

/// `/proc/<pid>/status` as `key → value` (`CapEff → 000001ffffffffff`).
fn parse_status(text: &str) -> BTreeMap<String, String> {
    text.lines().filter_map(|l| l.split_once(':')).map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned())).collect()
}

/// The inodes of `<proc_dir>/ns/*`, by kind. A link reads `net:[4026531840]`.
fn namespace_inodes(proc_dir: &str) -> BTreeMap<&'static str, u64> {
    NAMESPACE_KINDS
        .iter()
        .filter_map(|&kind| {
            let link = std::fs::read_link(format!("{proc_dir}/ns/{kind}")).ok()?;
            Some((kind, link_inode(link.to_str()?)?))
        })
        .collect()
}

fn link_inode(link: &str) -> Option<u64> {
    link.split_once(":[")?.1.strip_suffix(']')?.parse().ok()
}

/// What `config.json` asked for, per kind: a `linux.namespaces` entry
/// without a path is a new namespace, with one a joined one, and a kind
/// without an entry is the runtime's own.
fn namespace_modes(spec: &Spec) -> BTreeMap<String, (NamespaceMode, Option<String>)> {
    spec.linux()
        .as_ref()
        .and_then(|l| l.namespaces().clone())
        .unwrap_or_default()
        .iter()
        .map(|ns| {
            let mode = match ns.path() {
                Some(p) => (NamespaceMode::Join, Some(p.display().to_string())),
                None => (NamespaceMode::New, None),
            };
            (ns.typ().to_string(), mode)
        })
        .collect()
}

/// `uid_map` lines: `inside outside count`.
fn parse_id_map(text: &str) -> Vec<IdMapping> {
    text.lines()
        .filter_map(|l| {
            let mut f = l.split_whitespace().map(|n| n.parse::<u32>());
            match (f.next(), f.next(), f.next()) {
                (Some(Ok(container_id)), Some(Ok(host_id)), Some(Ok(size))) => {
                    Some(IdMapping { container_id, host_id, size })
                }
                _ => None,
            }
        })
        .collect()
}

/// A host id as the container sees it: through its map, or as it is without
/// one (no user namespace of its own). One the map doesn't cover is the
/// kernel's overflow id, `nobody`.
fn inside(host_id: u32, map: &[IdMapping]) -> u32 {
    if map.is_empty() {
        return host_id;
    }
    map.iter()
        .find(|m| host_id >= m.host_id && host_id - m.host_id < m.size)
        .map_or(65534, |m| m.container_id + (host_id - m.host_id))
}

/// A hex capability mask (`CapEff` of `/proc/<pid>/status`) as names.
fn cap_names(hex: &str) -> Vec<String> {
    let set = CapSet(u64::from_str_radix(hex, 16).unwrap_or(0));
    (0..64).map(Cap).filter(|&c| set.contains(c)).map(Cap::name).collect()
}

/// The serde name of an OCI enum value (`SCMP_ACT_ALLOW`, `c`).
fn json_string<T: serde::Serialize>(v: &T) -> String {
    match serde_json::to_value(v) {
        Ok(serde_json::Value::String(s)) => s,
        _ => String::new(),
    }
}

fn seccomp_profile(s: &LinuxSeccomp) -> SeccompProfile {
    const ALLOW: &str = "SCMP_ACT_ALLOW";
    let mut allowed = Vec::new();
    let mut conditional = Vec::new();
    let mut other = Vec::new();
    for rule in s.syscalls().iter().flatten() {
        let action = json_string(&rule.action());
        let has_args = rule.args().as_ref().is_some_and(|a| !a.is_empty());
        if action == ALLOW {
            (if has_args { &mut conditional } else { &mut allowed }).extend(rule.names().iter().cloned());
        } else {
            other.push(SeccompRule {
                names: rule.names().clone(),
                action,
                errno: rule.errno_ret(),
                conditional: has_args,
            });
        }
    }
    for list in [&mut allowed, &mut conditional] {
        list.sort();
        list.dedup();
    }
    // A call allowed outright isn't also "conditional" (the profile can
    // name it twice: allowed with some arguments and, for more
    // capabilities, with any).
    conditional.retain(|n| allowed.binary_search(n).is_err());
    SeccompProfile {
        default_action: json_string(&s.default_action()),
        default_errno: s.default_errno_ret(),
        architectures: s.architectures().iter().flatten().map(json_string).collect(),
        allowed,
        conditional,
        other,
    }
}

/// The cgroup's limits and usage; what a controller that isn't enabled
/// can't say stays at its default.
fn cgroup_usage(path: &str) -> CgroupUsage {
    let mut u = CgroupUsage { path: path.to_owned(), cpu_period: 100_000, ..Default::default() };
    let Ok(cg) = CgroupPath::parse(path).and_then(|p| Cgroup::open(&p)) else {
        return u;
    };
    let read = |f: &str| cg.read(f).ok();
    let number = |f: &str| read(f).and_then(|t| t.trim().parse::<u64>().ok());
    let max = |f: &str| read(f).and_then(|t| stats::parse_max(t.trim()).ok()).flatten();
    u.memory_current = number("memory.current").unwrap_or(0);
    u.memory_max = max("memory.max");
    u.swap_current = number("memory.swap.current");
    u.swap_max = max("memory.swap.max");
    u.pids_current = number("pids.current").unwrap_or(0);
    u.pids_max = max("pids.max");
    if let Some(text) = read("cpu.max") {
        let mut f = text.split_whitespace();
        u.cpu_quota = f.next().and_then(|q| q.parse().ok());
        u.cpu_period = f.next().and_then(|p| p.parse().ok()).unwrap_or(100_000);
    }
    u.cpu_weight = number("cpu.weight");
    u.cpu_usage_usec =
        read("cpu.stat").and_then(|t| stats::parse_flat_keyed(&t).get("usage_usec").copied()).unwrap_or(0);
    u.oom_kills = read("memory.events").map(|t| stats::parse_memory_events(&t).oom_kill).unwrap_or(0);
    u
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pid_belongs_to_the_container_only_in_its_cgroup() {
        let c = "/system.slice/rustletd.service/containers/abc";
        assert!(in_cgroup("0::/system.slice/rustletd.service/containers/abc\n", c));
        assert!(in_cgroup("0::/system.slice/rustletd.service/containers/abc/sub\n", c));
        assert!(!in_cgroup("0::/system.slice/rustletd.service/containers/abcd\n", c));
        assert!(!in_cgroup("0::/user.slice\n", c));
        assert!(!in_cgroup("", c));
    }

    #[test]
    fn status_lines_and_namespace_links() {
        let s = parse_status("Name:\tsh\nUid:\t0\t0\t0\t0\nCapEff:\t00000000a80425fb\nSeccomp:\t2\n");
        assert_eq!(s["Name"], "sh");
        assert_eq!(s["Seccomp"], "2");
        assert_eq!(link_inode("net:[4026531840]"), Some(4026531840));
        assert_eq!(link_inode("garbage"), None);
    }

    #[test]
    fn capability_masks_decode_to_names() {
        // Docker's default set.
        let names = cap_names("00000000a80425fb");
        assert_eq!(names.len(), 14);
        assert!(names.contains(&"CAP_CHOWN".to_owned()) && names.contains(&"CAP_SETFCAP".to_owned()));
        assert!(!names.contains(&"CAP_SYS_ADMIN".to_owned()));
        assert!(cap_names("0").is_empty());
        assert_eq!(cap_names("1ffffffffff").len(), 41);
    }

    #[test]
    fn device_rules_are_the_filters() {
        let linux: Linux = serde_json::from_value(serde_json::json!({
            "resources": {"devices": [{"allow": false, "access": "rwm"}]},
            "devices": [{"path": "/dev/fuse", "type": "c", "major": 10, "minor": 229}]
        }))
        .unwrap();
        let rules = device_rules(&linux, false);
        assert_eq!(rules[0], DeviceRule { kind: "a".into(), access: "rwm".into(), ..Default::default() });
        let null = rules.iter().find(|r| (r.major, r.minor) == (Some(1), Some(3))).unwrap();
        assert!(null.allow && null.origin == DeviceRuleOrigin::Default && null.kind == "c");
        let fuse = rules.last().unwrap();
        assert_eq!((fuse.major, fuse.minor, fuse.access.as_str()), (Some(10), Some(229), "m"));
        assert_eq!(fuse.origin, DeviceRuleOrigin::Node);
        assert!(device_rules(&linux, true).iter().all(|r| r.origin != DeviceRuleOrigin::Node));
    }

    #[test]
    fn id_maps() {
        let m = parse_id_map("         0    1000000      65536\n");
        assert_eq!(m, [IdMapping { container_id: 0, host_id: 1_000_000, size: 65536 }]);
        assert!(parse_id_map("").is_empty());
    }

    #[test]
    fn host_ids_map_back_into_the_container() {
        let m = [IdMapping { container_id: 0, host_id: 1_000_000, size: 65536 }];
        assert_eq!(inside(1_000_000, &m), 0);
        assert_eq!(inside(1_065_534, &m), 65534);
        assert_eq!(inside(1_065_536, &m), 65534, "past the end: the overflow id");
        assert_eq!(inside(0, &m), 65534, "the host's root isn't mapped");
        assert_eq!(inside(1000, &[]), 1000, "no user namespace of its own");
    }

    #[test]
    fn seccomp_profiles_are_summarized() {
        let s: LinuxSeccomp = serde_json::from_value(serde_json::json!({
            "defaultAction": "SCMP_ACT_ERRNO",
            "defaultErrnoRet": 1,
            "architectures": ["SCMP_ARCH_X86_64", "SCMP_ARCH_X86"],
            "syscalls": [
                {"names": ["read", "write"], "action": "SCMP_ACT_ALLOW"},
                {"names": ["clone"], "action": "SCMP_ACT_ALLOW",
                 "args": [{"index": 0, "value": 2114060288, "op": "SCMP_CMP_MASKED_EQ"}]},
                {"names": ["write"], "action": "SCMP_ACT_ALLOW",
                 "args": [{"index": 0, "value": 1, "op": "SCMP_CMP_EQ"}]},
                {"names": ["clone3"], "action": "SCMP_ACT_ERRNO", "errnoRet": 38}
            ]
        }))
        .unwrap();
        let p = seccomp_profile(&s);
        assert_eq!(p.default_action, "SCMP_ACT_ERRNO");
        assert_eq!(p.default_errno, Some(1));
        assert_eq!(p.architectures, ["SCMP_ARCH_X86_64", "SCMP_ARCH_X86"]);
        assert_eq!(p.allowed, ["read", "write"]);
        assert_eq!(p.conditional, ["clone"], "write is allowed outright");
        assert_eq!(p.other.len(), 1);
        assert_eq!((p.other[0].action.as_str(), p.other[0].errno), ("SCMP_ACT_ERRNO", Some(38)));
    }
}

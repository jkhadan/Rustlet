//! The default `config.json`, as written by `rustlet-runc spec`.
//!
//! It starts from runc's defaults (which `oci-spec`'s `Spec::default()`
//! mirrors), hardened the way Docker and Podman run containers:
//!
//! | field                                  | default                                       |
//! |----------------------------------------|-----------------------------------------------|
//! | `process.terminal`                     | true                                          |
//! | `process.capabilities`                 | Podman's 11 ([`caps::DEFAULT`]); inheritable and ambient empty |
//! | `process.noNewPrivileges`              | true                                          |
//! | `linux.seccomp`                        | Docker's default profile, resolved for those capabilities |
//! | `linux.maskedPaths`, `readonlyPaths`   | Docker's lists                                |
//!
//! `linux.cgroupsPath` and `linux.resources` stay out of the default: a
//! cgroup path is only valid inside a systemd-delegated subtree, which
//! depends on where you run (see `cgroups`).

use oci_spec::runtime::{LinuxCapabilitiesBuilder, PosixRlimitBuilder, PosixRlimitType, RootBuilder, Spec};

use crate::caps;
use crate::seccomp;

/// Docker's `maskedPaths`: files that leak host information or kernel
/// memory (`kcore`, `keys`, `timer_list`, …), and firmware/power knobs.
/// `/sys/devices/virtual/powercap` exposes RAPL energy counters, a side
/// channel (the PLATYPUS attack).
pub const MASKED_PATHS: [&str; 12] = [
    "/proc/asound",
    "/proc/acpi",
    "/proc/interrupts",
    "/proc/kcore",
    "/proc/keys",
    "/proc/latency_stats",
    "/proc/timer_list",
    "/proc/timer_stats",
    "/proc/sched_debug",
    "/proc/scsi",
    "/sys/firmware",
    "/sys/devices/virtual/powercap",
];

/// Docker's `readonlyPaths`: kernel knobs under `/proc` that aren't
/// namespaced, so a write would change the host.
pub const READONLY_PATHS: [&str; 5] = ["/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger"];

/// A spec for `rootfs/` next to `config.json` that runs `sh`.
pub fn default_spec() -> Spec {
    let mut spec = Spec::default();
    spec.set_version("1.2.0".into());
    spec.set_hostname(Some("rustlet".into()));
    spec.set_annotations(None);
    spec.set_root(Some(
        // readonly, as in runc: an image rootfs is shared state. It also
        // keeps root-owned files from appearing in your checkout.
        RootBuilder::default().path("rootfs").readonly(true).build().expect("static root"),
    ));

    let mut process = spec.process().clone().unwrap_or_default();
    // A PTY of its own: `rustlet-runc run` relays your terminal to it, and
    // the shell gets job control.
    process.set_terminal(Some(true));
    process.set_args(Some(vec!["sh".into()]));
    let default_caps = caps::to_spec(caps::default_set());
    process.set_capabilities(Some(
        LinuxCapabilitiesBuilder::default()
            .bounding(default_caps.clone())
            .effective(default_caps.clone())
            .permitted(default_caps)
            // Empty, as in Docker since CVE-2022-24769: a non-empty
            // inheritable set lets binaries with inheritable file
            // capabilities gain them.
            .inheritable(caps::to_spec(Default::default()))
            .ambient(caps::to_spec(Default::default()))
            .build()
            .expect("static capabilities"),
    ));
    process.set_no_new_privileges(Some(true));
    process.set_rlimits(Some(vec![
        PosixRlimitBuilder::default()
            .typ(PosixRlimitType::RlimitNofile)
            .soft(1024u64)
            .hard(1024u64)
            .build()
            .expect("static rlimit"),
    ]));
    spec.set_process(Some(process));

    if let Some(linux) = spec.linux_mut() {
        linux.set_resources(None);
        linux.set_masked_paths(Some(MASKED_PATHS.map(String::from).to_vec()));
        linux.set_readonly_paths(Some(READONLY_PATHS.map(String::from).to_vec()));
        linux.set_seccomp(Some(
            seccomp::docker::default_for(caps::default_set()).expect("the vendored Docker profile resolves"),
        ));
    }
    // runc mounts /proc with no options; Docker adds nosuid,noexec,nodev.
    // There is never a reason to execute or honour setuid bits on procfs.
    if let Some(mounts) = spec.mounts_mut() {
        for m in mounts.iter_mut().filter(|m| m.destination() == std::path::Path::new("/proc")) {
            m.set_options(Some(vec!["nosuid".into(), "noexec".into(), "nodev".into()]));
        }
    }
    spec
}

/// The first host id of the subordinate range `--userns=remap` uses
/// (docs/architecture.md §2.2.1): container ids `0..REMAP_SIZE` are host ids
/// `REMAP_HOST_ID..REMAP_HOST_ID + REMAP_SIZE`, for uids and gids alike. It
/// is far above both the regular users and the ranges `useradd` hands out in
/// `/etc/subuid` (100000 onwards, 65536 each).
pub const REMAP_HOST_ID: u32 = 1_000_000;
/// The size of that range: every 16-bit id an image can use.
pub const REMAP_SIZE: u32 = 65_536;

/// Gives `spec` a new user namespace in which container ids `0..size` are
/// host ids `host..host + size`, for uids and gids alike.
pub fn with_user_namespace(spec: &mut Spec, host: u32, size: u32) {
    use oci_spec::runtime::{LinuxIdMappingBuilder, LinuxNamespaceBuilder, LinuxNamespaceType};
    let linux = spec.linux_mut().get_or_insert_with(Default::default);
    let mut namespaces = linux.namespaces().clone().unwrap_or_default();
    if !namespaces.iter().any(|n| n.typ() == LinuxNamespaceType::User) {
        namespaces
            .push(LinuxNamespaceBuilder::default().typ(LinuxNamespaceType::User).build().expect("static namespace"));
    }
    linux.set_namespaces(Some(namespaces));
    let map = LinuxIdMappingBuilder::default().container_id(0u32).host_id(host).size(size).build().expect("static map");
    linux.set_uid_mappings(Some(vec![map]));
    linux.set_gid_mappings(Some(vec![map]));
}

/// Serializes a spec the way humans like to read it.
pub fn to_pretty_json(spec: &Spec) -> String {
    serde_json::to_string_pretty(spec).expect("a Spec always serializes") + "\n"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_spec_round_trips() {
        let s = default_spec();
        let back: Spec = serde_json::from_str(&to_pretty_json(&s)).unwrap();
        assert_eq!(s, back);
    }
}

//! From an image and `rustlet run`'s options to the OCI `config.json` the
//! runtime gets: `rustlet_image::runspec` does the image part (command,
//! environment, user, working directory, annotations, the user namespace),
//! this module the rest of the container's options.
//!
//! | option | spec |
//! |---|---|
//! | `--memory` | `memory.limit` = `memory.swap` (no swap on top) |
//! | `--cpus` | `cpu.quota`/`cpu.period` (100 ms periods) |
//! | `--pids-limit` | `pids.limit` (≤ 0: none) |
//! | `--cap-add`/`--cap-drop` | bounding = effective = permitted, Docker's rules for `ALL`; the seccomp profile is resolved again for the new set (it allows more syscalls with more capabilities) |
//! | `--security-opt seccomp=unconfined` | no `linux.seccomp` |
//! | `--security-opt no-new-privileges[=bool]` | `process.noNewPrivileges` (Rustlets defaults to true) |
//! | `--device HOST[:CONTAINER[:rwm]]` | a node and an allow rule (`rustlet_runtime::spec::add_host_device`) |
//! | `--privileged` | `rustlet_runtime::spec::privileged` |
//! | `--network` | the `network` namespace: the run's pin or the shared container's (`path`), or none at all (`host`) |
//! | `-v`, `--mount`, `--tmpfs` | binds of volumes' `_data` (idmapped under `--userns=remap`) and host paths, tmpfs mounts |
//! | (always) | binds of the generated `/etc/hosts`, `/etc/hostname`, `/etc/resolv.conf`, unless a mount covers them |
//!
//! Every container gets `linux.cgroupsPath`, so every container has a device
//! filter (and `CAP_MKNOD` is allowed by the runtime). Mounts are sorted by
//! depth, so `/data` is mounted before `/data/cache`; a mount on a default
//! destination (`/dev/shm`) replaces the default.

use std::path::{Path, PathBuf};
use std::str::FromStr;

use rustlet_image::Image;
use rustlet_image::runspec::{self, RunOptions};
use rustlet_runtime::caps;
use rustlet_runtime::oci_spec::runtime::{
    LinuxCapabilitiesBuilder, LinuxCpuBuilder, LinuxMemoryBuilder, LinuxNamespaceBuilder, LinuxNamespaceType,
    LinuxPidsBuilder, LinuxResources, Mount, MountBuilder, Spec,
};
use rustlet_spec::container::{ContainerConfig, UsernsMode};
use rustlet_spec::volume::{MountSpec, MountType};
use rustlet_sys::caps::{Cap, CapSet, last_cap};

use crate::error::{ApiError, ApiResult};

/// The `cpu.period` for `--cpus`, as Docker's.
const CPU_PERIOD: u64 = 100_000;

/// What the options say, checked before anything is created.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checked {
    pub caps: CapSet,
    pub seccomp: bool,
    pub no_new_privileges: Option<bool>,
    /// `(host, container, access)`.
    pub devices: Vec<(String, String, String)>,
}

/// Validates the options that don't need the image.
pub fn check(c: &ContainerConfig) -> ApiResult<Checked> {
    if c.image.trim().is_empty() {
        return Err(ApiError::invalid("no image given"));
    }
    if let Some(name) = &c.name
        && !rustlet_spec::valid_container_name(name)
    {
        return Err(ApiError::invalid(format!(
            "invalid container name {name:?}: use [a-zA-Z0-9][a-zA-Z0-9_.-]*, at most 128 characters"
        )));
    }
    if c.auto_remove && c.restart.name != rustlet_spec::container::RestartPolicyName::No {
        return Err(ApiError::invalid("--rm and a restart policy contradict each other"));
    }
    if let Some(cpus) = c.cpus
        && !(cpus > 0.0 && cpus.is_finite() && cpus <= 1024.0)
    {
        return Err(ApiError::invalid(format!("--cpus {cpus}: give a positive number of CPUs")));
    }
    if c.memory == Some(0) {
        return Err(ApiError::invalid("--memory 0: give a limit, or leave it out"));
    }
    if let Some(sig) = &c.stop_signal {
        parse_signal(sig)?;
    }
    if c.unset_env.iter().any(|name| name.is_empty() || name.contains(['=', '\0'])) {
        return Err(ApiError::invalid("unset environment names must be nonempty and contain neither = nor NUL"));
    }
    let caps = capabilities(&c.cap_add, &c.cap_drop)?;
    let mut seccomp = true;
    let mut no_new_privileges = None;
    for opt in &c.security_opt {
        let (key, value) = opt.split_once(['=', ':']).unwrap_or((opt.as_str(), ""));
        match (key, value) {
            ("seccomp", "unconfined") => seccomp = false,
            ("seccomp", other) => {
                return Err(ApiError::invalid(format!(
                    "--security-opt seccomp={other}: only `unconfined` (custom profiles aren't supported yet)"
                )));
            }
            ("no-new-privileges", "" | "true") => no_new_privileges = Some(true),
            ("no-new-privileges", "false") => no_new_privileges = Some(false),
            _ => return Err(ApiError::invalid(format!("unsupported --security-opt {opt:?}"))),
        }
    }
    let devices = c.devices.iter().map(|d| parse_device(d)).collect::<ApiResult<_>>()?;
    if let Some(h) = &c.healthcheck {
        check_healthcheck(h)?;
    }
    Ok(Checked { caps, seccomp, no_new_privileges, devices })
}

/// Docker's rules for a healthcheck's options: a test of `NONE`, `CMD`
/// with a program, or `CMD-SHELL` with one command (or none, for the
/// image's); durations of at least a millisecond, if given.
fn check_healthcheck(h: &rustlet_spec::container::HealthConfig) -> ApiResult<()> {
    match h.test.split_first() {
        None => {}
        Some((kind, [])) if kind == "NONE" => {}
        Some((kind, rest)) if kind == "CMD" && !rest.is_empty() && !rest[0].is_empty() => {}
        Some((kind, [command])) if kind == "CMD-SHELL" && !command.trim().is_empty() => {}
        Some(_) => {
            return Err(ApiError::invalid(format!(
                "healthcheck test {:?}: give [\"CMD\", program, args…], [\"CMD-SHELL\", command] or [\"NONE\"]",
                h.test
            )));
        }
    }
    for (what, value) in [
        ("interval", h.interval),
        ("timeout", h.timeout),
        ("start period", h.start_period),
        ("start interval", h.start_interval),
    ] {
        if let Some(ns) = value
            && ns != 0
            && ns < 1_000_000
        {
            return Err(ApiError::invalid(format!("the healthcheck's {what} must be at least 1ms")));
        }
        // Go's `time.Duration` is an int64 of nanoseconds, as Docker's API and an
        // image config (read back as signed) have it: a longer one would make a
        // committed image's config unreadable, and the image vanish from `images`.
        if value.is_some_and(|ns| ns > i64::MAX as u64) {
            return Err(ApiError::invalid(format!("the healthcheck's {what} is longer than 292 years")));
        }
    }
    Ok(())
}

/// Docker's rules: `--cap-drop ALL` starts from nothing and adds the
/// `--cap-add`s; `--cap-add ALL` starts from everything and drops the
/// `--cap-drop`s; otherwise the default set, plus adds, minus drops.
pub fn capabilities(add: &[String], drop: &[String]) -> ApiResult<CapSet> {
    let parse = |names: &[String]| -> ApiResult<Vec<Cap>> {
        names
            .iter()
            .filter(|n| !n.eq_ignore_ascii_case("ALL"))
            .map(|n| Cap::from_str(n).map_err(ApiError::invalid))
            .collect()
    };
    let all = |names: &[String]| names.iter().any(|n| n.eq_ignore_ascii_case("ALL"));
    let (adds, drops) = (parse(add)?, parse(drop)?);
    let mut set = if all(drop) {
        CapSet::EMPTY
    } else if all(add) {
        CapSet::all(last_cap())
    } else {
        caps::default_set()
    };
    if !all(add) {
        adds.iter().for_each(|c| set.insert(*c));
    }
    if !all(drop) {
        drops.iter().for_each(|c| set.remove(*c));
    }
    Ok(set)
}

/// `HOST[:CONTAINER[:ACCESS]]`.
fn parse_device(d: &str) -> ApiResult<(String, String, String)> {
    let parts: Vec<&str> = d.split(':').collect();
    let (host, container, access) = match parts.as_slice() {
        [h] => (*h, *h, "rwm"),
        [h, c] if c.chars().all(|ch| "rwm".contains(ch)) && !c.is_empty() => (*h, *h, *c),
        [h, c] => (*h, *c, "rwm"),
        [h, c, a] => (*h, *c, *a),
        _ => return Err(ApiError::invalid(format!("--device {d:?}: expected HOST[:CONTAINER[:rwm]]"))),
    };
    if !host.starts_with("/dev/") || !container.starts_with("/dev/") {
        return Err(ApiError::invalid(format!("--device {d:?}: both paths must be under /dev")));
    }
    Ok((host.into(), container.into(), access.into()))
}

/// `TERM`, `SIGTERM` or `15` → 15.
pub fn parse_signal(s: &str) -> ApiResult<i32> {
    if let Ok(n) = s.parse::<i32>() {
        return nix::sys::signal::Signal::try_from(n)
            .map(|s| s as i32)
            .map_err(|_| ApiError::invalid(format!("unknown signal number {n}")));
    }
    let up = s.trim().to_ascii_uppercase();
    let name = if up.starts_with("SIG") { up } else { format!("SIG{up}") };
    nix::sys::signal::Signal::from_str(&name)
        .map(|s| s as i32)
        .map_err(|_| ApiError::invalid(format!("unknown signal {s:?}")))
}

/// The image's `StopSignal`, validated before a container is created.
pub fn image_stop_signal(image: &Image) -> ApiResult<Option<String>> {
    let signal = image.config.config().and_then(|c| c.stop_signal().clone());
    if let Some(s) = &signal {
        parse_signal(s).map_err(|e| e.context("the image's StopSignal"))?;
    }
    Ok(signal)
}

/// What a start adds to the spec besides the container's options.
#[derive(Debug, Clone, Default)]
pub struct RunPlan {
    pub hostname: String,
    /// The network namespace to join; `None`: the host's.
    pub netns: Option<PathBuf>,
    /// `(destination, host file)`: the generated `/etc` files.
    pub etc_files: Vec<(String, PathBuf)>,
    /// The recorded mounts, and where volumes keep their data.
    pub mounts: Vec<MountSpec>,
    pub volumes: PathBuf,
}

/// The full spec for a start of the container `id`, whose rootfs is mounted
/// at `rootfs`.
pub fn build(image: &Image, rootfs: &Path, c: &ContainerConfig, plan: &RunPlan, cgroups_path: &str) -> ApiResult<Spec> {
    let hostname = plan.hostname.as_str();
    let checked = check(c)?;
    let options = RunOptions {
        args: c.cmd.clone(),
        clear_cmd: c.clear_cmd,
        entrypoint: c.entrypoint.clone(),
        env: c.env.clone(),
        unset_env: c.unset_env.clone(),
        user: c.user.clone(),
        workdir: c.workdir.clone(),
        tty: c.tty,
        hostname: Some(hostname.to_owned()),
        readonly_rootfs: c.read_only,
        userns_remap: c.userns == UsernsMode::Remap,
    };
    let mut spec = runspec::build(image, rootfs, &options)?;
    let linux = spec.linux_mut().get_or_insert_with(Default::default);
    linux.set_cgroups_path(Some(cgroups_path.into()));
    linux.set_resources(Some(resources(c)?));
    if c.privileged {
        rustlet_runtime::spec::privileged(&mut spec)?;
    } else {
        let set = caps::to_spec(checked.caps);
        let process = spec.process_mut().get_or_insert_with(Default::default);
        process.set_capabilities(Some(
            LinuxCapabilitiesBuilder::default()
                .bounding(set.clone())
                .effective(set.clone())
                .permitted(set)
                .inheritable(caps::to_spec(CapSet::EMPTY))
                .ambient(caps::to_spec(CapSet::EMPTY))
                .build()
                .map_err(|e| ApiError::internal(format!("capabilities: {e}")))?,
        ));
        let seccomp = if checked.seccomp {
            Some(
                rustlet_runtime::seccomp::docker::default_for(checked.caps)
                    .map_err(|e| ApiError::internal(format!("resolve the seccomp profile: {e}")))?,
            )
        } else {
            None
        };
        spec.linux_mut().get_or_insert_with(Default::default).set_seccomp(seccomp);
    }
    if let Some(nnp) = checked.no_new_privileges {
        spec.process_mut().get_or_insert_with(Default::default).set_no_new_privileges(Some(nnp));
    }
    // The daemon runs with OOMScoreAdjust=-500, so that the kernel's OOM
    // killer takes it last, and its shims inherit that. Without a value of
    // its own, a container (and its execs) would too, and be spared before
    // the host's ordinary processes. As with Docker, containers get 0.
    spec.process_mut().get_or_insert_with(Default::default).set_oom_score_adj(Some(0));
    for (host, container, access) in &checked.devices {
        rustlet_runtime::spec::add_host_device(&mut spec, Path::new(host), Path::new(container), access)
            .map_err(|e| ApiError::invalid(format!("--device {host}: {e}")))?;
    }
    set_network_namespace(&mut spec, plan.netns.as_deref());
    add_mounts(&mut spec, plan, c.userns == UsernsMode::Remap)?;
    Ok(spec)
}

/// Joins `netns`, or, for `None`, shares the runtime's (the host's).
fn set_network_namespace(spec: &mut Spec, netns: Option<&Path>) {
    let linux = spec.linux_mut().get_or_insert_with(Default::default);
    let mut namespaces: Vec<_> = linux
        .namespaces()
        .clone()
        .unwrap_or_default()
        .into_iter()
        .filter(|n| n.typ() != LinuxNamespaceType::Network)
        .collect();
    if let Some(path) = netns {
        namespaces.push(
            LinuxNamespaceBuilder::default()
                .typ(LinuxNamespaceType::Network)
                .path(path)
                .build()
                .expect("static namespace"),
        );
    }
    linux.set_namespaces(Some(namespaces));
}

/// The user's mounts and the generated `/etc` files, depth first, replacing
/// any default mount at the same destination.
fn add_mounts(spec: &mut Spec, plan: &RunPlan, remap: bool) -> ApiResult<()> {
    let mut ours: Vec<Mount> = Vec::new();
    for m in &plan.mounts {
        ours.push(oci_mount(m, &plan.volumes, remap)?);
    }
    for (dest, file) in &plan.etc_files {
        if plan.mounts.iter().any(|m| &m.target == dest) {
            continue;
        }
        ours.push(bind(file, dest, &["rbind", "rprivate"])?);
    }
    // Stable: equal depths keep their order.
    ours.sort_by_key(|m| m.destination().components().count());
    let mut mounts: Vec<Mount> = spec
        .mounts()
        .clone()
        .unwrap_or_default()
        .into_iter()
        .filter(|d| !ours.iter().any(|m| m.destination() == d.destination()))
        .collect();
    mounts.extend(ours);
    spec.set_mounts(Some(mounts));
    Ok(())
}

fn bind(source: &Path, dest: &str, options: &[&str]) -> ApiResult<Mount> {
    MountBuilder::default()
        .destination(dest)
        .typ("bind")
        .source(source)
        .options(options.iter().map(|o| o.to_string()).collect::<Vec<_>>())
        .build()
        .map_err(|e| ApiError::internal(format!("mount {dest}: {e}")))
}

/// One recorded mount as the runtime takes it.
fn oci_mount(m: &MountSpec, volumes: &Path, remap: bool) -> ApiResult<Mount> {
    let rw = if m.read_only { "ro" } else { "rw" };
    match m.kind {
        MountType::Volume => {
            let name = m
                .source
                .as_deref()
                .ok_or_else(|| ApiError::internal(format!("the volume on {} has no name", m.target)))?;
            let mut options = vec!["rbind", "rprivate", rw];
            if remap {
                options.push("idmap");
            }
            bind(&volumes.join(name).join("_data"), &m.target, &options)
        }
        MountType::Bind => {
            let source = m
                .source
                .as_deref()
                .ok_or_else(|| ApiError::internal(format!("the bind on {} has no source", m.target)))?;
            let mut options = vec!["rbind", "rprivate", rw];
            if remap && m.idmap {
                options.push("idmap");
            }
            bind(Path::new(source), &m.target, &options)
        }
        MountType::Tmpfs => {
            let mut options: Vec<String> = ["nosuid", "nodev", "noexec"].map(String::from).to_vec();
            if m.read_only {
                options.push("ro".into());
            }
            // The runtime takes the last word of each pair.
            options.extend(m.tmpfs_options.iter().cloned());
            if let Some(size) = m.tmpfs_size {
                options.push(format!("size={size}"));
            }
            if let Some(mode) = m.tmpfs_mode {
                options.push(format!("mode={mode:o}"));
            }
            MountBuilder::default()
                .destination(&m.target)
                .typ("tmpfs")
                .source("tmpfs")
                .options(options)
                .build()
                .map_err(|e| ApiError::internal(format!("mount {}: {e}", m.target)))
        }
    }
}

fn resources(c: &ContainerConfig) -> ApiResult<LinuxResources> {
    let mut r = LinuxResources::default();
    if let Some(bytes) = c.memory {
        let bytes = i64::try_from(bytes).map_err(|_| ApiError::invalid("--memory is too large"))?;
        r.set_memory(Some(
            LinuxMemoryBuilder::default()
                .limit(bytes)
                .swap(bytes)
                .build()
                .map_err(|e| ApiError::internal(e.to_string()))?,
        ));
    }
    if let Some(cpus) = c.cpus {
        let quota = (cpus * CPU_PERIOD as f64).round() as i64;
        r.set_cpu(Some(
            LinuxCpuBuilder::default()
                .quota(quota.max(1000))
                .period(CPU_PERIOD)
                .build()
                .map_err(|e| ApiError::internal(e.to_string()))?,
        ));
    }
    if let Some(n) = c.pids_limit.filter(|n| *n > 0) {
        r.set_pids(Some(LinuxPidsBuilder::default().limit(n).build().map_err(|e| ApiError::internal(e.to_string()))?));
    }
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(set: CapSet) -> Vec<String> {
        set.names()
    }

    #[test]
    fn capability_rules_follow_docker() {
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        let default = caps::default_set();
        assert_eq!(capabilities(&[], &[]).unwrap(), default);
        let only = capabilities(&s(&["NET_BIND_SERVICE"]), &s(&["ALL"])).unwrap();
        assert_eq!(names(only), ["CAP_NET_BIND_SERVICE"]);
        let all_but = capabilities(&s(&["ALL"]), &s(&["sys_admin"])).unwrap();
        assert!(!all_but.contains(Cap::from_str("SYS_ADMIN").unwrap()));
        assert!(all_but.contains(Cap::from_str("NET_ADMIN").unwrap()));
        let plus = capabilities(&s(&["CAP_NET_RAW"]), &s(&["CHOWN"])).unwrap();
        assert!(plus.contains(Cap::from_str("NET_RAW").unwrap()) && !plus.contains(Cap::from_str("CHOWN").unwrap()));
        assert!(capabilities(&s(&["NOT_A_CAP"]), &[]).is_err());
    }

    #[test]
    fn options_are_checked() {
        let ok = ContainerConfig { image: "alpine".into(), ..Default::default() };
        let c = check(&ok).unwrap();
        assert!(c.seccomp && c.no_new_privileges.is_none() && c.devices.is_empty());
        let bad = |f: fn(&mut ContainerConfig)| {
            let mut c = ok.clone();
            f(&mut c);
            check(&c).unwrap_err()
        };
        bad(|c| c.image = " ".into());
        bad(|c| c.name = Some("-x".into()));
        bad(|c| {
            c.auto_remove = true;
            c.restart = rustlet_spec::container::RestartPolicy::parse("always").unwrap();
        });
        bad(|c| c.cpus = Some(-1.0));
        bad(|c| c.memory = Some(0));
        bad(|c| c.stop_signal = Some("SIGNOPE".into()));
        bad(|c| c.security_opt = vec!["apparmor=x".into()]);
        bad(|c| c.devices = vec!["/etc/passwd".into()]);
        let mut c = ok.clone();
        c.security_opt = vec!["seccomp=unconfined".into(), "no-new-privileges=false".into()];
        c.devices = vec!["/dev/fuse".into(), "/dev/kvm:r".into(), "/dev/sda:/dev/xvda:rw".into()];
        let checked = check(&c).unwrap();
        assert!(!checked.seccomp);
        assert_eq!(checked.no_new_privileges, Some(false));
        assert_eq!(
            checked.devices,
            [
                ("/dev/fuse".into(), "/dev/fuse".into(), "rwm".into()),
                ("/dev/kvm".into(), "/dev/kvm".into(), "r".into()),
                ("/dev/sda".into(), "/dev/xvda".into(), "rw".into()),
            ]
        );
    }

    #[test]
    fn healthcheck_options_are_checked_as_docker_does() {
        use rustlet_spec::container::HealthConfig;
        let with = |h: HealthConfig| ContainerConfig { image: "a".into(), healthcheck: Some(h), ..Default::default() };
        let test = |t: &[&str]| HealthConfig { test: t.iter().map(|s| s.to_string()).collect(), ..Default::default() };
        for ok in [&[][..], &["NONE"], &["CMD", "true"], &["CMD", "pg_isready", "-q"], &["CMD-SHELL", "curl -f x"]] {
            assert!(check(&with(test(ok))).is_ok(), "{ok:?}");
        }
        for bad in
            [&["CMD"][..], &["CMD-SHELL"], &["CMD-SHELL", "a", "b"], &["NONE", "x"], &["SHELL", "x"], &["CMD", ""]]
        {
            assert!(check(&with(test(bad))).is_err(), "{bad:?}");
        }
        assert!(check(&with(HealthConfig { interval: Some(999_999), ..Default::default() })).is_err());
        assert!(check(&with(HealthConfig { timeout: Some(i64::MAX as u64 + 1), ..Default::default() })).is_err());
        assert!(check(&with(HealthConfig { timeout: Some(i64::MAX as u64), ..Default::default() })).is_ok());
        assert!(
            check(&with(HealthConfig { timeout: Some(0), interval: Some(1_000_000), ..Default::default() })).is_ok()
        );
    }

    #[test]
    fn signals_by_name_or_number() {
        assert_eq!(parse_signal("TERM").unwrap(), 15);
        assert_eq!(parse_signal("sigkill").unwrap(), 9);
        assert_eq!(parse_signal("2").unwrap(), 2);
        assert!(parse_signal("999").is_err() && parse_signal("WHAT").is_err());
    }

    #[test]
    fn mounts_and_the_network_namespace() {
        let mut spec = rustlet_runtime::spec::default_spec();
        let plan = RunPlan {
            hostname: "web".into(),
            netns: Some("/run/rustlet/netns/abc".into()),
            etc_files: vec![
                ("/etc/hosts".into(), "/c/hosts".into()),
                ("/etc/resolv.conf".into(), "/c/resolv.conf".into()),
            ],
            mounts: vec![
                MountSpec {
                    kind: MountType::Volume,
                    source: Some("cache".into()),
                    target: "/data/cache".into(),
                    ..Default::default()
                },
                MountSpec {
                    kind: MountType::Bind,
                    source: Some("/srv".into()),
                    target: "/data".into(),
                    read_only: true,
                    ..Default::default()
                },
                MountSpec {
                    kind: MountType::Tmpfs,
                    target: "/dev/shm".into(),
                    tmpfs_size: Some(1 << 20),
                    tmpfs_options: vec!["exec".into()],
                    ..Default::default()
                },
                MountSpec {
                    kind: MountType::Bind,
                    source: Some("/my/resolv".into()),
                    target: "/etc/resolv.conf".into(),
                    ..Default::default()
                },
            ],
            volumes: "/var/lib/rustlet/volumes".into(),
        };
        set_network_namespace(&mut spec, plan.netns.as_deref());
        add_mounts(&mut spec, &plan, true).unwrap();
        let net: Vec<_> = spec
            .linux()
            .as_ref()
            .unwrap()
            .namespaces()
            .as_ref()
            .unwrap()
            .iter()
            .filter(|n| n.typ() == LinuxNamespaceType::Network)
            .collect();
        assert_eq!(net.len(), 1);
        assert_eq!(net[0].path().as_deref(), Some(Path::new("/run/rustlet/netns/abc")));
        let mounts = spec.mounts().as_ref().unwrap();
        let dests: Vec<_> = mounts.iter().map(|m| m.destination().display().to_string()).collect();
        // One /dev/shm (ours), the user's resolv.conf instead of ours, depth order.
        assert_eq!(dests.iter().filter(|d| *d == "/dev/shm").count(), 1);
        let pos = |d: &str| dests.iter().position(|x| x == d).unwrap();
        assert!(pos("/data") < pos("/data/cache"));
        let resolv = &mounts[pos("/etc/resolv.conf")];
        assert_eq!(resolv.source().as_deref(), Some(Path::new("/my/resolv")));
        let cache = &mounts[pos("/data/cache")];
        assert_eq!(cache.source().as_deref(), Some(Path::new("/var/lib/rustlet/volumes/cache/_data")));
        assert!(cache.options().as_ref().unwrap().contains(&"idmap".to_owned()), "volumes are idmapped under remap");
        assert!(mounts[pos("/data")].options().as_ref().unwrap().contains(&"ro".to_owned()));
        assert!(!mounts[pos("/data")].options().as_ref().unwrap().contains(&"idmap".to_owned()));
        let shm = mounts[pos("/dev/shm")].options().as_ref().unwrap().join(",");
        assert_eq!(shm, "nosuid,nodev,noexec,exec,size=1048576");
        // The host's namespace: no network entry at all.
        set_network_namespace(&mut spec, None);
        assert!(
            !spec
                .linux()
                .as_ref()
                .unwrap()
                .namespaces()
                .as_ref()
                .unwrap()
                .iter()
                .any(|n| n.typ() == LinuxNamespaceType::Network)
        );
    }

    #[test]
    fn resources_map_like_docker() {
        let c =
            ContainerConfig { memory: Some(64 << 20), cpus: Some(1.5), pids_limit: Some(100), ..Default::default() };
        let r = resources(&c).unwrap();
        let m = r.memory().as_ref().unwrap();
        assert_eq!((m.limit(), m.swap()), (Some(64 << 20), Some(64 << 20)));
        let cpu = r.cpu().as_ref().unwrap();
        assert_eq!((cpu.quota(), cpu.period()), (Some(150_000), Some(100_000)));
        assert_eq!(r.pids().as_ref().unwrap().limit(), 100);
        let none = resources(&ContainerConfig { pids_limit: Some(0), ..Default::default() }).unwrap();
        assert!(none.pids().is_none() && none.memory().is_none());
    }
}

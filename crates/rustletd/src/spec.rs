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
//!
//! Every container gets `linux.cgroupsPath`, so every container has a device
//! filter (and `CAP_MKNOD` is allowed by the runtime).

use std::path::Path;
use std::str::FromStr;

use rustlet_image::Image;
use rustlet_image::runspec::{self, RunOptions};
use rustlet_runtime::caps;
use rustlet_runtime::oci_spec::runtime::{
    LinuxCapabilitiesBuilder, LinuxCpuBuilder, LinuxMemoryBuilder, LinuxPidsBuilder, LinuxResources, Spec,
};
use rustlet_spec::container::{ContainerConfig, UsernsMode};
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
    Ok(Checked { caps, seccomp, no_new_privileges, devices })
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

/// The image's `StopSignal`, if it says one that exists.
pub fn image_stop_signal(image: &Image) -> Option<String> {
    let s = image.config.config()?.stop_signal().clone()?;
    parse_signal(&s).ok().map(|_| s)
}

/// The full spec for a start of the container `id`, whose rootfs is mounted
/// at `rootfs`.
pub fn build(image: &Image, rootfs: &Path, c: &ContainerConfig, hostname: &str, cgroups_path: &str) -> ApiResult<Spec> {
    let checked = check(c)?;
    let options = RunOptions {
        args: c.cmd.clone(),
        entrypoint: c.entrypoint.clone(),
        env: c.env.clone(),
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
    for (host, container, access) in &checked.devices {
        rustlet_runtime::spec::add_host_device(&mut spec, Path::new(host), Path::new(container), access)
            .map_err(|e| ApiError::invalid(format!("--device {host}: {e}")))?;
    }
    Ok(spec)
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
    fn signals_by_name_or_number() {
        assert_eq!(parse_signal("TERM").unwrap(), 15);
        assert_eq!(parse_signal("sigkill").unwrap(), 9);
        assert_eq!(parse_signal("2").unwrap(), 2);
        assert!(parse_signal("999").is_err() && parse_signal("WHAT").is_err());
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

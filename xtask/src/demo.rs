//! `cargo xtask demo`: an interactive Alpine shell with cgroup limits.
//!
//! A container cgroup may only live inside a systemd-delegated subtree (see
//! `rustlet_runtime::cgroups`). Before the daemon exists (Phase 4), the
//! easiest such subtree is a throwaway scope:
//!
//! ```text
//! sudo systemd-run --scope -p Delegate=yes --unit=rustlet-demo-<pid> -- sh -c '
//!     mkdir <scope>/runtime; echo $$ > <scope>/runtime/cgroup.procs    # leaf for rustlet-runc
//!     exec rustlet-runc run --bundle .rustlet-dev/bundles/demo demo'
//! ```
//!
//! `rustlet-runc` moves out of the scope's own cgroup into the `runtime` leaf
//! first, because of cgroup v2's "no internal processes" rule: the scope can
//! only get a container child cgroup with controllers enabled once no process
//! sits in the scope itself. The container then gets `<scope>/demo`.

use std::path::Path;
use std::process::Command;

use anyhow::{Context, bail};
use rustlet_runtime::oci_spec::runtime::{
    LinuxCpuBuilder, LinuxMemoryBuilder, LinuxPidsBuilder, LinuxResourcesBuilder,
};
use rustlet_runtime::spec;

use crate::{cargo, dev_dir, run_cmd, workspace};

/// Parses `64M`, `1G`, `512k` or plain bytes.
fn parse_bytes(s: &str) -> anyhow::Result<i64> {
    let (num, mult) = match s.chars().last().map(|c| c.to_ascii_lowercase()) {
        Some('k') => (&s[..s.len() - 1], 1i64 << 10),
        Some('m') => (&s[..s.len() - 1], 1 << 20),
        Some('g') => (&s[..s.len() - 1], 1 << 30),
        _ => (s, 1),
    };
    Ok(num.parse::<i64>().with_context(|| format!("bad size {s:?}"))? * mult)
}

pub(crate) fn run(memory: Option<&str>, pids: Option<i64>, cpus: Option<f64>) -> anyhow::Result<()> {
    let rootfs = dev_dir().join("bundles/alpine/rootfs");
    if !rootfs.join("bin/busybox").exists() {
        bail!("the Alpine rootfs is missing: run `cargo xtask rootfs` first");
    }
    run_cmd(cargo().args(["build", "--quiet", "-p", "rustlet-runc"]))?;

    let unit = format!("rustlet-demo-{}", std::process::id());
    let scope = format!("/system.slice/{unit}.scope");
    let mut s = spec::default_spec();
    let mut root = s.root().clone().unwrap();
    root.set_path(rootfs.canonicalize()?);
    s.set_root(Some(root));
    let mut res = LinuxResourcesBuilder::default();
    if let Some(m) = memory {
        let bytes = parse_bytes(m)?;
        // swap = limit: no swap on top of the memory limit, so an OOM shows
        // up promptly instead of the container crawling through swap.
        res = res.memory(LinuxMemoryBuilder::default().limit(bytes).swap(bytes).build()?);
    }
    if let Some(p) = pids {
        res = res.pids(LinuxPidsBuilder::default().limit(p).build()?);
    }
    if let Some(c) = cpus {
        let period = 100_000u64;
        res = res.cpu(LinuxCpuBuilder::default().quota((c * period as f64) as i64).period(period).build()?);
    }
    let linux = s.linux_mut().as_mut().unwrap();
    linux.set_cgroups_path(Some(format!("{scope}/demo").into()));
    linux.set_resources(Some(res.build()?));

    let bundle = dev_dir().join("bundles/demo");
    std::fs::create_dir_all(&bundle)?;
    std::fs::write(bundle.join("config.json"), spec::to_pretty_json(&s))?;

    let runc = workspace().join("target/debug/rustlet-runc");
    let script = format!(
        "set -e; cg=/sys/fs/cgroup{scope}; mkdir \"$cg/runtime\"; echo $$ > \"$cg/runtime/cgroup.procs\"; \
         exec {} --root /run/rustlet/demo-{} run --bundle {} demo",
        shell_quote(&runc),
        std::process::id(),
        shell_quote(&bundle)
    );
    println!("container cgroup: /sys/fs/cgroup{scope}/demo   (try: cat /sys/fs/cgroup/memory.max inside)");
    let status = Command::new("sudo")
        .args(["/usr/bin/systemd-run", "--scope", "--quiet", "--collect"])
        .arg(format!("--unit={unit}"))
        .args(["-p", "Delegate=yes", "--", "/bin/sh", "-c", &script])
        .status()
        .context("run sudo systemd-run")?;
    std::process::exit(status.code().unwrap_or(1));
}

fn shell_quote(p: &Path) -> String {
    format!("'{}'", p.display().to_string().replace('\'', r"'\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes() {
        assert_eq!(parse_bytes("64M").unwrap(), 64 << 20);
        assert_eq!(parse_bytes("1g").unwrap(), 1 << 30);
        assert_eq!(parse_bytes("4096").unwrap(), 4096);
        assert!(parse_bytes("lots").is_err());
    }
}

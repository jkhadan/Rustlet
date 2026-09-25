//! `cargo xtask seccomp`: compile a seccomp profile and show what came out.
//!
//! ```text
//! cargo xtask seccomp                          Docker's profile, default caps, this kernel
//! cargo xtask seccomp --caps CHOWN,SYS_ADMIN   ... resolved for other capabilities
//! cargo xtask seccomp --bundle DIR             a bundle's linux.seccomp instead
//! cargo xtask seccomp --disasm                 also print the BPF program
//! cargo xtask seccomp --json                   print the resolved linux.seccomp instead
//! ```
//!
//! `--json` output can be pasted into a bundle's `config.json` as
//! `linux.seccomp`, which is how to experiment with a changed profile.

use std::path::Path;

use anyhow::{Context, bail};
use rustlet_runtime::oci_spec::runtime::LinuxSeccomp;
use rustlet_runtime::seccomp::docker::{self, Cap, CapSet, KernelVersion};
use rustlet_runtime::seccomp::{self, disasm, syscalls};

pub(crate) fn run(bundle: Option<&Path>, caps: Option<&str>, show_disasm: bool, json: bool) -> anyhow::Result<()> {
    let (what, spec) = match bundle {
        Some(dir) => bundle_seccomp(dir)?,
        None => {
            let caps = match caps {
                Some(list) => parse_caps(list)?,
                None => rustlet_runtime::caps::default_set(),
            };
            let kernel = KernelVersion::running()?;
            let spec = docker::resolve(docker::DEFAULT_PROFILE, caps, kernel)?;
            let names = if caps == CapSet::EMPTY { "no capabilities".into() } else { caps.names().join(", ") };
            (format!("Docker's default profile for {names} (kernel {kernel})"), spec)
        }
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&spec)?);
        return Ok(());
    }

    let (filter, stats) = seccomp::compile_with_stats(&spec)?;
    println!("{what}");
    let row = |label: &str, value: String| println!("  {label:<15} {value}");
    row("default action", disasm::action_name(stats.default_action));
    row("instructions", format!("{} (the kernel's limit is 4096)", stats.instructions));
    row("syscalls", format!("{} with rules of their own", stats.syscalls));
    if !stats.skipped.is_empty() {
        let shown: Vec<&str> = stats.skipped.iter().take(6).map(String::as_str).collect();
        let more = if stats.skipped.len() > shown.len() { ", …" } else { "" };
        row(
            "skipped",
            format!("{} names that aren't x86_64 syscalls: {}{more}", stats.skipped.len(), shown.join(", ")),
        );
    }
    row(
        "ENOSYS above",
        match stats.enosys_above {
            Some(nr) => format!("{nr} ({})", syscalls::name(nr).unwrap_or("?")),
            None => "no stub (permissive default action, or no rules)".into(),
        },
    );
    row(
        "dispatch",
        format!("{} ranges of syscall numbers, at most {} comparisons deep", stats.ranges, stats.dispatch_depth),
    );
    row("blocks", format!("{} distinct (syscalls with the same rules share one)", stats.blocks));
    row("trampolines", format!("{} (for jumps farther than 255 instructions)", stats.trampolines));
    row("flags", if filter.flags == 0 { "none".into() } else { format!("{:#x}", filter.flags) });
    if show_disasm {
        println!();
        print!("{}", filter.disassemble());
    }
    Ok(())
}

fn bundle_seccomp(dir: &Path) -> anyhow::Result<(String, LinuxSeccomp)> {
    let bundle = rustlet_runtime::Bundle::load(dir)?;
    let spec = bundle
        .spec
        .linux()
        .as_ref()
        .and_then(|l| l.seccomp().clone())
        .with_context(|| format!("{}/config.json has no linux.seccomp", bundle.dir.display()))?;
    Ok((format!("linux.seccomp of {}", bundle.dir.display()), spec))
}

/// `CHOWN,SYS_ADMIN` or `CAP_CHOWN,cap_sys_admin`; empty for none.
fn parse_caps(list: &str) -> anyhow::Result<CapSet> {
    let mut caps = CapSet::EMPTY;
    for name in list.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        match name.parse::<Cap>() {
            Ok(cap) => caps.insert(cap),
            Err(e) => bail!("--caps: {e}"),
        }
    }
    Ok(caps)
}

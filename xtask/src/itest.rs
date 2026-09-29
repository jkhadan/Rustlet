//! `cargo xtask itest`: privileged integration tests, safely.
//!
//! 1. Build `rustlet-runc` and the test binaries **as you** (never
//!    `sudo cargo`: that leaves root-owned files in `target/` and `~/.cargo`).
//! 2. Run each test binary as root inside a throwaway systemd scope:
//!
//!    ```text
//!    sudo systemd-run --scope -p Delegate=yes -p TasksMax=4096 -p MemoryMax=4G -- <test binary>
//!    ```
//!
//!    The scope caps what a runaway test can consume (a fork bomb hits
//!    `TasksMax`, a leak hits `MemoryMax`) and gives Phase 2a's cgroup tests
//!    a delegated subtree to create container cgroups in.
//!
//! The privileged tests are `#[ignore]`d so that a plain `cargo nextest run`
//! (as your user, and in CI's unprivileged job) skips them;
//! `--include-ignored` runs them here.

use std::process::Command;

use anyhow::{Context, bail};

use crate::{cargo, dev_dir, run_cmd};

pub(crate) fn run(extra: &[String]) -> anyhow::Result<()> {
    if !dev_dir().join("bundles/alpine/rootfs/bin/busybox").exists() {
        bail!("the Alpine test rootfs is missing: run `cargo xtask rootfs` first");
    }
    if !dev_dir().join("bundles/alpine-remap/rootfs/bin/busybox").exists() {
        bail!("the user-namespace test rootfs is missing: run `cargo xtask rootfs --remap` first");
    }
    run_cmd(cargo().args(["build", "--quiet", "-p", "rustlet-runc"]))?;
    let binaries = test_binaries()?;

    let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
    println!("itest: kernel {} ({} test binaries)", kernel.trim(), binaries.len());

    let mut failed = Vec::new();
    for (i, exe) in binaries.iter().enumerate() {
        let unit = format!("rustlet-itest-{}-{i}", std::process::id());
        let status = Command::new("sudo")
            .args(["/usr/bin/systemd-run", "--scope", "--quiet", "--collect"])
            .arg(format!("--unit={unit}"))
            .args(["-p", "Delegate=yes", "-p", "TasksMax=4096", "-p", "MemoryMax=4G", "--"])
            // sudo scrubs the environment; `env` puts back the one variable
            // worth having, without needing SETENV rights in sudoers.
            .args(["/usr/bin/env", "RUST_BACKTRACE=1"])
            .arg(exe)
            .arg("--include-ignored")
            .args(extra)
            .status()
            .context("run sudo systemd-run")?;
        if !status.success() {
            failed.push(exe.clone());
        }
    }
    // Each test binary uses its own `--root` (/run/rustlet/itest-<pid>);
    // remove the ones that ended up empty. (A failed run leaves its
    // containers there on purpose, for inspection; `scripts/cleanup.sh`
    // removes everything.)
    let _ = Command::new("sudo")
        .args(["/usr/bin/systemd-run", "--scope", "--quiet", "--collect", "--"])
        .args(["/usr/bin/find", "/run/rustlet", "-maxdepth", "1", "-name", "itest-*", "-empty", "-delete"])
        .status();
    if !failed.is_empty() {
        bail!("integration tests failed in: {failed:?}");
    }
    Ok(())
}

/// Builds the `rustlet-itests` test targets and returns their paths, from
/// cargo's JSON messages (the file names contain a hash, so they can't be
/// guessed).
fn test_binaries() -> anyhow::Result<Vec<String>> {
    let out = cargo()
        .args(["test", "-p", "rustlet-itests", "--no-run", "--message-format=json-render-diagnostics"])
        .output()
        .context("cargo test --no-run")?;
    if !out.status.success() {
        bail!("building the integration tests failed");
    }
    let mut exes = Vec::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let Ok(msg) = serde_json::from_str::<serde_json::Value>(line) else { continue };
        if msg["reason"] == "compiler-artifact"
            && msg["profile"]["test"] == true
            && let Some(exe) = msg["executable"].as_str()
        {
            exes.push(exe.to_owned());
        }
    }
    if exes.is_empty() {
        bail!("cargo produced no test binaries for rustlet-itests");
    }
    Ok(exes)
}

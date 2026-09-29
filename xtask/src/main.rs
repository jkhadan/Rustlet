//! `cargo xtask <task>`: development chores, written in Rust so they run the
//! same everywhere and need nothing but cargo.
//!
//! | task          | what it does                                                   |
//! |---------------|----------------------------------------------------------------|
//! | `rootfs`      | download Alpine's minirootfs, build the demo/test bundle; `--remap` adds the user-namespace one (via sudo) |
//! | `itest`       | build as you, then run the privileged tests as root in a limited systemd scope |
//! | `dev-storage` | put `/var/lib/rustlet` on its own loop-mounted ext4 image      |
//! | `check-host`  | report the host facts the design depends on                    |
//! | `demo`        | interactive Alpine shell with cgroup limits (`--memory 64M --pids 64`) |
//! | `seccomp`     | compile a seccomp profile to BPF: summary, `--disasm`, `--json` |
//! | `devices`     | build a device filter (defaults, or a bundle's) and show its eBPF program |
//! | `image-run`   | Phase 3                                                        |
//! | `gen-ts`      | Phase 6                                                        |
//!
//! Nothing here runs `sudo cargo`: builds always run as your user, and only
//! finished binaries are run as root (docs/architecture.md §4.7).
#![forbid(unsafe_code)]

mod checkhost;
mod demo;
mod devices;
mod devstorage;
mod itest;
mod rootfs;
mod seccomp;

use std::path::PathBuf;
use std::process::Command;

use anyhow::{Context, bail};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "cargo xtask", bin_name = "cargo xtask", about = "Rustlets development tasks")]
struct Cli {
    #[command(subcommand)]
    task: Task,
}

#[derive(Subcommand)]
enum Task {
    /// Download the Alpine minirootfs and generate .rustlet-dev/bundles/alpine.
    Rootfs {
        /// Re-extract the rootfs and overwrite config.json.
        #[arg(long)]
        force: bool,
        /// Also generate bundles/alpine-remap for user-namespace tests: a
        /// rootfs owned by host ids 1000000+ (asks for sudo to chown it).
        #[arg(long)]
        remap: bool,
    },
    /// The root half of `rootfs --remap`, which runs it through sudo.
    #[command(hide = true)]
    RemapExtract {
        /// The Alpine tarball (its sha256 is checked again).
        tarball: PathBuf,
        /// The bundle directory; must be .rustlet-dev/bundles/alpine-remap.
        bundle: PathBuf,
        /// Replace an existing rootfs.
        #[arg(long)]
        force: bool,
    },
    /// Run the privileged integration tests (tests/ crate) as root.
    Itest {
        /// Extra arguments for the test binaries, e.g. a name filter.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Create /var/lib/rustlet as a loop-mounted ext4 image (asks for sudo).
    DevStorage {
        /// Maximum size of the image (sparse; only used space costs disk).
        #[arg(long, default_value = "25G")]
        size: String,
        /// Print the commands instead of running them.
        #[arg(long)]
        dry_run: bool,
    },
    /// Check kernel, cgroups, tools and dev setup.
    CheckHost,
    /// Interactive Alpine shell with cgroup limits, in a throwaway delegated scope.
    Demo {
        /// Memory limit, e.g. 64M (no swap on top).
        #[arg(long)]
        memory: Option<String>,
        /// Maximum number of processes (try a fork bomb).
        #[arg(long)]
        pids: Option<i64>,
        /// CPU limit in CPUs, e.g. 0.5.
        #[arg(long)]
        cpus: Option<f64>,
        /// Run in a user namespace (container root = host uid 1000000); needs
        /// `cargo xtask rootfs --remap`.
        #[arg(long)]
        userns: bool,
    },
    /// Compile a seccomp profile (Docker's default, or a bundle's) and show the BPF program.
    Seccomp {
        /// Compile this bundle's `linux.seccomp` instead of Docker's profile.
        #[arg(long)]
        bundle: Option<PathBuf>,
        /// Capabilities to resolve Docker's profile for, e.g. CHOWN,SYS_ADMIN
        /// (default: the runtime's default set).
        #[arg(long, conflicts_with = "bundle")]
        caps: Option<String>,
        /// Also print the disassembled program.
        #[arg(long)]
        disasm: bool,
        /// Print the resolved OCI `linux.seccomp` as JSON instead.
        #[arg(long, conflicts_with = "disasm")]
        json: bool,
    },
    /// Build a device filter (the defaults, or a bundle's) and show its eBPF program.
    Devices {
        /// Use this bundle's `linux.resources.devices` and `linux.devices`.
        #[arg(long)]
        bundle: Option<PathBuf>,
        /// Also print the disassembled program.
        #[arg(long)]
        disasm: bool,
    },
    /// Pull an image and run it with rustlet-runc (Phase 3).
    ImageRun,
    /// Generate TypeScript types for the desktop app (Phase 6).
    GenTs,
}

fn main() -> anyhow::Result<()> {
    match Cli::parse().task {
        Task::Rootfs { force, remap } => rootfs::run(force, remap),
        Task::RemapExtract { tarball, bundle, force } => rootfs::remap_extract(&tarball, &bundle, force),
        Task::Itest { args } => itest::run(&args),
        Task::DevStorage { size, dry_run } => devstorage::run(&size, dry_run),
        Task::CheckHost => checkhost::run(),
        Task::Demo { memory, pids, cpus, userns } => demo::run(memory.as_deref(), pids, cpus, userns),
        Task::Seccomp { bundle, caps, disasm, json } => seccomp::run(bundle.as_deref(), caps.as_deref(), disasm, json),
        Task::Devices { bundle, disasm } => devices::run(bundle.as_deref(), disasm),
        Task::ImageRun => bail!("`image-run` arrives in Phase 3 (images)"),
        Task::GenTs => bail!("`gen-ts` arrives in Phase 6 (desktop app)"),
    }
}

/// The workspace root (the directory above `xtask/`).
pub(crate) fn workspace() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().expect("xtask lives in the workspace").to_owned()
}

/// `.rustlet-dev/`: generated bundles and download cache (git-ignored).
pub(crate) fn dev_dir() -> PathBuf {
    workspace().join(".rustlet-dev")
}

/// Runs a command, failing with its command line if it doesn't succeed.
pub(crate) fn run_cmd(cmd: &mut Command) -> anyhow::Result<()> {
    let shown = format!("{cmd:?}");
    let status = cmd.status().with_context(|| format!("run {shown}"))?;
    if !status.success() {
        bail!("{shown} failed: {status}");
    }
    Ok(())
}

/// The `cargo` that is running us (so `+toolchain` choices carry over).
pub(crate) fn cargo() -> Command {
    Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()))
}

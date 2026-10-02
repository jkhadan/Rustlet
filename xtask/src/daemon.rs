//! `cargo xtask daemon install|uninstall|status`: rustletd as the systemd
//! service it is meant to be (packaging/rustletd.service).
//!
//! ```text
//!  install    as you:  cargo build [--release] rustletd rustlet-shim rustlet-runc rustlet
//!             as root: copy them to /usr/local/bin (root:root 0755),
//!                      packaging/rustletd.service → /etc/systemd/system,
//!                      packaging/networkmanager-rustlet.conf →
//!                      /etc/NetworkManager/conf.d/rustlet.conf (if NetworkManager
//!                      is there; it then leaves rustlet*, rlb* and rlv* links alone),
//!                      systemctl daemon-reload, then restart rustletd
//!                      (and `enable` it with --enable)
//!  uninstall  as root: stop and disable it, remove the unit, the NetworkManager
//!                      drop-in and the binaries (images, containers, volumes and
//!                      state.db stay in /var/lib/rustlet)
//!  status     systemctl status rustletd
//! ```
//!
//! Containers survive `install` (the daemon restarts; shims keep running),
//! but a shim already running keeps the old binary it was started from.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, bail};
use clap::Subcommand;

use crate::{cargo, run_cmd, workspace};

const BINARIES: [&str; 4] = ["rustletd", "rustlet-shim", "rustlet-runc", "rustlet"];
const BIN_DIR: &str = "/usr/local/bin";
const UNIT: &str = "/etc/systemd/system/rustletd.service";
const NM_DIR: &str = "/etc/NetworkManager/conf.d";
const NM_DROP_IN: &str = "/etc/NetworkManager/conf.d/rustlet.conf";

#[derive(Subcommand, Debug, Clone)]
pub(crate) enum DaemonTask {
    /// Build, install to /usr/local/bin, install the unit, (re)start rustletd.
    Install {
        /// Install release builds (slower to build, much smaller and faster to start).
        #[arg(long)]
        release: bool,
        /// Also start it at boot.
        #[arg(long)]
        enable: bool,
    },
    /// Stop and remove the service and binaries (data in /var/lib/rustlet stays).
    Uninstall,
    /// systemctl status rustletd.
    Status,
}

pub(crate) fn run(task: &DaemonTask) -> anyhow::Result<()> {
    match task {
        DaemonTask::Install { release, .. } => {
            let mut build = cargo();
            build.args(["build", "--quiet"]);
            if *release {
                build.arg("--release");
            }
            for b in ["rustletd", "rustlet-shim", "rustlet-runc", "rustlet-cli"] {
                build.args(["-p", b]);
            }
            run_cmd(&mut build)?;
            as_root(task)
        }
        DaemonTask::Uninstall => as_root(task),
        DaemonTask::Status => {
            let _ = Command::new("systemctl").args(["status", "rustletd", "--no-pager"]).status();
            Ok(())
        }
    }
}

/// Re-runs `xtask daemon-root <same args>` through sudo.
fn as_root(_task: &DaemonTask) -> anyhow::Result<()> {
    let exe = std::env::current_exe().context("locate the xtask binary")?;
    let forwarded: Vec<OsString> = std::env::args_os().skip(2).collect();
    let status = Command::new("sudo")
        .arg(&exe)
        .arg("daemon-root")
        .args(&forwarded)
        .status()
        .context("run sudo xtask daemon-root")?;
    if !status.success() {
        bail!("xtask daemon-root failed: {status}");
    }
    Ok(())
}

/// The root half (`xtask daemon-root …`).
pub(crate) fn run_as_root(task: &DaemonTask) -> anyhow::Result<()> {
    if !nix::unistd::geteuid().is_root() {
        bail!("daemon-root must run as root (`cargo xtask daemon` runs it through sudo)");
    }
    match task {
        DaemonTask::Install { release, enable } => {
            let target = workspace().join("target").join(if *release { "release" } else { "debug" });
            for b in BINARIES {
                install_file(&target.join(b), &Path::new(BIN_DIR).join(b), 0o755)?;
            }
            let unit = std::fs::read_to_string(workspace().join("packaging/rustletd.service"))
                .context("read packaging/rustletd.service")?;
            write_file(Path::new(UNIT), unit.as_bytes(), 0o644)?;
            println!("installed  {} and {UNIT}", BINARIES.map(|b| format!("{BIN_DIR}/{b}")).join(", "));
            if Path::new(NM_DIR).is_dir() {
                install_file(&workspace().join("packaging/networkmanager-rustlet.conf"), Path::new(NM_DROP_IN), 0o644)?;
                reload_network_manager();
                println!("installed  {NM_DROP_IN} (NetworkManager leaves Rustlets' links alone)");
            }
            systemctl(&["daemon-reload"])?;
            if *enable {
                systemctl(&["enable", "rustletd"])?;
            }
            systemctl(&["restart", "rustletd"])?;
            println!("started    rustletd (`systemctl status rustletd`, `journalctl -u rustletd`)");
            Ok(())
        }
        DaemonTask::Uninstall => {
            let _ = systemctl(&["disable", "--now", "rustletd"]);
            let files = [PathBuf::from(UNIT), PathBuf::from(NM_DROP_IN)];
            for p in files.into_iter().chain(BINARIES.iter().map(|b| Path::new(BIN_DIR).join(b))) {
                match std::fs::remove_file(&p) {
                    Ok(()) => println!("removed    {}", p.display()),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e).with_context(|| format!("remove {}", p.display())),
                }
            }
            systemctl(&["daemon-reload"])?;
            reload_network_manager();
            println!(
                "left       /var/lib/rustlet (images, containers, volumes, state.db), and the bridges and nft table \
                 until reboot: `scripts/cleanup.sh [--purge]` removes them"
            );
            Ok(())
        }
        DaemonTask::Status => run(task),
    }
}

/// Copies `from` to `to` atomically (a new file, then a rename), so a
/// running binary is replaced rather than overwritten (`ETXTBSY`).
fn install_file(from: &Path, to: &Path, mode: u32) -> anyhow::Result<()> {
    let bytes = std::fs::read(from).with_context(|| format!("read {} (was it built?)", from.display()))?;
    write_file(to, &bytes, mode)
}

fn write_file(to: &Path, bytes: &[u8], mode: u32) -> anyhow::Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let tmp = to.with_extension("rustlet-new");
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(&tmp)
        .with_context(|| format!("create {}", tmp.display()))?;
    std::io::Write::write_all(&mut f, bytes).with_context(|| format!("write {}", tmp.display()))?;
    f.sync_all()?;
    drop(f);
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))?;
    std::os::unix::fs::chown(&tmp, Some(0), Some(0))?;
    std::fs::rename(&tmp, to).with_context(|| format!("move {} into place", to.display()))
}

/// Has NetworkManager read its configuration again, if it runs.
fn reload_network_manager() {
    let _ = Command::new("nmcli").args(["general", "reload", "conf"]).status();
}

fn systemctl(args: &[&str]) -> anyhow::Result<()> {
    run_cmd(Command::new("systemctl").args(args))
}

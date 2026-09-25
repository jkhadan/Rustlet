//! `cargo xtask dev-storage`: `/var/lib/rustlet` on its own filesystem.
//!
//! On this host `/`, `/home` and `/var/lib` are one ext4 filesystem. Giving
//! Rustlets' data directory a loop-mounted image of its own (§4.4 of the
//! architecture doc):
//!
//! * caps how much disk images and containers can take;
//! * means a runaway write fills *that* filesystem, not `/`;
//! * makes a full wipe trivial (`scripts/cleanup.sh --purge` deletes the image).
//!
//! The image is sparse: a 25G image only uses the blocks actually written.
//! These commands need root, and the dev sudoers file deliberately doesn't
//! allow `mkfs`/`mount`, so sudo asks for your password.

use std::path::Path;
use std::process::Command;

use anyhow::bail;

use crate::run_cmd;

const IMAGE: &str = "/var/lib/rustlet-dev-storage.img";
const MOUNT: &str = "/var/lib/rustlet";

pub(crate) fn run(size: &str, dry_run: bool) -> anyhow::Result<()> {
    if is_mountpoint(MOUNT) {
        println!("{MOUNT} is already a mount point; nothing to do.");
        return Ok(());
    }
    if Path::new(IMAGE).exists() {
        bail!("{IMAGE} exists but is not mounted; mount it with: sudo mount -o loop,noatime {IMAGE} {MOUNT}");
    }
    if std::fs::read_dir(MOUNT).is_ok_and(|mut d| d.next().is_some()) {
        bail!("{MOUNT} already has contents; move them away (or run scripts/cleanup.sh --purge) first");
    }
    let steps: [&[&str]; 5] = [
        &["truncate", "-s", size, IMAGE],
        &["chmod", "600", IMAGE],
        &["mkfs.ext4", "-q", "-L", "rustlet-dev", "-m", "0", IMAGE],
        &["mkdir", "-p", MOUNT],
        &["mount", "-o", "loop,noatime", IMAGE, MOUNT],
    ];
    for step in steps {
        if dry_run {
            println!("sudo {}", step.join(" "));
        } else {
            run_cmd(Command::new("sudo").args(step))?;
        }
    }
    println!("\nTo mount it at every boot, add this line to /etc/fstab:");
    println!("  {IMAGE} {MOUNT} ext4 loop,noatime,nofail 0 2");
    Ok(())
}

fn is_mountpoint(path: &str) -> bool {
    std::fs::read_to_string("/proc/self/mountinfo")
        .is_ok_and(|mi| mi.lines().any(|l| l.split(' ').nth(4) == Some(path)))
}

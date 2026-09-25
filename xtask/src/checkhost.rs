//! `cargo xtask check-host`: the host facts the design relies on
//! (docs/architecture.md, "Host facts"), checked read-only.

use std::path::Path;
use std::process::Command;

use crate::dev_dir;

pub(crate) fn run() -> anyhow::Result<()> {
    let mut bad = 0;
    let mut check = |ok: bool, what: &str, detail: String| {
        println!("{} {what:<26} {detail}", if ok { "ok  " } else { "FAIL" });
        if !ok {
            bad += 1;
        }
    };

    let release = read("/proc/sys/kernel/osrelease");
    let (major, minor) = kernel_version(&release);
    check((major, minor) >= (6, 8), "kernel >= 6.8", release.clone());

    let cg2 = Path::new("/sys/fs/cgroup/cgroup.controllers").exists();
    check(cg2, "cgroup v2 (unified)", read("/sys/fs/cgroup/cgroup.controllers"));
    check(true, "root subtree_control", read("/sys/fs/cgroup/cgroup.subtree_control"));

    let systemd = Command::new("systemctl")
        .arg("--version")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).split_whitespace().nth(1).unwrap_or("").to_owned())
        .unwrap_or_default();
    check(systemd.parse::<u32>().is_ok_and(|v| v >= 254), "systemd >= 254", systemd);

    for tool in ["runc", "strace", "nft", "ip", "curl"] {
        let found =
            ["/usr/sbin", "/usr/bin", "/sbin", "/bin"].iter().map(|d| Path::new(d).join(tool)).find(|p| p.exists());
        check(found.is_some(), &format!("tool: {tool}"), found.map(|p| p.display().to_string()).unwrap_or_default());
    }

    check(true, "ip_forward", read("/proc/sys/net/ipv4/ip_forward"));
    let sudoers = Path::new("/etc/sudoers.d/rustlet-dev").exists();
    check(sudoers, "dev sudoers installed", "/etc/sudoers.d/rustlet-dev".into());
    let rootfs = dev_dir().join("bundles/alpine/rootfs/bin/busybox").exists();
    check(rootfs, "alpine test rootfs", if rootfs { "present".into() } else { "run `cargo xtask rootfs`".into() });
    let storage = std::fs::read_to_string("/proc/self/mountinfo")
        .is_ok_and(|mi| mi.lines().any(|l| l.split(' ').nth(4) == Some("/var/lib/rustlet")));
    // Optional until Phase 3 stores images; so never counted as a failure.
    println!(
        "{} {:<26} {}",
        if storage { "ok  " } else { "info" },
        "dev storage",
        if storage { "/var/lib/rustlet is mounted" } else { "not set up (optional: cargo xtask dev-storage)" }
    );

    if bad > 0 {
        anyhow::bail!("{bad} check(s) failed");
    }
    Ok(())
}

fn read(path: &str) -> String {
    std::fs::read_to_string(path).map(|s| s.trim().to_owned()).unwrap_or_else(|e| format!("({e})"))
}

fn kernel_version(release: &str) -> (u32, u32) {
    let mut it = release.split(['.', '-']).map(|p| p.parse().unwrap_or(0));
    (it.next().unwrap_or(0), it.next().unwrap_or(0))
}

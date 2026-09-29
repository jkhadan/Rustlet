//! `cargo xtask rootfs [--remap]`: the Alpine bundles used by the demo and by
//! `itest`.
//!
//! ```text
//! .rustlet-dev/
//! ├─ cache/alpine-minirootfs-<ver>-x86_64.tar.gz   (sha256-pinned download)
//! └─ bundles/
//!    ├─ alpine/
//!    │  ├─ config.json                              (rustlet-runc spec's default)
//!    │  └─ rootfs/                                  (the extracted minirootfs, owned by you)
//!    └─ alpine-remap/                               (--remap only)
//!       ├─ config.json                              (the default + a user namespace)
//!       └─ rootfs/                                  (the same files, owned by 1000000 + tar ids)
//! ```
//!
//! The plain rootfs is extracted as *you*, so every file is owned by your uid
//! rather than root, and setuid/setgid bits are stripped (a setuid binary
//! owned by you would be pointless and confusing). That is fine without a
//! user namespace: busybox doesn't care who owns it.
//!
//! The remapped bundle is for user-namespace tests. Its config maps container
//! ids `0..REMAP_SIZE` to host ids `REMAP_HOST_ID..` (1000000 onwards), so its
//! rootfs must be owned by those host ids: a file that is root's in the
//! tarball belongs to host 1000000, `/etc/shadow`'s group 42 to host 1000042,
//! and so on. (Owned by you, everything would show up as `nobody` inside the
//! container.) Handing files to ids you don't own needs root, so `--remap`
//! re-runs this binary as `sudo xtask remap-extract`, which re-checks the
//! tarball's sha256, will only write to `bundles/alpine-remap/`, and does
//! nothing else as root.
//!
//! That rootfs sits under your home directory, which may be 0750 and so
//! closed to host uid 1000000. That is fine: the runtime opens the rootfs in
//! its privileged parent, before the container's user namespace exists.

use std::fs::File;
use std::io::Read;
use std::os::unix::fs::lchown;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use anyhow::{Context, bail};
use rustlet_runtime::oci_spec::runtime::Spec;
use rustlet_runtime::spec;
use sha2::{Digest, Sha256};

use crate::{dev_dir, run_cmd};

const ALPINE_BRANCH: &str = "v3.24";
const ALPINE_VERSION: &str = "3.24.2";
/// From Alpine's `latest-releases.yaml` for this version.
const ALPINE_SHA256: &str = "c5ca053cfe1d85c5b96dff8b9bc57045f7f184a30ffb6b65776409ca90388677";
/// The user-namespace bundle, relative to [`dev_dir`].
const REMAP_BUNDLE: &str = "bundles/alpine-remap";

pub(crate) fn run(force: bool, remap: bool) -> anyhow::Result<()> {
    let file = format!("alpine-minirootfs-{ALPINE_VERSION}-x86_64.tar.gz");
    let url = format!("https://dl-cdn.alpinelinux.org/alpine/{ALPINE_BRANCH}/releases/x86_64/{file}");
    let cache = dev_dir().join("cache");
    std::fs::create_dir_all(&cache)?;
    let tarball = cache.join(&file);

    if tarball.exists() && sha256(&tarball)? == ALPINE_SHA256 {
        println!("cached     {}", tarball.display());
    } else {
        let partial = tarball.with_extension("partial");
        println!("download   {url}");
        run_cmd(Command::new("curl").args(["-fL", "--retry", "3", "--progress-bar", "-o"]).arg(&partial).arg(&url))?;
        let got = sha256(&partial)?;
        if got != ALPINE_SHA256 {
            let _ = std::fs::remove_file(&partial);
            bail!("sha256 mismatch for {file}: expected {ALPINE_SHA256}, got {got}");
        }
        std::fs::rename(&partial, &tarball)?;
        println!("verified   sha256 {got}");
    }

    let bundle = dev_dir().join("bundles/alpine");
    let rootfs = bundle.join("rootfs");
    if rootfs.exists() && force {
        std::fs::remove_dir_all(&rootfs).with_context(|| {
            format!(
                "remove {} (if a container created root-owned files in it, delete it with sudo first)",
                rootfs.display()
            )
        })?;
    }
    if rootfs.exists() {
        println!("keep       {} (--force to re-extract)", rootfs.display());
    } else {
        let tmp = bundle.join("rootfs.partial");
        if tmp.exists() {
            std::fs::remove_dir_all(&tmp)?;
        }
        std::fs::create_dir_all(&tmp)?;
        let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(File::open(&tarball)?));
        archive.set_preserve_permissions(true);
        archive.set_preserve_ownerships(false);
        archive.set_mask(0o6000); // strip setuid/setgid
        archive.unpack(&tmp).with_context(|| format!("extract {file}"))?;
        std::fs::rename(&tmp, &rootfs)?;
        println!("extracted  {}", rootfs.display());
    }
    write_config(&bundle.join("config.json"), &spec::default_spec(), force)?;

    if remap {
        remap_bundle(&tarball, force)?;
    }

    println!(
        "\nTry it:\n  cargo build -p rustlet-runc\n  sudo ./target/debug/rustlet-runc run --bundle {} demo",
        rel(&bundle)
    );
    Ok(())
}

/// Writes `spec` to `config` unless it is already there; a config that
/// differs (perhaps edited by hand) is only replaced with `--force`.
fn write_config(config: &Path, spec: &Spec, force: bool) -> anyhow::Result<()> {
    match std::fs::read_to_string(config) {
        // Compared as specs, not as text: the capability sets are hash sets,
        // so their order in the JSON changes from one run to the next.
        Ok(have) if serde_json::from_str::<Spec>(&have).is_ok_and(|have| have == *spec) => {
            println!("up to date {}", config.display())
        }
        Ok(_) if !force => {
            println!("keep       {} (differs from this build's default; --force to regenerate)", config.display())
        }
        _ => {
            std::fs::write(config, spec::to_pretty_json(spec))?;
            println!("wrote      {}", config.display());
        }
    }
    Ok(())
}

/// `--remap`: builds `bundles/alpine-remap/`. The directory and its
/// config.json are yours; the rootfs comes from [`remap_extract`], run as
/// root through sudo.
fn remap_bundle(tarball: &Path, force: bool) -> anyhow::Result<()> {
    let bundle = dev_dir().join(REMAP_BUNDLE);
    std::fs::create_dir_all(&bundle)?;
    let rootfs = bundle.join("rootfs");
    if rootfs.exists() && !force {
        println!("keep       {} (--force to re-extract)", rootfs.display());
    } else {
        let exe = std::env::current_exe().context("locate the xtask binary")?;
        println!("sudo       chown to host ids {}+ needs root: {} remap-extract", spec::REMAP_HOST_ID, rel(&exe));
        // Plain `sudo`, not `sudo -n`: where running target/debug/xtask needs
        // a password, sudo asks for it.
        let mut cmd = Command::new("sudo");
        cmd.arg(&exe).arg("remap-extract").arg(tarball).arg(&bundle);
        if force {
            cmd.arg("--force");
        }
        run_cmd(&mut cmd)?;
    }

    let mut s = spec::default_spec();
    spec::with_user_namespace(&mut s, spec::REMAP_HOST_ID, spec::REMAP_SIZE);
    write_config(&bundle.join("config.json"), &s, force)
}

/// `xtask remap-extract <tarball> <bundle> [--force]`: the root half of
/// `rootfs --remap`. Extracts the pinned Alpine tarball into
/// `<bundle>/rootfs`, owned by host ids `REMAP_HOST_ID` + the uid/gid in each
/// tar header. `<bundle>` must be `.rustlet-dev/bundles/alpine-remap`.
pub(crate) fn remap_extract(tarball: &Path, bundle: &Path, force: bool) -> anyhow::Result<()> {
    if euid()? != 0 {
        bail!("remap-extract must run as root (`cargo xtask rootfs --remap` runs it through sudo)");
    }
    let allowed = dev_dir().join(REMAP_BUNDLE);
    let allowed = allowed.canonicalize().with_context(|| format!("resolve {}", allowed.display()))?;
    let bundle = bundle.canonicalize().with_context(|| format!("resolve {}", bundle.display()))?;
    if bundle != allowed {
        bail!("refusing to extract into {} as root: only {} is allowed", bundle.display(), allowed.display());
    }
    // Hash the bytes we then extract, so the file can't change in between.
    let bytes = std::fs::read(tarball).with_context(|| format!("read {}", tarball.display()))?;
    let got = hex::encode(Sha256::digest(&bytes));
    if got != ALPINE_SHA256 {
        bail!("sha256 mismatch for {}: expected {ALPINE_SHA256}, got {got}", tarball.display());
    }

    // std's remove_dir_all doesn't follow symlinks, so as root it can only
    // delete what is really inside the bundle.
    let rootfs = bundle.join("rootfs");
    if rootfs.exists() && force {
        std::fs::remove_dir_all(&rootfs).with_context(|| format!("remove {}", rootfs.display()))?;
    }
    if rootfs.exists() {
        println!("keep       {} (--force to re-extract)", rootfs.display());
        return Ok(());
    }
    let tmp = bundle.join("rootfs.partial");
    if tmp.symlink_metadata().is_ok() {
        std::fs::remove_dir_all(&tmp).with_context(|| format!("remove {}", tmp.display()))?;
    }
    std::fs::create_dir(&tmp)?;

    let archive = || tar::Archive::new(flate2::read::GzDecoder::new(bytes.as_slice()));
    let mut a = archive();
    a.set_preserve_permissions(true);
    a.set_preserve_ownerships(false); // set below, shifted by REMAP_HOST_ID
    // Strip setuid/setgid, as in the plain rootfs: the two trees should
    // differ only in ownership, and here those bits would make setuid-1000000
    // programs on the host.
    a.set_mask(0o6000);
    a.unpack(&tmp).with_context(|| format!("extract {}", tarball.display()))?;

    // Second pass: chown every entry. lchown, so a symlink itself is chowned
    // and its target (`/bin/busybox` means the host's!) is never touched.
    let root = tmp.canonicalize()?;
    lchown(&root, Some(spec::REMAP_HOST_ID), Some(spec::REMAP_HOST_ID))?; // in case there's no `./` entry
    let mut n = 0;
    for entry in archive().entries()? {
        let entry = entry?;
        let path = entry.path()?;
        let dest = inside(&root, &path)?;
        let (uid, gid) = (shift(entry.header().uid()?)?, shift(entry.header().gid()?)?);
        lchown(&dest, Some(uid), Some(gid)).with_context(|| format!("lchown {}", dest.display()))?;
        n += 1;
    }
    std::fs::rename(&tmp, &rootfs)?;
    println!("extracted  {} ({n} entries, owned by host ids {}+)", rootfs.display(), spec::REMAP_HOST_ID);
    Ok(())
}

/// `root/<path>` for an archive entry, checked the way `tar`'s own unpack
/// checks it: no `..` or absolute path, and nothing before the last
/// component resolves (through a symlink) outside `root`. The last component
/// itself isn't followed by `lchown`.
fn inside(root: &Path, path: &Path) -> anyhow::Result<PathBuf> {
    let mut dest = root.to_owned();
    for c in path.components() {
        match c {
            Component::Normal(p) => dest.push(p),
            Component::CurDir => {}
            _ => bail!("archive entry {} points outside the rootfs", path.display()),
        }
    }
    if dest != root {
        let parent = dest.parent().expect("dest is below root").canonicalize()?;
        if !parent.starts_with(root) {
            bail!("archive entry {} resolves outside the rootfs", path.display());
        }
    }
    Ok(dest)
}

/// Container id → host id. An id outside the mapping would be `nobody` in
/// the container, so it is an error rather than silently wrong.
fn shift(id: u64) -> anyhow::Result<u32> {
    match u32::try_from(id) {
        Ok(id) if id < spec::REMAP_SIZE => Ok(spec::REMAP_HOST_ID + id),
        _ => bail!("id {id} in the tarball is outside the {}-id mapping", spec::REMAP_SIZE),
    }
}

/// The effective uid, from `/proc/self/status` (`Uid: real effective saved
/// fs`); xtask has no libc bindings of its own.
fn euid() -> anyhow::Result<u32> {
    let status = std::fs::read_to_string("/proc/self/status")?;
    let uids = status.lines().find_map(|l| l.strip_prefix("Uid:")).context("no Uid: in /proc/self/status")?;
    uids.split_whitespace().nth(1).context("no effective uid in /proc/self/status")?.parse().context("parse euid")
}

fn sha256(path: &Path) -> anyhow::Result<String> {
    let mut f = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex::encode(h.finalize()))
}

fn rel(p: &Path) -> String {
    p.strip_prefix(crate::workspace()).unwrap_or(p).display().to_string()
}

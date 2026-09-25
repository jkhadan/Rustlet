//! `cargo xtask rootfs`: the Alpine bundle used by the demo and by `itest`.
//!
//! ```text
//! .rustlet-dev/
//! ├─ cache/alpine-minirootfs-<ver>-x86_64.tar.gz   (sha256-pinned download)
//! └─ bundles/alpine/
//!    ├─ config.json                                 (rustlet-runc spec's default)
//!    └─ rootfs/                                     (the extracted minirootfs)
//! ```
//!
//! The rootfs is extracted as *you*, so every file is owned by your uid
//! rather than root, and setuid/setgid bits are stripped (a setuid binary
//! owned by you would be pointless and confusing). That is fine for Phase 1:
//! busybox doesn't care who owns it. Phase 2c builds a properly chowned
//! rootfs for user-namespace tests.

use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, bail};
use rustlet_runtime::spec;
use sha2::{Digest, Sha256};

use crate::{dev_dir, run_cmd};

const ALPINE_BRANCH: &str = "v3.24";
const ALPINE_VERSION: &str = "3.24.2";
/// From Alpine's `latest-releases.yaml` for this version.
const ALPINE_SHA256: &str = "c5ca053cfe1d85c5b96dff8b9bc57045f7f184a30ffb6b65776409ca90388677";

pub(crate) fn run(force: bool) -> anyhow::Result<()> {
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

    let config = bundle.join("config.json");
    let want = spec::to_pretty_json(&spec::default_spec());
    match std::fs::read_to_string(&config) {
        Ok(have) if have == want => println!("up to date {}", config.display()),
        Ok(_) if !force => {
            println!("keep       {} (differs from this build's default; --force to regenerate)", config.display())
        }
        _ => {
            std::fs::write(&config, want)?;
            println!("wrote      {}", config.display());
        }
    }

    println!(
        "\nTry it:\n  cargo build -p rustlet-runc\n  sudo ./target/debug/rustlet-runc run --bundle {} demo",
        rel(&bundle)
    );
    Ok(())
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

//! `cargo xtask image-run [OPTIONS] IMAGE [ARGS…]`: pull an image and run
//! it with `rustlet-runc`. The whole of Phase 3 in one command, standing in
//! for the daemon until Phase 4.
//!
//! ```text
//!  as you   cargo build -p rustlet-runc
//!           sudo target/debug/xtask image-run-root <the same arguments>
//!  as root  pull      registry → /var/lib/rustlet/content       (skipped if the store has it)
//!           unpack    → snapshots/<chain ID>/fs                  (skipped per layer if done)
//!           overlay   → containers/<id>/rootfs                   (idmapped layers with --userns)
//!           spec      image config + your flags → containers/<id>/config.json
//!           run       systemd-run --scope -p Delegate=yes … rustlet-runc run
//!           clean up  unmount, delete containers/<id>             (--keep keeps it)
//! ```
//!
//! The scope gives the container a delegated cgroup, so it gets the device
//! filter and `--memory`/`--pids`/`--cpus` work, exactly as in `demo`. No
//! network yet (Phase 5): the container has its own network namespace with
//! only `lo`. Try `cargo xtask image-run alpine`, `… nginx`, `…
//! python:3-slim`, each with and without `--userns`.

use std::ffi::OsString;
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, bail};
use clap::Args;
use rustlet_image::import::{config, import};
use rustlet_image::pull::{self, BlobKind, Progress, PullOptions, PullPolicy, Puller};
use rustlet_image::rootfs::{ContainerRootfs, remap};
use rustlet_image::runspec::{self, RunOptions};
use rustlet_image::snapshot::SnapshotEvent;
use rustlet_image::{Digest, Image, ImageRef, Store};

use crate::demo::{resources, scope_script};
use crate::{cargo, dev_dir, run_cmd};

#[derive(Args, Debug, Clone)]
pub(crate) struct ImageRunArgs {
    /// The image, e.g. alpine, nginx:1.27, python:3-slim, ghcr.io/owner/name:tag.
    image: String,
    /// Command and arguments, replacing the image's CMD.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    args: Vec<String>,
    /// Run in a user namespace (container root = host uid 1000000), on idmapped layers.
    #[arg(long)]
    userns: bool,
    /// When to contact the registry.
    #[arg(long, default_value = "missing", value_parser = ["missing", "always", "never"])]
    pull: String,
    /// Allocate a terminal (the default when stdin is one).
    #[arg(short = 't', long, conflicts_with = "no_tty")]
    tty: bool,
    /// Don't allocate a terminal.
    #[arg(long)]
    no_tty: bool,
    /// Set an environment variable (repeatable).
    #[arg(short = 'e', long = "env", value_name = "KEY=VALUE")]
    env: Vec<String>,
    /// Run as USER[:GROUP] (names or ids from the image's /etc/passwd and /etc/group).
    #[arg(short = 'u', long)]
    user: Option<String>,
    /// Working directory inside the container.
    #[arg(short = 'w', long)]
    workdir: Option<String>,
    /// Replace the image's ENTRYPOINT ("" clears it).
    #[arg(long)]
    entrypoint: Option<String>,
    /// Mount the rootfs read-only.
    #[arg(long)]
    read_only: bool,
    /// Memory limit, e.g. 256M (no swap on top).
    #[arg(long)]
    memory: Option<String>,
    /// Maximum number of processes.
    #[arg(long)]
    pids: Option<i64>,
    /// CPU limit in CPUs, e.g. 0.5.
    #[arg(long)]
    cpus: Option<f64>,
    /// Keep containers/<id> (the writable layer) after the container exits.
    #[arg(long)]
    keep: bool,
    /// Print pull progress as NDJSON, the stream the daemon will send.
    #[arg(long)]
    json_progress: bool,
    /// Store IMAGE as an import of the cached Alpine minirootfs instead of pulling it (offline).
    #[arg(long)]
    local_alpine: bool,
    /// The image store.
    #[arg(long, default_value = Store::DEFAULT_ROOT)]
    store: PathBuf,
}

/// The user's half: build, then hand over to root. The arguments were
/// parsed (so mistakes show up before sudo asks for a password) and are
/// forwarded as they were typed.
pub(crate) fn run(_args: &ImageRunArgs) -> anyhow::Result<()> {
    run_cmd(cargo().args(["build", "--quiet", "-p", "rustlet-runc"]))?;
    let exe = std::env::current_exe().context("locate the xtask binary")?;
    // Everything after `image-run`, unchanged.
    let forwarded: Vec<OsString> = std::env::args_os().skip(2).collect();
    let status = Command::new("sudo")
        .arg(&exe)
        .arg("image-run-root")
        .args(&forwarded)
        .status()
        .context("run sudo xtask image-run-root")?;
    std::process::exit(status.code().unwrap_or(1));
}

/// The root half (`xtask image-run-root`).
pub(crate) fn run_as_root(args: &ImageRunArgs) -> anyhow::Result<()> {
    if !nix_is_root() {
        bail!("image-run-root must run as root (`cargo xtask image-run` runs it through sudo)");
    }
    let store = Store::open(&args.store).with_context(|| format!("open the image store {}", args.store.display()))?;
    let image = if args.local_alpine { local_alpine(&store, args)? } else { pull(&store, args)? };
    println!(
        "image      {} = {} ({}, {} layers, {})",
        image.display_name(),
        image.manifest_digest,
        image.config.platform(),
        image.layers.len(),
        size(image.compressed_size())
    );
    image.config.check_runnable()?;

    let snapshots = store.snapshots().ensure(store.content(), &image, &mut print_snapshot)?;
    let id = container_id();
    let short = &id[..12];
    let dir = store.containers_dir().join(&id);
    let maps = remap();
    let mut rootfs = ContainerRootfs::mount(&dir, &snapshots, args.userns.then_some(&maps))?;
    println!(
        "rootfs     {} (overlay of {} layers{})",
        rootfs.rootfs().display(),
        snapshots.len(),
        if args.userns { ", idmapped" } else { "" }
    );

    let result = run_container(args, &image, &rootfs, &id);
    if args.keep {
        rootfs.unmount()?;
        println!("kept       {} (upper/ is the container's writable layer)", dir.display());
    } else {
        rootfs.remove()?;
    }
    let code = result?;
    println!("exited     {short}: status {code}");
    std::process::exit(code);
}

fn run_container(args: &ImageRunArgs, image: &Image, rootfs: &ContainerRootfs, id: &str) -> anyhow::Result<i32> {
    let short = &id[..12];
    let tty = args.tty || (!args.no_tty && std::io::stdin().is_terminal());
    let options = RunOptions {
        args: args.args.clone(),
        entrypoint: args.entrypoint.as_ref().map(|e| if e.is_empty() { Vec::new() } else { vec![e.clone()] }),
        env: args.env.clone(),
        user: args.user.clone(),
        workdir: args.workdir.clone(),
        tty,
        hostname: Some(short.to_owned()),
        readonly_rootfs: args.read_only,
        userns_remap: args.userns,
    };
    let mut spec = runspec::build(image, &rootfs.rootfs(), &options)?;
    let unit = format!("rustlet-image-run-{}", std::process::id());
    let scope = format!("/system.slice/{unit}.scope");
    let linux = spec.linux_mut().get_or_insert_with(Default::default);
    linux.set_cgroups_path(Some(format!("{scope}/{short}").into()));
    linux.set_resources(Some(resources(args.memory.as_deref(), args.pids, args.cpus)?));
    let config = rootfs.dir().join("config.json");
    std::fs::write(&config, rustlet_runtime::spec::to_pretty_json(&spec))
        .with_context(|| format!("write {}", config.display()))?;
    let process = spec.process().as_ref().expect("runspec sets a process");
    println!(
        "run        {short}: {:?} as {}:{} in {}{}",
        process.args().as_deref().unwrap_or_default(),
        process.user().uid(),
        process.user().gid(),
        process.cwd().display(),
        if args.userns { ", user namespace 0 → 1000000" } else { "" }
    );

    let script = scope_script(&scope, Path::new("/run/rustlet/image-run"), rootfs.dir(), short);
    let mut child = Command::new("/usr/bin/systemd-run")
        .args(["--scope", "--quiet", "--collect"])
        .arg(format!("--unit={unit}"))
        .args(["-p", "Delegate=yes", "--", "/bin/sh", "-c", &script])
        .spawn()
        .context("run systemd-run")?;
    // From here on a Ctrl-C (or a closed terminal) is the container's
    // business; this process must survive it to unmount the rootfs. Ignored
    // only now, after the spawn: ignored signals are inherited across exec,
    // and rustlet-runc forwards SIGINT to the container.
    for sig in [libc::SIGINT, libc::SIGQUIT, libc::SIGHUP, libc::SIGTERM] {
        rustlet_sys::signal::ignore(sig)?;
    }
    let status = child.wait().context("wait for the container")?;
    Ok(status.code().unwrap_or(1))
}

fn pull(store: &Store, args: &ImageRunArgs) -> anyhow::Result<Image> {
    let reference = ImageRef::parse(&args.image)?;
    let policy = match args.pull.as_str() {
        "always" => PullPolicy::Always,
        "never" => PullPolicy::Never,
        _ => PullPolicy::Missing,
    };
    let puller = Puller::new(PullOptions::default());
    let json = args.json_progress;
    let tty = std::io::stdout().is_terminal();
    let printer = move |p: &Progress| print_progress(p, json, tty);
    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build().context("start tokio")?;
    let image = runtime.block_on(pull::ensure(store.content(), &puller, &reference, policy, &printer))?;
    Ok(image)
}

/// `--local-alpine`: the Alpine minirootfs from `cargo xtask rootfs`'s
/// cache, imported as a one-layer image named IMAGE.
fn local_alpine(store: &Store, args: &ImageRunArgs) -> anyhow::Result<Image> {
    let name = ImageRef::parse(&args.image)?.name();
    if args.pull != "always"
        && let Ok(image) = Image::load(store.content(), &name)
    {
        return Ok(image);
    }
    let cache = dev_dir().join("cache");
    let tarball = std::fs::read_dir(&cache)
        .with_context(|| format!("{}: run `cargo xtask rootfs` first", cache.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .find(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("alpine-minirootfs-") && n.ends_with(".tar.gz"))
        })
        .with_context(|| format!("no Alpine minirootfs in {}: run `cargo xtask rootfs` first", cache.display()))?;
    let mut tar = Vec::new();
    std::io::Read::read_to_end(&mut flate2::read::GzDecoder::new(std::fs::File::open(&tarball)?), &mut tar)?;
    println!("import     {} as {name}", tarball.display());
    let env = ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"];
    Ok(import(store.content(), &name, &[tar], config(&["/bin/sh"], &env, None)?)?)
}

fn print_progress(p: &Progress, json: bool, tty: bool) {
    if json {
        println!("{}", serde_json::to_string(p).expect("progress serializes"));
        return;
    }
    let kind = |k: &BlobKind| match k {
        BlobKind::Config => "config",
        BlobKind::Layer => "layer ",
    };
    match p {
        Progress::Resolving { reference } => println!("resolve    {reference}"),
        Progress::Resolved { manifest, repo_digest, platform, layers, size: total, .. } => {
            println!("manifest   {manifest} for {platform}, {layers} layers, {}", size(*total));
            if repo_digest != manifest {
                println!("index      {repo_digest}");
            }
        }
        Progress::Exists { kind: k, digest, size: n } => {
            println!("  {} {} already stored ({})", kind(k), short(digest), size(*n))
        }
        Progress::Downloading { kind: k, digest, current, total } if tty => {
            print!("\r  {} {} {} / {}   ", kind(k), short(digest), size(*current), size(*total));
            let _ = std::io::stdout().flush();
        }
        Progress::Downloading { .. } => {}
        Progress::Downloaded { kind: k, digest, size: n } => {
            if tty {
                print!("\r");
            }
            println!("  {} {} downloaded and verified ({})        ", kind(k), short(digest), size(*n));
        }
        Progress::Done { reference, .. } => println!("stored     {reference}"),
    }
}

fn print_snapshot(e: SnapshotEvent<'_>) {
    match e {
        SnapshotEvent::Exists { layer } => println!("  layer  {} already unpacked", short(&layer.chain_id)),
        SnapshotEvent::Unpacking { layer } => {
            print!("  layer  {} unpacking {} … ", short(&layer.blob), size(layer.size));
            let _ = std::io::stdout().flush();
        }
        SnapshotEvent::Unpacked { report, .. } => {
            let mut extra = Vec::new();
            if report.whiteouts > 0 {
                extra.push(format!("{} whiteouts", report.whiteouts));
            }
            if report.opaque_dirs > 0 {
                extra.push(format!("{} opaque dirs", report.opaque_dirs));
            }
            if !report.skipped_devices.is_empty() {
                extra.push(format!("{} device nodes skipped", report.skipped_devices.len()));
            }
            let extra = if extra.is_empty() { String::new() } else { format!(", {}", extra.join(", ")) };
            println!("{} entries, {} of files{extra}; diff ID verified", report.entries, size(report.bytes));
        }
    }
}

fn short(d: &Digest) -> &str {
    d.short()
}

/// `3.4 MiB`-style sizes.
pub(crate) fn size(bytes: u64) -> String {
    match bytes {
        b if b >= 1 << 30 => format!("{:.1} GiB", b as f64 / (1u64 << 30) as f64),
        b if b >= 1 << 20 => format!("{:.1} MiB", b as f64 / (1u64 << 20) as f64),
        b if b >= 1 << 10 => format!("{:.1} KiB", b as f64 / 1024.0),
        b => format!("{b} B"),
    }
}

/// 64 hex digits, like Docker's container ids; the first 12 are the
/// hostname and the cgroup name.
fn container_id() -> String {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    let mut seed = format!("{}-{}", now.as_nanos(), std::process::id()).into_bytes();
    let mut random = [0u8; 16];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let _ = std::io::Read::read_exact(&mut f, &mut random);
    }
    seed.extend_from_slice(&random);
    Digest::of(&seed).hex().to_owned()
}

fn nix_is_root() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| s.lines().find_map(|l| l.strip_prefix("Uid:")).map(str::to_owned))
        .and_then(|uids| uids.split_whitespace().nth(1).map(|e| e == "0"))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_and_ids() {
        assert_eq!(size(512), "512 B");
        assert_eq!(size(3 << 20), "3.0 MiB");
        let (a, b) = (container_id(), container_id());
        assert_eq!(a.len(), 64);
        assert_ne!(a, b);
    }
}

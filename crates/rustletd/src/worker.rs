//! `rustletd worker pull|unpack`: the child process image work runs in.
//!
//! A pull parses what a registry sends and an unpack what an image's
//! layers contain, and both can be made to allocate a lot: the `tar` crate
//! reads a GNU long-name or PAX header into memory whole (Go caps those at
//! 1 MiB), and `oci-client` buffers a manifest response whole before our
//! size check sees it. In the long-lived daemon that would be the daemon's
//! memory. So the daemon starts this child instead, in a cgroup of its own
//! with `memory.max` (and no swap): a hostile image gets the child
//! OOM-killed, and the daemon reports a failed pull.
//!
//! The child moves itself into that cgroup before it does anything else,
//! and reports progress as NDJSON [`PullEvent`]s on stdout, the same lines
//! the daemon streams to the client.

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Subcommand;
use rustlet_image::pull::{self, PullOptions, PullPolicy, Puller};
use rustlet_image::snapshot::SnapshotEvent;
use rustlet_image::{Image, ImageRef, Store};
use rustlet_spec::image::PullEvent;

#[derive(Subcommand, Debug, Clone)]
pub enum WorkerCommand {
    /// Pull an image (unless the policy says otherwise) and unpack it.
    Pull {
        #[arg(long)]
        data_root: PathBuf,
        #[arg(long)]
        reference: String,
        #[arg(long, value_parser = ["missing", "always", "never"])]
        policy: String,
        #[arg(long)]
        cgroup: Option<String>,
        #[arg(long = "insecure-registry")]
        insecure: Vec<String>,
    },
    /// Unpack the layers of an image already in the store.
    Unpack {
        #[arg(long)]
        data_root: PathBuf,
        /// A name or a manifest digest.
        #[arg(long)]
        image: String,
        #[arg(long)]
        cgroup: Option<String>,
    },
}

pub fn run(cmd: WorkerCommand) -> ExitCode {
    let cgroup = match &cmd {
        WorkerCommand::Pull { cgroup, .. } | WorkerCommand::Unpack { cgroup, .. } => cgroup.clone(),
    };
    if let Some(cg) = cgroup {
        let procs = format!("/sys/fs/cgroup{cg}/cgroup.procs");
        if let Err(e) = std::fs::write(&procs, "0") {
            emit(&PullEvent::Error { message: format!("move into {procs}: {e}") });
            return ExitCode::from(1);
        }
    }
    let result = match cmd {
        WorkerCommand::Pull { data_root, reference, policy, insecure, .. } => {
            pull_and_unpack(&data_root, &reference, &policy, insecure)
        }
        WorkerCommand::Unpack { data_root, image, .. } => {
            Store::open(&data_root).map_err(|e| e.to_string()).and_then(|store| unpack(&store, &image, &image))
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            emit(&PullEvent::Error { message });
            ExitCode::from(1)
        }
    }
}

fn emit(e: &PullEvent) {
    let mut out = std::io::stdout().lock();
    let _ = serde_json::to_writer(&mut out, e);
    let _ = out.write_all(b"\n");
    let _ = out.flush();
}

fn pull_and_unpack(
    data_root: &std::path::Path,
    reference: &str,
    policy: &str,
    insecure: Vec<String>,
) -> Result<(), String> {
    let store = Store::open(data_root).map_err(|e| e.to_string())?;
    let r = ImageRef::parse(reference).map_err(|e| e.to_string())?;
    let policy = match policy {
        "always" => PullPolicy::Always,
        "never" => PullPolicy::Never,
        _ => PullPolicy::Missing,
    };
    let puller = Puller::new(PullOptions { insecure_registries: insecure, ..PullOptions::default() });
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|e| format!("start tokio: {e}"))?;
    let printer = |p: &pull::Progress| {
        // `Progress` writes the same JSON as the first `PullEvent`s.
        let mut out = std::io::stdout().lock();
        let _ = serde_json::to_writer(&mut out, p);
        let _ = out.write_all(b"\n");
        let _ = out.flush();
    };
    let image =
        runtime.block_on(pull::ensure(store.content(), &puller, &r, policy, &printer)).map_err(|e| e.to_string())?;
    drop(runtime);
    unpack(&store, &image.manifest_digest.to_string(), &r.name())
}

fn unpack(store: &Store, image: &str, reference: &str) -> Result<(), String> {
    let image = Image::load(store.content(), image).map_err(|e| e.to_string())?;
    image.config.check_runnable().map_err(|e| e.to_string())?;
    store
        .snapshots()
        .ensure(store.content(), &image, &mut |e| {
            emit(&match e {
                SnapshotEvent::Exists { layer } => PullEvent::LayerExists { chain_id: layer.chain_id.to_string() },
                SnapshotEvent::Unpacking { layer } => PullEvent::Unpacking {
                    chain_id: layer.chain_id.to_string(),
                    blob: layer.blob.to_string(),
                    size: layer.size,
                },
                SnapshotEvent::Unpacked { layer, report } => PullEvent::Unpacked {
                    chain_id: layer.chain_id.to_string(),
                    entries: report.entries,
                    bytes: report.bytes,
                    whiteouts: report.whiteouts,
                    opaque_dirs: report.opaque_dirs,
                    skipped_devices: report.skipped_devices.len() as u64,
                },
            })
        })
        .map_err(|e| e.to_string())?;
    emit(&PullEvent::Ready { reference: reference.to_owned(), manifest: image.manifest_digest.to_string() });
    Ok(())
}

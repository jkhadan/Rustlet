//! `rustlet-shim`: started by rustletd, one per container start (see the
//! library docs for why it exists).
//!
//! ```text
//!  1. setsid()                 a session of its own: no controlling terminal, and
//!                              nothing sent to the daemon's process group reaches it
//!  2. PR_SET_CHILD_SUBREAPER   orphans below it (container init) come to it
//!  3. --cgroup                 out of the daemon's cgroup, into the shims' one
//!  4. bind shim.sock, set up stdio, rustlet-runc create
//!  5. one JSON line on stdout (Ready or Failed), then stdout → /dev/null
//!  6. serve shim.sock until Shutdown
//! ```
//!
//! Its stderr is `shim.log` (the daemon opens it), so a shim that outlives
//! the daemon still has somewhere to write.
#![forbid(unsafe_code)]

mod reaper;
mod runc;
mod server;
mod stdio;

use std::io::Write;
use std::os::fd::AsFd;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Context;
use clap::Parser;
use rustlet_shim::protocol::Handshake;
use rustlet_shim::{DEFAULT_LOG_MAX_FILES, DEFAULT_LOG_MAX_SIZE};

#[derive(Parser, Debug)]
#[command(name = "rustlet-shim", version, about = "Rustlets' per-container shim (started by rustletd)")]
struct Cli {
    #[arg(long)]
    id: String,
    #[arg(long)]
    bundle: PathBuf,
    #[arg(long)]
    dir: PathBuf,
    #[arg(long)]
    runtime: PathBuf,
    #[arg(long)]
    runtime_root: PathBuf,
    #[arg(long)]
    cgroup: Option<String>,
    #[arg(long)]
    log_path: PathBuf,
    #[arg(long, default_value_t = DEFAULT_LOG_MAX_SIZE)]
    log_max_size: u64,
    #[arg(long, default_value_t = DEFAULT_LOG_MAX_FILES)]
    log_max_files: u32,
    #[arg(long)]
    stdin: bool,
    #[arg(long)]
    stdin_once: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_ansi(false)
        .with_writer(std::io::stderr)
        .init();
    if let Err(e) = detach(&cli) {
        handshake(&Handshake::Failed { message: format!("{e:#}"), exit_code: None });
        return ExitCode::from(1);
    }
    let config = server::Config {
        id: cli.id,
        bundle: cli.bundle,
        dir: cli.dir,
        runtime: cli.runtime,
        runtime_root: cli.runtime_root,
        log_path: cli.log_path,
        log_max_size: cli.log_max_size,
        log_max_files: cli.log_max_files,
        stdin: cli.stdin,
        stdin_once: cli.stdin_once,
    };
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            handshake(&Handshake::Failed { message: format!("start tokio: {e}"), exit_code: None });
            return ExitCode::from(1);
        }
    };
    let local = tokio::task::LocalSet::new();
    match local.block_on(&runtime, server::run(config)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!("{e:#}");
            ExitCode::from(1)
        }
    }
}

/// Steps 1–3: away from the daemon, before anything is started.
fn detach(cli: &Cli) -> anyhow::Result<()> {
    nix::unistd::setsid().context("setsid")?;
    rustlet_sys::prctl::set_child_subreaper().context("become a child subreaper")?;
    if let Some(cg) = &cli.cgroup {
        let procs = format!("/sys/fs/cgroup{cg}/cgroup.procs");
        // "0": the writing process. Nothing else runs in the shim yet.
        std::fs::write(&procs, "0").with_context(|| format!("move into {procs}"))?;
    }
    rustlet_sys::prctl::set_name("rustlet-shim").ok();
    Ok(())
}

/// Step 5: the one line for the daemon. Afterwards stdout is /dev/null, so
/// that nothing written later can block on, or fail at, a pipe whose reader
/// (the daemon that started us) may be long gone.
pub(crate) fn handshake(h: &Handshake) {
    let mut line = serde_json::to_vec(h).expect("handshakes serialize");
    line.push(b'\n');
    let mut out = std::io::stdout().lock();
    if let Err(e) = out.write_all(&line).and_then(|()| out.flush()) {
        tracing::warn!("report to the daemon: {e}");
    }
    drop(out);
    match std::fs::File::open("/dev/null") {
        Ok(null) => {
            if let Err(e) = rustlet_sys::term::dup2_stdio(null.as_fd(), 1) {
                tracing::warn!("point stdout at /dev/null: {e}");
            }
        }
        Err(e) => tracing::warn!("open /dev/null: {e}"),
    }
}

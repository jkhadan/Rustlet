//! # rustletd: the Rustlets daemon
//!
//! ```text
//!  rustlet (CLI), desktop ──HTTP/JSON over /run/rustlet/rustlet.sock──► rustletd
//!                                                                         │ state.db, events
//!                     per container start: rustlet-shim ◄─────────────────┤ shim.sock
//!                                           └► rustlet-runc create/start/…│
//!                     per pull or unpack:   rustletd worker (memory-limited cgroup)
//! ```
//!
//! The daemon decides and remembers; it never forks a container process
//! itself. Each running container has a shim (`rustlet-shim`), which holds
//! its stdio and is its parent, so containers outlive the daemon:
//! `systemctl restart rustletd` (with `KillMode=process`) restarts only the
//! daemon, and the new one takes the shims over again
//! (`lifecycle::reconcile`).
//!
//! | module | what |
//! |---|---|
//! | `config` | daemon.toml and the paths derived from it |
//! | `daemon` | shared state, startup |
//! | `db` | state.db (SQLite) |
//! | `container`, `lifecycle` | the container state machine, the shim, restart policies |
//! | `attach`, `exec` | WebSocket sessions bridged to shim streams |
//! | `logs`, `stats`, `events` | the streams |
//! | `images`, `worker` | pulls and unpacks in memory-limited children, rmi + GC |
//! | `network` | networks, a run's namespace, address, DNS names and published ports, the firewall |
//! | `volumes` | volumes, mounts, copy-up |
//! | `spec` | image + options → config.json |
//! | `api` | the HTTP routes |
#![forbid(unsafe_code)]

mod api;
mod attach;
mod config;
mod container;
mod daemon;
mod db;
mod error;
mod events;
mod exec;
mod images;
mod lifecycle;
mod logs;
mod names;
mod network;
mod notify;
mod spec;
mod stats;
mod volumes;
mod worker;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::Context;
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "rustletd", version, about = "The Rustlets container daemon")]
struct Cli {
    /// Configuration file (default /etc/rustlet/daemon.toml, if it exists).
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    /// The API socket.
    #[arg(long)]
    socket: Option<PathBuf>,
    /// The group allowed to use the socket ("" for none).
    #[arg(long)]
    socket_group: Option<String>,
    /// Images, container layers and state.db.
    #[arg(long)]
    data_root: Option<PathBuf>,
    /// The socket, runtime state, shims.
    #[arg(long)]
    run_root: Option<PathBuf>,
    /// The delegated cgroup to put container, shim and worker cgroups in.
    #[arg(long)]
    cgroup_parent: Option<String>,
    /// rustlet-runc.
    #[arg(long)]
    runtime: Option<PathBuf>,
    /// rustlet-shim.
    #[arg(long)]
    shim: Option<PathBuf>,
    /// Log filter (RUST_LOG syntax), default "info".
    #[arg(long)]
    log_level: Option<String>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// (Internal) image work in a child process.
    #[command(subcommand, hide = true)]
    Worker(worker::WorkerCommand),
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let filter = cli.log_level.clone().or_else(|| std::env::var("RUST_LOG").ok()).unwrap_or_else(|| "info".into());
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(filter))
        .with_ansi(false)
        .with_writer(std::io::stderr)
        .init();
    if let Some(Command::Worker(w)) = cli.command {
        return worker::run(w);
    }
    let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("rustletd: start tokio: {e}");
            return ExitCode::from(1);
        }
    };
    match runtime.block_on(serve(cli)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!("{e:#}");
            notify::notify(&format!("STATUS=failed: {e:#}"));
            ExitCode::from(1)
        }
    }
}

async fn serve(cli: Cli) -> anyhow::Result<()> {
    let mut config = config::Config::load(cli.config.as_deref())?;
    if let Some(v) = cli.socket {
        config.socket = v;
    }
    if let Some(v) = cli.socket_group {
        config.socket_group = Some(v).filter(|g| !g.is_empty());
    }
    if let Some(v) = cli.data_root {
        config.data_root = v;
    }
    if let Some(v) = cli.run_root {
        config.run_root = v;
    }
    if let Some(v) = cli.cgroup_parent {
        config.cgroup_parent = Some(v);
    }
    if let Some(v) = cli.runtime {
        config.runtime = Some(v);
    }
    if let Some(v) = cli.shim {
        config.shim = Some(v);
    }
    let socket = config.socket.clone();
    let group = config.socket_group.clone();
    let daemon = daemon::Daemon::open(config).await?;
    let listener = bind(&socket, group.as_deref())?;
    tracing::info!(
        socket = %socket.display(),
        cgroup = %daemon.cgroup_parent,
        containers = daemon.all_containers().len(),
        "rustletd ready"
    );
    notify::notify("READY=1");
    let app = api::router(daemon);
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut int = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    tokio::select! {
        r = axum::serve(listener, app) => r.context("serve the API")?,
        _ = term.recv() => tracing::info!("SIGTERM: stopping (containers keep running)"),
        _ = int.recv() => tracing::info!("SIGINT: stopping (containers keep running)"),
    }
    // Open streams (logs -f, attach) end with the process; containers and
    // their shims don't notice.
    notify::notify("STOPPING=1");
    let _ = std::fs::remove_file(&socket);
    Ok(())
}

/// The API socket: mode 0660 and the socket group's, if that group
/// exists; otherwise 0600 (root only).
fn bind(path: &Path, group: Option<&str>) -> anyhow::Result<tokio::net::UnixListener> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    }
    match std::fs::symlink_metadata(path) {
        Ok(m) if std::os::unix::fs::FileTypeExt::is_socket(&m.file_type()) => std::fs::remove_file(path)?,
        Ok(_) => anyhow::bail!("{} exists and is not a socket", path.display()),
        Err(_) => {}
    }
    let listener = tokio::net::UnixListener::bind(path).with_context(|| format!("listen on {}", path.display()))?;
    let gid = group.and_then(|g| match nix::unistd::Group::from_name(g) {
        Ok(Some(gr)) => Some(gr.gid),
        _ => {
            tracing::info!("no group {g:?}: the socket is root's only");
            None
        }
    });
    match gid {
        Some(gid) => {
            nix::unistd::chown(path, None, Some(gid)).with_context(|| format!("chown {}", path.display()))?;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
        }
        None => std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?,
    }
    Ok(listener)
}

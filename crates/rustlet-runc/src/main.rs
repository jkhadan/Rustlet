//! `rustlet-runc`: a runc-compatible command line for `rustlet-runtime`.
//!
//! The command names and flags follow runc, so that tools written for runc
//! (and, later, our own shim and youki's `contest` suite) can drive it, and
//! so you can swap in `runc` to tell a runtime bug from a daemon bug.
//!
//! ```sh
//! cargo xtask rootfs                       # Alpine bundle in .rustlet-dev/bundles/alpine
//! sudo ./target/debug/rustlet-runc run --bundle .rustlet-dev/bundles/alpine demo
//! ```
//!
//! The OCI lifecycle, as separate steps:
//!
//! ```sh
//! rustlet-runc create --bundle B web     # set up; init waits before execve
//! rustlet-runc start web                 # init execs the program
//! rustlet-runc state web                 # {"status": "running", …}
//! rustlet-runc kill web TERM
//! rustlet-runc delete web
//! ```
#![forbid(unsafe_code)]

use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::ExitCode;
use std::str::FromStr;

use anyhow::{Context, bail};
use clap::{Parser, Subcommand, ValueEnum};
use rustlet_runtime::nix_signal::Signal;
use rustlet_runtime::oci_spec::runtime::Spec;
use rustlet_runtime::{CreateOptions, Errno, Error, ExecArgs, ExecOptions, ExecProcess, RunOptions, ops, spec};

#[derive(Parser, Debug)]
#[command(name = "rustlet-runc", version, about = "Rustlets' OCI runtime (runc-compatible CLI)")]
struct Cli {
    /// Directory for container state.
    #[arg(long, global = true, default_value = rustlet_runtime::state::DEFAULT_ROOT, value_name = "DIR")]
    root: PathBuf,
    /// Write log messages to this file instead of stderr.
    #[arg(long, global = true, value_name = "FILE")]
    log: Option<PathBuf>,
    /// Log format.
    #[arg(long, global = true, value_enum, default_value_t = LogFormat::Text)]
    log_format: LogFormat,
    /// Enable debug logging (also: RUST_LOG=rustlet_runtime=trace).
    #[arg(long, global = true)]
    debug: bool,
    /// Use systemd's cgroup driver (`slice:prefix:name` paths): not supported.
    #[arg(long, global = true, hide = true)]
    systemd_cgroup: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum LogFormat {
    Text,
    Json,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum Format {
    Table,
    Json,
}

/// Flags shared by `create` and `run`.
#[derive(clap::Args, Debug)]
struct CreateArgs {
    /// Bundle directory (holds config.json).
    #[arg(short, long, default_value = ".", value_name = "DIR")]
    bundle: PathBuf,
    /// Write the container init's (host) PID to this file.
    #[arg(long, value_name = "FILE")]
    pid_file: Option<PathBuf>,
    /// Listening Unix socket that receives the container's PTY master.
    #[arg(long, value_name = "PATH")]
    console_socket: Option<PathBuf>,
    /// Pass N extra file descriptors (3..3+N) to the container.
    #[arg(long, default_value_t = 0, value_name = "N")]
    preserve_fds: u32,
    /// Use chroot instead of pivot_root (not supported: pivot_root only).
    #[arg(long)]
    no_pivot: bool,
    /// Keep the caller's session keyring instead of creating one for the container.
    #[arg(long)]
    no_new_keyring: bool,
    /// Container ID.
    id: String,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Create and start a container; in the foreground, wait for it and delete it afterwards.
    Run {
        #[command(flatten)]
        args: CreateArgs,
        /// Return once the program runs, leaving the container behind.
        #[arg(short, long)]
        detach: bool,
    },
    /// Create a container: set it up and leave init waiting for `start`.
    Create {
        #[command(flatten)]
        args: CreateArgs,
    },
    /// Start a created container (init execs the program).
    Start { id: String },
    /// Print a container's state as JSON.
    State { id: String },
    /// Send a signal (default TERM) to a container's init.
    Kill {
        /// Signal every process in the container's cgroup.
        #[arg(short, long)]
        all: bool,
        id: String,
        /// Signal name or number: TERM, SIGTERM, 15, KILL, …
        signal: Option<String>,
    },
    /// Delete a container (a running one only with --force).
    Delete {
        /// Kill the container first if it is still running.
        #[arg(short, long)]
        force: bool,
        id: String,
    },
    /// Freeze every process in a container.
    Pause { id: String },
    /// Thaw a paused container.
    Resume { id: String },
    /// List the processes of a container (host PIDs).
    Ps {
        #[arg(short, long, value_enum, default_value_t = Format::Table)]
        format: Format,
        id: String,
    },
    /// List containers.
    List {
        #[arg(short, long, value_enum, default_value_t = Format::Table)]
        format: Format,
        /// Only print container IDs.
        #[arg(short, long)]
        quiet: bool,
    },
    /// Show container events; `--stats` prints one statistics snapshot.
    Events {
        /// Print resource statistics once and exit.
        #[arg(long)]
        stats: bool,
        id: String,
    },
    /// Write a default config.json for this build into the bundle directory.
    Spec {
        /// Bundle directory to write config.json into.
        #[arg(short, long, default_value = ".", value_name = "DIR")]
        bundle: PathBuf,
        /// Generate a rootless spec (Phase 8).
        #[arg(long)]
        rootless: bool,
    },
    /// Run a new process in a running (or created) container.
    Exec(ExecCli),
}

#[derive(clap::Args, Debug)]
struct ExecCli {
    /// OCI process.json describing the process (instead of COMMAND).
    #[arg(short, long, value_name = "FILE", conflicts_with = "command")]
    process: Option<PathBuf>,
    /// Give the process a PTY of its own.
    #[arg(short, long)]
    tty: bool,
    /// Listening Unix socket that receives the PTY master.
    #[arg(long, value_name = "PATH")]
    console_socket: Option<PathBuf>,
    /// Return once the process runs.
    #[arg(short, long)]
    detach: bool,
    /// Write the process's (host) PID to this file.
    #[arg(long, value_name = "FILE")]
    pid_file: Option<PathBuf>,
    /// Working directory inside the container.
    #[arg(long, value_name = "DIR")]
    cwd: Option<PathBuf>,
    /// Set an environment variable (repeatable).
    #[arg(short, long, value_name = "KEY=VALUE")]
    env: Vec<String>,
    /// Run as UID[:GID].
    #[arg(short, long, value_name = "UID[:GID]")]
    user: Option<String>,
    /// Add a supplementary group (repeatable).
    #[arg(short = 'g', long, value_name = "GID")]
    additional_gids: Vec<u32>,
    /// Add a capability (repeatable), e.g. NET_RAW.
    #[arg(short, long, value_name = "CAP")]
    cap: Vec<String>,
    /// Set no_new_privs for the process.
    #[arg(long)]
    no_new_privs: bool,
    /// Pass N extra file descriptors (3..3+N) to the process.
    #[arg(long, default_value_t = 0, value_name = "N")]
    preserve_fds: u32,
    /// Start in this sub-cgroup of the container's cgroup ("/" = the container's own).
    #[arg(long, value_name = "PATH")]
    cgroup: Option<String>,
    /// Allow exec into a paused container (the process waits, frozen, until resume).
    #[arg(long)]
    ignore_paused: bool,
    /// Container ID.
    id: String,
    /// The program and its arguments.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    command: Vec<String>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    // Everything that puts a process into a container runs from a sealed
    // copy of this binary (CVE-2019-5736, see rustlet_runtime::reexec).
    if cli.command.starts_a_process()
        && let Err(e) = rustlet_runtime::reexec::ensure_sealed_binary()
    {
        eprintln!("rustlet-runc: error: {e:#}");
        return ExitCode::from(1);
    }
    if let Err(e) = init_logging(&cli) {
        eprintln!("rustlet-runc: error: {e:#}");
        return ExitCode::from(1);
    }
    let log_to_file = cli.log.is_some();
    match dispatch(cli) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            if log_to_file {
                tracing::error!("{e:#}");
            }
            // "error:" like runc's `level=error`: tools that drive a runtime
            // (youki's contest among them) look for that word on stderr.
            eprintln!("rustlet-runc: error: {e:#}");
            ExitCode::from(exit_code_for(&e))
        }
    }
}

impl Command {
    /// `run`, `create` and `exec`: the commands that start a process in a
    /// container.
    fn starts_a_process(&self) -> bool {
        matches!(self, Command::Run { .. } | Command::Create { .. } | Command::Exec(_))
    }
}

/// Like a shell: 127 if the program wasn't found, 126 if it couldn't be
/// executed, 1 for any other failure.
fn exit_code_for(e: &anyhow::Error) -> u8 {
    match e.downcast_ref::<Error>() {
        Some(Error::Exec { errno: Errno::ENOENT, .. }) => 127,
        Some(Error::Exec { .. }) => 126,
        _ => 1,
    }
}

fn create_options(root: PathBuf, a: CreateArgs) -> anyhow::Result<CreateOptions> {
    if a.no_pivot {
        bail!("--no-pivot is not supported: rustlets always uses pivot_root");
    }
    Ok(CreateOptions {
        id: a.id,
        bundle: a.bundle,
        root,
        pid_file: a.pid_file,
        console_socket: a.console_socket,
        preserve_fds: a.preserve_fds,
        no_new_keyring: a.no_new_keyring,
    })
}

fn exec_options(root: PathBuf, e: ExecCli) -> anyhow::Result<ExecOptions> {
    let process = match e.process {
        Some(path) => ExecProcess::Json(path),
        None => {
            let user = e
                .user
                .as_deref()
                .map(|u| -> anyhow::Result<(u32, Option<u32>)> {
                    let (uid, gid) = match u.split_once(':') {
                        Some((uid, gid)) => (uid, Some(gid)),
                        None => (u, None),
                    };
                    let uid = uid.parse().with_context(|| format!("--user {u}: bad uid"))?;
                    let gid = gid.map(|g| g.parse()).transpose().with_context(|| format!("--user {u}: bad gid"))?;
                    Ok((uid, gid))
                })
                .transpose()?;
            ExecProcess::Args(ExecArgs {
                args: e.command,
                env: e.env,
                cwd: e.cwd,
                user,
                additional_gids: e.additional_gids,
                caps: e.cap,
                no_new_privs: e.no_new_privs,
            })
        }
    };
    Ok(ExecOptions {
        root,
        id: e.id,
        process,
        tty: e.tty,
        console_socket: e.console_socket,
        detach: e.detach,
        pid_file: e.pid_file,
        preserve_fds: e.preserve_fds,
        cgroup: e.cgroup,
        ignore_paused: e.ignore_paused,
    })
}

/// `TERM`, `SIGTERM`, `15` → SIGTERM.
fn parse_signal(s: &str) -> anyhow::Result<Signal> {
    if let Ok(n) = s.parse::<i32>() {
        return Signal::try_from(n).with_context(|| format!("unknown signal number {n}"));
    }
    let upper = s.to_ascii_uppercase();
    let name = if upper.starts_with("SIG") { upper } else { format!("SIG{upper}") };
    Signal::from_str(&name).with_context(|| format!("unknown signal {s:?}"))
}

fn print_json(v: &impl serde::Serialize) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(v)?);
    Ok(())
}

fn dispatch(cli: Cli) -> anyhow::Result<u8> {
    let root = cli.root;
    if cli.systemd_cgroup {
        bail!("--systemd-cgroup is not supported: give linux.cgroupsPath as a path inside a Delegate=yes unit");
    }
    match cli.command {
        Command::Run { args, detach } => {
            let status = rustlet_runtime::run(&RunOptions { create: create_options(root, args)?, detach })?;
            Ok(u8::try_from(status).unwrap_or(1))
        }
        Command::Create { args } => {
            rustlet_runtime::create(&create_options(root, args)?)?;
            Ok(0)
        }
        Command::Start { id } => ops::start(&root, &id).map(|()| 0).map_err(Into::into),
        Command::State { id } => {
            print_json(&ops::state(&root, &id)?)?;
            Ok(0)
        }
        Command::Kill { all, id, signal } => {
            let sig = parse_signal(signal.as_deref().unwrap_or("TERM"))?;
            ops::kill(&root, &id, sig, all)?;
            Ok(0)
        }
        Command::Delete { force, id } => ops::delete(&root, &id, force).map(|()| 0).map_err(Into::into),
        Command::Pause { id } => ops::pause(&root, &id).map(|()| 0).map_err(Into::into),
        Command::Resume { id } => ops::resume(&root, &id).map(|()| 0).map_err(Into::into),
        Command::Ps { format, id } => {
            let pids: Vec<i32> = ops::ps(&root, &id)?.into_iter().map(|p| p.as_raw()).collect();
            match format {
                Format::Json => print_json(&pids)?,
                Format::Table => {
                    println!("PID");
                    for p in pids {
                        println!("{p}");
                    }
                }
            }
            Ok(0)
        }
        Command::List { format, quiet } => {
            let all = ops::list(&root)?;
            match (format, quiet) {
                (_, true) => all.iter().for_each(|s| println!("{}", s.id)),
                (Format::Json, false) => print_json(&all)?,
                (Format::Table, false) => {
                    println!("{:<24} {:<8} {:<10} {:<40} CREATED", "ID", "PID", "STATUS", "BUNDLE");
                    for s in &all {
                        println!("{:<24} {:<8} {:<10} {:<40} {}", s.id, s.pid, s.status, s.bundle.display(), s.created);
                    }
                }
            }
            Ok(0)
        }
        Command::Events { stats, id } => {
            if !stats {
                bail!("streaming events arrive with the shim (Phase 4); use `events --stats` for a snapshot");
            }
            println!("{}", serde_json::to_string(&ops::stats(&root, &id)?)?);
            Ok(0)
        }
        Command::Spec { bundle, rootless } => {
            if rootless {
                bail!("--rootless arrives in Phase 8");
            }
            write_spec(&bundle, &spec::default_spec())?;
            Ok(0)
        }
        Command::Exec(e) => {
            let status = rustlet_runtime::exec(&exec_options(root, e)?)?;
            Ok(u8::try_from(status).unwrap_or(1))
        }
    }
}

fn write_spec(bundle: &std::path::Path, spec: &Spec) -> anyhow::Result<()> {
    let path = bundle.join("config.json");
    if path.exists() {
        bail!("{} exists; remove it first", path.display());
    }
    std::fs::write(&path, spec::to_pretty_json(spec)).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

fn init_logging(cli: &Cli) -> anyhow::Result<()> {
    use tracing_subscriber::EnvFilter;
    let default = if cli.debug { "rustlet_runtime=debug,rustlet_runc=debug" } else { "warn" };
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default));
    let builder = tracing_subscriber::fmt().with_env_filter(filter).with_target(false);
    // Note: the fmt subscriber writes synchronously from the calling thread;
    // it starts no background threads, which the single-threaded runtime
    // depends on.
    match (&cli.log, cli.log_format) {
        (Some(path), format) => {
            let file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .with_context(|| format!("open log file {}", path.display()))?;
            let b = builder.with_ansi(false).with_writer(std::sync::Mutex::new(file));
            if format == LogFormat::Json { b.json().init() } else { b.init() }
        }
        (None, LogFormat::Json) => builder.with_writer(std::io::stderr).json().init(),
        (None, LogFormat::Text) => {
            builder.with_writer(std::io::stderr).with_ansi(std::io::stderr().is_terminal()).without_time().init()
        }
    }
    Ok(())
}

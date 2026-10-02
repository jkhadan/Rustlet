//! `rustlet`: the Docker-like command line for rustletd.
//!
//! ```sh
//! rustlet run -it --rm alpine sh          # a shell in a fresh container, gone when it exits
//! rustlet run -d --name web nginx         # in the background; prints the id
//! rustlet logs -f web                     # follow its output
//! rustlet exec -it web sh                 # another process in it
//! rustlet stats                           # live resource use
//! rustlet stop web && rustlet rm web
//! ```
//!
//! Every command is a few calls to the daemon's API through
//! [`rustlet_client`]; the work (images, containers, logs) is the daemon's.
//! What the CLI owns is the user's side: flags, tables and progress, the
//! terminal (raw mode, size, detach keys, signals: [`relay`]), and exit
//! codes. Those follow Docker's:
//!
//! - **125** when Rustlets fails: a bad flag, a daemon that can't be
//!   reached, a request it refuses;
//! - **126** / **127** when the container's program can't be executed or
//!   wasn't found (as a shell would);
//! - otherwise the container's (or exec'd process's) own status, for the
//!   commands that wait for one: `run`, `start -a`, `attach`, `exec`;
//! - **1** when a command acting on several containers or images failed
//!   for some of them (`stop a b`, `rm`, `rmi`, `wait`, `inspect`).
//!
//! The daemon's socket is `/run/rustlet/rustlet.sock`, or what `--host` /
//! `RUSTLET_HOST` says (`unix:///path` or a path).
#![forbid(unsafe_code)]

mod config;
mod console;
mod containers;
mod format;
mod images;
mod pull;
mod relay;
mod run;
mod stats;
mod system;

#[cfg(test)]
mod tests;

use std::fmt;
use std::io::{self, Write};

use clap::{Parser, Subcommand};
use rustlet_client::Client;

use crate::console::Console;
use crate::containers::{ObjectType, Op};

#[derive(Parser, Debug)]
#[command(name = "rustlet", version, about = "Run and manage containers with rustletd")]
struct Cli {
    /// The daemon's socket: unix:///path or a path [default: /run/rustlet/rustlet.sock]
    #[arg(
        short = 'H',
        long,
        global = true,
        env = rustlet_client::HOST_ENV,
        value_name = "SOCKET",
        help_heading = "Global Options"
    )]
    host: Option<String>,
    /// Print debugging detail: the requests' bodies, errors in full
    #[arg(short = 'D', long, global = true, help_heading = "Global Options")]
    debug: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Create and run a new container from an image
    #[command(override_usage = "rustlet run [OPTIONS] IMAGE [COMMAND] [ARG...]")]
    Run(run::RunArgs),
    /// Create a new container (and print its ID)
    #[command(override_usage = "rustlet create [OPTIONS] IMAGE [COMMAND] [ARG...]")]
    Create(run::CreateArgs),
    /// Start one or more stopped containers
    Start(run::StartArgs),
    /// Stop one or more running containers
    Stop {
        /// Seconds to wait for the stop signal before killing
        #[arg(short = 't', long = "timeout", visible_alias = "time", value_name = "SECONDS")]
        timeout: Option<u32>,
        #[arg(value_name = "CONTAINER", required = true)]
        containers: Vec<String>,
    },
    /// Kill one or more running containers
    Kill {
        /// Signal to send (KILL, SIGTERM, 15, …)
        #[arg(short, long, default_value = "KILL")]
        signal: String,
        #[arg(value_name = "CONTAINER", required = true)]
        containers: Vec<String>,
    },
    /// Restart one or more containers
    Restart {
        /// Seconds to wait for the stop signal before killing
        #[arg(short = 't', long = "timeout", visible_alias = "time", value_name = "SECONDS")]
        timeout: Option<u32>,
        #[arg(value_name = "CONTAINER", required = true)]
        containers: Vec<String>,
    },
    /// Remove one or more containers
    Rm {
        /// Kill a running container first
        #[arg(short, long)]
        force: bool,
        #[arg(value_name = "CONTAINER", required = true)]
        containers: Vec<String>,
    },
    /// Pause all processes of one or more containers
    Pause {
        #[arg(value_name = "CONTAINER", required = true)]
        containers: Vec<String>,
    },
    /// Unpause all processes of one or more containers
    Unpause {
        #[arg(value_name = "CONTAINER", required = true)]
        containers: Vec<String>,
    },
    /// Wait until containers stop, then print their exit codes
    Wait {
        #[arg(value_name = "CONTAINER", required = true)]
        containers: Vec<String>,
    },
    /// List containers
    Ps(containers::PsArgs),
    /// Show a container's output
    Logs(containers::LogsArgs),
    /// Run a command in a running container
    #[command(override_usage = "rustlet exec [OPTIONS] CONTAINER COMMAND [ARG...]")]
    Exec(run::ExecArgs),
    /// Show low-level information on containers or images, as JSON
    Inspect {
        /// Only look for this type of object
        #[arg(long = "type", value_enum, value_name = "TYPE")]
        kind: Option<ObjectType>,
        #[arg(value_name = "NAME", required = true)]
        names: Vec<String>,
    },
    /// Show a live stream of containers' resource usage
    Stats(stats::StatsArgs),
    /// Attach to a running container's input and output
    Attach(run::AttachArgs),
    /// Download an image from a registry
    Pull {
        /// Only print the image's full name
        #[arg(short, long)]
        quiet: bool,
        image: String,
    },
    /// List images
    Images {
        /// Only print image IDs
        #[arg(short, long)]
        quiet: bool,
        /// Don't truncate IDs
        #[arg(long)]
        no_trunc: bool,
    },
    /// Remove one or more images
    Rmi {
        /// Remove the name even if containers use the image
        #[arg(short, long)]
        force: bool,
        #[arg(value_name = "IMAGE", required = true)]
        images: Vec<String>,
    },
    /// Show what happens in the daemon, as it happens
    Events(system::EventsArgs),
    /// Show the client's and the daemon's versions
    Version,
    /// Show what the daemon manages and how it is set up
    Info,
}

/// What every command gets: the daemon, the terminal, and `--debug`.
pub struct Ctx {
    pub client: Client,
    pub console: Console,
    pub debug: bool,
}

impl Ctx {
    /// A note for `--debug`, on stderr.
    pub fn debug(&mut self, what: fmt::Arguments<'_>) {
        if self.debug {
            let _ = writeln!(self.console.stderr, "rustlet: debug: {what}");
        }
    }
}

fn main() {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => {
            // Help and --version are not errors, nor is a bare `rustlet`
            // (which shows the help); a bad command line is Rustlets'
            // failure, 125 like the rest, as with Docker.
            let help = e.kind() == clap::error::ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand;
            let code = if e.use_stderr() && !help { 125 } else { 0 };
            let _ = e.print();
            std::process::exit(code);
        }
    };
    let code = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(runtime) => {
            let code = runtime.block_on(run_cli(cli, Console::system()));
            // A thread may still be blocked reading stdin; it can't be
            // interrupted, and must not keep the process alive.
            runtime.shutdown_background();
            code
        }
        Err(e) => {
            eprintln!("rustlet: error: starting the runtime: {e}");
            125
        }
    };
    std::process::exit(code);
}

/// Runs the command line on `console`; returns the exit code.
async fn run_cli(cli: Cli, console: Console) -> i32 {
    let mut ctx = match Client::from_host(cli.host.as_deref().unwrap_or("")) {
        Ok(client) => Ctx { client, console, debug: cli.debug },
        Err(e) => {
            let mut console = console;
            let _ = writeln!(console.stderr, "rustlet: error: {e}");
            return 125;
        }
    };
    let socket = ctx.client.socket().display().to_string();
    ctx.debug(format_args!("daemon socket {socket}"));
    let result = dispatch(&mut ctx, cli.command).await;
    let _ = ctx.console.stdout.flush();
    match result {
        Ok(code) => code,
        Err(e) => report(&mut ctx, &e),
    }
}

async fn dispatch(ctx: &mut Ctx, command: Command) -> anyhow::Result<i32> {
    match command {
        Command::Run(args) => run::run(ctx, args).await,
        Command::Create(args) => run::create(ctx, args).await,
        Command::Start(args) => run::start(ctx, args).await,
        Command::Stop { timeout, containers } => containers::each(ctx, &containers, Op::Stop(timeout)).await,
        Command::Kill { signal, containers } => containers::each(ctx, &containers, Op::Kill(signal)).await,
        Command::Restart { timeout, containers } => containers::each(ctx, &containers, Op::Restart(timeout)).await,
        Command::Rm { force, containers } => containers::each(ctx, &containers, Op::Remove { force }).await,
        Command::Pause { containers } => containers::each(ctx, &containers, Op::Pause).await,
        Command::Unpause { containers } => containers::each(ctx, &containers, Op::Unpause).await,
        Command::Wait { containers } => containers::wait(ctx, &containers).await,
        Command::Ps(args) => containers::ps(ctx, args).await,
        Command::Logs(args) => containers::logs(ctx, args).await,
        Command::Exec(args) => run::exec(ctx, args).await,
        Command::Inspect { kind, names } => containers::inspect(ctx, kind, &names).await,
        Command::Stats(args) => stats::stats(ctx, args).await,
        Command::Attach(args) => run::attach(ctx, args).await,
        Command::Pull { quiet, image } => images::pull(ctx, quiet, &image).await,
        Command::Images { quiet, no_trunc } => images::images(ctx, quiet, no_trunc).await,
        Command::Rmi { force, images } => images::rmi(ctx, force, &images).await,
        Command::Events(args) => system::events(ctx, args).await,
        Command::Version => system::version(ctx).await,
        Command::Info => system::info(ctx).await,
    }
}

/// Prints a failed command's error; returns the exit code for it.
fn report(ctx: &mut Ctx, e: &anyhow::Error) -> i32 {
    // Our output was cut off (`rustlet logs -f web | head`): stop quietly,
    // with the status of a process killed by SIGPIPE, as Docker's CLI is.
    if let Some(io) = e.downcast_ref::<io::Error>()
        && io.kind() == io::ErrorKind::BrokenPipe
    {
        return 141;
    }
    let _ = if ctx.debug {
        writeln!(ctx.console.stderr, "rustlet: error: {e:?}")
    } else {
        writeln!(ctx.console.stderr, "rustlet: error: {e:#}")
    };
    exit_code(e)
}

/// The exit code for a failed command: the daemon's error kind decides
/// (127 and 126 for a program that can't run), anything else is 125, "the
/// error is Rustlets', not the container's".
fn exit_code(e: &anyhow::Error) -> i32 {
    match e.downcast_ref::<rustlet_client::Error>() {
        Some(rustlet_client::Error::Api { body, .. }) => body.kind.cli_exit_code(),
        _ => 125,
    }
}

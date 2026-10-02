//! `run`, `create`, `start`, `attach` and `exec`: the commands that make a
//! container or process and may stay connected to it.
//!
//! `run` is `create`, then `start`, plus everything around them:
//!
//! ```text
//!  POST /containers ──404 no_such_image──► POST /images/pull ──► POST /containers
//!        │ (--pull always: pull first; --pull never: the 404 is the answer)
//!        ▼
//!  -d:  POST /start, print the id
//!  else GET /attach (WebSocket) ──► POST /start ──► relay until `exit` ──► (--rm) wait removed
//! ```
//!
//! The attach comes *before* the start: a container that prints and exits
//! at once (`run alpine echo hi`) would otherwise be gone, its output
//! with it, before the CLI is listening. The session's `exit` control
//! carries the status the CLI exits with. A start that fails (no such
//! program: 127, not executable: 126) exits with the code of the daemon's
//! error kind, as `docker run` does.
//!
//! Every flow takes the [`Ctx`] (client and console), so the tests run
//! them in-process against a mock daemon.

use std::io::Write;

use anyhow::bail;
use clap::ArgAction;
use rustlet_client::Session;
use rustlet_spec::ErrorKind;
use rustlet_spec::container::{ContainerConfig, ContainerStatus, CreateResponse, WaitCondition};
use rustlet_spec::exec::ExecConfig;
use rustlet_spec::image::PullPolicy;

use crate::Ctx;
use crate::config::{CreateFlags, Pull, resolve_env};
use crate::console::Console;
use crate::pull::{self, Reference};
use crate::relay::{self, End};

/// `rustlet run`.
#[derive(clap::Args, Debug)]
pub struct RunArgs {
    #[command(flatten)]
    pub flags: CreateFlags,
    /// Run in the background and print the container's ID
    #[arg(short, long)]
    pub detach: bool,
    /// Pass the signals the CLI receives on to the container (not with -t)
    #[arg(
        long,
        value_name = "BOOL",
        action = ArgAction::Set,
        num_args = 0..=1,
        require_equals = true,
        default_value_t = true,
        default_missing_value = "true"
    )]
    pub sig_proxy: bool,
    /// The image, then the command to run in it and its arguments
    #[arg(value_name = "IMAGE", required = true, num_args = 1.., trailing_var_arg = true, allow_hyphen_values = true)]
    pub args: Vec<String>,
}

/// `rustlet create`.
#[derive(clap::Args, Debug)]
pub struct CreateArgs {
    #[command(flatten)]
    pub flags: CreateFlags,
    /// The image, then the command to run in it and its arguments
    #[arg(value_name = "IMAGE", required = true, num_args = 1.., trailing_var_arg = true, allow_hyphen_values = true)]
    pub args: Vec<String>,
}

/// `rustlet start`.
#[derive(clap::Args, Debug)]
pub struct StartArgs {
    /// Attach to the container's output and wait for it to exit
    #[arg(short, long)]
    pub attach: bool,
    /// Attach the container's STDIN (implies --attach)
    #[arg(short, long)]
    pub interactive: bool,
    #[arg(value_name = "CONTAINER", required = true)]
    pub containers: Vec<String>,
}

/// `rustlet attach`.
#[derive(clap::Args, Debug)]
pub struct AttachArgs {
    /// Don't attach STDIN
    #[arg(long)]
    pub no_stdin: bool,
    /// Pass the signals the CLI receives on to the container (not with a TTY)
    #[arg(
        long,
        value_name = "BOOL",
        action = ArgAction::Set,
        num_args = 0..=1,
        require_equals = true,
        default_value_t = true,
        default_missing_value = "true"
    )]
    pub sig_proxy: bool,
    pub container: String,
}

/// `rustlet exec`.
#[derive(clap::Args, Debug)]
pub struct ExecArgs {
    /// Keep STDIN open and attach it
    #[arg(short, long)]
    pub interactive: bool,
    /// Allocate a pseudo-TTY
    #[arg(short, long)]
    pub tty: bool,
    /// Run the command in the background
    #[arg(short, long)]
    pub detach: bool,
    /// Run as USER[:GROUP] (default: the container's user)
    #[arg(short, long, value_name = "USER[:GROUP]")]
    pub user: Option<String>,
    /// Working directory inside the container
    #[arg(short, long, value_name = "DIR")]
    pub workdir: Option<String>,
    /// Set an environment variable; a bare KEY takes its value from this shell (repeatable)
    #[arg(short, long, value_name = "KEY[=VALUE]")]
    pub env: Vec<String>,
    /// The container, then the command and its arguments
    #[arg(value_name = "CONTAINER", required = true, num_args = 1.., trailing_var_arg = true, allow_hyphen_values = true)]
    pub args: Vec<String>,
}

/// The CLI's environment, for `-e KEY`.
fn from_environment(key: &str) -> Option<String> {
    std::env::var(key).ok()
}

pub async fn run(ctx: &mut Ctx, args: RunArgs) -> anyhow::Result<i32> {
    let (image, cmd) = first_and_rest(args.args);
    let mut config = args.flags.to_config(image, cmd, &from_environment)?;
    let attach_stdin = args.flags.interactive && !args.detach;
    if args.detach {
        // Nobody attaches now whose input ending should close the
        // container's: a later `attach` can come and go.
        config.stdin_once = false;
    } else {
        check_tty(&ctx.console, config.tty, attach_stdin)?;
    }
    let id = create_container(ctx, &config, args.flags.pull).await?.id;

    if args.detach {
        if let Err(e) = ctx.client.start(&id).await {
            remove_unstarted(ctx, &id, config.auto_remove).await;
            return Err(e.into());
        }
        writeln!(ctx.console.stdout, "{id}")?;
        return Ok(0);
    }
    let mut session = ctx.client.attach(&id, attach_stdin).await?;
    if config.tty {
        send_size(&mut session, &ctx.console).await;
    }
    if let Err(e) = ctx.client.start(&id).await {
        drop(session);
        remove_unstarted(ctx, &id, config.auto_remove).await;
        return Err(e.into());
    }
    let sig_proxy = (args.sig_proxy && !config.tty).then(|| id.clone());
    let options = relay::Options { tty: config.tty, stdin: attach_stdin, sig_proxy };
    let end = relay::relay(&ctx.client, session, options, &mut ctx.console).await?;
    if config.auto_remove && matches!(end, End::Exited { .. }) {
        wait_removed(ctx, &id).await?;
    }
    finish(ctx, &id, end)
}

pub async fn create(ctx: &mut Ctx, args: CreateArgs) -> anyhow::Result<i32> {
    let (image, cmd) = first_and_rest(args.args);
    let config = args.flags.to_config(image, cmd, &from_environment)?;
    let created = create_container(ctx, &config, args.flags.pull).await?;
    writeln!(ctx.console.stdout, "{}", created.id)?;
    Ok(0)
}

/// `POST /containers`, pulling the image first if it's missing (or
/// always, with `--pull always`). Progress goes to stderr, as with Docker,
/// so that stdout has only the id.
pub async fn create_container(ctx: &mut Ctx, config: &ContainerConfig, pull: Pull) -> anyhow::Result<CreateResponse> {
    if pull == Pull::Always {
        pull_to_stderr(ctx, &config.image, PullPolicy::Always).await?;
    }
    ctx.debug(format_args!("creating {}", serde_json::to_string(config)?));
    let created = match ctx.client.create_container(config).await {
        Err(e) if e.kind() == Some(ErrorKind::NoSuchImage) && pull != Pull::Never => {
            writeln!(
                ctx.console.stderr,
                "Unable to find image '{}' locally",
                Reference::parse(&config.image).familiar()
            )?;
            pull_to_stderr(ctx, &config.image, PullPolicy::Missing).await?;
            ctx.client.create_container(config).await?
        }
        created => created?,
    };
    for warning in &created.warnings {
        writeln!(ctx.console.stderr, "WARNING: {warning}")?;
    }
    Ok(created)
}

/// A pull on behalf of `run`/`create`: progress and summary on stderr.
async fn pull_to_stderr(ctx: &mut Ctx, image: &str, policy: PullPolicy) -> anyhow::Result<()> {
    let console = &mut ctx.console;
    let pulled = pull::pull(&ctx.client, &mut *console.stderr, console.stderr_tty, image, policy, false).await?;
    pull::summary(&mut *console.stderr, &pulled, &Reference::parse(image).familiar())?;
    Ok(())
}

/// After a failed start: a container that was to be removed when done is
/// removed now, since it never ran and so never will be otherwise.
async fn remove_unstarted(ctx: &mut Ctx, id: &str, auto_remove: bool) {
    if auto_remove {
        // Best effort: the daemon may have removed it already, and the
        // error to report is the start's.
        let _ = ctx.client.remove_container(id, true).await;
    }
}

pub async fn start(ctx: &mut Ctx, args: StartArgs) -> anyhow::Result<i32> {
    if !args.attach && !args.interactive {
        return crate::containers::each(ctx, &args.containers, crate::containers::Op::Start).await;
    }
    let [name] = args.containers.as_slice() else {
        bail!("you cannot start and attach multiple containers at once");
    };
    let info = ctx.client.inspect_container(name).await?;
    let (tty, stdin) = (info.config.tty, args.interactive && info.config.open_stdin);
    check_tty(&ctx.console, tty, stdin)?;
    let mut session = ctx.client.attach(&info.id, stdin).await?;
    if tty {
        send_size(&mut session, &ctx.console).await;
    }
    // Like `docker start -a`: a container that is already running is
    // just attached to.
    if !info.state.status.is_live() {
        ctx.client.start(&info.id).await?;
    }
    let options = relay::Options { tty, stdin, sig_proxy: (!tty).then(|| info.id.clone()) };
    let end = relay::relay(&ctx.client, session, options, &mut ctx.console).await?;
    finish(ctx, &info.id, end)
}

pub async fn attach(ctx: &mut Ctx, args: AttachArgs) -> anyhow::Result<i32> {
    let info = ctx.client.inspect_container(&args.container).await?;
    match info.state.status {
        ContainerStatus::Paused => bail!("you cannot attach to a paused container, unpause it first"),
        status if !status.is_live() => bail!("you cannot attach to a stopped container, start it first"),
        _ => {}
    }
    let (tty, stdin) = (info.config.tty, !args.no_stdin && info.config.open_stdin);
    check_tty(&ctx.console, tty, stdin)?;
    let mut session = ctx.client.attach(&info.id, stdin).await?;
    if tty {
        send_size(&mut session, &ctx.console).await;
    }
    let sig_proxy = (args.sig_proxy && !tty).then(|| info.id.clone());
    let end = relay::relay(&ctx.client, session, relay::Options { tty, stdin, sig_proxy }, &mut ctx.console).await?;
    finish(ctx, &info.id, end)
}

pub async fn exec(ctx: &mut Ctx, args: ExecArgs) -> anyhow::Result<i32> {
    let (container, cmd) = first_and_rest(args.args);
    if cmd.is_empty() {
        bail!("exec needs a command to run in {container}");
    }
    let stdin = args.interactive && !args.detach;
    if !args.detach {
        check_tty(&ctx.console, args.tty, stdin)?;
    }
    let config = ExecConfig {
        cmd,
        tty: args.tty,
        stdin: args.interactive,
        env: resolve_env(&args.env, &from_environment)?,
        user: args.user,
        workdir: args.workdir,
    };
    let exec = ctx.client.create_exec(&container, &config).await?;
    if args.detach {
        ctx.client.start_exec_detached(&exec.id).await?;
        return Ok(0);
    }
    let mut session = ctx.client.start_exec(&exec.id).await?;
    if args.tty {
        send_size(&mut session, &ctx.console).await;
    }
    // No signal proxy: `kill` is for containers, an exec has no route of
    // its own (nor does Docker proxy them).
    let options = relay::Options { tty: args.tty, stdin, sig_proxy: None };
    let end = relay::relay(&ctx.client, session, options, &mut ctx.console).await?;
    finish(ctx, &container, end)
}

/// The exit code of a relayed session.
fn finish(ctx: &mut Ctx, id: &str, end: End) -> anyhow::Result<i32> {
    match end {
        End::Exited { code, .. } => Ok(code),
        End::Detached => {
            writeln!(ctx.console.stderr, "Detached from {}; it keeps running.", rustlet_spec::short_id(id))?;
            Ok(0)
        }
        End::Signaled(signo) => Ok(128 + signo),
    }
}

/// `run --rm`: the container exited; return once the daemon has removed
/// it, so that a script's next command doesn't find it still there.
async fn wait_removed(ctx: &mut Ctx, id: &str) -> anyhow::Result<()> {
    // The signal proxy took SIGINT's default action away for good, so
    // Ctrl-C has to be watched for here: a removal that hangs can still be
    // given up on.
    let removed = tokio::select! {
        removed = ctx.client.wait(id, WaitCondition::Removed) => removed,
        _ = tokio::signal::ctrl_c() => return Ok(()),
    };
    match removed {
        Ok(w) => {
            // Dead: the removal failed, and the container is still there.
            if let Some(error) = w.error
                && ctx.client.inspect_container(id).await.is_ok_and(|i| i.state.status == ContainerStatus::Dead)
            {
                let short = rustlet_spec::short_id(id);
                writeln!(ctx.console.stderr, "rustlet: error: {short} could not be removed: {error}")?;
            }
            Ok(())
        }
        // Removed before we asked.
        Err(e) if e.is_not_found() => Ok(()),
        Err(e) => {
            let short = rustlet_spec::short_id(id);
            writeln!(ctx.console.stderr, "rustlet: error: waiting for {short} to be removed: {e}")?;
            Ok(())
        }
    }
}

/// Docker's rule: a TTY session's input must be a terminal. Piped input
/// in raw mode makes no sense, and without raw mode the PTY would echo it.
fn check_tty(console: &Console, tty: bool, stdin: bool) -> anyhow::Result<()> {
    if tty && stdin && !console.stdin_tty {
        bail!("the input device is not a TTY");
    }
    Ok(())
}

/// Tells the container's PTY the terminal's size before the process
/// starts, so that it never sees another.
async fn send_size(session: &mut Session, console: &Console) {
    if (console.stdin_tty || console.stdout_tty)
        && let Some((rows, cols)) = relay::terminal_size()
    {
        let _ = session.resize(rows, cols).await;
    }
}

/// `IMAGE [COMMAND…]` (clap has made sure there is a first).
fn first_and_rest(mut args: Vec<String>) -> (String, Vec<String>) {
    let first = if args.is_empty() { String::new() } else { args.remove(0) };
    (first, args)
}

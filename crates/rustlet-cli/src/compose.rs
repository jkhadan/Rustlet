//! `rustlet compose …`: applications of several containers, from a compose
//! file, through `rustlet_compose`.
//!
//! The work (reading the files, creating networks, volumes and containers
//! in dependency order, waiting for health, a project's logs) is the
//! library's, shared with the desktop app. What is here is the command
//! line: the flags, the library's events shown as Compose v2 shows its
//! plain progress (aligned, and on stderr, as Compose writes it), the
//! containers' output with a prefix each, and Ctrl-C:
//!
//! ```text
//! $ rustlet compose up
//! Network hits_default    Created                    ← progress, on stderr
//! Container hits-redis-1  Started
//! Container hits-redis-1  Healthy
//! Container hits-web-1    Started
//! redis-1  | Ready to accept connections tcp         ← output, on stdout
//! web-1    |  * Running on http://0.0.0.0:8000
//! ^CGracefully stopping... (press Ctrl+C again to force)
//! Container hits-web-1    Stopping
//! ```
//!
//! Without `-d`, `up` follows the output of the services' containers until
//! they have all exited, or until Ctrl-C, which stops them (a second one
//! kills them) and exits with 130. `down -p NAME` needs no file: the
//! project's containers and networks are found by their labels.

use std::collections::{BTreeMap, HashMap};
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard, PoisonError};

use anyhow::{Context, bail};
use chrono::{DateTime, Utc};
use clap::ValueEnum;
use futures::StreamExt;
use futures::stream::BoxStream;
use rustlet_compose::run::{Action, BuildPolicy, LogLine, RemoveImages, ResourceKind};
use rustlet_compose::{Compose, ComposeEvent, DownOptions, LoadOptions, Project, ServiceContainer, Stack, UpOptions};
use rustlet_spec::build::BuildEvent;
use rustlet_spec::logs::{LogStream, LogsQuery};
use tokio::signal::unix::{SignalKind, signal};

use crate::Ctx;
use crate::build::{BuildProgress, Out};
use crate::console::Console;
use crate::containers::parse_tail;
use crate::format::{Table, ago, command_text, natural_cmp, ports_text, status_text};
use crate::pull::PullLine;

/// `rustlet compose`.
#[derive(clap::Args, Debug)]
pub struct ComposeArgs {
    /// Compose file; given again, one that overrides and extends those before [default: compose.yaml, compose.yml, docker-compose.yaml or docker-compose.yml]
    #[arg(short, long = "file", value_name = "FILE")]
    pub files: Vec<PathBuf>,
    /// The project's name [default: the file's name:, else $COMPOSE_PROJECT_NAME, else its directory's]
    #[arg(short, long, value_name = "NAME")]
    pub project_name: Option<String>,
    /// Where the file's relative paths start [default: the first file's directory]
    #[arg(long, value_name = "DIR")]
    pub project_directory: Option<PathBuf>,
    /// Enable the services of this profile too (repeatable)
    #[arg(long, value_name = "PROFILE")]
    pub profile: Vec<String>,
    #[command(subcommand)]
    pub command: ComposeCommand,
}

#[derive(clap::Subcommand, Debug)]
pub enum ComposeCommand {
    /// Create and start the services' containers, with their networks, volumes and images
    Up(UpArgs),
    /// Stop and remove the project's containers and networks
    Down(DownArgs),
    /// List the project's containers
    Ps {
        /// Show all containers (default: running ones)
        #[arg(short, long)]
        all: bool,
        /// Only print container IDs
        #[arg(short, long)]
        quiet: bool,
        #[arg(value_name = "SERVICE")]
        services: Vec<String>,
    },
    /// Show the services' output
    Logs(LogsArgs),
    /// Build the images of the services that have a build: section
    Build {
        /// Run every step again, whatever the build cache has
        #[arg(long)]
        no_cache: bool,
        #[arg(value_name = "SERVICE")]
        services: Vec<String>,
    },
    /// Stop the services' containers
    Stop {
        /// Seconds each container gets to stop before it is killed
        #[arg(short, long, value_name = "SECONDS")]
        timeout: Option<u32>,
        #[arg(value_name = "SERVICE")]
        services: Vec<String>,
    },
    /// Start the services' existing containers
    Start {
        #[arg(value_name = "SERVICE")]
        services: Vec<String>,
    },
    /// List the projects that have containers running
    Ls {
        /// Show the projects whose containers have all stopped too
        #[arg(short, long)]
        all: bool,
    },
    /// Show the project as Rustlets reads it: normalized, as JSON
    Config {
        /// Only the services' names, in the order they start in
        #[arg(long)]
        services: bool,
    },
}

/// `compose up`.
#[derive(clap::Args, Debug)]
pub struct UpArgs {
    /// Leave the containers running in the background, without following their output
    #[arg(short, long)]
    pub detach: bool,
    /// Build the services' images first, even those that exist
    #[arg(long, conflicts_with = "no_build")]
    pub build: bool,
    /// Don't build a missing image: pull it, or fail
    #[arg(long)]
    pub no_build: bool,
    /// Recreate the containers even if their configuration hasn't changed
    #[arg(long, conflicts_with = "no_recreate")]
    pub force_recreate: bool,
    /// Never recreate a container that exists, even if its configuration changed
    #[arg(long)]
    pub no_recreate: bool,
    /// Remove the containers of services no longer in the file
    #[arg(long)]
    pub remove_orphans: bool,
    /// Seconds a container gets to stop (one recreated, or all on Ctrl-C)
    #[arg(short, long, value_name = "SECONDS")]
    pub timeout: Option<u32>,
    /// No colours in the output
    #[arg(long)]
    pub no_color: bool,
    #[arg(value_name = "SERVICE")]
    pub services: Vec<String>,
}

/// `compose down`.
#[derive(clap::Args, Debug)]
pub struct DownArgs {
    /// Remove the named volumes the file declares, and the containers' anonymous volumes
    #[arg(short, long)]
    pub volumes: bool,
    /// Remove images too: local (those built for services without image:) or all
    #[arg(long, value_enum, value_name = "TYPE")]
    pub rmi: Option<Rmi>,
    /// Remove the containers of services no longer in the file too
    #[arg(long)]
    pub remove_orphans: bool,
    /// Seconds each container gets to stop before it is killed
    #[arg(short, long, value_name = "SECONDS")]
    pub timeout: Option<u32>,
}

/// `down --rmi`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Rmi {
    Local,
    All,
}

/// `compose logs`.
#[derive(clap::Args, Debug)]
pub struct LogsArgs {
    /// Follow the output until the containers exit
    #[arg(short, long)]
    pub follow: bool,
    /// Number of lines to show from the end of each container's log ("all" for everything)
    #[arg(short = 'n', long, default_value = "all", value_name = "N")]
    pub tail: String,
    /// Show each line's timestamp
    #[arg(short, long)]
    pub timestamps: bool,
    /// No colours in the output
    #[arg(long)]
    pub no_color: bool,
    #[arg(value_name = "SERVICE")]
    pub services: Vec<String>,
}

/// The files Compose looks for when none is given, in order.
const DEFAULT_FILES: [&str; 4] = ["compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml"];

pub async fn compose(ctx: &mut Ctx, args: ComposeArgs) -> anyhow::Result<i32> {
    let options = LoadOptions {
        files: args.files,
        project_dir: args.project_directory,
        project_name: args.project_name,
        env: environment(),
        profiles: args.profile,
    };
    match args.command {
        ComposeCommand::Ls { all } => ls(ctx, all).await,
        ComposeCommand::Down(down) if !has_file(&options) && options.project_name.is_some() => {
            let name = options.project_name.as_deref().unwrap_or_default();
            down_project(ctx, name, &down).await
        }
        command => {
            let project = rustlet_compose::load(&options).map_err(compose_error)?;
            let compose = Compose::new(ctx.client.clone(), project);
            run(ctx, &compose, command).await
        }
    }
}

async fn run(ctx: &mut Ctx, compose: &Compose, command: ComposeCommand) -> anyhow::Result<i32> {
    let names = Names::of(&compose.project);
    match command {
        ComposeCommand::Up(args) => up(ctx, compose, args).await,
        ComposeCommand::Down(args) => {
            let screen = Screen::progress(&mut ctx.console, names);
            compose.down(&down_options(&args), &|e| screen.event(e)).await.map_err(compose_error)?;
            Ok(0)
        }
        ComposeCommand::Ps { all, quiet, services } => ps(ctx, compose, all, quiet, &services).await,
        ComposeCommand::Logs(args) => logs(ctx, compose, args).await,
        ComposeCommand::Build { no_cache, services } => {
            check_services(&compose.project, &services)?;
            let screen = Screen::progress(&mut ctx.console, names);
            compose.build(&services, no_cache, &|e| screen.event(e)).await.map_err(compose_error)?;
            Ok(0)
        }
        ComposeCommand::Stop { timeout, services } => {
            check_services(&compose.project, &services)?;
            let screen = Screen::progress(&mut ctx.console, names);
            compose.stop(&services, timeout, &|e| screen.event(e)).await.map_err(compose_error)?;
            Ok(0)
        }
        ComposeCommand::Start { services } => {
            check_services(&compose.project, &services)?;
            let screen = Screen::progress(&mut ctx.console, names);
            compose.start(&services, &|e| screen.event(e)).await.map_err(compose_error)?;
            Ok(0)
        }
        ComposeCommand::Config { services } => config(ctx, &compose.project, services),
        ComposeCommand::Ls { all } => ls(ctx, all).await,
    }
}

/// `compose up`: everything created and started; then, unless `-d`, their
/// output followed until they have all exited (exit 0) or Ctrl-C stops
/// them (exit 130), as Compose's attached `up`.
async fn up(ctx: &mut Ctx, compose: &Compose, args: UpArgs) -> anyhow::Result<i32> {
    check_services(&compose.project, &args.services)?;
    let options = UpOptions {
        services: args.services.clone(),
        build: if args.build {
            BuildPolicy::Always
        } else if args.no_build {
            BuildPolicy::Never
        } else {
            BuildPolicy::Missing
        },
        force_recreate: args.force_recreate,
        no_recreate: args.no_recreate,
        remove_orphans: args.remove_orphans,
        timeout: args.timeout,
        wait_timeout: None,
    };
    let names = Names::of(&compose.project);
    if args.detach {
        let screen = Screen::progress(&mut ctx.console, names);
        compose.up(&options, &|e| screen.event(e)).await.map_err(compose_error)?;
        return Ok(0);
    }
    // From here on Ctrl-C is ours: it stops the containers rather than
    // leaving them running behind a CLI that is gone.
    let mut interrupts = signal(SignalKind::interrupt()).context("listening for Ctrl-C")?;
    let color = ctx.console.stdout_tty && !args.no_color;
    let logs = LogPrinter::new(&names, &args.services, color, false);
    // Their output from now on: a container that was already running
    // showed the rest to whoever started it.
    let since = unix_time(Utc::now());
    let screen = Screen::new(&mut ctx.console, EventPrinter::new(names), logs);
    let on_event = |e| screen.event(e);
    let started = tokio::select! {
        up = compose.up(&options, &on_event) => {
            up.map_err(compose_error)?;
            true
        }
        _ = interrupts.recv() => false,
    };
    let mut output = None;
    if started {
        let query = LogsQuery { follow: true, since: Some(since), ..LogsQuery::default() };
        let mut lines = compose.logs(&args.services, &query).await.map_err(compose_error)?;
        loop {
            tokio::select! {
                line = lines.next() => match line {
                    Some(line) => screen.log(&line.map_err(compose_error)?)?,
                    // Every container has exited.
                    None => return Ok(0),
                },
                _ = interrupts.recv() => break,
            }
        }
        output = Some(lines);
    }
    screen.note("Gracefully stopping... (press Ctrl+C again to force)")?;
    let stop = compose.stop(&args.services, args.timeout, &on_event);
    tokio::pin!(stop);
    let mut forced = false;
    loop {
        tokio::select! {
            stopped = &mut stop => {
                stopped.map_err(compose_error)?;
                return Ok(130);
            }
            // What they print as they stop.
            line = next_line(&mut output) => match line {
                Some(Ok(line)) => screen.log(&line)?,
                _ => output = None,
            },
            _ = interrupts.recv(), if !forced => {
                forced = true;
                kill(compose, &args.services, &screen).await;
            }
        }
    }
}

/// The next line of `output`; never, without one.
async fn next_line(
    output: &mut Option<BoxStream<'static, rustlet_compose::Result<LogLine>>>,
) -> Option<rustlet_compose::Result<LogLine>> {
    match output {
        Some(lines) => lines.next().await,
        None => std::future::pending().await,
    }
}

/// The second Ctrl-C: the services' containers still running get
/// SIGKILL, as Compose's "force" does. Best effort: the stop goes on.
async fn kill(compose: &Compose, services: &[String], screen: &Screen<'_>) {
    let Ok(containers) = compose.ps(false).await else { return };
    for c in containers.iter().filter(|c| services.is_empty() || services.contains(&c.service)) {
        if compose.client.kill(&c.summary.id, Some("KILL")).await.is_ok() {
            screen.status(ResourceKind::Container, &c.summary.name, "Killed");
        }
    }
}

/// `compose down` for a project known only by name (`-p NAME` with no
/// file): its containers and networks, by their labels.
async fn down_project(ctx: &mut Ctx, name: &str, args: &DownArgs) -> anyhow::Result<i32> {
    let client = ctx.client.clone();
    let screen = Screen::progress(&mut ctx.console, Names { project: name.to_owned(), ..Names::default() });
    let options = down_options(args);
    rustlet_compose::run::down_project(&client, name, &options, &|e| screen.event(e)).await.map_err(compose_error)?;
    Ok(0)
}

fn down_options(args: &DownArgs) -> DownOptions {
    DownOptions {
        volumes: args.volumes,
        remove_orphans: args.remove_orphans,
        timeout: args.timeout,
        images: args.rmi.map(|rmi| match rmi {
            Rmi::Local => RemoveImages::Local,
            Rmi::All => RemoveImages::All,
        }),
    }
}

/// `compose ps`: the project's containers, by name; with `-q` their full
/// IDs, as Compose prints them.
async fn ps(ctx: &mut Ctx, compose: &Compose, all: bool, quiet: bool, services: &[String]) -> anyhow::Result<i32> {
    check_services(&compose.project, services)?;
    let mut containers = compose.ps(all).await.map_err(compose_error)?;
    containers.retain(|c| services.is_empty() || services.contains(&c.service));
    containers.sort_by(|a, b| natural_cmp(&a.summary.name, &b.summary.name));
    let out = &mut ctx.console.stdout;
    if quiet {
        for c in &containers {
            writeln!(out, "{}", c.summary.id)?;
        }
        return Ok(0);
    }
    out.write_all(ps_table(&containers, Utc::now()).as_bytes())?;
    Ok(0)
}

/// `compose logs`: the services' containers' output, each line with its
/// container's name in front.
async fn logs(ctx: &mut Ctx, compose: &Compose, args: LogsArgs) -> anyhow::Result<i32> {
    check_services(&compose.project, &args.services)?;
    let query = LogsQuery { follow: args.follow, tail: parse_tail(&args.tail)?, ..LogsQuery::default() };
    let names = Names::of(&compose.project);
    let color = ctx.console.stdout_tty && !args.no_color;
    let printer = LogPrinter::new(&names, &args.services, color, args.timestamps);
    let mut lines = compose.logs(&args.services, &query).await.map_err(compose_error)?;
    let screen = Screen::new(&mut ctx.console, EventPrinter::new(names), printer);
    while let Some(line) = lines.next().await {
        screen.log(&line.map_err(compose_error)?)?;
    }
    Ok(0)
}

/// `compose ls`: as Compose, without `-a` only the projects that have
/// containers running, and only those counted.
async fn ls(ctx: &mut Ctx, all: bool) -> anyhow::Result<i32> {
    let mut stacks = rustlet_compose::run::stacks(&ctx.client).await.map_err(compose_error)?;
    if !all {
        for stack in &mut stacks {
            stack.containers.retain(|c| c.summary.state.status.is_live());
        }
        stacks.retain(|stack| !stack.containers.is_empty());
    }
    stacks.sort_by(|a, b| natural_cmp(&a.name, &b.name));
    ctx.console.stdout.write_all(ls_table(&stacks).as_bytes())?;
    Ok(0)
}

/// `compose config`: the project as `up` would create it, every default
/// applied, as JSON; or only its services, in the order they start.
fn config(ctx: &mut Ctx, project: &Project, services: bool) -> anyhow::Result<i32> {
    let out = &mut ctx.console.stdout;
    if services {
        for service in project.startup_order(&[]).map_err(compose_error)? {
            writeln!(out, "{}", service.name)?;
        }
    } else {
        writeln!(out, "{}", serde_json::to_string_pretty(project)?)?;
    }
    Ok(0)
}

/// Is there a file to load: one given, or one of the default ones where
/// they are looked for?
fn has_file(options: &LoadOptions) -> bool {
    let dir = options.project_dir.clone().unwrap_or_else(|| PathBuf::from("."));
    !options.files.is_empty() || DEFAULT_FILES.iter().any(|name| dir.join(name).exists())
}

/// Services named on the command line must be the project's.
fn check_services(project: &Project, services: &[String]) -> anyhow::Result<()> {
    match services.iter().find(|s| project.service(s).is_none()) {
        Some(unknown) => bail!("no such service: {unknown}"),
        None => Ok(()),
    }
}

/// The CLI's environment, for the file's `${VAR}`s. A variable whose name
/// or value isn't UTF-8 can't be named in a YAML file anyway, and is left
/// out rather than made a panic.
fn environment() -> BTreeMap<String, String> {
    std::env::vars_os().filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?))).collect()
}

/// A compose error as the CLI reports it: the daemon's as they are, so
/// that their kind picks the exit code (and an unreachable daemon is
/// worded the same as everywhere); the rest by their message alone, which
/// already holds their source.
fn compose_error(e: rustlet_compose::Error) -> anyhow::Error {
    match e {
        rustlet_compose::Error::Client(e) => e.into(),
        other => anyhow::Error::msg(other.to_string()),
    }
}

/// Unix seconds with nanoseconds, as `since` takes a time.
fn unix_time(t: DateTime<Utc>) -> String {
    format!("{}.{:09}", t.timestamp(), t.timestamp_subsec_nanos())
}

/// What the printers need to know of a project: its name, and the names
/// of what its file makes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Names {
    pub project: String,
    /// Each service's containers: `hits-web-1`, …
    pub containers: BTreeMap<String, Vec<String>>,
    /// Its networks and volumes, by the daemon's names.
    pub networks: Vec<String>,
    pub volumes: Vec<String>,
}

impl Names {
    pub fn of(project: &Project) -> Names {
        let containers = project.services.iter().map(|s| {
            let names = (1..=s.replicas).map(|n| s.container_name(&project.name, n)).collect();
            (s.name.clone(), names)
        });
        Names {
            project: project.name.clone(),
            containers: containers.collect(),
            networks: project.networks.values().map(|n| n.name.clone()).collect(),
            volumes: project.volumes.values().map(|v| v.name.clone()).collect(),
        }
    }
}

/// Compose v2's plain progress: a line per change of a network, volume,
/// container or image, its kind and name padded to the longest the
/// project has so that the changes line up (`Container hits-redis-1
/// Healthy`); a service's build as `rustlet build` shows one; a pull as
/// its `Status:` line, between the image's `Pulling` and `Pulled`.
#[derive(Debug)]
pub struct EventPrinter {
    names: Names,
    width: usize,
    builds: HashMap<String, BuildProgress>,
    pulls: HashMap<String, PullLine>,
    /// What was printed last didn't end its line: a build step's output.
    mid_line: bool,
    /// The service whose build printed last.
    last_build: Option<String>,
}

impl EventPrinter {
    pub fn new(names: Names) -> EventPrinter {
        let labels = (names.networks.iter().map(|n| label(ResourceKind::Network, n)))
            .chain(names.volumes.iter().map(|v| label(ResourceKind::Volume, v)))
            .chain(names.containers.values().flatten().map(|c| label(ResourceKind::Container, c)));
        let width = labels.map(|l| l.chars().count()).max().unwrap_or(0);
        EventPrinter { names, width, builds: HashMap::new(), pulls: HashMap::new(), mid_line: false, last_build: None }
    }

    /// What to print for `event`.
    pub fn show(&mut self, event: &ComposeEvent) -> String {
        let text = match event {
            ComposeEvent::Resource { kind, name, action } => self.line(&label(*kind, name), action_text(*action)),
            ComposeEvent::Waiting { on, .. } => {
                // On the containers waited for, as Compose shows it.
                let labels = match self.names.containers.get(on) {
                    Some(containers) if !containers.is_empty() => {
                        containers.iter().map(|c| label(ResourceKind::Container, c)).collect()
                    }
                    _ => vec![format!("Service {on}")],
                };
                labels.iter().map(|l| self.line(l, "Waiting")).collect()
            }
            ComposeEvent::Build { service, event } => return self.build(service, event),
            ComposeEvent::Pull { image, event, .. } => {
                let line = self.pulls.entry(image.clone()).or_insert_with(|| PullLine::new(image));
                let Some(pulled) = line.update(event) else { return String::new() };
                let status = line.status(&pulled);
                self.pulls.remove(image);
                status.map(|s| s + "\n").unwrap_or_default()
            }
            ComposeEvent::Warning(message) => format!("WARNING: {message}\n"),
        };
        self.start_line(text)
    }

    /// A line about `name` of the CLI's own (`Killed`), aligned as the
    /// library's.
    pub fn status(&mut self, kind: ResourceKind, name: &str, status: &str) -> String {
        let line = self.line(&label(kind, name), status);
        self.start_line(line)
    }

    /// A line of the CLI's own.
    pub fn note(&mut self, note: &str) -> String {
        self.start_line(format!("{note}\n"))
    }

    /// What ends the line left open.
    pub fn finish(&mut self) -> String {
        self.end_line()
    }

    /// A service's build, as `rustlet build` shows one; another's line
    /// left open is ended first.
    fn build(&mut self, service: &str, event: &BuildEvent) -> String {
        let mut text = if self.last_build.as_deref() == Some(service) { String::new() } else { self.end_line() };
        let shown = self.builds.entry(service.to_owned()).or_default().show(event);
        text.extend(shown.iter().map(Out::text));
        if !shown.is_empty() {
            self.mid_line = !text.ends_with('\n');
            self.last_build = Some(service.to_owned());
        }
        text
    }

    fn line(&self, label: &str, status: &str) -> String {
        format!("{label:<width$}  {status}\n", width = self.width)
    }

    /// `text`, on a line of its own.
    fn start_line(&mut self, text: String) -> String {
        if text.is_empty() {
            return text;
        }
        self.end_line() + &text
    }

    /// The newline a build's unfinished output needs before anything else
    /// is printed; its build is told, so that it doesn't add another.
    fn end_line(&mut self) -> String {
        if !std::mem::take(&mut self.mid_line) {
            return String::new();
        }
        if let Some(progress) = self.last_build.as_deref().and_then(|service| self.builds.get_mut(service)) {
            progress.line_ended();
        }
        "\n".to_owned()
    }
}

/// `Container hits-web-1`.
fn label(kind: ResourceKind, name: &str) -> String {
    let kind = match kind {
        ResourceKind::Network => "Network",
        ResourceKind::Volume => "Volume",
        ResourceKind::Container => "Container",
        ResourceKind::Image => "Image",
    };
    format!("{kind} {name}")
}

/// Compose's word for each change.
fn action_text(action: Action) -> &'static str {
    match action {
        Action::Creating => "Creating",
        Action::Created => "Created",
        Action::Running => "Running",
        Action::Recreating => "Recreating",
        Action::Recreated => "Recreated",
        Action::Starting => "Starting",
        Action::Started => "Started",
        Action::Healthy => "Healthy",
        Action::Exited => "Exited",
        Action::Stopping => "Stopping",
        Action::Stopped => "Stopped",
        Action::Removing => "Removing",
        Action::Removed => "Removed",
        Action::Building => "Building",
        Action::Built => "Built",
        Action::Pulling => "Pulling",
        Action::Pulled => "Pulled",
    }
}

/// The colours of the containers' prefixes, in the order Compose gives
/// them out: cyan, yellow, green, magenta, blue, then their bright kinds.
const COLORS: [&str; 10] = ["36", "33", "32", "35", "34", "36;1", "33;1", "32;1", "35;1", "34;1"];

/// Containers' output as Compose v2 shows it: each line with the
/// container's name in front (less the project's, which every line would
/// repeat: `web-1`), padded to the longest so that the lines start in one
/// column, then ` | `; on a terminal, in a colour per container.
#[derive(Debug)]
pub struct LogPrinter {
    project: String,
    /// The longest name so far, plus one.
    width: usize,
    color: bool,
    timestamps: bool,
    /// Each container's colour, in the order they came.
    colors: HashMap<String, usize>,
}

impl LogPrinter {
    /// For the containers of `services` (all if empty), as far as `names`
    /// knows them; a longer name that comes later widens the column from
    /// then on.
    pub fn new(names: &Names, services: &[String], color: bool, timestamps: bool) -> LogPrinter {
        let lengths = names.containers.iter().filter(|(service, _)| services.is_empty() || services.contains(service));
        let lengths = lengths.flat_map(|(service, containers)| {
            containers.iter().map(move |c| log_name(&names.project, service, c).chars().count())
        });
        let width = lengths.max().map_or(0, |longest| longest + 1);
        LogPrinter { project: names.project.clone(), width, color, timestamps, colors: HashMap::new() }
    }

    /// The text to print for `line`.
    pub fn render(&mut self, line: &LogLine) -> String {
        let name = log_name(&self.project, &line.service, &line.container);
        self.width = self.width.max(name.chars().count() + 1);
        let mut prefix = format!("{name:<width$} | ", width = self.width);
        if self.color {
            let next = self.colors.len();
            let n = *self.colors.entry(line.container.clone()).or_insert(next);
            prefix = format!("\x1b[{}m{prefix}\x1b[0m", COLORS[n % COLORS.len()]);
        }
        let text = line.entry.log.strip_suffix('\n').unwrap_or(&line.entry.log);
        if self.timestamps { format!("{prefix}{} {text}\n", line.entry.ts) } else { format!("{prefix}{text}\n") }
    }
}

/// A container as its output's prefix names it: `web-1` for `hits-web-1`;
/// one named by `container_name` as it is.
fn log_name<'a>(project: &str, service: &str, container: &'a str) -> &'a str {
    let rest = container.strip_prefix(project).and_then(|rest| rest.strip_prefix('-'));
    match rest {
        Some(rest) if rest.strip_prefix(service).is_some_and(|n| n.starts_with('-')) => rest,
        _ => container,
    }
}

/// `compose ps`'s table, in Compose v2's columns.
pub fn ps_table(containers: &[ServiceContainer], now: DateTime<Utc>) -> String {
    let mut table = Table::new(&["NAME", "IMAGE", "COMMAND", "SERVICE", "CREATED", "STATUS", "PORTS"]);
    for c in containers {
        let s = &c.summary;
        table.row(vec![
            s.name.clone(),
            s.image.clone(),
            command_text(&s.command, false),
            c.service.clone(),
            ago(&s.created, now),
            status_text(&s.state, now),
            ports_text(&s.ports),
        ]);
    }
    table.render()
}

/// `compose ls`'s table: each project, the states of its containers, and
/// the files it was started from.
pub fn ls_table(stacks: &[Stack]) -> String {
    let mut table = Table::new(&["NAME", "STATUS", "CONFIG FILES"]);
    for stack in stacks {
        table.row(vec![stack.name.clone(), combined_status(&stack.containers), stack.config_files.join(",")]);
    }
    table.render()
}

/// Compose's STATUS of a project: how many of its containers are in each
/// state, the states in alphabetical order: `exited(1), running(2)`.
pub fn combined_status(containers: &[ServiceContainer]) -> String {
    let mut counts = BTreeMap::new();
    for c in containers {
        *counts.entry(c.summary.state.status.to_string()).or_insert(0) += 1;
    }
    counts.iter().map(|(status, n)| format!("{status}({n})")).collect::<Vec<_>>().join(", ")
}

/// The console, shared by the library's event callback (which it may call
/// from any of its tasks) and the command's own loop (output, notes): one
/// lock around it and the printers. Whatever line is left open when it
/// goes is ended.
struct Screen<'a> {
    inner: Mutex<Inner<'a>>,
}

struct Inner<'a> {
    console: &'a mut Console,
    events: EventPrinter,
    logs: LogPrinter,
}

impl<'a> Screen<'a> {
    fn new(console: &'a mut Console, events: EventPrinter, logs: LogPrinter) -> Screen<'a> {
        Screen { inner: Mutex::new(Inner { console, events, logs }) }
    }

    /// For the commands that show only progress.
    fn progress(console: &'a mut Console, names: Names) -> Screen<'a> {
        let logs = LogPrinter::new(&names, &[], false, false);
        Screen::new(console, EventPrinter::new(names), logs)
    }

    fn lock(&self) -> MutexGuard<'_, Inner<'a>> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// One of the library's events, on stderr. A callback has no one to
    /// return an error to: a failed write is dropped.
    fn event(&self, event: ComposeEvent) {
        let mut inner = self.lock();
        let text = inner.events.show(&event);
        let _ = write_now(&mut *inner.console.stderr, &text);
    }

    /// A status of the CLI's own about a resource, on stderr.
    fn status(&self, kind: ResourceKind, name: &str, status: &str) {
        let mut inner = self.lock();
        let text = inner.events.status(kind, name, status);
        let _ = write_now(&mut *inner.console.stderr, &text);
    }

    /// A line of the CLI's own, on stderr.
    fn note(&self, note: &str) -> io::Result<()> {
        let mut inner = self.lock();
        let text = inner.events.note(note);
        write_now(&mut *inner.console.stderr, &text)
    }

    /// A line of a container's output, on the stream it was printed on.
    fn log(&self, line: &LogLine) -> io::Result<()> {
        let mut inner = self.lock();
        let text = inner.logs.render(line);
        let out = match line.entry.stream {
            LogStream::Stdout => &mut inner.console.stdout,
            LogStream::Stderr => &mut inner.console.stderr,
        };
        write_now(&mut **out, &text)
    }
}

impl Drop for Screen<'_> {
    fn drop(&mut self) {
        let inner = self.inner.get_mut().unwrap_or_else(PoisonError::into_inner);
        let text = inner.events.finish();
        let _ = write_now(&mut *inner.console.stderr, &text);
    }
}

/// Writes and flushes `text`: progress is for now, not for when a buffer
/// fills.
fn write_now(out: &mut dyn Write, text: &str) -> io::Result<()> {
    if text.is_empty() {
        return Ok(());
    }
    out.write_all(text.as_bytes())?;
    out.flush()
}

#[cfg(test)]
mod tests {
    use rustlet_compose::Condition;
    use rustlet_spec::container::{ContainerState, ContainerStatus, ContainerSummary, Health, HealthStatus};
    use rustlet_spec::image::PullEvent;
    use rustlet_spec::logs::LogEntry;
    use rustlet_spec::network::{Protocol, PublishedPort};

    use super::*;

    /// The `hits` example: redis and web, one container each, one network.
    fn names() -> Names {
        Names {
            project: "hits".into(),
            containers: [("redis", "hits-redis-1"), ("web", "hits-web-1")]
                .map(|(s, c)| (s.to_owned(), vec![c.to_owned()]))
                .into(),
            networks: vec!["hits_default".into()],
            volumes: vec![],
        }
    }

    fn resource(kind: ResourceKind, name: &str, action: Action) -> ComposeEvent {
        ComposeEvent::Resource { kind, name: name.into(), action }
    }

    #[test]
    fn up_reads_like_compose_v2_with_its_changes_lined_up() {
        let mut printer = EventPrinter::new(names());
        let events = [
            resource(ResourceKind::Network, "hits_default", Action::Created),
            resource(ResourceKind::Container, "hits-redis-1", Action::Started),
            ComposeEvent::Waiting { service: "web".into(), on: "redis".into(), condition: Condition::Healthy },
            resource(ResourceKind::Container, "hits-redis-1", Action::Healthy),
            resource(ResourceKind::Container, "hits-web-1", Action::Started),
            resource(ResourceKind::Image, "registry.example/team/hits-web:latest", Action::Built),
            ComposeEvent::Warning("the attribute `version` is obsolete".into()),
        ];
        let text: String = events.iter().map(|e| printer.show(e)).collect();
        assert_eq!(
            text,
            "Network hits_default    Created\n\
             Container hits-redis-1  Started\n\
             Container hits-redis-1  Waiting\n\
             Container hits-redis-1  Healthy\n\
             Container hits-web-1    Started\n\
             Image registry.example/team/hits-web:latest  Built\n\
             WARNING: the attribute `version` is obsolete\n"
        );
        // The CLI's own lines line up too.
        assert_eq!(printer.status(ResourceKind::Container, "hits-web-1", "Killed"), "Container hits-web-1    Killed\n");
        assert_eq!(printer.note("Gracefully stopping..."), "Gracefully stopping...\n");
    }

    #[test]
    fn every_change_has_composes_word() {
        let mut printer = EventPrinter::new(Names::default());
        let actions = [
            (Action::Creating, "Creating"),
            (Action::Created, "Created"),
            (Action::Running, "Running"),
            (Action::Recreating, "Recreating"),
            (Action::Recreated, "Recreated"),
            (Action::Starting, "Starting"),
            (Action::Started, "Started"),
            (Action::Healthy, "Healthy"),
            (Action::Exited, "Exited"),
            (Action::Stopping, "Stopping"),
            (Action::Stopped, "Stopped"),
            (Action::Removing, "Removing"),
            (Action::Removed, "Removed"),
            (Action::Building, "Building"),
            (Action::Built, "Built"),
            (Action::Pulling, "Pulling"),
            (Action::Pulled, "Pulled"),
        ];
        for (action, word) in actions {
            assert_eq!(
                printer.show(&resource(ResourceKind::Volume, "hits_data", action)),
                format!("Volume hits_data  {word}\n")
            );
        }
        // A service the file doesn't have, waited on: by its name.
        let waiting = ComposeEvent::Waiting { service: "web".into(), on: "db".into(), condition: Condition::Started };
        assert_eq!(printer.show(&waiting), "Service db  Waiting\n");
    }

    #[test]
    fn builds_show_their_steps_and_pulls_their_status() {
        let mut printer = EventPrinter::new(names());
        let build = |event| ComposeEvent::Build { service: "web".into(), event };
        let pull = |event| ComposeEvent::Pull { service: "redis".into(), image: "redis:7-alpine".into(), event };
        let events = [
            resource(ResourceKind::Image, "hits-web", Action::Building),
            build(BuildEvent::Step { step: 1, total: 2, instruction: "FROM python:3-slim".into() }),
            build(BuildEvent::Step { step: 2, total: 2, instruction: "RUN pip install redis".into() }),
            build(BuildEvent::Output { step: 2, stream: LogStream::Stdout, text: "Collecting redis".into() }),
            // The step's output is cut off by a line of compose's own: that
            // starts a line of its own.
            resource(ResourceKind::Image, "redis:7-alpine", Action::Pulling),
            pull(PullEvent::Resolving { reference: "docker.io/library/redis:7-alpine".into() }),
            pull(PullEvent::Downloading {
                kind: rustlet_spec::image::BlobKind::Layer,
                digest: "sha256:ab".into(),
                current: 1,
                total: 2,
            }),
            pull(PullEvent::Ready {
                reference: "docker.io/library/redis:7-alpine".into(),
                manifest: "sha256:m".into(),
            }),
            resource(ResourceKind::Image, "redis:7-alpine", Action::Pulled),
            build(BuildEvent::StepDone { step: 2, layer: Some("sha256:9824c27679d3b27c0e1c".into()) }),
            build(BuildEvent::Done {
                id: "sha256:3c4d5e6f7a8b0011".into(),
                names: vec!["docker.io/library/hits-web:latest".into()],
            }),
            resource(ResourceKind::Image, "hits-web", Action::Built),
        ];
        let text: String = events.iter().map(|e| printer.show(e)).collect::<String>() + &printer.finish();
        assert_eq!(
            text,
            "Image hits-web          Building\n\
             Step 1/2 : FROM python:3-slim\n\
             Step 2/2 : RUN pip install redis\n\
             Collecting redis\n\
             Image redis:7-alpine    Pulling\n\
             Status: Downloaded newer image for redis:7-alpine\n\
             Image redis:7-alpine    Pulled\n \
             ---> 9824c27679d3\n\
             Successfully built 3c4d5e6f7a8b\n\
             Successfully tagged hits-web:latest\n\
             Image hits-web          Built\n"
        );
        // A step's unfinished output, ended when the screen goes, or when
        // another service's build prints.
        printer.show(&build(BuildEvent::Output { step: 3, stream: LogStream::Stdout, text: "50%".into() }));
        assert_eq!(printer.finish(), "\n");
        assert_eq!(printer.finish(), "");
        printer.show(&build(BuildEvent::Output { step: 3, stream: LogStream::Stdout, text: "60%".into() }));
        let other = ComposeEvent::Build {
            service: "worker".into(),
            event: BuildEvent::Step { step: 1, total: 1, instruction: "FROM alpine".into() },
        };
        assert_eq!(printer.show(&other), "\nStep 1/1 : FROM alpine\n");
        // And web's own next line doesn't end it again.
        let next = build(BuildEvent::Step { step: 4, total: 4, instruction: "CMD [\"python\"]".into() });
        assert_eq!(printer.show(&next), "Step 4/4 : CMD [\"python\"]\n");
    }

    fn line(service: &str, container: &str, stream: LogStream, log: &str) -> LogLine {
        LogLine {
            service: service.into(),
            container: container.into(),
            entry: LogEntry { ts: "2026-10-03T12:00:00.000000001Z".into(), stream, log: log.into() },
        }
    }

    #[test]
    fn output_lines_carry_their_containers_name_in_one_column() {
        let mut printer = LogPrinter::new(&names(), &[], false, false);
        let lines = [
            line("redis", "hits-redis-1", LogStream::Stdout, "Ready to accept connections tcp\n"),
            line("web", "hits-web-1", LogStream::Stdout, " * Running on http://0.0.0.0:8000\n"),
            // The last line before an exit may have no newline.
            line("web", "hits-web-1", LogStream::Stderr, "bye"),
        ];
        let text: String = lines.iter().map(|l| printer.render(l)).collect();
        assert_eq!(
            text,
            "redis-1  | Ready to accept connections tcp\n\
             web-1    |  * Running on http://0.0.0.0:8000\n\
             web-1    | bye\n"
        );
        // Only web's: the column is web's width; a container_name is shown
        // whole, and widens it from then on.
        let mut printer = LogPrinter::new(&names(), &["web".into()], false, true);
        assert_eq!(
            printer.render(&lines[1]),
            "web-1  | 2026-10-03T12:00:00.000000001Z  * Running on http://0.0.0.0:8000\n"
        );
        let custom = line("db", "postgres-main", LogStream::Stdout, "ready\n");
        assert_eq!(printer.render(&custom), "postgres-main  | 2026-10-03T12:00:00.000000001Z ready\n");
        assert_eq!(
            printer.render(&lines[1]),
            "web-1          | 2026-10-03T12:00:00.000000001Z  * Running on http://0.0.0.0:8000\n"
        );
        // A name that merely starts like the project's is a container_name.
        assert_eq!(log_name("hits", "web", "hits-webby"), "hits-webby");
        assert_eq!(log_name("hits", "web", "hits-web-12"), "web-12");
        assert_eq!(log_name("my-app", "db", "my-app-db-1"), "db-1");
    }

    #[test]
    fn on_a_terminal_each_container_gets_a_colour() {
        let mut printer = LogPrinter::new(&names(), &[], true, false);
        let redis = line("redis", "hits-redis-1", LogStream::Stdout, "a\n");
        let web = line("web", "hits-web-1", LogStream::Stdout, "b\n");
        assert_eq!(printer.render(&redis), "\x1b[36mredis-1  | \x1b[0ma\n");
        assert_eq!(printer.render(&web), "\x1b[33mweb-1    | \x1b[0mb\n");
        assert_eq!(printer.render(&redis), "\x1b[36mredis-1  | \x1b[0ma\n", "the same colour again");
        // Ten colours, then round again: the tenth container is bright
        // blue, the eleventh cyan like the first.
        for n in 3..=11 {
            printer.render(&line("x", &format!("other-{n}"), LogStream::Stdout, ""));
        }
        assert!(printer.render(&line("x", "other-10", LogStream::Stdout, "")).starts_with("\x1b[34;1m"));
        assert!(printer.render(&line("x", "other-11", LogStream::Stdout, "")).starts_with("\x1b[36m"));
    }

    fn container(name: &str, service: &str, status: ContainerStatus, health: Option<HealthStatus>) -> ServiceContainer {
        let ago = |minutes| (Utc::now() - chrono::Duration::minutes(minutes)).to_rfc3339();
        ServiceContainer {
            service: service.into(),
            number: 1,
            summary: ContainerSummary {
                id: name.repeat(8),
                name: name.into(),
                image: if service == "web" { "hits-web".into() } else { "redis:7-alpine".into() },
                command: if service == "web" {
                    vec!["python".into(), "app.py".into()]
                } else {
                    vec!["docker-entrypoint.sh".into(), "redis-server".into()]
                },
                created: ago(10),
                state: ContainerState {
                    status,
                    started_at: Some(ago(9)),
                    finished_at: Some(ago(1)),
                    exit_code: Some(0),
                    health: health.map(|status| Health { status, ..Health::default() }),
                    ..ContainerState::default()
                },
                ports: if service == "web" {
                    vec![PublishedPort {
                        host_ip: "0.0.0.0".parse().unwrap(),
                        host_port: 8000,
                        container_port: 8000,
                        protocol: Protocol::Tcp,
                    }]
                } else {
                    vec![]
                },
                ..ContainerSummary::default()
            },
        }
    }

    #[test]
    fn ps_draws_composes_table() {
        let containers = [
            container("hits-redis-1", "redis", ContainerStatus::Running, Some(HealthStatus::Healthy)),
            container("hits-web-1", "web", ContainerStatus::Running, None),
        ];
        // Compose's columns; the last but one padded even when the last is
        // empty, as tabwriter pads it.
        let expected = [
            "NAME           IMAGE            COMMAND                  SERVICE   CREATED          STATUS                   PORTS",
            "hits-redis-1   redis:7-alpine   \"docker-entrypoint.s…\"   redis     10 minutes ago   Up 9 minutes (healthy)   ",
            "hits-web-1     hits-web         \"python app.py\"          web       10 minutes ago   Up 9 minutes             \
             0.0.0.0:8000->8000/tcp",
        ]
        .map(|line| line.to_owned() + "\n")
        .concat();
        assert_eq!(ps_table(&containers, Utc::now()), expected);
    }

    #[test]
    fn ls_counts_each_projects_containers_by_state() {
        let stack = |name: &str, containers| Stack {
            name: name.into(),
            working_dir: Some(format!("/srv/{name}")),
            config_files: vec![format!("/srv/{name}/compose.yaml"), format!("/srv/{name}/compose.override.yaml")],
            containers,
        };
        let stacks = [
            stack(
                "hits",
                vec![
                    container("hits-web-1", "web", ContainerStatus::Running, None),
                    container("hits-redis-1", "redis", ContainerStatus::Running, None),
                    container("hits-worker-1", "worker", ContainerStatus::Exited, None),
                ],
            ),
            stack("blog", vec![container("blog-db-1", "db", ContainerStatus::Paused, None)]),
        ];
        assert_eq!(combined_status(&stacks[0].containers), "exited(1), running(2)");
        assert_eq!(
            ls_table(&stacks),
            "NAME      STATUS                  CONFIG FILES\n\
             hits      exited(1), running(2)   /srv/hits/compose.yaml,/srv/hits/compose.override.yaml\n\
             blog      paused(1)               /srv/blog/compose.yaml,/srv/blog/compose.override.yaml\n"
        );
        assert_eq!(combined_status(&[]), "");
    }

    #[test]
    fn rmi_and_options_reach_down() {
        let args = DownArgs { volumes: true, rmi: Some(Rmi::Local), remove_orphans: true, timeout: Some(3) };
        assert_eq!(
            down_options(&args),
            DownOptions { volumes: true, remove_orphans: true, timeout: Some(3), images: Some(RemoveImages::Local) }
        );
        let args = DownArgs { volumes: false, rmi: Some(Rmi::All), remove_orphans: false, timeout: None };
        assert_eq!(down_options(&args).images, Some(RemoveImages::All));
    }

    #[test]
    fn a_file_is_looked_for_where_compose_looks() {
        let dir = tempfile::tempdir().unwrap();
        let options = |files: Vec<PathBuf>| LoadOptions {
            files,
            project_dir: Some(dir.path().to_owned()),
            ..LoadOptions::default()
        };
        assert!(!has_file(&options(vec![])));
        assert!(has_file(&options(vec!["elsewhere.yaml".into()])));
        std::fs::write(dir.path().join("docker-compose.yml"), "services: {}\n").unwrap();
        assert!(has_file(&options(vec![])));
        assert_eq!(unix_time(DateTime::from_timestamp(1_727_780_000, 5).unwrap()), "1727780000.000000005");
    }
}

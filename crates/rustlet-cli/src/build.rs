//! `build`, `builder prune` and `commit`: images made here rather than
//! pulled.
//!
//! `rustlet build PATH` is one request, whose body is the build context:
//! PATH packed as a tar archive, less what its ignore file excludes
//! (`rustlet_build::context`). A blocking thread packs it straight into
//! the request ([`RequestBody::pipe`]), so a context of gigabytes is never
//! held in memory, and the daemon has the first files while the last are
//! still being read. The answer is the build's events, shown the way
//! Docker's classic builder shows a build ([`BuildProgress`]):
//!
//! ```text
//! Sending build context to rustletd  2.048kB
//! Step 1/3 : FROM python:3-slim
//! Status: Downloaded newer image for python:3-slim     ← its pull, in one line
//! Step 2/3 : RUN pip install redis
//!  ---> Running in 4f1d2c3b4a59
//! Collecting redis                                     ← what the step printed
//!  ---> Removed intermediate container 4f1d2c3b4a59
//!  ---> 9824c27679d3                                   ← the layer it added
//! Step 3/3 : CMD ["python", "app.py"]                  ← config only: no layer
//! Successfully built 3c4d5e6f7a8b
//! Successfully tagged app:latest
//! ```
//!
//! Unlike Docker's, a step's ` ---> ` line names the layer it added rather
//! than an intermediate image (there are none), and a step that only
//! changes the image's config has none. A step that fails ends the build
//! with the daemon's message and exit code 1, as `docker build` exits;
//! `-q` prints only the image's id, and what it held back only if the
//! build fails. A context that can't be packed (a file that can't be read)
//! is reported as that, naming the file, whatever the daemon made of the
//! body cut short.

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, bail};
use clap::ArgAction;
use futures::StreamExt;
use rustlet_build::context::{ContextError, Packed};
use rustlet_client::{BodyWriter, RequestBody};
use rustlet_spec::build::{BuildEvent, BuildOptions, CommitRequest};
use rustlet_spec::image::{PullEvent, PullPolicy};
use rustlet_spec::network::NetworkMode;
use rustlet_spec::short_id;
use tokio::task::JoinHandle;

use crate::Ctx;
use crate::config::parse_labels;
use crate::console::Console;
use crate::format::{human_size, short_digest};
use crate::pull::{PullLine, Reference};
use crate::run::from_environment;

/// `rustlet build`.
#[derive(clap::Args, Debug)]
pub struct BuildArgs {
    /// Name the image (repeatable; without one, `images` lists it as <none>)
    #[arg(short, long, value_name = "NAME[:TAG]")]
    pub tag: Vec<String>,
    /// The Containerfile, relative to the current directory [default: PATH/Containerfile, else PATH/Dockerfile]
    #[arg(short, long, value_name = "FILE")]
    pub file: Option<PathBuf>,
    /// Set an ARG's value; a bare NAME takes its value from this shell (repeatable)
    #[arg(long, value_name = "NAME[=VALUE]")]
    pub build_arg: Vec<String>,
    /// Build up to this stage, by name or index [default: the last]
    #[arg(long, value_name = "STAGE")]
    pub target: Option<String>,
    /// Run every step again, whatever the build cache has
    #[arg(long)]
    pub no_cache: bool,
    /// Ask the registries for newer versions of the base images
    #[arg(long)]
    pub pull: bool,
    /// Network for the RUN steps: bridge (the default), host, none, or a network's name
    #[arg(long, value_name = "NETWORK")]
    pub network: Option<String>,
    /// Set a label on the image (repeatable)
    #[arg(long, value_name = "KEY[=VALUE]")]
    pub label: Vec<String>,
    /// Only print the image's ID (and the progress, if the build fails)
    #[arg(short, long)]
    pub quiet: bool,
    /// The build context: the directory whose files COPY and ADD can use
    #[arg(value_name = "PATH")]
    pub context: PathBuf,
}

impl BuildArgs {
    /// The request's options. `dockerfile` is the Containerfile's name in
    /// the archive; `lookup` reads the CLI's environment, for a bare
    /// `--build-arg NAME`.
    pub fn to_options(
        &self,
        dockerfile: String,
        lookup: &dyn Fn(&str) -> Option<String>,
    ) -> anyhow::Result<BuildOptions> {
        if self.tag.iter().any(String::is_empty) {
            bail!("invalid tag \"\": an image's name can't be empty");
        }
        let network = match self.network.as_deref().map(NetworkMode::parse).transpose().map_err(anyhow::Error::msg)? {
            Some(NetworkMode::Container(other)) => bail!(
                "--network container:{other}: a build's RUN steps can't use another container's network (bridge, \
                 host, none or a network's name)"
            ),
            mode => mode.unwrap_or_default(),
        };
        Ok(BuildOptions {
            tags: self.tag.clone(),
            dockerfile: Some(dockerfile),
            build_args: build_args(&self.build_arg, lookup)?,
            target: self.target.clone(),
            no_cache: self.no_cache,
            pull: if self.pull { PullPolicy::Always } else { PullPolicy::Missing },
            network,
            labels: parse_labels(&self.label)?,
        })
    }
}

/// `--build-arg` values as a map, the last value of a name counting. A
/// bare `NAME` takes its value from the CLI's environment, as with Docker;
/// one that isn't set there has none, so the `ARG` keeps its default.
fn build_args(values: &[String], lookup: &dyn Fn(&str) -> Option<String>) -> anyhow::Result<BTreeMap<String, String>> {
    let mut args = BTreeMap::new();
    for v in values {
        let (name, value) = match v.split_once('=') {
            Some((name, value)) => (name, Some(value.to_owned())),
            None => (v.as_str(), lookup(v)),
        };
        if name.is_empty() {
            bail!("invalid --build-arg {v:?}: no name");
        }
        match value {
            Some(value) => args.insert(name.to_owned(), value),
            None => args.remove(name),
        };
    }
    Ok(args)
}

/// Packs a build context into a writer: `rustlet_build::context::pack`.
pub type PackFn = fn(&Path, &Path, &mut dyn Write) -> Result<Packed, ContextError>;

/// The client's half of a build context: `rustlet_build::context`'s
/// functions ([`Packer::real`]), or the tests' fakes, which pack without
/// a context on disk.
#[derive(Clone, Copy)]
pub struct Packer {
    /// The Containerfile a context directory has, if it has one.
    pub default_containerfile: fn(&Path) -> Option<PathBuf>,
    /// The Containerfile's name inside the archive.
    pub dockerfile_name: fn(&Path, &Path) -> Result<String, ContextError>,
    pub pack: PackFn,
}

impl Packer {
    pub fn real() -> Packer {
        use rustlet_build::context;
        Packer {
            default_containerfile: context::default_containerfile,
            dockerfile_name: context::dockerfile_name,
            pack: context::pack,
        }
    }
}

pub async fn build(ctx: &mut Ctx, args: BuildArgs) -> anyhow::Result<i32> {
    check_context(&args.context)?;
    let packer = ctx.packer;
    let containerfile = match &args.file {
        Some(file) if file.as_os_str() == "-" => {
            bail!("a Containerfile on stdin (-f -) isn't supported: give its path")
        }
        Some(file) => file.clone(),
        None => (packer.default_containerfile)(&args.context)
            .ok_or_else(|| anyhow!("no Containerfile or Dockerfile in {} (-f names one)", args.context.display()))?,
    };
    // Its message names the file.
    let dockerfile = (packer.dockerfile_name)(&args.context, &containerfile).map_err(|e| anyhow!("{e}"))?;
    let options = args.to_options(dockerfile, &from_environment)?;
    ctx.debug(format_args!("building with {}", serde_json::to_string(&options)?));
    // Before the context is packed, or anything sent: the options have to fit in a request.
    rustlet_client::check_build_options(&options)?;

    let (body, writer) = RequestBody::pipe();
    let context = args.context.clone();
    let packing = tokio::task::spawn_blocking(move || pack_into(packer.pack, &context, &containerfile, writer));
    let mut shown = Shown::new(args.quiet, ctx.console.stdout_tty);
    let failed = match send(ctx, &options, body, &mut shown).await {
        Ok(id) => {
            if args.quiet {
                writeln!(ctx.console.stdout, "{id}")?;
            }
            return Ok(0);
        }
        Err(failed) => failed,
    };
    shown.failed(&mut ctx.console)?;
    if let Some(e) = pack_failure(packing).await {
        return Err(e);
    }
    match failed {
        Failed::Build(message) => {
            writeln!(ctx.console.stderr, "rustlet: error: {message}")?;
            Ok(1)
        }
        Failed::Request(e) => Err(e),
    }
}

/// A build context is a directory here. Docker's others (a Git or tarball
/// URL, an archive on stdin) are refused by name rather than as missing
/// directories.
fn check_context(path: &Path) -> anyhow::Result<()> {
    let text = path.to_string_lossy();
    if text == "-" {
        bail!("a build context on stdin (-) isn't supported: give a directory");
    }
    if ["http://", "https://", "git://", "git@", "ssh://"].iter().any(|scheme| text.starts_with(scheme)) {
        bail!("a remote build context ({text}) isn't supported: give a directory");
    }
    match std::fs::metadata(path) {
        Ok(m) if m.is_dir() => Ok(()),
        Ok(_) => bail!("build context {}: not a directory", path.display()),
        Err(e) => bail!("build context {}: {e}", path.display()),
    }
}

/// How a build that stored no image ended.
enum Failed {
    /// The daemon's account of it (a step that failed): exit 1, as `docker
    /// build`.
    Build(String),
    /// Anything else: the request, the connection, our own output.
    Request(anyhow::Error),
}

/// Sends the build and shows its events; returns the image's id.
async fn send(
    ctx: &mut Ctx,
    options: &BuildOptions,
    context: RequestBody,
    shown: &mut Shown,
) -> Result<String, Failed> {
    let mut events = ctx.client.build(options, context).await.map_err(|e| Failed::Request(e.into()))?;
    while let Some(event) = events.next().await {
        let event = match event {
            Ok(event) => event,
            Err(rustlet_client::Error::Stream(message)) => return Err(Failed::Build(message)),
            Err(e) => return Err(Failed::Request(e.into())),
        };
        shown.event(&mut ctx.console, &event).map_err(|e| Failed::Request(e.into()))?;
        if let BuildEvent::Done { id, .. } = event {
            return Ok(id);
        }
    }
    Err(Failed::Request(anyhow!("the build ended without storing an image (did rustletd stop?)")))
}

/// Packs the context into the request's body, on a blocking thread. The
/// body ends with the archive, or fails with the packing, so that the
/// daemon never takes a context cut short for a whole one.
fn pack_into(pack: PackFn, context: &Path, containerfile: &Path, mut body: BodyWriter) -> Result<Packed, ContextError> {
    match pack(context, containerfile, &mut body) {
        Ok(packed) => {
            // A body that can't be finished is the request's failure,
            // which the request reports.
            let _ = body.finish();
            Ok(packed)
        }
        Err(e) => {
            body.abort(io::Error::other(e.to_string()));
            Err(e)
        }
    }
}

/// Why the packing failed, if it failed by itself: then whatever the
/// request did (a body cut short) followed from it, and this is the error
/// to report. A write that failed because the request had ended first
/// (`BrokenPipe`) is the request's failure, not the packing's.
async fn pack_failure(packing: JoinHandle<Result<Packed, ContextError>>) -> Option<anyhow::Error> {
    // With the request over, its next write fails: it ends soon.
    match tokio::time::timeout(Duration::from_secs(5), packing).await {
        Ok(Ok(Err(ContextError::Io { source, .. }))) if source.kind() == io::ErrorKind::BrokenPipe => None,
        // The message names the path, and is complete: its source is in it.
        Ok(Ok(Err(e))) => Some(anyhow!("packing the build context: {e}")),
        Ok(Err(e)) if e.is_panic() => Some(anyhow!("packing the build context: {e}")),
        _ => None,
    }
}

/// Where a build's progress goes: the console as it comes, or with `-q`
/// a buffer, shown (on stderr) only if the build fails, as Docker's CLI
/// does.
struct Shown {
    progress: BuildProgress,
    held: Option<Vec<u8>>,
}

impl Shown {
    fn new(quiet: bool, tty: bool) -> Shown {
        Shown { progress: BuildProgress::new(tty && !quiet), held: quiet.then(Vec::new) }
    }

    fn event(&mut self, console: &mut Console, event: &BuildEvent) -> io::Result<()> {
        let outs = self.progress.show(event);
        self.write(console, &outs)
    }

    /// After a failure: the lines left open are ended, and what `-q` held
    /// back is shown.
    fn failed(&mut self, console: &mut Console) -> io::Result<()> {
        let outs = self.progress.finish();
        self.write(console, &outs)?;
        if let Some(held) = self.held.take() {
            console.stderr.write_all(&held)?;
            console.stderr.flush()?;
        }
        Ok(())
    }

    fn write(&mut self, console: &mut Console, outs: &[Out]) -> io::Result<()> {
        if let Some(held) = &mut self.held {
            outs.iter().for_each(|out| held.extend_from_slice(out.text().as_bytes()));
            return Ok(());
        }
        for out in outs {
            match out {
                Out::Stdout(text) => console.stdout.write_all(text.as_bytes())?,
                Out::Stderr(text) => console.stderr.write_all(text.as_bytes())?,
            }
        }
        // A pull's line has no newline to flush it.
        console.stdout.flush()?;
        console.stderr.flush()
    }
}

/// A piece of output, and where it goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Out {
    Stdout(String),
    Stderr(String),
}

impl Out {
    pub fn text(&self) -> &str {
        match self {
            Out::Stdout(text) | Out::Stderr(text) => text,
        }
    }
}

/// A build's events, shown as Docker's classic builder shows a build (see
/// the module docs): what to print for each, and where. A base image's
/// pull is one line: on a terminal redrawn in place as it goes, elsewhere
/// only its `Status:` line at the end.
#[derive(Debug, Default)]
pub struct BuildProgress {
    tty: bool,
    /// The container of the `RUN` step going on, once it is known.
    container: Option<String>,
    /// The last output of a step didn't end its line.
    mid_line: bool,
    /// The base image being pulled.
    pulling: Option<PullLine>,
    /// Its line is on the screen, to be redrawn or cleared.
    drawn: bool,
    out: Vec<Out>,
}

impl BuildProgress {
    pub fn new(tty: bool) -> BuildProgress {
        BuildProgress { tty, ..BuildProgress::default() }
    }

    /// What to print for `event`.
    pub fn show(&mut self, event: &BuildEvent) -> Vec<Out> {
        match event {
            BuildEvent::Context { bytes, .. } => {
                self.line(format!("Sending build context to rustletd  {}", human_size(*bytes)));
            }
            // Its `FROM` step says it.
            BuildEvent::Stage { .. } => {}
            BuildEvent::Step { step, total, instruction } => self.line(format!("Step {step}/{total} : {instruction}")),
            BuildEvent::Pull { event } => self.pull(event),
            BuildEvent::Cached { .. } => self.line(" ---> Using cache".to_owned()),
            BuildEvent::Container { id, .. } => {
                self.line(format!(" ---> Running in {}", short_id(id)));
                self.container = Some(id.clone());
            }
            BuildEvent::Output { text, .. } => self.output(text),
            BuildEvent::StepDone { layer, .. } => {
                if let Some(id) = self.container.take() {
                    self.line(format!(" ---> Removed intermediate container {}", short_id(&id)));
                }
                if let Some(layer) = layer {
                    self.line(format!(" ---> {}", short_digest(layer)));
                }
            }
            BuildEvent::Warning { message } => {
                self.close();
                self.out.push(Out::Stderr(format!("[Warning] {message}\n")));
            }
            BuildEvent::Done { id, names } => {
                self.line(format!("Successfully built {}", short_digest(id)));
                for name in names {
                    self.line(format!("Successfully tagged {}", Reference::parse(name).familiar()));
                }
            }
            // The client ends the stream with it as an error, which is
            // reported as such.
            BuildEvent::Error { .. } => {}
        }
        std::mem::take(&mut self.out)
    }

    /// What ends the lines left open, before anything else is printed: a
    /// pull's, a step's output without its last newline.
    pub fn finish(&mut self) -> Vec<Out> {
        self.close();
        std::mem::take(&mut self.out)
    }

    /// A step's unfinished output had its line ended by someone else's
    /// (`compose`'s, between a build's): no newline is owed.
    pub fn line_ended(&mut self) {
        self.mid_line = false;
    }

    fn pull(&mut self, event: &PullEvent) {
        match event {
            PullEvent::Resolving { reference } => self.pulling = Some(PullLine::new(reference)),
            PullEvent::Resolved { reference, .. } if self.pulling.is_none() => {
                self.pulling = Some(PullLine::new(reference));
            }
            _ => {}
        }
        let Some(line) = self.pulling.as_mut() else { return };
        match line.update(event) {
            Some(pulled) => {
                let status = line.status(&pulled);
                self.pulling = None;
                match status {
                    Some(status) => self.line(status),
                    None => self.close(),
                }
            }
            // Not at `resolving`: an image that is there goes straight to
            // `ready`, and its line would only flash.
            None if self.tty && !matches!(event, PullEvent::Resolving { .. }) => {
                let text = line.text();
                self.draw(text);
            }
            None => {}
        }
    }

    /// Draws the pull's line over what it said before.
    fn draw(&mut self, text: String) {
        self.end_output();
        self.out.push(Out::Stdout(format!("\r\x1b[2K{text}")));
        self.drawn = true;
    }

    /// Ends what is open so that a line can start: the pull's line is
    /// cleared (its next event draws it again), a step's unfinished output
    /// gets its newline.
    fn close(&mut self) {
        if std::mem::take(&mut self.drawn) {
            self.out.push(Out::Stdout("\r\x1b[2K".to_owned()));
        }
        self.end_output();
    }

    fn end_output(&mut self) {
        if std::mem::take(&mut self.mid_line) {
            self.out.push(Out::Stdout("\n".to_owned()));
        }
    }

    fn line(&mut self, text: String) {
        self.close();
        self.out.push(Out::Stdout(text + "\n"));
    }

    /// A `RUN` step's output, as it comes: both its streams on stdout, as
    /// Docker shows them.
    fn output(&mut self, text: &str) {
        if text.is_empty() {
            return;
        }
        if std::mem::take(&mut self.drawn) {
            self.out.push(Out::Stdout("\r\x1b[2K".to_owned()));
        }
        self.out.push(Out::Stdout(text.to_owned()));
        self.mid_line = !text.ends_with('\n');
    }
}

/// `rustlet builder`.
#[derive(clap::Subcommand, Debug)]
pub enum BuilderCommand {
    /// Remove the build cache: the next builds run every step again
    Prune {
        /// Don't ask for confirmation
        #[arg(short, long)]
        force: bool,
    },
}

/// Docker's question before `builder prune --all`: here every entry of the
/// cache goes, none is kept as in use.
const PRUNE_WARNING: &str = "WARNING! This will remove all build cache. Are you sure you want to continue?";

pub async fn builder(ctx: &mut Ctx, command: BuilderCommand) -> anyhow::Result<i32> {
    match command {
        BuilderCommand::Prune { force } => prune(ctx, force).await,
    }
}

/// `builder prune`, after asking on the terminal (unless `force`): what
/// went and the space it took, as Docker prints them. With no terminal to
/// ask on, nothing is done without `-f`; declined, nothing is removed and
/// the exit code is 0, as with Docker.
async fn prune(ctx: &mut Ctx, force: bool) -> anyhow::Result<i32> {
    if !force {
        if !ctx.console.stdin_tty {
            bail!("not removing the build cache without -f: stdin isn't a terminal to ask on");
        }
        if !ctx.console.confirm(PRUNE_WARNING).await? {
            return Ok(0);
        }
    }
    let pruned = ctx.client.prune_build_cache().await?;
    let out = &mut ctx.console.stdout;
    if !pruned.deleted.is_empty() {
        writeln!(out, "Deleted build cache objects:")?;
        for entry in &pruned.deleted {
            writeln!(out, "{entry}")?;
        }
        writeln!(out)?;
    }
    writeln!(out, "Total reclaimed space: {}", human_size(pruned.space_reclaimed))?;
    Ok(0)
}

/// `rustlet commit`.
#[derive(clap::Args, Debug)]
pub struct CommitArgs {
    /// The image's author ("Jane Doe <jane@example.com>")
    #[arg(short, long)]
    pub author: Option<String>,
    /// A comment for the image's history
    #[arg(short, long)]
    pub message: Option<String>,
    /// Apply a Containerfile instruction to the image: CMD, ENTRYPOINT, ENV, EXPOSE, LABEL, ONBUILD, USER, VOLUME, WORKDIR, STOPSIGNAL or HEALTHCHECK (repeatable)
    #[arg(short, long, value_name = "INSTRUCTION")]
    pub change: Vec<String>,
    /// Pause the container while its changes are read
    #[arg(
        short,
        long,
        value_name = "BOOL",
        action = ArgAction::Set,
        num_args = 0..=1,
        require_equals = true,
        default_value_t = true,
        default_missing_value = "true"
    )]
    pub pause: bool,
    pub container: String,
    /// The new image's name (without one, `images` lists it as <none>)
    #[arg(value_name = "REPOSITORY[:TAG]")]
    pub reference: Option<String>,
}

/// `rustlet commit`: the container's changes as a new image; prints its
/// id.
pub async fn commit(ctx: &mut Ctx, args: CommitArgs) -> anyhow::Result<i32> {
    let request = CommitRequest {
        container: args.container,
        reference: args.reference,
        comment: args.message,
        author: args.author,
        pause: args.pause,
        changes: args.change,
    };
    ctx.debug(format_args!("committing {}", serde_json::to_string(&request)?));
    let committed = ctx.client.commit(&request).await?;
    writeln!(ctx.console.stdout, "{}", committed.id)?;
    Ok(0)
}

#[cfg(test)]
mod tests {
    use clap::Parser;
    use rustlet_spec::image::BlobKind;
    use rustlet_spec::logs::LogStream;

    use super::*;

    #[derive(Parser)]
    struct Probe {
        #[command(flatten)]
        args: BuildArgs,
    }

    fn args(argv: &[&str]) -> BuildArgs {
        Probe::try_parse_from(std::iter::once("probe").chain(argv.iter().copied())).unwrap().args
    }

    fn env(name: &str) -> Option<String> {
        (name == "HTTP_PROXY").then(|| "http://proxy:3128".to_owned())
    }

    fn options(argv: &[&str]) -> anyhow::Result<BuildOptions> {
        args(argv).to_options("Containerfile".into(), &env)
    }

    #[test]
    fn flags_become_build_options() {
        let o = options(&[
            "-t",
            "app",
            "--tag",
            "registry.example/app:1.0",
            "--build-arg",
            "VERSION=3.12",
            "--build-arg",
            "HTTP_PROXY",
            "--build-arg",
            "UNSET",
            "--build-arg",
            "EMPTY=",
            "--target",
            "runtime",
            "--no-cache",
            "--pull",
            "--network",
            "host",
            "--label",
            "org.opencontainers.image.title=app",
            "--label",
            "solo",
            "-q",
            "./app",
        ])
        .unwrap();
        assert_eq!(
            o,
            BuildOptions {
                tags: vec!["app".into(), "registry.example/app:1.0".into()],
                dockerfile: Some("Containerfile".into()),
                // A bare name takes this shell's value, or is left out.
                build_args: [("EMPTY", ""), ("HTTP_PROXY", "http://proxy:3128"), ("VERSION", "3.12")]
                    .map(|(k, v)| (k.to_owned(), v.to_owned()))
                    .into(),
                target: Some("runtime".into()),
                no_cache: true,
                pull: PullPolicy::Always,
                network: NetworkMode::Host,
                labels: [("org.opencontainers.image.title", "app"), ("solo", "")]
                    .map(|(k, v)| (k.to_owned(), v.to_owned()))
                    .into(),
            }
        );
        let a = args(&["-f", "../Containerfile.dev", "-q", "."]);
        assert_eq!(
            (a.file.as_deref(), a.quiet, a.context.as_path()),
            (Some(Path::new("../Containerfile.dev")), true, Path::new("."))
        );
    }

    #[test]
    fn defaults_leave_everything_to_the_daemon() {
        let o = options(&["."]).unwrap();
        assert_eq!(o, BuildOptions { dockerfile: Some("Containerfile".into()), ..BuildOptions::default() });
        assert_eq!((o.pull, o.network), (PullPolicy::Missing, NetworkMode::Bridge));
        assert!(Probe::try_parse_from(["probe"]).is_err(), "PATH is required");
    }

    #[test]
    fn build_args_take_the_last_value_given() {
        let o = options(&["--build-arg", "A=1", "--build-arg", "A=2", "--build-arg", "B=x", "--build-arg", "B", "."]);
        // A bare name unset here takes away the value before it, as with
        // Docker: the ARG keeps its default.
        assert_eq!(o.unwrap().build_args, [("A".to_owned(), "2".to_owned())].into());
        let o = options(&["--build-arg", "URL=http://x/?a=b", "."]).unwrap();
        assert_eq!(o.build_args["URL"], "http://x/?a=b", "split at the first =");
    }

    #[test]
    fn options_that_cant_work_are_refused() {
        let e = options(&["--network", "container:db", "."]).unwrap_err().to_string();
        assert!(e.starts_with("--network container:db: a build's RUN steps can't use"), "{e}");
        assert!(options(&["--network", "a b", "."]).is_err());
        assert_eq!(options(&["--network", "default", "."]).unwrap().network, NetworkMode::Bridge);
        assert_eq!(options(&["--network", "backend", "."]).unwrap().network, NetworkMode::Network("backend".into()));
        assert!(options(&["--build-arg", "=x", "."]).is_err());
        assert!(options(&["--label", "=x", "."]).is_err());
        assert!(options(&["-t", "", "."]).is_err());
    }

    #[test]
    fn contexts_are_directories() {
        let dir = tempfile::tempdir().unwrap();
        assert!(check_context(dir.path()).is_ok());
        let file = dir.path().join("Containerfile");
        std::fs::write(&file, "FROM scratch\n").unwrap();
        let e = check_context(&file).unwrap_err().to_string();
        assert!(e.ends_with(": not a directory"), "{e}");
        let e = check_context(&dir.path().join("gone")).unwrap_err().to_string();
        assert!(e.starts_with("build context ") && e.contains("No such file"), "{e}");
        for (path, says) in
            [("-", "on stdin"), ("https://github.com/o/r.git", "remote"), ("git@github.com:o/r", "remote")]
        {
            let e = check_context(Path::new(path)).unwrap_err().to_string();
            assert!(e.contains(says), "{path}: {e}");
        }
    }

    const LAYER: &str = "sha256:9824c27679d3b27c0e1cb00b2b5cdbc2d1ae6e8f00aabbccddeeff0011223344";
    const IMAGE: &str = "sha256:3c4d5e6f7a8b00112233445566778899aabbccddeeff00112233445566778899";

    fn step(step: usize, instruction: &str) -> BuildEvent {
        BuildEvent::Step { step, total: 4, instruction: instruction.into() }
    }

    fn output(text: &str) -> BuildEvent {
        BuildEvent::Output { step: 2, stream: LogStream::Stdout, text: text.into() }
    }

    fn pull(event: PullEvent) -> BuildEvent {
        BuildEvent::Pull { event }
    }

    /// A build of four steps: a pull for `FROM`, a `RUN` that prints on
    /// both streams (its last line without a newline), a cached `COPY`, a
    /// `CMD`.
    fn events() -> Vec<BuildEvent> {
        let reference = "docker.io/library/python:3-slim".to_owned();
        let blob = "sha256:aaaaaaaaaaaa1111111111111111111111111111111111111111111111111111";
        vec![
            BuildEvent::Context { files: 3, bytes: 2048 },
            BuildEvent::Stage { index: 0, name: None, base: "python:3-slim".into() },
            step(1, "FROM python:3-slim"),
            pull(PullEvent::Resolving { reference: reference.clone() }),
            pull(PullEvent::Resolved {
                reference: reference.clone(),
                manifest: "sha256:m".into(),
                repo_digest: "sha256:r".into(),
                platform: "linux/amd64".into(),
                layers: 1,
                size: 3_000_000,
            }),
            pull(PullEvent::Downloading {
                kind: BlobKind::Layer,
                digest: blob.into(),
                current: 1_200_000,
                total: 3_000_000,
            }),
            pull(PullEvent::Downloaded { kind: BlobKind::Layer, digest: blob.into(), size: 3_000_000 }),
            pull(PullEvent::Ready { reference, manifest: "sha256:m".into() }),
            BuildEvent::StepDone { step: 1, layer: None },
            step(2, "RUN pip install redis"),
            BuildEvent::Container { step: 2, id: "4f1d2c3b4a5968778695a4b3c2d1e0f0".into() },
            output("Collecting redis\n"),
            BuildEvent::Output { step: 2, stream: LogStream::Stderr, text: "WARNING: running pip as root\n".into() },
            output("Successfully installed redis"),
            BuildEvent::StepDone { step: 2, layer: Some(LAYER.into()) },
            step(3, "COPY app.py /app/"),
            BuildEvent::Cached { step: 3 },
            BuildEvent::StepDone { step: 3, layer: Some(IMAGE.into()) },
            BuildEvent::Warning { message: "One or more build-args [UNUSED] were not consumed".into() },
            step(4, "CMD [\"python\", \"/app/app.py\"]"),
            BuildEvent::StepDone { step: 4, layer: None },
            BuildEvent::Done {
                id: IMAGE.into(),
                names: vec!["docker.io/library/app:latest".into(), "ghcr.io/o/app:1".into()],
            },
        ]
    }

    /// `events` rendered: stdout and stderr.
    fn render(tty: bool, events: &[BuildEvent]) -> (String, String) {
        let mut progress = BuildProgress::new(tty);
        let (mut stdout, mut stderr) = (String::new(), String::new());
        let mut outs: Vec<Out> = events.iter().flat_map(|e| progress.show(e)).collect();
        outs.extend(progress.finish());
        for out in outs {
            match out {
                Out::Stdout(text) => stdout.push_str(&text),
                Out::Stderr(text) => stderr.push_str(&text),
            }
        }
        (stdout, stderr)
    }

    #[test]
    fn a_build_reads_like_dockers_classic_builder() {
        let (stdout, stderr) = render(false, &events());
        assert_eq!(
            stdout,
            "Sending build context to rustletd  2.048kB\n\
             Step 1/4 : FROM python:3-slim\n\
             Status: Downloaded newer image for python:3-slim\n\
             Step 2/4 : RUN pip install redis\n \
             ---> Running in 4f1d2c3b4a59\n\
             Collecting redis\n\
             WARNING: running pip as root\n\
             Successfully installed redis\n \
             ---> Removed intermediate container 4f1d2c3b4a59\n \
             ---> 9824c27679d3\n\
             Step 3/4 : COPY app.py /app/\n \
             ---> Using cache\n \
             ---> 3c4d5e6f7a8b\n\
             Step 4/4 : CMD [\"python\", \"/app/app.py\"]\n\
             Successfully built 3c4d5e6f7a8b\n\
             Successfully tagged app:latest\n\
             Successfully tagged ghcr.io/o/app:1\n"
        );
        assert_eq!(stderr, "[Warning] One or more build-args [UNUSED] were not consumed\n");
    }

    #[test]
    fn on_a_terminal_a_pull_is_one_line_redrawn() {
        let events = events();
        let (stdout, _) = render(true, &events[2..9]);
        let clear = "\r\x1b[2K";
        assert_eq!(
            stdout,
            format!(
                "Step 1/4 : FROM python:3-slim\n\
                 {clear}python:3-slim: Pulling\
                 {clear}python:3-slim: Downloading 1.2MB/3MB\
                 {clear}python:3-slim: Downloading 3MB/3MB\
                 {clear}Status: Downloaded newer image for python:3-slim\n"
            )
        );
        // A base image that was there (`resolving`, then `ready`): no line
        // flashes, and nothing stays, on a terminal or off one.
        let present = [
            step(1, "FROM alpine"),
            pull(PullEvent::Resolving { reference: "docker.io/library/alpine:latest".into() }),
            pull(PullEvent::Ready { reference: "docker.io/library/alpine:latest".into(), manifest: "sha256:m".into() }),
            step(2, "RUN true"),
        ];
        for tty in [true, false] {
            let (stdout, _) = render(tty, &present);
            assert_eq!(stdout, "Step 1/4 : FROM alpine\nStep 2/4 : RUN true\n", "tty: {tty}");
        }
    }

    #[test]
    fn output_without_its_newline_still_ends_its_line() {
        let (stdout, _) =
            render(false, &[output("50%"), output("... 100%"), BuildEvent::StepDone { step: 2, layer: None }]);
        assert_eq!(stdout, "50%... 100%\n");
        // Even when the build fails right after it.
        let (stdout, _) = render(false, &[output("half a line")]);
        assert_eq!(stdout, "half a line\n");
        // A warning meanwhile starts a line of its own.
        let mut progress = BuildProgress::new(false);
        progress.show(&output("partial"));
        let warned = progress.show(&BuildEvent::Warning { message: "w".into() });
        assert_eq!(warned, [Out::Stdout("\n".into()), Out::Stderr("[Warning] w\n".into())]);
    }
}

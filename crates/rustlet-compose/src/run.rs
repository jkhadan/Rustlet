//! Running a project against rustletd: `up`, `down`, `ps`, `logs`,
//! `build`, `stop`, `start`; and the projects the daemon has containers of.

use std::time::Duration;

use futures::stream::BoxStream;
use rustlet_client::Client;
use rustlet_spec::build::BuildEvent;
use rustlet_spec::container::ContainerSummary;
use rustlet_spec::image::PullEvent;
use rustlet_spec::logs::{LogEntry, LogsQuery};

use crate::Result;
use crate::project::Project;

/// A project, and the daemon to run it on.
#[derive(Debug, Clone)]
pub struct Compose {
    pub client: Client,
    pub project: Project,
}

/// What a project operation reports as it goes (the CLI prints these, the
/// desktop app forwards them to its window).
#[derive(Debug, Clone, PartialEq)]
pub enum ComposeEvent {
    /// A network, volume or container changed state.
    Resource {
        kind: ResourceKind,
        name: String,
        action: Action,
    },
    /// A service's image is being built.
    Build {
        service: String,
        event: BuildEvent,
    },
    /// A service's image is being pulled.
    Pull {
        service: String,
        image: String,
        event: PullEvent,
    },
    /// Waiting for `service`'s dependency `on` to reach `condition`.
    Waiting {
        service: String,
        on: String,
        condition: crate::project::Condition,
    },
    Warning(String),
}

/// What a [`ComposeEvent::Resource`] is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceKind {
    Network,
    Volume,
    Container,
    Image,
}

/// What happened to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Creating,
    Created,
    /// Left as it was (a container already up to date, a network that
    /// exists).
    Running,
    Recreating,
    Recreated,
    Starting,
    Started,
    Healthy,
    Exited,
    Stopping,
    Stopped,
    Removing,
    Removed,
    Building,
    Built,
    Pulling,
    Pulled,
}

/// Options of `up`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UpOptions {
    /// Only these services (and what they depend on); empty: all.
    pub services: Vec<String>,
    pub build: BuildPolicy,
    /// Recreate containers even if their config hash matches.
    pub force_recreate: bool,
    /// Never recreate: a container that exists is started as it is.
    pub no_recreate: bool,
    /// Remove containers of services no longer in the file.
    pub remove_orphans: bool,
    /// Seconds a recreated container gets to stop.
    pub timeout: Option<u32>,
    /// How long a `service_healthy` dependency may take (default: as long
    /// as it stays `starting`).
    pub wait_timeout: Option<Duration>,
}

/// When `up` builds a service's image.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum BuildPolicy {
    /// If the image isn't there.
    #[default]
    Missing,
    /// Every time (`--build`).
    Always,
    /// Never (`--no-build`): a missing image is pulled, or an error.
    Never,
}

/// Options of `down`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DownOptions {
    /// `-v`: the named volumes the file declares (not external ones), and
    /// the containers' anonymous volumes.
    pub volumes: bool,
    /// Containers of services no longer in the file too.
    pub remove_orphans: bool,
    /// Seconds each container gets to stop.
    pub timeout: Option<u32>,
    /// `--rmi local`: images built for services without `image:`; `all`:
    /// every service's image.
    pub images: Option<RemoveImages>,
}

/// `--rmi`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoveImages {
    Local,
    All,
}

/// A container of a project.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceContainer {
    pub service: String,
    pub number: u32,
    pub summary: ContainerSummary,
}

/// A project the daemon has containers of, from their labels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stack {
    pub name: String,
    pub working_dir: Option<String>,
    pub config_files: Vec<String>,
    /// By service, then number.
    pub containers: Vec<ServiceContainer>,
}

/// One line of `logs`: which container, and what it printed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogLine {
    pub service: String,
    pub container: String,
    pub entry: LogEntry,
}

/// Receives a project operation's events.
pub type Events<'a> = &'a (dyn Fn(ComposeEvent) + Send + Sync);

impl Compose {
    pub fn new(client: Client, project: Project) -> Compose {
        Compose { client, project }
    }

    /// Creates what is missing (networks, volumes, images: built or
    /// pulled), then each service's containers in dependency order, each
    /// once its dependencies reach their conditions; recreates containers
    /// whose service changed; starts them. Returns once all are started
    /// (the CLI then follows their logs, unless `-d`).
    pub async fn up(&self, options: &UpOptions, events: Events<'_>) -> Result<()> {
        let _ = (options, events);
        unimplemented!("up: agent B")
    }

    /// Stops and removes the project's containers (dependents first), then
    /// its networks (not external ones), and as `options` say its volumes
    /// and images.
    pub async fn down(&self, options: &DownOptions, events: Events<'_>) -> Result<()> {
        let _ = (options, events);
        unimplemented!("down: agent B")
    }

    /// The project's containers (running ones, or all), by service and
    /// number.
    pub async fn ps(&self, all: bool) -> Result<Vec<ServiceContainer>> {
        let _ = all;
        unimplemented!("ps: agent B")
    }

    /// Builds the images of `services` (all with `build:` if empty).
    pub async fn build(&self, services: &[String], no_cache: bool, events: Events<'_>) -> Result<()> {
        let _ = (services, no_cache, events);
        unimplemented!("build: agent B")
    }

    /// Stops the containers of `services` (all if empty), dependents first.
    pub async fn stop(&self, services: &[String], timeout: Option<u32>, events: Events<'_>) -> Result<()> {
        let _ = (services, timeout, events);
        unimplemented!("stop: agent B")
    }

    /// Starts the existing containers of `services` (all if empty), in
    /// dependency order.
    pub async fn start(&self, services: &[String], events: Events<'_>) -> Result<()> {
        let _ = (services, events);
        unimplemented!("start: agent B")
    }

    /// The logs of the containers of `services` (all if empty), merged: with
    /// `query.follow` as they come, else in time order.
    pub async fn logs(&self, services: &[String], query: &LogsQuery) -> Result<BoxStream<'static, Result<LogLine>>> {
        let _ = (services, query);
        unimplemented!("logs: agent B")
    }
}

/// Every project the daemon has containers of (`compose ls`, the desktop
/// app's stacks).
pub async fn stacks(client: &Client) -> Result<Vec<Stack>> {
    let _ = client;
    unimplemented!("stacks: agent B")
}

/// `down` for a project known only by its name: its containers and networks
/// by their labels (the desktop app's "remove stack", `compose -p NAME
/// down` without a file).
pub async fn down_project(client: &Client, project: &str, options: &DownOptions, events: Events<'_>) -> Result<()> {
    let _ = (client, project, options, events);
    unimplemented!("down_project: agent B")
}

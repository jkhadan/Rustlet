//! Running a project against rustletd: `up`, `down`, `ps`, `logs`,
//! `build`, `stop`, `start`; and the projects the daemon has containers of.
//!
//! Client-side, as Compose v2: the daemon knows containers, networks and
//! volumes, not projects. What belongs to a project is found by listing
//! them and reading their labels ([`crate::LABEL_PROJECT`] and the others),
//! so `ps`, `down` and the desktop app's stacks need nothing but the
//! daemon.
//!
//! `up`, step by step:
//!
//! 1. the networks the services use, created if missing (labelled with the
//!    project and the network's key); an `external` one must exist;
//! 2. the named volumes they mount, likewise;
//! 3. images: built (`build:`) when `--build` says so, when `pull_policy:
//!    build` does, or when missing; pulled when missing (every time with
//!    `pull_policy: always`); missing with `pull_policy: never` is an error;
//! 4. containers of services that aren't in the file any more (orphans):
//!    removed with `--remove-orphans`, else a warning; a service that a
//!    profile left out has no orphans;
//! 5. each service in dependency order: first what its dependencies must
//!    reach (`service_healthy`: their healthcheck said healthy;
//!    `service_completed_successfully`: they exited with 0; both polled every
//!    250 ms; `service_started` needs no wait, the dependency was started
//!    first), then its containers `<project>-<service>-<n>`: one whose
//!    config-hash label and image are the service's is left as it is
//!    (started if it isn't running); one that differs is recreated (stopped,
//!    removed, created again under its name); a missing one is created and
//!    started; those numbered above the replicas are removed, highest first.
//!
//! A container is created on its first network, with its aliases and
//! addresses there; each further network is connected before the start,
//! with its own.
//!
//! **Deviations** from Compose: one thing at a time (Compose starts
//! independent services in parallel); a recreated container gets new
//! anonymous volumes (Compose hands it the old one's); a service with
//! `build:` is pulled only when its image is missing and building isn't
//! allowed (`--no-build`), never to look for a newer one first.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use futures::stream::{BoxStream, StreamExt, TryStreamExt};
use rustlet_build::context::ContextError;
use rustlet_client::{Client, RequestBody};
use rustlet_spec::ErrorKind;
use rustlet_spec::build::{BuildEvent, BuildOptions};
use rustlet_spec::container::{ContainerInspect, ContainerStatus, ContainerSummary, HealthStatus, RemoveQuery};
use rustlet_spec::image::{PullEvent, PullPolicy};
use rustlet_spec::logs::{LogEntry, LogsQuery};
use rustlet_spec::network::{NetworkConnect, NetworkCreate, NetworkMode};
use rustlet_spec::volume::{MountType, VolumeCreate};

use crate::project::{Condition, Project, Service, default_image};
use crate::{
    Error, LABEL_CONFIG_FILES, LABEL_CONFIG_HASH, LABEL_DEPENDS_ON, LABEL_NETWORK, LABEL_NUMBER, LABEL_PROJECT,
    LABEL_SERVICE, LABEL_VOLUME, LABEL_WORKING_DIR, Result,
};

/// How often a dependency is looked at while `up` waits for it.
const POLL: Duration = Duration::from_millis(250);

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
    /// How long a dependency may take to become healthy (or, for
    /// `service_completed_successfully`, to exit); default: as long as it
    /// stays `starting` (running).
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
        if options.force_recreate && options.no_recreate {
            return Err(Error::Invalid("--force-recreate and --no-recreate can't go together".into()));
        }
        let order = self.project.startup_order(&options.services)?;
        self.ensure_networks(&order, events).await?;
        self.ensure_volumes(&order, events).await?;
        self.ensure_images(&order, options.build, events).await?;
        let containers = self.containers(true).await?;
        let orphans = self.orphans(&containers);
        if options.remove_orphans {
            for orphan in orphans {
                stop_and_remove(&self.client, &orphan.summary, options.timeout, false, events).await?;
            }
        } else {
            warn_orphans(&orphans, events);
        }
        for service in order {
            self.wait_for_dependencies(service, options.wait_timeout, events).await?;
            self.converge(service, options, events).await?;
        }
        Ok(())
    }

    /// Stops and removes the project's containers (dependents first), then
    /// its networks (not external ones), and as `options` say its volumes
    /// and images.
    pub async fn down(&self, options: &DownOptions, events: Events<'_>) -> Result<()> {
        let containers = self.containers(true).await?;
        let orphans = self.orphans(&containers);
        if options.remove_orphans {
            for orphan in orphans.iter().rev() {
                stop_and_remove(&self.client, &orphan.summary, options.timeout, options.volumes, events).await?;
            }
        } else {
            warn_orphans(&orphans, events);
        }
        for service in self.project.dependency_order(&[], false)?.into_iter().rev() {
            for c in containers.iter().filter(|c| c.service == service.name).rev() {
                stop_and_remove(&self.client, &c.summary, options.timeout, options.volumes, events).await?;
            }
        }
        remove_networks(&self.client, &self.project.name, events).await?;
        if options.volumes {
            remove_volumes(&self.client, &self.project.name, events).await?;
        }
        if let Some(which) = options.images {
            let images = self
                .project
                .services
                .iter()
                .filter(|s| {
                    which == RemoveImages::All
                        || (s.build.is_some() && s.image == default_image(&self.project.name, &s.name))
                })
                .map(|s| s.image.clone())
                // Collected: an iterator of closures held across the awaits
                // would make this future not `Send` (`futures_are_send`).
                .collect::<Vec<_>>();
            remove_images(&self.client, images, events).await?;
        }
        Ok(())
    }

    /// The project's containers (running ones, or all), by service (in the
    /// project's order, those of services it doesn't have last) and number.
    pub async fn ps(&self, all: bool) -> Result<Vec<ServiceContainer>> {
        self.containers(all).await
    }

    /// Builds the images of `services` (all with `build:` if empty).
    pub async fn build(&self, services: &[String], no_cache: bool, events: Events<'_>) -> Result<()> {
        self.check_services(services)?;
        let mut built = BTreeSet::new();
        for service in self.selected(services) {
            if service.build.is_none() {
                if !services.is_empty() {
                    events(ComposeEvent::Warning(format!(
                        "service {:?} has no build section: there is nothing to build",
                        service.name
                    )));
                }
                continue;
            }
            if built.insert(service.image.as_str()) {
                self.build_image(service, no_cache, events).await?;
            }
        }
        Ok(())
    }

    /// Stops the containers of `services` (all if empty), dependents first.
    pub async fn stop(&self, services: &[String], timeout: Option<u32>, events: Events<'_>) -> Result<()> {
        self.check_services(services)?;
        let containers = self.containers(true).await?;
        for service in self.project.dependency_order(&[], false)?.into_iter().rev() {
            if !services.is_empty() && !services.contains(&service.name) {
                continue;
            }
            for c in containers.iter().filter(|c| c.service == service.name && is_live(c.summary.state.status)).rev() {
                resource(events, ResourceKind::Container, &c.summary.name, Action::Stopping);
                ignore_gone(self.client.stop(&c.summary.id, timeout).await)?;
                resource(events, ResourceKind::Container, &c.summary.name, Action::Stopped);
            }
        }
        Ok(())
    }

    /// Starts the existing containers of `services` (all if empty), in
    /// dependency order.
    ///
    /// As with Compose, what they depend on is started too, and waited for
    /// as `depends_on` says.
    pub async fn start(&self, services: &[String], events: Events<'_>) -> Result<()> {
        for service in self.project.startup_order(services)? {
            if service.replicas == 0 {
                continue;
            }
            let containers = self.containers_of(service, true).await?;
            if containers.is_empty() {
                return Err(Error::Invalid(format!(
                    "service {:?} has no container to start (up creates them)",
                    service.name
                )));
            }
            self.wait_for_dependencies(service, None, events).await?;
            for c in &containers {
                ensure_started(&self.client, &c.summary, events).await?;
            }
        }
        Ok(())
    }

    /// The logs of the containers of `services` (all if empty), merged: with
    /// `query.follow` as they come, else in time order.
    pub async fn logs(&self, services: &[String], query: &LogsQuery) -> Result<BoxStream<'static, Result<LogLine>>> {
        self.check_services(services)?;
        let mut streams: Vec<BoxStream<'static, Result<LogLine>>> = Vec::new();
        for c in self.containers(true).await? {
            if !services.is_empty() && !services.contains(&c.service) {
                continue;
            }
            let entries = self.client.logs(&c.summary.id, query).await?;
            let (service, container) = (c.service, c.summary.name);
            let lines = entries.map(move |entry: rustlet_client::Result<LogEntry>| -> Result<LogLine> {
                Ok(LogLine { service: service.clone(), container: container.clone(), entry: entry? })
            });
            streams.push(lines.boxed());
        }
        if query.follow {
            return Ok(futures::stream::select_all(streams).boxed());
        }
        let mut lines = Vec::new();
        for stream in streams {
            lines.extend(stream.try_collect::<Vec<_>>().await?);
        }
        // Stable: a container's lines with the same time keep their order.
        lines.sort_by(|a, b| time_key(&a.entry.ts).cmp(&time_key(&b.entry.ts)));
        Ok(futures::stream::iter(lines.into_iter().map(Ok)).boxed())
    }

    /// `services` (all if empty), in the project's order.
    fn selected<'a>(&'a self, services: &'a [String]) -> impl Iterator<Item = &'a Service> + 'a {
        self.project.services.iter().filter(move |s| services.is_empty() || services.contains(&s.name))
    }

    fn check_services(&self, services: &[String]) -> Result<()> {
        match services.iter().find(|s| self.project.service(s).is_none()) {
            Some(unknown) => Err(Error::Invalid(format!("no such service: {unknown}"))),
            None => Ok(()),
        }
    }

    /// The project's containers (all, or running ones), by service in the
    /// project's order (others last, by name), then number.
    async fn containers(&self, all: bool) -> Result<Vec<ServiceContainer>> {
        let mut containers = project_containers(&self.client, &self.project.name, all).await?;
        let position =
            |service: &str| self.project.services.iter().position(|s| s.name == service).unwrap_or(usize::MAX);
        containers.sort_by_cached_key(|c| (position(&c.service), c.service.clone(), c.number, c.summary.name.clone()));
        Ok(containers)
    }

    /// The containers of `service`, by number.
    async fn containers_of(&self, service: &Service, all: bool) -> Result<Vec<ServiceContainer>> {
        let mut containers = self.containers(all).await?;
        containers.retain(|c| c.service == service.name);
        Ok(containers)
    }

    /// Containers of services the file doesn't have (and no profile left
    /// out).
    fn orphans<'a>(&self, containers: &'a [ServiceContainer]) -> Vec<&'a ServiceContainer> {
        containers
            .iter()
            .filter(|c| {
                self.project.service(&c.service).is_none() && !self.project.disabled_services.contains(&c.service)
            })
            .collect()
    }

    /// The networks `services` are on: created if missing, with the
    /// project's labels; an external one must exist.
    async fn ensure_networks(&self, services: &[&Service], events: Events<'_>) -> Result<()> {
        let used: BTreeSet<&str> = services.iter().flat_map(|s| &s.networks).map(|n| n.network.as_str()).collect();
        let existing = self.client.list_networks().await?;
        for (key, network) in &self.project.networks {
            if !used.contains(network.name.as_str()) {
                continue;
            }
            if let Some(found) = existing.iter().find(|n| n.name == network.name) {
                if !network.external && found.labels.get(LABEL_PROJECT) != Some(&self.project.name) {
                    events(ComposeEvent::Warning(format!(
                        "a network named {} exists but wasn't made for project {}: it is used as it is (external: \
                         true says so and silences this)",
                        network.name, self.project.name
                    )));
                }
                resource(events, ResourceKind::Network, &network.name, Action::Running);
                continue;
            }
            if network.external {
                return Err(Error::Invalid(format!(
                    "network {} is external (external: true), but there is no such network: create it first",
                    network.name
                )));
            }
            resource(events, ResourceKind::Network, &network.name, Action::Creating);
            let (subnet6, subnet): (Vec<&String>, Vec<&String>) = network.subnets.iter().partition(|s| s.contains(':'));
            let mut labels = network.labels.clone();
            labels.insert(LABEL_PROJECT.into(), self.project.name.clone());
            labels.insert(LABEL_NETWORK.into(), key.clone());
            let create = NetworkCreate {
                name: network.name.clone(),
                subnet: subnet.first().map(|s| s.to_string()),
                subnet6: subnet6.first().map(|s| s.to_string()),
                ipv6: network.enable_ipv6,
                internal: network.internal,
                labels,
                ..NetworkCreate::default()
            };
            self.client.create_network(&create).await?;
            resource(events, ResourceKind::Network, &network.name, Action::Created);
        }
        Ok(())
    }

    /// The named volumes `services` mount: created if missing, with the
    /// project's labels; an external one must exist.
    async fn ensure_volumes(&self, services: &[&Service], events: Events<'_>) -> Result<()> {
        let used: BTreeSet<&str> = services
            .iter()
            .flat_map(|s| &s.config.mounts)
            .filter(|m| m.kind == MountType::Volume)
            .filter_map(|m| m.source.as_deref())
            .collect();
        let existing = self.client.list_volumes().await?;
        for (key, volume) in &self.project.volumes {
            if !used.contains(volume.name.as_str()) {
                continue;
            }
            if let Some(found) = existing.iter().find(|v| v.name == volume.name) {
                if !volume.external && found.labels.get(LABEL_PROJECT) != Some(&self.project.name) {
                    events(ComposeEvent::Warning(format!(
                        "a volume named {} exists but wasn't made for project {}: it is used as it is (external: true \
                         says so and silences this)",
                        volume.name, self.project.name
                    )));
                }
                resource(events, ResourceKind::Volume, &volume.name, Action::Running);
                continue;
            }
            if volume.external {
                return Err(Error::Invalid(format!(
                    "volume {} is external (external: true), but there is no such volume: create it first",
                    volume.name
                )));
            }
            resource(events, ResourceKind::Volume, &volume.name, Action::Creating);
            let mut labels = volume.labels.clone();
            labels.insert(LABEL_PROJECT.into(), self.project.name.clone());
            labels.insert(LABEL_VOLUME.into(), key.clone());
            self.client.create_volume(&VolumeCreate { name: Some(volume.name.clone()), labels }).await?;
            resource(events, ResourceKind::Volume, &volume.name, Action::Created);
        }
        Ok(())
    }

    /// Each service's image, built or pulled as needed (once per image).
    async fn ensure_images(&self, services: &[&Service], policy: BuildPolicy, events: Events<'_>) -> Result<()> {
        let mut seen = BTreeSet::new();
        for service in services.iter().filter(|s| s.replicas > 0) {
            if !seen.insert(service.image.as_str()) {
                continue;
            }
            let present = image_exists(&self.client, &service.image).await?;
            if let Some(build) = &service.build {
                let must_build = match policy {
                    BuildPolicy::Always => true,
                    BuildPolicy::Never => false,
                    BuildPolicy::Missing => build.always || !present,
                };
                if must_build {
                    self.build_image(service, false, events).await?;
                    continue;
                }
            }
            match (service.pull_policy, present) {
                (PullPolicy::Always, _) if service.build.is_none() => {
                    self.pull(service, PullPolicy::Always, events).await?;
                }
                (_, true) => {}
                (PullPolicy::Never, false) => {
                    return Err(Error::Invalid(format!(
                        "service {:?}: there is no image {}, and {}",
                        service.name,
                        service.image,
                        match service.build {
                            Some(_) => "it may be neither built (--no-build) nor pulled (pull_policy: never)",
                            None => "it may not be pulled (pull_policy: never)",
                        }
                    )));
                }
                (_, false) => self.pull(service, PullPolicy::Missing, events).await?,
            }
        }
        Ok(())
    }

    async fn pull(&self, service: &Service, policy: PullPolicy, events: Events<'_>) -> Result<()> {
        resource(events, ResourceKind::Image, &service.image, Action::Pulling);
        let mut progress = self.client.pull(&service.image, policy).await?;
        while let Some(event) = progress.next().await {
            events(ComposeEvent::Pull { service: service.name.clone(), image: service.image.clone(), event: event? });
        }
        resource(events, ResourceKind::Image, &service.image, Action::Pulled);
        Ok(())
    }

    /// Builds `service`'s image: its context packed on a blocking thread
    /// as the request sends it, the daemon's progress forwarded.
    async fn build_image(&self, service: &Service, no_cache: bool, events: Events<'_>) -> Result<()> {
        let Some(build) = &service.build else { return Ok(()) };
        resource(events, ResourceKind::Image, &service.image, Action::Building);
        let context = build.context.clone();
        let containerfile = match &build.dockerfile {
            Some(file) => context.join(file),
            None => rustlet_build::context::default_containerfile(&context).ok_or_else(|| {
                Error::Invalid(format!(
                    "service {:?}: no Containerfile or Dockerfile in {} (build.dockerfile names another)",
                    service.name,
                    context.display()
                ))
            })?,
        };
        let network = match &build.network {
            Some(network) => NetworkMode::parse(network)
                .map_err(|e| Error::Invalid(format!("service {:?}: build.network: {e}", service.name)))?,
            None => NetworkMode::default(),
        };
        let options = BuildOptions {
            tags: vec![service.image.clone()],
            dockerfile: Some(rustlet_build::context::dockerfile_name(&context, &containerfile)?),
            build_args: build.args.clone(),
            target: build.target.clone(),
            no_cache: no_cache || build.no_cache,
            network,
            labels: build.labels.clone(),
            ..BuildOptions::default()
        };
        let (body, mut writer) = RequestBody::pipe();
        let packing = tokio::task::spawn_blocking(move || {
            let packed = rustlet_build::context::pack(&context, &containerfile, &mut writer);
            match &packed {
                Ok(_) => {
                    // A failure to finish is the request's, which reports it.
                    let _ = writer.finish();
                }
                Err(e) => writer.abort(std::io::Error::other(e.to_string())),
            }
            packed
        });
        let sent = async {
            let mut progress = self.client.build(&options, body).await?;
            while let Some(event) = progress.next().await {
                events(ComposeEvent::Build { service: service.name.clone(), event: event? });
            }
            Ok::<_, Error>(())
        }
        .await;
        let packed =
            packing.await.map_err(|e| ContextError::Invalid(format!("packing the build context failed: {e}")))?;
        match (packed, sent) {
            (Ok(_), Ok(())) => {}
            (Ok(_), Err(e)) => return Err(e),
            (Err(e), Ok(())) => return Err(e.into()),
            // The daemon's answer, or the packer's trouble: whichever came
            // first (a packer that found the request gone says only that).
            (Err(packing), Err(sending)) => {
                let daemon_said = matches!(
                    sending,
                    Error::Client(rustlet_client::Error::Api { .. } | rustlet_client::Error::Stream(_))
                );
                return Err(if daemon_said || is_broken_pipe(&packing) { sending } else { packing.into() });
            }
        }
        resource(events, ResourceKind::Image, &service.image, Action::Built);
        Ok(())
    }

    /// Waits for what `service`'s dependencies must reach. A dependency
    /// that isn't required and fails is a warning.
    async fn wait_for_dependencies(
        &self,
        service: &Service,
        timeout: Option<Duration>,
        events: Events<'_>,
    ) -> Result<()> {
        for dep in &service.depends_on {
            // `service_started` asks for nothing more than the order did.
            if dep.condition == Condition::Started {
                continue;
            }
            // An optional dependency the project doesn't have, or one
            // scaled to nothing.
            let Some(target) = self.project.service(&dep.service).filter(|t| t.replicas > 0) else { continue };
            events(ComposeEvent::Waiting {
                service: service.name.clone(),
                on: dep.service.clone(),
                condition: dep.condition,
            });
            match self.wait_for(target, dep.condition, timeout, events).await {
                Ok(()) => {}
                Err(e) if !dep.required => {
                    events(ComposeEvent::Warning(format!(
                        "{e} ({} goes on without it: required: false)",
                        service.name
                    )));
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Polls each container of `target` until it reaches `condition`.
    async fn wait_for(
        &self,
        target: &Service,
        condition: Condition,
        timeout: Option<Duration>,
        events: Events<'_>,
    ) -> Result<()> {
        let deadline = timeout.map(|t| Instant::now() + t);
        let mut containers = self.containers_of(target, true).await?;
        containers.retain(|c| (1..=target.replicas).contains(&c.number));
        if containers.is_empty() {
            return Err(Error::Dependency(format!(
                "dependency failed to start: service {:?} has no container",
                target.name
            )));
        }
        for c in &containers {
            let mut has_healthcheck = None;
            loop {
                let inspect = self.client.inspect_container(&c.summary.id).await?;
                let Some(state) = self.check(&target.name, &inspect, condition, &mut has_healthcheck).await? else {
                    break;
                };
                if let (Some(deadline), Some(timeout)) = (deadline, timeout)
                    && Instant::now() >= deadline
                {
                    return Err(Error::Dependency(format!(
                        "dependency failed to start: container {} is still {state} after {timeout:?}",
                        inspect.name
                    )));
                }
                tokio::time::sleep(POLL).await;
            }
            let action = if condition == Condition::Healthy { Action::Healthy } else { Action::Exited };
            resource(events, ResourceKind::Container, &c.summary.name, action);
        }
        Ok(())
    }

    /// `None` once the container meets `condition`; else what it is
    /// meanwhile; an error once it never will. The messages are Compose's.
    async fn check(
        &self,
        service: &str,
        c: &ContainerInspect,
        condition: Condition,
        has_healthcheck: &mut Option<bool>,
    ) -> Result<Option<String>> {
        let state = &c.state;
        let ended = matches!(state.status, ContainerStatus::Exited | ContainerStatus::Dead);
        match condition {
            Condition::Started => Ok((state.status == ContainerStatus::Created).then(|| "created".into())),
            Condition::Healthy => {
                if ended {
                    return Err(Error::Dependency(format!(
                        "dependency failed to start: container {} exited ({})",
                        c.name,
                        state.exit_code.unwrap_or(-1)
                    )));
                }
                match state.health.as_ref().map(|h| h.status) {
                    Some(HealthStatus::Healthy) => Ok(None),
                    Some(HealthStatus::Unhealthy) => {
                        Err(Error::Dependency(format!("dependency failed to start: container {} is unhealthy", c.name)))
                    }
                    Some(HealthStatus::Starting) => Ok(Some("starting".into())),
                    // No check has run yet; or none ever will.
                    None => {
                        let has = match *has_healthcheck {
                            Some(has) => has,
                            None => *has_healthcheck.insert(self.has_healthcheck(c).await?),
                        };
                        if !has {
                            return Err(Error::Dependency(format!(
                                "dependency failed to start: container {} has no healthcheck configured",
                                c.name
                            )));
                        }
                        Ok(Some("starting".into()))
                    }
                }
            }
            Condition::CompletedSuccessfully => match (ended, state.exit_code) {
                (true, Some(0)) => Ok(None),
                (true, code) => Err(Error::Dependency(format!(
                    "service {service:?} didn't complete successfully: exit {}",
                    code.unwrap_or(-1)
                ))),
                (false, _) => Ok(Some(state.status.to_string())),
            },
        }
    }

    /// Whether the container has a healthcheck: its own, else its image's
    /// `HEALTHCHECK`.
    async fn has_healthcheck(&self, c: &ContainerInspect) -> Result<bool> {
        if let Some(health) = &c.config.healthcheck {
            if health.is_none() {
                return Ok(false);
            }
            if !health.test.is_empty() {
                return Ok(true);
            }
        }
        let image = if c.config.image.is_empty() { &c.image } else { &c.config.image };
        let config = match self.client.inspect_image(image).await {
            Ok(image) => image.config,
            Err(e) if e.is_not_found() => return Ok(false),
            Err(e) => return Err(e.into()),
        };
        let test = config.pointer("/config/Healthcheck/Test").and_then(|t| t.as_array());
        Ok(test.and_then(|t| t.first()).and_then(|t| t.as_str()).is_some_and(|t| t != "NONE"))
    }

    /// Brings `service`'s containers to what it says: each one up to date
    /// and started, the ones it no longer has removed.
    async fn converge(&self, service: &Service, options: &UpOptions, events: Events<'_>) -> Result<()> {
        let existing = self.containers_of(service, true).await?;
        let hash = service.config_hash();
        let image_id = match service.replicas {
            0 => String::new(),
            _ => self.client.inspect_image(&service.image).await?.summary.id,
        };
        let mut kept = BTreeSet::new();
        for n in 1..=service.replicas {
            let Some(c) = existing.iter().find(|c| c.number == n) else {
                let name = service.container_name(&self.project.name, n);
                resource(events, ResourceKind::Container, &name, Action::Creating);
                let id = self.create(service, n, events).await?;
                resource(events, ResourceKind::Container, &name, Action::Created);
                start(&self.client, &id, &name, events).await?;
                continue;
            };
            kept.insert(c.summary.id.as_str());
            let current = c.summary.labels.get(LABEL_CONFIG_HASH) == Some(&hash) && c.summary.image_id == image_id;
            let usable = !matches!(c.summary.state.status, ContainerStatus::Dead | ContainerStatus::Removing);
            if usable && (options.no_recreate || (current && !options.force_recreate)) {
                ensure_started(&self.client, &c.summary, events).await?;
            } else {
                self.recreate(service, n, &c.summary, options.timeout, events).await?;
            }
        }
        // Scaled down (or a number given twice): the highest go first.
        for c in existing.iter().rev().filter(|c| !kept.contains(c.summary.id.as_str())) {
            stop_and_remove(&self.client, &c.summary, options.timeout, false, events).await?;
        }
        Ok(())
    }

    /// Container `n` of `service` again: the old one stopped and removed
    /// (its anonymous volumes kept), a new one created and started.
    async fn recreate(
        &self,
        service: &Service,
        n: u32,
        old: &ContainerSummary,
        timeout: Option<u32>,
        events: Events<'_>,
    ) -> Result<()> {
        resource(events, ResourceKind::Container, &old.name, Action::Recreating);
        if is_live(old.state.status) {
            ignore_gone(self.client.stop(&old.id, timeout).await)?;
        }
        ignore_gone(self.client.remove_container_with(&old.id, &RemoveQuery { force: true, volumes: false }).await)?;
        let name = service.container_name(&self.project.name, n);
        let id = self.create(service, n, events).await?;
        resource(events, ResourceKind::Container, &name, Action::Recreated);
        start(&self.client, &id, &name, events).await
    }

    /// Creates container `n` of `service`, on all its networks, without
    /// starting it; returns its id.
    async fn create(&self, service: &Service, n: u32, events: Events<'_>) -> Result<String> {
        let mut config = service.config.clone();
        config.name = Some(service.container_name(&self.project.name, n));
        config.labels = self.labels(service, n);
        // The first network comes with the create; the others, each with
        // its aliases and addresses, by `network connect` before the start.
        config.extra_networks.clear();
        let created = self.client.create_container(&config).await?;
        for warning in created.warnings {
            events(ComposeEvent::Warning(format!("{}: {warning}", created.name)));
        }
        for network in service.networks.iter().skip(1) {
            let connect = NetworkConnect {
                container: created.id.clone(),
                aliases: network.aliases.clone(),
                ipv4_address: network.ipv4_address,
                ipv6_address: network.ipv6_address,
            };
            self.client.connect_network(&network.network, &connect).await?;
        }
        Ok(created.id)
    }

    /// The labels of container `n` of `service`: the service's own, and
    /// the project's over them.
    fn labels(&self, service: &Service, n: u32) -> BTreeMap<String, String> {
        let files: Vec<String> = self.project.files.iter().map(|f| f.display().to_string()).collect();
        let depends_on: Vec<String> = service
            .depends_on
            .iter()
            .map(|d| format!("{}:{}:{}", d.service, condition_name(d.condition), d.required))
            .collect();
        let mut labels = service.config.labels.clone();
        for (key, value) in [
            (LABEL_PROJECT, self.project.name.clone()),
            (LABEL_SERVICE, service.name.clone()),
            (LABEL_NUMBER, n.to_string()),
            (LABEL_CONFIG_HASH, service.config_hash()),
            (LABEL_WORKING_DIR, self.project.dir.display().to_string()),
            (LABEL_CONFIG_FILES, files.join(",")),
            (LABEL_DEPENDS_ON, depends_on.join(",")),
        ] {
            labels.insert(key.to_owned(), value);
        }
        labels
    }
}

/// Every project the daemon has containers of (`compose ls`, the desktop
/// app's stacks), by name.
pub async fn stacks(client: &Client) -> Result<Vec<Stack>> {
    let mut stacks: BTreeMap<String, Stack> = BTreeMap::new();
    for summary in client.list_containers(true).await? {
        let Some(project) = summary.labels.get(LABEL_PROJECT).cloned() else { continue };
        let stack = stacks.entry(project.clone()).or_insert_with(|| Stack {
            name: project,
            working_dir: None,
            config_files: Vec::new(),
            containers: Vec::new(),
        });
        if stack.working_dir.is_none() {
            stack.working_dir = summary.labels.get(LABEL_WORKING_DIR).cloned();
        }
        if stack.config_files.is_empty()
            && let Some(files) = summary.labels.get(LABEL_CONFIG_FILES)
        {
            stack.config_files = files.split(',').filter(|f| !f.is_empty()).map(str::to_owned).collect();
        }
        stack.containers.push(service_container(summary));
    }
    let mut stacks: Vec<Stack> = stacks.into_values().collect();
    for stack in &mut stacks {
        stack
            .containers
            .sort_by(|a, b| (&a.service, a.number, &a.summary.name).cmp(&(&b.service, b.number, &b.summary.name)));
    }
    Ok(stacks)
}

/// `down` for a project known only by its name: its containers and networks
/// by their labels (the desktop app's "remove stack", `compose -p NAME
/// down` without a file).
///
/// Dependents go first, as the containers' [`LABEL_DEPENDS_ON`] say. With
/// `--rmi local`, the images named as built ones are (`<project>-<service>`).
pub async fn down_project(client: &Client, project: &str, options: &DownOptions, events: Events<'_>) -> Result<()> {
    let containers = project_containers(client, project, true).await?;
    for c in shutdown_order(&containers) {
        stop_and_remove(client, &c.summary, options.timeout, options.volumes, events).await?;
    }
    remove_networks(client, project, events).await?;
    if options.volumes {
        remove_volumes(client, project, events).await?;
    }
    if let Some(which) = options.images {
        let images = containers
            .iter()
            .filter(|c| which == RemoveImages::All || c.summary.image == default_image(project, &c.service))
            .map(|c| c.summary.image.clone())
            .collect::<Vec<_>>();
        remove_images(client, images, events).await?;
    }
    Ok(())
}

fn resource(events: Events<'_>, kind: ResourceKind, name: &str, action: Action) {
    events(ComposeEvent::Resource { kind, name: name.to_owned(), action });
}

/// Running, paused or about to run again: there is something to stop.
fn is_live(status: ContainerStatus) -> bool {
    status.is_live() || status == ContainerStatus::Restarting
}

fn condition_name(condition: Condition) -> &'static str {
    match condition {
        Condition::Started => "service_started",
        Condition::Healthy => "service_healthy",
        Condition::CompletedSuccessfully => "service_completed_successfully",
    }
}

/// The containers labelled as `project`'s (all, or running ones).
async fn project_containers(client: &Client, project: &str, all: bool) -> Result<Vec<ServiceContainer>> {
    let containers = client.list_containers(all).await?;
    Ok(containers
        .into_iter()
        .filter(|c| c.labels.get(LABEL_PROJECT).is_some_and(|p| p == project))
        .map(service_container)
        .collect())
}

fn service_container(summary: ContainerSummary) -> ServiceContainer {
    let service = summary.labels.get(LABEL_SERVICE).cloned().unwrap_or_default();
    let number = summary.labels.get(LABEL_NUMBER).and_then(|n| n.parse().ok()).unwrap_or(0);
    ServiceContainer { service, number, summary }
}

/// A project's containers in the order to take them down: dependents
/// before what they depend on (by their [`LABEL_DEPENDS_ON`]), services
/// otherwise by name, a service's containers highest number first.
fn shutdown_order(containers: &[ServiceContainer]) -> Vec<&ServiceContainer> {
    let mut deps: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for c in containers {
        let entry = deps.entry(c.service.as_str()).or_default();
        if let Some(label) = c.summary.labels.get(LABEL_DEPENDS_ON) {
            entry.extend(label.split(',').filter_map(|d| d.split(':').next()).filter(|d| !d.is_empty()));
        }
    }
    let mut remaining: Vec<&str> = deps.keys().copied().collect();
    let mut order = Vec::new();
    while !remaining.is_empty() {
        // One that nothing left depends on; in a cycle, the first.
        let next = remaining
            .iter()
            .position(|s| !remaining.iter().any(|o| o != s && deps.get(o).is_some_and(|d| d.contains(s))))
            .unwrap_or(0);
        order.push(remaining.remove(next));
    }
    let mut sorted = Vec::with_capacity(containers.len());
    for service in order {
        let mut of_service: Vec<&ServiceContainer> = containers.iter().filter(|c| c.service == service).collect();
        of_service.sort_by_key(|c| std::cmp::Reverse(c.number));
        sorted.extend(of_service);
    }
    sorted
}

fn warn_orphans(orphans: &[&ServiceContainer], events: Events<'_>) {
    if orphans.is_empty() {
        return;
    }
    let names: Vec<&str> = orphans.iter().map(|c| c.summary.name.as_str()).collect();
    events(ComposeEvent::Warning(format!(
        "Found orphan containers ({}) for this project. If you removed or renamed this service in your compose file, \
         you can run this command with the --remove-orphans flag to clean it up.",
        names.join(", ")
    )));
}

async fn image_exists(client: &Client, image: &str) -> Result<bool> {
    match client.inspect_image(image).await {
        Ok(_) => Ok(true),
        Err(e) if e.is_not_found() => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// Starts a container that isn't running; one that is is reported
/// `Running`.
async fn ensure_started(client: &Client, c: &ContainerSummary, events: Events<'_>) -> Result<()> {
    if is_live(c.state.status) {
        resource(events, ResourceKind::Container, &c.name, Action::Running);
        return Ok(());
    }
    start(client, &c.id, &c.name, events).await
}

async fn start(client: &Client, id: &str, name: &str, events: Events<'_>) -> Result<()> {
    resource(events, ResourceKind::Container, name, Action::Starting);
    client.start(id).await?;
    resource(events, ResourceKind::Container, name, Action::Started);
    Ok(())
}

/// Stops a live container, then removes it (with its anonymous volumes if
/// `volumes`).
async fn stop_and_remove(
    client: &Client,
    c: &ContainerSummary,
    timeout: Option<u32>,
    volumes: bool,
    events: Events<'_>,
) -> Result<()> {
    if is_live(c.state.status) {
        resource(events, ResourceKind::Container, &c.name, Action::Stopping);
        ignore_gone(client.stop(&c.id, timeout).await)?;
        resource(events, ResourceKind::Container, &c.name, Action::Stopped);
    }
    resource(events, ResourceKind::Container, &c.name, Action::Removing);
    ignore_gone(client.remove_container_with(&c.id, &RemoveQuery { force: true, volumes }).await)?;
    resource(events, ResourceKind::Container, &c.name, Action::Removed);
    Ok(())
}

/// A container that is already gone is what was asked for (`--rm`, a
/// race with another client).
fn ignore_gone(result: rustlet_client::Result<()>) -> Result<()> {
    match result {
        Err(e) if e.is_not_found() => Ok(()),
        other => Ok(other?),
    }
}

/// The networks labelled as `project`'s (external ones never are). One
/// still in use (another project's container on it) stays, with a warning.
async fn remove_networks(client: &Client, project: &str, events: Events<'_>) -> Result<()> {
    for network in client.list_networks().await? {
        if network.labels.get(LABEL_PROJECT).is_none_or(|p| p != project) {
            continue;
        }
        resource(events, ResourceKind::Network, &network.name, Action::Removing);
        match client.remove_network(&network.id).await {
            Err(e) if e.kind() == Some(ErrorKind::Conflict) => {
                events(ComposeEvent::Warning(format!("network {} is still in use, so it stays: {e}", network.name)));
                continue;
            }
            Err(e) if !e.is_not_found() => return Err(e.into()),
            _ => {}
        }
        resource(events, ResourceKind::Network, &network.name, Action::Removed);
    }
    Ok(())
}

/// The volumes labelled as `project`'s (external ones never are).
async fn remove_volumes(client: &Client, project: &str, events: Events<'_>) -> Result<()> {
    for volume in client.list_volumes().await? {
        if volume.labels.get(LABEL_PROJECT).is_none_or(|p| p != project) {
            continue;
        }
        resource(events, ResourceKind::Volume, &volume.name, Action::Removing);
        match client.remove_volume(&volume.name, true).await {
            Err(e) if e.kind() == Some(ErrorKind::Conflict) => {
                events(ComposeEvent::Warning(format!("volume {} is still in use, so it stays: {e}", volume.name)));
                continue;
            }
            Err(e) => return Err(e.into()),
            Ok(()) => {}
        }
        resource(events, ResourceKind::Volume, &volume.name, Action::Removed);
    }
    Ok(())
}

/// `images` that exist, each once; one still in use stays, with a warning.
async fn remove_images(client: &Client, images: impl IntoIterator<Item = String>, events: Events<'_>) -> Result<()> {
    let mut seen = BTreeSet::new();
    for image in images {
        if !seen.insert(image.clone()) || !image_exists(client, &image).await? {
            continue;
        }
        resource(events, ResourceKind::Image, &image, Action::Removing);
        match client.remove_image(&image, false).await {
            Err(e) if e.kind() == Some(ErrorKind::Conflict) => {
                events(ComposeEvent::Warning(format!("image {image} is still in use, so it stays: {e}")));
                continue;
            }
            Err(e) if !e.is_not_found() => return Err(e.into()),
            _ => {}
        }
        resource(events, ResourceKind::Image, &image, Action::Removed);
    }
    Ok(())
}

fn is_broken_pipe(e: &ContextError) -> bool {
    matches!(e, ContextError::Io { source, .. } if source.kind() == std::io::ErrorKind::BrokenPipe)
}

/// A log entry's time as a key that sorts in time order: its date and
/// time to the second, and its fraction as nanoseconds (RFC 3339 may give
/// fewer digits, and `…:00.5Z` must come after `…:00.25Z`).
fn time_key(ts: &str) -> (&str, u32) {
    let ts = ts.trim_end_matches('Z');
    match ts.split_once('.') {
        Some((seconds, fraction)) => {
            let digits: String = fraction.chars().take_while(char::is_ascii_digit).take(9).collect();
            (seconds, format!("{digits:0<9}").parse().unwrap_or(0))
        }
        None => (ts, 0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn container(service: &str, number: u32, depends_on: &str) -> ServiceContainer {
        let mut labels = BTreeMap::new();
        labels.insert(LABEL_DEPENDS_ON.to_owned(), depends_on.to_owned());
        let summary = ContainerSummary { name: format!("p-{service}-{number}"), labels, ..ContainerSummary::default() };
        ServiceContainer { service: service.into(), number, summary }
    }

    #[test]
    fn without_the_file_dependents_still_go_down_first() {
        let containers = [
            container("db", 1, ""),
            container("web", 1, "api:service_started:true"),
            container("api", 1, "db:service_healthy:true,cache:service_started:false"),
            container("api", 2, "db:service_healthy:true,cache:service_started:false"),
            container("cache", 1, ""),
        ];
        let order: Vec<&str> = shutdown_order(&containers).iter().map(|c| c.summary.name.as_str()).collect();
        assert_eq!(order, ["p-web-1", "p-api-2", "p-api-1", "p-cache-1", "p-db-1"]);
        // A cycle doesn't stop it.
        let cycle = [container("a", 1, "b:service_started:true"), container("b", 1, "a:service_started:true")];
        assert_eq!(shutdown_order(&cycle).len(), 2);
    }

    #[test]
    fn log_times_sort_whatever_their_digits() {
        let mut times = [
            "2026-10-01T00:00:01Z",
            "2026-10-01T00:00:00.5Z",
            "2026-10-01T00:00:00.25Z",
            "2026-10-01T00:00:00.123456789Z",
        ];
        times.sort_by_key(|t| time_key(t));
        assert_eq!(
            times,
            [
                "2026-10-01T00:00:00.123456789Z",
                "2026-10-01T00:00:00.25Z",
                "2026-10-01T00:00:00.5Z",
                "2026-10-01T00:00:01Z"
            ]
        );
    }

    #[test]
    fn conditions_are_labelled_by_composes_names() {
        let names: Vec<&str> = [Condition::Started, Condition::Healthy, Condition::CompletedSuccessfully]
            .into_iter()
            .map(condition_name)
            .collect();
        assert_eq!(names, ["service_started", "service_healthy", "service_completed_successfully"]);
    }

    /// The desktop app runs these on Tauri's multithreaded runtime, from
    /// commands whose futures must be `Send` for any lifetime of their
    /// arguments: a compile-time check, so that this crate notices first.
    #[allow(dead_code)]
    fn futures_are_send(compose: &Compose, client: &Client) {
        fn send<T: Send>(_: T) {}
        let events: Events<'_> = &|_| {};
        send(compose.up(&UpOptions::default(), events));
        send(compose.down(&DownOptions::default(), events));
        send(compose.ps(true));
        send(compose.build(&[], false, events));
        send(compose.stop(&[], None, events));
        send(compose.start(&[], events));
        send(compose.logs(&[], &LogsQuery::default()));
        send(stacks(client));
        send(down_project(client, "p", &DownOptions::default(), events));
    }
}

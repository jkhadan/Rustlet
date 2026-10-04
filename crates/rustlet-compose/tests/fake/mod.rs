//! A rustletd in the test process: an axum router on a temporary Unix
//! socket that keeps containers, networks, volumes and images in memory,
//! with as much of the daemon's behaviour as compose relies on: unique
//! names; the image and networks a container needs, required at its create;
//! live containers, networks in use and volumes in use refused removal; a
//! healthcheck's progress and an exit played out as each container's
//! [`Script`] says, one step per inspection.
//!
//! Everything it does is written down in [`Daemon::calls`], by name, for
//! the tests to compare: `create shop-web-1`, `start shop-web-1`, …

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, MutexGuard};

use axum::Json;
use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use rustlet_client::Client;
use rustlet_spec::container::{
    ContainerConfig, ContainerInspect, ContainerState, ContainerStatus, ContainerSummary, CreateResponse, Health,
    HealthStatus, ListQuery, RemoveQuery, StopQuery,
};
use rustlet_spec::image::{
    ImageDeleteQuery, ImageDeleteResponse, ImageInspect, ImageQuery, ImageSummary, PullEvent, PullPolicy, PullQuery,
};
use rustlet_spec::logs::{LogEntry, LogsQuery};
use rustlet_spec::network::{
    EndpointSettings, Network, NetworkConnect, NetworkCreate, NetworkCreateResponse, NetworkSettings,
};
use rustlet_spec::volume::{MountType, Volume, VolumeCreate, VolumeRemoveQuery};
use rustlet_spec::{ErrorBody, ErrorKind, NDJSON, routes};
use tokio::net::UnixListener;

/// What a container does once started, one step per inspection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Script {
    /// Its healthcheck says healthy at the `n`th inspection.
    Healthy(u32),
    /// Its healthcheck says unhealthy at the `n`th inspection.
    Unhealthy(u32),
    /// It exits with the code at the `n`th inspection.
    Exits(i32, u32),
}

/// A container, as the fake keeps it.
#[derive(Debug, Clone)]
pub struct Container {
    pub id: String,
    pub name: String,
    pub config: ContainerConfig,
    pub image_id: String,
    pub state: ContainerState,
    /// Its networks in order, each with what it was given there.
    pub endpoints: Vec<EndpointSettings>,
    /// Inspections since its last start.
    pub inspections: u32,
}

/// The fake's state.
#[derive(Debug, Default)]
pub struct Daemon {
    pub containers: Vec<Container>,
    pub networks: Vec<Network>,
    pub volumes: Vec<Volume>,
    /// Image name → id.
    pub images: BTreeMap<String, String>,
    /// Images whose config has a `HEALTHCHECK`.
    pub image_healthchecks: BTreeSet<String>,
    /// By container name.
    pub scripts: BTreeMap<String, Script>,
    /// By container name: what `logs` sends.
    pub logs: BTreeMap<String, Vec<LogEntry>>,
    /// What it did, in order.
    pub calls: Vec<String>,
    serial: u64,
}

pub type Shared = Arc<Mutex<Daemon>>;

impl Daemon {
    fn next_id(&mut self) -> String {
        self.serial += 1;
        format!("{:064x}", self.serial)
    }

    pub fn add_image(&mut self, name: &str) {
        let id = format!("sha256:{}", self.next_id());
        self.images.insert(name.to_owned(), id);
    }

    /// A container made by hand, as another client would (no labels).
    pub fn add_container(&mut self, name: &str, image: &str) {
        let id = self.next_id();
        let config = ContainerConfig { image: image.into(), name: Some(name.into()), ..ContainerConfig::default() };
        let state = ContainerState { status: ContainerStatus::Running, ..ContainerState::default() };
        let image_id = self.images.get(image).cloned().unwrap_or_default();
        self.containers.push(Container {
            id,
            name: name.into(),
            config,
            image_id,
            state,
            endpoints: Vec::new(),
            inspections: 0,
        });
    }

    /// A network or a volume made by hand (no labels).
    pub fn add_network(&mut self, name: &str) {
        let id = self.next_id();
        self.networks.push(Network { id, name: name.into(), driver: "bridge".into(), ..Network::default() });
    }

    pub fn add_volume(&mut self, name: &str) {
        self.volumes.push(Volume { name: name.into(), driver: "local".into(), ..Volume::default() });
    }

    pub fn container(&self, name: &str) -> &Container {
        self.containers.iter().find(|c| c.name == name).unwrap_or_else(|| panic!("no container {name}"))
    }

    pub fn has_container(&self, name: &str) -> bool {
        self.containers.iter().any(|c| c.name == name)
    }

    pub fn network(&self, name: &str) -> &Network {
        self.networks.iter().find(|n| n.name == name).unwrap_or_else(|| panic!("no network {name}"))
    }

    pub fn volume(&self, name: &str) -> Option<&Volume> {
        self.volumes.iter().find(|v| v.name == name)
    }

    fn find(&self, id: &str) -> Option<usize> {
        self.containers.iter().position(|c| c.id == id || c.name == id)
    }

    /// One step of container `i`'s script, if it runs.
    fn play(&mut self, i: usize) {
        let script = self.scripts.get(&self.containers[i].name).copied();
        let c = &mut self.containers[i];
        let Some(script) = script.filter(|_| c.state.status == ContainerStatus::Running) else { return };
        c.inspections += 1;
        let health = |status| Some(Health { status, ..Health::default() });
        match script {
            Script::Healthy(n) if c.inspections == n => {
                c.state.health = health(HealthStatus::Healthy);
                self.calls.push(format!("healthy {}", c.name));
            }
            Script::Unhealthy(n) if c.inspections == n => {
                c.state.health = health(HealthStatus::Unhealthy);
                self.calls.push(format!("unhealthy {}", c.name));
            }
            Script::Exits(code, n) if c.inspections == n => {
                c.state.status = ContainerStatus::Exited;
                c.state.exit_code = Some(code);
                c.state.pid = None;
                self.calls.push(format!("exited {} {code}", c.name));
            }
            _ => {}
        }
    }
}

/// A running fake daemon, and a client for it.
pub struct Fake {
    pub daemon: Shared,
    pub client: Client,
    _dir: tempfile::TempDir,
}

impl Fake {
    /// A daemon with its default network `bridge` and the images `images`.
    pub fn start(images: &[&str]) -> Fake {
        let mut daemon = Daemon::default();
        daemon.add_network("bridge");
        for image in images {
            daemon.add_image(image);
        }
        let daemon = Arc::new(Mutex::new(daemon));
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("rustlet.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let app = router(daemon.clone());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Fake { daemon, client: Client::new(socket), _dir: dir }
    }

    pub fn lock(&self) -> MutexGuard<'_, Daemon> {
        self.daemon.lock().unwrap()
    }

    /// What it did since the last call.
    pub fn calls(&self) -> Vec<String> {
        std::mem::take(&mut self.lock().calls)
    }
}

fn router(daemon: Shared) -> Router {
    use routes::pattern as p;
    Router::new()
        .route(p::CONTAINERS, get(list_containers).post(create_container))
        .route(p::CONTAINER, get(inspect_container).delete(remove_container))
        .route(&p::container_action("start"), post(start))
        .route(&p::container_action("stop"), post(stop))
        .route(&p::container_action("logs"), get(logs))
        .route(p::NETWORKS, get(list_networks).post(create_network))
        .route(p::NETWORK, delete(remove_network))
        .route(p::NETWORK_CONNECT, post(connect_network))
        .route(p::VOLUMES, get(list_volumes).post(create_volume))
        .route(p::VOLUME, delete(remove_volume))
        .route(p::IMAGE_INSPECT, get(inspect_image))
        .route(p::IMAGE_PULL, post(pull))
        .route(p::IMAGES, delete(remove_image))
        .with_state(daemon)
}

fn error(kind: ErrorKind, message: impl Into<String>) -> Response {
    let status = StatusCode::from_u16(kind.status()).unwrap();
    (status, Json(ErrorBody::new(kind, message))).into_response()
}

fn ndjson<T: serde::Serialize>(items: &[T]) -> Response {
    let body: String = items.iter().map(|item| serde_json::to_string(item).unwrap() + "\n").collect();
    ([(header::CONTENT_TYPE, NDJSON)], body).into_response()
}

fn summary(c: &Container) -> ContainerSummary {
    ContainerSummary {
        id: c.id.clone(),
        name: c.name.clone(),
        image: c.config.image.clone(),
        image_id: c.image_id.clone(),
        command: c.config.cmd.clone(),
        created: "2026-10-04T00:00:00Z".into(),
        state: c.state.clone(),
        labels: c.config.labels.clone(),
        ports: Vec::new(),
        network_mode: c.config.network.clone(),
    }
}

async fn list_containers(State(d): State<Shared>, Query(q): Query<ListQuery>) -> Json<Vec<ContainerSummary>> {
    let d = d.lock().unwrap();
    Json(d.containers.iter().filter(|c| q.all || c.state.status == ContainerStatus::Running).map(summary).collect())
}

async fn create_container(State(d): State<Shared>, Json(config): Json<ContainerConfig>) -> Response {
    let mut d = d.lock().unwrap();
    let name = config.name.clone().unwrap_or_else(|| "unnamed".into());
    if d.has_container(&name) {
        return error(ErrorKind::Conflict, format!("the name {name} is in use"));
    }
    let Some(image_id) = d.images.get(&config.image).cloned() else {
        return error(ErrorKind::NoSuchImage, format!("no such image: {}", config.image));
    };
    let first = config.network.network_name().map(str::to_owned);
    let mut endpoints = Vec::new();
    for (i, network) in first.iter().chain(&config.extra_networks).enumerate() {
        if !d.networks.iter().any(|n| &n.name == network) {
            return error(ErrorKind::NoSuchNetwork, format!("no such network: {network}"));
        }
        let mut endpoint = EndpointSettings { network: network.clone(), ..EndpointSettings::default() };
        if i == 0 {
            endpoint.aliases = config.network_aliases.clone();
            endpoint.ipv4_requested = config.ip;
            endpoint.ipv6_requested = config.ip6;
        }
        endpoints.push(endpoint);
    }
    // Named volumes that don't exist are made, as the daemon does.
    for m in &config.mounts {
        if let (MountType::Volume, Some(source)) = (m.kind, &m.source)
            && d.volume(source).is_none()
        {
            d.add_volume(source);
        }
    }
    let id = d.next_id();
    d.calls.push(format!("create {name}"));
    let c = Container {
        id: id.clone(),
        name: name.clone(),
        config,
        image_id,
        state: ContainerState::default(),
        endpoints,
        inspections: 0,
    };
    d.containers.push(c);
    (StatusCode::CREATED, Json(CreateResponse { id, name, warnings: Vec::new() })).into_response()
}

async fn inspect_container(State(d): State<Shared>, Path(id): Path<String>) -> Response {
    let mut d = d.lock().unwrap();
    let Some(i) = d.find(&id) else { return error(ErrorKind::NoSuchContainer, format!("no such container: {id}")) };
    d.play(i);
    let c = &d.containers[i];
    let network =
        NetworkSettings { mode: c.config.network.clone(), networks: c.endpoints.clone(), ..NetworkSettings::default() };
    Json(ContainerInspect {
        id: c.id.clone(),
        name: c.name.clone(),
        image: c.config.image.clone(),
        image_id: c.image_id.clone(),
        config: c.config.clone(),
        state: c.state.clone(),
        network,
        ..ContainerInspect::default()
    })
    .into_response()
}

async fn start(State(d): State<Shared>, Path(id): Path<String>) -> Response {
    let mut d = d.lock().unwrap();
    let Some(i) = d.find(&id) else { return error(ErrorKind::NoSuchContainer, format!("no such container: {id}")) };
    let c = &mut d.containers[i];
    if c.state.status != ContainerStatus::Running {
        // A healthcheck of its own reports `starting` at once; the image's
        // only once a check has run, as a daemon may.
        let health =
            c.config.healthcheck.as_ref().filter(|h| !h.test.is_empty() && !h.is_none()).map(|_| Health::default());
        c.state = ContainerState {
            status: ContainerStatus::Running,
            pid: Some(4000 + i as i32),
            started_at: Some("2026-10-04T00:00:00Z".into()),
            health,
            ..ContainerState::default()
        };
        c.inspections = 0;
    }
    let call = format!("start {}", c.name);
    d.calls.push(call);
    StatusCode::NO_CONTENT.into_response()
}

async fn stop(State(d): State<Shared>, Path(id): Path<String>, Query(q): Query<StopQuery>) -> Response {
    let mut d = d.lock().unwrap();
    let Some(i) = d.find(&id) else { return error(ErrorKind::NoSuchContainer, format!("no such container: {id}")) };
    let c = &mut d.containers[i];
    if c.state.status == ContainerStatus::Running {
        c.state.status = ContainerStatus::Exited;
        c.state.exit_code = Some(143);
        c.state.pid = None;
    }
    let call = match q.timeout {
        Some(t) => format!("stop {} timeout={t}", c.name),
        None => format!("stop {}", c.name),
    };
    d.calls.push(call);
    StatusCode::NO_CONTENT.into_response()
}

async fn remove_container(State(d): State<Shared>, Path(id): Path<String>, Query(q): Query<RemoveQuery>) -> Response {
    let mut d = d.lock().unwrap();
    let Some(i) = d.find(&id) else { return error(ErrorKind::NoSuchContainer, format!("no such container: {id}")) };
    if d.containers[i].state.status == ContainerStatus::Running && !q.force {
        return error(ErrorKind::Conflict, "the container is running: stop it first, or force");
    }
    let c = d.containers.remove(i);
    d.calls.push(format!("rm {}{}", c.name, if q.volumes { " -v" } else { "" }));
    StatusCode::NO_CONTENT.into_response()
}

async fn logs(State(d): State<Shared>, Path(id): Path<String>, Query(_): Query<LogsQuery>) -> Response {
    let d = d.lock().unwrap();
    let Some(i) = d.find(&id) else { return error(ErrorKind::NoSuchContainer, format!("no such container: {id}")) };
    ndjson(&d.logs.get(&d.containers[i].name).cloned().unwrap_or_default())
}

async fn list_networks(State(d): State<Shared>) -> Json<Vec<Network>> {
    Json(d.lock().unwrap().networks.clone())
}

async fn create_network(State(d): State<Shared>, Json(create): Json<NetworkCreate>) -> Response {
    let mut d = d.lock().unwrap();
    if d.networks.iter().any(|n| n.name == create.name) {
        return error(ErrorKind::Conflict, format!("network {} exists", create.name));
    }
    let id = d.next_id();
    d.calls.push(format!("network create {}", create.name));
    d.networks.push(Network {
        id: id.clone(),
        name: create.name.clone(),
        driver: "bridge".into(),
        subnet: create.subnet.unwrap_or_default(),
        ipv6: create.ipv6,
        subnet6: create.subnet6,
        internal: create.internal,
        dns: true,
        labels: create.labels,
        ..Network::default()
    });
    (StatusCode::CREATED, Json(NetworkCreateResponse { id, name: create.name })).into_response()
}

async fn remove_network(State(d): State<Shared>, Path(id): Path<String>) -> Response {
    let mut d = d.lock().unwrap();
    let Some(i) = d.networks.iter().position(|n| n.id == id || n.name == id) else {
        return error(ErrorKind::NoSuchNetwork, format!("no such network: {id}"));
    };
    let name = d.networks[i].name.clone();
    if d.containers.iter().any(|c| c.endpoints.iter().any(|e| e.network == name)) {
        return error(ErrorKind::Conflict, format!("network {name} has containers"));
    }
    d.networks.remove(i);
    d.calls.push(format!("network rm {name}"));
    StatusCode::NO_CONTENT.into_response()
}

async fn connect_network(
    State(d): State<Shared>,
    Path(id): Path<String>,
    Json(body): Json<NetworkConnect>,
) -> Response {
    let mut d = d.lock().unwrap();
    let Some(network) = d.networks.iter().find(|n| n.id == id || n.name == id).map(|n| n.name.clone()) else {
        return error(ErrorKind::NoSuchNetwork, format!("no such network: {id}"));
    };
    let Some(i) = d.find(&body.container) else {
        return error(ErrorKind::NoSuchContainer, format!("no such container: {}", body.container));
    };
    let mut call = format!("connect {network} {}", d.containers[i].name);
    if !body.aliases.is_empty() {
        call += &format!(" aliases={}", body.aliases.join(","));
    }
    if let Some(ip) = body.ipv4_address {
        call += &format!(" ip={ip}");
    }
    d.containers[i].endpoints.push(EndpointSettings {
        network,
        aliases: body.aliases,
        ipv4_requested: body.ipv4_address,
        ipv6_requested: body.ipv6_address,
        ..EndpointSettings::default()
    });
    d.calls.push(call);
    StatusCode::NO_CONTENT.into_response()
}

async fn list_volumes(State(d): State<Shared>) -> Json<Vec<Volume>> {
    Json(d.lock().unwrap().volumes.clone())
}

async fn create_volume(State(d): State<Shared>, Json(create): Json<VolumeCreate>) -> Response {
    let mut d = d.lock().unwrap();
    let name = create.name.unwrap_or_else(|| "anonymous".into());
    if d.volume(&name).is_some() {
        return error(ErrorKind::Conflict, format!("volume {name} exists"));
    }
    d.calls.push(format!("volume create {name}"));
    let volume = Volume { name, driver: "local".into(), labels: create.labels, ..Volume::default() };
    d.volumes.push(volume.clone());
    (StatusCode::CREATED, Json(volume)).into_response()
}

async fn remove_volume(
    State(d): State<Shared>,
    Path(name): Path<String>,
    Query(q): Query<VolumeRemoveQuery>,
) -> Response {
    let mut d = d.lock().unwrap();
    let Some(i) = d.volumes.iter().position(|v| v.name == name) else {
        return match q.force {
            true => StatusCode::NO_CONTENT.into_response(),
            false => error(ErrorKind::NoSuchVolume, format!("no such volume: {name}")),
        };
    };
    if d.containers.iter().any(|c| c.config.mounts.iter().any(|m| m.source.as_deref() == Some(name.as_str()))) {
        return error(ErrorKind::Conflict, format!("volume {name} is in use"));
    }
    d.volumes.remove(i);
    d.calls.push(format!("volume rm {name}"));
    StatusCode::NO_CONTENT.into_response()
}

async fn inspect_image(State(d): State<Shared>, Query(q): Query<ImageQuery>) -> Response {
    let d = d.lock().unwrap();
    let Some(id) = d.images.get(&q.name) else {
        return error(ErrorKind::NoSuchImage, format!("no such image: {}", q.name));
    };
    let config = match d.image_healthchecks.contains(&q.name) {
        true => serde_json::json!({"config": {"Healthcheck": {"Test": ["CMD-SHELL", "true"]}}}),
        false => serde_json::json!({"config": {}}),
    };
    let summary = ImageSummary { id: id.clone(), names: vec![q.name.clone()], ..ImageSummary::default() };
    Json(ImageInspect { summary, config, ..ImageInspect::default() }).into_response()
}

async fn pull(State(d): State<Shared>, Query(q): Query<PullQuery>) -> Response {
    let mut d = d.lock().unwrap();
    let policy = match q.policy {
        PullPolicy::Missing => "missing",
        PullPolicy::Always => "always",
        PullPolicy::Never => "never",
    };
    d.calls.push(format!("pull {} {policy}", q.reference));
    let resolving = PullEvent::Resolving { reference: q.reference.clone() };
    if q.reference.starts_with("unpullable") {
        let message = format!("{}: not found in the registry", q.reference);
        return ndjson(&[resolving, PullEvent::Error { message }]);
    }
    if !d.images.contains_key(&q.reference) {
        d.add_image(&q.reference);
    }
    let manifest = d.images[&q.reference].clone();
    ndjson(&[resolving, PullEvent::Ready { reference: q.reference, manifest }])
}

async fn remove_image(State(d): State<Shared>, Query(q): Query<ImageDeleteQuery>) -> Response {
    let mut d = d.lock().unwrap();
    if d.images.remove(&q.name).is_none() {
        return error(ErrorKind::NoSuchImage, format!("no such image: {}", q.name));
    }
    d.calls.push(format!("rmi {}", q.name));
    Json(ImageDeleteResponse { untagged: vec![q.name], deleted: Vec::new() }).into_response()
}

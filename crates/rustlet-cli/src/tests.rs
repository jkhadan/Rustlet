//! Whole commands, run in-process as `main` runs them (parsed command
//! line, [`run_cli`], exit code), against a mock daemon: an axum server on
//! a temporary Unix socket that records the calls it gets and answers like
//! rustletd would.

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use clap::Parser;
use futures::StreamExt;
use rustlet_spec::container::{
    AttachQuery, ContainerConfig, ContainerInspect, ContainerState, ContainerStatus, ContainerSummary, CreateResponse,
    KillQuery, RemoveQuery, StopQuery, WaitQuery, WaitResponse,
};
use rustlet_spec::exec::{ExecConfig, ExecCreated};
use rustlet_spec::image::{BlobKind, ImageQuery, ImageSummary, PullEvent, PullQuery};
use rustlet_spec::logs::{LogEntry, LogStream, LogsQuery};
use rustlet_spec::network::{
    Network, NetworkCreate, NetworkCreateResponse, NetworkMode, NetworkSettings, PortMapping, Protocol, PruneResponse,
    PublishedPort,
};
use rustlet_spec::routes::pattern;
use rustlet_spec::stats::{StatsQuery, StatsSample};
use rustlet_spec::stream::{self, Control};
use rustlet_spec::system::{Info, Version};
use rustlet_spec::volume::{MountType, Volume, VolumeCreate, VolumePruneQuery, VolumeRemoveQuery};
use rustlet_spec::{ErrorBody, ErrorKind};
use tokio::net::UnixListener;
use tokio::sync::Notify;

use crate::console::testing::{Buffer, console};
use crate::{Cli, Command, run_cli};

const ID: &str = "4f1d2c3b4a5968778695a4b3c2d1e0f0011223344556677889900aabbccddee";
const LAYER: &str = "sha256:9824c27679d3b27c0e1cb00b2b5cdbc2d1ae6e8f00aabbccddeeff0011223344";

fn parse(args: &[&str]) -> Cli {
    Cli::try_parse_from(std::iter::once("rustlet").chain(args.iter().copied())).unwrap()
}

#[test]
fn the_command_after_the_image_is_taken_verbatim() {
    let Command::Run(run) = parse(&["run", "-it", "--rm", "alpine", "sh", "-c", "echo hi"]).command else { panic!() };
    assert!(run.flags.interactive && run.flags.tty && run.flags.rm && run.sig_proxy);
    assert_eq!(run.args, ["alpine", "sh", "-c", "echo hi"]);
    // After the image, flags are the command's, even ones `run` knows.
    let Command::Run(run) = parse(&["run", "alpine", "ls", "-la", "--rm", "-it"]).command else { panic!() };
    assert!(!run.flags.rm && !run.flags.tty);
    assert_eq!(run.args, ["alpine", "ls", "-la", "--rm", "-it"]);
    let Command::Run(run) = parse(&["run", "--sig-proxy=false", "-e", "A=1", "alpine", "--help"]).command else {
        panic!()
    };
    assert!(!run.sig_proxy);
    assert_eq!(run.flags.env, ["A=1"]);
    assert_eq!(run.args, ["alpine", "--help"]);
    let Command::Exec(exec) = parse(&["exec", "-it", "-u", "0", "web", "sh", "-c", "ls -l"]).command else { panic!() };
    assert!(exec.interactive && exec.tty);
    assert_eq!(exec.args, ["web", "sh", "-c", "ls -l"]);
    assert!(Cli::try_parse_from(["rustlet", "run"]).is_err());
}

#[test]
fn host_and_debug_go_anywhere() {
    let cli = parse(&["ps", "-a", "-H", "unix:///tmp/r.sock", "--debug"]);
    assert_eq!(cli.host.as_deref(), Some("unix:///tmp/r.sock"));
    assert!(cli.debug);
    let Command::Stop { timeout, containers } = parse(&["stop", "-t", "3", "a", "b"]).command else { panic!() };
    assert_eq!((timeout, containers.as_slice()), (Some(3), &["a".to_owned(), "b".to_owned()][..]));
    let Command::Stop { timeout, .. } = parse(&["stop", "--time", "4", "a"]).command else { panic!() };
    assert_eq!(timeout, Some(4));
    let Command::Kill { signal, .. } = parse(&["kill", "a"]).command else { panic!() };
    assert_eq!(signal, "KILL");
}

/// The mock daemon: what it was asked, and how it should answer.
#[derive(Default)]
struct Daemon {
    calls: Mutex<Vec<String>>,
    /// The first create answers `no_such_image`.
    image_missing: AtomicBool,
    /// Start answers this error.
    start_fails: Mutex<Option<ErrorBody>>,
    /// Attach answers an error instead of upgrading.
    attach_fails: AtomicBool,
    started: Notify,
    configs: Mutex<Vec<ContainerConfig>>,
    execs: Mutex<Vec<ExecConfig>>,
    /// What came in on stdin.
    stdin: Mutex<Vec<u8>>,
    /// The options of each `rm`.
    removals: Mutex<Vec<RemoveQuery>>,
    network_creates: Mutex<Vec<NetworkCreate>>,
    volume_creates: Mutex<Vec<VolumeCreate>>,
    /// A prune has removed what there was.
    networks_pruned: AtomicBool,
    volumes_pruned: AtomicBool,
}

type Shared = State<Arc<Daemon>>;

impl Daemon {
    fn call(&self, call: impl Into<String>) {
        self.calls.lock().unwrap().push(call.into());
    }

    fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
}

fn error(kind: ErrorKind, message: &str) -> Response {
    (StatusCode::from_u16(kind.status()).unwrap(), Json(ErrorBody::new(kind, message))).into_response()
}

fn ndjson<T: serde::Serialize>(items: &[T]) -> Response {
    let body: String = items.iter().map(|i| serde_json::to_string(i).unwrap() + "\n").collect();
    ([(header::CONTENT_TYPE, rustlet_spec::NDJSON)], Body::from(body)).into_response()
}

async fn create(State(d): Shared, Json(config): Json<ContainerConfig>) -> Response {
    d.call(format!("create {}", config.image));
    d.configs.lock().unwrap().push(config);
    if d.image_missing.swap(false, Ordering::SeqCst) {
        return error(ErrorKind::NoSuchImage, "no such image: alpine");
    }
    let created = CreateResponse { id: ID.into(), name: "brave_turing".into(), warnings: vec![] };
    (StatusCode::CREATED, Json(created)).into_response()
}

async fn pull(State(d): Shared, Query(q): Query<PullQuery>) -> Response {
    d.call(format!("pull {} {:?}", q.reference, q.policy));
    let reference = "docker.io/library/alpine:latest".to_owned();
    ndjson(&[
        PullEvent::Resolving { reference: reference.clone() },
        PullEvent::Resolved {
            reference: reference.clone(),
            manifest: "sha256:m".into(),
            repo_digest: "sha256:r".into(),
            platform: "linux/amd64".into(),
            layers: 1,
            size: 3_000_000,
        },
        PullEvent::Downloading { kind: BlobKind::Layer, digest: LAYER.into(), current: 0, total: 3_000_000 },
        PullEvent::Downloaded { kind: BlobKind::Layer, digest: LAYER.into(), size: 3_000_000 },
        PullEvent::Done { reference: reference.clone(), manifest: "sha256:m".into() },
        PullEvent::Unpacking { chain_id: "sha256:c".into(), blob: LAYER.into(), size: 3_000_000 },
        PullEvent::Unpacked {
            chain_id: "sha256:c".into(),
            entries: 1,
            bytes: 1,
            whiteouts: 0,
            opaque_dirs: 0,
            skipped_devices: 0,
        },
        PullEvent::Ready { reference, manifest: "sha256:m".into() },
    ])
}

async fn attach(State(d): Shared, Query(q): Query<AttachQuery>, ws: WebSocketUpgrade) -> Response {
    d.call(format!("attach stdin={}", q.stdin));
    if d.attach_fails.load(Ordering::SeqCst) {
        return error(ErrorKind::Internal, "attach failed");
    }
    ws.on_upgrade(move |socket| container_session(socket, d, q.stdin))
}

/// A container that prints once started; with stdin, it first echoes its
/// input until the input ends. A client that hangs up (detaches) ends it
/// early.
async fn container_session(mut socket: WebSocket, d: Arc<Daemon>, stdin: bool) {
    d.started.notified().await;
    let send = |id, data: &[u8]| Message::Binary(stream::data_message(id, data).into());
    if stdin {
        loop {
            match socket.recv().await {
                Some(Ok(Message::Binary(b))) => {
                    let (id, data) = stream::parse_data_message(&b).unwrap();
                    assert_eq!(id, stream::STDIN);
                    d.stdin.lock().unwrap().extend_from_slice(data);
                    socket.send(send(stream::STDOUT, data)).await.unwrap();
                }
                Some(Ok(Message::Text(t))) => match serde_json::from_str(&t).unwrap() {
                    Control::StdinEof => break,
                    Control::Resize { rows, cols } => d.call(format!("resize {rows}x{cols}")),
                    other => panic!("{other:?}"),
                },
                Some(Ok(Message::Close(_)) | Err(_)) | None => {
                    d.call("hangup");
                    return;
                }
                Some(Ok(_)) => {}
            }
        }
    }
    socket.send(send(stream::STDOUT, b"hello\n")).await.unwrap();
    socket.send(send(stream::STDERR, b"oops\n")).await.unwrap();
    let exit = serde_json::to_string(&Control::Exit { code: 3, oom_killed: false }).unwrap();
    socket.send(Message::Text(exit.into())).await.unwrap();
}

async fn start(State(d): Shared, Path(id): Path<String>) -> Response {
    d.call(format!("start {}", rustlet_spec::short_id(&id)));
    if let Some(e) = d.start_fails.lock().unwrap().take() {
        return error(e.kind, &e.message);
    }
    d.started.notify_one();
    StatusCode::NO_CONTENT.into_response()
}

async fn wait(State(d): Shared, Query(q): Query<WaitQuery>) -> Json<WaitResponse> {
    d.call(format!("wait {:?}", q.condition));
    Json(WaitResponse { status_code: 3, ..WaitResponse::default() })
}

async fn remove(State(d): Shared, Path(id): Path<String>, Query(q): Query<RemoveQuery>) -> StatusCode {
    d.call(format!("rm {}", rustlet_spec::short_id(&id)));
    d.removals.lock().unwrap().push(q);
    StatusCode::NO_CONTENT
}

fn published(host_ip: [u8; 4], host_port: u16, container_port: u16, protocol: Protocol) -> PublishedPort {
    PublishedPort { host_ip: Ipv4Addr::from(host_ip), host_port, container_port, protocol }
}

/// `web`, with four published ports (out of order); nothing else exists.
async fn inspect_container(State(d): Shared, Path(id): Path<String>) -> Response {
    d.call(format!("inspect container {id}"));
    if id != "web" {
        return error(ErrorKind::NoSuchContainer, &format!("no such container: {id}"));
    }
    let ports = vec![
        published([127, 0, 0, 1], 8443, 443, Protocol::Tcp),
        published([0, 0, 0, 0], 8080, 80, Protocol::Tcp),
        published([0, 0, 0, 0], 5353, 53, Protocol::Udp),
        published([127, 0, 0, 1], 9090, 80, Protocol::Tcp),
    ];
    let network = NetworkSettings { ports, ..NetworkSettings::default() };
    Json(ContainerInspect { id: "b".repeat(64), name: id, network, ..ContainerInspect::default() }).into_response()
}

/// No image is there.
async fn inspect_image(State(d): Shared, Query(q): Query<ImageQuery>) -> Response {
    d.call(format!("inspect image {}", q.name));
    error(ErrorKind::NoSuchImage, &format!("no such image: {}", q.name))
}

async fn stop(State(d): Shared, Path(id): Path<String>, Query(q): Query<StopQuery>) -> Response {
    d.call(format!("stop {id} {:?}", q.timeout));
    if id == "missing" {
        return error(ErrorKind::NoSuchContainer, "no such container: missing");
    }
    StatusCode::NO_CONTENT.into_response()
}

async fn kill(State(d): Shared, Path(id): Path<String>, Query(q): Query<KillQuery>) -> StatusCode {
    d.call(format!("kill {id} {:?}", q.signal));
    StatusCode::NO_CONTENT
}

async fn list() -> Json<Vec<ContainerSummary>> {
    let ago = |minutes| (chrono::Utc::now() - chrono::Duration::minutes(minutes)).to_rfc3339();
    Json(vec![
        ContainerSummary {
            id: "a".repeat(64),
            name: "old".into(),
            image: "alpine".into(),
            command: vec!["sleep".into(), "1000".into()],
            created: ago(120),
            state: ContainerState {
                status: ContainerStatus::Exited,
                exit_code: Some(0),
                finished_at: Some(ago(3)),
                ..ContainerState::default()
            },
            ..ContainerSummary::default()
        },
        ContainerSummary {
            id: "b".repeat(64),
            name: "web".into(),
            image: "nginx:1.27".into(),
            command: vec!["/docker-entrypoint.sh".into(), "nginx".into(), "-g".into(), "daemon off;".into()],
            created: ago(10),
            state: ContainerState {
                status: ContainerStatus::Running,
                started_at: Some(ago(5)),
                ..ContainerState::default()
            },
            ports: vec![
                published([127, 0, 0, 1], 8443, 443, Protocol::Tcp),
                published([0, 0, 0, 0], 8080, 80, Protocol::Tcp),
            ],
            ..ContainerSummary::default()
        },
    ])
}

async fn logs(Query(q): Query<LogsQuery>) -> Response {
    assert_eq!(q.tail, Some(2));
    let entry = |ts: &str, stream, log: &str| LogEntry { ts: ts.into(), stream, log: log.into() };
    ndjson(&[
        entry("2026-10-01T12:00:00.000000001Z", LogStream::Stdout, "out\n"),
        entry("2026-10-01T12:00:00.000000002Z", LogStream::Stderr, "err\n"),
    ])
}

async fn exec_create(State(d): Shared, Json(config): Json<ExecConfig>) -> Response {
    d.call("exec create");
    d.execs.lock().unwrap().push(config);
    (StatusCode::CREATED, Json(ExecCreated { id: "e1".into() })).into_response()
}

async fn exec_start(State(d): Shared, ws: WebSocketUpgrade) -> Response {
    d.call("exec start");
    let missing = d.execs.lock().unwrap().last().is_some_and(|e| e.cmd[0] == "nope");
    if missing {
        return ws.on_upgrade(|mut socket| async move {
            let error =
                Control::Error { message: "exec: \"nope\": not found".into(), kind: ErrorKind::CommandNotFound };
            socket.send(Message::Text(serde_json::to_string(&error).unwrap().into())).await.unwrap();
        });
    }
    ws.on_upgrade(|mut socket| async move {
        socket.send(Message::Binary(stream::data_message(stream::STDOUT, b"in exec\n").into())).await.unwrap();
        let exit = serde_json::to_string(&Control::Exit { code: 5, oom_killed: false }).unwrap();
        socket.send(Message::Text(exit.into())).await.unwrap();
    })
}

async fn exec_start_detached(State(d): Shared) -> Json<rustlet_spec::exec::ExecStarted> {
    d.call("exec start -d");
    Json(rustlet_spec::exec::ExecStarted { pid: 42 })
}

async fn info() -> Json<Info> {
    Json(Info { memory: 2 << 30, networks: 4, volumes: 4, ..Info::default() })
}

async fn version() -> Json<Version> {
    Json(Version { version: "0.1.0".into(), api_version: "v1".into(), ..Version::default() })
}

/// The mock's networks, in no particular order; ids `bbbb…` to `eeee…`.
fn networks() -> Vec<Network> {
    let network = |id: &str, name: &str, subnet: &str| Network {
        id: id.repeat(64),
        name: name.into(),
        driver: "bridge".into(),
        subnet: subnet.into(),
        ..Network::default()
    };
    vec![
        network("b", "bridge", "10.89.0.0/24"),
        network("d", "net10", "10.89.10.0/24"),
        network("c", "backend", "10.89.1.0/24"),
        network("e", "net2", "10.89.2.0/24"),
    ]
}

/// A network by name or id prefix, as the daemon finds them.
fn find_network(id: &str) -> Option<Network> {
    networks().into_iter().find(|n| n.name == id || n.id.starts_with(id))
}

async fn network_list() -> Json<Vec<Network>> {
    Json(networks())
}

async fn network_create(State(d): Shared, Json(config): Json<NetworkCreate>) -> Response {
    d.network_creates.lock().unwrap().push(config.clone());
    let created = NetworkCreateResponse { id: "f".repeat(64), name: config.name };
    (StatusCode::CREATED, Json(created)).into_response()
}

async fn network_inspect(State(d): Shared, Path(id): Path<String>) -> Response {
    d.call(format!("inspect network {id}"));
    match find_network(&id) {
        Some(network) => Json(network).into_response(),
        None => error(ErrorKind::NoSuchNetwork, &format!("no such network: {id}")),
    }
}

async fn network_remove(State(d): Shared, Path(id): Path<String>) -> Response {
    d.call(format!("network rm {id}"));
    match find_network(&id) {
        Some(_) => StatusCode::NO_CONTENT.into_response(),
        None => error(ErrorKind::NoSuchNetwork, &format!("no such network: {id}")),
    }
}

/// The first prune removes two networks; the next finds nothing.
async fn network_prune(State(d): Shared) -> Json<PruneResponse> {
    d.call("network prune");
    let deleted =
        if d.networks_pruned.swap(true, Ordering::SeqCst) { vec![] } else { vec!["net10".into(), "net2".into()] };
    Json(PruneResponse { deleted, space_reclaimed: 0 })
}

/// The name of the mock's anonymous volume.
fn anonymous() -> String {
    "9e".repeat(32)
}

/// The mock's volumes, in no particular order.
fn volumes() -> Vec<Volume> {
    let volume = |name: String, anonymous| Volume {
        driver: "local".into(),
        mountpoint: format!("/var/lib/rustlet/volumes/{name}/_data"),
        anonymous,
        name,
        ..Volume::default()
    };
    vec![
        volume("data".into(), false),
        volume(anonymous(), true),
        volume("cache10".into(), false),
        volume("cache2".into(), false),
    ]
}

async fn volume_list() -> Json<Vec<Volume>> {
    Json(volumes())
}

async fn volume_create(State(d): Shared, Json(config): Json<VolumeCreate>) -> Response {
    d.volume_creates.lock().unwrap().push(config.clone());
    let volume = Volume { name: config.name.unwrap_or_else(anonymous), driver: "local".into(), ..Volume::default() };
    (StatusCode::CREATED, Json(volume)).into_response()
}

async fn volume_inspect(State(d): Shared, Path(name): Path<String>) -> Response {
    d.call(format!("inspect volume {name}"));
    match volumes().into_iter().find(|v| v.name == name) {
        Some(volume) => Json(volume).into_response(),
        None => error(ErrorKind::NoSuchVolume, &format!("no such volume: {name}")),
    }
}

async fn volume_remove(State(d): Shared, Path(name): Path<String>, Query(q): Query<VolumeRemoveQuery>) -> Response {
    d.call(format!("volume rm {name} force={}", q.force));
    if q.force || volumes().iter().any(|v| v.name == name) {
        return StatusCode::NO_CONTENT.into_response();
    }
    error(ErrorKind::NoSuchVolume, &format!("no such volume: {name}"))
}

/// The first prune removes the anonymous volume (with `all`, the named ones
/// too), 7.8 MB in all; the next finds nothing.
async fn volume_prune(State(d): Shared, Query(q): Query<VolumePruneQuery>) -> Json<PruneResponse> {
    d.call(format!("volume prune all={}", q.all));
    if d.volumes_pruned.swap(true, Ordering::SeqCst) {
        return Json(PruneResponse::default());
    }
    let mut deleted = vec![anonymous()];
    if q.all {
        deleted.extend(["cache10".into(), "cache2".into(), "data".into()]);
    }
    Json(PruneResponse { deleted, space_reclaimed: 7_812_345 })
}

/// Two samples a second apart (by their `read` times), then nothing more,
/// as from a running container.
async fn stats(Path(id): Path<String>, Query(q): Query<StatsQuery>) -> Response {
    assert!(q.stream);
    let sample = |read: &str, usage_usec| StatsSample {
        id: id.clone(),
        read: read.into(),
        cpu: [("usage_usec".to_owned(), usage_usec)].into(),
        memory_current: 100 << 20,
        memory_stat: [("inactive_file".to_owned(), 30 << 20)].into(),
        pids_current: 4,
        ..StatsSample::default()
    };
    let lines = [sample("2026-10-01T12:00:00Z", 0), sample("2026-10-01T12:00:01Z", 500_000)]
        .map(|s| Ok::<_, std::convert::Infallible>(serde_json::to_string(&s).unwrap() + "\n"));
    let body = futures::stream::iter(lines).chain(futures::stream::pending());
    ([(header::CONTENT_TYPE, rustlet_spec::NDJSON)], Body::from_stream(body)).into_response()
}

async fn images() -> Json<Vec<ImageSummary>> {
    Json(vec![
        ImageSummary {
            id: "sha256:1111111111112222222222222222222222222222222222222222222222222222".into(),
            names: vec!["docker.io/library/alpine:latest".into(), "docker.io/library/alpine:3.20".into()],
            created: Some((chrono::Utc::now() - chrono::Duration::days(15)).to_rfc3339()),
            size: 3_620_000,
            ..ImageSummary::default()
        },
        ImageSummary {
            id: "sha256:3333333333334444444444444444444444444444444444444444444444444444".into(),
            names: vec!["ghcr.io/o/app:v1".into()],
            created: Some((chrono::Utc::now() - chrono::Duration::hours(3)).to_rfc3339()),
            size: 187_430_000,
            ..ImageSummary::default()
        },
    ])
}

/// Serves `app`; returns the `-H` value that reaches it, and the directory
/// guard.
fn serve(app: Router) -> (String, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("rustlet.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("unix://{}", socket.display()), dir)
}

/// Ctrl-C, as the terminal would send it. (nextest runs each test in a
/// process of its own.)
fn sigint_ourselves() {
    std::process::Command::new("kill").args(["-INT", &std::process::id().to_string()]).status().unwrap();
}

/// Serves a mock daemon; returns it, the `-H` value that reaches it, and
/// the directory guard.
fn daemon() -> (Arc<Daemon>, String, tempfile::TempDir) {
    let d = Arc::new(Daemon::default());
    let app = Router::new()
        .route(pattern::CONTAINERS, post(create).get(list))
        .route(pattern::CONTAINER, get(inspect_container).delete(remove))
        .route(&pattern::container_action("start"), post(start))
        .route(&pattern::container_action("attach"), get(attach))
        .route(&pattern::container_action("wait"), post(wait))
        .route(&pattern::container_action("stop"), post(stop))
        .route(&pattern::container_action("kill"), post(kill))
        .route(&pattern::container_action("logs"), get(logs))
        .route(&pattern::container_action("exec"), post(exec_create))
        .route(pattern::EXEC_START, get(exec_start).post(exec_start_detached))
        .route(&pattern::container_action("stats"), get(stats))
        .route(pattern::IMAGE_PULL, post(pull))
        .route(pattern::IMAGES, get(images))
        .route(pattern::IMAGE_INSPECT, get(inspect_image))
        .route(pattern::NETWORKS, get(network_list).post(network_create))
        .route(pattern::NETWORK, get(network_inspect).delete(network_remove))
        .route(pattern::NETWORK_PRUNE, post(network_prune))
        .route(pattern::VOLUMES, get(volume_list).post(volume_create))
        .route(pattern::VOLUME, get(volume_inspect).delete(volume_remove))
        .route(pattern::VOLUME_PRUNE, post(volume_prune))
        .route(pattern::INFO, get(info))
        .route(pattern::VERSION, get(version))
        .with_state(d.clone());
    let (host, dir) = serve(app);
    (d, host, dir)
}

/// Runs `rustlet -H host args…` with `stdin`; returns the exit code and
/// what it printed.
async fn rustlet(host: &str, args: &[&str], stdin: &[u8]) -> (i32, Buffer, Buffer) {
    let mut argv = vec!["-H", host];
    argv.extend_from_slice(args);
    let (console, stdout, stderr) = console(stdin);
    let code = tokio::time::timeout(Duration::from_secs(20), run_cli(parse(&argv), console)).await.expect("hung");
    (code, stdout, stderr)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn run_pulls_a_missing_image_attaches_before_starting_and_exits_with_the_containers_code() {
    let (d, host, _dir) = daemon();
    d.image_missing.store(true, Ordering::SeqCst);

    let (code, stdout, stderr) = rustlet(&host, &["run", "--rm", "alpine", "echo", "hi"], b"").await;
    let stderr = stderr.text();
    assert_eq!(code, 3, "{stderr}");
    assert_eq!(stdout.text(), "hello\n");
    // The attach is open before the start, so nothing printed is lost; the
    // removal is waited for, after the exit.
    assert_eq!(
        d.calls(),
        [
            "create alpine",
            "pull alpine Missing",
            "create alpine",
            "attach stdin=false",
            &format!("start {}", rustlet_spec::short_id(ID)),
            "wait Removed",
        ]
    );
    let pulled = "Unable to find image 'alpine:latest' locally\n\
                  latest: Pulling from library/alpine\n\
                  9824c27679d3: Pulling fs layer\n\
                  9824c27679d3: Download complete\n\
                  9824c27679d3: Pull complete\n\
                  Digest: sha256:r\n\
                  Status: Downloaded newer image for alpine:latest\n";
    assert!(stderr.starts_with(pulled), "{stderr}");
    assert!(stderr.ends_with("oops\n"), "{stderr}");
    let configs = d.configs.lock().unwrap().clone();
    assert_eq!(configs[1].cmd, ["echo", "hi"]);
    assert!(configs[1].auto_remove && !configs[1].open_stdin);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn run_interactive_sends_input_and_its_end() {
    let (d, host, _dir) = daemon();
    let (code, stdout, stderr) = rustlet(&host, &["run", "-i", "alpine", "cat"], b"ping\npong\n").await;
    assert_eq!(code, 3, "{}", stderr.text());
    // The input came back (echoed), then the container's own output.
    assert_eq!(stdout.text(), "ping\npong\nhello\n");
    let config = d.configs.lock().unwrap()[0].clone();
    assert!(config.open_stdin && config.stdin_once);
    assert!(d.calls().contains(&"attach stdin=true".to_owned()));
}

#[tokio::test]
async fn run_detached_starts_and_prints_the_id() {
    let (d, host, _dir) = daemon();
    let (code, stdout, stderr) =
        rustlet(&host, &["run", "-d", "-i", "--name", "web", "alpine", "sleep", "1d"], b"").await;
    assert_eq!(code, 0, "{}", stderr.text());
    assert_eq!(stdout.text(), format!("{ID}\n"));
    assert_eq!(d.calls(), ["create alpine", &format!("start {}", rustlet_spec::short_id(ID))]);
    let config = d.configs.lock().unwrap()[0].clone();
    // Input stays open for a later attach, not closed after the first.
    assert!(config.open_stdin && !config.stdin_once);
    assert_eq!(config.name.as_deref(), Some("web"));
}

#[tokio::test]
async fn a_start_that_fails_exits_with_its_kinds_code_and_cleans_up() {
    let (d, host, _dir) = daemon();
    *d.start_fails.lock().unwrap() = Some(ErrorBody::new(ErrorKind::CommandNotFound, "exec: \"nope\": not found"));
    let (code, _, stderr) = rustlet(&host, &["run", "--rm", "alpine", "nope"], b"").await;
    assert_eq!(code, 127);
    assert_eq!(stderr.text(), "rustlet: error: exec: \"nope\": not found\n");
    // With --rm, a container that never ran is removed right away, and its
    // anonymous volumes with it, as the daemon removes a --rm container.
    assert_eq!(d.calls().last().unwrap(), &format!("rm {}", rustlet_spec::short_id(ID)));
    assert_eq!(*d.removals.lock().unwrap(), [RemoveQuery { force: true, volumes: true }]);
}

#[tokio::test]
async fn an_attach_that_fails_still_removes_the_rm_container() {
    let (d, host, _dir) = daemon();
    d.attach_fails.store(true, Ordering::SeqCst);
    let (code, _, _) = rustlet(&host, &["run", "--rm", "alpine", "true"], b"").await;
    assert_eq!(code, 125);
    assert_eq!(d.calls().last().unwrap(), &format!("rm {}", rustlet_spec::short_id(ID)));
}

#[tokio::test]
async fn exec_detached_sends_no_input() {
    let (d, host, _dir) = daemon();
    let (code, _, stderr) = rustlet(&host, &["exec", "-d", "-i", "web", "cat"], b"").await;
    assert_eq!(code, 0, "{}", stderr.text());
    assert_eq!(d.calls(), ["exec create", "exec start -d"]);
    // Nothing would ever send it any (nor end it): `cat` would run forever.
    assert!(!d.execs.lock().unwrap()[0].stdin);
}

/// Ctrl-C passed on to a container that is gone (it exited as the attach
/// began): the kill fails, and the session must still end.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ctrl_c_ends_an_attach_whose_container_is_gone() {
    let inspect = || async {
        Json(rustlet_spec::container::ContainerInspect {
            id: ID.into(),
            name: "web".into(),
            state: ContainerState { status: ContainerStatus::Running, ..ContainerState::default() },
            ..Default::default()
        })
    };
    // An attach that waits for a start that never comes.
    let attach = |ws: WebSocketUpgrade| async move {
        ws.on_upgrade(|socket| async move {
            let _socket = socket;
            std::future::pending::<()>().await
        })
    };
    let kill = || async { error(ErrorKind::Conflict, "container web is not running") };
    let (host, _dir) = serve(
        Router::new()
            .route(pattern::CONTAINER, get(inspect))
            .route(&pattern::container_action("attach"), get(attach))
            .route(&pattern::container_action("kill"), post(kill)),
    );
    let ctrl_c = async {
        tokio::time::sleep(Duration::from_millis(500)).await;
        sigint_ourselves();
    };
    let ((code, _, _), ()) = tokio::join!(rustlet(&host, &["attach", "--no-stdin", "web"], b""), ctrl_c);
    assert_eq!(code, 130);
}

#[tokio::test]
async fn a_detached_start_that_fails_removes_its_rm_container() {
    let (d, host, _dir) = daemon();
    *d.start_fails.lock().unwrap() = Some(ErrorBody::new(ErrorKind::CommandNotFound, "exec: \"nope\": not found"));
    let (code, stdout, _) = rustlet(&host, &["run", "-d", "--rm", "alpine", "nope"], b"").await;
    assert_eq!((code, stdout.text().as_str()), (127, ""));
    assert_eq!(d.calls().last().unwrap(), &format!("rm {}", rustlet_spec::short_id(ID)));
}

/// Without a terminal, Ctrl-C goes to the container (`kill INT`), and the
/// CLI waits for its exit.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sigint_is_passed_on_to_the_container() {
    let killed = Arc::new(Notify::new());
    let signals = Arc::new(Mutex::new(Vec::<Option<String>>::new()));
    let (k, s) = (killed.clone(), signals.clone());
    let kill = move |Query(q): Query<KillQuery>| async move {
        s.lock().unwrap().push(q.signal);
        k.notify_one();
        StatusCode::NO_CONTENT
    };
    let k = killed.clone();
    // A container that exits once it gets a signal.
    let attach = move |ws: WebSocketUpgrade| async move {
        ws.on_upgrade(move |mut socket| async move {
            k.notified().await;
            let exit = serde_json::to_string(&Control::Exit { code: 130, oom_killed: false }).unwrap();
            socket.send(Message::Text(exit.into())).await.unwrap();
        })
    };
    let created = || async {
        let created = CreateResponse { id: ID.into(), name: "x".into(), warnings: vec![] };
        (StatusCode::CREATED, Json(created)).into_response()
    };
    let (host, _dir) = serve(
        Router::new()
            .route(pattern::CONTAINERS, post(created))
            .route(&pattern::container_action("start"), post(|| async { StatusCode::NO_CONTENT }))
            .route(&pattern::container_action("kill"), post(kill))
            .route(&pattern::container_action("attach"), get(attach)),
    );
    let ctrl_c = async {
        tokio::time::sleep(Duration::from_millis(500)).await;
        sigint_ourselves();
    };
    let ((code, _, stderr), ()) = tokio::join!(rustlet(&host, &["run", "alpine", "sleep", "1000"], b""), ctrl_c);
    assert_eq!(code, 130, "{}", stderr.text());
    assert_eq!(signals.lock().unwrap().as_slice(), [Some("INT".to_owned())]);
}

#[tokio::test]
async fn a_closed_stdout_ends_quietly_with_141() {
    struct Closed;
    impl std::io::Write for Closed {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let (_d, host, _dir) = daemon();
    let (mut console, _, stderr) = console(b"");
    console.stdout = Box::new(Closed);
    let code = run_cli(parse(&["-H", &host, "ps", "-a"]), console).await;
    assert_eq!((code, stderr.text().as_str()), (141, ""));
}

#[tokio::test]
async fn pull_never_means_a_missing_image_is_an_error() {
    let (d, host, _dir) = daemon();
    d.image_missing.store(true, Ordering::SeqCst);
    let (code, _, stderr) = rustlet(&host, &["run", "--pull", "never", "alpine"], b"").await;
    assert_eq!((code, stderr.text().as_str()), (125, "rustlet: error: no such image: alpine\n"));
    assert_eq!(d.calls(), ["create alpine"]);
}

#[tokio::test]
async fn exec_exits_with_the_processs_code() {
    let (d, host, _dir) = daemon();
    let (code, stdout, _) =
        rustlet(&host, &["exec", "-e", "A=1", "-w", "/srv", "web", "sh", "-c", "exit 5"], b"").await;
    assert_eq!((code, stdout.text().as_str()), (5, "in exec\n"));
    assert_eq!(d.calls(), ["exec create", "exec start"]);
    let exec = d.execs.lock().unwrap()[0].clone();
    assert_eq!(
        exec,
        ExecConfig {
            cmd: vec!["sh".into(), "-c".into(), "exit 5".into()],
            env: vec!["A=1".into()],
            workdir: Some("/srv".into()),
            ..ExecConfig::default()
        }
    );
}

#[tokio::test]
async fn an_exec_whose_program_is_missing_exits_127() {
    let (_d, host, _dir) = daemon();
    let (code, _, stderr) = rustlet(&host, &["exec", "web", "nope"], b"").await;
    assert_eq!((code, stderr.text().as_str()), (127, "rustlet: error: exec: \"nope\": not found\n"));
    let (code, _, stderr) = rustlet(&host, &["exec", "web"], b"").await;
    assert_eq!((code, stderr.text().as_str()), (125, "rustlet: error: exec needs a command to run in web\n"));
}

#[tokio::test]
async fn batch_commands_go_on_past_a_failure() {
    let (d, host, _dir) = daemon();
    let (code, stdout, stderr) = rustlet(&host, &["stop", "-t", "1", "a", "missing", "b"], b"").await;
    assert_eq!(code, 1);
    assert_eq!(stdout.text(), "a\nb\n");
    assert_eq!(stderr.text(), "rustlet: error: no such container: missing\n");
    assert_eq!(d.calls(), ["stop a Some(1)", "stop missing Some(1)", "stop b Some(1)"]);
    let (code, stdout, _) = rustlet(&host, &["kill", "-s", "HUP", "a"], b"").await;
    assert_eq!((code, stdout.text().as_str()), (0, "a\n"));
    assert_eq!(d.calls().last().unwrap(), "kill a Some(\"HUP\")");
}

#[tokio::test]
async fn ps_draws_dockers_table() {
    let (_d, host, _dir) = daemon();
    let (code, stdout, _) = rustlet(&host, &["ps", "-a"], b"").await;
    assert_eq!(code, 0);
    // Ports by container port, in Docker's place for them.
    let expected = "\
CONTAINER ID   IMAGE        COMMAND                  CREATED          STATUS                     PORTS                                           NAMES
bbbbbbbbbbbb   nginx:1.27   \"/docker-entrypoint.…\"   10 minutes ago   Up 5 minutes               0.0.0.0:8080->80/tcp, 127.0.0.1:8443->443/tcp   web
aaaaaaaaaaaa   alpine       \"sleep 1000\"             2 hours ago      Exited (0) 3 minutes ago                                                   old
";
    assert_eq!(stdout.text(), expected);
    let (_, stdout, _) = rustlet(&host, &["ps", "-q", "--no-trunc"], b"").await;
    assert_eq!(stdout.text(), format!("{}\n{}\n", "b".repeat(64), "a".repeat(64)));
}

#[tokio::test]
async fn rm_takes_anonymous_volumes_only_with_v() {
    let (d, host, _dir) = daemon();
    let (code, stdout, _) = rustlet(&host, &["rm", "-v", "a"], b"").await;
    assert_eq!((code, stdout.text().as_str()), (0, "a\n"));
    rustlet(&host, &["rm", "--force", "--volumes", "b"], b"").await;
    rustlet(&host, &["rm", "-f", "c"], b"").await;
    assert_eq!(
        *d.removals.lock().unwrap(),
        [
            RemoveQuery { force: false, volumes: true },
            RemoveQuery { force: true, volumes: true },
            RemoveQuery { force: true, volumes: false },
        ]
    );
}

#[tokio::test]
async fn port_shows_published_ports_like_docker() {
    let (d, host, _dir) = daemon();
    let (code, stdout, stderr) = rustlet(&host, &["port", "web"], b"").await;
    assert_eq!(code, 0, "{}", stderr.text());
    assert_eq!(
        stdout.text(),
        "53/udp -> 0.0.0.0:5353\n\
         80/tcp -> 0.0.0.0:8080\n\
         80/tcp -> 127.0.0.1:9090\n\
         443/tcp -> 127.0.0.1:8443\n"
    );
    // One port: the host addresses it is published on.
    let (code, stdout, _) = rustlet(&host, &["port", "web", "80"], b"").await;
    assert_eq!((code, stdout.text().as_str()), (0, "0.0.0.0:8080\n127.0.0.1:9090\n"));
    let (code, stdout, _) = rustlet(&host, &["port", "web", "53/udp"], b"").await;
    assert_eq!((code, stdout.text().as_str()), (0, "0.0.0.0:5353\n"));
    // 53 is published for UDP only, and a port without a protocol is TCP's.
    let (code, stdout, stderr) = rustlet(&host, &["port", "web", "53"], b"").await;
    assert_eq!(
        (code, stdout.text().as_str(), stderr.text().as_str()),
        (1, "", "rustlet: error: no public port '53' published for web\n")
    );
    let (code, _, stderr) = rustlet(&host, &["port", "web", "http"], b"").await;
    assert_eq!(code, 125);
    assert!(stderr.text().starts_with("rustlet: error: invalid port \"http\""), "{}", stderr.text());
    let (code, _, stderr) = rustlet(&host, &["port", "gone"], b"").await;
    assert_eq!((code, stderr.text().as_str()), (125, "rustlet: error: no such container: gone\n"));
    // A bad port is refused before the daemon is asked.
    assert_eq!(d.calls().iter().filter(|c| c.starts_with("inspect container")).count(), 5);
}

#[tokio::test]
async fn run_sends_ports_networks_and_mounts() {
    let (d, host, _dir) = daemon();
    let args = [
        "run",
        "-d",
        "-p",
        "8080:80",
        "--net",
        "backend",
        "--network-alias",
        "api",
        "-v",
        "./site:/www:ro",
        "--tmpfs",
        "/run",
        "nginx",
    ];
    let (code, _, stderr) = rustlet(&host, &args, b"").await;
    assert_eq!(code, 0, "{}", stderr.text());
    let config = d.configs.lock().unwrap()[0].clone();
    assert_eq!((config.network, config.network_aliases), (NetworkMode::Network("backend".into()), vec!["api".into()]));
    assert_eq!(config.ports, PortMapping::parse("8080:80").unwrap());
    // A host path starting with `.` is the CLI's own directory's.
    let site = std::env::current_dir().unwrap().join("site");
    assert_eq!((config.mounts[0].kind, config.mounts[0].source.as_deref()), (MountType::Bind, site.to_str()));
    assert!(config.mounts[0].read_only);
    assert_eq!((config.mounts[1].kind, config.mounts[1].target.as_str()), (MountType::Tmpfs, "/run"));

    // What can't work is refused before anything exists.
    let (code, _, stderr) = rustlet(&host, &["create", "--network", "container:web", "-p", "80", "alpine"], b"").await;
    assert_eq!(code, 125);
    let stderr = stderr.text();
    assert!(
        stderr.starts_with("rustlet: error: conflicting options: --network container:web and --publish"),
        "{stderr}"
    );
    assert_eq!(d.calls().iter().filter(|c| c.starts_with("create")).count(), 1);
}

#[tokio::test]
async fn networks_are_created_listed_inspected_and_removed() {
    let (d, host, _dir) = daemon();
    let args = [
        "network",
        "create",
        "--subnet",
        "10.89.5.0/24",
        "--gateway",
        "10.89.5.1",
        "--internal",
        "--label",
        "tier=db",
        "--label",
        "solo",
        "store",
    ];
    let (code, stdout, stderr) = rustlet(&host, &args, b"").await;
    assert_eq!(code, 0, "{}", stderr.text());
    assert_eq!(stdout.text(), format!("{}\n", "f".repeat(64)));
    let expected = NetworkCreate {
        name: "store".into(),
        subnet: Some("10.89.5.0/24".into()),
        gateway: Some("10.89.5.1".into()),
        internal: true,
        labels: [("solo".to_owned(), String::new()), ("tier".to_owned(), "db".to_owned())].into(),
    };
    assert_eq!(*d.network_creates.lock().unwrap(), [expected]);
    // As Docker's CLI: a gateway is in a subnet that is given too.
    let (code, _, stderr) = rustlet(&host, &["network", "create", "--gateway", "10.89.5.1", "x"], b"").await;
    assert_eq!((code, stderr.text().as_str()), (125, "rustlet: error: --gateway needs the --subnet it belongs to\n"));
    assert_eq!(d.network_creates.lock().unwrap().len(), 1);

    // By name, naturally: net2 before net10.
    let (code, stdout, _) = rustlet(&host, &["network", "ls"], b"").await;
    let expected = "\
NETWORK ID     NAME      DRIVER    SUBNET
cccccccccccc   backend   bridge    10.89.1.0/24
bbbbbbbbbbbb   bridge    bridge    10.89.0.0/24
eeeeeeeeeeee   net2      bridge    10.89.2.0/24
dddddddddddd   net10     bridge    10.89.10.0/24
";
    assert_eq!((code, stdout.text().as_str()), (0, expected));
    let (_, stdout, _) = rustlet(&host, &["network", "list", "-q"], b"").await;
    assert_eq!(stdout.text(), "cccccccccccc\nbbbbbbbbbbbb\neeeeeeeeeeee\ndddddddddddd\n");
    let (_, stdout, _) = rustlet(&host, &["network", "ls", "-q", "--no-trunc"], b"").await;
    assert_eq!(stdout.text(), ["c", "b", "e", "d"].map(|c| c.repeat(64) + "\n").concat());

    // A JSON array of those found; the rest on stderr, and exit 1.
    let (code, stdout, stderr) = rustlet(&host, &["network", "inspect", "backend", "nope", "eeee"], b"").await;
    assert_eq!((code, stderr.text().as_str()), (1, "rustlet: error: no such network: nope\n"));
    let found: Vec<Network> = serde_json::from_str(&stdout.text()).unwrap();
    assert_eq!(found, [find_network("backend").unwrap(), find_network("net2").unwrap()]);

    // Each name once it is gone; failures on the way.
    let (code, stdout, stderr) = rustlet(&host, &["network", "rm", "backend", "nope", "net2"], b"").await;
    assert_eq!(
        (code, stdout.text().as_str(), stderr.text().as_str()),
        (1, "backend\nnet2\n", "rustlet: error: no such network: nope\n")
    );
    let removed: Vec<String> = d.calls().into_iter().filter(|c| c.starts_with("network rm")).collect();
    assert_eq!(removed, ["network rm backend", "network rm nope", "network rm net2"]);
}

#[tokio::test]
async fn network_prune_asks_first() {
    let (d, host, _dir) = daemon();
    let question = "WARNING! This will remove all custom networks not used by at least one container.\n\
                    Are you sure you want to continue? [y/N] \n";
    // Nobody to answer (a script without -f): refused, and said so.
    let (code, stdout, stderr) = rustlet(&host, &["network", "prune"], b"").await;
    assert_eq!((code, stdout.text().as_str()), (125, question));
    assert!(stderr.text().starts_with("rustlet: error: no answer on stdin"), "{}", stderr.text());
    // Anything but y is a no, as with Docker (an empty line, even "yes"):
    // nothing happens, and that is no failure.
    for no in [&b"N\n"[..], b"\n", b"yes\n"] {
        let (code, stdout, stderr) = rustlet(&host, &["network", "prune"], no).await;
        assert_eq!((code, stdout.text().as_str(), stderr.text().as_str()), (0, question, ""));
    }
    assert!(!d.calls().contains(&"network prune".to_owned()));
    // A yes, typed or piped.
    let (code, stdout, _) = rustlet(&host, &["network", "prune"], b"y\n").await;
    assert_eq!((code, stdout.text()), (0, format!("{question}Deleted Networks:\nnet10\nnet2\n\n")));
    // -f asks nothing; nothing left to remove, nothing printed.
    let (code, stdout, _) = rustlet(&host, &["network", "prune", "-f"], b"").await;
    assert_eq!((code, stdout.text().as_str()), (0, ""));
    assert_eq!(d.calls().iter().filter(|c| *c == "network prune").count(), 2);
}

#[tokio::test]
async fn volumes_are_created_listed_inspected_and_removed() {
    let (d, host, _dir) = daemon();
    let (code, stdout, _) = rustlet(&host, &["volume", "create", "--label", "tier=db", "store"], b"").await;
    assert_eq!((code, stdout.text().as_str()), (0, "store\n"));
    // Without a name, the daemon makes one up.
    let (code, stdout, _) = rustlet(&host, &["volume", "create"], b"").await;
    assert_eq!((code, stdout.text()), (0, format!("{}\n", anonymous())));
    let named = VolumeCreate { name: Some("store".into()), labels: [("tier".to_owned(), "db".to_owned())].into() };
    assert_eq!(*d.volume_creates.lock().unwrap(), [named, VolumeCreate::default()]);

    let (code, stdout, _) = rustlet(&host, &["volume", "ls"], b"").await;
    let expected = format!(
        "DRIVER    VOLUME NAME\n\
         local     {}\n\
         local     cache2\n\
         local     cache10\n\
         local     data\n",
        anonymous()
    );
    assert_eq!((code, stdout.text()), (0, expected));
    let (_, stdout, _) = rustlet(&host, &["volume", "list", "-q"], b"").await;
    assert_eq!(stdout.text(), format!("{}\ncache2\ncache10\ndata\n", anonymous()));

    let (code, stdout, stderr) = rustlet(&host, &["volume", "inspect", "data", "nope"], b"").await;
    assert_eq!((code, stderr.text().as_str()), (1, "rustlet: error: no such volume: nope\n"));
    let found: Vec<Volume> = serde_json::from_str(&stdout.text()).unwrap();
    assert_eq!(found, [volumes()[0].clone()]);

    let (code, stdout, stderr) = rustlet(&host, &["volume", "rm", "data", "nope"], b"").await;
    assert_eq!(
        (code, stdout.text().as_str(), stderr.text().as_str()),
        (1, "data\n", "rustlet: error: no such volume: nope\n")
    );
    // With -f, one that isn't there is no error.
    let (code, stdout, _) = rustlet(&host, &["volume", "rm", "-f", "nope"], b"").await;
    assert_eq!((code, stdout.text().as_str()), (0, "nope\n"));
    let removed: Vec<String> = d.calls().into_iter().filter(|c| c.starts_with("volume rm")).collect();
    assert_eq!(removed, ["volume rm data force=false", "volume rm nope force=false", "volume rm nope force=true"]);
}

#[tokio::test]
async fn volume_prune_asks_first_and_counts_the_space() {
    let (d, host, _dir) = daemon();
    let question = |what| {
        format!(
            "WARNING! This will remove {what} local volumes not used by at least one container.\n\
             Are you sure you want to continue? [y/N] \n"
        )
    };
    let (code, stdout, _) = rustlet(&host, &["volume", "prune"], b"").await;
    assert_eq!((code, stdout.text()), (125, question("anonymous")));
    let (code, stdout, _) = rustlet(&host, &["volume", "prune", "--all"], b"n\n").await;
    assert_eq!((code, stdout.text()), (0, question("all")));
    assert!(!d.calls().iter().any(|c| c.starts_with("volume prune")));
    // What went, and the space it took in Docker's four digits.
    let (code, stdout, _) = rustlet(&host, &["volume", "prune", "-f"], b"").await;
    let pruned = format!("Deleted Volumes:\n{}\n\nTotal reclaimed space: 7.812MB\n", anonymous());
    assert_eq!((code, stdout.text()), (0, pruned));
    // Nothing (left) to remove: only the total.
    let (code, stdout, _) = rustlet(&host, &["volume", "prune", "-a"], b"y\n").await;
    assert_eq!((code, stdout.text()), (0, question("all") + "Total reclaimed space: 0B\n"));
    let pruned: Vec<String> = d.calls().into_iter().filter(|c| c.starts_with("volume prune")).collect();
    assert_eq!(pruned, ["volume prune all=false", "volume prune all=true"]);
}

#[tokio::test]
async fn inspect_finds_networks_and_volumes_too() {
    let (d, host, _dir) = daemon();
    let (code, stdout, stderr) = rustlet(&host, &["inspect", "web", "backend", "data", "nothing"], b"").await;
    assert_eq!((code, stderr.text().as_str()), (1, "rustlet: error: no such object: nothing\n"));
    let found: Vec<serde_json::Value> = serde_json::from_str(&stdout.text()).unwrap();
    let names: Vec<&str> = found.iter().map(|o| o["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["web", "backend", "data"]);
    // In Docker's order: container, image, network, volume; the first found wins.
    let lookups = |name: &str| -> Vec<String> {
        let calls = d.calls().into_iter().filter(|c| c.starts_with("inspect ") && c.ends_with(&format!(" {name}")));
        calls.map(|c| c.split(' ').nth(1).unwrap().to_owned()).collect()
    };
    assert_eq!(lookups("web"), ["container"]);
    assert_eq!(lookups("backend"), ["container", "image", "network"]);
    assert_eq!(lookups("nothing"), ["container", "image", "network", "volume"]);

    // With --type, only there, and the daemon's own word for a miss.
    let (code, stdout, _) = rustlet(&host, &["inspect", "--type", "volume", "data"], b"").await;
    assert_eq!(code, 0);
    assert_eq!(serde_json::from_str::<Vec<Volume>>(&stdout.text()).unwrap(), [volumes()[0].clone()]);
    let (code, stdout, stderr) = rustlet(&host, &["inspect", "--type", "network", "data"], b"").await;
    assert_eq!((code, stdout.text().as_str()), (1, "[]\n"));
    assert_eq!(stderr.text(), "rustlet: error: no such network: data\n");
    assert_eq!(lookups("data"), ["container", "image", "network", "volume", "volume", "network"]);
}

#[tokio::test]
async fn info_counts_networks_and_volumes() {
    let (_d, host, _dir) = daemon();
    let (code, stdout, stderr) = rustlet(&host, &["info"], b"").await;
    assert_eq!(code, 0, "{}", stderr.text());
    let stdout = stdout.text();
    assert!(stdout.contains("\nImages: 0\nNetworks: 4\nVolumes: 4\nServer Version: 0.1.0\n"), "{stdout}");
}

#[tokio::test]
async fn logs_split_streams_and_stamp_lines() {
    let (_d, host, _dir) = daemon();
    let (code, stdout, stderr) = rustlet(&host, &["logs", "-t", "--tail", "2", "web"], b"").await;
    assert_eq!(code, 0);
    assert_eq!(stdout.text(), "2026-10-01T12:00:00.000000001Z out\n");
    assert_eq!(stderr.text(), "2026-10-01T12:00:00.000000002Z err\n");
}

#[tokio::test]
async fn an_absent_daemon_is_reported_with_125() {
    let dir = tempfile::tempdir().unwrap();
    let host = dir.path().join("rustlet.sock").display().to_string();
    let (code, _, stderr) = rustlet(&host, &["ps"], b"").await;
    assert_eq!(code, 125);
    let stderr = stderr.text();
    assert!(stderr.starts_with("rustlet: error: cannot connect to rustletd at "), "{stderr}");
    assert!(stderr.contains("is rustletd running?"), "{stderr}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stats_no_stream_computes_from_two_samples() {
    let (_d, host, _dir) = daemon();
    let (code, stdout, stderr) = rustlet(&host, &["stats", "--no-stream"], b"").await;
    assert_eq!(code, 0, "{}", stderr.text());
    // Only the running container; half a CPU between the samples; memory
    // without the inactive page cache, against the host's 2 GiB.
    let expected = "\
CONTAINER ID   NAME      CPU %     MEM USAGE / LIMIT   MEM %     NET I/O   BLOCK I/O   PIDS
bbbbbbbbbbbb   web       50.00%    70MiB / 2GiB        3.42%     0B / 0B   0B / 0B     4
";
    assert_eq!(stdout.text(), expected);
}

#[tokio::test]
async fn pull_shows_progress_then_the_name() {
    let (d, host, _dir) = daemon();
    let (code, stdout, _) = rustlet(&host, &["pull", "alpine"], b"").await;
    assert_eq!(code, 0);
    assert_eq!(
        stdout.text(),
        "Using default tag: latest\n\
         latest: Pulling from library/alpine\n\
         9824c27679d3: Pulling fs layer\n\
         9824c27679d3: Download complete\n\
         9824c27679d3: Pull complete\n\
         Digest: sha256:r\n\
         Status: Downloaded newer image for alpine:latest\n\
         docker.io/library/alpine:latest\n"
    );
    // `rustlet pull` always asks the registry.
    assert_eq!(d.calls(), ["pull alpine Always"]);
    let (_, stdout, _) = rustlet(&host, &["pull", "-q", "alpine:latest"], b"").await;
    assert_eq!(stdout.text(), "docker.io/library/alpine:latest\n");
}

#[tokio::test]
async fn images_name_rows_the_way_docker_does() {
    let (_d, host, _dir) = daemon();
    let (code, stdout, _) = rustlet(&host, &["images"], b"").await;
    assert_eq!(code, 0);
    let expected = "\
REPOSITORY      TAG       IMAGE ID       CREATED       SIZE
ghcr.io/o/app   v1        333333333333   3 hours ago   187MB
alpine          latest    111111111111   2 weeks ago   3.62MB
alpine          3.20      111111111111   2 weeks ago   3.62MB
";
    assert_eq!(stdout.text(), expected);
    let (_, stdout, _) = rustlet(&host, &["images", "-q"], b"").await;
    assert_eq!(stdout.text(), "333333333333\n111111111111\n");
}

/// The terminal path, which needs a real terminal: raw mode, the size sent
/// before start, the detach keys, the terminal restored after. Run it by
/// hand in a PTY, with input that comes once raw mode is on (before that,
/// the line discipline would swallow Ctrl-Q as flow control):
///
/// ```sh
/// (sleep 2; printf 'abc\x10\x11') | script -qec \
///     "stty rows 30 cols 100; target/debug/deps/rustlet-<hash> --ignored --exact tests::a_terminal_session_detaches" /dev/null
/// ```
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a terminal and typed input; see the comment"]
async fn a_terminal_session_detaches() {
    let (d, host, _dir) = daemon();
    let code = run_cli(parse(&["-H", &host, "run", "-it", "alpine", "sh"]), crate::Console::system()).await;
    assert_eq!(code, 0);
    assert_eq!(d.stdin.lock().unwrap().as_slice(), b"abc");
    let calls = d.calls();
    // Once before start, once as the relay begins.
    assert_eq!(calls.iter().filter(|c| *c == "resize 30x100").count(), 2, "{calls:?}");
    assert_eq!(calls.last().unwrap(), "hangup");
    // Out of raw mode again.
    assert!(!crossterm::terminal::is_raw_mode_enabled().unwrap());
}

//! Whole commands, run in-process as `main` runs them (parsed command
//! line, [`run_cli`], exit code), against a mock daemon: an axum server on
//! a temporary Unix socket that records the calls it gets and answers like
//! rustletd would.

use std::io;
use std::net::Ipv4Addr;
use std::path::PathBuf;
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
use bytes::Bytes;
use clap::Parser;
use futures::StreamExt;
use rustlet_build::context::{ContextError, Packed};
use rustlet_spec::build::{BuildEvent, BuildOptions, BuildQuery, CommitRequest, CommitResponse};
use rustlet_spec::container::{
    AttachQuery, ContainerConfig, ContainerInspect, ContainerState, ContainerStatus, ContainerSummary, CreateResponse,
    HealthConfig, KillQuery, RemoveQuery, StopQuery, WaitQuery, WaitResponse,
};
use rustlet_spec::exec::{ExecConfig, ExecCreated};
use rustlet_spec::image::{
    BlobKind, ImageQuery, ImageSaveRequest, ImageSummary, ImageTagQuery, LoadEvent, PullEvent, PullPolicy, PullQuery,
};
use rustlet_spec::logs::{LogEntry, LogStream, LogsQuery};
use rustlet_spec::network::{
    Network, NetworkConnect, NetworkCreate, NetworkCreateResponse, NetworkDisconnect, NetworkMode, NetworkSettings,
    PortMapping, Protocol, PruneResponse, PublishedPort,
};
use rustlet_spec::routes::pattern;
use rustlet_spec::stats::{StatsQuery, StatsSample};
use rustlet_spec::stream::{self, Control};
use rustlet_spec::system::{Info, Version};
use rustlet_spec::volume::{MountType, Volume, VolumeCreate, VolumePruneQuery, VolumeRemoveQuery};
use rustlet_spec::{ErrorBody, ErrorKind};
use tokio::net::UnixListener;
use tokio::sync::Notify;

use crate::build::Packer;
use crate::compose::{ComposeCommand, Rmi};
use crate::console::Console;
use crate::console::testing::{Buffer, console};
use crate::{Cli, Command, run_cli, run_cli_with};

const ID: &str = "4f1d2c3b4a5968778695a4b3c2d1e0f0011223344556677889900aabbccddee";
const LAYER: &str = "sha256:9824c27679d3b27c0e1cb00b2b5cdbc2d1ae6e8f00aabbccddeeff0011223344";
/// What the mock builds, commits and loads.
const IMAGE_ID: &str = "sha256:3c4d5e6f7a8b00112233445566778899aabbccddeeff00112233445566778899";
/// The image a load finds without a name.
const UNNAMED_ID: &str = "sha256:5a5b5c5d5e5f00112233445566778899aabbccddeeff00112233445566778899";

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
    network_connects: Mutex<Vec<NetworkConnect>>,
    network_disconnects: Mutex<Vec<NetworkDisconnect>>,
    volume_creates: Mutex<Vec<VolumeCreate>>,
    /// A prune has removed what there was.
    networks_pruned: AtomicBool,
    volumes_pruned: AtomicBool,
    /// Each build's options, and the context it was sent.
    builds: Mutex<Vec<BuildOptions>>,
    contexts: Mutex<Vec<Vec<u8>>>,
    commits: Mutex<Vec<CommitRequest>>,
    /// Each archive loaded.
    loads: Mutex<Vec<Vec<u8>>>,
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

fn published(host_ip: &str, host_port: u16, container_port: u16, protocol: Protocol) -> PublishedPort {
    PublishedPort { host_ip: host_ip.parse().unwrap(), host_port, container_port, protocol }
}

/// `web`, with five published ports (out of order), one on an IPv6
/// address; nothing else exists.
async fn inspect_container(State(d): Shared, Path(id): Path<String>) -> Response {
    d.call(format!("inspect container {id}"));
    if id != "web" {
        return error(ErrorKind::NoSuchContainer, &format!("no such container: {id}"));
    }
    let ports = vec![
        published("127.0.0.1", 8443, 443, Protocol::Tcp),
        published("::1", 9090, 80, Protocol::Tcp),
        published("0.0.0.0", 8080, 80, Protocol::Tcp),
        published("0.0.0.0", 5353, 53, Protocol::Udp),
        published("127.0.0.1", 9090, 80, Protocol::Tcp),
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
                published("::1", 8443, 443, Protocol::Tcp),
                published("127.0.0.1", 8443, 443, Protocol::Tcp),
                published("0.0.0.0", 8080, 80, Protocol::Tcp),
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
/// `backend` has IPv6 too.
fn networks() -> Vec<Network> {
    let network = |id: &str, name: &str, subnet: &str| Network {
        id: id.repeat(64),
        name: name.into(),
        driver: "bridge".into(),
        subnet: subnet.into(),
        ..Network::default()
    };
    let backend = Network {
        ipv6: true,
        subnet6: Some("fd00:89:0:1::/64".into()),
        gateway6: Some("fd00:89:0:1::1".into()),
        ..network("c", "backend", "10.89.1.0/24")
    };
    vec![
        network("b", "bridge", "10.89.0.0/24"),
        network("d", "net10", "10.89.10.0/24"),
        backend,
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

async fn network_connect(State(d): Shared, Path(id): Path<String>, Json(body): Json<NetworkConnect>) -> Response {
    d.call(format!("network connect {id} {}", body.container));
    if find_network(&id).is_none() {
        return error(ErrorKind::NoSuchNetwork, &format!("no such network: {id}"));
    }
    d.network_connects.lock().unwrap().push(body);
    StatusCode::NO_CONTENT.into_response()
}

/// With `force`, a network that is gone is no error: the container just
/// forgets it, as the spec has it.
async fn network_disconnect(State(d): Shared, Path(id): Path<String>, Json(body): Json<NetworkDisconnect>) -> Response {
    d.call(format!("network disconnect {id} {}", body.container));
    if find_network(&id).is_none() && !body.force {
        return error(ErrorKind::NoSuchNetwork, &format!("no such network: {id}"));
    }
    d.network_disconnects.lock().unwrap().push(body);
    StatusCode::NO_CONTENT.into_response()
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

/// A name as the daemon gives it back: `app` → `docker.io/library/app:latest`.
fn full_name(name: &str) -> String {
    let full = if name.contains('/') { name.to_owned() } else { format!("docker.io/library/{name}") };
    if full.rsplit('/').next().unwrap_or_default().contains(':') { full } else { full + ":latest" }
}

/// Reads the whole context, then builds in three steps: `FROM alpine`
/// (pulled), a `RUN` that prints on both streams, a `CMD`. The target
/// `broken` fails at the `RUN`.
async fn build(State(d): Shared, Query(q): Query<BuildQuery>, body: Body) -> Response {
    let context = match axum::body::to_bytes(body, usize::MAX).await {
        Ok(context) => context,
        Err(e) => {
            d.call("build: the context broke off");
            return error(ErrorKind::Invalid, &format!("reading the build context: {e}"));
        }
    };
    let options = q.options().unwrap();
    d.contexts.lock().unwrap().push(context.to_vec());
    d.builds.lock().unwrap().push(options.clone());
    let alpine = "docker.io/library/alpine:latest".to_owned();
    let layer = BlobKind::Layer;
    let mut events = vec![
        BuildEvent::Context { files: 2, bytes: 2048 },
        BuildEvent::Stage { index: 0, name: None, base: "alpine".into() },
        BuildEvent::Step { step: 1, total: 3, instruction: "FROM alpine".into() },
        BuildEvent::Pull { event: PullEvent::Resolving { reference: alpine.clone() } },
        BuildEvent::Pull {
            event: PullEvent::Downloading { kind: layer, digest: LAYER.into(), current: 0, total: 3_000_000 },
        },
        BuildEvent::Pull { event: PullEvent::Downloaded { kind: layer, digest: LAYER.into(), size: 3_000_000 } },
        BuildEvent::Pull { event: PullEvent::Ready { reference: alpine, manifest: "sha256:m".into() } },
        BuildEvent::StepDone { step: 1, layer: None },
        BuildEvent::Step { step: 2, total: 3, instruction: "RUN apk add curl".into() },
        BuildEvent::Container { step: 2, id: ID.into() },
        BuildEvent::Output {
            step: 2,
            stream: LogStream::Stdout,
            text: "fetch https://dl-cdn.alpinelinux.org/\n".into(),
        },
        BuildEvent::Output { step: 2, stream: LogStream::Stderr, text: "warning: no cache\n".into() },
    ];
    if options.target.as_deref() == Some("broken") {
        let message = "The command '/bin/sh -c apk add curl' returned a non-zero code: 1".into();
        events.push(BuildEvent::Error { message });
        return ndjson(&events);
    }
    events.extend([
        BuildEvent::StepDone { step: 2, layer: Some(LAYER.into()) },
        BuildEvent::Warning { message: "One or more build-args [UNUSED] were not consumed".into() },
        BuildEvent::Step { step: 3, total: 3, instruction: "CMD [\"sh\"]".into() },
        BuildEvent::StepDone { step: 3, layer: None },
        BuildEvent::Done { id: IMAGE_ID.into(), names: options.tags.iter().map(|t| full_name(t)).collect() },
    ]);
    ndjson(&events)
}

/// The cache had two entries, 7.8 MB.
async fn build_prune(State(d): Shared) -> Json<PruneResponse> {
    d.call("build prune");
    Json(PruneResponse { deleted: vec!["sha256:aaaa".into(), "sha256:bbbb".into()], space_reclaimed: 7_812_345 })
}

/// Any container but `gone` commits.
async fn commit(State(d): Shared, Json(request): Json<CommitRequest>) -> Response {
    d.call(format!("commit {}", request.container));
    if request.container == "gone" {
        return error(ErrorKind::NoSuchContainer, "no such container: gone");
    }
    d.commits.lock().unwrap().push(request.clone());
    let name = request.reference.as_deref().map(full_name);
    (StatusCode::CREATED, Json(CommitResponse { id: IMAGE_ID.into(), name, layer: LAYER.into() })).into_response()
}

/// Any image but `missing` takes another name.
async fn tag(State(d): Shared, Query(q): Query<ImageTagQuery>) -> Response {
    d.call(format!("tag {} {}", q.source, q.target));
    if q.source == "missing" {
        return error(ErrorKind::NoSuchImage, "no such image: missing");
    }
    StatusCode::NO_CONTENT.into_response()
}

/// An "archive" naming the images asked for; `missing` is refused, and
/// the archive of `broken` breaks off after its first chunk (sent before
/// it breaks: an error that came at once would end the response before
/// its head).
async fn save(State(d): Shared, Json(request): Json<ImageSaveRequest>) -> Response {
    d.call(format!("save {}", request.names.join(" ")));
    if request.names.iter().any(|n| n == "missing") {
        return error(ErrorKind::NoSuchImage, "no such image: missing");
    }
    let archive = Bytes::from(format!("archive of {}", request.names.join(", ")));
    let tar = [(header::CONTENT_TYPE, "application/x-tar")];
    if request.names.iter().any(|n| n == "broken") {
        let breaks = futures::stream::once(async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            Err(io::Error::other("the disk is on fire"))
        });
        let chunks = futures::stream::iter([Ok(archive)]).chain(breaks);
        return (tar, Body::from_stream(chunks)).into_response();
    }
    (tar, Body::from(archive)).into_response()
}

/// Takes the archive in: it held `app:1.0` and an image without a name.
async fn load(State(d): Shared, body: Body) -> Response {
    let archive = axum::body::to_bytes(body, usize::MAX).await.unwrap();
    d.loads.lock().unwrap().push(archive.to_vec());
    ndjson(&[
        LoadEvent::Blob { digest: LAYER.into(), size: 3_000_000, existed: false },
        LoadEvent::Blob { digest: IMAGE_ID.into(), size: 1500, existed: true },
        LoadEvent::Loaded { id: IMAGE_ID.into(), name: Some("docker.io/library/app:1.0".into()) },
        LoadEvent::Loaded { id: UNNAMED_ID.into(), name: None },
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
        .route(pattern::IMAGE_TAG, post(tag))
        .route(pattern::IMAGE_SAVE, post(save))
        .route(pattern::IMAGE_LOAD, post(load))
        .route(pattern::BUILD, post(build))
        .route(pattern::BUILD_PRUNE, post(build_prune))
        .route(pattern::COMMIT, post(commit))
        .route(pattern::NETWORKS, get(network_list).post(network_create))
        .route(pattern::NETWORK, get(network_inspect).delete(network_remove))
        .route(pattern::NETWORK_PRUNE, post(network_prune))
        .route(pattern::NETWORK_CONNECT, post(network_connect))
        .route(pattern::NETWORK_DISCONNECT, post(network_disconnect))
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
    let (console, stdout, stderr) = console(stdin);
    (rustlet_on(host, args, console).await, stdout, stderr)
}

/// Runs `rustlet -H host args…` on `console` (one that says it is a
/// terminal); returns the exit code.
async fn rustlet_on(host: &str, args: &[&str], console: Console) -> i32 {
    let mut argv = vec!["-H", host];
    argv.extend_from_slice(args);
    tokio::time::timeout(Duration::from_secs(20), run_cli(parse(&argv), console)).await.expect("hung")
}

/// [`rustlet`], with `packer` packing build contexts.
async fn rustlet_packing(host: &str, args: &[&str], packer: Packer) -> (i32, Buffer, Buffer) {
    let mut argv = vec!["-H", host];
    argv.extend_from_slice(args);
    let (console, stdout, stderr) = console(b"");
    let code = tokio::time::timeout(Duration::from_secs(20), run_cli_with(parse(&argv), console, packer));
    (code.await.expect("hung"), stdout, stderr)
}

/// Packs no files: the "archive" says which context and Containerfile it
/// was given. A context's Containerfile is `Containerfile`, by that name.
fn fake_packer() -> Packer {
    Packer {
        default_containerfile: |dir| Some(dir.join("Containerfile")),
        dockerfile_name: |_, file| Ok(file.file_name().unwrap_or_default().to_string_lossy().into_owned()),
        pack: |context, file, out| {
            let archive = format!("context {} with {}", context.display(), file.display());
            let io = |source| ContextError::Io { path: context.to_owned(), source };
            out.write_all(archive.as_bytes()).map_err(io)?;
            Ok(Packed { dockerfile: "Containerfile".into(), entries: 2, bytes: 2048, excluded: 0 })
        },
    }
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
    // Ports by container port, in Docker's place for them; an IPv6 host
    // address in brackets, after the IPv4 ones.
    let expected = "\
CONTAINER ID   IMAGE        COMMAND                  CREATED          STATUS                     PORTS                                                                NAMES
bbbbbbbbbbbb   nginx:1.27   \"/docker-entrypoint.…\"   10 minutes ago   Up 5 minutes               0.0.0.0:8080->80/tcp, 127.0.0.1:8443->443/tcp, [::1]:8443->443/tcp   web
aaaaaaaaaaaa   alpine       \"sleep 1000\"             2 hours ago      Exited (0) 3 minutes ago                                                                        old
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
    // An IPv6 host address in brackets, after the IPv4 ones.
    assert_eq!(
        stdout.text(),
        "53/udp -> 0.0.0.0:5353\n\
         80/tcp -> 0.0.0.0:8080\n\
         80/tcp -> 127.0.0.1:9090\n\
         80/tcp -> [::1]:9090\n\
         443/tcp -> 127.0.0.1:8443\n"
    );
    // One port: the host addresses it is published on.
    let (code, stdout, _) = rustlet(&host, &["port", "web", "80"], b"").await;
    assert_eq!((code, stdout.text().as_str()), (0, "0.0.0.0:8080\n127.0.0.1:9090\n[::1]:9090\n"));
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
async fn run_and_create_join_several_networks_at_chosen_addresses() {
    let (d, host, _dir) = daemon();
    let args = [
        "run",
        "-d",
        "--network",
        "backend",
        "--ip",
        "10.89.1.5",
        "--ip6",
        "fd00:89:0:1::5",
        "--network-alias",
        "api",
        "--net",
        "net2",
        "--network",
        "default",
        "nginx",
    ];
    let (code, _, stderr) = rustlet(&host, &args, b"").await;
    assert_eq!(code, 0, "{}", stderr.text());
    let (code, _, stderr) = rustlet(&host, &["create", "--network", "bridge", "--net", "backend", "alpine"], b"").await;
    assert_eq!(code, 0, "{}", stderr.text());
    // The first network is the mode, and the aliases and addresses are on
    // it; the others go by name, `default` as the default network's.
    let first = ContainerConfig {
        image: "nginx".into(),
        network: NetworkMode::Network("backend".into()),
        network_aliases: vec!["api".into()],
        ip: Some(Ipv4Addr::new(10, 89, 1, 5)),
        ip6: Some("fd00:89:0:1::5".parse().unwrap()),
        extra_networks: vec!["net2".into(), "bridge".into()],
        ..ContainerConfig::default()
    };
    let second = ContainerConfig {
        image: "alpine".into(),
        network: NetworkMode::Bridge,
        extra_networks: vec!["backend".into()],
        ..ContainerConfig::default()
    };
    assert_eq!(*d.configs.lock().unwrap(), [first, second]);
}

#[tokio::test]
async fn network_options_that_cant_work_are_refused_before_any_request() {
    let (d, host, _dir) = daemon();
    let alone = |a, b| {
        format!(
            "conflicting options: --network {a} and --network {b} (host, none and container:NAME can't be combined \
             with other networks)"
        )
    };
    let twice = |n| format!("--network {n} is given more than once");
    let chosen = |flag, mode| {
        format!("{flag} needs a user-defined network as the first --network: {mode} doesn't take static addresses")
    };
    let shared = |flag| {
        format!(
            "conflicting options: --network container:web and {flag} (on web's network, the ports, addresses, DNS \
             settings, /etc/hosts and host name are web's)"
        )
    };
    let cases: [(&[&str], String); 13] = [
        // Only bridge networks go together.
        (&["--network", "host", "--network", "backend"], alone("host", "backend")),
        (&["--network", "backend", "--network", "bridge", "--network", "none"], alone("backend", "none")),
        (&["--net", "default", "--net", "container:web"], alone("bridge", "container:web")),
        // The same network twice; `default` is `bridge`.
        (&["--network", "backend", "--network", "backend"], twice("backend")),
        (&["--network", "default", "--network", "bridge"], twice("bridge")),
        (&["--network", "host", "--network", "host"], twice("host")),
        // An address of one's choosing, only on a user-defined first network.
        (&["--ip", "10.89.0.5"], chosen("--ip", "bridge")),
        (&["--network", "bridge", "--network", "backend", "--ip6", "fd00:89:0:1::5"], chosen("--ip6", "bridge")),
        (&["--network", "none", "--ip", "10.89.0.5"], chosen("--ip", "none")),
        (&["--network", "host", "--ip6", "::5"], chosen("--ip6", "host")),
        // On another container's network, the addresses are that one's.
        (&["--network", "container:web", "--ip", "10.89.1.5"], shared("--ip")),
        (&["--network", "container:web", "--ip6", "fd00::5"], shared("--ip6")),
        // Aliases are the first network's too.
        (
            &["--network", "bridge", "--network", "backend", "--network-alias", "api"],
            "--network-alias needs a user-defined network (--network NAME): bridge has no DNS server to answer it"
                .into(),
        ),
    ];
    for command in ["run", "create"] {
        for (args, error) in &cases {
            let argv = [&[command][..], args, &["alpine"]].concat();
            let (code, _, stderr) = rustlet(&host, &argv, b"").await;
            assert_eq!((code, stderr.text()), (125, format!("rustlet: error: {error}\n")), "{argv:?}");
        }
    }
    // An address that isn't one is a bad command line, as any bad value.
    for (flag, bad) in [("--ip", "10.89.1"), ("--ip", "fd00::5"), ("--ip6", "10.89.1.5"), ("--ip6", "nope")] {
        let e = Cli::try_parse_from(["rustlet", "run", flag, bad, "alpine"]).unwrap_err();
        assert_eq!(e.kind(), clap::error::ErrorKind::ValueValidation, "{flag} {bad}");
    }
    assert!(!d.calls().iter().any(|c| c.starts_with("create")), "{:?}", d.calls());
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
        ..Default::default()
    };
    assert_eq!(*d.network_creates.lock().unwrap(), [expected]);
    // As Docker's CLI: a gateway is in a subnet that is given too.
    let (code, _, stderr) = rustlet(&host, &["network", "create", "--gateway", "10.89.5.1", "x"], b"").await;
    assert_eq!((code, stderr.text().as_str()), (125, "rustlet: error: --gateway needs the --subnet it belongs to\n"));
    assert_eq!(d.network_creates.lock().unwrap().len(), 1);

    // By name, naturally: net2 before net10; a network's IPv6 subnet after
    // its IPv4 one.
    let (code, stdout, _) = rustlet(&host, &["network", "ls"], b"").await;
    let expected = "\
NETWORK ID     NAME      DRIVER    SUBNET
cccccccccccc   backend   bridge    10.89.1.0/24, fd00:89:0:1::/64
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
async fn network_create_sorts_subnets_and_gateways_by_family() {
    let (d, host, _dir) = daemon();
    let args = [
        "network",
        "create",
        "--ipv6",
        "--subnet",
        "fd00:89:0:5::/64",
        "--gateway",
        "fd00:89:0:5::1",
        "--subnet",
        "10.89.5.0/24",
        "--gateway",
        "10.89.5.1",
        "dual",
    ];
    let (code, _, stderr) = rustlet(&host, &args, b"").await;
    assert_eq!(code, 0, "{}", stderr.text());
    // --ipv6 alone: both subnets from the daemon's pools.
    let (code, _, stderr) = rustlet(&host, &["network", "create", "--ipv6", "pooled"], b"").await;
    assert_eq!(code, 0, "{}", stderr.text());
    let dual = NetworkCreate {
        name: "dual".into(),
        subnet: Some("10.89.5.0/24".into()),
        gateway: Some("10.89.5.1".into()),
        ipv6: true,
        subnet6: Some("fd00:89:0:5::/64".into()),
        gateway6: Some("fd00:89:0:5::1".into()),
        ..NetworkCreate::default()
    };
    let pooled = NetworkCreate { name: "pooled".into(), ipv6: true, ..NetworkCreate::default() };
    assert_eq!(*d.network_creates.lock().unwrap(), [dual, pooled]);

    // What the values' families alone say is wrong; the rest (prefix
    // lengths, host bits, overlaps) is the daemon's to find.
    for (args, error) in [
        (&["--subnet", "fd00:89:0:5::/64"][..], "--subnet fd00:89:0:5::/64: an IPv6 subnet needs --ipv6"),
        (
            &["--subnet", "10.89.5.0/24", "--subnet", "10.89.6.0/24"],
            "--subnet 10.89.5.0/24 and --subnet 10.89.6.0/24: a network has one IPv4 subnet at most",
        ),
        (
            &["--ipv6", "--subnet", "fd00:89:0:5::/64", "--subnet", "fd00:89:0:6::/64"],
            "--subnet fd00:89:0:5::/64 and --subnet fd00:89:0:6::/64: a network has one IPv6 subnet at most",
        ),
        (
            &["--subnet", "backend/24"],
            "--subnet \"backend/24\": not a subnet in CIDR form (10.89.5.0/24, fd00:89:0:5::/64)",
        ),
        (&["--subnet", "10.89.5.0/24", "--gateway", "10.89.5"], "--gateway \"10.89.5\": not an IP address"),
        (&["--subnet", "10.89.5.0/24", "--gateway", "fd00:89:0:5::1"], "--gateway needs the --subnet it belongs to"),
        (
            &["--ipv6", "--subnet", "fd00:89:0:5::/64", "--gateway", "10.89.5.1"],
            "--gateway needs the --subnet it belongs to",
        ),
        (
            &["--subnet", "10.89.5.0/24", "--gateway", "10.89.5.1", "--gateway", "10.89.5.2"],
            "--gateway 10.89.5.1 and --gateway 10.89.5.2: a subnet has one gateway",
        ),
    ] {
        let argv = [&["network", "create"][..], args, &["x"]].concat();
        let (code, _, stderr) = rustlet(&host, &argv, b"").await;
        assert_eq!((code, stderr.text()), (125, format!("rustlet: error: {error}\n")), "{args:?}");
    }
    assert_eq!(d.network_creates.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn containers_are_connected_to_networks_and_disconnected() {
    let (d, host, _dir) = daemon();
    let args = [
        "network",
        "connect",
        "--alias",
        "db",
        "--alias",
        "store",
        "--ip",
        "10.89.1.5",
        "--ip6",
        "fd00:89:0:1::5",
        "backend",
        "web",
    ];
    // Nothing printed, as with Docker.
    let (code, stdout, stderr) = rustlet(&host, &args, b"").await;
    assert_eq!((code, stdout.text().as_str(), stderr.text().as_str()), (0, "", ""));
    let (code, _, stderr) = rustlet(&host, &["network", "connect", "net2", "web"], b"").await;
    assert_eq!(code, 0, "{}", stderr.text());
    let chosen = NetworkConnect {
        container: "web".into(),
        aliases: vec!["db".into(), "store".into()],
        ipv4_address: Some(Ipv4Addr::new(10, 89, 1, 5)),
        ipv6_address: Some("fd00:89:0:1::5".parse().unwrap()),
    };
    let plain = NetworkConnect { container: "web".into(), ..NetworkConnect::default() };
    assert_eq!(*d.network_connects.lock().unwrap(), [chosen, plain]);
    // The daemon's refusal is the command's error.
    let (code, _, stderr) = rustlet(&host, &["network", "connect", "nope", "web"], b"").await;
    assert_eq!((code, stderr.text().as_str()), (125, "rustlet: error: no such network: nope\n"));
    // A name the DNS server couldn't answer is refused before any request,
    // and an address that isn't one is a bad command line.
    let (code, _, stderr) = rustlet(&host, &["network", "connect", "--alias", "a b", "backend", "web"], b"").await;
    assert_eq!((code, stderr.text().as_str()), (125, "rustlet: error: --alias \"a b\" is not a host name\n"));
    for (flag, bad) in [("--ip", "10.89.1"), ("--ip", "fd00::5"), ("--ip6", "10.89.1.5")] {
        let e = Cli::try_parse_from(["rustlet", "network", "connect", flag, bad, "backend", "web"]).unwrap_err();
        assert_eq!(e.kind(), clap::error::ErrorKind::ValueValidation, "{flag} {bad}");
    }
    let connects: Vec<String> = d.calls().into_iter().filter(|c| c.starts_with("network connect")).collect();
    assert_eq!(connects, ["network connect backend web", "network connect net2 web", "network connect nope web"]);

    let (code, stdout, stderr) = rustlet(&host, &["network", "disconnect", "backend", "web"], b"").await;
    assert_eq!((code, stdout.text().as_str(), stderr.text().as_str()), (0, "", ""));
    // From a network that is gone, only with --force.
    let (code, _, stderr) = rustlet(&host, &["network", "disconnect", "gone", "web"], b"").await;
    assert_eq!((code, stderr.text().as_str()), (125, "rustlet: error: no such network: gone\n"));
    let (code, _, stderr) = rustlet(&host, &["network", "disconnect", "-f", "gone", "web"], b"").await;
    assert_eq!(code, 0, "{}", stderr.text());
    assert_eq!(
        *d.network_disconnects.lock().unwrap(),
        [
            NetworkDisconnect { container: "web".into(), force: false },
            NetworkDisconnect { container: "web".into(), force: true },
        ]
    );
    let disconnects: Vec<String> = d.calls().into_iter().filter(|c| c.starts_with("network disconnect")).collect();
    assert_eq!(
        disconnects,
        ["network disconnect backend web", "network disconnect gone web", "network disconnect gone web"]
    );
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

/// What a build of the mock prints until its `RUN` fails, or goes on.
const BUILD_STEPS: &str = "Sending build context to rustletd  2.048kB\n\
                           Step 1/3 : FROM alpine\n\
                           Status: Downloaded newer image for alpine:latest\n\
                           Step 2/3 : RUN apk add curl\n \
                           ---> Running in 4f1d2c3b4a59\n\
                           fetch https://dl-cdn.alpinelinux.org/\n\
                           warning: no cache\n";

#[tokio::test]
async fn build_packs_its_context_into_the_request_and_shows_the_steps() {
    let (d, host, _dir) = daemon();
    let context = tempfile::tempdir().unwrap();
    let path = context.path().to_str().unwrap();
    let args = [
        "build",
        "-t",
        "app",
        "--tag",
        "app:1.0",
        "--build-arg",
        "V=1",
        "--label",
        "tier=web",
        "--network",
        "none",
        "--pull",
        path,
    ];
    let (code, stdout, stderr) = rustlet_packing(&host, &args, fake_packer()).await;
    assert_eq!(code, 0, "{}", stderr.text());
    let rest = " ---> Removed intermediate container 4f1d2c3b4a59\n \
                ---> 9824c27679d3\n\
                Step 3/3 : CMD [\"sh\"]\n\
                Successfully built 3c4d5e6f7a8b\n\
                Successfully tagged app:latest\n\
                Successfully tagged app:1.0\n";
    assert_eq!(stdout.text(), format!("{BUILD_STEPS}{rest}"));
    assert_eq!(stderr.text(), "[Warning] One or more build-args [UNUSED] were not consumed\n");
    // The options in the query, the packed context as the body.
    let expected = BuildOptions {
        tags: vec!["app".into(), "app:1.0".into()],
        dockerfile: Some("Containerfile".into()),
        build_args: [("V".to_owned(), "1".to_owned())].into(),
        pull: PullPolicy::Always,
        network: NetworkMode::None,
        labels: [("tier".to_owned(), "web".to_owned())].into(),
        ..BuildOptions::default()
    };
    assert_eq!(*d.builds.lock().unwrap(), [expected]);
    let sent = format!("context {path} with {path}/Containerfile");
    assert_eq!(*d.contexts.lock().unwrap(), [sent.into_bytes()]);

    // -f names the Containerfile, from the current directory.
    let (code, _, stderr) = rustlet_packing(&host, &["build", "-f", "../Dockerfile.dev", path], fake_packer()).await;
    assert_eq!(code, 0, "{}", stderr.text());
    assert_eq!(d.builds.lock().unwrap()[1].dockerfile.as_deref(), Some("Dockerfile.dev"));
    assert_eq!(d.contexts.lock().unwrap()[1], format!("context {path} with ../Dockerfile.dev").into_bytes());
}

#[tokio::test]
async fn build_quiet_prints_the_id_alone_and_the_rest_only_if_it_fails() {
    let (_d, host, _dir) = daemon();
    let context = tempfile::tempdir().unwrap();
    let path = context.path().to_str().unwrap();
    let (code, stdout, stderr) = rustlet_packing(&host, &["build", "-q", path], fake_packer()).await;
    assert_eq!((code, stdout.text(), stderr.text()), (0, format!("{IMAGE_ID}\n"), String::new()));
    // A failure: what was held back, then the daemon's message.
    let (code, stdout, stderr) =
        rustlet_packing(&host, &["build", "-q", "--target", "broken", path], fake_packer()).await;
    assert_eq!((code, stdout.text().as_str()), (1, ""));
    let error = "rustlet: error: The command '/bin/sh -c apk add curl' returned a non-zero code: 1\n";
    assert_eq!(stderr.text(), format!("{BUILD_STEPS}{error}"));
}

#[tokio::test]
async fn a_failed_step_ends_the_build_with_the_daemons_message_and_1() {
    let (_d, host, _dir) = daemon();
    let context = tempfile::tempdir().unwrap();
    let args = ["build", "--target", "broken", context.path().to_str().unwrap()];
    let (code, stdout, stderr) = rustlet_packing(&host, &args, fake_packer()).await;
    assert_eq!(code, 1);
    assert_eq!(stdout.text(), BUILD_STEPS);
    assert_eq!(stderr.text(), "rustlet: error: The command '/bin/sh -c apk add curl' returned a non-zero code: 1\n");
}

#[tokio::test]
async fn a_context_that_cant_be_packed_is_reported_by_the_file_that_failed() {
    let (d, host, _dir) = daemon();
    let context = tempfile::tempdir().unwrap();
    // A first chunk goes out, then a file can't be read.
    let unreadable = Packer {
        pack: |context, _, out| {
            let io = |source| ContextError::Io { path: context.to_owned(), source };
            out.write_all(&[0; 100_000]).map_err(io)?;
            Err(ContextError::Io { path: context.join("secret.key"), source: io::ErrorKind::PermissionDenied.into() })
        },
        ..fake_packer()
    };
    let (code, stdout, stderr) = rustlet_packing(&host, &["build", context.path().to_str().unwrap()], unreadable).await;
    assert_eq!((code, stdout.text().as_str()), (125, ""));
    let key = context.path().join("secret.key");
    assert_eq!(
        stderr.text(),
        format!("rustlet: error: packing the build context: {}: permission denied\n", key.display())
    );
    // The daemon never took the cut-off body for a context.
    assert!(d.builds.lock().unwrap().is_empty());
}

#[tokio::test]
async fn build_needs_a_directory_and_a_containerfile_before_any_request() {
    let (d, host, _dir) = daemon();
    let context = tempfile::tempdir().unwrap();
    let path = context.path().to_str().unwrap();
    let none = Packer { default_containerfile: |_| None, ..fake_packer() };
    let (code, _, stderr) = rustlet_packing(&host, &["build", path], none).await;
    assert_eq!(
        (code, stderr.text()),
        (125, format!("rustlet: error: no Containerfile or Dockerfile in {path} (-f names one)\n"))
    );
    let file = context.path().join("Containerfile");
    std::fs::write(&file, "FROM alpine\n").unwrap();
    let (code, _, stderr) = rustlet_packing(&host, &["build", file.to_str().unwrap()], fake_packer()).await;
    assert_eq!(
        (code, stderr.text()),
        (125, format!("rustlet: error: build context {}: not a directory\n", file.display()))
    );
    for (args, says) in [
        (&["build", "-"][..], "a build context on stdin (-) isn't supported"),
        (&["build", "https://github.com/o/app.git"], "a remote build context"),
        (&["build", "-f", "-", path], "a Containerfile on stdin (-f -) isn't supported"),
        (&["build", "--network", "container:web", path], "--network container:web: a build's RUN steps"),
    ] {
        let (code, _, stderr) = rustlet_packing(&host, args, fake_packer()).await;
        assert_eq!(code, 125, "{args:?}");
        assert!(stderr.text().starts_with(&format!("rustlet: error: {says}")), "{args:?}: {}", stderr.text());
    }
    assert!(d.builds.lock().unwrap().is_empty());
}

#[tokio::test]
async fn builder_prune_asks_on_a_terminal_and_never_without_one() {
    let (d, host, _dir) = daemon();
    let pruned = "Deleted build cache objects:\nsha256:aaaa\nsha256:bbbb\n\nTotal reclaimed space: 7.812MB\n";
    let (code, stdout, _) = rustlet(&host, &["builder", "prune", "-f"], b"").await;
    assert_eq!((code, stdout.text().as_str()), (0, pruned));
    // No terminal to ask on: refused without -f, even with a yes piped in.
    let (code, stdout, stderr) = rustlet(&host, &["builder", "prune"], b"y\n").await;
    assert_eq!((code, stdout.text().as_str()), (125, ""));
    assert_eq!(
        stderr.text(),
        "rustlet: error: not removing the build cache without -f: stdin isn't a terminal to ask on\n"
    );
    // On a terminal, asked; anything but y is a no.
    let question = "WARNING! This will remove all build cache. Are you sure you want to continue? [y/N] ";
    for (answer, expected) in [(&b"n\n"[..], question.to_owned()), (b"y\n", format!("{question}{pruned}"))] {
        let (mut terminal, stdout, _) = console(answer);
        terminal.stdin_tty = true;
        assert_eq!(rustlet_on(&host, &["builder", "prune"], terminal).await, 0);
        assert_eq!(stdout.text(), expected);
    }
    assert_eq!(d.calls().iter().filter(|c| *c == "build prune").count(), 2);
}

#[tokio::test]
async fn commit_sends_the_containers_changes_and_prints_the_new_images_id() {
    let (d, host, _dir) = daemon();
    let args = [
        "commit",
        "-a",
        "Jane Doe <jane@example.com>",
        "-m",
        "with curl",
        "-c",
        "CMD [\"sh\"]",
        "--change",
        "ENV A=1",
        "--pause=false",
        "web",
        "app:2",
    ];
    let (code, stdout, stderr) = rustlet(&host, &args, b"").await;
    assert_eq!((code, stdout.text()), (0, format!("{IMAGE_ID}\n")), "{}", stderr.text());
    // Paused by default; -p alone is true, -p=false isn't.
    for args in [&["commit", "web"][..], &["commit", "-p", "web"], &["commit", "-p=false", "web"]] {
        let (code, _, stderr) = rustlet(&host, args, b"").await;
        assert_eq!(code, 0, "{args:?}: {}", stderr.text());
    }
    let web = |pause| CommitRequest { container: "web".into(), pause, ..CommitRequest::default() };
    let first = CommitRequest {
        container: "web".into(),
        reference: Some("app:2".into()),
        comment: Some("with curl".into()),
        author: Some("Jane Doe <jane@example.com>".into()),
        pause: false,
        changes: vec!["CMD [\"sh\"]".into(), "ENV A=1".into()],
    };
    assert_eq!(*d.commits.lock().unwrap(), [first, web(true), web(true), web(false)]);
    let (code, _, stderr) = rustlet(&host, &["commit", "gone"], b"").await;
    assert_eq!((code, stderr.text().as_str()), (125, "rustlet: error: no such container: gone\n"));
}

#[tokio::test]
async fn tag_names_an_image_quietly() {
    let (d, host, _dir) = daemon();
    let (code, stdout, stderr) = rustlet(&host, &["tag", "alpine", "registry.example/alpine:3"], b"").await;
    assert_eq!((code, stdout.text().as_str(), stderr.text().as_str()), (0, "", ""));
    let (code, _, stderr) = rustlet(&host, &["tag", "missing", "x"], b"").await;
    assert_eq!((code, stderr.text().as_str()), (125, "rustlet: error: no such image: missing\n"));
    assert_eq!(d.calls(), ["tag alpine registry.example/alpine:3", "tag missing x"]);
}

#[tokio::test]
async fn save_writes_the_archive_to_a_file_or_a_pipe_never_to_a_terminal() {
    let (d, host, dir) = daemon();
    let out = dir.path().join("images.tar");
    let (code, stdout, stderr) = rustlet(&host, &["save", "-o", out.to_str().unwrap(), "alpine", "app:1.0"], b"").await;
    assert_eq!((code, stdout.text().as_str(), stderr.text().as_str()), (0, "", ""));
    assert_eq!(std::fs::read_to_string(&out).unwrap(), "archive of alpine, app:1.0");
    // Onto stdout, which is a pipe here.
    let (code, stdout, _) = rustlet(&host, &["save", "alpine"], b"").await;
    assert_eq!((code, stdout.text().as_str()), (0, "archive of alpine"));
    // Onto a terminal: refused before the daemon is asked.
    let (mut terminal, stdout, stderr) = console(b"");
    terminal.stdout_tty = true;
    assert_eq!(rustlet_on(&host, &["save", "alpine"], terminal).await, 125);
    assert_eq!(stdout.text(), "");
    assert_eq!(stderr.text(), "rustlet: error: refusing to write an archive to a terminal; use -o or redirect\n");
    assert_eq!(d.calls().iter().filter(|c| c.starts_with("save")).count(), 2);
}

#[tokio::test]
async fn a_failed_save_leaves_no_partial_archive_and_an_old_one_as_it_was() {
    let (_d, host, dir) = daemon();
    let out = dir.path().join("images.tar");
    std::fs::write(&out, "the old archive").unwrap();
    let (code, _, stderr) = rustlet(&host, &["save", "-o", out.to_str().unwrap(), "alpine", "broken"], b"").await;
    assert_eq!(code, 125);
    let stderr = stderr.text();
    assert!(stderr.starts_with(&format!("rustlet: error: -o {}: ", out.display())), "{stderr}");
    assert_eq!(std::fs::read_to_string(&out).unwrap(), "the old archive");
    // Refused by the daemon: no file at all.
    let new = dir.path().join("new.tar");
    let (code, _, stderr) = rustlet(&host, &["save", "-o", new.to_str().unwrap(), "missing"], b"").await;
    assert_eq!((code, stderr.text().as_str()), (125, "rustlet: error: no such image: missing\n"));
    let mut left: Vec<String> =
        std::fs::read_dir(dir.path()).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
    left.sort();
    assert_eq!(left, ["images.tar", "rustlet.sock"]);
}

#[tokio::test]
async fn load_sends_the_archive_and_says_what_it_loaded() {
    let (d, host, dir) = daemon();
    let archive = dir.path().join("images.tar");
    std::fs::write(&archive, "an archive").unwrap();
    let loaded = format!("Loaded image: app:1.0\nLoaded image ID: {UNNAMED_ID}\n");
    let (code, stdout, stderr) = rustlet(&host, &["load", "-i", archive.to_str().unwrap()], b"").await;
    assert_eq!((code, stdout.text()), (0, loaded.clone()), "{}", stderr.text());
    let (code, stdout, _) = rustlet(&host, &["load"], b"piped in").await;
    assert_eq!((code, stdout.text()), (0, loaded.clone()));
    // On a terminal, a line per blob first, unless -q.
    let (mut terminal, stdout, _) = console(b"from a pipe");
    terminal.stdout_tty = true;
    assert_eq!(rustlet_on(&host, &["load"], terminal).await, 0);
    assert_eq!(stdout.text(), format!("9824c27679d3: Loaded 3MB\n3c4d5e6f7a8b: Already exists\n{loaded}"));
    let (mut terminal, stdout, _) = console(b"from a pipe");
    terminal.stdout_tty = true;
    assert_eq!(rustlet_on(&host, &["load", "--quiet"], terminal).await, 0);
    assert_eq!(stdout.text(), loaded);
    let bodies = ["an archive", "piped in", "from a pipe", "from a pipe"].map(|s| s.as_bytes().to_vec());
    assert_eq!(*d.loads.lock().unwrap(), bodies);

    // Not from a terminal, nor from a file that isn't there.
    let (mut terminal, _, stderr) = console(b"");
    terminal.stdin_tty = true;
    assert_eq!(rustlet_on(&host, &["load"], terminal).await, 125);
    let stderr = stderr.text();
    assert!(stderr.starts_with("rustlet: error: requested load from stdin, but stdin is a terminal"), "{stderr}");
    let (code, _, stderr) = rustlet(&host, &["load", "-i", "/nonexistent/images.tar"], b"").await;
    assert_eq!(code, 125);
    assert!(stderr.text().starts_with("rustlet: error: -i /nonexistent/images.tar: "), "{}", stderr.text());
    assert_eq!(d.loads.lock().unwrap().len(), 4);
}

#[tokio::test]
async fn health_flags_reach_the_daemon_and_conflicting_ones_dont() {
    let (d, host, _dir) = daemon();
    let args =
        ["create", "--health-cmd", "wget -qO- localhost", "--health-interval=10s", "--health-retries", "2", "nginx"];
    let (code, _, stderr) = rustlet(&host, &args, b"").await;
    assert_eq!(code, 0, "{}", stderr.text());
    let (code, _, stderr) = rustlet(&host, &["run", "-d", "--no-healthcheck", "nginx"], b"").await;
    assert_eq!(code, 0, "{}", stderr.text());
    let (code, _, stderr) =
        rustlet(&host, &["run", "-d", "--no-healthcheck", "--health-timeout", "1s", "nginx"], b"").await;
    assert_eq!(
        (code, stderr.text().as_str()),
        (
            125,
            "rustlet: error: conflicting options: --no-healthcheck and --health-timeout (no healthcheck runs to \
             take options)\n"
        )
    );
    let checks: Vec<Option<HealthConfig>> = d.configs.lock().unwrap().iter().map(|c| c.healthcheck.clone()).collect();
    let probe = HealthConfig {
        test: vec!["CMD-SHELL".into(), "wget -qO- localhost".into()],
        interval: Some(10_000_000_000),
        retries: Some(2),
        ..HealthConfig::default()
    };
    let off = HealthConfig { test: vec!["NONE".into()], ..HealthConfig::default() };
    assert_eq!(checks, [Some(probe), Some(off)]);
}

#[test]
fn compose_takes_files_project_and_profiles_before_its_command() {
    let argv = [
        "compose",
        "-f",
        "compose.yaml",
        "--file",
        "compose.dev.yaml",
        "-p",
        "hits",
        "--project-directory",
        "/srv/hits",
        "--profile",
        "debug",
        "--profile",
        "tools",
        "up",
        "-d",
        "--build",
        "--force-recreate",
        "--remove-orphans",
        "-t",
        "3",
        "web",
        "worker",
    ];
    let Command::Compose(c) = parse(&argv).command else { panic!() };
    assert_eq!(c.files, [PathBuf::from("compose.yaml"), PathBuf::from("compose.dev.yaml")]);
    assert_eq!(c.project_name.as_deref(), Some("hits"));
    assert_eq!(c.project_directory, Some(PathBuf::from("/srv/hits")));
    assert_eq!(c.profile, ["debug", "tools"]);
    let ComposeCommand::Up(up) = c.command else { panic!() };
    assert!(up.detach && up.build && up.force_recreate && up.remove_orphans);
    assert!(!up.no_build && !up.no_recreate && !up.no_color);
    assert_eq!((up.timeout, up.services.as_slice()), (Some(3), &["web".to_owned(), "worker".to_owned()][..]));

    // A command's own -f is its own: `logs -f` follows.
    let Command::Compose(c) =
        parse(&["compose", "-f", "x.yaml", "logs", "-f", "-n", "5", "-t", "--no-color", "web"]).command
    else {
        panic!()
    };
    assert_eq!(c.files, [PathBuf::from("x.yaml")]);
    let ComposeCommand::Logs(logs) = c.command else { panic!() };
    assert!(logs.follow && logs.timestamps && logs.no_color);
    assert_eq!((logs.tail.as_str(), logs.services.as_slice()), ("5", &["web".to_owned()][..]));

    let Command::Compose(c) =
        parse(&["compose", "-p", "hits", "down", "-v", "--rmi", "local", "--remove-orphans", "-t", "1"]).command
    else {
        panic!()
    };
    let ComposeCommand::Down(down) = c.command else { panic!() };
    assert!(down.volumes && down.remove_orphans);
    assert_eq!((down.rmi, down.timeout), (Some(Rmi::Local), Some(1)));

    let compose = |args: &[&str]| match parse(&[&["compose"][..], args].concat()).command {
        Command::Compose(c) => c.command,
        _ => panic!(),
    };
    assert!(
        matches!(compose(&["ps", "-a", "-q", "web"]), ComposeCommand::Ps { all: true, quiet: true, services } if services == ["web"])
    );
    assert!(
        matches!(compose(&["build", "--no-cache"]), ComposeCommand::Build { no_cache: true, services } if services.is_empty())
    );
    assert!(matches!(compose(&["stop", "-t", "0", "db"]), ComposeCommand::Stop { timeout: Some(0), .. }));
    assert!(matches!(compose(&["start", "db"]), ComposeCommand::Start { services } if services == ["db"]));
    assert!(matches!(compose(&["ls", "--all"]), ComposeCommand::Ls { all: true }));
    assert!(matches!(compose(&["config", "--services"]), ComposeCommand::Config { services: true }));
    assert!(matches!(compose(&["down"]), ComposeCommand::Down(d) if d.rmi.is_none() && !d.volumes));

    // What can't go together, or isn't a value, is a bad command line.
    for bad in [
        &["compose", "up", "--build", "--no-build"][..],
        &["compose", "up", "--force-recreate", "--no-recreate"],
        &["compose", "down", "--rmi", "some"],
        &["compose", "logs", "-n"],
        &["compose"],
    ] {
        assert!(Cli::try_parse_from(std::iter::once("rustlet").chain(bad.iter().copied())).is_err(), "{bad:?}");
    }
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

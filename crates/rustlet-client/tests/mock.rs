//! The client against an in-process axum server on a temporary Unix
//! socket: real HTTP, chunked NDJSON and WebSocket upgrades, with routes
//! that do just enough to check what the client sent.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Json;
use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use futures::{SinkExt, StreamExt};
use rustlet_client::{Client, Error, SessionEvent};
use rustlet_spec::container::{AttachQuery, ContainerConfig, ContainerSummary, CreateResponse, ListQuery, RemoveQuery};
use rustlet_spec::exec::{ExecConfig, ExecCreated, ExecStarted};
use rustlet_spec::image::{PullEvent, PullPolicy, PullQuery};
use rustlet_spec::logs::{LogStream, LogsQuery};
use rustlet_spec::network::{Network, NetworkCreate, NetworkCreateResponse, PruneResponse};
use rustlet_spec::stream::{self, Control};
use rustlet_spec::volume::{Volume, VolumeCreate, VolumePruneQuery, VolumeRemoveQuery};
use rustlet_spec::{ErrorBody, ErrorKind, routes};
use tokio::net::UnixListener;
use tokio::sync::{mpsc, oneshot};

/// Serves `app` on a socket in a fresh temporary directory (kept alive by
/// the returned guard).
fn serve(app: Router) -> (tempfile::TempDir, Client) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rustlet.sock");
    let listener = UnixListener::bind(&path).unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (dir, Client::new(path))
}

/// Fails a test that would otherwise hang.
async fn within<T>(f: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(10), f).await.expect("timed out")
}

fn not_found(kind: ErrorKind, message: &str) -> Response {
    (StatusCode::NOT_FOUND, Json(ErrorBody::new(kind, message))).into_response()
}

#[tokio::test]
async fn json_requests_and_responses() {
    async fn create(headers: HeaderMap, Json(config): Json<ContainerConfig>) -> Response {
        assert_eq!(headers[header::HOST], "localhost");
        assert_eq!(headers[header::CONTENT_TYPE], "application/json");
        assert_eq!(config.image, "alpine");
        assert_eq!(config.cmd, ["echo", "hi"]);
        let created = CreateResponse { id: "0123456789abcdef".into(), name: "web".into(), warnings: vec![] };
        (StatusCode::CREATED, Json(created)).into_response()
    }
    async fn list(Query(q): Query<ListQuery>) -> Json<Vec<ContainerSummary>> {
        Json(vec![ContainerSummary { id: format!("all={}", q.all), ..ContainerSummary::default() }])
    }
    let app = Router::new()
        .route(routes::pattern::PING, get(|| async { "OK" }))
        .route(routes::pattern::CONTAINERS, post(create).get(list))
        .route(&routes::pattern::container_action("stop"), post(|| async { StatusCode::NO_CONTENT }));
    let (_dir, client) = serve(app);

    within(client.ping()).await.unwrap();
    let created = within(client.create_container(&ContainerConfig {
        image: "alpine".into(),
        cmd: vec!["echo".into(), "hi".into()],
        ..ContainerConfig::default()
    }))
    .await
    .unwrap();
    assert_eq!((created.id.as_str(), created.name.as_str()), ("0123456789abcdef", "web"));
    assert_eq!(within(client.list_containers(true)).await.unwrap()[0].id, "all=true");
    assert_eq!(within(client.list_containers(false)).await.unwrap()[0].id, "all=false");
    within(client.stop("web", Some(3))).await.unwrap();
}

#[tokio::test]
async fn error_bodies_become_api_errors() {
    let app = Router::new()
        .route(
            routes::pattern::CONTAINER,
            get(|Path(id): Path<String>| async move {
                not_found(ErrorKind::NoSuchContainer, &format!("no such container: {id}"))
            }),
        )
        .route(
            &routes::pattern::container_action("start"),
            post(|| async {
                let body = ErrorBody::new(ErrorKind::CommandNotFound, "exec: \"nope\": not found in $PATH");
                (StatusCode::INTERNAL_SERVER_ERROR, Json(body))
            }),
        );
    let (_dir, client) = serve(app);

    let e = within(client.inspect_container("web")).await.unwrap_err();
    match &e {
        Error::Api { status: 404, body } => {
            assert_eq!(body.kind, ErrorKind::NoSuchContainer);
            assert_eq!(body.message, "no such container: web");
        }
        other => panic!("{other:?}"),
    }
    assert!(e.is_not_found());
    // A name that isn't a path segment still reaches the route as one.
    let e = within(client.inspect_container("a/b c")).await.unwrap_err();
    assert_eq!(e.to_string(), "no such container: a/b c");
    let e = within(client.start("web")).await.unwrap_err();
    assert_eq!(e.kind().map(ErrorKind::cli_exit_code), Some(127));
}

/// What a mock route was sent, one line per request, for the test to
/// compare once the calls are done.
type Seen = Arc<Mutex<Vec<String>>>;

fn saw(seen: &Seen, what: String) {
    seen.lock().unwrap().push(what);
}

#[tokio::test]
async fn container_removal_takes_its_volumes_only_when_asked() {
    async fn remove(State(seen): State<Seen>, Path(id): Path<String>, Query(q): Query<RemoveQuery>) -> StatusCode {
        saw(&seen, format!("rm {id} force={} volumes={}", q.force, q.volumes));
        StatusCode::NO_CONTENT
    }
    let seen = Seen::default();
    let (_dir, client) =
        serve(Router::new().route(routes::pattern::CONTAINER, delete(remove)).with_state(seen.clone()));

    within(client.remove_container("web", true)).await.unwrap();
    within(client.remove_container_with("web", &RemoveQuery { force: false, volumes: true })).await.unwrap();
    assert_eq!(*seen.lock().unwrap(), ["rm web force=true volumes=false", "rm web force=false volumes=true"]);
}

#[tokio::test]
async fn network_routes() {
    async fn create(State(seen): State<Seen>, Json(config): Json<NetworkCreate>) -> Response {
        saw(&seen, format!("create {config:?}"));
        let created = NetworkCreateResponse { id: "1d".repeat(32), name: config.name };
        (StatusCode::CREATED, Json(created)).into_response()
    }
    async fn list() -> Json<Vec<Network>> {
        let network = |name: &str| Network { name: name.into(), driver: "bridge".into(), ..Network::default() };
        Json(vec![network("bridge"), network("backend")])
    }
    async fn inspect(Path(id): Path<String>) -> Response {
        if id != "backend" {
            return not_found(ErrorKind::NoSuchNetwork, &format!("no such network: {id}"));
        }
        let subnet = "10.89.1.0/24".to_owned();
        Json(Network { id: "1d".repeat(32), name: id, subnet, ..Network::default() }).into_response()
    }
    async fn remove(State(seen): State<Seen>, Path(id): Path<String>) -> StatusCode {
        saw(&seen, format!("rm {id}"));
        StatusCode::NO_CONTENT
    }
    async fn prune(State(seen): State<Seen>) -> Json<PruneResponse> {
        saw(&seen, "prune".into());
        Json(PruneResponse { deleted: vec!["old".into(), "test".into()], space_reclaimed: 0 })
    }
    let seen = Seen::default();
    let app = Router::new()
        .route(routes::pattern::NETWORKS, get(list).post(create))
        .route(routes::pattern::NETWORK, get(inspect).delete(remove))
        .route(routes::pattern::NETWORK_PRUNE, post(prune))
        .with_state(seen.clone());
    let (_dir, client) = serve(app);

    let config = NetworkCreate {
        name: "backend".into(),
        subnet: Some("10.89.1.0/24".into()),
        gateway: Some("10.89.1.1".into()),
        internal: true,
        labels: [("tier".to_owned(), "db".to_owned())].into(),
    };
    let created = within(client.create_network(&config)).await.unwrap();
    assert_eq!((created.id, created.name.as_str()), ("1d".repeat(32), "backend"));
    let names: Vec<String> = within(client.list_networks()).await.unwrap().into_iter().map(|n| n.name).collect();
    assert_eq!(names, ["bridge", "backend"]);
    assert_eq!(within(client.inspect_network("backend")).await.unwrap().subnet, "10.89.1.0/24");
    let e = within(client.inspect_network("front/end")).await.unwrap_err();
    assert!(e.is_not_found());
    assert_eq!((e.kind(), e.to_string().as_str()), (Some(ErrorKind::NoSuchNetwork), "no such network: front/end"));
    within(client.remove_network("backend")).await.unwrap();
    assert_eq!(within(client.prune_networks()).await.unwrap().deleted, ["old", "test"]);
    assert_eq!(*seen.lock().unwrap(), [format!("create {config:?}"), "rm backend".into(), "prune".into()]);
}

#[tokio::test]
async fn volume_routes() {
    async fn create(State(seen): State<Seen>, Json(config): Json<VolumeCreate>) -> Response {
        saw(&seen, format!("create {config:?}"));
        let name = config.name.unwrap_or_else(|| "a5".repeat(32));
        let volume = Volume { mountpoint: format!("/var/lib/rustlet/volumes/{name}/_data"), name, ..Volume::default() };
        (StatusCode::CREATED, Json(volume)).into_response()
    }
    async fn list() -> Json<Vec<Volume>> {
        Json(vec![Volume { name: "data".into(), driver: "local".into(), ..Volume::default() }])
    }
    async fn inspect(Path(name): Path<String>) -> Response {
        match name.as_str() {
            "data" => Json(Volume { name, containers: vec!["web".into()], ..Volume::default() }).into_response(),
            _ => not_found(ErrorKind::NoSuchVolume, &format!("no such volume: {name}")),
        }
    }
    async fn remove(
        State(seen): State<Seen>,
        Path(name): Path<String>,
        Query(q): Query<VolumeRemoveQuery>,
    ) -> StatusCode {
        saw(&seen, format!("rm {name} force={}", q.force));
        StatusCode::NO_CONTENT
    }
    async fn prune(State(seen): State<Seen>, Query(q): Query<VolumePruneQuery>) -> Json<PruneResponse> {
        saw(&seen, format!("prune all={}", q.all));
        Json(PruneResponse { deleted: vec!["cache".into()], space_reclaimed: 4096 })
    }
    let seen = Seen::default();
    let app = Router::new()
        .route(routes::pattern::VOLUMES, get(list).post(create))
        .route(routes::pattern::VOLUME, get(inspect).delete(remove))
        .route(routes::pattern::VOLUME_PRUNE, post(prune))
        .with_state(seen.clone());
    let (_dir, client) = serve(app);

    let named = VolumeCreate { name: Some("data".into()), labels: [("k".to_owned(), String::new())].into() };
    assert_eq!(within(client.create_volume(&named)).await.unwrap().mountpoint, "/var/lib/rustlet/volumes/data/_data");
    let anonymous = within(client.create_volume(&VolumeCreate::default())).await.unwrap();
    assert_eq!(anonymous.name, "a5".repeat(32));
    assert_eq!(within(client.list_volumes()).await.unwrap()[0].driver, "local");
    assert_eq!(within(client.inspect_volume("data")).await.unwrap().containers, ["web"]);
    let e = within(client.inspect_volume("my data")).await.unwrap_err();
    assert_eq!((e.kind(), e.to_string().as_str()), (Some(ErrorKind::NoSuchVolume), "no such volume: my data"));
    within(client.remove_volume("data", false)).await.unwrap();
    within(client.remove_volume("gone", true)).await.unwrap();
    let pruned = within(client.prune_volumes(true)).await.unwrap();
    assert_eq!((pruned.deleted.as_slice(), pruned.space_reclaimed), (&["cache".to_owned()][..], 4096));
    within(client.prune_volumes(false)).await.unwrap();
    assert_eq!(
        *seen.lock().unwrap(),
        [
            format!("create {named:?}"),
            format!("create {:?}", VolumeCreate::default()),
            "rm data force=false".into(),
            "rm gone force=true".into(),
            "prune all=true".into(),
            "prune all=false".into(),
        ]
    );
}

#[tokio::test]
async fn ndjson_arrives_line_by_line_and_ends_with_its_error() {
    // The second line is split across two chunks, and its second half is
    // only sent once the client has the first entry: that only works if
    // entries are handed out as they arrive.
    struct Gate(Mutex<Option<oneshot::Receiver<()>>>);
    async fn logs(State(gate): State<Arc<Gate>>, Query(q): Query<LogsQuery>) -> Response {
        assert!(q.follow && q.stdout && q.stderr);
        assert_eq!(q.tail, Some(2));
        let opened = gate.0.lock().unwrap().take().unwrap();
        let (tx, rx) = mpsc::channel::<Result<Bytes, std::io::Error>>(4);
        tokio::spawn(async move {
            let one = "{\"ts\":\"1\",\"stream\":\"stdout\",\"log\":\"one\\n\"}\n{\"ts\":\"2\",\"str";
            tx.send(Ok(Bytes::from(one))).await.unwrap();
            opened.await.unwrap();
            tx.send(Ok(Bytes::from("eam\":\"stderr\",\"log\":\"two\\n\"}\n\n"))).await.unwrap();
            tx.send(Ok(Bytes::from("{\"error\":\"the log file was rotated away\"}\n"))).await.unwrap();
        });
        let body = futures::stream::unfold(rx, |mut rx| async move { rx.recv().await.map(|chunk| (chunk, rx)) });
        ([(header::CONTENT_TYPE, rustlet_spec::NDJSON)], Body::from_stream(body)).into_response()
    }
    let (open, opened) = oneshot::channel();
    let gate = Arc::new(Gate(Mutex::new(Some(opened))));
    let app = Router::new().route(&routes::pattern::container_action("logs"), get(logs)).with_state(gate);
    let (_dir, client) = serve(app);

    let query = LogsQuery { follow: true, tail: Some(2), ..LogsQuery::default() };
    let mut entries = within(client.logs("web", &query)).await.unwrap();
    let first = within(entries.next()).await.unwrap().unwrap();
    assert_eq!((first.stream, first.log.as_str()), (LogStream::Stdout, "one\n"));
    open.send(()).unwrap();
    let second = within(entries.next()).await.unwrap().unwrap();
    assert_eq!((second.ts.as_str(), second.stream, second.log.as_str()), ("2", LogStream::Stderr, "two\n"));
    match within(entries.next()).await {
        Some(Err(Error::Stream(m))) => assert_eq!(m, "the log file was rotated away"),
        other => panic!("{other:?}"),
    }
    assert!(within(entries.next()).await.is_none());
}

#[tokio::test]
async fn dropping_a_stream_hangs_up() {
    // An endless stream (`events`): the only way to end it is to drop it,
    // and the daemon must see that, or it would feed a dead client forever.
    type Closed = Arc<Mutex<Option<oneshot::Sender<()>>>>;
    async fn events(State(closed): State<Closed>) -> Response {
        let (tx, rx) = mpsc::channel::<Result<Bytes, std::io::Error>>(1);
        let closed = closed.lock().unwrap().take().unwrap();
        tokio::spawn(async move {
            let line = "{\"time\":\"t\",\"kind\":\"container\",\"action\":\"start\",\"id\":\"x\"}\n";
            tx.send(Ok(Bytes::from(line))).await.unwrap();
            // Resolves once the server has dropped the body: the client is gone.
            tx.closed().await;
            closed.send(()).unwrap();
        });
        let body = futures::stream::unfold(rx, |mut rx| async move { rx.recv().await.map(|chunk| (chunk, rx)) });
        ([(header::CONTENT_TYPE, rustlet_spec::NDJSON)], Body::from_stream(body)).into_response()
    }
    let (tx, rx) = oneshot::channel();
    let app = Router::new().route(routes::pattern::EVENTS, get(events)).with_state(Arc::new(Mutex::new(Some(tx))));
    let (_dir, client) = serve(app);

    let mut events = within(client.events(&Default::default())).await.unwrap();
    assert_eq!(within(events.next()).await.unwrap().unwrap().action, "start");
    drop(events);
    within(rx).await.unwrap();
}

#[tokio::test]
async fn a_failed_pull_ends_with_an_err() {
    async fn pull(Query(q): Query<PullQuery>) -> Response {
        assert_eq!((q.reference.as_str(), q.policy), ("docker.io/library/alpine:latest", PullPolicy::Always));
        let events = [
            PullEvent::Resolving { reference: q.reference.clone() },
            PullEvent::Error { message: "registry: 429 Too Many Requests".into() },
        ];
        let body: String = events.iter().map(|e| serde_json::to_string(e).unwrap() + "\n").collect();
        ([(header::CONTENT_TYPE, rustlet_spec::NDJSON)], body).into_response()
    }
    let (_dir, client) = serve(Router::new().route(routes::pattern::IMAGE_PULL, post(pull)));

    let events: Vec<_> =
        within(within(client.pull("docker.io/library/alpine:latest", PullPolicy::Always)).await.unwrap().collect())
            .await;
    assert!(matches!(&events[0], Ok(PullEvent::Resolving { .. })), "{events:?}");
    assert!(matches!(&events[1], Err(Error::Stream(m)) if m == "registry: 429 Too Many Requests"), "{events:?}");
    assert_eq!(events.len(), 2);
}

#[tokio::test]
async fn exec_create_and_detached_start() {
    async fn create(Path(id): Path<String>, Json(config): Json<ExecConfig>) -> Response {
        assert_eq!((id.as_str(), config.cmd.as_slice(), config.tty), ("web", &["ls".to_owned()][..], true));
        (StatusCode::CREATED, Json(ExecCreated { id: "e1".into() })).into_response()
    }
    let app = Router::new().route(&routes::pattern::container_action("exec"), post(create)).route(
        routes::pattern::EXEC_START,
        post(|Path(id): Path<String>| async move {
            assert_eq!(id, "e1");
            Json(ExecStarted { pid: 4242 })
        }),
    );
    let (_dir, client) = serve(app);

    let config = ExecConfig { cmd: vec!["ls".into()], tty: true, ..ExecConfig::default() };
    let created = within(client.create_exec("web", &config)).await.unwrap();
    assert_eq!(within(client.start_exec_detached(&created.id)).await.unwrap().pid, 4242);
}

/// What the attach route saw the client send.
#[derive(Debug, Default, PartialEq)]
struct Received {
    stdin: Vec<u8>,
    resizes: Vec<(u16, u16)>,
    eof: bool,
    /// The answer to the route's ping, which tungstenite sends by itself.
    pong: bool,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn websocket_sessions_carry_both_directions() {
    type Report = Arc<Mutex<Option<oneshot::Sender<Received>>>>;
    async fn attach(State(report): State<Report>, Query(q): Query<AttachQuery>, ws: WebSocketUpgrade) -> Response {
        assert!(q.stdin);
        ws.on_upgrade(move |socket| session(socket, report))
    }
    async fn session(mut socket: WebSocket, report: Report) {
        let data = |id, d: &[u8]| Message::Binary(stream::data_message(id, d).into());
        socket.send(data(stream::STDOUT, b"out")).await.unwrap();
        socket.send(Message::Ping(Bytes::from_static(b"are you there"))).await.unwrap();
        socket.send(data(stream::STDERR, b"err")).await.unwrap();
        let mut received = Received::default();
        // The pong too, before the exit and the close: a pong still queued
        // when the socket closes would fail the client's next read, the one
        // that would have read the exit.
        while !(received.eof && received.pong) {
            match socket.recv().await.unwrap().unwrap() {
                Message::Binary(b) => {
                    let (id, d) = stream::parse_data_message(&b).unwrap();
                    assert_eq!(id, stream::STDIN);
                    received.stdin.extend_from_slice(d);
                }
                Message::Text(t) => match serde_json::from_str(&t).unwrap() {
                    Control::Resize { rows, cols } => received.resizes.push((rows, cols)),
                    Control::StdinEof => received.eof = true,
                    other => panic!("{other:?}"),
                },
                Message::Pong(_) => received.pong = true,
                other => panic!("{other:?}"),
            }
        }
        report.lock().unwrap().take().unwrap().send(received).unwrap();
        let exit = Control::Exit { code: 7, oom_killed: true };
        socket.send(Message::Text(serde_json::to_string(&exit).unwrap().into())).await.unwrap();
        let _ = socket.close().await;
    }
    let (tx, rx) = oneshot::channel();
    let app = Router::new()
        .route(&routes::pattern::container_action("attach"), get(attach))
        .with_state(Arc::new(Mutex::new(Some(tx))));
    let (_dir, client) = serve(app);

    let session = within(client.attach("web", true)).await.unwrap();
    let (mut sender, mut receiver) = session.split();
    let input = tokio::spawn(async move {
        sender.resize(24, 80).await.unwrap();
        sender.send_stdin(b"hello ").await.unwrap();
        sender.send_stdin(b"").await.unwrap();
        sender.send_stdin(b"world").await.unwrap();
        sender.resize(50, 132).await.unwrap();
        sender.stdin_eof().await.unwrap();
    });
    let mut events = Vec::new();
    while let Some(event) = within(receiver.recv()).await.unwrap() {
        events.push(event);
    }
    within(input).await.unwrap();
    assert_eq!(
        events,
        [
            SessionEvent::Stdout(Bytes::from_static(b"out")),
            SessionEvent::Stderr(Bytes::from_static(b"err")),
            SessionEvent::Exit { code: 7, oom_killed: true },
        ]
    );
    let received = within(rx).await.unwrap();
    let expected =
        Received { stdin: b"hello world".to_vec(), resizes: vec![(24, 80), (50, 132)], eof: true, pong: true };
    assert_eq!(received, expected);
}

#[tokio::test]
async fn sessions_report_errors_and_early_closes() {
    async fn attach(Path(id): Path<String>, ws: WebSocketUpgrade) -> Response {
        match id.as_str() {
            "gone" => not_found(ErrorKind::NoSuchContainer, "no such container: gone"),
            "fails" => ws.on_upgrade(|mut socket| async move {
                let error = Control::Error { message: "exec failed".into(), kind: ErrorKind::CommandNotExecutable };
                socket.send(Message::Text(serde_json::to_string(&error).unwrap().into())).await.unwrap();
                let _ = socket.close().await;
            }),
            _ => ws.on_upgrade(|mut socket| async move {
                socket.send(Message::Binary(stream::data_message(stream::STDOUT, b"bye").into())).await.unwrap();
                let _ = socket.close().await;
            }),
        }
    }
    let (_dir, client) = serve(Router::new().route(&routes::pattern::container_action("attach"), get(attach)));

    // A refused upgrade is the daemon's error, like any other response.
    let e = within(client.attach("gone", false)).await.unwrap_err();
    assert_eq!((e.kind(), e.to_string().as_str()), (Some(ErrorKind::NoSuchContainer), "no such container: gone"));

    let mut session = within(client.attach("fails", false)).await.unwrap();
    let event = within(session.recv()).await.unwrap();
    assert_eq!(
        event,
        Some(SessionEvent::Error { message: "exec failed".into(), kind: ErrorKind::CommandNotExecutable })
    );
    assert_eq!(within(session.recv()).await.unwrap(), None);

    // Closed with no exit status: the caller must not invent one.
    let mut session = within(client.attach("closes", false)).await.unwrap();
    assert_eq!(within(session.recv()).await.unwrap(), Some(SessionEvent::Stdout(Bytes::from_static(b"bye"))));
    let e = within(session.recv()).await.unwrap_err();
    assert!(matches!(e, Error::Protocol(_)), "{e:?}");
    assert_eq!(within(session.recv()).await.unwrap(), None);
}

#[tokio::test]
async fn a_missing_socket_says_the_daemon_isnt_running() {
    let dir = tempfile::tempdir().unwrap();
    let client = Client::new(dir.path().join("rustlet.sock"));
    let e = client.version().await.unwrap_err();
    assert!(matches!(e, Error::Connect { .. }), "{e:?}");
    let message = e.to_string();
    assert!(message.contains(&dir.path().join("rustlet.sock").display().to_string()), "{message}");
    assert!(message.contains("is rustletd running?"), "{message}");
    // Sessions connect the same way.
    assert!(matches!(client.attach("web", false).await.unwrap_err(), Error::Connect { .. }));
}

#[tokio::test]
async fn a_line_that_never_ends_is_refused() {
    async fn logs() -> Response {
        let chunk = Bytes::from(vec![b'x'; 1 << 20]);
        let body = futures::stream::iter((0..17).map(move |_| Ok::<_, std::io::Error>(chunk.clone())))
            .chain(futures::stream::pending());
        ([(header::CONTENT_TYPE, rustlet_spec::NDJSON)], Body::from_stream(body)).into_response()
    }
    let (_dir, client) = serve(Router::new().route(&routes::pattern::container_action("logs"), get(logs)));
    let mut entries = within(client.logs("web", &LogsQuery::default())).await.unwrap();
    assert!(matches!(within(entries.next()).await, Some(Err(Error::Protocol(_)))));
    assert!(within(entries.next()).await.is_none());
}

#[tokio::test]
async fn nothing_is_read_after_an_error_line() {
    async fn logs() -> Response {
        let body = "{\"error\":\"gone\"}\n{\"ts\":\"t\",\"stream\":\"stdout\",\"log\":\"after\\n\"}\n";
        ([(header::CONTENT_TYPE, rustlet_spec::NDJSON)], body).into_response()
    }
    let (_dir, client) = serve(Router::new().route(&routes::pattern::container_action("logs"), get(logs)));
    let entries: Vec<_> = within(within(client.logs("web", &LogsQuery::default())).await.unwrap().collect()).await;
    assert_eq!(entries.len(), 1, "{entries:?}");
    assert!(matches!(&entries[0], Err(Error::Stream(m)) if m == "gone"));
}

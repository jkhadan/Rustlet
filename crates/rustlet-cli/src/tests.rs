//! Whole commands, run in-process as `main` runs them (parsed command
//! line, [`run_cli`], exit code), against a mock daemon: an axum server on
//! a temporary Unix socket that records the calls it gets and answers like
//! rustletd would.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use clap::Parser;
use futures::StreamExt;
use rustlet_spec::container::{
    AttachQuery, ContainerConfig, ContainerState, ContainerStatus, ContainerSummary, CreateResponse, KillQuery,
    StopQuery, WaitQuery, WaitResponse,
};
use rustlet_spec::exec::{ExecConfig, ExecCreated};
use rustlet_spec::image::{BlobKind, ImageSummary, PullEvent, PullQuery};
use rustlet_spec::logs::{LogEntry, LogStream, LogsQuery};
use rustlet_spec::routes::pattern;
use rustlet_spec::stats::{StatsQuery, StatsSample};
use rustlet_spec::stream::{self, Control};
use rustlet_spec::system::Info;
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

async fn remove(State(d): Shared, Path(id): Path<String>) -> StatusCode {
    d.call(format!("rm {}", rustlet_spec::short_id(&id)));
    StatusCode::NO_CONTENT
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
    Json(Info { memory: 2 << 30, ..Info::default() })
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

/// Serves a mock daemon; returns it, the `-H` value that reaches it, and
/// the directory guard.
fn daemon() -> (Arc<Daemon>, String, tempfile::TempDir) {
    let d = Arc::new(Daemon::default());
    let app = Router::new()
        .route(pattern::CONTAINERS, post(create).get(list))
        .route(pattern::CONTAINER, delete(remove))
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
        .route(pattern::INFO, get(info))
        .with_state(d.clone());
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("rustlet.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (d, format!("unix://{}", socket.display()), dir)
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
    // With --rm, a container that never ran is removed right away.
    assert_eq!(d.calls().last().unwrap(), &format!("rm {}", rustlet_spec::short_id(ID)));
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
    let expected = "\
CONTAINER ID   IMAGE        COMMAND                  CREATED          STATUS                     NAMES
bbbbbbbbbbbb   nginx:1.27   \"/docker-entrypoint.…\"   10 minutes ago   Up 5 minutes               web
aaaaaaaaaaaa   alpine       \"sleep 1000\"             2 hours ago      Exited (0) 3 minutes ago   old
";
    assert_eq!(stdout.text(), expected);
    let (_, stdout, _) = rustlet(&host, &["ps", "-q", "--no-trunc"], b"").await;
    assert_eq!(stdout.text(), format!("{}\n{}\n", "b".repeat(64), "a".repeat(64)));
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

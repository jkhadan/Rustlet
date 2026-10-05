//! Review tests for Phase 7's CLI: whole commands run in-process (parsed
//! command line, `run_cli_with`, exit code) against small axum mock
//! daemons on temporary Unix sockets, as `tests.rs` does.

use std::io::{self, Read};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Json;
use axum::Router;
use axum::body::Body;
use axum::extract::{Query, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use bytes::Bytes;
use clap::Parser;
use futures::StreamExt;
use rustlet_build::context::{ContextError, Packed};
use rustlet_spec::build::{BuildEvent, BuildOptions, BuildQuery};
use rustlet_spec::container::{ContainerConfig, CreateResponse, HealthConfig};
use rustlet_spec::image::{ImageSaveRequest, LoadEvent};
use rustlet_spec::routes::pattern;
use rustlet_spec::{ErrorBody, ErrorKind};
use tokio::net::UnixListener;

use crate::build::Packer;
use crate::console::Console;
use crate::console::testing::{Buffer, console};
use crate::{Cli, run_cli_with};

const IMAGE_ID: &str = "sha256:3c4d5e6f7a8b00112233445566778899aabbccddeeff00112233445566778899";

/// How often the timing-dependent tests repeat what they check: a daemon
/// that answers while a 32 MiB context is still being sent loses the race
/// against the client's next write in a fifth to a half of the runs here.
const RACE_RUNS: usize = 40;

/// Serves `app`; returns the `-H` value that reaches it, and the directory
/// guard.
fn serve(app: Router) -> (String, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("rustlet.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("unix://{}", socket.display()), dir)
}

fn parse(host: &str, args: &[&str]) -> Cli {
    Cli::try_parse_from(["rustlet", "-H", host].into_iter().chain(args.iter().copied())).unwrap()
}

/// Runs `rustlet -H host args…` on `console` with `packer`; the exit code.
async fn rustlet_on(host: &str, args: &[&str], console: Console, packer: Packer) -> i32 {
    tokio::time::timeout(Duration::from_secs(20), run_cli_with(parse(host, args), console, packer)).await.expect("hung")
}

/// Runs `rustlet -H host args…` with nothing on stdin; the exit code and
/// what it printed.
async fn rustlet(host: &str, args: &[&str], packer: Packer) -> (i32, Buffer, Buffer) {
    let (console, stdout, stderr) = console(b"");
    (rustlet_on(host, args, console, packer).await, stdout, stderr)
}

/// Packs a few bytes: the "archive" names the context.
fn small_packer() -> Packer {
    Packer {
        default_containerfile: |dir| Some(dir.join("Containerfile")),
        dockerfile_name: |_, _| Ok("Containerfile".into()),
        pack: |context, _, out| {
            let io = |source| ContextError::Io { path: context.to_owned(), source };
            out.write_all(b"a small context").map_err(io)?;
            Ok(Packed { dockerfile: "Containerfile".into(), entries: 1, bytes: 15, excluded: 0 })
        },
    }
}

/// Packs 32 MiB: a real project's context, larger than the socket's
/// buffers, so it is still being sent when the daemon answers.
fn big_packer() -> Packer {
    Packer {
        pack: |context, _, out| {
            let io = |source| ContextError::Io { path: context.to_owned(), source };
            let block = vec![0u8; 64 * 1024];
            for _ in 0..512 {
                out.write_all(&block).map_err(io)?;
            }
            Ok(Packed { dockerfile: "Containerfile".into(), entries: 1, bytes: 32 << 20, excluded: 0 })
        },
        ..small_packer()
    }
}

fn closed_upload(code: i32, stderr: &str) -> bool {
    code == 125
        && stderr
            == "rustlet: error: connection to rustletd: the daemon closed the connection while the request's body was still being sent (it refused or failed the request: see rustletd's log)\n"
}

fn error(kind: ErrorKind, message: &str) -> Response {
    (StatusCode::from_u16(kind.status()).unwrap(), Json(ErrorBody::new(kind, message))).into_response()
}

fn ndjson<T: serde::Serialize>(items: &[T]) -> Response {
    let body: String = items.iter().map(|i| serde_json::to_string(i).unwrap() + "\n").collect();
    ([(header::CONTENT_TYPE, rustlet_spec::NDJSON)], Body::from(body)).into_response()
}

/// What rustletd's build and load do when they fail on the body they are
/// reading (a full disk, a corrupt blob): the response's head is out at
/// once, the task reads the body for a while (30 ms of an upload that takes
/// longer), then drops it and ends the stream with `last`, an error line.
fn failing_while_reading<T: serde::Serialize + Send + 'static>(body: Body, last: T) -> Response {
    let (tx, rx) = futures::channel::mpsc::unbounded::<Result<Bytes, io::Error>>();
    tokio::spawn(async move {
        let mut data = body.into_data_stream();
        let reading = async { while data.next().await.is_some() {} };
        let _ = tokio::time::timeout(Duration::from_millis(30), reading).await;
        drop(data);
        let _ = tx.unbounded_send(Ok(Bytes::from(serde_json::to_string(&last).unwrap() + "\n")));
    });
    ([(header::CONTENT_TYPE, rustlet_spec::NDJSON)], Body::from_stream(rx)).into_response()
}

/// An early refusal preserves the daemon's reason or reports that it
/// closed the connection during upload. Both paths fail with 125 and stop
/// packing; neither leaves a generic HTTP connection error.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn review_build_refused_before_its_context_was_read_says_why() {
    async fn build(Query(_q): Query<BuildQuery>) -> Response {
        error(ErrorKind::Invalid, "-t \"MyApp\": repository name must be lowercase")
    }
    let (host, _dir) = serve(Router::new().route(pattern::BUILD, post(build)));
    let context = tempfile::tempdir().unwrap();
    let mut wrong = Vec::new();
    for _ in 0..RACE_RUNS {
        let (code, _, stderr) =
            rustlet(&host, &["build", "-t", "MyApp", context.path().to_str().unwrap()], big_packer()).await;
        let stderr = stderr.text();
        if (code, stderr.as_str()) != (125, "rustlet: error: -t \"MyApp\": repository name must be lowercase\n")
            && !closed_upload(code, &stderr)
        {
            wrong.push((code, stderr));
        }
    }
    assert!(wrong.is_empty(), "{} of {RACE_RUNS} runs didn't say why, e.g. {:?}", wrong.len(), wrong[0]);
}

/// A failed build yields its streamed error and exit 1 when that line
/// arrives; an interrupted connection yields the upload diagnostic and
/// exit 125. Neither path claims a successful build.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn review_build_failing_while_its_context_is_sent_shows_the_daemons_message() {
    async fn build(Query(_q): Query<BuildQuery>, body: Body) -> Response {
        let message = "the build context: no space left on device".into();
        failing_while_reading(body, BuildEvent::Error { message })
    }
    let (host, _dir) = serve(Router::new().route(pattern::BUILD, post(build)));
    let context = tempfile::tempdir().unwrap();
    let mut wrong = Vec::new();
    for _ in 0..RACE_RUNS {
        let (code, _, stderr) = rustlet(&host, &["build", context.path().to_str().unwrap()], big_packer()).await;
        let stderr = stderr.text();
        if (code, stderr.as_str()) != (1, "rustlet: error: the build context: no space left on device\n")
            && !closed_upload(code, &stderr)
        {
            wrong.push((code, stderr));
        }
    }
    assert!(wrong.is_empty(), "{} of {RACE_RUNS} runs lost the daemon's message, e.g. {:?}", wrong.len(), wrong[0]);
}

/// Options larger than the HTTP URI limit are refused before packing or
/// connecting, with the largest argument identified for the user.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn review_build_with_a_70kb_build_arg_is_refused_clearly() {
    async fn build(Query(q): Query<BuildQuery>, body: Body) -> Response {
        let _ = axum::body::to_bytes(body, usize::MAX).await;
        let o = q.options().unwrap();
        ndjson(&[BuildEvent::Done { id: IMAGE_ID.into(), names: vec![format!("{} bytes", o.build_args["CA"].len())] }])
    }
    let (host, _dir) = serve(Router::new().route(pattern::BUILD, post(build)));
    let context = tempfile::tempdir().unwrap();
    let ca = format!("CA={}", "x".repeat(70_000));
    let (code, stdout, stderr) =
        rustlet(&host, &["build", "-q", "--build-arg", &ca, context.path().to_str().unwrap()], small_packer()).await;
    assert_eq!((code, stdout.text()), (125, String::new()));
    assert!(stderr.text().contains("holds at most 65534"), "{}", stderr.text());
    assert!(stderr.text().contains("build arg \"CA\""), "{}", stderr.text());
}

/// Expected (config.rs: "`--health-*` and `--no-healthcheck`, as Docker's
/// CLI reads them"): Docker's CLI counts a `--health-*` option as given
/// only when it isn't zero or empty (`haveHealthSettings := copts.healthCmd
/// != "" || copts.healthInterval != 0 || … || copts.healthRetries != 0`,
/// cli/command/container/opts.go), so `--no-healthcheck --health-retries 0`
/// (or `--health-cmd ""`, `--health-interval 0s`) is a plain
/// `--no-healthcheck`, not a conflict.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn review_no_healthcheck_with_zero_valued_health_options_is_no_conflict() {
    async fn create(State(seen): State<Arc<Mutex<Vec<ContainerConfig>>>>, Json(c): Json<ContainerConfig>) -> Response {
        seen.lock().unwrap().push(c);
        let created = CreateResponse { id: "0123456789ab".into(), name: "x".into(), warnings: vec![] };
        (StatusCode::CREATED, Json(created)).into_response()
    }
    let seen: Arc<Mutex<Vec<ContainerConfig>>> = Arc::default();
    let (host, _dir) = serve(Router::new().route(pattern::CONTAINERS, post(create)).with_state(seen.clone()));
    for zero in [&["--health-retries", "0"][..], &["--health-interval", "0s"], &["--health-cmd", ""]] {
        let args = [&["create", "--no-healthcheck"][..], zero, &["nginx"]].concat();
        let (code, _, stderr) = rustlet(&host, &args, small_packer()).await;
        assert_eq!(code, 0, "{args:?}: {}", stderr.text());
    }
    let off = HealthConfig { test: vec!["NONE".into()], ..HealthConfig::default() };
    assert!(seen.lock().unwrap().iter().all(|c| c.healthcheck.as_ref() == Some(&off)));
}

/// Expected (images.rs: "renamed to `path` once it is whole (as Docker's
/// CLI does)"): Docker's CLI writes `save -o`'s archive through
/// `os.CreateTemp` (mode 0600) and renames it, so the archive, which can
/// hold whatever the image's layers and config hold (keys, build args), is
/// readable by its owner only. Here the partial file is created with the
/// default 0666 less the umask: world-readable.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn review_save_output_is_readable_by_its_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    async fn save(Json(_r): Json<ImageSaveRequest>) -> Response {
        ([(header::CONTENT_TYPE, "application/x-tar")], Body::from("an archive")).into_response()
    }
    let (host, dir) = serve(Router::new().route(pattern::IMAGE_SAVE, post(save)));
    let out = dir.path().join("app.tar");
    let (code, _, stderr) = rustlet(&host, &["save", "-o", out.to_str().unwrap(), "app"], small_packer()).await;
    assert_eq!(code, 0, "{}", stderr.text());
    let mode = std::fs::metadata(&out).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode & 0o077, 0, "the archive is {mode:o}");
}

/// Input that fails after its first part: a file on a failing disk, a pipe
/// whose writer died. Its error comes once the request is under way.
struct FailingInput {
    sent: usize,
}

impl Read for FailingInput {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.sent >= 256 * 1024 {
            std::thread::sleep(Duration::from_millis(300));
            return Err(io::Error::other("Input/output error"));
        }
        let n = buf.len().min(256 * 1024 - self.sent);
        buf[..n].fill(7);
        self.sent += n;
        Ok(n)
    }
}

/// Expected (build.rs module docs: "A context that can't be packed (a file
/// that can't be read) is reported as that ... whatever the daemon made of
/// the body cut short"; body.rs: `abort` "Ends the body with an error: the
/// request fails"): `load` whose input fails partway (a file on a failing
/// disk, a flaky network mount) says the input failed, with its error, as
/// `build` does for its context. rustletd answers `load` at once (NDJSON)
/// and reads the archive as it comes, as this mock does; once the head is
/// in, the aborted body only shows as "error reading a body from
/// connection: connection error", which hides the cause.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn review_load_whose_input_fails_says_so() {
    async fn load(body: Body) -> Response {
        let (mut tx, rx) = futures::channel::mpsc::channel::<Result<Bytes, io::Error>>(4);
        tokio::spawn(async move {
            let mut data = body.into_data_stream();
            let last = loop {
                match data.next().await {
                    Some(Ok(_)) => {}
                    Some(Err(e)) => break LoadEvent::Error { message: format!("read the archive: {e}") },
                    None => break LoadEvent::Loaded { id: IMAGE_ID.into(), name: None },
                }
            };
            let line = serde_json::to_string(&last).unwrap() + "\n";
            let _ = futures::SinkExt::send(&mut tx, Ok(Bytes::from(line))).await;
        });
        ([(header::CONTENT_TYPE, rustlet_spec::NDJSON)], Body::from_stream(rx)).into_response()
    }
    let (host, _dir) = serve(Router::new().route(pattern::IMAGE_LOAD, post(load)));
    let (stdout, stderr) = (Buffer::default(), Buffer::default());
    let console = Console {
        stdin: Some(Box::new(FailingInput { sent: 0 })),
        stdout: Box::new(stdout.clone()),
        stderr: Box::new(stderr.clone()),
        stdin_tty: false,
        stdout_tty: false,
        stderr_tty: false,
    };
    let code = rustlet_on(&host, &["load"], console, small_packer()).await;
    let stderr = stderr.text();
    assert_eq!(code, 125, "{stderr}");
    assert!(stderr.contains("Input/output error"), "the input's failure isn't named: {stderr:?}");
}

/// A failed load during upload preserves its reason when available, or
/// reports the interrupted upload. Both paths fail with 125.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn review_load_failing_partway_through_its_archive_says_why() {
    async fn load(body: Body) -> Response {
        failing_while_reading(
            body,
            LoadEvent::Error { message: "read the archive: numeric field was not a number".into() },
        )
    }
    let (host, _dir) = serve(Router::new().route(pattern::IMAGE_LOAD, post(load)));
    let mut wrong = Vec::new();
    for _ in 0..RACE_RUNS {
        let (console, _, stderr) = console(&vec![0x1f; 32 << 20]);
        let code = rustlet_on(&host, &["load"], console, small_packer()).await;
        let stderr = stderr.text();
        if (code, stderr.as_str()) != (125, "rustlet: error: read the archive: numeric field was not a number\n")
            && !closed_upload(code, &stderr)
        {
            wrong.push((code, stderr));
        }
    }
    assert!(wrong.is_empty(), "{} of {RACE_RUNS} runs didn't say why, e.g. {:?}", wrong.len(), wrong[0]);
}

/// Expected (Docker's CLI, cli/command/image/build/context.go,
/// `getDockerfileRelPath`: without `-f`, "look for 'dockerfile' too but
/// only use it if we found it"): `build DIR` whose Containerfile is a
/// lowercase `dockerfile` builds it, as `docker build DIR` does.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn review_build_finds_a_lowercase_dockerfile() {
    async fn build(Query(q): Query<BuildQuery>, body: Body) -> Response {
        let _ = axum::body::to_bytes(body, usize::MAX).await;
        let o = q.options().unwrap();
        ndjson(&[BuildEvent::Done { id: IMAGE_ID.into(), names: o.dockerfile.into_iter().collect() }])
    }
    let (host, _dir) = serve(Router::new().route(pattern::BUILD, post(build)));
    let context = tempfile::tempdir().unwrap();
    std::fs::write(context.path().join("dockerfile"), "FROM scratch\n").unwrap();
    let (code, stdout, stderr) =
        rustlet(&host, &["build", "-q", context.path().to_str().unwrap()], Packer::real()).await;
    assert_eq!((code, stdout.text()), (0, format!("{IMAGE_ID}\n")), "{}", stderr.text());
}

/// Checked, holds: the build options the CLI sends for repeated `-t` and
/// `--label`, and `--build-arg NAME` taking this shell's value (Docker's
/// `ValidateEnv`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn review_build_options_reach_the_daemon_as_given() {
    async fn build(
        State(seen): State<Arc<Mutex<Vec<BuildOptions>>>>,
        Query(q): Query<BuildQuery>,
        body: Body,
    ) -> Response {
        let _ = axum::body::to_bytes(body, usize::MAX).await;
        seen.lock().unwrap().push(q.options().unwrap());
        ndjson(&[BuildEvent::Done { id: IMAGE_ID.into(), names: vec![] }])
    }
    let seen: Arc<Mutex<Vec<BuildOptions>>> = Arc::default();
    let (host, _dir) = serve(Router::new().route(pattern::BUILD, post(build)).with_state(seen.clone()));
    let context = tempfile::tempdir().unwrap();
    let args = [
        "build",
        "-t",
        "a",
        "-t",
        "b:1",
        "--label",
        "k=1",
        "--label",
        "k=2",
        "--label",
        "solo",
        "--build-arg",
        "HOME",
        context.path().to_str().unwrap(),
    ];
    let (code, _, stderr) = rustlet(&host, &args, small_packer()).await;
    assert_eq!(code, 0, "{}", stderr.text());
    let o = seen.lock().unwrap()[0].clone();
    assert_eq!(o.tags, ["a", "b:1"]);
    assert_eq!(o.labels, [("k".to_owned(), "2".to_owned()), ("solo".to_owned(), String::new())].into());
    assert_eq!(o.build_args.get("HOME"), std::env::var("HOME").ok().as_ref());
}

/// The CLI parser rejects durations that overflow signed nanoseconds,
/// before any daemon request can be made.
#[test]
fn review_health_duration_beyond_int64_nanoseconds_is_refused() {
    let error = Cli::try_parse_from(["rustlet", "create", "--health-interval", "3000000h", "nginx"]).unwrap_err();
    assert!(error.to_string().contains("too long"), "{error}");
}

/// NDJSON as rustletd writes it, as the bytes of a response.
fn lines(events: &[BuildEvent]) -> Vec<u8> {
    events.iter().flat_map(|e| (serde_json::to_string(e).unwrap() + "\n").into_bytes()).collect()
}

/// A daemon whose `build` reads the whole context, then answers with
/// `answer` in pieces of `chunk` bytes, a millisecond apart.
fn build_answering(answer: Vec<u8>, chunk: usize) -> (String, tempfile::TempDir) {
    let answer = Arc::new(answer);
    let app = Router::new().route(
        pattern::BUILD,
        post(move |body: Body| {
            let answer = answer.clone();
            async move {
                let _ = axum::body::to_bytes(body, usize::MAX).await;
                let pieces: Vec<Bytes> = answer.chunks(chunk).map(Bytes::copy_from_slice).collect();
                let stream = futures::stream::iter(pieces).then(|piece| async move {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                    Ok::<_, io::Error>(piece)
                });
                ([(header::CONTENT_TYPE, rustlet_spec::NDJSON)], Body::from_stream(stream)).into_response()
            }
        }),
    );
    serve(app)
}

fn step_events(output: &str) -> Vec<BuildEvent> {
    vec![
        BuildEvent::Context { files: 1, bytes: 2048 },
        BuildEvent::Step { step: 1, total: 1, instruction: "RUN echo hi".into() },
        BuildEvent::Output { step: 1, stream: rustlet_spec::logs::LogStream::Stdout, text: output.into() },
        BuildEvent::StepDone { step: 1, layer: None },
    ]
}

/// Checked, holds (ndjson.rs: "HTTP framing has nothing to do with line
/// boundaries"): a build's events split at every 7th byte of the response
/// (halfway through lines and through multi-byte text) come out as the
/// same build.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn review_build_events_split_across_chunks_arrive_whole() {
    let mut events = step_events("h\u{e9}llo \u{1f600}\n");
    events.push(BuildEvent::Done { id: IMAGE_ID.into(), names: vec![] });
    let (host, _dir) = build_answering(lines(&events), 7);
    let context = tempfile::tempdir().unwrap();
    let (code, stdout, stderr) = rustlet(&host, &["build", context.path().to_str().unwrap()], small_packer()).await;
    assert_eq!(code, 0, "{}", stderr.text());
    assert_eq!(
        stdout.text(),
        "Sending build context to rustletd  2.048kB\nStep 1/1 : RUN echo hi\nh\u{e9}llo \u{1f600}\nSuccessfully built 3c4d5e6f7a8b\n"
    );
}

/// Checked, holds (build.rs `send`): a response that ends cleanly without
/// `done` or `error` (the daemon's build task died) is a failure, with 125
/// and what was shown ended on a line of its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn review_build_stream_that_ends_without_done_fails() {
    let (host, _dir) = build_answering(lines(&step_events("partial")), 4096);
    let context = tempfile::tempdir().unwrap();
    let (code, stdout, stderr) = rustlet(&host, &["build", context.path().to_str().unwrap()], small_packer()).await;
    assert_eq!(code, 125);
    assert_eq!(stderr.text(), "rustlet: error: the build ended without storing an image (did rustletd stop?)\n");
    assert!(stdout.text().ends_with("partial\n"), "{:?}", stdout.text());
}

/// Checked, holds: a line that isn't JSON in the middle of the stream ends
/// the build with 125 and an error naming the answer, after what came
/// before it was shown.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn review_build_garbage_in_the_stream_fails_with_125() {
    let mut answer = lines(&step_events("hi\n")[..2]);
    answer.extend_from_slice(b"this is not json\n");
    let (host, _dir) = build_answering(answer, 4096);
    let context = tempfile::tempdir().unwrap();
    let (code, stdout, stderr) = rustlet(&host, &["build", context.path().to_str().unwrap()], small_packer()).await;
    assert_eq!(code, 125);
    assert!(stderr.text().starts_with("rustlet: error: unexpected answer from rustletd: "), "{}", stderr.text());
    assert_eq!(stdout.text(), "Sending build context to rustletd  2.048kB\nStep 1/1 : RUN echo hi\n");
}

/// Checked, holds: a megabyte of output without a newline (one NDJSON
/// line of over a megabyte, far below the client's 16 MiB limit) is shown
/// whole.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn review_build_output_line_of_a_megabyte_arrives_whole() {
    let long = "x".repeat(1 << 20);
    let mut events = step_events(&long);
    events.push(BuildEvent::Done { id: IMAGE_ID.into(), names: vec![] });
    let (host, _dir) = build_answering(lines(&events), 64 * 1024);
    let context = tempfile::tempdir().unwrap();
    let (code, stdout, stderr) = rustlet(&host, &["build", context.path().to_str().unwrap()], small_packer()).await;
    assert_eq!(code, 0, "{}", stderr.text());
    let out = stdout.text();
    assert!(out.contains(&format!("{long}\nSuccessfully built 3c4d5e6f7a8b\n")), "{} bytes", out.len());
}

/// Checked, holds (images.rs: "one with none a `<none>` row"): an image
/// that a build left without a name is a `<none>` row of `images`, and its
/// id is in `images -q`, as Docker shows them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn review_images_lists_an_unnamed_image_as_none() {
    async fn images() -> Json<Vec<rustlet_spec::image::ImageSummary>> {
        Json(vec![rustlet_spec::image::ImageSummary {
            id: IMAGE_ID.into(),
            names: vec![],
            created: Some((chrono::Utc::now() - chrono::Duration::hours(3)).to_rfc3339()),
            size: 187_430_000,
            ..Default::default()
        }])
    }
    let (host, _dir) = serve(Router::new().route(pattern::IMAGES, axum::routing::get(images)));
    let (code, stdout, _) = rustlet(&host, &["images"], small_packer()).await;
    assert_eq!(code, 0);
    let rows: Vec<Vec<String>> =
        stdout.text().lines().map(|l| l.split_whitespace().map(str::to_owned).collect()).collect();
    assert_eq!(rows[0], ["REPOSITORY", "TAG", "IMAGE", "ID", "CREATED", "SIZE"]);
    assert_eq!(rows[1], ["<none>", "<none>", "3c4d5e6f7a8b", "3", "hours", "ago", "187MB"]);
    let (code, stdout, _) = rustlet(&host, &["images", "-q"], small_packer()).await;
    assert_eq!((code, stdout.text()), (0, "3c4d5e6f7a8b\n".to_owned()));
}

/// Checked, holds (Docker's `docker load -i DIR` fails with "read DIR: is a
/// directory"): `rustlet load -i DIR` names the cause. `File::open`
/// succeeds on a directory, the first read fails with EISDIR, and the body
/// is aborted with that error before the daemon has answered, so the
/// request's own error ("error from user's Body stream: Is a directory")
/// is what the command prints. (A failure after the daemon has started to
/// answer is not named: `review_load_whose_input_fails_says_so`.)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn review_load_of_a_directory_says_it_is_a_directory() {
    async fn load(body: Body) -> Response {
        let read = axum::body::to_bytes(body, usize::MAX).await;
        let last = match read {
            Ok(_) => {
                LoadEvent::Error { message: "not an image archive: it has neither index.json nor manifest.json".into() }
            }
            Err(e) => LoadEvent::Error { message: format!("read the archive: {e}") },
        };
        ndjson(&[last])
    }
    let (host, dir) = serve(Router::new().route(pattern::IMAGE_LOAD, post(load)));
    let (code, _, stderr) = rustlet(&host, &["load", "-i", dir.path().to_str().unwrap()], small_packer()).await;
    let stderr = stderr.text();
    assert_eq!(code, 125, "{stderr}");
    assert!(stderr.to_lowercase().contains("is a directory"), "the user passed a directory and is told: {stderr:?}");
}

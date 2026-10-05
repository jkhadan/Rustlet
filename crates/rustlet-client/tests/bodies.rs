//! Requests with streamed bodies (a build's context, an archive to load):
//! what the client does when the daemon answers or hangs up while the body
//! is still being sent, when the body fails by itself, and when the caller
//! drops the answer; and the limit on a build's options.
//!
//! Against an in-process axum server (as rustletd's, hyper underneath) on a
//! temporary Unix socket, and against hand-made servers on raw sockets
//! where a test needs to say exactly when the daemon hangs up.

use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Json;
use axum::Router;
use axum::body::Body;
use axum::extract::Query;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use futures::StreamExt;
use rustlet_client::{Client, Error, MAX_TARGET, RequestBody};
use rustlet_spec::build::{BuildEvent, BuildOptions, BuildQuery};
use rustlet_spec::{ErrorBody, ErrorKind, routes};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

/// Serves `app` on a socket in a fresh temporary directory (kept alive by
/// the returned guard).
fn serve(app: Router) -> (tempfile::TempDir, Client) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rustlet.sock");
    let listener = UnixListener::bind(&path).unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (dir, Client::new(path))
}

/// A "daemon" on a raw socket: `handler` gets each connection's stream.
fn serve_raw<F, Fut>(handler: F) -> (tempfile::TempDir, Client)
where
    F: Fn(UnixStream) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rustlet.sock");
    let listener = UnixListener::bind(&path).unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(handler(stream));
        }
    });
    (dir, Client::new(path))
}

/// Reads a request up to the end of its head; false if the client went
/// first.
async fn read_head(stream: &mut UnixStream) -> bool {
    let mut head = Vec::new();
    let mut buf = [0; 4096];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
        match stream.read(&mut buf).await {
            Ok(0) | Err(_) => return false,
            Ok(n) => head.extend_from_slice(&buf[..n]),
        }
    }
    true
}

/// Fails a test that would otherwise hang.
async fn within<T>(f: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(10), f).await.expect("timed out")
}

type Writing = tokio::task::JoinHandle<io::Result<()>>;

/// A body of `total` bytes written from a blocking thread, as `rustlet
/// build` packs a context; the thread's result says how the writer ended.
fn big_body(total: usize) -> (RequestBody, Writing) {
    let (body, mut writer) = RequestBody::pipe();
    let writing = tokio::task::spawn_blocking(move || {
        let block = vec![b'x'; 64 * 1024];
        let mut sent = 0;
        while sent < total {
            writer.write_all(&block)?;
            sent += block.len();
        }
        writer.finish()
    });
    (body, writing)
}

/// A body that never ends by itself: its writer writes until a write fails.
fn endless_body() -> (RequestBody, Writing) {
    let (body, mut writer) = RequestBody::pipe();
    let writing = tokio::task::spawn_blocking(move || {
        let block = vec![b'x'; 64 * 1024];
        loop {
            writer.write_all(&block)?;
        }
    });
    (body, writing)
}

fn ndjson(events: &[BuildEvent]) -> Response {
    let lines: String = events.iter().map(|e| serde_json::to_string(e).unwrap() + "\n").collect();
    ([(header::CONTENT_TYPE, rustlet_spec::NDJSON)], lines).into_response()
}

/// Expected (the docs of `Client::build`: a daemon that hangs up before the
/// whole body is in "gives `Error::Io` saying so, rather than hyper's
/// account of the write that failed"): a daemon that reads a request's head
/// and closes the connection while the context is still being sent (what
/// refusing or failing a request looks like from the client's side) is
/// told so plainly, however hyper came to know: a write that met a closed
/// socket, a reset, or the end of the connection before any answer. The
/// error is still a plain `Error` the CLI maps to 125, and the writer stops.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_daemon_that_hangs_up_during_the_body_is_told_plainly() {
    let (_dir, client) = serve_raw(|mut stream| async move {
        read_head(&mut stream).await;
    });
    for _ in 0..10 {
        let (body, writing) = endless_body();
        let result = within(client.build(&BuildOptions::default(), body)).await;
        let ended = within(writing).await.unwrap();
        assert_eq!(ended.unwrap_err().kind(), io::ErrorKind::BrokenPipe, "the writer stops with the request");
        let e = result.unwrap_err();
        assert!(matches!(&e, Error::Io(io) if io.kind() == io::ErrorKind::BrokenPipe), "{e:?}");
        assert_eq!(
            e.to_string(),
            "connection to rustletd: the daemon closed the connection while the request's body was still being sent \
             (it refused or failed the request: see rustletd's log)"
        );
        assert_eq!(e.kind(), None, "not an API error: the CLI's exit code is 125");
    }
}

/// The same for `load`'s archive, which goes through the same request path.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_daemon_that_hangs_up_during_an_archive_is_told_plainly() {
    let (_dir, client) = serve_raw(|mut stream| async move {
        read_head(&mut stream).await;
    });
    let (body, writing) = endless_body();
    let result = within(client.load_images(body)).await;
    let _ = within(writing).await.unwrap();
    let e = result.unwrap_err();
    assert!(e.to_string().contains("closed the connection while the request's body was still being sent"), "{e}");
}

/// Response headers can arrive before the daemon stops reading an upload.
/// A later connection failure has the same useful diagnostic as one that
/// happened before any answer, rather than hyper's generic body error.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_daemon_that_hangs_up_after_its_response_headers_is_told_plainly() {
    for loading in [false, true] {
        let close = Arc::new(tokio::sync::Notify::new());
        let signal = close.clone();
        let (_dir, client) = serve_raw(move |mut stream| {
            let signal = signal.clone();
            async move {
                assert!(read_head(&mut stream).await);
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nTransfer-Encoding: chunked\r\n\r\n",
                    )
                    .await
                    .unwrap();
                signal.notified().await;
            }
        });
        let (body, writing) = endless_body();
        let error = if loading {
            let mut events = within(client.load_images(body)).await.unwrap();
            close.notify_one();
            within(events.next()).await.unwrap().unwrap_err()
        } else {
            let mut events = within(client.build(&BuildOptions::default(), body)).await.unwrap();
            close.notify_one();
            within(events.next()).await.unwrap().unwrap_err()
        };
        assert!(matches!(&error, Error::Io(io) if io.kind() == io::ErrorKind::BrokenPipe), "{error:?}");
        assert!(error.to_string().contains("closed the connection while the request's body was still being sent"));
        assert_eq!(within(writing).await.unwrap().unwrap_err().kind(), io::ErrorKind::BrokenPipe);
    }
}

/// The upload's source can fail after response headers too. That failure
/// still belongs to the body and must never be attributed to the daemon.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_body_that_fails_after_response_headers_is_not_reported_as_a_daemon_hangup() {
    let (_dir, client) = serve_raw(|mut stream| async move {
        assert!(read_head(&mut stream).await);
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nTransfer-Encoding: chunked\r\n\r\n")
            .await
            .unwrap();
        let mut sink = [0; 64 * 1024];
        while matches!(stream.read(&mut sink).await, Ok(n) if n > 0) {}
    });
    let (body, writer) = RequestBody::pipe();
    let mut events = within(client.build(&BuildOptions::default(), body)).await.unwrap();
    within(tokio::task::spawn_blocking(move || writer.abort(io::Error::other("a file vanished")))).await.unwrap();
    let error = within(events.next()).await.unwrap().unwrap_err();
    assert!(matches!(error, Error::Http(_)), "{error:?}");
    assert!(!error.to_string().contains("the daemon closed"), "{error}");
}

/// Expected (the docs of `Client::build`: "a body that fails by itself (its
/// writer aborted, its reader failed) is `Error::Http`, which names that
/// failure"): when the body's own writer fails, the cause is not replaced by
/// the message about the daemon hanging up: the daemon did nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_body_that_fails_by_itself_keeps_its_own_message() {
    // A daemon that reads and never answers.
    let (_dir, client) = serve_raw(|mut stream| async move {
        read_head(&mut stream).await;
        let mut sink = vec![0; 64 * 1024];
        while matches!(stream.read(&mut sink).await, Ok(n) if n > 0) {}
    });
    let (body, mut writer) = RequestBody::pipe();
    let writing = tokio::task::spawn_blocking(move || {
        writer.write_all(&[1; 100_000]).unwrap();
        writer.flush().unwrap();
        writer.abort(io::Error::other("a file vanished"));
    });
    let e = within(client.build(&BuildOptions::default(), body)).await.unwrap_err();
    within(writing).await.unwrap();
    assert!(matches!(&e, Error::Http(_)), "{e:?}");
    assert!(e.to_string().contains("a file vanished"), "{e}");
}

/// Expected (lib.rs: "The status code is checked before any streaming
/// starts"): a refusal the daemon sends once it has read the whole context
/// is the caller's `Err(Error::Api)`, with the daemon's message and kind.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refusal_sent_after_the_body_was_read_is_kept() {
    async fn build(Query(_q): Query<BuildQuery>, body: Body) -> Response {
        let read = axum::body::to_bytes(body, usize::MAX).await.unwrap().len();
        assert_eq!(read, 32 << 20, "the whole context came");
        let refusal = ErrorBody::new(ErrorKind::Invalid, "invalid tag \"Bad Name\": a name can't hold a space");
        (StatusCode::BAD_REQUEST, Json(refusal)).into_response()
    }
    let (_dir, client) = serve(Router::new().route(routes::pattern::BUILD, post(build)));
    let (body, writing) = big_body(32 << 20);
    let e = within(client.build(&BuildOptions::default(), body)).await.unwrap_err();
    within(writing).await.unwrap().unwrap();
    assert!(matches!(&e, Error::Api { status: 400, body } if body.kind == ErrorKind::Invalid), "{e:?}");
    assert_eq!(e.to_string(), "invalid tag \"Bad Name\": a name can't hold a space");
}

/// Expected (spec build.rs: the stream "ends with `done` or `error`"; lib.rs:
/// a failed build ends "with `Err(Error::Stream(message))`"): an `error`
/// line the daemon sends once it has read the whole context is the stream's
/// last item, with the daemon's message.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_error_line_sent_after_the_body_was_read_is_kept() {
    async fn build(Query(_q): Query<BuildQuery>, body: Body) -> Response {
        let read = axum::body::to_bytes(body, usize::MAX).await.unwrap().len();
        ndjson(&[
            BuildEvent::Context { files: 1, bytes: read as u64 },
            BuildEvent::Error { message: "the build context: no space left on device".into() },
        ])
    }
    let (_dir, client) = serve(Router::new().route(routes::pattern::BUILD, post(build)));
    let (body, writing) = big_body(32 << 20);
    let events: Vec<_> =
        within(async { client.build(&BuildOptions::default(), body).await.unwrap().collect::<Vec<_>>().await }).await;
    within(writing).await.unwrap().unwrap();
    assert_eq!(events.len(), 2, "{events:?}");
    assert!(matches!(&events[0], Ok(BuildEvent::Context { bytes, .. }) if *bytes == 32 << 20), "{events:?}");
    assert!(matches!(&events[1], Err(Error::Stream(m)) if m == "the build context: no space left on device"));
}

/// Expected (body.rs: "`abort` fails the request instead ... so that a body
/// cut short never passes for a whole one"): a writer that fails before its
/// first byte, or after some, never gives the daemon a body that ends
/// cleanly.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_aborted_body_reaches_the_daemon_cut() {
    let seen: Arc<Mutex<Vec<Result<usize, String>>>> = Arc::default();
    let record = seen.clone();
    let app = Router::new().route(
        routes::pattern::BUILD,
        post(move |body: Body| {
            let record = record.clone();
            async move {
                let read = axum::body::to_bytes(body, usize::MAX).await;
                record.lock().unwrap().push(read.map(|b| b.len()).map_err(|e| e.to_string()));
                ndjson(&[BuildEvent::Error { message: "cut".into() }])
            }
        }),
    );
    let (_dir, client) = serve(app);
    for written in [0usize, 100, 200_000] {
        let (body, mut writer) = RequestBody::pipe();
        let writing = tokio::task::spawn_blocking(move || {
            writer.write_all(&vec![1; written]).unwrap();
            writer.flush().unwrap();
            std::thread::sleep(Duration::from_millis(100));
            writer.abort(io::Error::other("a file vanished"));
        });
        let result = within(async {
            match client.build(&BuildOptions::default(), body).await {
                Ok(stream) => stream.collect::<Vec<_>>().await.into_iter().last().map(|r| r.map(|_| ())),
                Err(e) => Some(Err(e)),
            }
        })
        .await;
        within(writing).await.unwrap();
        assert!(matches!(result, Some(Err(_))), "{written}: {result:?}");
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let seen = seen.lock().unwrap();
    assert!(seen.iter().all(Result::is_err), "the daemon took a cut body for a whole one: {seen:?}");
}

/// Expected (lib.rs: "dropping the stream hangs up"; body.rs: "a request
/// that fails makes the writer's next write fail (`BrokenPipe`), which stops
/// the packer"): a build whose events are dropped while its context is
/// still being written (the caller gave up) stops the writer, as long as the
/// daemon goes on reading what it is sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropping_a_builds_events_hangs_up_and_stops_its_writer() {
    let app = Router::new().route(
        routes::pattern::BUILD,
        post(|body: Body| async move {
            tokio::spawn(async move {
                let mut data = body.into_data_stream();
                while data.next().await.is_some_and(|chunk| chunk.is_ok()) {}
            });
            let pending = futures::stream::pending::<Result<bytes::Bytes, io::Error>>();
            ([(header::CONTENT_TYPE, rustlet_spec::NDJSON)], Body::from_stream(pending)).into_response()
        }),
    );
    let (_dir, client) = serve(app);
    let (body, writing) = endless_body();
    let events = within(client.build(&BuildOptions::default(), body)).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    drop(events);
    let ended = tokio::time::timeout(Duration::from_secs(5), writing).await;
    let ended = ended.expect("the writer is still blocked 5 s after the build's events were dropped").unwrap();
    assert_eq!(ended.unwrap_err().kind(), io::ErrorKind::BrokenPipe);
}

/// Expected (the docs of `Client::build`: options "that take more fail here
/// with `Error::Request` before anything is sent, naming the largest"): a
/// build arg of 70 KB, past what a request's URI holds, is refused by the
/// client without a connection: this client's socket isn't even there, and
/// the error is about the options, not the connection.
#[tokio::test]
async fn options_too_large_for_a_request_fail_before_anything_is_sent() {
    let dir = tempfile::tempdir().unwrap();
    let client = Client::new(dir.path().join("no-such.sock"));
    let options = BuildOptions {
        build_args: [("CA".to_owned(), "x".repeat(70_000))].into(),
        labels: [("tier".to_owned(), "web".to_owned())].into(),
        ..BuildOptions::default()
    };
    let (body, mut writer) = RequestBody::pipe();
    let e = client.build(&options, body).await.unwrap_err();
    assert!(matches!(&e, Error::Request(m) if m.contains("build arg \"CA\"") && m.contains("70002 bytes")), "{e:?}");
    assert!(e.to_string().contains(&format!("at most {MAX_TARGET}")), "{e}");
    // Nothing took the body: a writer finds the request gone.
    let written = tokio::task::spawn_blocking(move || writer.write_all(&vec![0; 1 << 20])).await.unwrap();
    assert_eq!(written.unwrap_err().kind(), io::ErrorKind::BrokenPipe);
}

/// Expected (the same limit, to the byte): options whose request target is
/// exactly [`MAX_TARGET`] bytes reach the daemon, decoded, however large
/// the one build arg is.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn options_that_just_fit_reach_the_daemon() {
    async fn build(Query(q): Query<BuildQuery>, body: Body) -> Response {
        let _ = axum::body::to_bytes(body, usize::MAX).await;
        let o = q.options().unwrap();
        ndjson(&[BuildEvent::Done { id: "sha256:ab".into(), names: vec![o.build_args["CA"].len().to_string()] }])
    }
    let (_dir, client) = serve(Router::new().route(routes::pattern::BUILD, post(build)));
    let with =
        |n: usize| BuildOptions { build_args: [("CA".to_owned(), "x".repeat(n))].into(), ..BuildOptions::default() };
    // The target grows by one byte per `x`: find how many fill it.
    let empty = rustlet_client::check_build_options(&with(0));
    assert!(empty.is_ok());
    let mut room = 0;
    for step in [1 << 16, 1 << 8, 1] {
        while rustlet_client::check_build_options(&with(room + step)).is_ok() {
            room += step;
        }
    }
    assert!(room > 65_000, "{room}");
    let events: Vec<_> = within(async {
        client.build(&with(room), RequestBody::from_bytes("a context")).await.unwrap().collect::<Vec<_>>().await
    })
    .await;
    assert!(matches!(&events[0], Ok(BuildEvent::Done { names, .. }) if *names == [room.to_string()]), "{events:?}");
    assert!(rustlet_client::check_build_options(&with(room + 1)).is_err());
}

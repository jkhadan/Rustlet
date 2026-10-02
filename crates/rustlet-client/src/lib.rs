//! # rustlet-client: rustletd's API as async calls
//!
//! The daemon speaks HTTP/1.1 with JSON bodies on a Unix socket; the
//! contract, route by route, is [`rustlet_spec`]. This crate turns each
//! route into one typed method of [`Client`], so that the CLI, the desktop
//! app and the tests never build a path or parse a response by hand.
//!
//! ```no_run
//! # async fn demo() -> rustlet_client::Result<()> {
//! use futures::StreamExt;
//! use rustlet_spec::logs::LogsQuery;
//!
//! let client = rustlet_client::Client::from_env()?;
//! for c in client.list_containers(true).await? {
//!     println!("{} {}", rustlet_spec::short_id(&c.id), c.name);
//! }
//! let mut logs = client.logs("web", &LogsQuery { follow: true, ..LogsQuery::default() }).await?;
//! while let Some(entry) = logs.next().await {
//!     print!("{}", entry?.log);
//! }
//! # Ok(()) }
//! ```
//!
//! **One connection per request.** A Unix socket costs a `connect()`, not
//! a TCP and TLS handshake, so there is nothing worth pooling; and a
//! connection that belongs to one request can't be held up by another's
//! half-read body: a `logs --follow` in one task and a `stop` in another
//! share nothing. The connection lives exactly as long as its response,
//! which is how a streaming call is cancelled: dropping the stream hangs
//! up, and the daemon stops sending.
//!
//! **Three shapes of response.**
//! - JSON: read whole and decoded into the spec's type.
//! - NDJSON ([`JsonStream`]): decoded line by line as frames arrive, so an
//!   endless `follow` stream yields each item as soon as it is sent. A
//!   stream that fails halfway ends with an `Err` ([`Error::Stream`] for
//!   the daemon's error line).
//! - WebSocket ([`Session`]): attach and attached exec, both directions at
//!   once.
//!
//! The status code is checked before any streaming starts, so "no such
//! container" is an `Err` from the call itself, never an item of a stream.
//!
//! **Errors** ([`Error`]) separate the daemon's refusals ([`Error::Api`],
//! with its [`rustlet_spec::ErrorKind`]) from not reaching it at all
//! ([`Error::Connect`], worded for a user: "is rustletd running?") and from
//! transport and protocol failures.
//!
//! Every method needs a tokio runtime: the connection is driven by a task
//! of its own.

#![forbid(unsafe_code)]

mod error;
mod ndjson;
mod session;

use std::borrow::Cow;
use std::path::{Path, PathBuf};

use bytes::Bytes;
use http::header::{CONTENT_TYPE, HOST, USER_AGENT};
use http::{HeaderValue, Method, Request, Response};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use rustlet_spec::container::{
    AttachQuery, ContainerConfig, ContainerInspect, ContainerSummary, CreateResponse, KillQuery, ListQuery,
    RemoveQuery, StopQuery, WaitCondition, WaitQuery, WaitResponse,
};
use rustlet_spec::event::{Event, EventsQuery};
use rustlet_spec::exec::{ExecConfig, ExecCreated, ExecInspect, ExecStarted};
use rustlet_spec::image::{
    ImageDeleteQuery, ImageDeleteResponse, ImageInspect, ImageQuery, ImageSummary, PullEvent, PullPolicy, PullQuery,
};
use rustlet_spec::logs::{LogEntry, LogsQuery};
use rustlet_spec::network::{Network, NetworkCreate, NetworkCreateResponse, PruneResponse};
use rustlet_spec::stats::{StatsQuery, StatsSample};
use rustlet_spec::system::{Info, Version};
use rustlet_spec::volume::{Volume, VolumeCreate, VolumePruneQuery, VolumeRemoveQuery};
use rustlet_spec::{ErrorBody, ErrorKind, routes};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::net::UnixStream;
use tokio_tungstenite::tungstenite;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

pub use error::{Error, Result};
pub use ndjson::JsonStream;
pub use session::{Session, SessionEvent, SessionReceiver, SessionSender};

/// The environment variable that names the daemon's socket, as
/// `unix:///path` or a plain path ([`Client::from_env`]).
pub const HOST_ENV: &str = "RUSTLET_HOST";

/// What requests say they are.
const AGENT: &str = concat!("rustlet-client/", env!("CARGO_PKG_VERSION"));

/// Error bodies are short messages; a larger one isn't read in full.
const MAX_ERROR_BODY: usize = 1 << 20;

/// A handle on the daemon at one socket. Cheap to clone; it holds no
/// connection between calls.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Client {
    socket: PathBuf,
}

impl Client {
    /// A client for the daemon listening on `socket`.
    pub fn new(socket: impl Into<PathBuf>) -> Client {
        Client { socket: socket.into() }
    }

    /// A client for `host`: `unix:///path/to/socket` or a plain path; empty
    /// means [`rustlet_spec::DEFAULT_SOCKET`]. Other schemes (`tcp://`) are
    /// refused: the daemon listens only on a Unix socket.
    pub fn from_host(host: &str) -> Result<Client> {
        let host = host.trim();
        if host.is_empty() {
            return Ok(Client::new(rustlet_spec::DEFAULT_SOCKET));
        }
        match host.split_once("://") {
            None => Ok(Client::new(host)),
            Some(("unix", path)) if !path.is_empty() => Ok(Client::new(path)),
            Some(_) => Err(Error::InvalidHost(host.to_owned())),
        }
    }

    /// A client for [`HOST_ENV`] (`RUSTLET_HOST`), or the default socket
    /// when it isn't set.
    pub fn from_env() -> Result<Client> {
        Client::from_host(&std::env::var(HOST_ENV).unwrap_or_default())
    }

    /// The socket this client connects to.
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    // --- system ---

    /// `GET /_ping`: is the daemon there and answering?
    pub async fn ping(&self) -> Result<()> {
        self.call(Method::GET, routes::ping()).await
    }

    /// The daemon's version, API version and kernel.
    pub async fn version(&self) -> Result<Version> {
        self.get(routes::version()).await
    }

    /// What the daemon manages (container, image, network and volume
    /// counts) and how it is set up (its directories, runtime, the host's
    /// CPUs and memory).
    pub async fn info(&self) -> Result<Info> {
        self.get(routes::info()).await
    }

    /// `GET /events`: what happens from now on (after replaying the recent
    /// past with `since`), until the stream is dropped.
    pub async fn events(&self, query: &EventsQuery) -> Result<JsonStream<Event>> {
        self.stream(with_query(routes::events(), query)?, Ok).await
    }

    // --- containers ---

    /// Running containers, or all of them.
    pub async fn list_containers(&self, all: bool) -> Result<Vec<ContainerSummary>> {
        self.get(with_query(routes::containers(), &ListQuery { all })?).await
    }

    /// Creates a container; fails with `NoSuchImage` if the store doesn't
    /// have its image (pull it, then create again).
    pub async fn create_container(&self, config: &ContainerConfig) -> Result<CreateResponse> {
        self.send(Method::POST, routes::containers(), config).await
    }

    /// `id` is a full id, a unique prefix of one, or a name.
    pub async fn inspect_container(&self, id: &str) -> Result<ContainerInspect> {
        self.get(routes::container(&segment(id))).await
    }

    /// With `force`, a live container is killed first. Its anonymous
    /// volumes stay; [`remove_container_with`](Self::remove_container_with)
    /// can take them too.
    pub async fn remove_container(&self, id: &str, force: bool) -> Result<()> {
        self.remove_container_with(id, &RemoveQuery { force, ..RemoveQuery::default() }).await
    }

    /// `rm` with all its options: `force` kills a live container first,
    /// `volumes` removes its anonymous volumes with it (`rm -v`).
    pub async fn remove_container_with(&self, id: &str, query: &RemoveQuery) -> Result<()> {
        self.call(Method::DELETE, with_query(routes::container(&segment(id)), query)?).await
    }

    /// Starts a created or exited container. A program that can't run fails
    /// here, with `CommandNotFound` or `CommandNotExecutable`.
    pub async fn start(&self, id: &str) -> Result<()> {
        self.call(Method::POST, action(id, routes::action::START)).await
    }

    /// The stop signal, then `KILL` after `timeout` seconds (default: the
    /// container's `stop_timeout`, else 10).
    pub async fn stop(&self, id: &str, timeout: Option<u32>) -> Result<()> {
        self.call(Method::POST, with_query(action(id, routes::action::STOP), &StopQuery { timeout })?).await
    }

    /// `signal` as `TERM`, `SIGTERM` or `15`; default `KILL`.
    pub async fn kill(&self, id: &str, signal: Option<&str>) -> Result<()> {
        let query = KillQuery { signal: signal.map(str::to_owned) };
        self.call(Method::POST, with_query(action(id, routes::action::KILL), &query)?).await
    }

    /// [`stop`](Self::stop) (if it is running), then start.
    pub async fn restart(&self, id: &str, timeout: Option<u32>) -> Result<()> {
        self.call(Method::POST, with_query(action(id, routes::action::RESTART), &StopQuery { timeout })?).await
    }

    /// Freezes every process of the container.
    pub async fn pause(&self, id: &str) -> Result<()> {
        self.call(Method::POST, action(id, routes::action::PAUSE)).await
    }

    /// Thaws a paused container.
    pub async fn unpause(&self, id: &str) -> Result<()> {
        self.call(Method::POST, action(id, routes::action::UNPAUSE)).await
    }

    /// Blocks until `condition` holds; then the container's last exit.
    pub async fn wait(&self, id: &str, condition: WaitCondition) -> Result<WaitResponse> {
        let path = with_query(action(id, routes::action::WAIT), &WaitQuery { condition })?;
        read_json(self.request(Method::POST, path, None).await?).await
    }

    /// The container's log, entry by entry; with `follow`, until it exits.
    pub async fn logs(&self, id: &str, query: &LogsQuery) -> Result<JsonStream<LogEntry>> {
        self.stream(with_query(action(id, routes::action::LOGS), query)?, Ok).await
    }

    /// A sample every second, until the stream is dropped or the container
    /// stops.
    pub async fn stats(&self, id: &str) -> Result<JsonStream<StatsSample>> {
        self.stream(with_query(action(id, routes::action::STATS), &StatsQuery { stream: true })?, Ok).await
    }

    /// One sample.
    pub async fn stats_once(&self, id: &str) -> Result<StatsSample> {
        self.get(with_query(action(id, routes::action::STATS), &StatsQuery { stream: false })?).await
    }

    /// Attaches to the container's output, and with `stdin` to its input
    /// (it must have been created with `open_stdin`). Attaching before
    /// `start` misses nothing of what the container prints.
    pub async fn attach(&self, id: &str, stdin: bool) -> Result<Session> {
        self.websocket(with_query(action(id, routes::action::ATTACH), &AttachQuery { stdin })?).await
    }

    // --- exec ---

    /// Checks `config` and returns an exec id, to be started within a
    /// minute.
    pub async fn create_exec(&self, id: &str, config: &ExecConfig) -> Result<ExecCreated> {
        self.send(Method::POST, action(id, routes::action::EXEC), config).await
    }

    /// An exec's config and state (its exit code once it has exited).
    pub async fn inspect_exec(&self, exec_id: &str) -> Result<ExecInspect> {
        self.get(routes::exec(&segment(exec_id))).await
    }

    /// Runs the exec in the background.
    pub async fn start_exec_detached(&self, exec_id: &str) -> Result<ExecStarted> {
        let response = self.request(Method::POST, routes::exec_start(&segment(exec_id)), None).await?;
        read_json(response).await
    }

    /// Runs the exec attached: its input and output are the session's.
    pub async fn start_exec(&self, exec_id: &str) -> Result<Session> {
        self.websocket(routes::exec_start(&segment(exec_id))).await
    }

    // --- images ---

    /// Every image in the store.
    pub async fn list_images(&self) -> Result<Vec<ImageSummary>> {
        self.get(routes::images()).await
    }

    /// An image, by name (`alpine`, `docker.io/library/alpine:latest`).
    pub async fn inspect_image(&self, name: &str) -> Result<ImageInspect> {
        self.get(with_query(routes::image_inspect(), &ImageQuery { name: name.to_owned() })?).await
    }

    /// Removes the name `name`, and whatever only it kept.
    pub async fn remove_image(&self, name: &str, force: bool) -> Result<ImageDeleteResponse> {
        let path = with_query(routes::images(), &ImageDeleteQuery { name: name.to_owned(), force })?;
        read_json(self.request(Method::DELETE, path, None).await?).await
    }

    /// Pulls `reference`, reporting progress as it goes. The stream never
    /// yields [`PullEvent::Error`]: a failed pull ends with
    /// `Err(Error::Stream(message))`, like any other stream. A pull that
    /// succeeded ends with [`PullEvent::Ready`].
    pub async fn pull(&self, reference: &str, policy: PullPolicy) -> Result<JsonStream<PullEvent>> {
        let query = PullQuery { reference: reference.to_owned(), policy };
        let response = self.request(Method::POST, with_query(routes::image_pull(), &query)?, None).await?;
        Ok(JsonStream::new(response.into_body(), |event| match event {
            PullEvent::Error { message } => Err(Error::Stream(message)),
            event => Ok(event),
        }))
    }

    // --- networks ---

    /// Every network, the default `bridge` among them.
    pub async fn list_networks(&self) -> Result<Vec<Network>> {
        self.get(routes::networks()).await
    }

    /// Creates a bridge network; its subnet comes from the daemon's pool
    /// unless `config` names one.
    pub async fn create_network(&self, config: &NetworkCreate) -> Result<NetworkCreateResponse> {
        self.send(Method::POST, routes::networks(), config).await
    }

    /// `id` is a network's id, a unique prefix of one, or its name.
    pub async fn inspect_network(&self, id: &str) -> Result<Network> {
        self.get(routes::network(&segment(id))).await
    }

    /// `id` as for [`inspect_network`](Self::inspect_network).
    pub async fn remove_network(&self, id: &str) -> Result<()> {
        self.call(Method::DELETE, routes::network(&segment(id))).await
    }

    /// Removes the user-defined networks no container uses; the answer
    /// names them.
    pub async fn prune_networks(&self) -> Result<PruneResponse> {
        read_json(self.request(Method::POST, routes::network_prune(), None).await?).await
    }

    // --- volumes ---

    /// Every volume, named and anonymous.
    pub async fn list_volumes(&self) -> Result<Vec<Volume>> {
        self.get(routes::volumes()).await
    }

    /// Creates a volume; without a name in `config`, an anonymous one with
    /// a generated name.
    pub async fn create_volume(&self, config: &VolumeCreate) -> Result<Volume> {
        self.send(Method::POST, routes::volumes(), config).await
    }

    /// A volume, by its name.
    pub async fn inspect_volume(&self, name: &str) -> Result<Volume> {
        self.get(routes::volume(&segment(name))).await
    }

    /// With `force`, a volume that doesn't exist is no error.
    pub async fn remove_volume(&self, name: &str, force: bool) -> Result<()> {
        self.call(Method::DELETE, with_query(routes::volume(&segment(name)), &VolumeRemoveQuery { force })?).await
    }

    /// Removes the anonymous volumes no container uses, and with `all` the
    /// named ones too; the answer names them, with the bytes freed.
    pub async fn prune_volumes(&self, all: bool) -> Result<PruneResponse> {
        let path = with_query(routes::volume_prune(), &VolumePruneQuery { all })?;
        read_json(self.request(Method::POST, path, None).await?).await
    }

    // --- plumbing ---

    async fn connect(&self) -> Result<UnixStream> {
        UnixStream::connect(&self.socket).await.map_err(|cause| Error::Connect { socket: self.socket.clone(), cause })
    }

    /// Sends a request on a connection of its own; a 2xx response is
    /// returned with its body unread, anything else becomes
    /// [`Error::Api`].
    async fn request(&self, method: Method, path: String, json: Option<Vec<u8>>) -> Result<Response<Incoming>> {
        let io = TokioIo::new(self.connect().await?);
        let (mut sender, connection) = hyper::client::conn::http1::handshake::<_, Full<Bytes>>(io).await?;
        // The connection is driven until the response body has been read
        // or dropped. Its errors reach the caller through the response.
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let builder = Request::builder()
            .method(method)
            .uri(path)
            .header(HOST, "localhost")
            .header(USER_AGENT, HeaderValue::from_static(AGENT));
        let request = match json {
            Some(body) => builder.header(CONTENT_TYPE, "application/json").body(Full::new(Bytes::from(body)))?,
            None => builder.body(Full::new(Bytes::new()))?,
        };
        let response = sender.send_request(request).await?;
        if response.status().is_success() {
            return Ok(response);
        }
        let status = response.status();
        let body = Limited::new(response.into_body(), MAX_ERROR_BODY).collect().await;
        let body = body.map(|b| b.to_bytes()).unwrap_or_default();
        Err(api_error(status.as_u16(), status.canonical_reason(), &body))
    }

    async fn get<T: DeserializeOwned>(&self, path: String) -> Result<T> {
        read_json(self.request(Method::GET, path, None).await?).await
    }

    async fn send<B: Serialize, T: DeserializeOwned>(&self, method: Method, path: String, body: &B) -> Result<T> {
        read_json(self.request(method, path, Some(serde_json::to_vec(body)?)).await?).await
    }

    /// A request whose answer carries nothing (204, or `OK`).
    async fn call(&self, method: Method, path: String) -> Result<()> {
        let response = self.request(method, path, None).await?;
        response.into_body().collect().await?;
        Ok(())
    }

    async fn stream<T>(&self, path: String, check: fn(T) -> Result<T>) -> Result<JsonStream<T>>
    where
        T: DeserializeOwned + Send + 'static,
    {
        Ok(JsonStream::new(self.request(Method::GET, path, None).await?.into_body(), check))
    }

    async fn websocket(&self, path: String) -> Result<Session> {
        let stream = self.connect().await?;
        let mut request = format!("ws://localhost{path}").into_client_request()?;
        request.headers_mut().insert(USER_AGENT, HeaderValue::from_static(AGENT));
        match tokio_tungstenite::client_async(request, stream).await {
            Ok((socket, _)) => Ok(Session::new(socket)),
            // The daemon refused the upgrade: a normal error response.
            Err(tungstenite::Error::Http(response)) => {
                let status = response.status();
                Err(api_error(status.as_u16(), status.canonical_reason(), response.body().as_deref().unwrap_or(&[])))
            }
            Err(e) => Err(e.into()),
        }
    }
}

/// `/v1/containers/{id}/{action}`.
fn action(id: &str, action: &str) -> String {
    routes::container_action(&segment(id), action)
}

/// `path?query`, or just `path` when every field of `query` is `None`.
fn with_query(path: String, query: &impl Serialize) -> Result<String> {
    let query = serde_urlencoded::to_string(query).map_err(|e| Error::Request(format!("encoding a query: {e}")))?;
    Ok(if query.is_empty() { path } else { format!("{path}?{query}") })
}

/// `s` as one path segment. Ids and names never need escaping, but what a
/// user typed might: `a/b` or `..` must stay one segment that names no
/// container, not become another route.
fn segment(s: &str) -> Cow<'_, str> {
    let plain = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~');
    if s.bytes().all(plain) && s != "." && s != ".." && !s.is_empty() {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        if plain(b) && b != b'.' {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    Cow::Owned(out)
}

async fn read_json<T: DeserializeOwned>(response: Response<Incoming>) -> Result<T> {
    let body = response.into_body().collect().await?.to_bytes();
    Ok(serde_json::from_slice(&body)?)
}

/// An error response as [`Error::Api`]. The body should be an
/// [`ErrorBody`]; whatever else it is (a proxy's page, a chunk-framed body
/// from a refused upgrade) still gives a message.
fn api_error(status: u16, reason: Option<&str>, body: &[u8]) -> Error {
    let parsed = error_body(body, status).or_else(|| {
        // The body of a refused upgrade comes as read off the socket:
        // possibly with chunked framing around the JSON.
        let start = body.iter().position(|&b| b == b'{')?;
        let end = body.iter().rposition(|&b| b == b'}')?;
        error_body(body.get(start..=end)?, status)
    });
    let mut body = parsed.unwrap_or_else(|| {
        let text = String::from_utf8_lossy(body).trim().to_owned();
        let message =
            if text.is_empty() { format!("HTTP {status} {}", reason.unwrap_or("")).trim().to_owned() } else { text };
        ErrorBody::new(kind_for_status(status), message)
    });
    if body.message.is_empty() {
        body.message = format!("HTTP {status} {}", reason.unwrap_or("")).trim().to_owned();
    }
    Error::Api { status, body }
}

/// An [`ErrorBody`] if `json` is one: it has a message. A kind this client
/// doesn't know (from a newer daemon), or none, is the status's.
fn error_body(json: &[u8], status: u16) -> Option<ErrorBody> {
    let v: serde_json::Value = serde_json::from_slice(json).ok()?;
    let message = v.get("message")?.as_str().filter(|m| !m.is_empty())?.to_owned();
    let kind = v
        .get("kind")
        .and_then(|k| serde_json::from_value::<ErrorKind>(k.clone()).ok())
        .unwrap_or_else(|| kind_for_status(status));
    Some(ErrorBody::new(kind, message))
}

/// The best guess at a kind when the body doesn't say.
fn kind_for_status(status: u16) -> ErrorKind {
    match status {
        400 => ErrorKind::Invalid,
        409 => ErrorKind::Conflict,
        // 404 could be any of five kinds; `Error::is_not_found` looks at
        // the status instead.
        _ => ErrorKind::Internal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts() {
        assert_eq!(Client::from_host("").unwrap().socket(), Path::new(rustlet_spec::DEFAULT_SOCKET));
        assert_eq!(Client::from_host("unix:///tmp/r.sock").unwrap().socket(), Path::new("/tmp/r.sock"));
        assert_eq!(Client::from_host("/tmp/r.sock").unwrap().socket(), Path::new("/tmp/r.sock"));
        assert_eq!(Client::from_host("./r.sock").unwrap().socket(), Path::new("./r.sock"));
        for bad in ["tcp://127.0.0.1:2375", "unix://", "http://localhost"] {
            assert!(matches!(Client::from_host(bad), Err(Error::InvalidHost(_))), "{bad}");
        }
    }

    #[test]
    fn queries_leave_out_none() {
        let q = LogsQuery { tail: Some(5), ..LogsQuery::default() };
        assert_eq!(with_query("/p".into(), &q).unwrap(), "/p?follow=false&tail=5&stdout=true&stderr=true");
        assert_eq!(with_query("/p".into(), &StopQuery { timeout: None }).unwrap(), "/p");
        assert_eq!(
            with_query("/p".into(), &WaitQuery { condition: WaitCondition::NextExit }).unwrap(),
            "/p?condition=next-exit"
        );
        let pull = PullQuery { reference: "docker.io/library/alpine:latest".into(), policy: PullPolicy::Always };
        assert_eq!(
            with_query("/p".into(), &pull).unwrap(),
            "/p?reference=docker.io%2Flibrary%2Falpine%3Alatest&policy=always"
        );
        assert_eq!(
            with_query("/p".into(), &RemoveQuery { force: false, volumes: true }).unwrap(),
            "/p?force=false&volumes=true"
        );
        assert_eq!(with_query("/p".into(), &VolumePruneQuery { all: true }).unwrap(), "/p?all=true");
    }

    #[test]
    fn segments_stay_segments() {
        assert_eq!(segment("web-1.v2_x"), "web-1.v2_x");
        assert_eq!(segment("0123abcd"), "0123abcd");
        assert_eq!(segment("a/b"), "a%2Fb");
        assert_eq!(segment(".."), "%2E%2E");
        assert_eq!(segment("a b?"), "a%20b%3F");
        assert_eq!(segment(""), "");
        assert_eq!(action("../images", "start"), "/v1/containers/%2E%2E%2Fimages/start");
    }

    #[test]
    fn error_bodies_become_api_errors() {
        let e =
            api_error(404, Some("Not Found"), br#"{"message":"no such container: web","kind":"no_such_container"}"#);
        assert!(matches!(&e, Error::Api { status: 404, body } if body.kind == ErrorKind::NoSuchContainer));
        assert_eq!(e.to_string(), "no such container: web");
        // Chunked framing around the JSON, as a refused upgrade's body may have.
        let e = api_error(409, None, b"2a\r\n{\"message\":\"is paused\",\"kind\":\"conflict\"}\r\n0\r\n\r\n");
        assert_eq!((e.kind(), e.to_string().as_str()), (Some(ErrorKind::Conflict), "is paused"));
        let e = api_error(502, Some("Bad Gateway"), b"");
        assert_eq!(e.to_string(), "HTTP 502 Bad Gateway");
        let e = api_error(400, None, b"plain text");
        assert_eq!((e.kind(), e.to_string().as_str()), (Some(ErrorKind::Invalid), "plain text"));
    }

    #[test]
    fn error_bodies_that_arent_ours_keep_their_text() {
        // A kind from a newer daemon: the message stays, the kind is the
        // status's.
        let e = api_error(409, Some("Conflict"), br#"{"message":"is paused","kind":"brand_new_kind"}"#);
        assert_eq!((e.kind(), e.to_string().as_str()), (Some(ErrorKind::Conflict), "is paused"));
        // Somebody else's JSON: its text.
        let e = api_error(400, Some("Bad Request"), br#"{"error":"bad name"}"#);
        assert_eq!(e.kind(), Some(ErrorKind::Invalid));
        assert!(e.to_string().contains("bad name"), "{e}");
    }
}

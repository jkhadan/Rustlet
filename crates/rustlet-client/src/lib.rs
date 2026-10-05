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
//! - Bytes ([`ByteStream`]): `save`'s archive, chunk by chunk.
//!
//! **Bodies that are streamed.** `build` sends a build context and `load`
//! an archive, either of which can be large: a [`RequestBody`] is sent as it
//! is produced, by a blocking writer on another thread
//! ([`RequestBody::pipe`]) or a reader ([`RequestBody::from_reader`]).
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

mod body;
mod error;
mod ndjson;
mod session;

use std::borrow::Cow;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::Poll;

use bytes::Bytes;
use futures::StreamExt as _;
use futures::stream::BoxStream;
use http::header::{CONTENT_TYPE, HOST, USER_AGENT};
use http::{HeaderValue, Method, Request, Response};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Full, Limited, StreamBody};
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use rustlet_spec::build::{BuildEvent, BuildOptions, BuildQuery, CommitRequest, CommitResponse};
use rustlet_spec::container::{
    AttachQuery, ContainerConfig, ContainerInspect, ContainerSummary, CreateResponse, KillQuery, ListQuery,
    RemoveQuery, StopQuery, WaitCondition, WaitQuery, WaitResponse,
};
use rustlet_spec::event::{Event, EventsQuery};
use rustlet_spec::exec::{ExecConfig, ExecCreated, ExecInspect, ExecStarted};
use rustlet_spec::image::{
    ImageDeleteQuery, ImageDeleteResponse, ImageInspect, ImageQuery, ImageSaveRequest, ImageSummary, ImageTagQuery,
    LoadEvent, PullEvent, PullPolicy, PullQuery,
};
use rustlet_spec::isolation::Isolation;
use rustlet_spec::logs::{LogEntry, LogsQuery};
use rustlet_spec::network::{
    Network, NetworkConnect, NetworkCreate, NetworkCreateResponse, NetworkDisconnect, PruneResponse,
};
use rustlet_spec::stats::{StatsQuery, StatsSample};
use rustlet_spec::system::{Info, Version};
use rustlet_spec::volume::{Volume, VolumeCreate, VolumePruneQuery, VolumeRemoveQuery};
use rustlet_spec::{ErrorBody, ErrorKind, routes};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::net::UnixStream;
use tokio_tungstenite::tungstenite;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

pub use body::{BodyWriter, ByteStream, RequestBody};
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

    /// `GET /containers/{id}/isolation`: what separates a running container
    /// from the host (a conflict for one that isn't running).
    pub async fn isolation(&self, id: &str) -> Result<Isolation> {
        self.get(action(id, routes::action::ISOLATION)).await
    }

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

    /// Gives the image `source` (a name, an id or a unique id prefix) the
    /// name `target` too, taking it from whatever it named before.
    pub async fn tag_image(&self, source: &str, target: &str) -> Result<()> {
        let query = ImageTagQuery { source: source.to_owned(), target: target.to_owned() };
        self.call(Method::POST, with_query(routes::image_tag(), &query)?).await
    }

    /// A tar archive of the images `names` (an OCI image layout, which
    /// `load` and `docker load` read), as it is written.
    pub async fn save_images(&self, names: &[String]) -> Result<ByteStream> {
        let body = serde_json::to_vec(&ImageSaveRequest { names: names.to_vec() })?;
        Ok(ByteStream::new(self.request(Method::POST, routes::image_save(), Some(body)).await?.into_body()))
    }

    /// Loads the images of the archive `archive` (as `save` writes it, or
    /// Docker's `docker save` format). Like a pull, a failed load ends the
    /// stream with `Err(Error::Stream(message))`; the stream never yields
    /// [`LoadEvent::Error`].
    pub async fn load_images(&self, archive: RequestBody) -> Result<JsonStream<LoadEvent>> {
        let payload = Payload::Stream(archive, "application/x-tar");
        let response = self.send_payload(Method::POST, routes::image_load(), payload).await?;
        Ok(JsonStream::upload(response, |event| match event {
            LoadEvent::Error { message } => Err(Error::Stream(message)),
            event => Ok(event),
        }))
    }

    // --- build ---

    /// Builds an image from `context`, the build context packed as a tar
    /// archive (`rustlet_build::context::pack` makes one), as `options`
    /// say. Progress comes as it happens; a build that succeeded ends with
    /// [`BuildEvent::Done`], one that failed with
    /// `Err(Error::Stream(message))` (the stream never yields
    /// [`BuildEvent::Error`]).
    ///
    /// **A limit.** The options travel URL-encoded in the request's URI,
    /// which the `http` crate holds to 65,534 bytes ([`MAX_TARGET`]): a
    /// build whose options take more (a build arg or label of tens of
    /// kilobytes, above all) fails here with [`Error::Request`] before
    /// anything is sent, naming the largest. [`check_build_options`] asks
    /// the same beforehand.
    ///
    /// **A context that is refused while it is being sent.** A daemon that
    /// hangs up before the whole body is in (it refused or failed the
    /// request) gives [`Error::Io`] saying so, rather than hyper's account
    /// of the write that failed. Failures from the body's own source (its
    /// writer aborted, its reader failed) remain [`Error::Http`].
    pub async fn build(&self, options: &BuildOptions, context: RequestBody) -> Result<JsonStream<BuildEvent>> {
        let path = build_target(options)?;
        let response = self.send_payload(Method::POST, path, Payload::Stream(context, "application/x-tar")).await?;
        Ok(JsonStream::upload(response, |event| match event {
            BuildEvent::Error { message } => Err(Error::Stream(message)),
            event => Ok(event),
        }))
    }

    /// Forgets the build cache: the next builds run every step again. The
    /// answer lists the cache entries removed.
    pub async fn prune_build_cache(&self) -> Result<PruneResponse> {
        read_json(self.request(Method::POST, routes::build_prune(), None).await?).await
    }

    /// A container's changes as a new image.
    pub async fn commit(&self, request: &CommitRequest) -> Result<CommitResponse> {
        self.send(Method::POST, routes::commit(), request).await
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

    /// Connects a container to the network `id` (id, unique prefix or
    /// name): at once if it runs, otherwise from its next start.
    pub async fn connect_network(&self, id: &str, body: &NetworkConnect) -> Result<()> {
        self.call_with(Method::POST, routes::network_connect(&segment(id)), body).await
    }

    /// Disconnects a container from the network `id`; with `force`, also
    /// from one that is gone (the container forgets it).
    pub async fn disconnect_network(&self, id: &str, body: &NetworkDisconnect) -> Result<()> {
        self.call_with(Method::POST, routes::network_disconnect(&segment(id)), body).await
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
        let payload = match json {
            Some(body) => Payload::Json(body),
            None => Payload::Empty,
        };
        self.send_payload(method, path, payload).await
    }

    async fn send_payload(&self, method: Method, path: String, payload: Payload) -> Result<Response<Incoming>> {
        let io = TokioIo::new(self.connect().await?);
        let (mut sender, connection) = hyper::client::conn::http1::handshake::<_, ReqBody>(io).await?;
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
        // For a streamed body: whether it has all been handed to the
        // connection, to tell a request that failed before its body was in
        // from one that failed after.
        let mut upload = None;
        let request = match payload {
            Payload::Empty => builder.body(full(Bytes::new()))?,
            Payload::Json(body) => builder.header(CONTENT_TYPE, "application/json").body(full(Bytes::from(body)))?,
            Payload::Stream(body, content_type) => {
                let (stream, progress) = noting_the_end(body.stream);
                upload = Some(progress);
                let frames = futures::StreamExt::map(stream, |chunk| chunk.map(hyper::body::Frame::data));
                builder.header(CONTENT_TYPE, content_type).body(StreamBody::new(frames).boxed_unsync())?
            }
        };
        let mut response = match sender.send_request(request).await {
            Ok(response) => response,
            Err(e) => return Err(upload_error(e, upload.as_ref())),
        };
        if response.status().is_success() {
            if let Some(progress) = upload {
                response.extensions_mut().insert(progress);
            }
            return Ok(response);
        }
        let status = response.status();
        let body = match Limited::new(response.into_body(), MAX_ERROR_BODY).collect().await {
            Ok(body) => body.to_bytes(),
            Err(cause) => {
                if let Ok(cause) = cause.downcast::<hyper::Error>() {
                    let error = upload_error(*cause, upload.as_ref());
                    if matches!(error, Error::Io(_)) {
                        return Err(error);
                    }
                }
                Bytes::new()
            }
        };
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
        read_empty(self.request(method, path, None).await?).await
    }

    /// [`call`](Self::call) with a JSON body.
    async fn call_with<B: Serialize>(&self, method: Method, path: String, body: &B) -> Result<()> {
        read_empty(self.request(method, path, Some(serde_json::to_vec(body)?)).await?).await
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

/// The longest request target (`path?query`) the `http` crate takes: its
/// `Uri`'s own limit, `u16::MAX - 1` bytes. A build's options travel in it
/// ([`BuildQuery`]), so they have to fit.
pub const MAX_TARGET: usize = 65_534;

/// The request target of a build with `options`, which must fit
/// [`MAX_TARGET`].
fn build_target(options: &BuildOptions) -> Result<String> {
    let target = with_query(routes::build(), &BuildQuery::new(options))?;
    if target.len() > MAX_TARGET {
        return Err(Error::Request(options_too_large(options, target.len())));
    }
    Ok(target)
}

/// Whether `options`, encoded as [`Client::build`] sends them, fit in a
/// request: what `build` checks before it sends anything. The error names
/// the largest build arg or label.
pub fn check_build_options(options: &BuildOptions) -> Result<()> {
    build_target(options).map(drop)
}

/// Why `options` don't fit, and what to shorten.
fn options_too_large(options: &BuildOptions, encoded: usize) -> String {
    let args = options.build_args.iter().map(|(name, value)| ("build arg", name, name.len() + value.len()));
    let labels = options.labels.iter().map(|(name, value)| ("label", name, name.len() + value.len()));
    let largest = match args.chain(labels).max_by_key(|&(_, _, size)| size) {
        Some((kind, name, size)) => format!("; the largest is {kind} {name:?} ({size} bytes)"),
        None => String::new(),
    };
    format!("the build's options take {encoded} bytes in the request's URI, which holds at most {MAX_TARGET}{largest}")
}

/// Whether a streamed request ended or its own source failed. The latter
/// must not be reported as a daemon that closed the connection.
#[derive(Clone, Default)]
struct UploadProgress {
    sent: Arc<AtomicBool>,
    failed: Arc<AtomicBool>,
}

/// `stream`, and its progress, shared with the response's reader.
fn noting_the_end(
    stream: BoxStream<'static, io::Result<Bytes>>,
) -> (BoxStream<'static, io::Result<Bytes>>, UploadProgress) {
    let progress = UploadProgress::default();
    let failed = progress.failed.clone();
    let stream = stream.inspect(move |chunk| {
        if chunk.is_err() {
            failed.store(true, Ordering::Release);
        }
    });
    let flag = progress.sent.clone();
    let end = futures::stream::poll_fn(move |_| {
        flag.store(true, Ordering::Release);
        Poll::Ready(None::<io::Result<Bytes>>)
    });
    (stream.chain(end).boxed(), progress)
}

/// A connection failure while an upload is still in progress, whether it
/// happens before response headers or while reading the response's body.
fn upload_error(e: hyper::Error, upload: Option<&UploadProgress>) -> Error {
    let sending = upload
        .is_some_and(|progress| !progress.sent.load(Ordering::Acquire) && !progress.failed.load(Ordering::Acquire));
    if sending && connection_went(&e) { Error::Io(closed_while_sending(e)) } else { e.into() }
}

/// Is `e` the connection going (a write that met a closed socket, a reset,
/// a hang-up before any answer), rather than something about the request
/// itself? The failure of the body's own source is not: hyper calls it a
/// user error, and its message names the cause.
fn connection_went(e: &hyper::Error) -> bool {
    if e.is_user() {
        return false;
    }
    let mut cause: Option<&(dyn std::error::Error + 'static)> = Some(e);
    while let Some(c) = cause {
        if let Some(io) = c.downcast_ref::<io::Error>()
            && matches!(
                io.kind(),
                io::ErrorKind::BrokenPipe
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::UnexpectedEof
            )
        {
            return true;
        }
        // Once response headers were delivered, hyper's HTTP/1 dispatcher
        // replaces the connection's error with this body-error cause.
        if c.to_string() == "connection error" {
            return true;
        }
        cause = c.source();
    }
    e.is_incomplete_message()
}

/// What a client still sending its body is told when the daemon hangs up:
/// that, and that the daemon refused or failed the request, as it does
/// before it has read a context it won't take. Hyper's account is kept as
/// the cause, for `--debug`.
fn closed_while_sending(cause: hyper::Error) -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, ClosedWhileSending(cause))
}

#[derive(Debug)]
struct ClosedWhileSending(hyper::Error);

impl fmt::Display for ClosedWhileSending {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            "the daemon closed the connection while the request's body was still being sent \
             (it refused or failed the request: see rustletd's log)",
        )
    }
}

impl std::error::Error for ClosedWhileSending {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

/// Every request's body type: whole or streamed.
type ReqBody = UnsyncBoxBody<Bytes, std::io::Error>;

/// What a request carries.
enum Payload {
    Empty,
    Json(Vec<u8>),
    /// A streamed body, and its content type.
    Stream(RequestBody, &'static str),
}

fn full(bytes: Bytes) -> ReqBody {
    Full::new(bytes).map_err(|never| match never {}).boxed_unsync()
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

/// Reads an answer that carries nothing to its end: a daemon that hangs up
/// halfway is still an error.
async fn read_empty(response: Response<Incoming>) -> Result<()> {
    response.into_body().collect().await?;
    Ok(())
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

    /// Expected (the `http` crate's `Uri`: at most `u16::MAX - 1` bytes):
    /// [`MAX_TARGET`] is what a request target may hold, to the byte, so
    /// that `build` can refuse options that don't fit before it sends.
    #[test]
    fn the_target_limit_is_the_http_crates() {
        let target = |n: usize| format!("/{}", "a".repeat(n - 1));
        assert!(http::Uri::try_from(target(MAX_TARGET)).is_ok());
        assert!(http::Uri::try_from(target(MAX_TARGET + 1)).is_err());
    }

    fn with_arg(value_len: usize) -> BuildOptions {
        BuildOptions { build_args: [("CA".to_owned(), "x".repeat(value_len))].into(), ..BuildOptions::default() }
    }

    /// Expected (the `http` crate takes a target of 65,534 bytes, and `build`
    /// says "an `Err(Error::Request)` before anything is sent" past that):
    /// options that fill the request target exactly are taken, one byte more
    /// are refused, and the error gives the size, the limit, and the build
    /// arg that is largest.
    #[test]
    fn options_fit_up_to_the_last_byte_of_the_target() {
        let room = MAX_TARGET - build_target(&with_arg(0)).unwrap().len();
        assert_eq!(build_target(&with_arg(room)).unwrap().len(), MAX_TARGET);
        assert!(check_build_options(&with_arg(room)).is_ok());

        let e = check_build_options(&with_arg(room + 1)).unwrap_err();
        assert!(matches!(e, Error::Request(_)), "{e:?}");
        assert_eq!(
            e.to_string(),
            format!(
                "invalid request: the build's options take {} bytes in the request's URI, which holds at most \
                 {MAX_TARGET}; the largest is build arg \"CA\" ({} bytes)",
                MAX_TARGET + 1,
                room + 1 + "CA".len()
            )
        );
    }

    /// The largest of the build args and labels is the one named, whichever
    /// it is; with neither (options that are large some other way), none is.
    #[test]
    fn the_error_names_the_largest_build_arg_or_label() {
        let big = "y".repeat(MAX_TARGET);
        let options = BuildOptions {
            build_args: [("SMALL".to_owned(), "1".to_owned()), ("MEDIUM".to_owned(), "z".repeat(1000))].into(),
            labels: [("org.example.cert".to_owned(), big.clone())].into(),
            ..BuildOptions::default()
        };
        let e = check_build_options(&options).unwrap_err().to_string();
        assert!(e.ends_with(&format!("the largest is label \"org.example.cert\" ({} bytes)", 16 + big.len())), "{e}");

        let options = BuildOptions { tags: vec!["a".repeat(MAX_TARGET)], ..BuildOptions::default() };
        let e = check_build_options(&options).unwrap_err().to_string();
        assert!(e.ends_with(&format!("which holds at most {MAX_TARGET}")), "{e}");
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

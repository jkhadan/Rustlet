//! The HTTP API on the Unix socket (routes: the table in `rustlet_spec`).

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::ws::WebSocketUpgrade;
use axum::extract::{Path, Query, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use rustlet_spec::container::{
    AttachQuery, ContainerConfig, ContainerStatus, KillQuery, ListQuery, RemoveQuery, StopQuery, WaitQuery,
};
use rustlet_spec::event::{EventKind, EventsQuery};
use rustlet_spec::exec::ExecConfig;
use rustlet_spec::image::{ImageDeleteQuery, ImageQuery, PullEvent, PullQuery};
use rustlet_spec::logs::LogsQuery;
use rustlet_spec::routes::{action, pattern};
use rustlet_spec::stats::StatsQuery;
use rustlet_spec::system::{Info, Version};
use rustlet_spec::{NDJSON, StreamError};
use serde::Serialize;
use tokio::sync::mpsc;

use crate::daemon::Daemon;
use crate::error::{ApiError, ApiResult};
use crate::lifecycle::blocking;
use crate::{logs, stats};

type D = State<Arc<Daemon>>;

pub fn router(daemon: Arc<Daemon>) -> Router {
    let c = pattern::container_action;
    Router::new()
        .route(pattern::PING, get(|| async { "OK" }))
        .route(pattern::VERSION, get(version))
        .route(pattern::INFO, get(info))
        .route(pattern::EVENTS, get(events))
        .route(pattern::CONTAINERS, get(list).post(create))
        .route(pattern::CONTAINER, get(inspect).delete(remove))
        .route(&c(action::START), post(start))
        .route(&c(action::STOP), post(stop))
        .route(&c(action::KILL), post(kill))
        .route(&c(action::RESTART), post(restart))
        .route(&c(action::PAUSE), post(pause))
        .route(&c(action::UNPAUSE), post(unpause))
        .route(&c(action::WAIT), post(wait))
        .route(&c(action::LOGS), get(container_logs))
        .route(&c(action::STATS), get(container_stats))
        .route(&c(action::ATTACH), get(attach))
        .route(&c(action::EXEC), post(exec_create))
        .route(pattern::EXEC, get(exec_inspect))
        .route(pattern::EXEC_START, get(exec_start_attached).post(exec_start_detached))
        .route(pattern::IMAGES, get(images).delete(image_remove))
        .route(pattern::IMAGE_PULL, post(image_pull))
        .route(pattern::IMAGE_INSPECT, get(image_inspect))
        .with_state(daemon)
}

/// An NDJSON response fed by `rx`; it ends when the sender is dropped, and
/// the sender learns that the client went away when sends fail.
fn ndjson<T: Serialize + Send + 'static>(rx: mpsc::Receiver<T>) -> Response {
    let body = futures::stream::unfold(rx, |mut rx| async move {
        let item = rx.recv().await?;
        let mut line = serde_json::to_vec(&item).expect("API types serialize");
        line.push(b'\n');
        Some((Ok::<_, Infallible>(Bytes::from(line)), rx))
    });
    ([(header::CONTENT_TYPE, NDJSON)], Body::from_stream(body)).into_response()
}

fn no_content() -> Response {
    StatusCode::NO_CONTENT.into_response()
}

/// Runs an operation to its end in a task of its own. hyper drops a
/// handler whose client hangs up (Ctrl-C on `rustlet start`), and an
/// operation stopped at an arbitrary `.await` (with a shim spawned but the
/// start not recorded, say) leaves processes that nothing watches.
async fn to_the_end<T: Send + 'static>(op: impl Future<Output = ApiResult<T>> + Send + 'static) -> ApiResult<T> {
    tokio::spawn(op).await.unwrap_or_else(|e| Err(ApiError::internal(format!("the operation failed: {e}"))))
}

fn kernel() -> String {
    nix::sys::utsname::uname().map(|u| u.release().to_string_lossy().into_owned()).unwrap_or_default()
}

async fn version() -> Json<Version> {
    Json(Version {
        version: env!("CARGO_PKG_VERSION").into(),
        api_version: rustlet_spec::API_VERSION.into(),
        os: std::env::consts::OS.into(),
        arch: std::env::consts::ARCH.into(),
        kernel: kernel(),
    })
}

async fn info(State(d): D) -> ApiResult<Json<Info>> {
    let (containers, running, paused, stopped) = d.counts();
    let images = d.images.list()?.len();
    Ok(Json(Info {
        containers,
        running,
        paused,
        stopped,
        images,
        networks: 0,
        volumes: 0,
        data_root: d.paths.data_root.display().to_string(),
        run_root: d.paths.run_root.display().to_string(),
        cgroup_parent: d.cgroup_parent.clone(),
        storage_driver: "overlay".into(),
        runtime: d.runtime.display().to_string(),
        shim: d.shim.display().to_string(),
        kernel: kernel(),
        cpus: stats::cpus_online() as usize,
        memory: stats::host_memory(),
    }))
}

async fn events(State(d): D, Query(q): Query<EventsQuery>) -> ApiResult<Response> {
    let since = q.since.as_deref().map(logs::parse_time).transpose()?;
    let only = q.container.as_ref().map(|key| d.find(key).map(|c| c.id().to_owned()).unwrap_or_else(|_| key.clone()));
    let (recent, mut live) = d.events.subscribe();
    let (tx, rx) = mpsc::channel(256);
    let wanted = move |e: &rustlet_spec::event::Event| {
        only.as_ref()
            .is_none_or(|id| e.kind == EventKind::Container && (&e.id == id || e.attributes.get("name") == Some(id)))
    };
    tokio::spawn(async move {
        for e in recent {
            let after = since.is_none_or(|s| {
                chrono::DateTime::parse_from_rfc3339(&e.time).is_ok_and(|t| t.with_timezone(&chrono::Utc) >= s)
            });
            if since.is_some() && after && wanted(&e) && tx.send(e).await.is_err() {
                return;
            }
        }
        loop {
            tokio::select! {
                got = live.recv() => match got {
                    Ok(e) if wanted(&e) => if tx.send(e).await.is_err() { return },
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => tracing::warn!("an events client missed {n} events"),
                    Err(_) => return,
                },
                () = tx.closed() => return,
            }
        }
    });
    Ok(ndjson(rx))
}

// ── containers ─────────────────────────────────────────────────────────────

async fn list(State(d): D, Query(q): Query<ListQuery>) -> Json<Vec<rustlet_spec::container::ContainerSummary>> {
    let mut all: Vec<_> = d
        .all_containers()
        .iter()
        .map(|c| c.summary())
        .filter(|s| q.all || s.state.status.is_live() || s.state.status == ContainerStatus::Restarting)
        .collect();
    all.sort_by(|a, b| b.created.cmp(&a.created));
    Json(all)
}

async fn create(State(d): D, Json(config): Json<ContainerConfig>) -> ApiResult<Response> {
    let r = to_the_end(async move { d.create(config).await }).await?;
    Ok((StatusCode::CREATED, Json(r)).into_response())
}

async fn inspect(State(d): D, Path(id): Path<String>) -> ApiResult<Json<rustlet_spec::container::ContainerInspect>> {
    let c = d.find(&id)?;
    Ok(Json(c.inspect(&d.paths, &d.cgroup_parent)))
}

async fn remove(State(d): D, Path(id): Path<String>, Query(q): Query<RemoveQuery>) -> ApiResult<Response> {
    let c = d.find(&id)?;
    to_the_end(async move { d.remove(&c, q.force).await }).await?;
    Ok(no_content())
}

async fn start(State(d): D, Path(id): Path<String>) -> ApiResult<Response> {
    let c = d.find(&id)?;
    to_the_end(async move { d.start(&c).await }).await?;
    Ok(no_content())
}

async fn stop(State(d): D, Path(id): Path<String>, Query(q): Query<StopQuery>) -> ApiResult<Response> {
    let c = d.find(&id)?;
    to_the_end(async move { d.stop(&c, q.timeout).await }).await?;
    Ok(no_content())
}

async fn kill(State(d): D, Path(id): Path<String>, Query(q): Query<KillQuery>) -> ApiResult<Response> {
    let c = d.find(&id)?;
    to_the_end(async move { d.kill(&c, q.signal.as_deref()).await }).await?;
    Ok(no_content())
}

async fn restart(State(d): D, Path(id): Path<String>, Query(q): Query<StopQuery>) -> ApiResult<Response> {
    let c = d.find(&id)?;
    to_the_end(async move { d.restart(&c, q.timeout).await }).await?;
    Ok(no_content())
}

async fn pause(State(d): D, Path(id): Path<String>) -> ApiResult<Response> {
    let c = d.find(&id)?;
    to_the_end(async move { d.pause(&c, true).await }).await?;
    Ok(no_content())
}

async fn unpause(State(d): D, Path(id): Path<String>) -> ApiResult<Response> {
    let c = d.find(&id)?;
    to_the_end(async move { d.pause(&c, false).await }).await?;
    Ok(no_content())
}

async fn wait(
    State(d): D,
    Path(id): Path<String>,
    Query(q): Query<WaitQuery>,
) -> ApiResult<Json<rustlet_spec::container::WaitResponse>> {
    let c = d.find(&id)?;
    Ok(Json(d.wait(&c, q.condition).await))
}

async fn container_logs(State(d): D, Path(id): Path<String>, Query(q): Query<LogsQuery>) -> ApiResult<Response> {
    let c = d.find(&id)?;
    let filter = logs::Filter::new(&q)?;
    let path = d.paths.container_log(c.id());
    let (entries, pos) = {
        let (path, filter, tail) = (path.clone(), filter.clone(), q.tail);
        blocking(move || logs::existing(&path, &filter, tail)).await?
    };
    let (tx, rx) = mpsc::channel(256);
    let state = c.subscribe();
    tokio::spawn(async move {
        for e in entries {
            if tx.send(logs::LogLine::Entry(e)).await.is_err() {
                return;
            }
        }
        if q.follow {
            logs::follow(path, pos, filter, state, tx).await;
        }
    });
    Ok(ndjson(rx))
}

async fn container_stats(State(d): D, Path(id): Path<String>, Query(q): Query<StatsQuery>) -> ApiResult<Response> {
    let c = d.find(&id)?;
    if !c.status().is_live() {
        return Err(ApiError::conflict(format!("container {} is not running", c.record.name)));
    }
    let first = stats::sample(&c, &d.cgroup_parent)?;
    if !q.stream {
        return Ok(Json(first).into_response());
    }
    let (tx, rx) = mpsc::channel::<serde_json::Value>(4);
    tokio::spawn(async move {
        let mut next = Some(first);
        loop {
            let sample = match next.take() {
                Some(s) => s,
                None => match stats::sample(&c, &d.cgroup_parent) {
                    Ok(s) => s,
                    Err(e) => {
                        if c.status().is_live() {
                            let _ = tx
                                .send(serde_json::to_value(StreamError { error: e.message }).expect("serializes"))
                                .await;
                        }
                        return;
                    }
                },
            };
            if tx.send(serde_json::to_value(sample).expect("serializes")).await.is_err() {
                return;
            }
            tokio::select! {
                () = tokio::time::sleep(Duration::from_secs(1)) => {}
                () = tx.closed() => return,
            }
            if !c.status().is_live() {
                return;
            }
        }
    });
    Ok(ndjson(rx))
}

async fn attach(
    State(d): D,
    Path(id): Path<String>,
    Query(q): Query<AttachQuery>,
    ws: WebSocketUpgrade,
) -> ApiResult<Response> {
    let c = d.find(&id)?;
    if matches!(c.status(), ContainerStatus::Removing | ContainerStatus::Dead) {
        return Err(ApiError::conflict(format!("container {} is {}", c.record.name, c.status())));
    }
    // Input only reaches a container that keeps a stdin (`-i`).
    let stdin = q.stdin && c.record.config.open_stdin;
    // Before the `101`: the client may start the container as soon as it
    // has it.
    let exits = c.subscribe().borrow().exits;
    let waiting = (!c.status().is_live()).then(|| crate::attach::register(&c, stdin));
    Ok(ws.on_upgrade(move |socket| crate::attach::attach(d, c, socket, stdin, exits, waiting)))
}

// ── exec ───────────────────────────────────────────────────────────────────

async fn exec_create(State(d): D, Path(id): Path<String>, Json(config): Json<ExecConfig>) -> ApiResult<Response> {
    let c = d.find(&id)?;
    let created = d.create_exec(c, config)?;
    Ok((StatusCode::CREATED, Json(created)).into_response())
}

async fn exec_inspect(State(d): D, Path(id): Path<String>) -> ApiResult<Json<rustlet_spec::exec::ExecInspect>> {
    Ok(Json(d.find_exec(&id)?.inspect()))
}

async fn exec_start_attached(State(d): D, Path(id): Path<String>, ws: WebSocketUpgrade) -> ApiResult<Response> {
    let s = d.find_exec(&id)?;
    Ok(ws.on_upgrade(move |socket| d.run_exec_attached(s, socket)))
}

async fn exec_start_detached(State(d): D, Path(id): Path<String>) -> ApiResult<Json<rustlet_spec::exec::ExecStarted>> {
    let s = d.find_exec(&id)?;
    Ok(Json(to_the_end(async move { d.start_exec_detached(s).await }).await?))
}

// ── images ─────────────────────────────────────────────────────────────────

async fn images(State(d): D) -> ApiResult<Json<Vec<rustlet_spec::image::ImageSummary>>> {
    Ok(Json(d.images.list()?))
}

async fn image_inspect(State(d): D, Query(q): Query<ImageQuery>) -> ApiResult<Json<rustlet_spec::image::ImageInspect>> {
    let image = d.images.resolve(&q.name)?;
    let users = d.image_users().remove(&image.manifest_digest.to_string()).unwrap_or_default();
    Ok(Json(d.images.inspect(&q.name, users)?))
}

async fn image_pull(State(d): D, Query(q): Query<PullQuery>) -> ApiResult<Response> {
    rustlet_image::ImageRef::parse(&q.reference).map_err(|e| ApiError::invalid(e.to_string()))?;
    let (tx, rx) = mpsc::channel::<PullEvent>(256);
    tokio::spawn(async move {
        match d.images.pull(&q.reference, q.policy, tx).await {
            Ok(image) => d.events.emit(
                EventKind::Image,
                "pull",
                &image.display_name(),
                [("id".to_owned(), image.manifest_digest.to_string())].into(),
            ),
            Err(e) => tracing::info!("pull {}: {e}", q.reference),
        }
    });
    Ok(ndjson(rx))
}

async fn image_remove(
    State(d): D,
    Query(q): Query<ImageDeleteQuery>,
) -> ApiResult<Json<rustlet_spec::image::ImageDeleteResponse>> {
    let images = d.clone();
    let r = to_the_end(async move { images.images.remove(&q.name, q.force, || images.image_users()).await }).await?;
    for name in &r.untagged {
        d.events.emit(EventKind::Image, "untag", name, Default::default());
    }
    for gone in &r.deleted {
        d.events.emit(EventKind::Image, "delete", gone, Default::default());
    }
    Ok(Json(r))
}

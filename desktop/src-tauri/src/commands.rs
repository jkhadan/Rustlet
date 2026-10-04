//! The commands the frontend can `invoke()`.
//!
//! Each is a thin wrapper over one call of [`rustlet_client::Client`]: the
//! arguments arrive as JSON and are deserialized into the API's own types
//! (`rustlet_spec`), the result goes back as JSON, an error as a
//! [`CommandError`]. The TypeScript side of every type comes from the same
//! Rust definitions (`cargo xtask gen-ts`), so a field renamed in
//! `rustlet-spec` breaks the frontend's type check, not the app.
//!
//! Argument names are snake_case on both sides (`rename_all`), like the
//! API's JSON. Every command is listed in `build.rs`, which makes Tauri
//! generate a permission for it; `capabilities/main.json` grants exactly
//! these to the app's window.
//!
//! A few do a client's work beyond one call, as the CLI does it: a build
//! packs its context (`builder.rs`), compose runs a project
//! (`compose.rs`), save and load write and read the user's files
//! (`archive.rs`). What they decide stays the libraries' and the daemon's.

use std::sync::Arc;

use rustlet_client::{Client, RequestBody};
use rustlet_spec::build::{BuildEvent, BuildOptions, CommitRequest, CommitResponse};
use rustlet_spec::container::{ContainerConfig, ContainerInspect, ContainerSummary, CreateResponse, RemoveQuery};
use rustlet_spec::image::{ImageDeleteResponse, ImageInspect, ImageSummary, LoadEvent, PullEvent, PullPolicy};
use rustlet_spec::isolation::Isolation;
use rustlet_spec::logs::{LogEntry, LogsQuery};
use rustlet_spec::network::{
    Network, NetworkConnect, NetworkCreate, NetworkCreateResponse, NetworkDisconnect, PortMapping, PruneResponse,
};
use rustlet_spec::stats::StatsSample;
use rustlet_spec::system::{Info, Version};
use rustlet_spec::volume::{MountSpec, Volume, VolumeCreate};
use tauri::State;
use tauri::ipc::{Channel, InvokeResponseBody};

use crate::compose::{self, ComposeProgress, Stack};
use crate::error::{CommandError, CommandResult};
use crate::streams::{self, DaemonMessage, StreamId, StreamMessage, Streams};
use crate::terminal::{SessionId, TerminalRequest, Terminals};
use crate::{archive, builder};

/// What every command can reach.
pub struct App {
    pub client: Client,
    pub streams: Arc<Streams>,
    pub terminals: Arc<Terminals>,
}

type S<'a> = State<'a, App>;

// ── the daemon ────────────────────────────────────────────────────────────

/// The socket the app talks to (`RUSTLET_HOST`, else the default).
#[tauri::command(rename_all = "snake_case")]
pub fn daemon_socket(app: S<'_>) -> String {
    app.client.socket().display().to_string()
}

#[tauri::command(rename_all = "snake_case")]
pub async fn daemon_version(app: S<'_>) -> CommandResult<Version> {
    Ok(app.client.version().await?)
}

#[tauri::command(rename_all = "snake_case")]
pub async fn daemon_info(app: S<'_>) -> CommandResult<Info> {
    Ok(app.client.info().await?)
}

/// The app's connection to the daemon and its events (see
/// [`streams::watch_daemon`]); the frontend opens it once.
#[tauri::command(rename_all = "snake_case")]
pub fn daemon_watch(app: S<'_>, channel: Channel<DaemonMessage>) -> StreamId {
    app.streams.spawn(streams::watch_daemon(app.client.clone(), channel))
}

/// Starts the installed service: `pkexec systemctl start rustletd`, which
/// asks for an administrator's password in a dialog of the desktop's
/// polkit agent.
#[tauri::command(rename_all = "snake_case")]
pub async fn daemon_start() -> CommandResult<()> {
    let out = tokio::process::Command::new("pkexec")
        .args(["systemctl", "start", "rustletd"])
        .output()
        .await
        .map_err(|e| CommandError::failed(format!("run pkexec: {e}")))?;
    match out.status.code() {
        Some(0) => Ok(()),
        // pkexec's own: the dialog was dismissed, or the user may not.
        Some(126) => Err(CommandError::failed("the password dialog was dismissed")),
        Some(127) => Err(CommandError::failed("not authorized to start rustletd")),
        _ => Err(CommandError::failed(format!(
            "systemctl start rustletd failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ))),
    }
}

// ── containers ────────────────────────────────────────────────────────────

/// `-p` and `-v` values in Docker's syntax, parsed as `rustlet run` parses
/// them (the same functions), so the run dialog accepts what the CLI
/// accepts and says what is wrong in the same words.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize)]
pub struct RunOptions {
    pub ports: Vec<PortMapping>,
    pub mounts: Vec<MountSpec>,
}

#[tauri::command(rename_all = "snake_case")]
pub fn parse_run_options(ports: Vec<String>, volumes: Vec<String>) -> CommandResult<RunOptions> {
    let mut out = RunOptions::default();
    for p in ports.iter().map(|p| p.trim()).filter(|p| !p.is_empty()) {
        out.ports.extend(PortMapping::parse(p).map_err(CommandError::invalid)?);
    }
    for v in volumes.iter().map(|v| v.trim()).filter(|v| !v.is_empty()) {
        out.mounts.push(MountSpec::parse_volume(v).map_err(CommandError::invalid)?);
    }
    Ok(out)
}

#[tauri::command(rename_all = "snake_case")]
pub async fn container_list(app: S<'_>, all: bool) -> CommandResult<Vec<ContainerSummary>> {
    Ok(app.client.list_containers(all).await?)
}

#[tauri::command(rename_all = "snake_case")]
pub async fn container_inspect(app: S<'_>, id: String) -> CommandResult<ContainerInspect> {
    Ok(app.client.inspect_container(&id).await?)
}

/// `config` may leave out any field but `image`: the API's defaults apply.
#[tauri::command(rename_all = "snake_case")]
pub async fn container_create(app: S<'_>, config: ContainerConfig) -> CommandResult<CreateResponse> {
    Ok(app.client.create_container(&config).await?)
}

#[tauri::command(rename_all = "snake_case")]
pub async fn container_start(app: S<'_>, id: String) -> CommandResult<()> {
    Ok(app.client.start(&id).await?)
}

#[tauri::command(rename_all = "snake_case")]
pub async fn container_stop(app: S<'_>, id: String, timeout: Option<u32>) -> CommandResult<()> {
    Ok(app.client.stop(&id, timeout).await?)
}

#[tauri::command(rename_all = "snake_case")]
pub async fn container_restart(app: S<'_>, id: String, timeout: Option<u32>) -> CommandResult<()> {
    Ok(app.client.restart(&id, timeout).await?)
}

#[tauri::command(rename_all = "snake_case")]
pub async fn container_kill(app: S<'_>, id: String, signal: Option<String>) -> CommandResult<()> {
    Ok(app.client.kill(&id, signal.as_deref()).await?)
}

#[tauri::command(rename_all = "snake_case")]
pub async fn container_pause(app: S<'_>, id: String) -> CommandResult<()> {
    Ok(app.client.pause(&id).await?)
}

#[tauri::command(rename_all = "snake_case")]
pub async fn container_unpause(app: S<'_>, id: String) -> CommandResult<()> {
    Ok(app.client.unpause(&id).await?)
}

#[tauri::command(rename_all = "snake_case")]
pub async fn container_remove(app: S<'_>, id: String, force: bool, volumes: bool) -> CommandResult<()> {
    Ok(app.client.remove_container_with(&id, &RemoveQuery { force, volumes }).await?)
}

#[tauri::command(rename_all = "snake_case")]
pub async fn container_isolation(app: S<'_>, id: String) -> CommandResult<Isolation> {
    Ok(app.client.isolation(&id).await?)
}

/// The container's log: what is there (`query.tail`, `since`, …), then with
/// `query.follow` what it prints until it exits.
#[tauri::command(rename_all = "snake_case")]
pub async fn container_logs(
    app: S<'_>,
    id: String,
    query: LogsQuery,
    channel: Channel<StreamMessage<LogEntry>>,
) -> CommandResult<StreamId> {
    let logs = app.client.logs(&id, &query).await?;
    Ok(app.streams.spawn(streams::forward(logs, channel)))
}

/// A sample a second while it runs.
#[tauri::command(rename_all = "snake_case")]
pub async fn container_stats(
    app: S<'_>,
    id: String,
    channel: Channel<StreamMessage<StatsSample>>,
) -> CommandResult<StreamId> {
    let stats = app.client.stats(&id).await?;
    Ok(app.streams.spawn(streams::forward(stats, channel)))
}

/// The container's changes as a new image (`rustlet commit`). `request`
/// may leave out any field but `container`: a running container is paused
/// while its changes are read, unless `pause` is `false`.
#[tauri::command(rename_all = "snake_case")]
pub async fn container_commit(app: S<'_>, request: CommitRequest) -> CommandResult<CommitResponse> {
    Ok(app.client.commit(&request).await?)
}

// ── streams and terminals ─────────────────────────────────────────────────

/// Stops a stream (the view that showed it is gone). `false`: it had ended.
#[tauri::command(rename_all = "snake_case")]
pub fn stream_cancel(app: S<'_>, stream: StreamId) -> bool {
    app.streams.cancel(stream)
}

/// Runs `cmd` in the container on a terminal of its own; its output goes to
/// `output` (raw bytes, then an `exit` or `error` message).
#[tauri::command(rename_all = "snake_case")]
#[allow(clippy::too_many_arguments)]
pub async fn terminal_open(
    app: S<'_>,
    container: String,
    cmd: Vec<String>,
    user: Option<String>,
    rows: u16,
    cols: u16,
    output: Channel<InvokeResponseBody>,
) -> CommandResult<SessionId> {
    let req = TerminalRequest { container, cmd, user, rows, cols };
    app.terminals.open(&app.client, req, output).await
}

/// `data` is bytes, not text: what xterm.js calls binary input (mouse
/// reports in the X10 encoding) is a byte per character, which UTF-8 would
/// turn into two.
#[tauri::command(rename_all = "snake_case")]
pub async fn terminal_input(app: S<'_>, session: SessionId, data: Vec<u8>) -> CommandResult<()> {
    app.terminals.input(session, &data).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn terminal_resize(app: S<'_>, session: SessionId, rows: u16, cols: u16) -> CommandResult<()> {
    app.terminals.resize(session, rows, cols).await
}

/// The terminal is gone: its process gets `SIGHUP`.
#[tauri::command(rename_all = "snake_case")]
pub async fn terminal_close(app: S<'_>, session: SessionId) -> CommandResult<()> {
    app.terminals.close(session).await;
    Ok(())
}

// ── images ────────────────────────────────────────────────────────────────

#[tauri::command(rename_all = "snake_case")]
pub async fn image_list(app: S<'_>) -> CommandResult<Vec<ImageSummary>> {
    Ok(app.client.list_images().await?)
}

#[tauri::command(rename_all = "snake_case")]
pub async fn image_inspect(app: S<'_>, name: String) -> CommandResult<ImageInspect> {
    Ok(app.client.inspect_image(&name).await?)
}

#[tauri::command(rename_all = "snake_case")]
pub async fn image_remove(app: S<'_>, name: String, force: bool) -> CommandResult<ImageDeleteResponse> {
    Ok(app.client.remove_image(&name, force).await?)
}

/// Pulls (and unpacks) `reference`, reporting progress per blob and layer.
#[tauri::command(rename_all = "snake_case")]
pub async fn image_pull(
    app: S<'_>,
    reference: String,
    policy: Option<PullPolicy>,
    channel: Channel<StreamMessage<PullEvent>>,
) -> CommandResult<StreamId> {
    let pull = app.client.pull(&reference, policy.unwrap_or(PullPolicy::Always)).await?;
    Ok(app.streams.spawn(streams::forward(pull, channel)))
}

/// Gives the image `source` (a name, an id or a unique id prefix) the name
/// `target` too.
#[tauri::command(rename_all = "snake_case")]
pub async fn image_tag(app: S<'_>, source: String, target: String) -> CommandResult<()> {
    Ok(app.client.tag_image(&source, &target).await?)
}

/// Saves the images `names` into a new file at `path` (absolute, or from
/// `~/`); returns the archive's size. A failed save leaves no file.
#[tauri::command(rename_all = "snake_case")]
pub async fn image_save(app: S<'_>, names: Vec<String>, path: String) -> CommandResult<u64> {
    archive::save(&app.client, &names, &path).await
}

/// Loads the images of the archive at `path`, reporting each blob and
/// image. The file is read as it is sent: stopping the stream stops the
/// load.
#[tauri::command(rename_all = "snake_case")]
pub async fn image_load(
    app: S<'_>,
    path: String,
    channel: Channel<StreamMessage<LoadEvent>>,
) -> CommandResult<StreamId> {
    let file = archive::open(&path)?;
    let load = app.client.load_images(RequestBody::from_reader(file)).await?;
    Ok(app.streams.spawn(streams::forward(load, channel)))
}

/// Builds an image from the directory `context` with `containerfile`
/// (relative to the context, absolute, or from `~/`; default its
/// `Containerfile`, else its `Dockerfile`), as `options` say; the context
/// is packed here and sent as it is packed. `options.dockerfile` is set
/// from the file. Stopping the stream stops the build.
#[tauri::command(rename_all = "snake_case")]
pub async fn image_build(
    app: S<'_>,
    context: String,
    containerfile: Option<String>,
    options: BuildOptions,
    channel: Channel<StreamMessage<BuildEvent>>,
) -> CommandResult<StreamId> {
    let build = builder::start(&app.client, &context, containerfile.as_deref(), options).await?;
    Ok(app.streams.spawn(streams::forward(builder::events(build), channel)))
}

/// Forgets the build cache (`rustlet builder prune`).
#[tauri::command(rename_all = "snake_case")]
pub async fn build_prune(app: S<'_>) -> CommandResult<PruneResponse> {
    Ok(app.client.prune_build_cache().await?)
}

// ── compose ───────────────────────────────────────────────────────────────

/// The compose projects the daemon has containers of.
#[tauri::command(rename_all = "snake_case")]
pub async fn stack_list(app: S<'_>) -> CommandResult<Vec<Stack>> {
    compose::list(&app.client).await
}

/// `compose up -d` of the project in `files` (one or more, the later ones
/// overriding the first), named `project_name` if given (`-p`; else as the
/// files say) and rooted at `project_dir` if given (`--project-directory`;
/// else the first file's directory). A file that doesn't load fails this;
/// then the up's progress comes on `channel`, and it runs to its end even
/// if the stream is stopped.
#[tauri::command(rename_all = "snake_case")]
pub async fn compose_up(
    app: S<'_>,
    files: Vec<String>,
    project_name: Option<String>,
    project_dir: Option<String>,
    channel: Channel<StreamMessage<ComposeProgress>>,
) -> CommandResult<StreamId> {
    let options = compose::load_options(&files, project_name, project_dir, compose::app_env())?;
    let progress = compose::up(app.client.clone(), options).await?;
    Ok(app.streams.spawn(streams::forward(progress, channel)))
}

/// `compose -p PROJECT down`: stops and removes the project's containers
/// and networks, and with `volumes` its volumes.
#[tauri::command(rename_all = "snake_case")]
pub async fn compose_down(app: S<'_>, project: String, volumes: bool) -> CommandResult<()> {
    compose::down(&app.client, &project, volumes).await
}

// ── networks ──────────────────────────────────────────────────────────────

#[tauri::command(rename_all = "snake_case")]
pub async fn network_list(app: S<'_>) -> CommandResult<Vec<Network>> {
    Ok(app.client.list_networks().await?)
}

#[tauri::command(rename_all = "snake_case")]
pub async fn network_inspect(app: S<'_>, id: String) -> CommandResult<Network> {
    Ok(app.client.inspect_network(&id).await?)
}

#[tauri::command(rename_all = "snake_case")]
pub async fn network_create(app: S<'_>, config: NetworkCreate) -> CommandResult<NetworkCreateResponse> {
    Ok(app.client.create_network(&config).await?)
}

#[tauri::command(rename_all = "snake_case")]
pub async fn network_remove(app: S<'_>, id: String) -> CommandResult<()> {
    Ok(app.client.remove_network(&id).await?)
}

#[tauri::command(rename_all = "snake_case")]
pub async fn network_connect(app: S<'_>, id: String, body: NetworkConnect) -> CommandResult<()> {
    Ok(app.client.connect_network(&id, &body).await?)
}

#[tauri::command(rename_all = "snake_case")]
pub async fn network_disconnect(app: S<'_>, id: String, body: NetworkDisconnect) -> CommandResult<()> {
    Ok(app.client.disconnect_network(&id, &body).await?)
}

#[tauri::command(rename_all = "snake_case")]
pub async fn network_prune(app: S<'_>) -> CommandResult<PruneResponse> {
    Ok(app.client.prune_networks().await?)
}

// ── volumes ───────────────────────────────────────────────────────────────

#[tauri::command(rename_all = "snake_case")]
pub async fn volume_list(app: S<'_>) -> CommandResult<Vec<Volume>> {
    Ok(app.client.list_volumes().await?)
}

#[tauri::command(rename_all = "snake_case")]
pub async fn volume_inspect(app: S<'_>, name: String) -> CommandResult<Volume> {
    Ok(app.client.inspect_volume(&name).await?)
}

#[tauri::command(rename_all = "snake_case")]
pub async fn volume_create(app: S<'_>, config: VolumeCreate) -> CommandResult<Volume> {
    Ok(app.client.create_volume(&config).await?)
}

#[tauri::command(rename_all = "snake_case")]
pub async fn volume_remove(app: S<'_>, name: String, force: bool) -> CommandResult<()> {
    Ok(app.client.remove_volume(&name, force).await?)
}

#[tauri::command(rename_all = "snake_case")]
pub async fn volume_prune(app: S<'_>, all: bool) -> CommandResult<PruneResponse> {
    Ok(app.client.prune_volumes(all).await?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_options_parse_like_the_cli() {
        let o = parse_run_options(
            vec!["8080:80".into(), " ".into(), "127.0.0.1::53/udp".into()],
            vec!["data:/data:ro".into()],
        )
        .unwrap();
        assert_eq!(o.ports.len(), 2);
        assert_eq!((o.ports[0].host_port, o.ports[0].container_port), (Some(8080), 80));
        assert_eq!(o.mounts[0].source.as_deref(), Some("data"));
        assert!(o.mounts[0].read_only);
        let e = parse_run_options(vec![], vec!["./rel:/x".into()]).unwrap_err();
        assert_eq!(e.kind, "invalid");
        assert!(e.message.contains("neither an absolute host path nor a volume name"), "{e:?}");
        assert!(parse_run_options(vec!["99999".into()], vec![]).is_err());
    }

    /// The commit dialog sends what it asks for, nothing else: the API's
    /// defaults (pause while committing) apply to the rest.
    #[test]
    fn a_commit_from_the_dialog_pauses_the_container() {
        let r: CommitRequest =
            serde_json::from_value(serde_json::json!({"container": "web", "reference": null, "comment": "fixed"}))
                .unwrap();
        assert_eq!((r.container.as_str(), r.reference, r.comment.as_deref()), ("web", None, Some("fixed")));
        assert!(r.pause);
    }

    /// The build form sends only what it asks for: the rest takes the
    /// API's defaults, and `dockerfile` is the app's to set.
    #[test]
    fn build_options_from_the_form_take_the_apis_defaults() {
        let o: BuildOptions = serde_json::from_value(serde_json::json!({
            "tags": ["hits:latest"], "build_args": {"V": "1"}, "target": null,
            "no_cache": true, "pull": "always", "network": "host",
        }))
        .unwrap();
        assert_eq!(o.tags, ["hits:latest"]);
        assert_eq!((o.no_cache, o.pull, o.dockerfile), (true, PullPolicy::Always, None));
        assert_eq!(o.network.to_string(), "host");
        assert!(o.labels.is_empty());
    }
}

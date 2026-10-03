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

use std::sync::Arc;

use rustlet_client::Client;
use rustlet_spec::container::{ContainerConfig, ContainerInspect, ContainerSummary, CreateResponse, RemoveQuery};
use rustlet_spec::image::{ImageDeleteResponse, ImageInspect, ImageSummary, PullEvent, PullPolicy};
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

use crate::error::{CommandError, CommandResult};
use crate::streams::{self, DaemonMessage, StreamId, StreamMessage, Streams};
use crate::terminal::{SessionId, TerminalRequest, Terminals};

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
    let invalid = |message: String| CommandError { kind: "invalid".into(), message };
    let mut out = RunOptions::default();
    for p in ports.iter().map(|p| p.trim()).filter(|p| !p.is_empty()) {
        out.ports.extend(PortMapping::parse(p).map_err(invalid)?);
    }
    for v in volumes.iter().map(|v| v.trim()).filter(|v| !v.is_empty()) {
        out.mounts.push(MountSpec::parse_volume(v).map_err(invalid)?);
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
}

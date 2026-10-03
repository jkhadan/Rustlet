//! # Rustlets Desktop: the Rust half of the Tauri app
//!
//! ```text
//!  ┌─────────────── webview (WebKitGTK) ────────────────┐
//!  │ React + TypeScript (desktop/src)                   │
//!  │   invoke("container_stop", {id})      → Promise    │
//!  │   new Channel(onmessage)              ← streams    │
//!  └──────────────┬─────────────────────────────────────┘
//!                 │ Tauri IPC: JSON (or raw bytes) over the webview's
//!                 │ custom `ipc://` protocol and `eval`ed callbacks
//!  ┌──────────────▼──────── this crate ─────────────────┐
//!  │ commands.rs   one command per API call             │
//!  │ streams.rs    NDJSON streams → channels, the daemon│
//!  │               connection and its events            │
//!  │ terminal.rs   exec sessions for xterm.js           │
//!  └──────────────┬─────────────────────────────────────┘
//!                 │ rustlet-client: HTTP/1.1, NDJSON, WebSocket
//!                 ▼
//!        /run/rustlet/rustlet.sock (rustletd)
//! ```
//!
//! The webview never talks to the daemon itself: it can only invoke the
//! commands this crate registers, and only those the capability in
//! `capabilities/main.json` grants. The socket's permissions decide who
//! may use the daemon at all (root, or the `rustlet` group), and the app
//! runs as the desktop user, so a user who may not use the daemon gets a
//! `denied` error rather than more power.

#![forbid(unsafe_code)]

pub mod commands;
pub mod error;
pub mod streams;
pub mod terminal;

use std::sync::Arc;
use std::time::Duration;

use tauri::webview::PageLoadEvent;

use crate::commands::App;

/// Runs the app until its window closes.
pub fn run() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("RUSTLET_DESKTOP_LOG")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();
    let client = rustlet_client::Client::from_env().unwrap_or_else(|e| {
        tracing::warn!("{e}; using {}", rustlet_spec::DEFAULT_SOCKET);
        rustlet_client::Client::new(rustlet_spec::DEFAULT_SOCKET)
    });
    let streams = Arc::new(streams::Streams::default());
    let terminals = Arc::new(terminal::Terminals::default());
    let (on_load_streams, on_load_terminals) = (streams.clone(), terminals.clone());
    let on_exit_terminals = terminals.clone();
    let app = tauri::Builder::default()
        .manage(App { client, streams, terminals })
        .setup(|app| {
            // Logging out (SIGTERM), Ctrl-C under `pnpm tauri dev`, a closed
            // terminal that started the app (SIGHUP): an orderly exit, so
            // that the terminals are hung up below.
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                if let Some(signal) = exit_signal().await {
                    tracing::info!("{signal}: exiting");
                    handle.exit(0);
                }
            });
            Ok(())
        })
        // A page that (re)loads starts from nothing: whatever the previous
        // one had open would run on with nobody to show it to.
        .on_page_load(move |_, payload| {
            if payload.event() == PageLoadEvent::Started {
                on_load_streams.cancel_all();
                let terminals = on_load_terminals.clone();
                tauri::async_runtime::spawn(async move { terminals.close_all().await });
            }
        })
        .invoke_handler(tauri::generate_handler![
            commands::daemon_socket,
            commands::daemon_version,
            commands::daemon_info,
            commands::daemon_watch,
            commands::daemon_start,
            commands::parse_run_options,
            commands::container_list,
            commands::container_inspect,
            commands::container_create,
            commands::container_start,
            commands::container_stop,
            commands::container_restart,
            commands::container_kill,
            commands::container_pause,
            commands::container_unpause,
            commands::container_remove,
            commands::container_isolation,
            commands::container_logs,
            commands::container_stats,
            commands::stream_cancel,
            commands::terminal_open,
            commands::terminal_input,
            commands::terminal_resize,
            commands::terminal_close,
            commands::image_list,
            commands::image_inspect,
            commands::image_remove,
            commands::image_pull,
            commands::network_list,
            commands::network_inspect,
            commands::network_create,
            commands::network_remove,
            commands::network_connect,
            commands::network_disconnect,
            commands::network_prune,
            commands::volume_list,
            commands::volume_inspect,
            commands::volume_create,
            commands::volume_remove,
            commands::volume_prune,
        ])
        .build(tauri::generate_context!())
        .expect("the app failed to start");
    // The window is closed, or the app was told to quit: the terminals'
    // processes get SIGHUP, as when a tab closes. Without it, the sockets
    // close with the process, which the daemon takes for a detach, and a
    // shell per open terminal would run on in its container.
    app.run(move |_, event| {
        if let tauri::RunEvent::Exit = event {
            tracing::debug!(terminals = on_exit_terminals.len(), "exiting: hanging up the terminals");
            tauri::async_runtime::block_on(async {
                let all = on_exit_terminals.close_all();
                if tokio::time::timeout(Duration::from_secs(2), all).await.is_err() {
                    tracing::warn!("the daemon didn't take every terminal's hangup in time");
                }
            });
        }
    });
}

/// The first of SIGTERM, SIGINT and SIGHUP, by name; `None` if they can't
/// be caught.
async fn exit_signal() -> Option<&'static str> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = signal(SignalKind::terminate()).ok()?;
    let mut int = signal(SignalKind::interrupt()).ok()?;
    let mut hup = signal(SignalKind::hangup()).ok()?;
    tokio::select! {
        _ = term.recv() => Some("SIGTERM"),
        _ = int.recv() => Some("SIGINT"),
        _ = hup.recv() => Some("SIGHUP"),
    }
}

//! Terminal sessions: `exec -it` for the frontend's xterm.js.
//!
//! ```text
//!  xterm.js                     this module                        rustletd → shim → PTY
//!  ────────                     ───────────                        ────────────────────
//!  terminal_open ─────────────► create_exec(tty, stdin, size) ───► POST …/exec
//!                               start_exec ──────────────────────► GET /exec/{id}/start (WebSocket)
//!          ◄─── session id ───  spawn(pump)
//!  write(bytes) ◄── Raw(bytes) ◄─ pump ◄────────────── binary [1][output]
//!  onData(keys) ─ terminal_input ─► sender.send_stdin ───────────► binary [0][input]
//!  onResize ───── terminal_resize ► sender.resize ───────────────► {"type":"resize",…}
//!  tab closed ─── terminal_close ─► sender.hangup + close ───────► {"type":"hangup"} → SIGHUP
//!  "[exited]" ◄── Json(exit) ◄──── pump ◄────────────────────────── {"type":"exit",…}
//! ```
//!
//! Output goes to the frontend as raw bytes (`InvokeResponseBody::Raw`,
//! an `ArrayBuffer` in JavaScript), not as JSON text: a terminal's output
//! is bytes, and a UTF-8 character split between two reads must reach
//! xterm.js's decoder as it is. The session's end arrives on the same
//! channel as a JSON message ([`TerminalMessage`]).
//!
//! Input order: Tauri may run two invocations of an async command at the
//! same time, so the frontend sends the next input only once the previous
//! `terminal_input` has returned, joining what was typed meanwhile into
//! one message (`TerminalInput` in `src/lib/terminal.ts`).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use rustlet_client::{Client, SessionEvent, SessionReceiver, SessionSender};
use rustlet_spec::exec::ExecConfig;
use serde::Serialize;
use tauri::ipc::{Channel, InvokeResponseBody};

use crate::error::{CommandError, CommandResult};

pub type SessionId = u32;

/// The JSON messages of a session's output channel (its data is raw).
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TerminalMessage {
    /// The process exited (shell-style status); the last message.
    Exit { code: i32 },
    /// The session failed (the program isn't in the container, say); the
    /// last message.
    Error { error: CommandError },
}

/// What [`Terminals::open`] runs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TerminalRequest {
    pub container: String,
    pub cmd: Vec<String>,
    pub user: Option<String>,
    pub rows: u16,
    pub cols: u16,
}

/// The sessions that are open, by id.
#[derive(Debug, Default)]
pub struct Terminals {
    next: AtomicU32,
    open: Mutex<HashMap<SessionId, Arc<tokio::sync::Mutex<SessionSender>>>>,
}

impl Terminals {
    /// Starts the process on a terminal of its own and pumps its output to
    /// `output` until it exits.
    pub async fn open(
        self: &Arc<Self>,
        client: &Client,
        req: TerminalRequest,
        output: Channel<InvokeResponseBody>,
    ) -> CommandResult<SessionId> {
        let config = ExecConfig {
            cmd: req.cmd,
            tty: true,
            stdin: true,
            // Programs pick their escape sequences from TERM; xterm.js
            // speaks xterm's.
            env: vec!["TERM=xterm-256color".into()],
            user: req.user,
            console_size: Some([req.rows.max(1), req.cols.max(1)]),
            ..ExecConfig::default()
        };
        let exec = client.create_exec(&req.container, &config).await?;
        let (sender, receiver) = client.start_exec(&exec.id).await?.split();
        let id = self.next.fetch_add(1, Ordering::Relaxed) + 1;
        self.lock().insert(id, Arc::new(tokio::sync::Mutex::new(sender)));
        let terminals = Arc::clone(self);
        tauri::async_runtime::spawn(async move {
            pump(receiver, output).await;
            terminals.lock().remove(&id);
        });
        Ok(id)
    }

    /// Input for the session's process, as typed.
    pub async fn input(&self, id: SessionId, data: &[u8]) -> CommandResult<()> {
        let sender = self.get(id)?;
        sender.lock().await.send_stdin(data).await.map_err(Into::into)
    }

    pub async fn resize(&self, id: SessionId, rows: u16, cols: u16) -> CommandResult<()> {
        let sender = self.get(id)?;
        sender.lock().await.resize(rows.max(1), cols.max(1)).await.map_err(Into::into)
    }

    /// The frontend's terminal is gone: hang up (the process gets
    /// `SIGHUP`) and close. A session that has ended is no error.
    pub async fn close(&self, id: SessionId) {
        let sender = self.lock().remove(&id);
        if let Some(sender) = sender {
            hang_up(&sender).await;
        }
    }

    /// Every session, when the page that showed them is gone.
    pub async fn close_all(&self) {
        let all: Vec<_> = self.lock().drain().map(|(_, s)| s).collect();
        for sender in all {
            hang_up(&sender).await;
        }
    }

    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn get(&self, id: SessionId) -> CommandResult<Arc<tokio::sync::Mutex<SessionSender>>> {
        self.lock().get(&id).cloned().ok_or_else(|| CommandError::failed(format!("terminal session {id} has ended")))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<SessionId, Arc<tokio::sync::Mutex<SessionSender>>>> {
        self.open.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

async fn hang_up(sender: &tokio::sync::Mutex<SessionSender>) {
    let mut sender = sender.lock().await;
    let _ = sender.hangup().await;
    let _ = sender.close().await;
}

/// The session's output to the channel, then how it ended.
async fn pump(mut receiver: SessionReceiver, output: Channel<InvokeResponseBody>) {
    let last = loop {
        match receiver.recv().await {
            Ok(Some(SessionEvent::Stdout(data) | SessionEvent::Stderr(data))) => {
                if output.send(InvokeResponseBody::Raw(data.to_vec())).is_err() {
                    return;
                }
            }
            Ok(Some(SessionEvent::Exit { code, .. })) => break TerminalMessage::Exit { code },
            Ok(Some(SessionEvent::Error { message, kind })) => {
                break TerminalMessage::Error { error: rustlet_client::Error::api(kind, message).into() };
            }
            // A session we hung up on ourselves ends without an exit.
            Ok(None) => return,
            Err(e) => break TerminalMessage::Error { error: e.into() },
        }
    };
    let json = serde_json::to_string(&last).expect("terminal messages serialize");
    let _ = output.send(InvokeResponseBody::Json(json));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_are_tagged() {
        assert_eq!(
            serde_json::to_string(&TerminalMessage::Exit { code: 129 }).unwrap(),
            r#"{"type":"exit","code":129}"#
        );
        let e = TerminalMessage::Error { error: CommandError::failed("x") };
        assert_eq!(serde_json::to_string(&e).unwrap(), r#"{"type":"error","error":{"kind":"failed","message":"x"}}"#);
    }
}

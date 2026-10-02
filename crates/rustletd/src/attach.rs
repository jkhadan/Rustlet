//! Attach and exec sessions: a client's WebSocket on one side, a shim
//! stream on the other (framing: `rustlet_spec::stream`).
//!
//! Attaching to a container that isn't running yet registers the client
//! with the container: `start` opens the shim stream for it, and applies its
//! terminal size, *before* the program runs, so `rustlet run` sees all of
//! its output from the first byte. Until then, its input is held back.

use std::sync::{Arc, Mutex};

use axum::extract::ws::{Message, WebSocket};
use futures::stream::{SplitSink, SplitStream};
use futures::{SinkExt, StreamExt};
use rustlet_shim::client::{ShimClient, ShimStream, StreamEvent};
use rustlet_shim::protocol::{ExitStatus, Request, Response};
use rustlet_spec::container::ContainerStatus;
use rustlet_spec::stream::{Control, STDERR, STDIN, STDOUT, data_message, parse_data_message};
use tokio::sync::oneshot;

use crate::container::{Container, PendingAttach};
use crate::daemon::Daemon;
use crate::error::ApiError;

/// Input held back while an attach waits for its container to start.
const MAX_EARLY_INPUT: usize = 1 << 20;

type Sink = SplitSink<WebSocket, Message>;
type Source = SplitStream<WebSocket>;

/// `GET /v1/containers/{id}/attach`, once upgraded.
pub async fn attach(daemon: Arc<Daemon>, c: Arc<Container>, ws: WebSocket, stdin: bool) {
    let (mut sink, mut source) = ws.split();
    let stream = if c.status().is_live() {
        let socket = daemon.paths.shim(c.id()).socket();
        let opened = async { ShimClient::connect(&socket).await?.open_stream(&Request::Attach { stdin }).await }.await;
        match opened {
            Ok((Response::Ok, Some(stream))) => stream,
            other => {
                let e = ApiError::internal(format!("attach to {}: {other:?}", c.record.name));
                return send_error(&mut sink, &e).await;
            }
        }
    } else {
        match wait_for_start(&c, stdin, &mut sink, &mut source).await {
            Some((stream, early, eof)) => {
                let mut stream = stream;
                if !early.is_empty() && stream.writer().stdin(&early).await.is_err() {
                    return;
                }
                if eof {
                    let _ = stream.writer().close_stdin().await;
                }
                stream
            }
            None => return,
        }
    };
    bridge(sink, source, stream, stdin).await;
}

/// Registers the client with the container and waits for `start` to hand
/// over its stream. Returns it with the input that arrived meanwhile (and
/// whether that input ended), or `None` if the client or container went away.
async fn wait_for_start(
    c: &Container,
    stdin: bool,
    sink: &mut Sink,
    source: &mut Source,
) -> Option<(ShimStream, Vec<u8>, bool)> {
    let (tx, rx) = oneshot::channel();
    let resize = Arc::new(Mutex::new(None));
    c.pending_attach.lock().unwrap_or_else(|e| e.into_inner()).push(PendingAttach {
        stdin,
        resize: resize.clone(),
        tx,
    });
    if matches!(c.status(), ContainerStatus::Removing | ContainerStatus::Dead) {
        send_error(sink, &ApiError::conflict(format!("container {} is {}", c.record.name, c.status()))).await;
        return None;
    }
    tokio::pin!(rx);
    let mut early = Vec::new();
    let mut eof = false;
    loop {
        tokio::select! {
            got = &mut rx => {
                return match got {
                    Ok(Ok(stream)) => Some((stream, early, eof)),
                    Ok(Err(e)) => {
                        send_error(sink, &e).await;
                        None
                    }
                    Err(_) => {
                        send_error(sink, &ApiError::internal("the container's start was abandoned")).await;
                        None
                    }
                };
            }
            msg = source.next() => match msg {
                Some(Ok(Message::Text(t))) => match serde_json::from_str::<Control>(&t) {
                    Ok(Control::Resize { rows, cols }) => *resize.lock().unwrap_or_else(|e| e.into_inner()) = Some((rows, cols)),
                    Ok(Control::StdinEof) => eof = true,
                    _ => {}
                },
                Some(Ok(Message::Binary(b))) => {
                    if let Some((STDIN, data)) = parse_data_message(&b)
                        && stdin
                        && early.len() + data.len() <= MAX_EARLY_INPUT
                    {
                        early.extend_from_slice(data);
                    }
                }
                Some(Ok(_)) => {}
                // The client gave up before the start: the pending entry's
                // sender fails when the start gets to it.
                Some(Err(_)) | None => return None,
            },
        }
    }
}

/// Copies between the client and the shim until the process exits (the
/// exit is the last thing sent) or the client goes away (detaching: the
/// process goes on).
pub async fn bridge(mut sink: Sink, mut source: Source, stream: ShimStream, stdin: bool) -> Option<ExitStatus> {
    let (mut reader, mut writer) = stream.split();
    let to_client = async {
        loop {
            let message = match reader.recv().await {
                Ok(Some(StreamEvent::Stdout(b))) => Message::Binary(data_message(STDOUT, &b).into()),
                Ok(Some(StreamEvent::Stderr(b))) => Message::Binary(data_message(STDERR, &b).into()),
                Ok(Some(StreamEvent::Exited(exit))) => {
                    let control = Control::Exit { code: exit.code, oom_killed: exit.oom_killed };
                    let _ = sink.send(text(&control)).await;
                    let _ = sink.close().await;
                    return Some(exit);
                }
                Ok(None) | Err(_) => {
                    let e = ApiError::internal("the container's shim went away");
                    send_error(&mut sink, &e).await;
                    return None;
                }
            };
            if sink.send(message).await.is_err() {
                return None;
            }
        }
    };
    let from_client = async {
        while let Some(Ok(msg)) = source.next().await {
            let ok = match msg {
                Message::Binary(b) => match parse_data_message(&b) {
                    Some((STDIN, data)) if stdin => writer.stdin(data).await.is_ok(),
                    _ => true,
                },
                Message::Text(t) => match serde_json::from_str::<Control>(&t) {
                    Ok(Control::Resize { rows, cols }) => writer.resize(rows, cols).await.is_ok(),
                    Ok(Control::StdinEof) => writer.close_stdin().await.is_ok(),
                    _ => true,
                },
                Message::Close(_) => break,
                _ => true,
            };
            if !ok {
                break;
            }
        }
    };
    tokio::select! {
        exit = to_client => exit,
        () = from_client => None,
    }
}

fn text(c: &Control) -> Message {
    Message::Text(serde_json::to_string(c).expect("controls serialize").into())
}

async fn send_error(sink: &mut Sink, e: &ApiError) {
    let _ = sink.send(text(&Control::Error { message: e.message.clone(), kind: e.kind })).await;
    let _ = sink.close().await;
}

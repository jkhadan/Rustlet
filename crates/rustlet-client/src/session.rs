//! Attach and attached-exec sessions: a WebSocket per session.
//!
//! The framing is [`rustlet_spec::stream`]'s: binary messages carry data,
//! the first byte saying whose (stdin from us, stdout and stderr from the
//! daemon); text messages carry a JSON [`Control`]. This module turns that
//! into calls ([`SessionSender`]) and events ([`SessionReceiver`]).
//!
//! A terminal relay needs both directions at once, from different tasks:
//! one copies keystrokes in while another prints output, and a third may
//! send a resize when the window changes. So a [`Session`] splits into a
//! sender and a receiver that share the socket (behind `futures`' `BiLock`,
//! held only while a frame is read or written).
//!
//! **How a session ends.** The daemon sends `exit` once the process has
//! exited and all its output has been sent, then closes the socket; or
//! `error` if the session failed (an exec whose program doesn't exist, a
//! container that exited before it could be attached to). Either is the
//! receiver's last event: after it, [`SessionReceiver::recv`] returns
//! `Ok(None)`. A socket that closes *before* either arrived is an error
//! ([`Error::Protocol`], or [`Error::WebSocket`] if the connection broke
//! without a close): the caller can't know how the process ended, and must
//! not report a status it doesn't have. Hanging up ourselves
//! ([`SessionSender::close`]) is a detach: an attached container keeps
//! running.
//!
//! **Pings.** tungstenite answers a ping by itself (the pong goes out with
//! the next read or write), so pings never surface as events.

use bytes::Bytes;
use futures::stream::{SplitSink, SplitStream};
use futures::{SinkExt, StreamExt};
use rustlet_spec::ErrorKind;
use rustlet_spec::stream::{self, Control};
use tokio::net::UnixStream;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;

use crate::error::{Error, Result};

type Socket = WebSocketStream<UnixStream>;

/// What the daemon sends during a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionEvent {
    /// Output on the process's stdout (everything, with a terminal).
    Stdout(Bytes),
    /// Output on its stderr.
    Stderr(Bytes),
    /// The process exited (shell-style status: 128 + signal for a signal).
    /// The last event.
    Exit { code: i32, oom_killed: bool },
    /// The session failed; `kind` as in [`rustlet_spec::ErrorBody`]. The
    /// last event.
    Error { message: String, kind: ErrorKind },
}

/// An open attach or exec session. Use it directly, or [`split`](Session::split)
/// it to send and receive from different tasks.
#[derive(Debug)]
pub struct Session {
    sender: SessionSender,
    receiver: SessionReceiver,
}

/// The sending half of a [`Session`].
#[derive(Debug)]
pub struct SessionSender {
    sink: SplitSink<Socket, Message>,
}

/// The receiving half of a [`Session`].
#[derive(Debug)]
pub struct SessionReceiver {
    stream: SplitStream<Socket>,
    /// `exit` or `error` arrived: nothing more will.
    finished: bool,
}

impl Session {
    pub(crate) fn new(socket: Socket) -> Session {
        let (sink, stream) = socket.split();
        Session { sender: SessionSender { sink }, receiver: SessionReceiver { stream, finished: false } }
    }

    /// The two halves, to be used from different tasks.
    pub fn split(self) -> (SessionSender, SessionReceiver) {
        (self.sender, self.receiver)
    }

    /// See [`SessionSender::send_stdin`].
    pub async fn send_stdin(&mut self, data: &[u8]) -> Result<()> {
        self.sender.send_stdin(data).await
    }

    /// See [`SessionSender::resize`].
    pub async fn resize(&mut self, rows: u16, cols: u16) -> Result<()> {
        self.sender.resize(rows, cols).await
    }

    /// See [`SessionSender::stdin_eof`].
    pub async fn stdin_eof(&mut self) -> Result<()> {
        self.sender.stdin_eof().await
    }

    /// See [`SessionSender::hangup`].
    pub async fn hangup(&mut self) -> Result<()> {
        self.sender.hangup().await
    }

    /// See [`SessionReceiver::recv`].
    pub async fn recv(&mut self) -> Result<Option<SessionEvent>> {
        self.receiver.recv().await
    }

    /// See [`SessionSender::close`].
    pub async fn close(mut self) -> Result<()> {
        self.sender.close().await
    }
}

impl SessionSender {
    /// Input for the process. Empty input is not sent: the end of input is
    /// [`stdin_eof`](Self::stdin_eof), not an empty message.
    pub async fn send_stdin(&mut self, data: &[u8]) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        self.sink.send(Message::Binary(stream::data_message(stream::STDIN, data).into())).await?;
        Ok(())
    }

    /// The terminal's size, in characters: once at the start and whenever
    /// it changes.
    pub async fn resize(&mut self, rows: u16, cols: u16) -> Result<()> {
        self.control(&Control::Resize { rows, cols }).await
    }

    /// No more input will come.
    pub async fn stdin_eof(&mut self) -> Result<()> {
        self.control(&Control::StdinEof).await
    }

    /// In an exec session: this client's terminal is gone, and the process
    /// gets `SIGHUP` (as a shell does when its window closes). The session
    /// then ends with its exit; [`close`](Self::close) right after is fine.
    pub async fn hangup(&mut self) -> Result<()> {
        self.control(&Control::Hangup).await
    }

    /// Hangs up (a detach: the process keeps running).
    pub async fn close(&mut self) -> Result<()> {
        self.sink.close().await?;
        Ok(())
    }

    async fn control(&mut self, control: &Control) -> Result<()> {
        self.sink.send(Message::text(serde_json::to_string(control)?)).await?;
        Ok(())
    }
}

impl SessionReceiver {
    /// The next event; `Ok(None)` once the session is over (it ended with
    /// `exit` or `error`, or an `Err` was returned). Cancel-safe: nothing
    /// is lost if the future is dropped before it completes (as in a
    /// `select!`).
    pub async fn recv(&mut self) -> Result<Option<SessionEvent>> {
        if self.finished {
            return Ok(None);
        }
        loop {
            let message = match self.stream.next().await {
                Some(Ok(message)) => message,
                Some(Err(e)) => return Err(self.fail(e.into())),
                None => return Err(self.fail(closed_early())),
            };
            match message {
                Message::Binary(data) => {
                    return match stream::parse_data_message(&data) {
                        Some((stream::STDOUT, _)) => Ok(Some(SessionEvent::Stdout(data.slice(1..)))),
                        Some((stream::STDERR, _)) => Ok(Some(SessionEvent::Stderr(data.slice(1..)))),
                        _ => {
                            let id = data.first().map_or("none".to_owned(), u8::to_string);
                            Err(self.fail(Error::Protocol(format!("a data message for stream {id}"))))
                        }
                    };
                }
                Message::Text(text) => {
                    let event = match serde_json::from_str::<Control>(&text) {
                        Ok(Control::Exit { code, oom_killed }) => SessionEvent::Exit { code, oom_killed },
                        Ok(Control::Error { message, kind }) => SessionEvent::Error { message, kind },
                        Ok(other) => {
                            return Err(
                                self.fail(Error::Protocol(format!("the daemon sent a client's control {other:?}")))
                            );
                        }
                        Err(e) => return Err(self.fail(Error::Protocol(format!("a control message {text:?}: {e}")))),
                    };
                    self.finished = true;
                    return Ok(Some(event));
                }
                // tungstenite has already queued the pong.
                Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => continue,
                Message::Close(_) => return Err(self.fail(closed_early())),
            }
        }
    }

    /// Ends the session with `e`: there's no telling what a later message
    /// would mean.
    fn fail(&mut self, e: Error) -> Error {
        self.finished = true;
        e
    }
}

fn closed_early() -> Error {
    Error::Protocol("rustletd closed the session before the process exited".to_owned())
}

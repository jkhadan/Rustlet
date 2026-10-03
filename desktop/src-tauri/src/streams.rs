//! Streams: the daemon's NDJSON responses, forwarded to the frontend over
//! Tauri channels.
//!
//! ```text
//!  frontend (TypeScript)              this module                         rustletd
//!  ─────────────────────              ───────────                         ────────
//!  ch = new Channel(onmessage)
//!  invoke("logs_watch", {…, channel: ch}) ─► client.logs(…) ─────────► GET …/logs?follow=true
//!                          ◄── stream id ─┘  spawn(forward)
//!  onmessage({type: "items", items}) ◄─── channel.send(batch) ◄─ JsonStream ◄─ NDJSON lines
//!  invoke("stream_cancel", {stream}) ───► abort the task: the JsonStream is
//!                                         dropped, its connection closes, and
//!                                         the daemon stops sending
//! ```
//!
//! Errors the daemon gives before the stream starts (no such container,
//! a container that isn't running) reject the `invoke` itself: a stream
//! that has an id has started. After that, a stream ends with one last
//! message, `end` or `error`.
//!
//! **Batching.** A channel message is a JavaScript call in the webview, so
//! a burst (the last 1000 lines of a log, or a busy container) would cost a
//! call per line. [`forward`] waits for the first item, then takes every
//! item that has *already* arrived (`now_or_never`), up to [`MAX_BATCH`],
//! and sends them together. A quiet stream gets each item at once; a busy
//! one gets fewer, bigger messages, with no timer adding latency.
//!
//! **The daemon itself** ([`watch_daemon`]): one events stream for the
//! whole app, kept open by reconnecting with backoff. Its `connected` and
//! `disconnected` messages are the app's connection indicator, and a
//! `connected` tells the frontend to refetch everything, since anything may
//! have changed while it wasn't listening (a daemon restart empties the
//! daemon's event history too).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use futures::{FutureExt, Stream, StreamExt};
use rustlet_client::Client;
use rustlet_spec::event::{Event, EventsQuery};
use rustlet_spec::system::Version;
use serde::Serialize;
use tauri::ipc::Channel;
use tokio::task::AbortHandle;

use crate::error::CommandError;

/// Identifies a running stream to `stream_cancel`.
pub type StreamId = u32;

/// At most this many items per message.
pub const MAX_BATCH: usize = 512;

/// Reconnecting to the daemon: the first retry after this, doubling up to
/// [`MAX_RETRY`].
const MIN_RETRY: Duration = Duration::from_millis(250);
const MAX_RETRY: Duration = Duration::from_secs(4);

/// What a stream sends the frontend.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum StreamMessage<T> {
    /// What arrived since the last message, in order.
    Items { items: Vec<T> },
    /// The stream is over (a pull finished, logs without `follow`, a
    /// container that exited); nothing more comes.
    End,
    /// The stream failed; nothing more comes.
    Error { error: CommandError },
}

/// The streams that run, so that the frontend can stop them.
#[derive(Debug, Default)]
pub struct Streams {
    next: AtomicU32,
    running: Mutex<HashMap<StreamId, AbortHandle>>,
}

impl Streams {
    /// Runs `task` until it ends or is cancelled, on Tauri's runtime: a
    /// sync command runs on the main thread, outside any runtime, where
    /// `tokio::spawn` would panic.
    pub fn spawn(self: &Arc<Self>, task: impl Future<Output = ()> + Send + 'static) -> StreamId {
        let id = self.next.fetch_add(1, Ordering::Relaxed) + 1;
        let streams = Arc::clone(self);
        // Held across the spawn, so a task that ends at once can't remove
        // its entry before it is inserted.
        let mut running = self.lock();
        let handle = tauri::async_runtime::spawn(async move {
            task.await;
            streams.lock().remove(&id);
        });
        running.insert(id, handle.inner().abort_handle());
        id
    }

    /// Stops a stream; `false` if it had already ended.
    pub fn cancel(&self, id: StreamId) -> bool {
        let handle = self.lock().remove(&id);
        handle.inspect(AbortHandle::abort).is_some()
    }

    /// Stops every stream (the page was reloaded: nobody listens any more).
    pub fn cancel_all(&self) {
        for (_, handle) in self.lock().drain() {
            handle.abort();
        }
    }

    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<StreamId, AbortHandle>> {
        self.running.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Forwards `stream` to `channel` until it ends, fails, or the frontend is
/// gone, in batches of what has already arrived.
pub async fn forward<T, S>(mut stream: S, channel: Channel<StreamMessage<T>>)
where
    T: Serialize,
    S: Stream<Item = rustlet_client::Result<T>> + Unpin,
{
    loop {
        let (batch, last) = next_batch(&mut stream).await;
        if !batch.is_empty() && channel.send(StreamMessage::Items { items: batch }).is_err() {
            return;
        }
        if let Some(last) = last {
            let _ = channel.send(last);
            return;
        }
    }
}

/// Waits for an item, then takes what else has arrived. The second value is
/// the stream's last message, once it has ended or failed.
async fn next_batch<T, S>(stream: &mut S) -> (Vec<T>, Option<StreamMessage<T>>)
where
    S: Stream<Item = rustlet_client::Result<T>> + Unpin,
{
    let mut batch = Vec::new();
    let mut next = stream.next().await;
    loop {
        match next {
            Some(Ok(item)) => batch.push(item),
            Some(Err(e)) => return (batch, Some(StreamMessage::Error { error: e.into() })),
            None => return (batch, Some(StreamMessage::End)),
        }
        if batch.len() >= MAX_BATCH {
            return (batch, None);
        }
        match stream.next().now_or_never() {
            Some(item) => next = item,
            None => return (batch, None),
        }
    }
}

/// What [`watch_daemon`] sends.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DaemonMessage {
    /// Connected (again). Anything may have changed meanwhile: the frontend
    /// refetches what it shows.
    Connected { socket: String, version: Version },
    /// Not connected, and why; retried with backoff. Sent when the
    /// connection is lost and when the reason changes, not on every retry.
    Disconnected { socket: String, error: CommandError },
    /// Events, in the order they happened.
    Events { events: Vec<Event> },
}

/// Keeps one events stream open for the app, reconnecting with backoff,
/// until the frontend is gone.
pub async fn watch_daemon(client: Client, channel: Channel<DaemonMessage>) {
    let socket = client.socket().display().to_string();
    let mut delay = MIN_RETRY;
    let mut reported: Option<CommandError> = None;
    loop {
        let error = match connect(&client).await {
            Ok((version, mut stream)) => {
                delay = MIN_RETRY;
                if channel.send(DaemonMessage::Connected { socket: socket.clone(), version }).is_err() {
                    return;
                }
                reported = None;
                loop {
                    let (events, last) = next_batch(&mut stream).await;
                    if !events.is_empty() && channel.send(DaemonMessage::Events { events }).is_err() {
                        return;
                    }
                    match last {
                        None => continue,
                        Some(StreamMessage::Error { error }) => break error,
                        Some(_) => break CommandError::failed("rustletd ended the event stream"),
                    }
                }
            }
            Err(error) => {
                delay = (delay * 2).min(MAX_RETRY);
                error
            }
        };
        if reported.as_ref() != Some(&error) {
            let message = DaemonMessage::Disconnected { socket: socket.clone(), error: error.clone() };
            if channel.send(message).is_err() {
                return;
            }
            reported = Some(error);
        }
        tokio::time::sleep(delay).await;
    }
}

async fn connect(client: &Client) -> Result<(Version, rustlet_client::JsonStream<Event>), CommandError> {
    let version = client.version().await?;
    let events = client.events(&EventsQuery::default()).await?;
    Ok((version, events))
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use tauri::ipc::InvokeResponseBody;

    use super::*;

    /// A channel whose messages land in a list, as JSON.
    fn recorder() -> (Channel<StreamMessage<u32>>, Arc<Mutex<Vec<serde_json::Value>>>) {
        let got = Arc::new(Mutex::new(Vec::new()));
        let sink = got.clone();
        let channel = Channel::new(move |body| {
            if let InvokeResponseBody::Json(json) = body {
                sink.lock().unwrap().push(serde_json::from_str(&json).unwrap());
            }
            Ok(())
        });
        (channel, got)
    }

    #[tokio::test]
    async fn what_has_arrived_goes_in_one_message_and_the_end_follows() {
        let (channel, got) = recorder();
        let items = futures::stream::iter((1..=3).map(Ok));
        forward(items, channel).await;
        assert_eq!(
            *got.lock().unwrap(),
            [serde_json::json!({"type": "items", "items": [1, 2, 3]}), serde_json::json!({"type": "end"})]
        );
    }

    #[tokio::test]
    async fn batches_are_capped() {
        let (channel, got) = recorder();
        let n = MAX_BATCH as u32 + 5;
        forward(futures::stream::iter((0..n).map(Ok)), channel).await;
        let got = got.lock().unwrap();
        assert_eq!(got.len(), 3, "a full batch, the rest, the end");
        assert_eq!(got[0]["items"].as_array().unwrap().len(), MAX_BATCH);
        assert_eq!(got[1]["items"].as_array().unwrap().len(), 5);
    }

    #[tokio::test]
    async fn a_failure_ends_the_stream_after_what_came_before_it() {
        let (channel, got) = recorder();
        let items = futures::stream::iter([Ok(1), Err(rustlet_client::Error::Stream("disk full".into()))]);
        forward(items, channel).await;
        assert_eq!(
            *got.lock().unwrap(),
            [
                serde_json::json!({"type": "items", "items": [1]}),
                serde_json::json!({"type": "error", "error": {"kind": "failed", "message": "disk full"}}),
            ]
        );
    }

    #[tokio::test]
    async fn items_still_to_come_are_not_waited_for() {
        let (channel, got) = recorder();
        let (tx, rx) = futures::channel::mpsc::unbounded();
        tx.unbounded_send(Ok(1)).unwrap();
        let task = tokio::spawn(forward(rx, channel));
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(*got.lock().unwrap(), [serde_json::json!({"type": "items", "items": [1]})]);
        tx.unbounded_send(Ok(2)).unwrap();
        drop(tx);
        task.await.unwrap();
        assert_eq!(got.lock().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn streams_can_be_cancelled_and_forget_themselves() {
        let streams = Arc::new(Streams::default());
        let forever = streams.spawn(futures::future::pending());
        let done = streams.spawn(async {});
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!streams.cancel(done), "it ended by itself");
        assert_eq!(streams.len(), 1);
        assert!(streams.cancel(forever));
        assert!(!streams.cancel(forever));
        streams.spawn(futures::future::pending());
        streams.cancel_all();
        assert!(streams.is_empty());
    }

    /// Sync commands (`daemon_watch`) run on the main thread, outside any
    /// runtime: spawning from there must work.
    #[test]
    fn streams_start_outside_a_runtime() {
        let streams = Arc::new(Streams::default());
        let (tx, rx) = std::sync::mpsc::channel();
        streams.spawn(async move { tx.send(()).unwrap() });
        rx.recv_timeout(Duration::from_secs(5)).expect("the task ran");
    }

    #[test]
    fn daemon_messages_are_tagged() {
        let m = DaemonMessage::Disconnected { socket: "/s".into(), error: CommandError::failed("x") };
        assert_eq!(
            serde_json::to_value(&m).unwrap(),
            serde_json::json!({"type": "disconnected", "socket": "/s", "error": {"kind": "failed", "message": "x"}})
        );
    }
}

//! Relaying an attach or exec session to the CLI's own terminal.
//!
//! A session is a WebSocket ([`rustlet_client::Session`]); this module
//! connects it to the CLI's standard streams the way `docker run`,
//! `attach` and `exec` do:
//!
//! - **Output.** Stdout data goes to the CLI's stdout, stderr data to its
//!   stderr, each written and flushed as it arrives. With a TTY there is
//!   only stdout: the container's PTY merges the two.
//! - **Input** (`-i`). A thread reads the CLI's stdin: a blocking read
//!   can't be cancelled, so it gets a thread of its own, which may still
//!   be waiting in `read` when the session is over (the process exits
//!   soon after). The bytes go out as stdin data, and the end of input
//!   as `stdin_eof`.
//! - **Terminal** (`-t` with a terminal on stdin). Raw mode, so every
//!   keystroke reaches the container's PTY as it is typed and unprocessed:
//!   Ctrl-C is a byte for the container's line discipline to turn into
//!   SIGINT, not a signal for the CLI. A guard restores the terminal on
//!   every way out (including errors, and panics, whose message is
//!   printed after the restore). The PTY gets our size at the start and
//!   on every SIGWINCH. Ctrl-P Ctrl-Q detaches, leaving the container
//!   running; SIGTERM or SIGHUP leave too, after restoring the terminal.
//! - **Signals** (`--sig-proxy`, without `-t`). SIGINT, SIGTERM, SIGHUP,
//!   SIGQUIT, SIGUSR1 and SIGUSR2 sent to the CLI are sent on to the
//!   container through `kill`; the CLI stays to report how it ended.
//!
//! The session ends with the daemon's `exit` (whose code the CLI exits
//! with), its `error` (an [`rustlet_client::Error::Api`] with the error's
//! kind, so a missing program still exits 127), or a detach.

use std::future::poll_fn;
use std::io::{Read, Write};
use std::sync::Once;
use std::task::Poll;
use std::time::Duration;

use anyhow::{Context, bail};
use rustlet_client::{Client, Session, SessionEvent, SessionSender};
use tokio::signal::unix::{Signal, SignalKind, signal};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::console::Console;

/// Ctrl-P Ctrl-Q, Docker's default detach keys.
const DETACH_KEYS: [u8; 2] = [0x10, 0x11];

/// How to relay a session.
#[derive(Debug, Clone, Default)]
pub struct Options {
    /// The process has a PTY.
    pub tty: bool,
    /// Forward the CLI's stdin.
    pub stdin: bool,
    /// Send the signals the CLI receives to this container.
    pub sig_proxy: Option<String>,
}

/// How a relayed session ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum End {
    /// The process exited with this (shell-style) status.
    Exited { code: i32, oom_killed: bool },
    /// The user detached; the process keeps running.
    Detached,
    /// The CLI got this signal (SIGTERM or SIGHUP) with the terminal in
    /// raw mode, restored it and left; the process keeps running.
    Signaled(i32),
}

/// What goes out on the session, from whichever task: one writer task
/// owns the sending half and sends these in order.
#[derive(Debug)]
enum Outgoing {
    Stdin(Vec<u8>),
    Resize { rows: u16, cols: u16 },
    StdinEof,
    Hangup,
}

/// Relays `session` until it ends.
pub async fn relay(client: &Client, session: Session, options: Options, console: &mut Console) -> anyhow::Result<End> {
    let (sender, mut receiver) = session.split();
    let (out, outgoing) = mpsc::channel(64);
    let writer = tokio::spawn(write_session(sender, outgoing));
    let mut tasks = Tasks::default();

    let raw = options.tty && options.stdin && console.stdin_tty;
    // Dropped last, whichever way this function returns.
    let _raw_mode = if raw { Some(RawMode::enable()?) } else { None };

    if options.tty && (console.stdin_tty || console.stdout_tty) {
        if let Some((rows, cols)) = terminal_size() {
            let _ = out.send(Outgoing::Resize { rows, cols }).await;
        }
        tasks.spawn(watch_size(out.clone()));
    }

    let (detach_tx, mut detached) = mpsc::channel::<()>(1);
    if options.stdin {
        match console.stdin.take() {
            Some(stdin) => {
                let chunks = read_in_thread(stdin)?;
                tasks.spawn(pump_stdin(chunks, out.clone(), raw.then(DetachKeys::default), detach_tx));
            }
            None => {
                let _ = out.send(Outgoing::StdinEof).await;
            }
        }
    }

    let (signal_tx, mut signaled) = mpsc::channel::<i32>(1);
    if let Some(id) = &options.sig_proxy {
        tasks.spawn(proxy_signals(client.clone(), id.clone()));
    } else if raw {
        tasks.spawn(watch_termination(signal_tx));
    }

    let end = loop {
        tokio::select! {
            event = receiver.recv() => match event? {
                Some(SessionEvent::Stdout(data)) => write_now(&mut console.stdout, &data)?,
                Some(SessionEvent::Stderr(data)) => write_now(&mut console.stderr, &data)?,
                Some(SessionEvent::Exit { code, oom_killed }) => break End::Exited { code, oom_killed },
                Some(SessionEvent::Error { message, kind }) => {
                    return Err(rustlet_client::Error::api(kind, message).into());
                }
                None => bail!("the session ended without an exit status"),
            },
            Some(()) = detached.recv() => break End::Detached,
            Some(signo) = signaled.recv() => break End::Signaled(signo),
        }
    };
    drop(tasks);
    if matches!(end, End::Detached | End::Signaled(_)) {
        // Hanging up is the detach. Let the close go out before the
        // process exits, but don't wait on a daemon that doesn't read.
        let hang_up = async move {
            let _ = out.send(Outgoing::Hangup).await;
            let _ = writer.await;
        };
        let _ = tokio::time::timeout(Duration::from_secs(2), hang_up).await;
    } else {
        writer.abort();
    }
    Ok(end)
}

/// The terminal's size as (rows, columns), if there is a terminal.
pub fn terminal_size() -> Option<(u16, u16)> {
    let (cols, rows) = crossterm::terminal::size().ok()?;
    (rows > 0 && cols > 0).then_some((rows, cols))
}

fn write_now(out: &mut (dyn Write + Send), data: &[u8]) -> std::io::Result<()> {
    out.write_all(data)?;
    out.flush()
}

async fn write_session(mut sender: SessionSender, mut outgoing: mpsc::Receiver<Outgoing>) {
    while let Some(message) = outgoing.recv().await {
        let sent = match message {
            Outgoing::Stdin(data) => sender.send_stdin(&data).await,
            Outgoing::Resize { rows, cols } => sender.resize(rows, cols).await,
            Outgoing::StdinEof => sender.stdin_eof().await,
            Outgoing::Hangup => {
                let _ = sender.close().await;
                return;
            }
        };
        // The session is gone; how it ended is the receiver's to report.
        if sent.is_err() {
            return;
        }
    }
}

/// Reads `stdin` on a thread of its own, chunk by chunk; the channel
/// closes at the end of input (or a read error, which ends it too).
fn read_in_thread(mut stdin: Box<dyn Read + Send>) -> anyhow::Result<mpsc::Receiver<Vec<u8>>> {
    let (tx, rx) = mpsc::channel(4);
    std::thread::Builder::new()
        .name("stdin".to_owned())
        .spawn(move || {
            let mut buf = vec![0; 32 * 1024];
            loop {
                match stdin.read(&mut buf) {
                    Ok(0) => return,
                    Ok(n) => {
                        if tx.blocking_send(buf[..n].to_vec()).is_err() {
                            return;
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => return,
                }
            }
        })
        .context("starting the stdin thread")?;
    Ok(rx)
}

async fn pump_stdin(
    mut chunks: mpsc::Receiver<Vec<u8>>,
    out: mpsc::Sender<Outgoing>,
    mut keys: Option<DetachKeys>,
    detach: mpsc::Sender<()>,
) {
    while let Some(chunk) = chunks.recv().await {
        let (data, detached) = match &mut keys {
            Some(keys) => keys.feed(&chunk),
            None => (chunk, false),
        };
        if !data.is_empty() && out.send(Outgoing::Stdin(data)).await.is_err() {
            return;
        }
        if detached {
            let _ = detach.send(()).await;
            return;
        }
    }
    let _ = out.send(Outgoing::StdinEof).await;
}

async fn watch_size(out: mpsc::Sender<Outgoing>) {
    let Ok(mut changes) = signal(SignalKind::window_change()) else { return };
    while changes.recv().await.is_some() {
        if let Some((rows, cols)) = terminal_size()
            && out.send(Outgoing::Resize { rows, cols }).await.is_err()
        {
            return;
        }
    }
}

/// The signals `--sig-proxy` passes on, and their names for `kill`.
fn proxied() -> [(SignalKind, &'static str); 6] {
    [
        (SignalKind::interrupt(), "INT"),
        (SignalKind::terminate(), "TERM"),
        (SignalKind::hangup(), "HUP"),
        (SignalKind::quit(), "QUIT"),
        (SignalKind::user_defined1(), "USR1"),
        (SignalKind::user_defined2(), "USR2"),
    ]
}

async fn proxy_signals(client: Client, id: String) {
    let mut signals: Vec<(Signal, &str)> =
        proxied().into_iter().filter_map(|(kind, name)| Some((signal(kind).ok()?, name))).collect();
    loop {
        let name = next_signal(&mut signals).await;
        // One that can't be delivered (the container has just exited)
        // changes nothing: the session reports the exit.
        let _ = client.kill(&id, Some(name)).await;
    }
}

/// SIGTERM and SIGHUP while in raw mode: leave cleanly instead of dying
/// with the terminal still raw.
async fn watch_termination(tx: mpsc::Sender<i32>) {
    let mut signals: Vec<(Signal, i32)> = [(SignalKind::terminate(), 15), (SignalKind::hangup(), 1)]
        .into_iter()
        .filter_map(|(kind, signo)| Some((signal(kind).ok()?, signo)))
        .collect();
    let signo = next_signal(&mut signals).await;
    let _ = tx.send(signo).await;
}

/// Waits for any of `signals`; returns its tag.
async fn next_signal<T: Copy>(signals: &mut [(Signal, T)]) -> T {
    poll_fn(|cx| {
        for (signal, tag) in signals.iter_mut() {
            if let Poll::Ready(Some(())) = signal.poll_recv(cx) {
                return Poll::Ready(*tag);
            }
        }
        Poll::Pending
    })
    .await
}

/// Recognises the detach keys in the input, also when a read ends between
/// them. A key that starts the sequence is held back until the next byte
/// shows whether the sequence follows; if it doesn't, the held key is
/// input after all and goes out with that byte.
#[derive(Debug, Default)]
pub struct DetachKeys {
    matched: usize,
}

impl DetachKeys {
    /// The bytes of `input` to forward, and whether the sequence is now
    /// complete (whatever followed it is dropped: the session is over).
    pub fn feed(&mut self, input: &[u8]) -> (Vec<u8>, bool) {
        let mut forward = Vec::with_capacity(input.len() + self.matched);
        for &b in input {
            if b == DETACH_KEYS[self.matched] {
                self.matched += 1;
                if self.matched == DETACH_KEYS.len() {
                    self.matched = 0;
                    return (forward, true);
                }
                continue;
            }
            forward.extend_from_slice(&DETACH_KEYS[..self.matched]);
            self.matched = usize::from(b == DETACH_KEYS[0]);
            if self.matched == 0 {
                forward.push(b);
            }
        }
        (forward, false)
    }
}

/// Raw mode on the CLI's terminal, for as long as this lives.
struct RawMode;

impl RawMode {
    fn enable() -> anyhow::Result<RawMode> {
        static HOOK: Once = Once::new();
        HOOK.call_once(|| {
            let previous = std::panic::take_hook();
            std::panic::set_hook(Box::new(move |info| {
                // The hook runs before unwinding drops the guard: restore
                // first, or the message comes out staircased.
                let _ = crossterm::terminal::disable_raw_mode();
                previous(info);
            }));
        });
        crossterm::terminal::enable_raw_mode().context("putting the terminal into raw mode")?;
        Ok(RawMode)
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        let _ = crossterm::terminal::disable_raw_mode();
    }
}

/// Tasks that end with the relay.
#[derive(Default)]
struct Tasks(Vec<JoinHandle<()>>);

impl Tasks {
    fn spawn(&mut self, task: impl Future<Output = ()> + Send + 'static) {
        self.0.push(tokio::spawn(task));
    }
}

impl Drop for Tasks {
    fn drop(&mut self) {
        for task in &self.0 {
            task.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Feeds `chunks` in turn: what was forwarded, and whether it detached.
    fn feed(chunks: &[&[u8]]) -> (Vec<u8>, bool) {
        let mut keys = DetachKeys::default();
        let mut forwarded = Vec::new();
        for chunk in chunks {
            let (data, detached) = keys.feed(chunk);
            forwarded.extend(data);
            if detached {
                return (forwarded, true);
            }
        }
        (forwarded, false)
    }

    #[test]
    fn detach_keys_in_one_read() {
        assert_eq!(feed(&[b"ls\r\x10\x11ignored"]), (b"ls\r".to_vec(), true));
        assert_eq!(feed(&[b"\x10\x11"]), (vec![], true));
    }

    #[test]
    fn detach_keys_split_across_reads() {
        assert_eq!(feed(&[b"ab\x10", b"\x11"]), (b"ab".to_vec(), true));
        assert_eq!(feed(&[b"\x10", b"", b"\x11"]), (vec![], true));
    }

    #[test]
    fn a_lone_ctrl_p_is_input_after_all() {
        // Held back until the next byte, then sent with it.
        let mut keys = DetachKeys::default();
        assert_eq!(keys.feed(b"x\x10"), (b"x".to_vec(), false));
        assert_eq!(keys.feed(b"y"), (b"\x10y".to_vec(), false));
        // Two Ctrl-Ps, then Ctrl-Q: the first is input, the second starts
        // the sequence.
        assert_eq!(feed(&[b"\x10", b"\x10", b"\x11"]), (b"\x10".to_vec(), true));
        assert_eq!(feed(&[b"\x10\x10\x10q"]), (b"\x10\x10\x10q".to_vec(), false));
        // Ctrl-Q alone is just input.
        assert_eq!(feed(&[b"\x11\x11"]), (b"\x11\x11".to_vec(), false));
    }
}

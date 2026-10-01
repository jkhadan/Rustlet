//! The daemon ↔ shim protocol on `shim.sock`.
//!
//! A connection carries frames:
//!
//! ```text
//!  [len: u32, big-endian][kind: u8][payload: len - 1 bytes]
//!
//!  kind 0  message   a JSON Request (daemon → shim) or Response (shim → daemon)
//!  kind 1  stdin     bytes for the process's input   (daemon → shim)
//!  kind 2  stdout    the process's output            (shim → daemon)
//!  kind 3  stderr
//! ```
//!
//! Most requests get one response. [`Request::Attach`] and [`Request::Exec`]
//! turn the connection into a stream once they are answered `Ok`/`Started`:
//! output frames flow from the shim, stdin frames and the stream requests
//! ([`Request::Resize`], [`Request::CloseStdin`]) from the daemon, until the
//! shim sends [`Response::Exited`] and closes. [`Request::Wait`] is answered
//! when the container exits, possibly much later. Requests that change
//! state are served one at a time.

use std::io;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The largest frame accepted (length field included in neither).
pub const MAX_FRAME: usize = 1 << 20;
/// Output is sent in chunks of at most this many bytes.
pub const CHUNK: usize = 64 * 1024;

pub const KIND_MESSAGE: u8 = 0;
pub const KIND_STDIN: u8 = 1;
pub const KIND_STDOUT: u8 = 2;
pub const KIND_STDERR: u8 = 3;

/// One frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// The JSON of a [`Request`] or [`Response`].
    Message(Vec<u8>),
    Stdin(Vec<u8>),
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
}

impl Frame {
    pub fn request(r: &Request) -> Frame {
        Frame::Message(serde_json::to_vec(r).expect("requests serialize"))
    }
    pub fn response(r: &Response) -> Frame {
        Frame::Message(serde_json::to_vec(r).expect("responses serialize"))
    }
    fn kind(&self) -> u8 {
        match self {
            Frame::Message(_) => KIND_MESSAGE,
            Frame::Stdin(_) => KIND_STDIN,
            Frame::Stdout(_) => KIND_STDOUT,
            Frame::Stderr(_) => KIND_STDERR,
        }
    }
    fn payload(&self) -> &[u8] {
        match self {
            Frame::Message(b) | Frame::Stdin(b) | Frame::Stdout(b) | Frame::Stderr(b) => b,
        }
    }
}

/// Reads one frame; `Ok(None)` at a clean end of the connection (between
/// frames).
pub async fn read_frame(r: &mut (impl AsyncRead + Unpin)) -> io::Result<Option<Frame>> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_be_bytes(len) as usize;
    if len == 0 || len > MAX_FRAME + 1 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("bad frame length {len}")));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    let payload = buf.split_off(1);
    Ok(Some(match buf[0] {
        KIND_MESSAGE => Frame::Message(payload),
        KIND_STDIN => Frame::Stdin(payload),
        KIND_STDOUT => Frame::Stdout(payload),
        KIND_STDERR => Frame::Stderr(payload),
        k => return Err(io::Error::new(io::ErrorKind::InvalidData, format!("bad frame kind {k}"))),
    }))
}

/// Writes one frame (and flushes).
pub async fn write_frame(w: &mut (impl AsyncWrite + Unpin), frame: &Frame) -> io::Result<()> {
    let payload = frame.payload();
    if payload.len() > MAX_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "frame too large"));
    }
    let mut buf = Vec::with_capacity(payload.len() + 5);
    buf.extend_from_slice(&(payload.len() as u32 + 1).to_be_bytes());
    buf.push(frame.kind());
    buf.extend_from_slice(payload);
    w.write_all(&buf).await?;
    w.flush().await
}

/// Parses a message frame's JSON.
pub fn decode<T: for<'de> Deserialize<'de>>(json: &[u8]) -> io::Result<T> {
    serde_json::from_slice(json).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Daemon → shim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Request {
    /// → [`Response::Status`].
    Status,
    /// Let init `execve` the program (`rustlet-runc start`). → `Ok`.
    Start,
    /// `rustlet-runc kill [--all] <id> <signal>`. → `Ok`.
    Kill { signal: i32, all: bool },
    /// `rustlet-runc pause` / `resume`. → `Ok`.
    Pause,
    Resume,
    /// → [`Response::Exited`] once the container has exited (at once if it
    /// has already).
    Wait,
    /// Stream the container's output from now on, and with `stdin` take
    /// input for it. → `Ok`, then the stream.
    Attach { stdin: bool },
    /// Run another process (`rustlet-runc exec -d`), reaped by the shim.
    /// → [`Response::Started`], then the stream.
    Exec(ExecRequest),
    /// The terminal size: of the container's terminal as a request of its
    /// own or in an attach stream, of the exec's in an exec stream. → `Ok`
    /// (only as a request of its own).
    Resize { rows: u16, cols: u16 },
    /// In a stream: the client's input ended. The process's stdin is closed
    /// if it is an exec's, or the container's when it was started with
    /// `stdin_once`.
    CloseStdin,
    /// `rustlet-runc delete [--force]`: remove the runtime's state and
    /// cgroup once the container has exited (`force`: kill it first). → `Ok`.
    Delete { force: bool },
    /// Exit the shim once the reply is sent. → `Ok`.
    Shutdown,
}

/// What [`Request::Exec`] runs. The process is the container's own
/// (`process` in `config.json`) with these changes, as `rustlet-runc exec`
/// applies them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ExecRequest {
    /// The daemon's id for it (only used in file names and logs).
    pub exec_id: String,
    pub args: Vec<String>,
    /// `KEY=VALUE`, over the container's environment.
    pub env: Vec<String>,
    pub cwd: Option<String>,
    /// A resolved user (ids in the container); `None`: the container's.
    pub user: Option<ExecUser>,
    pub tty: bool,
    pub stdin: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ExecUser {
    pub uid: u32,
    pub gid: u32,
    pub additional_gids: Vec<u32>,
}

/// Shim → daemon.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Response {
    Ok,
    /// An exec runs, with this host PID.
    Started { pid: i32 },
    Status(ShimStatus),
    Exited(ExitStatus),
    /// `exit_code`: `rustlet-runc`'s, when it failed (127: the program
    /// wasn't found, 126: it couldn't be executed).
    Error { message: String, exit_code: Option<i32> },
}

/// How a process ended.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ExitStatus {
    /// Shell-style: the exit status, or 128 + the signal.
    pub code: i32,
    /// The signal that killed it, if one did.
    pub signal: Option<i32>,
    /// The container's cgroup saw an OOM kill (`memory.events`) while it
    /// ran. Always false for an exec.
    pub oom_killed: bool,
    /// RFC 3339 with nanoseconds, UTC.
    pub finished_at: String,
}

/// What the shim knows about its container.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ShimStatus {
    pub id: String,
    pub shim_pid: i32,
    /// Host PID of the container's init.
    pub init_pid: i32,
    pub state: ShimState,
    /// Once it has exited.
    pub exit: Option<ExitStatus>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShimState {
    /// Created, init waiting for `Start`.
    #[default]
    Created,
    Running,
    Paused,
    Exited,
}

/// The one line the shim writes to its stdout, a pipe to the daemon, once
/// `rustlet-runc create` has finished; then it closes stdout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Handshake {
    /// The container exists, init waits for `Start`; the socket listens.
    Ready { init_pid: i32, shim_pid: i32 },
    /// Nothing was created (the shim exits).
    Failed { message: String, exit_code: Option<i32> },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn frames_round_trip() {
        let frames = [
            Frame::request(&Request::Kill { signal: 15, all: true }),
            Frame::Stdin(b"hello\n".to_vec()),
            Frame::Stdout(vec![0; CHUNK]),
            Frame::Stderr(Vec::new()),
            Frame::response(&Response::Exited(ExitStatus { code: 137, signal: Some(9), ..Default::default() })),
        ];
        let mut buf = Vec::new();
        for f in &frames {
            write_frame(&mut buf, f).await.unwrap();
        }
        let mut r = &buf[..];
        for f in &frames {
            assert_eq!(read_frame(&mut r).await.unwrap().as_ref(), Some(f));
        }
        assert_eq!(read_frame(&mut r).await.unwrap(), None);
    }

    #[tokio::test]
    async fn bad_frames_are_refused() {
        // Zero length, oversized, unknown kind, truncated payload.
        for bad in [
            vec![0, 0, 0, 0],
            ((MAX_FRAME as u32) + 2).to_be_bytes().to_vec(),
            vec![0, 0, 0, 2, 9, 0],
            vec![0, 0, 0, 5, 0, b'{'],
        ] {
            assert!(read_frame(&mut &bad[..]).await.is_err(), "{bad:?}");
        }
        let mut sink = Vec::new();
        assert!(write_frame(&mut sink, &Frame::Stdout(vec![0; MAX_FRAME + 1])).await.is_err());
    }

    #[test]
    fn messages_are_tagged_json() {
        let r = Request::Exec(ExecRequest { exec_id: "e".into(), args: vec!["ls".into()], ..Default::default() });
        let json = serde_json::to_value(&r).unwrap();
        assert_eq!(json["type"], "exec");
        assert_eq!(json["args"][0], "ls");
        assert_eq!(decode::<Request>(&serde_json::to_vec(&r).unwrap()).unwrap(), r);
        let h = Handshake::Ready { init_pid: 10, shim_pid: 9 };
        assert_eq!(serde_json::to_string(&h).unwrap(), r#"{"ready":{"init_pid":10,"shim_pid":9}}"#);
        let s = Response::Status(ShimStatus { state: ShimState::Running, ..Default::default() });
        assert_eq!(serde_json::to_value(&s).unwrap()["state"], "running");
    }
}

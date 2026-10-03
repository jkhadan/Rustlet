//! The WebSocket framing of `attach` and `exec`.
//!
//! ```text
//!  binary message   [stream: u8][bytes…]      data: 0 = stdin (client → daemon),
//!                                                    1 = stdout, 2 = stderr (daemon → client)
//!  text message     {"type": "…", …}          control: a JSON [`Control`]
//! ```
//!
//! With a terminal there is only stdout: a PTY merges the two outputs.
//! The client sends `resize` whenever its terminal changes size (and once
//! at the start), `stdin_eof` when its input ends, and in an exec session
//! `hangup` when its terminal goes away (the process gets `SIGHUP`). The daemon sends
//! `exit` when the process has exited and its output has been sent, then
//! closes the socket; `error` if the session fails (the start of an exec, a
//! container that exited before it could be attached to).
//!
//! An attach session ends when the container exits; a client that just
//! hangs up (detaches) leaves the container running.

use serde::{Deserialize, Serialize};
use ts_rs::TS;

/// Data stream ids, the first byte of a binary message.
pub const STDIN: u8 = 0;
pub const STDOUT: u8 = 1;
pub const STDERR: u8 = 2;

/// A text message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Control {
    /// Client → daemon: the terminal's size, in characters.
    Resize { rows: u16, cols: u16 },
    /// Client → daemon: no more input.
    StdinEof,
    /// Client → daemon, in an exec session: the client's terminal is gone
    /// (a closed window or tab). The process gets `SIGHUP`, as a shell does
    /// when its terminal closes, and the session ends with its exit as
    /// usual. Without it, a client that hangs up detaches: the process runs
    /// on. In an attach session it means nothing.
    Hangup,
    /// Daemon → client: the process exited (shell-style status).
    Exit { code: i32, oom_killed: bool },
    /// Daemon → client: the session failed. `kind` as in [`crate::ErrorBody`].
    Error { message: String, kind: crate::ErrorKind },
}

/// A binary message for `stream` carrying `data`.
pub fn data_message(stream: u8, data: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(data.len() + 1);
    m.push(stream);
    m.extend_from_slice(data);
    m
}

/// Splits a binary message into its stream id and data.
pub fn parse_data_message(message: &[u8]) -> Option<(u8, &[u8])> {
    let (&stream, data) = message.split_first()?;
    matches!(stream, STDIN | STDOUT | STDERR).then_some((stream, data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_messages_round_trip() {
        let m = data_message(STDERR, b"oops\n");
        assert_eq!(parse_data_message(&m), Some((STDERR, &b"oops\n"[..])));
        assert_eq!(parse_data_message(&[]), None);
        assert_eq!(parse_data_message(&[7, 1]), None);
        assert_eq!(parse_data_message(&[STDIN]), Some((STDIN, &b""[..])));
    }

    #[test]
    fn control_messages_are_tagged() {
        let c = Control::Resize { rows: 24, cols: 80 };
        assert_eq!(serde_json::to_string(&c).unwrap(), r#"{"type":"resize","rows":24,"cols":80}"#);
        let e: Control = serde_json::from_str(r#"{"type":"exit","code":3,"oom_killed":false}"#).unwrap();
        assert_eq!(e, Control::Exit { code: 3, oom_killed: false });
        assert_eq!(serde_json::to_string(&Control::StdinEof).unwrap(), r#"{"type":"stdin_eof"}"#);
        assert_eq!(serde_json::to_string(&Control::Hangup).unwrap(), r#"{"type":"hangup"}"#);
    }
}

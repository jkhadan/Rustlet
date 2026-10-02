//! # rustlet-spec: the daemon's API, as types
//!
//! `rustletd` serves HTTP/1.1 with JSON bodies on a Unix socket
//! ([`DEFAULT_SOCKET`]); `rustlet-client`, the `rustlet` CLI and (from Phase
//! 6) the desktop app talk to it. Every request and response body, every
//! streamed record and the WebSocket framing are defined here, once, so the
//! two sides can't drift apart. JSON field names are the Rust ones
//! (snake_case); every struct takes missing fields as their defaults, so a
//! newer client can talk to an older daemon and the other way round.
//!
//! ## Routes
//!
//! All under `/v1` ([`routes`] builds the paths). `{id}` is a container's
//! full id, a unique prefix of it (12 characters is the usual short form), or
//! its name.
//!
//! | method | path | body → response |
//! |---|---|---|
//! | GET | `/_ping` | → `OK` (text) |
//! | GET | `/version` | → [`system::Version`] |
//! | GET | `/info` | → [`system::Info`] |
//! | GET | `/events?since=&container=` | → NDJSON [`event::Event`], until the client hangs up |
//! | GET | `/containers?all=` | → `[`[`container::ContainerSummary`]`]` (running only, unless `all=true`) |
//! | POST | `/containers` | [`container::ContainerConfig`] → 201 [`container::CreateResponse`] |
//! | GET | `/containers/{id}` | → [`container::ContainerInspect`] |
//! | DELETE | `/containers/{id}?force=` | → 204 |
//! | POST | `/containers/{id}/start` | → 204 |
//! | POST | `/containers/{id}/stop?timeout=` | → 204 (seconds; default: the container's `stop_timeout`, else 10) |
//! | POST | `/containers/{id}/kill?signal=` | → 204 (`TERM`, `SIGTERM` or `15`; default `KILL`) |
//! | POST | `/containers/{id}/restart?timeout=` | → 204 |
//! | POST | `/containers/{id}/pause` | → 204 |
//! | POST | `/containers/{id}/unpause` | → 204 |
//! | POST | `/containers/{id}/wait?condition=` | → [`container::WaitResponse`] ([`container::WaitCondition`]) |
//! | GET | `/containers/{id}/logs?…` | → NDJSON [`logs::LogEntry`] ([`logs::LogsQuery`]) |
//! | GET | `/containers/{id}/stats?stream=` | → NDJSON [`stats::StatsSample`], one a second (one JSON object with `stream=false`) |
//! | GET | `/containers/{id}/attach?stdin=` | → WebSocket ([`stream`]) |
//! | POST | `/containers/{id}/exec` | [`exec::ExecConfig`] → 201 [`exec::ExecCreated`] |
//! | GET | `/exec/{id}` | → [`exec::ExecInspect`] |
//! | GET | `/exec/{id}/start` | → WebSocket ([`stream`]): runs the process attached |
//! | POST | `/exec/{id}/start` | → [`exec::ExecStarted`]: runs it detached |
//! | GET | `/images` | → `[`[`image::ImageSummary`]`]` |
//! | POST | `/images/pull?reference=&policy=` | → NDJSON [`image::PullEvent`] |
//! | GET | `/images/inspect?name=` | → [`image::ImageInspect`] |
//! | DELETE | `/images?name=&force=` | → [`image::ImageDeleteResponse`] |
//!
//! Image names travel as query parameters, not path segments: a name such as
//! `docker.io/library/alpine:latest` has slashes in it.
//!
//! ## Errors
//!
//! Any failed request answers with a 4xx/5xx status and an [`ErrorBody`]:
//! 400 for a bad request, 404 for something that doesn't exist, 409 for a
//! conflict (a name in use, a container in the wrong state), 500 for
//! everything else. [`ErrorKind`] says the same for programs, plus what a
//! CLI needs to pick its exit code.
//!
//! ## Streams
//!
//! NDJSON (`application/x-ndjson`): one JSON value per line, sent as it
//! happens; the response ends when the stream does (a pull finished, a
//! container's log ended with `follow=false`), or when the client hangs up.
//! A stream that fails halfway can't change its status code any more, so it
//! ends with a final `{"error": "…"}` line ([`StreamError`]) instead; for a
//! pull that is [`image::PullEvent::Error`].
//!
//! Attach and exec are bidirectional, so they are WebSockets; see
//! [`stream`] for the framing.

#![forbid(unsafe_code)]

pub mod container;
pub mod event;
pub mod exec;
pub mod image;
pub mod logs;
pub mod routes;
pub mod stats;
pub mod stream;
pub mod system;

use serde::{Deserialize, Serialize};

/// Where the daemon listens.
pub const DEFAULT_SOCKET: &str = "/run/rustlet/rustlet.sock";

/// The path prefix of every route, and what [`system::Version`] reports.
pub const API_VERSION: &str = "v1";

/// The content type of streamed responses.
pub const NDJSON: &str = "application/x-ndjson";

/// The length of a short container id (as `ps` shows it, and the hostname).
pub const SHORT_ID_LEN: usize = 12;

/// The short form of a container id.
pub fn short_id(id: &str) -> &str {
    &id[..id.len().min(SHORT_ID_LEN)]
}

/// The body of every error response.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ErrorBody {
    pub message: String,
    pub kind: ErrorKind,
}

impl ErrorBody {
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> ErrorBody {
        ErrorBody { message: message.into(), kind }
    }
}

/// What went wrong, for programs: the HTTP status says the same in less
/// detail.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    /// 400: the request itself is wrong (a bad option, an invalid name).
    Invalid,
    /// 404.
    NoSuchContainer,
    /// 404: create a container from an image the store doesn't have; the
    /// CLI pulls it and tries again.
    NoSuchImage,
    /// 404.
    NoSuchExec,
    /// 409: a name is taken, or the container is in the wrong state.
    Conflict,
    /// 500 from `start` or an exec: the program wasn't found in the
    /// container (a CLI exits 127, as a shell would).
    CommandNotFound,
    /// 500 from `start` or an exec: the program exists but can't be
    /// executed (a CLI exits 126).
    CommandNotExecutable,
    /// 500: anything else.
    #[default]
    Internal,
}

impl ErrorKind {
    /// The HTTP status a response with this kind carries.
    pub fn status(self) -> u16 {
        match self {
            ErrorKind::Invalid => 400,
            ErrorKind::NoSuchContainer | ErrorKind::NoSuchImage | ErrorKind::NoSuchExec => 404,
            ErrorKind::Conflict => 409,
            ErrorKind::CommandNotFound | ErrorKind::CommandNotExecutable | ErrorKind::Internal => 500,
        }
    }

    /// The exit code a Docker-like CLI uses when a request fails this way:
    /// 127 and 126 like a shell, 125 for everything else ("the error is
    /// Rustlets', not the container's").
    pub fn cli_exit_code(self) -> i32 {
        match self {
            ErrorKind::CommandNotFound => 127,
            ErrorKind::CommandNotExecutable => 126,
            _ => 125,
        }
    }
}

/// The last line of an NDJSON stream that failed after it had started.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct StreamError {
    pub error: String,
}

/// Is `name` a valid container name? Docker's rule:
/// `[a-zA-Z0-9][a-zA-Z0-9_.-]*`, and at most 128 characters here.
pub fn valid_container_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else { return false };
    name.len() <= 128
        && first.is_ascii_alphanumeric()
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_for_programs_that_cant_run() {
        assert_eq!(ErrorKind::CommandNotFound.cli_exit_code(), 127);
        assert_eq!(ErrorKind::CommandNotExecutable.cli_exit_code(), 126);
        assert_eq!(ErrorKind::Conflict.cli_exit_code(), 125);
    }

    #[test]
    fn names() {
        for ok in ["web", "a", "web-1", "my_app.v2", "0abc"] {
            assert!(valid_container_name(ok), "{ok}");
        }
        for bad in ["", "-web", "_x", ".x", "a/b", "a b", "ä", &"x".repeat(129)] {
            assert!(!valid_container_name(bad), "{bad}");
        }
    }

    #[test]
    fn error_bodies_round_trip_and_default() {
        let e = ErrorBody::new(ErrorKind::NoSuchImage, "no such image: alpine");
        let json = serde_json::to_string(&e).unwrap();
        assert_eq!(json, r#"{"message":"no such image: alpine","kind":"no_such_image"}"#);
        assert_eq!(serde_json::from_str::<ErrorBody>(&json).unwrap(), e);
        // An older daemon's body without a kind still parses.
        let old: ErrorBody = serde_json::from_str(r#"{"message":"boom"}"#).unwrap();
        assert_eq!(old.kind, ErrorKind::Internal);
        assert_eq!(ErrorKind::CommandNotFound.cli_exit_code(), 127);
        assert_eq!(ErrorKind::Conflict.status(), 409);
    }

    #[test]
    fn short_ids() {
        assert_eq!(short_id("0123456789abcdef"), "0123456789ab");
        assert_eq!(short_id("abc"), "abc");
    }
}

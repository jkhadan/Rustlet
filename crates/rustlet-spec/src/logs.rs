//! Container logs: the shim's file format and `GET /v1/containers/{id}/logs`.
//!
//! The shim writes what the container prints to
//! `containers/<id>/container.log`, one [`LogEntry`] per line of output, as
//! JSON lines (Docker's `json-file` driver does the same, with other field
//! names). A line longer than 16 KiB is cut into several entries; output
//! that isn't UTF-8 is stored with U+FFFD in place of the invalid bytes.
//! With a terminal, everything is `stdout` (a PTY has one output).
//!
//! When the file reaches its size limit it is renamed to `container.log.1`
//! (and `.1` to `.2`, …) and a new one is started.

use serde::{Deserialize, Serialize};

/// One record: also one line of the NDJSON `logs` response.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct LogEntry {
    /// When the shim read it: RFC 3339 with nanoseconds, UTC.
    pub ts: String,
    pub stream: LogStream,
    /// The text, including its `\n` (the last entry before an exit may
    /// lack one).
    pub log: String,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogStream {
    #[default]
    Stdout,
    Stderr,
}

/// Query of `GET /v1/containers/{id}/logs`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct LogsQuery {
    /// Keep the response open and send new entries as they are written,
    /// until the container exits (and its last output is sent).
    pub follow: bool,
    /// Only the last N entries (before following).
    pub tail: Option<u64>,
    /// Only entries at or after this time: RFC 3339, or Unix seconds
    /// (fractions allowed).
    pub since: Option<String>,
    /// Only entries before this time.
    pub until: Option<String>,
    pub stdout: bool,
    pub stderr: bool,
}

impl Default for LogsQuery {
    fn default() -> LogsQuery {
        LogsQuery { follow: false, tail: None, since: None, until: None, stdout: true, stderr: true }
    }
}

/// Lines longer than this are split into several entries.
pub const MAX_LINE: usize = 16 * 1024;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_defaults_include_both_streams() {
        let q: LogsQuery = serde_json::from_str(r#"{"follow":true}"#).unwrap();
        assert!(q.follow && q.stdout && q.stderr && q.tail.is_none());
    }

    #[test]
    fn entries_are_compact() {
        let e = LogEntry { ts: "2026-10-01T00:00:00.000000001Z".into(), stream: LogStream::Stderr, log: "x\n".into() };
        assert_eq!(
            serde_json::to_string(&e).unwrap(),
            r#"{"ts":"2026-10-01T00:00:00.000000001Z","stream":"stderr","log":"x\n"}"#
        );
    }
}

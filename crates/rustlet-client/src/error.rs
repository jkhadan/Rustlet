//! What can go wrong talking to rustletd.
//!
//! The variants follow what a caller does about them. An [`Error::Api`] is
//! the daemon's own answer: its [`ErrorKind`] picks a CLI's exit code, and
//! `NoSuchImage` is what makes `run` pull and try again. [`Error::Connect`]
//! means the daemon wasn't reached at all, and says why in words a user can
//! act on ("is rustletd running?", "use sudo or join the group"). The rest
//! are transport and protocol failures, which only a bug or a daemon going
//! away explains.
//!
//! Every message is complete on its own: it includes the underlying error's
//! text, and so no variant also returns that error as its `source()`.
//! Printing the chain (`anyhow`'s `{:#}`) would otherwise say it twice.

use std::io;
use std::path::PathBuf;

use rustlet_spec::{ErrorBody, ErrorKind};
use tokio_tungstenite::tungstenite;

/// `Result` with [`Error`].
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// A failed call.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The daemon answered with an error status (or refused a WebSocket
    /// upgrade with one); `body` is its [`ErrorBody`].
    #[error("{}", .body.message)]
    Api { status: u16, body: ErrorBody },
    /// The socket couldn't be connected to: the daemon isn't running, or
    /// this user may not use its socket.
    #[error("cannot connect to rustletd at {}: {}", .socket.display(), connect_reason(.cause))]
    Connect { socket: PathBuf, cause: io::Error },
    /// Reading or writing the connection failed.
    #[error("connection to rustletd: {0}")]
    Io(io::Error),
    /// A body that isn't the JSON the contract describes.
    #[error("unexpected answer from rustletd: {0}")]
    Json(serde_json::Error),
    /// The HTTP exchange failed (the daemon hung up halfway through a
    /// response, say).
    #[error("HTTP: {}", chain(.0))]
    Http(hyper::Error),
    /// A request that couldn't be put together (a query that doesn't
    /// encode). Only a bug in this crate produces one.
    #[error("invalid request: {0}")]
    Request(String),
    /// The WebSocket of an attach or exec session failed.
    #[error("WebSocket: {0}")]
    WebSocket(Box<tungstenite::Error>),
    /// The daemon broke the protocol: a data message for a stream that
    /// doesn't exist, a control message that isn't one, or a session that
    /// was closed before it reported how the process ended.
    #[error("protocol error: {0}")]
    Protocol(String),
    /// An NDJSON stream that had started ended with an error line
    /// (`{"error": "…"}`, or a pull's `error` event): the message is the
    /// daemon's.
    #[error("{0}")]
    Stream(String),
    /// `RUSTLET_HOST` or `--host` names something other than a Unix socket.
    #[error("invalid host {0:?}: expected unix:///path/to/socket or a path")]
    InvalidHost(String),
}

impl Error {
    /// The daemon's [`ErrorKind`], for an [`Error::Api`].
    pub fn kind(&self) -> Option<ErrorKind> {
        match self {
            Error::Api { body, .. } => Some(body.kind),
            _ => None,
        }
    }

    /// The HTTP status, for an [`Error::Api`].
    pub fn status(&self) -> Option<u16> {
        match self {
            Error::Api { status, .. } => Some(*status),
            _ => None,
        }
    }

    /// A 404: no such container, image or exec. (An older daemon may not
    /// say which kind; the status still does.)
    pub fn is_not_found(&self) -> bool {
        self.status() == Some(404)
    }

    /// An API error with the daemon's `kind` and `message`, as a session's
    /// `error` control reports one.
    pub fn api(kind: ErrorKind, message: impl Into<String>) -> Error {
        Error::Api { status: kind.status(), body: ErrorBody::new(kind, message) }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error {
        Error::Io(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Error {
        Error::Json(e)
    }
}

impl From<hyper::Error> for Error {
    fn from(e: hyper::Error) -> Error {
        Error::Http(e)
    }
}

impl From<http::Error> for Error {
    fn from(e: http::Error) -> Error {
        Error::Request(e.to_string())
    }
}

impl From<tungstenite::Error> for Error {
    fn from(e: tungstenite::Error) -> Error {
        Error::WebSocket(Box::new(e))
    }
}

/// Why a connect failed, with what to do about the two failures a user
/// actually meets.
fn connect_reason(e: &io::Error) -> String {
    match e.kind() {
        io::ErrorKind::NotFound => "no such socket (is rustletd running?)".to_owned(),
        // A socket file left behind by a daemon that is gone.
        io::ErrorKind::ConnectionRefused => "connection refused (is rustletd running?)".to_owned(),
        io::ErrorKind::PermissionDenied => "permission denied (the socket is for root and the `rustlet` group, \
                                            which is root-equivalent: use sudo, or ask to be added to the group)"
            .to_owned(),
        _ => e.to_string(),
    }
}

/// `e` and its sources, joined with ": ". hyper's own message is only the
/// outer layer ("error reading a body from connection"); what happened is
/// in the sources.
fn chain(e: &dyn std::error::Error) -> String {
    let mut s = e.to_string();
    let mut source = e.source();
    while let Some(cause) = source {
        s.push_str(": ");
        s.push_str(&cause.to_string());
        source = cause.source();
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_errors_say_what_to_do() {
        let e = |kind| Error::Connect { socket: "/run/rustlet/rustlet.sock".into(), cause: io::Error::from(kind) };
        let missing = e(io::ErrorKind::NotFound).to_string();
        assert!(missing.starts_with("cannot connect to rustletd at /run/rustlet/rustlet.sock: "), "{missing}");
        assert!(missing.contains("is rustletd running?"), "{missing}");
        let denied = e(io::ErrorKind::PermissionDenied).to_string();
        assert!(denied.contains("sudo") && denied.contains("`rustlet` group"), "{denied}");
        assert!(e(io::ErrorKind::ConnectionRefused).to_string().contains("is rustletd running?"));
    }

    #[test]
    fn api_errors_show_the_daemons_message() {
        let e = Error::api(ErrorKind::NoSuchImage, "no such image: alpine");
        assert_eq!(e.to_string(), "no such image: alpine");
        assert_eq!(e.kind(), Some(ErrorKind::NoSuchImage));
        assert_eq!(e.status(), Some(404));
        assert!(e.is_not_found());
        assert!(std::error::Error::source(&e).is_none());
    }
}

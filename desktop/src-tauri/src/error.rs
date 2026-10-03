//! What a failed command gives the frontend.
//!
//! A command that returns `Err` makes the frontend's `invoke()` promise
//! reject with the error serialized as JSON: here a [`CommandError`],
//! `{"kind": "...", "message": "..."}`. The frontend decides what to do from
//! the kind and shows the message as it is:
//!
//! | kind | when | the frontend |
//! |---|---|---|
//! | `unreachable` | nothing listens on the socket (the daemon is stopped) | shows "start the daemon" |
//! | `denied` | the socket isn't this user's to use | explains the `rustlet` group |
//! | the daemon's [`ErrorKind`] (`no_such_image`, `conflict`, …) | the daemon refused | `no_such_image` makes "run" pull first |
//! | `failed` | anything else (a broken connection, a protocol error) | shows the message |

use std::io;

use rustlet_spec::ErrorKind;
use serde::Serialize;

/// A failed command, as the frontend receives it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CommandError {
    pub kind: String,
    pub message: String,
}

pub type CommandResult<T> = Result<T, CommandError>;

impl CommandError {
    pub fn failed(message: impl Into<String>) -> CommandError {
        CommandError { kind: "failed".into(), message: message.into() }
    }

    /// The daemon's own kind of error, as the API spells it.
    fn api(kind: ErrorKind, message: String) -> CommandError {
        let kind = match serde_json::to_value(kind) {
            Ok(serde_json::Value::String(s)) => s,
            _ => "failed".into(),
        };
        CommandError { kind, message }
    }
}

impl From<rustlet_client::Error> for CommandError {
    fn from(e: rustlet_client::Error) -> CommandError {
        let message = e.to_string();
        match e {
            rustlet_client::Error::Api { body, .. } => CommandError::api(body.kind, message),
            rustlet_client::Error::Connect { cause, .. } => {
                let kind = if cause.kind() == io::ErrorKind::PermissionDenied { "denied" } else { "unreachable" };
                CommandError { kind: kind.into(), message }
            }
            _ => CommandError::failed(message),
        }
    }
}

impl std::fmt::Display for CommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.message, self.kind)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_follow_what_the_frontend_does() {
        let e = CommandError::from(rustlet_client::Error::api(ErrorKind::NoSuchImage, "no such image: x"));
        assert_eq!(e, CommandError { kind: "no_such_image".into(), message: "no such image: x".into() });
        let refused = rustlet_client::Error::Connect {
            socket: "/run/rustlet/rustlet.sock".into(),
            cause: io::Error::from(io::ErrorKind::ConnectionRefused),
        };
        assert_eq!(CommandError::from(refused).kind, "unreachable");
        let denied = rustlet_client::Error::Connect {
            socket: "/run/rustlet/rustlet.sock".into(),
            cause: io::Error::from(io::ErrorKind::PermissionDenied),
        };
        let denied = CommandError::from(denied);
        assert_eq!(denied.kind, "denied");
        assert!(denied.message.contains("/run/rustlet/rustlet.sock"), "{denied:?}");
        assert_eq!(CommandError::from(rustlet_client::Error::Protocol("x".into())).kind, "failed");
        // The JSON the frontend's `invoke()` rejects with.
        assert_eq!(
            serde_json::to_string(&CommandError::failed("boom")).unwrap(),
            r#"{"kind":"failed","message":"boom"}"#
        );
    }
}

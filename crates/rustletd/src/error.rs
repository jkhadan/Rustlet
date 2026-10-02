//! Errors as the API reports them: an [`ErrorKind`] (which fixes the HTTP
//! status) and a message for people.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use rustlet_spec::{ErrorBody, ErrorKind};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiError {
    pub kind: ErrorKind,
    pub message: String,
}

pub type ApiResult<T> = Result<T, ApiError>;

impl ApiError {
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> ApiError {
        ApiError { kind, message: message.into() }
    }
    pub fn invalid(message: impl Into<String>) -> ApiError {
        ApiError::new(ErrorKind::Invalid, message)
    }
    pub fn conflict(message: impl Into<String>) -> ApiError {
        ApiError::new(ErrorKind::Conflict, message)
    }
    pub fn internal(message: impl Into<String>) -> ApiError {
        ApiError::new(ErrorKind::Internal, message)
    }
    pub fn no_such_container(id: &str) -> ApiError {
        ApiError::new(ErrorKind::NoSuchContainer, format!("no such container: {id}"))
    }
    pub fn no_such_image(name: &str) -> ApiError {
        ApiError::new(ErrorKind::NoSuchImage, format!("no such image: {name}"))
    }
    pub fn no_such_network(name: &str) -> ApiError {
        ApiError::new(ErrorKind::NoSuchNetwork, format!("no such network: {name}"))
    }
    pub fn no_such_volume(name: &str) -> ApiError {
        ApiError::new(ErrorKind::NoSuchVolume, format!("no such volume: {name}"))
    }

    /// A failure of `rustlet-runc` with its exit status: 127 and 126 keep
    /// their shell meaning.
    pub fn runtime(message: impl Into<String>, exit_code: Option<i32>) -> ApiError {
        let kind = match exit_code {
            Some(127) => ErrorKind::CommandNotFound,
            Some(126) => ErrorKind::CommandNotExecutable,
            _ => ErrorKind::Internal,
        };
        ApiError::new(kind, message)
    }

    /// Adds what was being done in front of the message.
    pub fn context(self, what: impl std::fmt::Display) -> ApiError {
        ApiError { kind: self.kind, message: format!("{what}: {}", self.message) }
    }

    pub fn body(&self) -> ErrorBody {
        ErrorBody::new(self.kind, self.message.clone())
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ApiError {}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.kind.status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        if status.is_server_error() {
            tracing::warn!(kind = ?self.kind, "{}", self.message);
        }
        (status, axum::Json(self.body())).into_response()
    }
}

impl From<rustlet_image::Error> for ApiError {
    fn from(e: rustlet_image::Error) -> ApiError {
        let kind = match &e {
            rustlet_image::Error::Invalid(_) | rustlet_image::Error::Unsupported(_) => ErrorKind::Invalid,
            rustlet_image::Error::NotFound(_) => ErrorKind::NoSuchImage,
            _ => ErrorKind::Internal,
        };
        ApiError::new(kind, e.to_string())
    }
}

impl From<rustlet_runtime::Error> for ApiError {
    fn from(e: rustlet_runtime::Error) -> ApiError {
        ApiError::internal(e.to_string())
    }
}

impl From<rustlet_net::Error> for ApiError {
    fn from(e: rustlet_net::Error) -> ApiError {
        match (&e, e.errno()) {
            (rustlet_net::Error::Invalid(_), _) => ApiError::invalid(e.to_string()),
            (_, Some(rustlet_sys::Errno::EADDRINUSE)) => ApiError::conflict(e.to_string()),
            _ => ApiError::internal(e.to_string()),
        }
    }
}

impl From<std::io::Error> for ApiError {
    fn from(e: std::io::Error) -> ApiError {
        ApiError::internal(e.to_string())
    }
}

impl From<rusqlite::Error> for ApiError {
    fn from(e: rusqlite::Error) -> ApiError {
        ApiError::internal(format!("state database: {e}"))
    }
}

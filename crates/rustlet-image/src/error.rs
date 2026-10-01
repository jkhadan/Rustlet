//! Errors from the image layer.
//!
//! Like the runtime's, every error says what was being done when it
//! happened ([`Context`]), because "No such file or directory" alone is
//! useless when a pull touches thousands of files.

/// What went wrong.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A file operation failed.
    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: std::io::Error,
    },
    /// A system call failed.
    #[error("{context}: {errno}")]
    Sys { context: String, errno: rustlet_sys::Errno },
    /// Malformed input: a reference, digest, manifest, config or layer entry.
    #[error("{0}")]
    Invalid(String),
    /// Content didn't hash (or measure) to what its descriptor says.
    #[error("{what}: expected {expected}, got {actual}")]
    DigestMismatch { what: String, expected: String, actual: String },
    /// Something the store doesn't have.
    #[error("{0}")]
    NotFound(String),
    /// Something this build deliberately doesn't do.
    #[error("{0}")]
    Unsupported(String),
    /// The registry refused, or the network failed.
    #[error("registry: {0}")]
    Registry(String),
    /// JSON that didn't parse or serialize.
    #[error("{context}: {source}")]
    Json {
        context: String,
        #[source]
        source: serde_json::Error,
    },
    /// Deleting a directory tree was refused or failed.
    #[error("{context}: {source}")]
    Remove {
        context: String,
        #[source]
        source: rustlet_sys::tree::RemoveError,
    },
    /// The runtime library refused something (building a spec, writing maps).
    #[error(transparent)]
    Runtime(#[from] rustlet_runtime::Error),
}

/// `Result` with [`Error`].
pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub(crate) fn invalid(msg: impl Into<String>) -> Error {
        Error::Invalid(msg.into())
    }

    pub(crate) fn unsupported(msg: impl Into<String>) -> Error {
        Error::Unsupported(msg.into())
    }

    /// The kernel's error number, if this came from a system call (directly
    /// or through `std::io`).
    pub fn errno(&self) -> Option<rustlet_sys::Errno> {
        match self {
            Error::Sys { errno, .. } => Some(*errno),
            Error::Io { source, .. } => source.raw_os_error().map(rustlet_sys::Errno::from_raw),
            _ => None,
        }
    }
}

/// Adds "what we were doing" to an error.
pub trait Context<T> {
    fn context(self, context: impl Into<String>) -> Result<T>;
    fn with_context<C: Into<String>>(self, f: impl FnOnce() -> C) -> Result<T>;
}

impl<T> Context<T> for std::result::Result<T, std::io::Error> {
    fn context(self, context: impl Into<String>) -> Result<T> {
        self.map_err(|source| Error::Io { context: context.into(), source })
    }
    fn with_context<C: Into<String>>(self, f: impl FnOnce() -> C) -> Result<T> {
        self.map_err(|source| Error::Io { context: f().into(), source })
    }
}

impl<T> Context<T> for std::result::Result<T, rustlet_sys::Errno> {
    fn context(self, context: impl Into<String>) -> Result<T> {
        self.map_err(|errno| Error::Sys { context: context.into(), errno })
    }
    fn with_context<C: Into<String>>(self, f: impl FnOnce() -> C) -> Result<T> {
        self.map_err(|errno| Error::Sys { context: f().into(), errno })
    }
}

impl<T> Context<T> for std::result::Result<T, serde_json::Error> {
    fn context(self, context: impl Into<String>) -> Result<T> {
        self.map_err(|source| Error::Json { context: context.into(), source })
    }
    fn with_context<C: Into<String>>(self, f: impl FnOnce() -> C) -> Result<T> {
        self.map_err(|source| Error::Json { context: f().into(), source })
    }
}

impl<T> Context<T> for std::result::Result<T, rustlet_sys::tree::RemoveError> {
    fn context(self, context: impl Into<String>) -> Result<T> {
        self.map_err(|source| Error::Remove { context: context.into(), source })
    }
    fn with_context<C: Into<String>>(self, f: impl FnOnce() -> C) -> Result<T> {
        self.map_err(|source| Error::Remove { context: f().into(), source })
    }
}

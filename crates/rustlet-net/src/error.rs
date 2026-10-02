//! Errors from host-side networking.
//!
//! As in the other crates, every error says what was being done when it
//! happened ([`Context`]): "File exists" means little until it reads
//! "create the veth rlv0123456789ab: File exists".

/// What went wrong.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A file or socket operation failed.
    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: std::io::Error,
    },
    /// A system call (netlink included) failed.
    #[error("{context}: {errno}")]
    Sys { context: String, errno: rustlet_sys::Errno },
    /// Malformed input: a subnet, an address, a name.
    #[error("{0}")]
    Invalid(String),
    /// `nft` refused a ruleset, or couldn't be run.
    #[error("nft: {0}")]
    Nft(String),
}

/// `Result` with [`Error`].
pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    #[allow(dead_code)]
    pub(crate) fn invalid(msg: impl Into<String>) -> Error {
        Error::Invalid(msg.into())
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

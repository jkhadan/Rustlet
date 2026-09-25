//! The runtime's error type.
//!
//! Errors carry *context* ("mount proc on /proc") next to the raw kernel
//! `errno`, because `EINVAL` alone tells you almost nothing when a container
//! fails to start. Errors raised inside the container's init process travel
//! back to `rustlet-runc` as text over the sync socket (see `sync`), so they
//! end up as [`Error::Init`].

use rustlet_sys::Errno;

/// Result type of this crate.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// One feature that `config.json` asks for but this build doesn't implement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unsupported {
    /// The spec field, e.g. `linux.seccomp`.
    pub field: String,
    /// When support is planned, e.g. `Phase 2b`.
    pub when: &'static str,
}

/// Everything that can go wrong in the runtime.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// `config.json` is malformed or asks for something that is never allowed.
    #[error("invalid config.json: {0}")]
    InvalidSpec(String),

    /// `config.json` uses features this build doesn't implement yet. They are
    /// rejected instead of ignored: silently skipping, say, `linux.seccomp`
    /// would run the container with less isolation than its author asked for.
    #[error("config.json uses features this build does not support yet:{}", list(.0))]
    Unsupported(Vec<Unsupported>),

    /// A lifecycle operation doesn't apply: the container doesn't exist, is
    /// in the wrong state, already exists, …
    #[error("{0}")]
    Container(String),

    /// A system call failed.
    #[error("{context}: {errno}")]
    Sys { context: String, errno: Errno },

    /// A file operation through `std` failed. The error is part of the
    /// message and deliberately *not* the error's `source()`: otherwise
    /// `{:#}` printing would show it twice. (Which is also why the field
    /// isn't called `source`: thiserror treats a field of that name as the
    /// source even without `#[source]`.)
    #[error("{context}: {err}")]
    Io { context: String, err: std::io::Error },

    /// The container's init process failed before it could `execve` the
    /// user's program. `errno` is the underlying kernel error, if any.
    #[error("container init failed: {message}")]
    Init { message: String, errno: Option<i32> },

    /// Everything was set up, but the user's program itself could not be
    /// executed: not found in `$PATH` (`ENOENT`), not executable, … Kept
    /// apart from [`Error::Init`] so the CLI can exit 127/126 like a shell
    /// for exactly this case, and not for, say, a missing bind-mount source.
    #[error("cannot run the program: {message}")]
    Exec { message: String, errno: Errno },
}

fn list(items: &[Unsupported]) -> String {
    items.iter().map(|u| format!("\n  - {} ({})", u.field, u.when)).collect()
}

impl Error {
    /// The kernel error behind this error, if there is one.
    pub fn errno(&self) -> Option<Errno> {
        match self {
            Error::Sys { errno, .. } => Some(*errno),
            Error::Io { err, .. } => err.raw_os_error().map(Errno::from_raw),
            Error::Init { errno, .. } => errno.map(Errno::from_raw),
            Error::Exec { errno, .. } => Some(*errno),
            Error::InvalidSpec(_) | Error::Unsupported(_) | Error::Container(_) => None,
        }
    }

    pub(crate) fn invalid(msg: impl Into<String>) -> Error {
        Error::InvalidSpec(msg.into())
    }

    pub(crate) fn container(msg: impl Into<String>) -> Error {
        Error::Container(msg.into())
    }
}

/// Adds context to `Errno` and `io::Error` results, like `anyhow::Context`
/// but producing our typed [`Error`].
pub(crate) trait Context<T> {
    fn context(self, context: impl Into<String>) -> Result<T>;
    fn with_context<C: Into<String>>(self, f: impl FnOnce() -> C) -> Result<T>;
}

impl<T> Context<T> for std::result::Result<T, Errno> {
    fn context(self, context: impl Into<String>) -> Result<T> {
        self.map_err(|errno| Error::Sys { context: context.into(), errno })
    }
    fn with_context<C: Into<String>>(self, f: impl FnOnce() -> C) -> Result<T> {
        self.map_err(|errno| Error::Sys { context: f().into(), errno })
    }
}

impl<T> Context<T> for std::result::Result<T, std::io::Error> {
    fn context(self, context: impl Into<String>) -> Result<T> {
        self.map_err(|err| Error::Io { context: context.into(), err })
    }
    fn with_context<C: Into<String>>(self, f: impl FnOnce() -> C) -> Result<T> {
        self.map_err(|err| Error::Io { context: f().into(), err })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_lists_every_field() {
        let e = Error::Unsupported(vec![
            Unsupported { field: "linux.seccomp".into(), when: "Phase 2b" },
            Unsupported { field: "process.terminal".into(), when: "Phase 2a" },
        ]);
        let s = e.to_string();
        assert!(s.contains("linux.seccomp (Phase 2b)"), "{s}");
        assert!(s.contains("process.terminal (Phase 2a)"), "{s}");
    }

    #[test]
    fn io_errors_are_printed_once() {
        let e = Err::<(), _>(std::io::Error::from_raw_os_error(libc::ENOENT)).context("read x").unwrap_err();
        // No source(): `{:#}` in the CLI would repeat the message otherwise.
        assert!(std::error::Error::source(&e).is_none());
        assert_eq!(e.to_string(), "read x: No such file or directory (os error 2)");
        assert_eq!(e.errno(), Some(Errno::ENOENT));
    }

    #[test]
    fn context_keeps_errno() {
        let r: Result<()> = Err(Errno::EPERM).context("mount proc");
        let e = r.unwrap_err();
        assert_eq!(e.errno(), Some(Errno::EPERM));
        assert!(e.to_string().starts_with("mount proc: EPERM"));
    }
}

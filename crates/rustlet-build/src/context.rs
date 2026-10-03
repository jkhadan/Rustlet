//! Packing a build context: the client's half of a build.
//!
//! `rustlet build DIR` sends DIR as a tar archive, less what the ignore
//! file excludes (`ignore`). Like Docker's CLI, the client does this, so
//! that what is excluded (a `target/` of gigabytes, `.git`, secrets) never
//! leaves it:
//!
//! - entries in byte order of their paths, parents first; directories,
//!   regular files, symlinks (as symlinks, their targets as they are); hard
//!   links as separate files; FIFOs, sockets and devices left out;
//! - owners 0:0 and no user or group names (`COPY` sets its own owners;
//!   the client's ids mean nothing in an image); modes and modification
//!   times kept;
//! - the Containerfile and the ignore file are always included, even if a
//!   pattern excludes them (the daemon needs the first; Docker does the
//!   same);
//! - a Containerfile outside the context (`-f ../Containerfile`) is added
//!   as `.rustlet-containerfile` ([`dockerfile_name`] says which name the
//!   build's options should give);
//! - a symlink or a path that can't be read is an error naming it, except
//!   what is excluded (never looked at, unless an exception needs the walk
//!   to enter it).
//!
//! [`pack`] writes to any `std::io::Write`: `rustlet_client::RequestBody::
//! pipe` sends it as it is written.

use std::io::Write;
use std::path::{Path, PathBuf};

/// The default Containerfile of `context`: `Containerfile`, else
/// `Dockerfile`, if one is there.
pub fn default_containerfile(context: &Path) -> Option<PathBuf> {
    let _ = context;
    unimplemented!("default_containerfile: agent A")
}

/// The name the Containerfile `containerfile` has inside the packed
/// context (its path relative to `context`, `/`-separated, or
/// `.rustlet-containerfile` when it is outside): what
/// `BuildOptions::dockerfile` should say.
pub fn dockerfile_name(context: &Path, containerfile: &Path) -> Result<String, ContextError> {
    let _ = (context, containerfile);
    unimplemented!("dockerfile_name: agent A")
}

/// What [`pack`] put in the archive.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Packed {
    /// [`dockerfile_name`]'s answer.
    pub dockerfile: String,
    /// Entries (directories included).
    pub entries: u64,
    /// Bytes of file content.
    pub bytes: u64,
    /// Paths excluded by the ignore file (directories counted once).
    pub excluded: u64,
}

/// Why a context couldn't be packed.
#[derive(Debug, thiserror::Error)]
pub enum ContextError {
    #[error("{path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("{0}")]
    Invalid(String),
}

/// Packs `context` (a directory) with `containerfile` (as given, relative
/// to the current directory or absolute) into `out`.
pub fn pack(context: &Path, containerfile: &Path, out: &mut dyn Write) -> Result<Packed, ContextError> {
    let _ = (context, containerfile, out);
    unimplemented!("pack: agent A")
}

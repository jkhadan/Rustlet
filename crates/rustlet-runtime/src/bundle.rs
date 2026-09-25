//! OCI bundles: a directory holding `config.json` and (usually) the rootfs.
//!
//! ```text
//! bundle/
//! ├─ config.json     the runtime spec: process, mounts, namespaces, …
//! └─ rootfs/         the container's `/`, referenced by `root.path`
//! ```
//!
//! Relative paths in `config.json` (`root.path`, bind-mount sources) are
//! relative to the bundle directory, not to the caller's working directory.

use std::path::{Path, PathBuf};

use oci_spec::runtime::Spec;

use crate::error::{Context, Error, Result};

/// A loaded bundle.
#[derive(Debug, Clone)]
pub struct Bundle {
    /// Canonical (absolute, symlink-free) bundle directory.
    pub dir: PathBuf,
    /// The parsed `config.json`.
    pub spec: Spec,
}

impl Bundle {
    /// Reads `<dir>/config.json`.
    pub fn load(dir: &Path) -> Result<Bundle> {
        let dir = std::fs::canonicalize(dir).with_context(|| format!("bundle directory {}", dir.display()))?;
        let config = dir.join("config.json");
        let text = std::fs::read(&config).with_context(|| format!("read {}", config.display()))?;
        // Parsed with serde_json directly: `Spec::load` reduces every
        // mistake to "serde failed", while serde's own message says what and
        // where ("no variant for TEST_CAP at line 12 column 20").
        let spec: Spec =
            serde_json::from_slice(&text).map_err(|e| Error::invalid(format!("{}: {e}", config.display())))?;
        Ok(Bundle { dir, spec })
    }

    /// Wraps an in-memory spec (used by tests and `xtask`).
    pub fn from_spec(dir: PathBuf, spec: Spec) -> Bundle {
        Bundle { dir, spec }
    }

    /// Resolves a path from `config.json` against the bundle directory.
    pub fn resolve(&self, p: &Path) -> PathBuf {
        if p.is_absolute() { p.to_owned() } else { self.dir.join(p) }
    }
}

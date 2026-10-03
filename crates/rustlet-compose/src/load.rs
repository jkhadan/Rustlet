//! From files to a [`Project`]: finding the file, `.env`, interpolation,
//! overrides, names and paths.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::Result;
use crate::project::Project;

/// What to load.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LoadOptions {
    /// `-f`: the files, in order; a later one overrides and extends an
    /// earlier one (Compose's merge rules). Empty: the first of
    /// `compose.yaml`, `compose.yml`, `docker-compose.yaml`,
    /// `docker-compose.yml` in the current directory.
    pub files: Vec<PathBuf>,
    /// `--project-directory`.
    pub project_dir: Option<PathBuf>,
    /// `-p`.
    pub project_name: Option<String>,
    /// The environment interpolation reads (the process's), over the
    /// project directory's `.env`.
    pub env: BTreeMap<String, String>,
    /// `--profile`: services with `profiles:` only when one of theirs is
    /// listed.
    pub profiles: Vec<String>,
}

/// Loads a project from files (see [`LoadOptions`]).
pub fn load(options: &LoadOptions) -> Result<Project> {
    let _ = options;
    unimplemented!("load: agent B")
}

/// Loads a project from YAML text, as if it were a file in `dir`.
pub fn load_str(yaml: &str, dir: &Path, options: &LoadOptions) -> Result<Project> {
    let _ = (yaml, dir, options);
    unimplemented!("load_str: agent B")
}

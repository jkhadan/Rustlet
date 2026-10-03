//! `.dockerignore`: what of the context directory a build never sees.
//!
//! ```text
//!  # comments, and blank lines, are ignored
//!  target/          everything below target/
//!  **/*.log         .log files at any depth
//!  !keep.log        …except this one (a later line wins)
//!  /secret          a leading / is the context's root (the same as without)
//! ```
//!
//! Docker's semantics (`moby/patternmatcher`): each line is a pattern for
//! the path relative to the context, `/`-separated, cleaned (`a/../b` is
//! `b`); `*`, `?` and `[…]` match within one component (Go's
//! `filepath.Match`), `**` any number of components; a pattern that matches
//! a directory excludes everything below it; the last pattern that matches
//! a path (itself or a parent directory) decides, and `!` patterns include
//! again. A walk that meets an excluded directory must still enter it when
//! an exception could include something below
//! ([`IgnoreRules::may_include_below`]).
//!
//! The file: `<Containerfile>.dockerignore` next to the Containerfile
//! (BuildKit's), else `.containerignore` (Podman's), else `.dockerignore`, in
//! the context's root ([`ignore_file`]).

use std::path::{Path, PathBuf};

/// Parsed ignore patterns.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IgnoreRules {
    patterns: Vec<String>,
}

impl IgnoreRules {
    /// Parses an ignore file's text. Malformed patterns (an unclosed `[`)
    /// are an error, with their line.
    pub fn parse(text: &str) -> Result<IgnoreRules, String> {
        let _ = text;
        unimplemented!("IgnoreRules::parse: agent A")
    }

    /// Is the context path `rel` (relative, `/`-separated) excluded?
    pub fn excludes(&self, rel: &str) -> bool {
        let _ = rel;
        unimplemented!("IgnoreRules::excludes: agent A")
    }

    /// Below the excluded directory `rel`, could an exception include
    /// something?
    pub fn may_include_below(&self, rel: &str) -> bool {
        let _ = rel;
        unimplemented!("IgnoreRules::may_include_below: agent A")
    }
}

/// The ignore file that applies to a build of `context` with `containerfile`
/// (a path, as given), if one exists.
pub fn ignore_file(context: &Path, containerfile: &Path) -> Option<PathBuf> {
    let _ = (context, containerfile);
    unimplemented!("ignore_file: agent A")
}

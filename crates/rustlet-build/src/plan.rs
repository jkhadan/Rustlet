//! Which stages to build, and the variables a stage sees.
//!
//! A build makes its *target* stage (the last, unless `--target` names
//! one) and whatever that needs: the stage its `FROM` names, and every
//! stage a `COPY --from` reads, recursively. Stages are built in the
//! file's order; one nobody needs is skipped (BuildKit does the same; the
//! classic builder built them all).
//!
//! `FROM` lines are expanded with the global `ARG`s (those before the first
//! `FROM`), build args over their defaults, plus the automatic platform
//! args ([`platform_args`]). A stage name is matched case-insensitively,
//! before image names: `FROM build` after `FROM golang AS build` is the
//! stage. `FROM scratch` is the empty filesystem.
//!
//! In a stage, an `ARG` makes a variable visible from then on (to
//! expansion, and to `RUN` as an environment variable): its build arg's
//! value, else its default, else, for a name the global `ARG`s declared,
//! their value ([`ArgScope`]). A build arg no `ARG` declares is reported
//! ([`Plan::unused_args`]), as Docker warns.

use std::collections::BTreeMap;

use crate::parser::Containerfile;

/// Where a stage starts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Base {
    /// `FROM scratch`.
    Scratch,
    /// An earlier stage, by index.
    Stage(usize),
    /// An image reference, expanded.
    Image(String),
}

/// What [`plan`] decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// The stages to build, in order.
    pub stages: Vec<usize>,
    /// The target stage.
    pub target: usize,
    /// Each stage's base, by stage index (stages not built included).
    pub bases: Vec<Base>,
    /// Build args no `ARG` of the file declares.
    pub unused_args: Vec<String>,
    /// The steps of the stages built, their `FROM` lines included: what a
    /// build's progress counts to.
    pub total_steps: usize,
}

/// Plans a build of `file` up to `target` (a stage name, or an index), with
/// `build_args` (`--build-arg`).
pub fn plan(file: &Containerfile, target: Option<&str>, build_args: &BTreeMap<String, String>) -> Result<Plan, String> {
    let _ = (file, target, build_args);
    unimplemented!("plan: agent A")
}

/// What `COPY --from=<from>` in stage `current` reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FromSource {
    /// An earlier stage.
    Stage(usize),
    /// An image (pulled if missing, as a `FROM` would be).
    Image(String),
}

/// Resolves `--from` (already expanded): a stage name (case-insensitive) or
/// index, which must come before `current`; anything else is an image.
pub fn resolve_from(file: &Containerfile, current: usize, from: &str) -> Result<FromSource, String> {
    let _ = (file, current, from);
    unimplemented!("resolve_from: agent A")
}

/// The args every build defines without an `ARG` default (BuildKit's
/// automatic platform args): `TARGETPLATFORM` (`linux/amd64`),
/// `TARGETOS`, `TARGETARCH`, `TARGETVARIANT` (empty), and the `BUILD…`
/// ones with the same values.
pub fn platform_args() -> BTreeMap<String, String> {
    unimplemented!("platform_args: agent A")
}

/// The `ARG` variables a stage sees.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ArgScope {
    /// Declared so far in the stage, with their values (`None`: declared
    /// without a value from anywhere: unset).
    declared: BTreeMap<String, Option<String>>,
    /// The global `ARG`s' values (expanded), and the build args.
    global: BTreeMap<String, Option<String>>,
    build_args: BTreeMap<String, String>,
}

impl ArgScope {
    /// A stage's scope at its `FROM`: nothing declared yet. `global`: the
    /// global `ARG`s with their values (as [`plan`] expanded them).
    pub fn new(global: BTreeMap<String, Option<String>>, build_args: BTreeMap<String, String>) -> ArgScope {
        let _ = (global, build_args);
        unimplemented!("ArgScope::new: agent A")
    }

    /// `ARG name[=default]` (default expanded): visible from now on, with
    /// the build arg's value, else the default, else the global's.
    pub fn declare(&mut self, name: &str, default: Option<String>) {
        let _ = (name, default);
        unimplemented!("ArgScope::declare: agent A")
    }

    /// The value of a declared variable.
    pub fn get(&self, name: &str) -> Option<String> {
        let _ = name;
        unimplemented!("ArgScope::get: agent A")
    }

    /// The declared variables with values, for a `RUN`'s environment and
    /// cache key, sorted by name.
    pub fn vars(&self) -> Vec<(String, String)> {
        unimplemented!("ArgScope::vars: agent A")
    }
}

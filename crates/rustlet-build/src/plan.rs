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
//!
//! `COPY --from` is expanded here with the same variables as `FROM` (the
//! global ones), as BuildKit does to know a stage's dependencies before
//! anything runs. Docker's predefined proxy args (`HTTP_PROXY`,
//! `no_proxy`…) need no `ARG`: a `RUN` gets them from the build args
//! ([`ArgScope::proxy_env`]), and they are never reported unused.

use std::collections::{BTreeMap, BTreeSet};

use crate::expand;
use crate::parser::{Containerfile, InstructionKind};

/// Docker's predefined args: usable by `RUN` without an `ARG`, kept out of
/// the history and the cache key.
const PROXY_ARGS: &[&str] = &[
    "HTTP_PROXY",
    "http_proxy",
    "HTTPS_PROXY",
    "https_proxy",
    "FTP_PROXY",
    "ftp_proxy",
    "NO_PROXY",
    "no_proxy",
    "ALL_PROXY",
    "all_proxy",
];

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
    /// The global `ARG`s' values (a build arg over the expanded default;
    /// `None`: declared, without a value), and the [`platform_args`]: what
    /// `FROM` lines see, and what each stage's [`ArgScope::new`] takes.
    pub global_args: BTreeMap<String, Option<String>>,
}

/// Plans a build of `file` up to `target` (a stage name, or an index), with
/// `build_args` (`--build-arg`).
pub fn plan(file: &Containerfile, target: Option<&str>, build_args: &BTreeMap<String, String>) -> Result<Plan, String> {
    let global_args = global_values(file, build_args)?;
    let lookup = |name: &str| global_args.get(name).cloned().flatten();
    let expand = |raw: &str| expand::word(raw, file.escape, &lookup);

    let mut bases = Vec::with_capacity(file.stages.len());
    for stage in &file.stages {
        let at = |message: String| format!("line {}: FROM {}: {message}", stage.line, stage.base);
        let base = expand(&stage.base).map_err(|e| at(e.to_string()))?;
        if base.is_empty() {
            return Err(at("the image name is empty".to_owned()));
        }
        if let Some(platform) = &stage.platform {
            let platform = expand(platform).map_err(|e| at(e.to_string()))?;
            if platform != "linux/amd64" {
                return Err(at(format!("--platform={platform}: Rustlets builds linux/amd64 images only")));
            }
        }
        bases.push(if base.eq_ignore_ascii_case("scratch") {
            Base::Scratch
        } else if let Some(earlier) = stage_named(file, &base, stage.index) {
            Base::Stage(earlier)
        } else {
            Base::Image(base)
        });
    }

    let target = target_stage(file, target)?;
    // The target and what it needs, through FROM and COPY --from.
    let mut needed = vec![false; file.stages.len()];
    let mut queue = vec![target];
    while let Some(index) = queue.pop() {
        if std::mem::replace(&mut needed[index], true) {
            continue;
        }
        if let Base::Stage(base) = bases[index] {
            queue.push(base);
        }
        for instruction in &file.stages[index].instructions {
            let InstructionKind::Copy(copy) = &instruction.kind else { continue };
            let Some(from) = &copy.from else { continue };
            let at = |message: String| format!("line {}: COPY --from={from}: {message}", instruction.line);
            let from = expand(from).map_err(|e| at(e.to_string()))?;
            if from.is_empty() {
                continue;
            }
            if let FromSource::Stage(source) =
                resolve_from(file, index, &from).map_err(|e| format!("line {}: {e}", instruction.line))?
            {
                queue.push(source);
            }
        }
    }
    let stages: Vec<usize> = (0..file.stages.len()).filter(|&i| needed[i]).collect();
    let total_steps = stages.iter().map(|&i| 1 + file.stages[i].instructions.len()).sum();

    let declared: BTreeSet<&str> = file
        .global_args
        .iter()
        .chain(file.stages.iter().flat_map(|stage| &stage.instructions).flat_map(
            |instruction| match &instruction.kind {
                InstructionKind::Arg(args) => args.as_slice(),
                _ => &[],
            },
        ))
        .map(|arg| arg.name.as_str())
        .collect();
    let platform = platform_args();
    let unused_args = build_args
        .keys()
        .filter(|name| {
            !declared.contains(name.as_str()) && !platform.contains_key(*name) && !PROXY_ARGS.contains(&name.as_str())
        })
        .cloned()
        .collect();

    Ok(Plan { stages, target, bases, unused_args, total_steps, global_args })
}

/// The variables of `FROM` lines: the platform args, then the global
/// `ARG`s in order, each default expanded with those before it.
fn global_values(
    file: &Containerfile,
    build_args: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, Option<String>>, String> {
    let mut values: BTreeMap<String, Option<String>> =
        platform_args().into_iter().map(|(name, value)| (name, Some(value))).collect();
    for arg in &file.global_args {
        let value = match (build_args.get(&arg.name), &arg.default) {
            (Some(value), _) => Some(value.clone()),
            (None, Some(default)) => Some(
                expand::word(default, file.escape, &|name| values.get(name).cloned().flatten())
                    .map_err(|e| format!("ARG {}: {e}", arg.name))?,
            ),
            (None, None) => None,
        };
        match value {
            Some(value) => {
                values.insert(arg.name.clone(), Some(value));
            }
            // Declared without a value: unset, unless a platform arg.
            None => {
                values.entry(arg.name.clone()).or_insert(None);
            }
        }
    }
    Ok(values)
}

/// The stage before `before` named `name` (case-insensitively).
fn stage_named(file: &Containerfile, name: &str, before: usize) -> Option<usize> {
    let name = name.to_ascii_lowercase();
    file.stages[..before].iter().find(|stage| stage.name.as_deref() == Some(name.as_str())).map(|stage| stage.index)
}

/// `--target`: a stage's name (case-insensitively) or index; the last
/// stage without one.
fn target_stage(file: &Containerfile, target: Option<&str>) -> Result<usize, String> {
    let Some(target) = target else { return Ok(file.stages.len().saturating_sub(1)) };
    if let Some(index) = stage_named(file, target, file.stages.len()) {
        return Ok(index);
    }
    if !target.is_empty()
        && target.bytes().all(|b| b.is_ascii_digit())
        && let Ok(index) = target.parse::<usize>()
        && index < file.stages.len()
    {
        return Ok(index);
    }
    let stages: Vec<String> =
        file.stages.iter().map(|stage| stage.name.clone().unwrap_or_else(|| stage.index.to_string())).collect();
    Err(format!("target stage {target:?} could not be found (the stages: {})", stages.join(", ")))
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
    let not_before = |what: String| {
        format!("COPY --from={from}: {what} isn't before this stage (a stage copies only from earlier ones)")
    };
    if !from.is_empty() && from.bytes().all(|b| b.is_ascii_digit()) {
        return match from.parse::<usize>() {
            Ok(index) if index < current => Ok(FromSource::Stage(index)),
            _ => Err(not_before(format!("stage {from}"))),
        };
    }
    let name = from.to_ascii_lowercase();
    match file.stages.iter().find(|stage| stage.name.as_deref() == Some(name.as_str())) {
        Some(stage) if stage.index < current => Ok(FromSource::Stage(stage.index)),
        Some(_) => Err(not_before(format!("the stage {name:?}"))),
        None => Ok(FromSource::Image(from.to_owned())),
    }
}

/// The args every build defines without an `ARG` default (BuildKit's
/// automatic platform args): `TARGETPLATFORM` (`linux/amd64`),
/// `TARGETOS`, `TARGETARCH`, `TARGETVARIANT` (empty), and the `BUILD…`
/// ones with the same values.
pub fn platform_args() -> BTreeMap<String, String> {
    let mut args = BTreeMap::new();
    for side in ["TARGET", "BUILD"] {
        for (name, value) in [("PLATFORM", "linux/amd64"), ("OS", "linux"), ("ARCH", "amd64"), ("VARIANT", "")] {
            args.insert(format!("{side}{name}"), value.to_owned());
        }
    }
    args
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
        ArgScope { declared: BTreeMap::new(), global, build_args }
    }

    /// `ARG name[=default]` (default expanded): visible from now on, with
    /// the build arg's value, else the default, else the global's. Declared
    /// again with none of those, it keeps the value it had (BuildKit keeps
    /// the variable).
    pub fn declare(&mut self, name: &str, default: Option<String>) {
        let value = self.build_args.get(name).cloned().or(default).or_else(|| self.global.get(name).cloned().flatten());
        match value {
            Some(value) => {
                self.declared.insert(name.to_owned(), Some(value));
            }
            None => {
                self.declared.entry(name.to_owned()).or_insert(None);
            }
        }
    }

    /// The value of a declared variable.
    pub fn get(&self, name: &str) -> Option<String> {
        self.declared.get(name).cloned().flatten()
    }

    /// The declared variables with values, for a `RUN`'s environment and
    /// cache key, sorted by name.
    pub fn vars(&self) -> Vec<(String, String)> {
        self.declared.iter().filter_map(|(name, value)| Some((name.clone(), value.clone()?))).collect()
    }

    /// Docker's predefined proxy args given as build args (`HTTP_PROXY`,
    /// `no_proxy`…): a `RUN`'s environment has them without an `ARG`; they
    /// stay out of its cache key and history, as in Docker. Sorted by
    /// name; one the stage declared is in [`ArgScope::vars`] instead.
    pub fn proxy_env(&self) -> Vec<(String, String)> {
        self.build_args
            .iter()
            .filter(|(name, _)| PROXY_ARGS.contains(&name.as_str()) && !self.declared.contains_key(name.as_str()))
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect()
    }
}

#[cfg(test)]
mod tests;

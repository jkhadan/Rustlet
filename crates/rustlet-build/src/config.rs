//! What a build does to the image's config: the `config` object of the
//! image config JSON (`Env`, `Cmd`, `Entrypoint`, `User`, `WorkingDir`,
//! `ExposedPorts`, `Volumes`, `Labels`, `StopSignal`, `Healthcheck`,
//! `Shell`, `OnBuild`), plus the history line each step leaves.
//!
//! ```text
//!  base image's config ──ENV, WORKDIR, CMD, …──► the built image's config
//! ```
//!
//! Docker's rules, applied by [`ImageConfigState::apply`]:
//!
//! - `ENV` sets (replacing an existing name in place); `LABEL` too, in
//!   `Labels`; `EXPOSE` and `VOLUME` add to their sets.
//! - `WORKDIR` relative to the current one (`/a` then `b` is `/a/b`),
//!   cleaned lexically.
//! - `CMD`/`ENTRYPOINT` in shell form become the `SHELL` (default
//!   `["/bin/sh", "-c"]`) plus the string. Setting `ENTRYPOINT` clears a
//!   `Cmd` the stage inherited from its base image (one set in this stage
//!   stays).
//! - `HEALTHCHECK` becomes Docker's `Healthcheck` (`Test`, durations in
//!   nanoseconds); `NONE` is `{"Test": ["NONE"]}`.
//! - `MAINTAINER` sets the image's `author`, outside `config` (the caller
//!   puts [`ImageConfigState::author`] there).
//!
//! Unknown fields of the base image's `config` are kept as they are.

use std::time::Duration;

use serde_json::{Map, Value};

use crate::op::Op;
use crate::parser::Command;

/// A stage's image config as the build goes.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ImageConfigState {
    /// The `config` object.
    pub config: Map<String, Value>,
    /// `MAINTAINER`'s.
    pub author: Option<String>,
    /// Whether this stage set `Cmd` (an `ENTRYPOINT` keeps it then).
    pub cmd_set: bool,
}

impl ImageConfigState {
    /// A stage's start: the base image's `config` object (none for
    /// `scratch`).
    pub fn new(base: Option<&Value>) -> ImageConfigState {
        let _ = base;
        unimplemented!("ImageConfigState::new: agent A")
    }

    /// Applies a step that changes only the config. `RUN`, `COPY`, `ADD`
    /// and `ARG` are no-ops here.
    pub fn apply(&mut self, op: &Op) -> Result<(), String> {
        let _ = op;
        unimplemented!("ImageConfigState::apply: agent A")
    }

    /// `Env`, as `NAME=value` strings, in order.
    pub fn env(&self) -> Vec<String> {
        unimplemented!("ImageConfigState::env: agent A")
    }

    /// The value of `Env`'s `name`.
    pub fn env_var(&self, name: &str) -> Option<String> {
        let _ = name;
        unimplemented!("ImageConfigState::env_var: agent A")
    }

    /// `User`, if set (and not empty).
    pub fn user(&self) -> Option<String> {
        unimplemented!("ImageConfigState::user: agent A")
    }

    /// `WorkingDir`, else `/`.
    pub fn workdir(&self) -> String {
        unimplemented!("ImageConfigState::workdir: agent A")
    }

    /// `Shell`, else `["/bin/sh", "-c"]`.
    pub fn shell(&self) -> Vec<String> {
        unimplemented!("ImageConfigState::shell: agent A")
    }

    /// The program and arguments a `RUN` with `command` executes: the shell
    /// and the string, or the exec form as it is.
    pub fn run_args(&self, command: &Command) -> Vec<String> {
        let _ = command;
        unimplemented!("ImageConfigState::run_args: agent A")
    }

    /// The `config` object, for the image config JSON.
    pub fn to_value(&self) -> Value {
        Value::Object(self.config.clone())
    }
}

/// The history line a step leaves (`created_by`), as BuildKit writes them:
/// `RUN /bin/sh -c apk add curl # buildkit`-style without the comment, so
/// `RUN /bin/sh -c apk add curl`, `COPY app.py /app/`, `ENV A=b`,
/// `WORKDIR /app`, `CMD ["sh"]`. `state` is the config *before* the step
/// (a `RUN`'s shell).
pub fn created_by(op: &Op, state: &ImageConfigState) -> String {
    let _ = (op, state);
    unimplemented!("created_by: agent A")
}

/// Go's duration syntax (`300ms`, `1.5h`, `2h45m`; units `ns`, `us`/`µs`,
/// `ms`, `s`, `m`, `h`), as `HEALTHCHECK`'s options take it.
pub fn parse_duration(s: &str) -> Result<Duration, String> {
    let _ = s;
    unimplemented!("parse_duration: agent A")
}

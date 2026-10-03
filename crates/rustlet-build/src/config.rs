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
/// `ms`, `s`, `m`, `h`), as `HEALTHCHECK`'s options, compose files and the
/// CLI's `--health-*` flags take it. `0` alone needs no unit; negative
/// durations are refused (none of those uses has a meaning for one).
pub fn parse_duration(s: &str) -> Result<Duration, String> {
    let bad = || format!("invalid duration {s:?} (examples: 30s, 1m30s, 500ms)");
    let text = s.trim().strip_prefix('+').unwrap_or(s.trim());
    if text == "0" {
        return Ok(Duration::ZERO);
    }
    if text.is_empty() || text.starts_with('-') {
        return Err(bad());
    }
    let mut total: u128 = 0;
    let mut rest = text;
    while !rest.is_empty() {
        let number_len = rest.find(|c: char| !(c.is_ascii_digit() || c == '.')).ok_or_else(bad)?;
        let (number, after) = rest.split_at(number_len);
        let unit_len = after.find(|c: char| c.is_ascii_digit() || c == '.').unwrap_or(after.len());
        let (unit, next) = after.split_at(unit_len);
        let nanos_per: u128 = match unit {
            "ns" => 1,
            "us" | "µs" | "μs" => 1_000,
            "ms" => 1_000_000,
            "s" => 1_000_000_000,
            "m" => 60_000_000_000,
            "h" => 3_600_000_000_000,
            _ => return Err(bad()),
        };
        let (whole, fraction) = number.split_once('.').unwrap_or((number, ""));
        if whole.is_empty() && fraction.is_empty() {
            return Err(bad());
        }
        let whole: u128 = if whole.is_empty() { 0 } else { whole.parse().map_err(|_| bad())? };
        let mut part = whole.checked_mul(nanos_per).ok_or_else(bad)?;
        // The fraction, digit by digit, to the nanosecond.
        let mut scale = nanos_per;
        for digit in fraction.chars() {
            let d = digit.to_digit(10).ok_or_else(bad)? as u128;
            scale /= 10;
            part += d * scale;
        }
        total = total.checked_add(part).ok_or_else(bad)?;
        rest = next;
    }
    u64::try_from(total).map(Duration::from_nanos).map_err(|_| bad())
}

#[cfg(test)]
mod duration_tests {
    use super::*;

    #[test]
    fn go_durations() {
        let d = |s| parse_duration(s).unwrap();
        assert_eq!(d("30s"), Duration::from_secs(30));
        assert_eq!(d("1m30s"), Duration::from_secs(90));
        assert_eq!(d("2h45m"), Duration::from_secs(2 * 3600 + 45 * 60));
        assert_eq!(d("1.5h"), Duration::from_secs(5400));
        assert_eq!(d("300ms"), Duration::from_millis(300));
        assert_eq!(d(".5s"), Duration::from_millis(500));
        assert_eq!(d("1us"), Duration::from_micros(1));
        assert_eq!(d("1µs"), Duration::from_micros(1));
        assert_eq!(d("10ns"), Duration::from_nanos(10));
        assert_eq!(d("0"), Duration::ZERO);
        assert_eq!(d("0s"), Duration::ZERO);
        assert_eq!(d("1h0m0.25s"), Duration::from_millis(3_600_250));
        for bad in ["", "10", "s", "1x", "-1s", "1.2.3s", "1 s", "ms5", "."] {
            assert!(parse_duration(bad).is_err(), "{bad:?}");
        }
        assert_eq!(d(" 1s "), Duration::from_secs(1), "surrounding whitespace is trimmed");
        assert!(parse_duration("99999999999h").is_err(), "too long for u64 nanoseconds");
    }
}

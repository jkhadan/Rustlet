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
//! - `ONBUILD` adds its instruction to `OnBuild`. The base image's own
//!   triggers are not inherited: Docker runs them at the start of the
//!   child's build and leaves them out of the child; Rustlets doesn't run
//!   them (the builder says so) and leaves them out too.
//!
//! Unknown fields of the base image's `config` are kept as they are.

use std::time::Duration;

use serde_json::{Map, Value};

use crate::op::{HealthcheckOp, Op};
use crate::parser::Command;
use crate::path::clean;

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
    /// `scratch`), less its `OnBuild` triggers (see the module docs).
    pub fn new(base: Option<&Value>) -> ImageConfigState {
        let mut config = base.and_then(Value::as_object).cloned().unwrap_or_default();
        config.remove("OnBuild");
        ImageConfigState { config, author: None, cmd_set: false }
    }

    /// Applies a step that changes only the config. `RUN`, `COPY`, `ADD`
    /// and `ARG` are no-ops here.
    pub fn apply(&mut self, op: &Op) -> Result<(), String> {
        match op {
            Op::Run(_) | Op::Copy(_) | Op::Arg(_) => {}
            Op::Env(pairs) => {
                let env = self.array_mut("Env")?;
                for (name, value) in pairs {
                    let entry = Value::String(format!("{name}={value}"));
                    match env.iter().position(|e| e.as_str().is_some_and(|e| env_name(e) == name)) {
                        Some(i) => env[i] = entry,
                        None => env.push(entry),
                    }
                }
            }
            Op::Label(pairs) => {
                let labels = self.object_mut("Labels")?;
                for (name, value) in pairs {
                    labels.insert(name.clone(), Value::String(value.clone()));
                }
            }
            Op::Workdir(path) => {
                let workdir = join_workdir(&self.workdir(), path);
                self.config.insert("WorkingDir".into(), Value::String(workdir));
            }
            Op::User(user) => {
                self.config.insert("User".into(), Value::String(user.clone()));
            }
            Op::Expose(ports) => {
                let set = self.object_mut("ExposedPorts")?;
                for port in ports {
                    set.insert(port.clone(), Value::Object(Map::new()));
                }
            }
            Op::Volume(paths) => {
                let set = self.object_mut("Volumes")?;
                for path in paths {
                    set.insert(path.clone(), Value::Object(Map::new()));
                }
            }
            Op::StopSignal(signal) => {
                self.config.insert("StopSignal".into(), Value::String(signal.clone()));
            }
            Op::Healthcheck(check) => {
                self.config.insert("Healthcheck".into(), healthcheck_value(check.as_ref()));
            }
            Op::Shell(shell) => {
                self.config.insert("Shell".into(), Value::from(shell.clone()));
            }
            Op::Cmd(command) => {
                let args = self.run_args(command);
                self.config.insert("Cmd".into(), Value::from(args));
                self.cmd_set = true;
            }
            Op::Entrypoint(command) => {
                let args = self.run_args(command);
                self.config.insert("Entrypoint".into(), Value::from(args));
                // The base image's command was for its own entrypoint.
                if !self.cmd_set {
                    self.config.remove("Cmd");
                }
            }
            Op::Maintainer(author) => self.author = Some(author.clone()),
            Op::Onbuild(trigger) => self.array_mut("OnBuild")?.push(Value::String(trigger.clone())),
        }
        Ok(())
    }

    /// `Env`, as `NAME=value` strings, in order.
    pub fn env(&self) -> Vec<String> {
        self.config
            .get("Env")
            .and_then(Value::as_array)
            .map(|env| env.iter().filter_map(Value::as_str).map(str::to_owned).collect())
            .unwrap_or_default()
    }

    /// The value of `Env`'s `name`.
    pub fn env_var(&self, name: &str) -> Option<String> {
        self.env()
            .iter()
            .rev()
            .find(|e| env_name(e) == name)
            .map(|e| e.split_once('=').map_or("", |(_, v)| v).to_owned())
    }

    /// `User`, if set (and not empty).
    pub fn user(&self) -> Option<String> {
        self.config.get("User").and_then(Value::as_str).filter(|u| !u.is_empty()).map(str::to_owned)
    }

    /// `WorkingDir`, else `/`.
    pub fn workdir(&self) -> String {
        self.config.get("WorkingDir").and_then(Value::as_str).filter(|w| !w.is_empty()).unwrap_or("/").to_owned()
    }

    /// `Shell`, else `["/bin/sh", "-c"]`.
    pub fn shell(&self) -> Vec<String> {
        let shell: Vec<String> = self
            .config
            .get("Shell")
            .and_then(Value::as_array)
            .map(|shell| shell.iter().filter_map(Value::as_str).map(str::to_owned).collect())
            .unwrap_or_default();
        if shell.is_empty() { vec!["/bin/sh".to_owned(), "-c".to_owned()] } else { shell }
    }

    /// The program and arguments a `RUN` with `command` executes: the shell
    /// and the string, or the exec form as it is.
    pub fn run_args(&self, command: &Command) -> Vec<String> {
        match command {
            Command::Shell(command) => {
                let mut args = self.shell();
                args.push(command.clone());
                args
            }
            Command::Exec(args) => args.clone(),
        }
    }

    /// The `config` object, for the image config JSON.
    pub fn to_value(&self) -> Value {
        Value::Object(self.config.clone())
    }

    /// `config[key]` as a list, made one if it is missing or null.
    fn array_mut(&mut self, key: &str) -> Result<&mut Vec<Value>, String> {
        let slot = self.config.entry(key).or_insert(Value::Null);
        if slot.is_null() {
            *slot = Value::Array(Vec::new());
        }
        slot.as_array_mut().ok_or_else(|| format!("the base image's config has an {key} that isn't a list"))
    }

    /// `config[key]` as an object, made one if it is missing or null.
    fn object_mut(&mut self, key: &str) -> Result<&mut Map<String, Value>, String> {
        let slot = self.config.entry(key).or_insert(Value::Null);
        if slot.is_null() {
            *slot = Value::Object(Map::new());
        }
        slot.as_object_mut().ok_or_else(|| format!("the base image's config has an {key} that isn't an object"))
    }
}

/// `NAME` of `NAME=value` (all of an entry without `=`).
fn env_name(entry: &str) -> &str {
    entry.split_once('=').map_or(entry, |(name, _)| name)
}

/// `WORKDIR path` after `current`: relative paths join it, and the result
/// is cleaned lexically.
fn join_workdir(current: &str, path: &str) -> String {
    if path.starts_with('/') { clean(path) } else { clean(&format!("/{current}/{path}")) }
}

/// Docker's `Healthcheck` object: `Test`, and the options given, durations
/// in nanoseconds.
fn healthcheck_value(check: Option<&HealthcheckOp>) -> Value {
    let Some(check) = check else {
        return serde_json::json!({ "Test": ["NONE"] });
    };
    let mut value = Map::new();
    value.insert("Test".into(), Value::from(check.test.clone()));
    for (key, duration) in [
        ("Interval", check.interval),
        ("Timeout", check.timeout),
        ("StartPeriod", check.start_period),
        ("StartInterval", check.start_interval),
    ] {
        if let Some(duration) = duration {
            value.insert(key.into(), Value::from(u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)));
        }
    }
    if let Some(retries) = check.retries {
        value.insert("Retries".into(), Value::from(retries));
    }
    Value::Object(value)
}

/// The history line a step leaves (`created_by`), as BuildKit writes them:
/// `RUN /bin/sh -c apk add curl # buildkit`-style without the comment, so
/// `RUN /bin/sh -c apk add curl`, `COPY app.py /app/`, `ENV A=b`,
/// `WORKDIR /app`, `CMD ["sh"]`. `state` is the config *before* the step
/// (a `RUN`'s shell).
pub fn created_by(op: &Op, state: &ImageConfigState) -> String {
    let json = |items: &[String]| Value::from(items.to_vec()).to_string();
    let pairs = |pairs: &[(String, String)]| {
        pairs.iter().map(|(name, value)| format!("{name}={value}")).collect::<Vec<_>>().join(" ")
    };
    match op {
        Op::Run(command) => format!("RUN {}", state.run_args(command).join(" ")),
        Op::Cmd(command) => format!("CMD {}", json(&state.run_args(command))),
        Op::Entrypoint(command) => format!("ENTRYPOINT {}", json(&state.run_args(command))),
        Op::Copy(copy) => {
            let mut line = String::from(if copy.add { "ADD" } else { "COPY" });
            if let Some(from) = &copy.from {
                line += &format!(" --from={from}");
            }
            if let Some(chown) = &copy.chown {
                line += &format!(" --chown={chown}");
            }
            if let Some(chmod) = copy.chmod {
                line += &format!(" --chmod={chmod:o}");
            }
            for path in copy.sources.iter().chain([&copy.dest]) {
                line.push(' ');
                line += path;
            }
            line
        }
        Op::Env(env) => format!("ENV {}", pairs(env)),
        Op::Arg(args) => {
            let args: Vec<String> = args
                .iter()
                .map(|(name, default)| match default {
                    Some(default) => format!("{name}={default}"),
                    None => name.clone(),
                })
                .collect();
            format!("ARG {}", args.join(" "))
        }
        Op::Label(labels) => format!("LABEL {}", pairs(labels)),
        Op::Workdir(path) => format!("WORKDIR {}", join_workdir(&state.workdir(), path)),
        Op::User(user) => format!("USER {user}"),
        Op::Expose(ports) => format!("EXPOSE {}", ports.join(" ")),
        Op::Volume(paths) => format!("VOLUME {}", json(paths)),
        Op::StopSignal(signal) => format!("STOPSIGNAL {signal}"),
        Op::Healthcheck(None) => "HEALTHCHECK NONE".to_owned(),
        Op::Healthcheck(Some(check)) => {
            let mut line = String::from("HEALTHCHECK");
            for (option, duration) in [
                ("interval", check.interval),
                ("timeout", check.timeout),
                ("start-period", check.start_period),
                ("start-interval", check.start_interval),
            ] {
                if let Some(duration) = duration {
                    line += &format!(" --{option}={}", format_duration(duration));
                }
            }
            if let Some(retries) = check.retries {
                line += &format!(" --retries={retries}");
            }
            format!("{line} {}", check.test.join(" "))
        }
        Op::Shell(shell) => format!("SHELL {}", json(shell)),
        Op::Maintainer(author) => format!("MAINTAINER {author}"),
        Op::Onbuild(trigger) => format!("ONBUILD {trigger}"),
    }
}

/// A duration as Go prints one (`30s`, `1m30s`, `1h0m0s`, `1.5s`, `500ms`,
/// `1.5µs`, `0s`): [`parse_duration`]'s inverse, for history lines and
/// anything that shows a healthcheck's options.
pub fn format_duration(duration: Duration) -> String {
    let nanos = duration.as_nanos();
    if nanos == 0 {
        return "0s".to_owned();
    }
    if nanos < 1_000_000_000 {
        let (unit, digits) = if nanos < 1_000 {
            ("ns", 0)
        } else if nanos < 1_000_000 {
            ("µs", 3)
        } else {
            ("ms", 6)
        };
        let (whole, fraction) = split_fraction(nanos, digits);
        return format!("{whole}{fraction}{unit}");
    }
    let (seconds, fraction) = split_fraction(nanos, 9);
    let (hours, minutes, seconds) = (seconds / 3600, seconds / 60 % 60, seconds % 60);
    if hours > 0 {
        format!("{hours}h{minutes}m{seconds}{fraction}s")
    } else if minutes > 0 {
        format!("{minutes}m{seconds}{fraction}s")
    } else {
        format!("{seconds}{fraction}s")
    }
}

/// `value / 10^digits`, and its fraction as `.5` (no trailing zeros; empty
/// when there is none).
fn split_fraction(value: u128, digits: u32) -> (u128, String) {
    let scale = 10u128.pow(digits);
    let rest = value % scale;
    let fraction = if rest == 0 {
        String::new()
    } else {
        format!(".{}", format!("{rest:0width$}", width = digits as usize).trim_end_matches('0'))
    };
    (value / scale, fraction)
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
            part = part.checked_add(d * scale).ok_or_else(bad)?;
        }
        total = total.checked_add(part).ok_or_else(bad)?;
        rest = next;
    }
    u64::try_from(total).map(Duration::from_nanos).map_err(|_| bad())
}

#[cfg(test)]
mod tests;

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

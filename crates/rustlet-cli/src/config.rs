//! From `run`/`create` flags to the daemon's [`ContainerConfig`].
//!
//! The CLI does here what Docker's does before a request leaves: sizes
//! become bytes, `-e KEY` takes its value from the CLI's own environment,
//! `--entrypoint ""` becomes "no entrypoint", labels become a map. It also
//! refuses what can't work (`--rm` with a restart policy, a name the
//! daemon would reject), so that the error comes before anything exists.
//! What the flags *mean* (an entrypoint replacing the image's, a user
//! looked up in the image) is the daemon's business.

use std::collections::BTreeMap;

use anyhow::{Context, bail};
use clap::ValueEnum;
use rustlet_spec::container::{ContainerConfig, RestartPolicy, RestartPolicyName, UsernsMode};

use crate::format::parse_size;

/// The flags `run` and `create` share.
#[derive(clap::Args, Debug, Clone, Default)]
pub struct CreateFlags {
    /// Keep STDIN open, and attach to it
    #[arg(short, long)]
    pub interactive: bool,
    /// Allocate a pseudo-TTY
    #[arg(short, long)]
    pub tty: bool,
    /// Remove the container when it exits
    #[arg(long)]
    pub rm: bool,
    /// Assign a name to the container
    #[arg(long)]
    pub name: Option<String>,
    /// Set an environment variable; a bare KEY takes its value from this shell (repeatable)
    #[arg(short, long, value_name = "KEY[=VALUE]")]
    pub env: Vec<String>,
    /// Run as USER[:GROUP] (names or ids from the image)
    #[arg(short, long, value_name = "USER[:GROUP]")]
    pub user: Option<String>,
    /// Working directory inside the container
    #[arg(short, long, value_name = "DIR")]
    pub workdir: Option<String>,
    /// Replace the image's entrypoint ("" clears it)
    #[arg(long, value_name = "COMMAND", allow_hyphen_values = true)]
    pub entrypoint: Option<String>,
    /// Container host name (default: the short id)
    #[arg(long)]
    pub hostname: Option<String>,
    /// Set a label (repeatable)
    #[arg(short, long, value_name = "KEY[=VALUE]")]
    pub label: Vec<String>,
    /// Memory limit: bytes, or with a unit (512m, 1g)
    #[arg(short, long, value_name = "SIZE")]
    pub memory: Option<String>,
    /// CPU time, in CPUs (1.5)
    #[arg(long, value_name = "N", allow_negative_numbers = true)]
    pub cpus: Option<f64>,
    /// Maximum number of processes (0 or -1: unlimited)
    #[arg(long, value_name = "N", allow_negative_numbers = true)]
    pub pids_limit: Option<i64>,
    /// Mount the root filesystem read-only
    #[arg(long)]
    pub read_only: bool,
    /// User namespace: host (none) or remap (container root is an unprivileged host user)
    #[arg(long, value_enum, value_name = "MODE")]
    pub userns: Option<Userns>,
    /// Restart policy: no, always, unless-stopped, on-failure[:max-retries]
    #[arg(long, value_name = "POLICY", value_parser = RestartPolicy::parse)]
    pub restart: Option<RestartPolicy>,
    /// Signal that stops the container (default: the image's, else SIGTERM)
    #[arg(long, value_name = "SIGNAL")]
    pub stop_signal: Option<String>,
    /// Seconds to wait for the stop signal before killing
    #[arg(long, value_name = "SECONDS")]
    pub stop_timeout: Option<u32>,
    /// Add a capability (repeatable; ALL for all)
    #[arg(long, value_name = "CAP")]
    pub cap_add: Vec<String>,
    /// Drop a capability (repeatable; ALL for all)
    #[arg(long, value_name = "CAP")]
    pub cap_drop: Vec<String>,
    /// All capabilities and host devices, no seccomp: not isolation from host root
    #[arg(long)]
    pub privileged: bool,
    /// Security options: seccomp=unconfined, no-new-privileges[=true|false] (repeatable)
    #[arg(long, value_name = "OPT")]
    pub security_opt: Vec<String>,
    /// Add a host device: HOST[:CONTAINER[:rwm]] (repeatable)
    #[arg(long, value_name = "DEVICE")]
    pub device: Vec<String>,
    /// When to pull the image
    #[arg(long, value_enum, default_value_t = Pull::Missing, value_name = "WHEN")]
    pub pull: Pull,
}

/// `--pull`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
pub enum Pull {
    /// Only if the image isn't there
    #[default]
    Missing,
    /// Ask the registry first, every time
    Always,
    /// Never: the image must be there
    Never,
}

/// `--userns`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Userns {
    Host,
    Remap,
}

impl CreateFlags {
    /// The request for `image` running `cmd` (empty: the image's). `-i`
    /// sets `open_stdin` and `stdin_once`, as for a client that attaches
    /// (`run` without `-d`, `create`); `run -d` clears `stdin_once`.
    /// `lookup` reads the CLI's environment, for `-e KEY`.
    pub fn to_config(
        &self,
        image: String,
        cmd: Vec<String>,
        lookup: &dyn Fn(&str) -> Option<String>,
    ) -> anyhow::Result<ContainerConfig> {
        if let Some(name) = &self.name
            && !rustlet_spec::valid_container_name(name)
        {
            bail!("invalid container name {name:?}: only [a-zA-Z0-9][a-zA-Z0-9_.-]* is allowed, up to 128 characters");
        }
        let restart = self.restart.unwrap_or_default();
        if self.rm && restart.name != RestartPolicyName::No {
            bail!("conflicting options: --restart and --rm (a removed container can't be restarted)");
        }
        // 0 means no limit, as for Docker (and --cpus below).
        let memory = self
            .memory
            .as_deref()
            .map(parse_size)
            .transpose()
            .map_err(anyhow::Error::msg)
            .context("--memory")?
            .filter(|&m| m > 0);
        if let Some(c) = self.cpus
            && (!c.is_finite() || c < 0.0)
        {
            bail!("--cpus {c}: must be a positive number of CPUs");
        }
        // 0 means no limit, as for Docker.
        let cpus = self.cpus.filter(|&c| c > 0.0);
        Ok(ContainerConfig {
            image,
            name: self.name.clone(),
            cmd,
            entrypoint: self.entrypoint.as_ref().map(|e| if e.is_empty() { Vec::new() } else { vec![e.clone()] }),
            env: resolve_env(&self.env, lookup)?,
            user: self.user.clone(),
            workdir: self.workdir.clone(),
            hostname: self.hostname.clone(),
            tty: self.tty,
            open_stdin: self.interactive,
            stdin_once: self.interactive,
            labels: parse_labels(&self.label)?,
            read_only: self.read_only,
            userns: match self.userns {
                Some(Userns::Remap) => UsernsMode::Remap,
                Some(Userns::Host) | None => UsernsMode::Host,
            },
            memory,
            cpus,
            pids_limit: self.pids_limit,
            restart,
            auto_remove: self.rm,
            stop_signal: self.stop_signal.clone(),
            stop_timeout: self.stop_timeout,
            cap_add: self.cap_add.clone(),
            cap_drop: self.cap_drop.clone(),
            privileged: self.privileged,
            security_opt: self.security_opt.clone(),
            devices: self.device.clone(),
            ..ContainerConfig::default()
        })
    }
}

/// `-e` values as `KEY=VALUE`. A bare `KEY` takes its value from the CLI's
/// environment, as with Docker; one that isn't set there is left out
/// (Docker would pass the bare name, which its daemon then drops).
pub fn resolve_env(values: &[String], lookup: &dyn Fn(&str) -> Option<String>) -> anyhow::Result<Vec<String>> {
    let mut env = Vec::with_capacity(values.len());
    for v in values {
        let (key, value) = match v.split_once('=') {
            Some((key, value)) => (key, Some(value.to_owned())),
            None => (v.as_str(), None),
        };
        if key.is_empty() {
            bail!("invalid environment variable {v:?}: no name");
        }
        match value.or_else(|| lookup(key)) {
            Some(value) => env.push(format!("{key}={value}")),
            None => continue,
        }
    }
    Ok(env)
}

/// `-l KEY=VALUE` (or a bare `KEY`, with an empty value).
fn parse_labels(values: &[String]) -> anyhow::Result<BTreeMap<String, String>> {
    let mut labels = BTreeMap::new();
    for v in values {
        let (key, value) = v.split_once('=').unwrap_or((v, ""));
        if key.is_empty() {
            bail!("invalid label {v:?}: no key");
        }
        labels.insert(key.to_owned(), value.to_owned());
    }
    Ok(labels)
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[derive(Parser)]
    struct Probe {
        #[command(flatten)]
        flags: CreateFlags,
    }

    fn flags(args: &[&str]) -> CreateFlags {
        Probe::try_parse_from(std::iter::once("probe").chain(args.iter().copied())).unwrap().flags
    }

    fn env(key: &str) -> Option<String> {
        match key {
            "HOME" => Some("/home/me".into()),
            _ => None,
        }
    }

    #[test]
    fn every_flag_reaches_the_config() {
        let f = flags(&[
            "-it",
            "--rm",
            "--name",
            "web",
            "-e",
            "A=1",
            "-e",
            "HOME",
            "-e",
            "UNSET",
            "-e",
            "EMPTY=",
            "-u",
            "1000:1000",
            "-w",
            "/srv",
            "--entrypoint",
            "/bin/sh",
            "--hostname",
            "box",
            "-l",
            "tier=front",
            "-l",
            "solo",
            "--memory",
            "512m",
            "--cpus",
            "1.5",
            "--pids-limit",
            "-1",
            "--read-only",
            "--userns",
            "remap",
            "--stop-signal",
            "SIGINT",
            "--stop-timeout",
            "3",
            "--cap-add",
            "NET_ADMIN",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--device",
            "/dev/fuse",
            "--pull",
            "never",
        ]);
        assert_eq!(f.pull, Pull::Never);
        let c = f.to_config("alpine".into(), vec!["sh".into(), "-c".into(), "echo hi".into()], &env).unwrap();
        let expected = ContainerConfig {
            image: "alpine".into(),
            name: Some("web".into()),
            cmd: vec!["sh".into(), "-c".into(), "echo hi".into()],
            entrypoint: Some(vec!["/bin/sh".into()]),
            env: vec!["A=1".into(), "HOME=/home/me".into(), "EMPTY=".into()],
            user: Some("1000:1000".into()),
            workdir: Some("/srv".into()),
            hostname: Some("box".into()),
            tty: true,
            open_stdin: true,
            stdin_once: true,
            labels: [("solo".to_owned(), String::new()), ("tier".to_owned(), "front".to_owned())].into(),
            read_only: true,
            userns: UsernsMode::Remap,
            memory: Some(512 << 20),
            cpus: Some(1.5),
            pids_limit: Some(-1),
            restart: RestartPolicy::default(),
            auto_remove: true,
            stop_signal: Some("SIGINT".into()),
            stop_timeout: Some(3),
            cap_add: vec!["NET_ADMIN".into()],
            cap_drop: vec!["ALL".into()],
            privileged: false,
            security_opt: vec!["no-new-privileges".into()],
            devices: vec!["/dev/fuse".into()],
            ..ContainerConfig::default()
        };
        assert_eq!(c, expected);
    }

    #[test]
    fn defaults_leave_everything_to_the_image() {
        let c = flags(&[]).to_config("alpine".into(), vec![], &env).unwrap();
        assert_eq!(c, ContainerConfig { image: "alpine".into(), ..ContainerConfig::default() });
        assert_eq!(flags(&[]).pull, Pull::Missing);
    }

    #[test]
    fn entrypoints() {
        let entrypoint = |args: &[&str]| flags(args).to_config("a".into(), vec![], &env).unwrap().entrypoint;
        assert_eq!(entrypoint(&["--entrypoint", ""]), Some(vec![]));
        assert_eq!(entrypoint(&["--entrypoint="]), Some(vec![]));
        assert_eq!(entrypoint(&["--entrypoint", "-x"]), Some(vec!["-x".to_owned()]));
        assert_eq!(entrypoint(&[]), None);
    }

    #[test]
    fn restart_policies_and_their_conflicts() {
        let config = |args: &[&str]| flags(args).to_config("a".into(), vec![], &env);
        let c = config(&["--restart", "on-failure:3"]).unwrap();
        assert_eq!(c.restart, RestartPolicy { name: RestartPolicyName::OnFailure, max_retries: 3 });
        assert!(config(&["--rm", "--restart", "no"]).is_ok());
        let e = config(&["--rm", "--restart", "always"]).unwrap_err();
        assert!(e.to_string().contains("--restart and --rm"), "{e}");
        assert!(Probe::try_parse_from(["p", "--restart", "sometimes"]).is_err());
    }

    #[test]
    fn bad_values_are_refused_before_any_request() {
        let config = |args: &[&str]| flags(args).to_config("a".into(), vec![], &env);
        for bad in [
            &["--name=-web"][..],
            &["--name", "a b"],
            &["--memory", "lots"],
            &["--cpus", "-1"],
            &["--cpus", "NaN"],
            &["-e", "=x"],
            &["-l", "=x"],
        ] {
            assert!(config(bad).is_err(), "{bad:?}");
        }
        assert_eq!(config(&["--cpus", "0"]).unwrap().cpus, None);
        assert_eq!(config(&["--memory", "0"]).unwrap().memory, None, "0: no limit, as for Docker");
        assert!(format!("{:#}", config(&["--memory", "lots"]).unwrap_err()).starts_with("--memory: invalid size"));
    }
}

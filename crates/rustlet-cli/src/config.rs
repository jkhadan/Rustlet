//! From `run`/`create` flags to the daemon's [`ContainerConfig`].
//!
//! The CLI does here what Docker's does before a request leaves: sizes
//! become bytes, `-e KEY` takes its value from the CLI's own environment,
//! `-v ./dir:…` its current directory, `--entrypoint ""` becomes "no
//! entrypoint", labels become a map, port ranges one mapping per port. It
//! also refuses what can't work (`--rm` with a restart policy, a name the
//! daemon would reject, `-p` on another container's network, `--network
//! host` beside another network, `--ip` on the default one, two mounts on
//! one path), so that the error comes before anything exists. What the
//! flags *mean* (an entrypoint replacing the image's, a user looked up in
//! the image, a volume created on first use) is the daemon's business.

use std::collections::{BTreeMap, HashSet};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, anyhow, bail};
use clap::ValueEnum;
use rustlet_spec::container::{ContainerConfig, RestartPolicy, RestartPolicyName, UsernsMode};
use rustlet_spec::network::{NetworkMode, PortMapping, parse_extra_host, valid_hostname};
use rustlet_spec::volume::MountSpec;

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
    /// Publish a container port on the host: [[HOST_IP:][HOST_PORT]:]CONTAINER_PORT[/PROTO] (repeatable)
    #[arg(short, long, value_name = "PORT")]
    pub publish: Vec<String>,
    /// Publish every port the image exposes, each on a free host port
    #[arg(short = 'P', long)]
    pub publish_all: bool,
    /// Network to join: bridge (the default), none, host, container:NAME|ID, or a network's name (repeatable, to join more networks)
    #[arg(long, visible_alias = "net", value_name = "NETWORK")]
    pub network: Vec<String>,
    /// Another name for the container on its first (user-defined) network (repeatable)
    #[arg(long, value_name = "ALIAS")]
    pub network_alias: Vec<String>,
    /// IPv4 address on its first network, a user-defined one (default: the next free one)
    #[arg(long, value_name = "IPV4")]
    pub ip: Option<Ipv4Addr>,
    /// IPv6 address on its first network, a user-defined one with IPv6 (default: the next free one)
    #[arg(long, value_name = "IPV6")]
    pub ip6: Option<Ipv6Addr>,
    /// DNS server to use instead of the host's (repeatable)
    #[arg(long, value_name = "IP")]
    pub dns: Vec<String>,
    /// DNS search domain (repeatable)
    #[arg(long, value_name = "DOMAIN")]
    pub dns_search: Vec<String>,
    /// DNS resolver option, as resolv.conf takes it: ndots:2 (repeatable)
    #[arg(long, value_name = "OPTION")]
    pub dns_option: Vec<String>,
    /// Add an /etc/hosts line: NAME:IP, or NAME:host-gateway for the host (repeatable)
    #[arg(long, value_name = "NAME:IP")]
    pub add_host: Vec<String>,
    /// Mount a volume or a host path: [SOURCE:]TARGET[:ro,nocopy,…] (repeatable)
    #[arg(short, long, value_name = "VOLUME")]
    pub volume: Vec<String>,
    /// Mount a volume, host path or tmpfs: type=…,source=…,target=…[,readonly] (repeatable)
    #[arg(long, value_name = "MOUNT")]
    pub mount: Vec<String>,
    /// Mount a tmpfs: TARGET[:size=…,mode=…,…] (repeatable)
    #[arg(long, value_name = "TMPFS")]
    pub tmpfs: Vec<String>,
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
    /// `lookup` reads the CLI's environment, for `-e KEY`, and `cwd` gives
    /// its current directory, for `-v ./dir:…` (asked only then).
    pub fn to_config(
        &self,
        image: String,
        cmd: Vec<String>,
        lookup: &dyn Fn(&str) -> Option<String>,
        cwd: &dyn Fn() -> io::Result<PathBuf>,
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
        let (network, extra_networks) = self.networks()?;
        self.check_network(&network)?;
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
            healthcheck: None,
            cap_add: self.cap_add.clone(),
            cap_drop: self.cap_drop.clone(),
            privileged: self.privileged,
            security_opt: self.security_opt.clone(),
            devices: self.device.clone(),
            network,
            network_aliases: self.network_alias.clone(),
            ip: self.ip,
            ip6: self.ip6,
            extra_networks,
            ports: parse_ports(&self.publish)?,
            publish_all: self.publish_all,
            dns: parse_dns(&self.dns)?,
            dns_search: check_dns_search(&self.dns_search)?,
            dns_options: self.dns_option.clone(),
            extra_hosts: parse_extra_hosts(&self.add_host)?,
            mounts: self.mounts(cwd)?,
        })
    }

    /// `-v`, `--mount` and `--tmpfs`, in that order.
    fn mounts(&self, cwd: &dyn Fn() -> io::Result<PathBuf>) -> anyhow::Result<Vec<MountSpec>> {
        let mut mounts = Vec::new();
        for v in &self.volume {
            mounts.push(MountSpec::parse_volume(&absolute_source(v, cwd)?).map_err(anyhow::Error::msg)?);
        }
        for m in &self.mount {
            mounts.push(MountSpec::parse_mount(m).map_err(anyhow::Error::msg)?);
        }
        for t in &self.tmpfs {
            mounts.push(MountSpec::parse_tmpfs(t).map_err(anyhow::Error::msg)?);
        }
        check_mount_points(&mounts)?;
        Ok(mounts)
    }

    /// `--network`, given once or more: the first is the container's
    /// network mode, any later one another network to connect it to, by
    /// name (`bridge` and `default` are the default network). Only bridge
    /// networks go together: on the host's network, on none or on another
    /// container's, the container has no network namespace of its own to
    /// connect anywhere else.
    fn networks(&self) -> anyhow::Result<(NetworkMode, Vec<String>)> {
        let modes = self.network.iter().map(|n| NetworkMode::parse(n));
        let modes: Vec<NetworkMode> = modes.collect::<Result<_, _>>().map_err(anyhow::Error::msg)?;
        let mut seen = HashSet::new();
        for mode in &modes {
            if !seen.insert(mode) {
                bail!("--network {mode} is given more than once");
            }
        }
        if modes.len() > 1
            && let Some(alone) = modes.iter().position(|m| m.network_name().is_none())
        {
            // The first and the one that can't go with it, or the second if
            // that is the first.
            let (a, b) = (&modes[0], &modes[alone.max(1)]);
            bail!(
                "conflicting options: --network {a} and --network {b} (host, none and container:NAME can't be \
                 combined with other networks)"
            );
        }
        // Bridge networks all, by now.
        let extra = modes.iter().skip(1).filter_map(NetworkMode::network_name).map(str::to_owned).collect();
        Ok((modes.into_iter().next().unwrap_or_default(), extra))
    }

    /// Refuses what `mode` leaves no room for, as Docker does: a container
    /// on another container's network has that one's ports, addresses, DNS
    /// settings, hosts file and host name; aliases are names for the DNS
    /// server that only a user-defined network has; and an address of the
    /// user's choosing (`--ip`, `--ip6`) is for a user-defined network too,
    /// the default one's subnet being the daemon's configuration, not the
    /// user's.
    fn check_network(&self, mode: &NetworkMode) -> anyhow::Result<()> {
        if let NetworkMode::Container(other) = mode {
            let given = [
                ("--publish", !self.publish.is_empty()),
                ("--publish-all", self.publish_all),
                ("--dns", !self.dns.is_empty()),
                ("--dns-search", !self.dns_search.is_empty()),
                ("--dns-option", !self.dns_option.is_empty()),
                ("--add-host", !self.add_host.is_empty()),
                ("--hostname", self.hostname.is_some()),
                ("--network-alias", !self.network_alias.is_empty()),
                ("--ip", self.ip.is_some()),
                ("--ip6", self.ip6.is_some()),
            ];
            if let Some((flag, _)) = given.iter().find(|(_, given)| *given) {
                bail!(
                    "conflicting options: --network container:{other} and {flag} (on {other}'s network, the ports, \
                     addresses, DNS settings, /etc/hosts and host name are {other}'s)"
                );
            }
        }
        if !self.network_alias.is_empty() && !matches!(mode, NetworkMode::Network(_)) {
            bail!(
                "--network-alias needs a user-defined network (--network NAME): {mode} has no DNS server to answer it"
            );
        }
        let addresses = [("--ip", self.ip.is_some()), ("--ip6", self.ip6.is_some())];
        if let Some((flag, _)) = addresses.iter().find(|(_, given)| *given)
            && !matches!(mode, NetworkMode::Network(_))
        {
            bail!("{flag} needs a user-defined network as the first --network: {mode} doesn't take static addresses");
        }
        Ok(())
    }
}

/// `-v`'s value with a host path that starts with `.` made absolute
/// against the CLI's current directory (`./site:/www` →
/// `/home/me/site:/www`), as Docker's CLI does since 23.0. Like Go's
/// `filepath.Abs` there, it drops `.` and resolves `..` by the path's text
/// alone, not the file system's links. Nothing else is rewritten:
/// `site:/www` names a volume.
fn absolute_source(value: &str, cwd: &dyn Fn() -> io::Result<PathBuf>) -> anyhow::Result<String> {
    let Some((source, rest)) = value.split_once(':').filter(|(source, _)| source.starts_with('.')) else {
        return Ok(value.to_owned());
    };
    let dir = cwd().with_context(|| format!("-v {value:?}: reading the current directory"))?;
    let absolute = clean(&dir.join(source));
    let Some(absolute) = absolute.to_str() else {
        bail!("-v {value:?}: the current directory's path isn't UTF-8");
    };
    // `-v` splits at colons: the path would come apart.
    if absolute.contains(':') {
        bail!("-v {value:?}: the host path {absolute:?} has a ':' in it, which -v can't express; use --mount");
    }
    Ok(format!("{absolute}:{rest}"))
}

/// The absolute `path` without `.` and `..` components; a `..` takes the
/// component before it away (none at `/`).
fn clean(path: &Path) -> PathBuf {
    let mut clean = PathBuf::from("/");
    for component in path.components() {
        match component {
            Component::Normal(name) => clean.push(name),
            Component::ParentDir => {
                clean.pop();
            }
            Component::RootDir | Component::CurDir | Component::Prefix(_) => {}
        }
    }
    clean
}

/// Two mounts on one path can't both be seen there; Docker refuses them
/// too.
fn check_mount_points(mounts: &[MountSpec]) -> anyhow::Result<()> {
    let mut seen = HashSet::new();
    for m in mounts {
        // `/data`, `/data/` and `//data/.` are one place.
        let place: Vec<&str> = m.target.split('/').filter(|c| !c.is_empty() && *c != ".").collect();
        if !seen.insert(place) {
            bail!("duplicate mount point: {}", m.target);
        }
    }
    Ok(())
}

/// `-p` values, a range giving one mapping per port.
fn parse_ports(values: &[String]) -> anyhow::Result<Vec<PortMapping>> {
    let ports = values.iter().map(|p| PortMapping::parse(p)).collect::<Result<Vec<_>, _>>();
    Ok(ports.map_err(anyhow::Error::msg)?.concat())
}

/// `--add-host` values as the daemon takes them: `NAME:IP` (not `NAME=IP`),
/// the IP without brackets.
fn parse_extra_hosts(values: &[String]) -> anyhow::Result<Vec<String>> {
    let host = |h: &String| parse_extra_host(h).map(|(name, ip)| format!("{name}:{ip}"));
    values.iter().map(host).collect::<Result<_, _>>().map_err(anyhow::Error::msg)
}

/// `--dns` values: IP addresses, as Docker's CLI checks them, in their
/// usual form (`::1` for `0:0::1`).
fn parse_dns(values: &[String]) -> anyhow::Result<Vec<String>> {
    values
        .iter()
        .map(|v| v.parse::<IpAddr>().map(|ip| ip.to_string()).map_err(|_| anyhow!("--dns {v:?}: not an IP address")))
        .collect()
}

/// `--dns-search` values: domain names, or `.` for none, as Docker's CLI
/// checks them.
fn check_dns_search(values: &[String]) -> anyhow::Result<Vec<String>> {
    if let Some(bad) = values.iter().find(|v| *v != "." && !valid_hostname(v)) {
        bail!("--dns-search {bad:?}: not a domain name");
    }
    Ok(values.to_vec())
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

/// `-l KEY=VALUE` (or a bare `KEY`, with an empty value); `--label` of
/// `network create` and `volume create` too.
pub fn parse_labels(values: &[String]) -> anyhow::Result<BTreeMap<String, String>> {
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
    use rustlet_spec::network::Protocol;
    use rustlet_spec::volume::MountType;

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

    fn cwd() -> io::Result<PathBuf> {
        Ok("/home/me/src".into())
    }

    /// `args` as the config for `a`, with no command.
    fn config(args: &[&str]) -> anyhow::Result<ContainerConfig> {
        flags(args).to_config("a".into(), vec![], &env, &cwd)
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
            "-p",
            "8080:80",
            "--publish",
            "127.0.0.1:9000-9001:9000-9001/udp",
            "-P",
            "--network",
            "backend",
            "--network-alias",
            "api",
            "--network-alias",
            "www",
            "--ip",
            "10.89.1.5",
            "--ip6",
            "fd00:89:0:1::5",
            "--net",
            "net2",
            "--network",
            "default",
            "--dns",
            "10.0.0.2",
            "--dns",
            "0:0::1",
            "--dns-search",
            "corp.example",
            "--dns-option",
            "ndots:2",
            "--add-host",
            "db=10.0.0.5",
            "--add-host",
            "gw:host-gateway",
            "--add-host",
            "v6:[fe80::1]",
            "-v",
            "data:/data:ro",
            "--volume",
            "./site:/www",
            "-v",
            "/cache",
            "--mount",
            "type=bind,src=/etc/hosts,dst=/etc/h,readonly",
            "--tmpfs",
            "/run:size=64m",
            "--pull",
            "never",
        ]);
        assert_eq!(f.pull, Pull::Never);
        let c = f.to_config("alpine".into(), vec!["sh".into(), "-c".into(), "echo hi".into()], &env, &cwd).unwrap();
        let mapping = |host_ip, host_port, container_port, protocol| PortMapping {
            host_ip,
            host_port: Some(host_port),
            container_port,
            protocol,
        };
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
            healthcheck: None,
            cap_add: vec!["NET_ADMIN".into()],
            cap_drop: vec!["ALL".into()],
            privileged: false,
            security_opt: vec!["no-new-privileges".into()],
            devices: vec!["/dev/fuse".into()],
            network: NetworkMode::Network("backend".into()),
            network_aliases: vec!["api".into(), "www".into()],
            ip: Some(Ipv4Addr::new(10, 89, 1, 5)),
            ip6: Some("fd00:89:0:1::5".parse().unwrap()),
            // `default` is the default network, by its name.
            extra_networks: vec!["net2".into(), "bridge".into()],
            // The range is one mapping per port.
            ports: vec![
                mapping(None, 8080, 80, Protocol::Tcp),
                mapping(Some(Ipv4Addr::LOCALHOST.into()), 9000, 9000, Protocol::Udp),
                mapping(Some(Ipv4Addr::LOCALHOST.into()), 9001, 9001, Protocol::Udp),
            ],
            publish_all: true,
            dns: vec!["10.0.0.2".into(), "::1".into()],
            dns_search: vec!["corp.example".into()],
            dns_options: vec!["ndots:2".into()],
            extra_hosts: vec!["db:10.0.0.5".into(), "gw:host-gateway".into(), "v6:fe80::1".into()],
            mounts: vec![
                MountSpec {
                    source: Some("data".into()),
                    target: "/data".into(),
                    read_only: true,
                    ..MountSpec::default()
                },
                MountSpec {
                    kind: MountType::Bind,
                    source: Some("/home/me/src/site".into()),
                    target: "/www".into(),
                    create_host_path: true,
                    ..MountSpec::default()
                },
                MountSpec { kind: MountType::Volume, target: "/cache".into(), ..MountSpec::default() },
                MountSpec {
                    kind: MountType::Bind,
                    source: Some("/etc/hosts".into()),
                    target: "/etc/h".into(),
                    read_only: true,
                    ..MountSpec::default()
                },
                MountSpec {
                    kind: MountType::Tmpfs,
                    target: "/run".into(),
                    tmpfs_size: Some(64 << 20),
                    ..MountSpec::default()
                },
            ],
        };
        assert_eq!(c, expected);
    }

    #[test]
    fn defaults_leave_everything_to_the_image() {
        let c = flags(&[]).to_config("alpine".into(), vec![], &env, &cwd).unwrap();
        assert_eq!(c, ContainerConfig { image: "alpine".into(), ..ContainerConfig::default() });
        assert_eq!(c.network, NetworkMode::Bridge);
        assert_eq!(flags(&[]).pull, Pull::Missing);
    }

    #[test]
    fn entrypoints() {
        let entrypoint = |args: &[&str]| config(args).unwrap().entrypoint;
        assert_eq!(entrypoint(&["--entrypoint", ""]), Some(vec![]));
        assert_eq!(entrypoint(&["--entrypoint="]), Some(vec![]));
        assert_eq!(entrypoint(&["--entrypoint", "-x"]), Some(vec!["-x".to_owned()]));
        assert_eq!(entrypoint(&[]), None);
    }

    #[test]
    fn restart_policies_and_their_conflicts() {
        let c = config(&["--restart", "on-failure:3"]).unwrap();
        assert_eq!(c.restart, RestartPolicy { name: RestartPolicyName::OnFailure, max_retries: 3 });
        assert!(config(&["--rm", "--restart", "no"]).is_ok());
        let e = config(&["--rm", "--restart", "always"]).unwrap_err();
        assert!(e.to_string().contains("--restart and --rm"), "{e}");
        assert!(Probe::try_parse_from(["p", "--restart", "sometimes"]).is_err());
    }

    #[test]
    fn network_modes() {
        let network = |args: &[&str]| config(args).unwrap().network;
        assert_eq!(network(&["--network", "none"]), NetworkMode::None);
        assert_eq!(network(&["--net", "host"]), NetworkMode::Host);
        assert_eq!(network(&["--net=default"]), NetworkMode::Bridge);
        assert_eq!(network(&["--network", "container:db"]), NetworkMode::Container("db".into()));
        let e = config(&["--network", "a b"]).unwrap_err().to_string();
        assert!(e.starts_with("--network \"a b\": "), "{e}");
        // Given again: more networks, after the first.
        let c = config(&["--network", "bridge", "--net", "b", "--network=a"]).unwrap();
        assert_eq!((c.network, c.extra_networks), (NetworkMode::Bridge, vec!["b".into(), "a".into()]));
        let e = config(&["--network", "a", "--network", "b c"]).unwrap_err().to_string();
        assert!(e.starts_with("--network \"b c\": "), "{e}");
    }

    #[test]
    fn what_another_containers_network_decides_is_refused() {
        for (flag, args) in [
            ("--publish", &["-p", "80"][..]),
            ("--publish-all", &["-P"]),
            ("--dns", &["--dns", "1.1.1.1"]),
            ("--dns-search", &["--dns-search", "corp.example"]),
            ("--dns-option", &["--dns-option", "ndots:1"]),
            ("--add-host", &["--add-host", "db:10.0.0.5"]),
            ("--hostname", &["--hostname", "box"]),
            ("--network-alias", &["--network-alias", "api"]),
            ("--ip", &["--ip", "10.89.1.5"]),
            ("--ip6", &["--ip6", "fd00::5"]),
        ] {
            let e = config(&[&["--network", "container:db"][..], args].concat()).unwrap_err().to_string();
            assert!(e.starts_with(&format!("conflicting options: --network container:db and {flag} (")), "{e}");
        }
        assert!(config(&["--network", "container:db", "-e", "A=1", "-v", "/data"]).is_ok());
        // The same flags with a network namespace of the container's own
        // are fine, and so is publishing on the host's network (what that
        // means is the daemon's to say).
        assert!(config(&["--network", "none", "-p", "80", "--dns", "1.1.1.1", "--hostname", "box"]).is_ok());
        assert!(config(&["--network", "host", "-P", "--add-host", "db:10.0.0.5"]).is_ok());
    }

    #[test]
    fn aliases_need_a_user_defined_network() {
        let modes: [&[&str]; 5] =
            [&[], &["--network", "bridge"], &["--network", "default"], &["--network", "none"], &["--network", "host"]];
        for mode in modes {
            let e = config(&[mode, &["--network-alias", "api"]].concat()).unwrap_err().to_string();
            assert!(e.starts_with("--network-alias needs a user-defined network (--network NAME): "), "{e}");
        }
        assert_eq!(config(&["--network", "backend", "--network-alias", "api"]).unwrap().network_aliases, ["api"]);
    }

    #[test]
    fn relative_host_paths_are_made_absolute() {
        let mount = |v: &str| config(&["-v", v]).unwrap().mounts.remove(0);
        let source = |v: &str| mount(v).source.unwrap();
        assert_eq!(source("./site:/www"), "/home/me/src/site");
        assert_eq!(source("./site/:/www:ro"), "/home/me/src/site");
        assert_eq!(source(".:/src"), "/home/me/src");
        assert_eq!(source("..:/up"), "/home/me");
        assert_eq!(source("../lib/./x/../y:/y"), "/home/me/lib/y");
        assert_eq!(source(".hidden:/h"), "/home/me/src/.hidden");
        assert_eq!(source("../../../..:/root"), "/");
        assert_eq!(mount("./site:/www").kind, MountType::Bind);
        assert!(mount("./site:/www:ro").read_only);
        // Nothing else changes: an absolute path stays as it is, a name is
        // a volume's, and a path alone is the target of an anonymous volume.
        assert_eq!(source("/srv/../www:/www"), "/srv/../www");
        assert_eq!(mount("site:/www").kind, MountType::Volume);
        assert!(config(&["-v", "./site"]).is_err(), "a relative target");
        assert_eq!(absolute_source("site:/www", &cwd).unwrap(), "site:/www");

        // The current directory is only asked for when it's needed.
        let gone = || -> io::Result<PathBuf> { Err(io::ErrorKind::NotFound.into()) };
        let config_in_gone = |v: &str| flags(&["-v", v]).to_config("a".into(), vec![], &env, &gone);
        assert!(config_in_gone("data:/data").is_ok());
        let e = format!("{:#}", config_in_gone("./data:/data").unwrap_err());
        assert!(e.starts_with("-v \"./data:/data\": reading the current directory: "), "{e}");
        // A colon in it would split the rewritten value in the wrong place.
        let odd = || -> io::Result<PathBuf> { Ok("/home/me/a:b".into()) };
        let e = flags(&["-v", "./d:/d"]).to_config("a".into(), vec![], &env, &odd).unwrap_err().to_string();
        assert!(e.contains("use --mount"), "{e}");
    }

    #[test]
    fn two_mounts_on_one_path_are_refused() {
        for args in [
            &["-v", "data:/data", "-v", "/data"][..],
            &["-v", "data:/data", "--tmpfs", "/data/"],
            &["--mount", "dst=/data", "-v", "/srv:/data/."],
            &["--tmpfs", "/run", "--tmpfs", "//run"],
        ] {
            let e = config(args).unwrap_err().to_string();
            assert!(e.starts_with("duplicate mount point: "), "{args:?}: {e}");
        }
        assert_eq!(config(&["-v", "data:/data", "--tmpfs", "/data/tmp"]).unwrap().mounts.len(), 2);
    }

    #[test]
    fn bad_values_are_refused_before_any_request() {
        for bad in [
            &["--name=-web"][..],
            &["--name", "a b"],
            &["--memory", "lots"],
            &["--cpus", "-1"],
            &["--cpus", "NaN"],
            &["-e", "=x"],
            &["-l", "=x"],
            &["-p", "80:80:80:80"],
            &["-p", "8000-8001:80"],
            &["--dns", "8.8.8"],
            &["--dns", "[::1]"],
            &["--dns-search", "a..b"],
            &["--add-host", "db"],
            &["--add-host", "db:nope"],
            &["-v", "../x"],
            &["-v", "x:/data"],
            &["--mount", "type=bind,dst=/x"],
            &["--tmpfs", "/x:size=lots"],
        ] {
            assert!(config(bad).is_err(), "{bad:?}");
        }
        assert_eq!(config(&["--cpus", "0"]).unwrap().cpus, None);
        assert_eq!(config(&["--memory", "0"]).unwrap().memory, None, "0: no limit, as for Docker");
        assert!(format!("{:#}", config(&["--memory", "lots"]).unwrap_err()).starts_with("--memory: invalid size"));
        assert_eq!(config(&["--dns-search", "."]).unwrap().dns_search, ["."], "no search domain");
        // The spec's parsers say which flag and value were wrong.
        assert!(config(&["-p", "x"]).unwrap_err().to_string().starts_with("-p \"x\": "));
        assert!(config(&["--tmpfs", "tmp"]).unwrap_err().to_string().starts_with("--tmpfs \"tmp\": "));
    }
}

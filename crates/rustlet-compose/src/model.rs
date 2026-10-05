//! The compose file as written: the supported subset of the Compose
//! Specification, read from the YAML document (interpolated, and merged when
//! there are several files) into plain types.
//!
//! The document is walked by hand rather than through `#[derive(Deserialize)]`:
//!
//! - every error names its place (`services.web.ports[1]: …`);
//! - a key Rustlets doesn't support is refused by name (`services.web.secrets
//!   is not supported`), never silently dropped;
//! - the several forms Compose allows for one field (a string or a list,
//!   `KEY=VALUE` items or a mapping, short or long syntax) are each read in
//!   one place, and so are the strings interpolation leaves where a number or
//!   a boolean belongs (`replicas: ${N}`, `tty: ${TTY:-false}`): Compose
//!   converts those back by the field's type, and so does this. A boolean
//!   may be written with YAML 1.1's other words too (`yes`, `no`, `on`,
//!   `off`, `y`, `n`: compose-go's `toBoolean`), with a warning
//!   ([`ComposeFile::warnings`]).
//!
//! A key whose value is empty (`image:` alone) counts as not given.
//! Extension fields (`x-…`) are accepted and ignored wherever Compose takes
//! them: at the top level and in every settings mapping (a service, its
//! `build`, `healthcheck`, `deploy`…, a network, a volume), but not in
//! mappings of names (`environment`, `labels`, `services`), where `x-db` is a
//! name like any other. So is the obsolete top-level `version`.
//!
//! What only the project can decide (named volumes' and networks' daemon
//! names, relative paths, `env_file` contents, the value a bare
//! `environment` key takes) is left to [`crate::load`].

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::rc::Rc;
use std::str::FromStr;
use std::time::Duration;

use rustlet_spec::container::{HealthConfig, RestartPolicy};
use rustlet_spec::network::{PortMapping, parse_extra_host};
use rustlet_spec::volume::{MountSpec, MountType};
use serde_yaml_ng::Value;

use crate::project::Condition;
use crate::{Error, Result};

/// A compose file.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ComposeFile {
    pub name: Option<String>,
    /// The obsolete `version` was given (Compose warns, and ignores it).
    pub version: bool,
    /// In the file's order.
    pub services: Vec<ServiceDef>,
    pub networks: BTreeMap<String, NetworkDef>,
    pub volumes: BTreeMap<String, VolumeDef>,
    /// What reading it noticed and accepted: a boolean written `yes`.
    pub warnings: Vec<String>,
}

/// A service as written.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ServiceDef {
    pub name: String,
    pub image: Option<String>,
    pub build: Option<BuildDef>,
    /// A string is split as a POSIX shell would ([`split_command`]).
    pub command: Option<Vec<String>>,
    pub entrypoint: Option<Vec<String>>,
    /// In order; a bare `KEY` has no value (the environment's is taken).
    pub environment: Vec<(String, Option<String>)>,
    pub env_file: Vec<EnvFileDef>,
    pub ports: Vec<PortMapping>,
    pub volumes: Vec<MountDef>,
    pub tmpfs: Vec<MountSpec>,
    /// In the file's order.
    pub networks: Vec<ServiceNetworkDef>,
    pub depends_on: Vec<DependsOnDef>,
    pub restart: Option<RestartPolicy>,
    pub healthcheck: Option<HealthConfig>,
    pub working_dir: Option<String>,
    pub user: Option<String>,
    pub hostname: Option<String>,
    pub container_name: Option<String>,
    pub labels: BTreeMap<String, String>,
    pub tty: bool,
    pub stdin_open: bool,
    pub read_only: bool,
    pub privileged: bool,
    pub cap_add: Vec<String>,
    pub cap_drop: Vec<String>,
    pub security_opt: Vec<String>,
    pub devices: Vec<String>,
    pub dns: Vec<String>,
    pub dns_search: Vec<String>,
    pub dns_opt: Vec<String>,
    /// `name:ip`, checked.
    pub extra_hosts: Vec<String>,
    pub stop_signal: Option<String>,
    pub stop_grace_period: Option<Duration>,
    /// Bytes; `None` for 0 (no limit).
    pub mem_limit: Option<u64>,
    /// `None` for 0 (no limit).
    pub cpus: Option<f64>,
    pub pids_limit: Option<i64>,
    pub deploy: DeployDef,
    pub scale: Option<u32>,
    pub pull_policy: Option<PullPolicyDef>,
    pub profiles: Vec<String>,
    pub network_mode: Option<String>,
    /// Accepted, and ignored with a warning: Rustlets has no `--expose`.
    pub expose: Vec<String>,
}

/// `build:`, the string form being its `context`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BuildDef {
    /// As written (default `.`), relative to the project directory.
    pub context: String,
    pub dockerfile: Option<String>,
    pub args: Vec<(String, Option<String>)>,
    pub target: Option<String>,
    pub labels: BTreeMap<String, String>,
    pub network: Option<String>,
    pub no_cache: bool,
}

/// One of `env_file:`: a path, or `{path, required}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvFileDef {
    /// As written, relative to the project directory.
    pub path: String,
    /// A missing file is an error (default), or skipped.
    pub required: bool,
}

/// One of a service's `volumes:`, short or long syntax.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MountDef {
    pub kind: MountType,
    /// A volume's key in the file, or a host path as written (`/abs`,
    /// `./rel`, `../rel`, `~/rel`); none for an anonymous volume or a tmpfs.
    pub source: Option<String>,
    pub target: String,
    pub read_only: bool,
    pub no_copy: bool,
    pub create_host_path: bool,
    pub tmpfs_size: Option<u64>,
}

/// A service on one of the file's networks.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServiceNetworkDef {
    /// The network's key in the file.
    pub key: String,
    pub aliases: Vec<String>,
    pub ipv4_address: Option<Ipv4Addr>,
    pub ipv6_address: Option<Ipv6Addr>,
}

/// One of `depends_on:`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependsOnDef {
    pub service: String,
    pub condition: Condition,
    pub required: bool,
}

/// `deploy:`, what of it Rustlets reads.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DeployDef {
    pub replicas: Option<u32>,
    /// `resources.limits`: `None` for 0 (no limit).
    pub cpus: Option<f64>,
    /// Bytes; `None` for 0 (no limit).
    pub memory: Option<u64>,
    pub pids: Option<i64>,
}

/// `pull_policy:`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PullPolicyDef {
    Always,
    /// `missing`, or its old name `if_not_present`.
    Missing,
    Never,
    /// Build the image, every time.
    Build,
}

/// A network of the file (top-level `networks:`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkDef {
    /// `name:` (or an external network's legacy `external: {name: …}`).
    pub name: Option<String>,
    pub external: bool,
    pub internal: bool,
    pub enable_ipv6: bool,
    /// `ipam.config[].subnet`.
    pub subnets: Vec<String>,
    pub labels: BTreeMap<String, String>,
}

/// A named volume of the file (top-level `volumes:`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VolumeDef {
    pub name: Option<String>,
    pub external: bool,
    pub labels: BTreeMap<String, String>,
}

/// Reads a compose document (a mapping, or nothing for an empty file).
pub fn parse(doc: &Value) -> Result<ComposeFile> {
    let root = At::default();
    if !matches!(doc, Value::Mapping(_) | Value::Null) {
        return Err(Error::Parse(format!(
            "a compose file is a mapping (services:, networks:, volumes:), not {}",
            kind(doc)
        )));
    }
    let mut file = ComposeFile::default();
    for (key, value) in entries(doc, &root)? {
        let at = root.key(key);
        match key {
            "name" => file.name = opt_text(value, &at)?,
            "version" => file.version = true,
            "services" => {
                for (name, def) in entries(value, &at)? {
                    check_name(name, "service", &at)?;
                    file.services.push(service(name, def, &at.key(name))?);
                }
            }
            "networks" => {
                for (name, def) in entries(value, &at)? {
                    check_name(name, "network", &at)?;
                    file.networks.insert(name.to_owned(), network(def, &at.key(name))?);
                }
            }
            "volumes" => {
                for (name, def) in entries(value, &at)? {
                    check_name(name, "volume", &at)?;
                    file.volumes.insert(name.to_owned(), volume(def, &at.key(name))?);
                }
            }
            _ => other_key(key, &at)?,
        }
    }
    file.warnings = root.take_warnings();
    Ok(file)
}

fn service(name: &str, def: &Value, at: &At) -> Result<ServiceDef> {
    let mut s = ServiceDef { name: name.to_owned(), ..ServiceDef::default() };
    if !matches!(def, Value::Mapping(_) | Value::Null) {
        return Err(at.bad(format!("a service is a mapping (image:, build:, …), not {}", kind(def))));
    }
    for (key, value) in entries(def, at)? {
        let at = &at.key(key);
        match key {
            "image" => s.image = opt_text(value, at)?.filter(|i| !i.is_empty()),
            "build" => s.build = build(value, at)?,
            "command" => s.command = command(value, at)?,
            "entrypoint" => s.entrypoint = command(value, at)?,
            "environment" => s.environment = key_values(value, at)?,
            "env_file" => s.env_file = env_files(value, at)?,
            "ports" => s.ports = ports(value, at)?,
            "volumes" => s.volumes = mounts(value, at)?,
            "tmpfs" => s.tmpfs = tmpfs(value, at)?,
            "networks" => s.networks = service_networks(value, at)?,
            "depends_on" => s.depends_on = depends_on(value, at)?,
            "restart" => s.restart = restart(value, at)?,
            "healthcheck" => s.healthcheck = healthcheck(value, at)?,
            "working_dir" => s.working_dir = opt_text(value, at)?,
            "user" => s.user = opt_text(value, at)?,
            "hostname" => s.hostname = opt_text(value, at)?,
            "container_name" => s.container_name = opt_text(value, at)?,
            "labels" => s.labels = labels(value, at)?,
            "tty" => s.tty = flag(value, at)?,
            "stdin_open" => s.stdin_open = flag(value, at)?,
            "read_only" => s.read_only = flag(value, at)?,
            "privileged" => s.privileged = flag(value, at)?,
            "cap_add" => s.cap_add = texts(value, at)?,
            "cap_drop" => s.cap_drop = texts(value, at)?,
            "security_opt" => s.security_opt = texts(value, at)?,
            "devices" => s.devices = texts(value, at)?,
            "dns" => s.dns = text_or_texts(value, at)?,
            "dns_search" => s.dns_search = text_or_texts(value, at)?,
            "dns_opt" => s.dns_opt = texts(value, at)?,
            "extra_hosts" => s.extra_hosts = extra_hosts(value, at)?,
            "stop_signal" => s.stop_signal = opt_text(value, at)?,
            "stop_grace_period" => s.stop_grace_period = opt_duration(value, at)?,
            "mem_limit" => s.mem_limit = opt_size(value, at)?.filter(|&bytes| bytes > 0),
            "cpus" => s.cpus = opt_cpus(value, at)?,
            "pids_limit" => s.pids_limit = opt_number(value, at, "a process count")?,
            "deploy" => s.deploy = deploy(value, at)?,
            "scale" => s.scale = opt_number(value, at, "a container count")?,
            "pull_policy" => s.pull_policy = pull_policy(value, at)?,
            "profiles" => s.profiles = texts(value, at)?,
            "network_mode" => s.network_mode = opt_text(value, at)?,
            "expose" => s.expose = texts(value, at)?,
            _ => other_key(key, at)?,
        }
    }
    Ok(s)
}

/// `build: DIR`, or its long form.
fn build(v: &Value, at: &At) -> Result<Option<BuildDef>> {
    let mut b = BuildDef { context: ".".into(), ..BuildDef::default() };
    match v {
        Value::Null => return Ok(None),
        Value::Mapping(_) => {
            for (key, value) in entries(v, at)? {
                let at = &at.key(key);
                match key {
                    "context" => b.context = opt_text(value, at)?.unwrap_or_else(|| ".".into()),
                    "dockerfile" => b.dockerfile = opt_text(value, at)?,
                    "args" => b.args = key_values(value, at)?,
                    "target" => b.target = opt_text(value, at)?,
                    "labels" => b.labels = labels(value, at)?,
                    "network" => b.network = opt_text(value, at)?,
                    "no_cache" => b.no_cache = flag(value, at)?,
                    _ => other_key(key, at)?,
                }
            }
        }
        other => b.context = text(other, at)?,
    }
    if b.context.contains("://") || b.context.starts_with("git@") {
        return Err(at.invalid(format!("the context {:?} is remote; only a local directory is supported", b.context)));
    }
    Ok(Some(b))
}

/// `command:`/`entrypoint:`: a list as it is, a string split as a shell
/// would.
fn command(v: &Value, at: &At) -> Result<Option<Vec<String>>> {
    match v {
        Value::Null => Ok(None),
        Value::Sequence(_) => texts(v, at).map(Some),
        other => split_command(&text(other, at)?).map(Some).map_err(|e| at.bad(e)),
    }
}

/// Splits a command line into words as a POSIX shell does, without
/// expanding anything: blanks separate words, `'…'` is literal, `"…"` takes
/// the escapes `\"`, `\\`, `\$` and `` \` ``, and a backslash outside quotes
/// escapes the next character. `''` is an empty word.
pub fn split_command(s: &str) -> std::result::Result<Vec<String>, String> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut in_word = false;
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            c if c.is_whitespace() => {
                if in_word {
                    words.push(std::mem::take(&mut word));
                    in_word = false;
                }
            }
            '\'' => {
                in_word = true;
                loop {
                    match chars.next() {
                        Some('\'') => break,
                        Some(c) => word.push(c),
                        None => return Err(format!("{s:?}: a ' quote is never closed")),
                    }
                }
            }
            '"' => {
                in_word = true;
                loop {
                    match chars.next() {
                        Some('"') => break,
                        Some('\\') => match chars.peek() {
                            Some(&e @ ('"' | '\\' | '$' | '`')) => {
                                word.push(e);
                                chars.next();
                            }
                            Some('\n') => {
                                chars.next();
                            }
                            _ => word.push('\\'),
                        },
                        Some(c) => word.push(c),
                        None => return Err(format!("{s:?}: a \" quote is never closed")),
                    }
                }
            }
            '\\' => {
                in_word = true;
                match chars.next() {
                    Some('\n') => {}
                    Some(c) => word.push(c),
                    None => word.push('\\'),
                }
            }
            c => {
                in_word = true;
                word.push(c);
            }
        }
    }
    if in_word {
        words.push(word);
    }
    Ok(words)
}

/// `env_file:`: a path, or a list of paths and `{path, required}`.
fn env_files(v: &Value, at: &At) -> Result<Vec<EnvFileDef>> {
    let one = |item: &Value, at: &At| -> Result<EnvFileDef> {
        let Value::Mapping(_) = item else {
            return Ok(EnvFileDef { path: text(item, at)?, required: true });
        };
        let mut file = EnvFileDef { path: String::new(), required: true };
        for (key, value) in entries(item, at)? {
            let at = &at.key(key);
            match key {
                "path" => file.path = text(value, at)?,
                "required" => file.required = opt_flag(value, at)?.unwrap_or(true),
                _ => other_key(key, at)?,
            }
        }
        if file.path.is_empty() {
            return Err(at.bad("an env_file needs its path"));
        }
        Ok(file)
    };
    match v {
        Value::Null => Ok(Vec::new()),
        Value::Sequence(items) => items.iter().enumerate().map(|(i, item)| one(item, &at.index(i))).collect(),
        other => one(other, at).map(|f| vec![f]),
    }
}

/// `ports:`: short syntax (`PortMapping::parse`'s) or `{target, published,
/// host_ip, protocol}`; a range is one mapping per port.
fn ports(v: &Value, at: &At) -> Result<Vec<PortMapping>> {
    let mut mappings = Vec::new();
    let mut seen = BTreeSet::new();
    for (i, item) in list(v, at)?.iter().enumerate() {
        let at = &at.index(i);
        let spec = match item {
            Value::Mapping(_) => long_port(item, at)?,
            other => text(other, at)?,
        };
        for mapping in PortMapping::parse(&spec).map_err(|e| at.bad(e))? {
            // Short and long syntax share Compose's normalized uniqueness
            // key, including implicit tcp and the default host address.
            let host = mapping.host_ip.unwrap_or(std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED));
            if seen.insert((host, mapping.container_port, mapping.host_port, mapping.protocol)) {
                mappings.push(mapping);
            }
        }
    }
    Ok(mappings)
}

/// The long syntax, written as the short one.
fn long_port(v: &Value, at: &At) -> Result<String> {
    let (mut target, mut published, mut host_ip, mut protocol) = (None, None, None, None);
    for (key, value) in entries(v, at)? {
        let at = &at.key(key);
        match key {
            "target" => target = opt_text(value, at)?,
            "published" => published = opt_text(value, at)?.filter(|p| !p.is_empty()),
            "host_ip" => host_ip = opt_text(value, at)?.filter(|ip| !ip.is_empty()),
            "protocol" => protocol = opt_text(value, at)?,
            _ => other_key(key, at)?,
        }
    }
    let target = target.ok_or_else(|| at.bad("a port needs its target"))?;
    let mut spec = match &host_ip {
        Some(ip) if ip.contains(':') => format!("[{ip}]:"),
        Some(ip) => format!("{ip}:"),
        None => String::new(),
    };
    match published {
        Some(p) => spec += &format!("{p}:"),
        None if host_ip.is_some() => spec.push(':'),
        None => {}
    }
    spec += &target;
    if let Some(protocol) = protocol {
        spec += &format!("/{protocol}");
    }
    Ok(spec)
}

/// A service's `volumes:`.
fn mounts(v: &Value, at: &At) -> Result<Vec<MountDef>> {
    list(v, at)?
        .iter()
        .enumerate()
        .map(|(i, item)| {
            let at = &at.index(i);
            match item {
                Value::Mapping(_) => long_mount(item, at),
                other => short_mount(&text(other, at)?, at),
            }
        })
        .collect()
}

/// `[SOURCE:]TARGET[:MODE]`: a source starting with `/`, `.` or `~` is a
/// host path, anything else a named volume's key; none, an anonymous
/// volume. Host paths are created if missing, as Compose does for this
/// syntax.
fn short_mount(spec: &str, at: &At) -> Result<MountDef> {
    let parts: Vec<&str> = spec.split(':').collect();
    if parts.iter().any(|p| p.is_empty()) {
        return Err(at.bad(format!("{spec:?}: an empty part (expected [SOURCE:]TARGET[:MODE])")));
    }
    let (source, target, mode) = match parts.as_slice() {
        [t] => (None, *t, ""),
        [s, t] => (Some(*s), *t, ""),
        [s, t, m] => (Some(*s), *t, *m),
        _ => return Err(at.bad(format!("{spec:?}: too many colons (expected [SOURCE:]TARGET[:MODE])"))),
    };
    let host_path = source.is_some_and(|s| s.starts_with(['/', '.', '~']));
    let mut m = MountDef {
        kind: if host_path { MountType::Bind } else { MountType::Volume },
        source: source.map(str::to_owned),
        target: target.to_owned(),
        create_host_path: host_path,
        ..MountDef::default()
    };
    for option in mode.split(',').filter(|o| !o.is_empty()) {
        match option {
            "ro" => m.read_only = true,
            "rw" => m.read_only = false,
            "nocopy" if m.kind == MountType::Volume => m.no_copy = true,
            "nocopy" => return Err(at.invalid(format!("{spec:?}: nocopy is for volumes, not host paths"))),
            "private" | "rprivate" => {}
            "z" | "Z" => return Err(at.invalid(format!("{spec:?}: SELinux relabelling (z, Z) isn't supported"))),
            "shared" | "rshared" | "slave" | "rslave" => {
                return Err(at.invalid(format!("{spec:?}: {option}: container mounts are always private")));
            }
            other => return Err(at.bad(format!("{spec:?}: unknown option {other:?} (ro, rw, nocopy)"))),
        }
    }
    check_target(&m.target, at)?;
    Ok(m)
}

/// `{type, source, target, read_only, volume: {nocopy}, bind:
/// {create_host_path}, tmpfs: {size}}`.
fn long_mount(v: &Value, at: &At) -> Result<MountDef> {
    let mut m = MountDef::default();
    let mut kind = None;
    // The type-specific sections given, to check them against the type.
    let mut sections: Vec<(&str, MountType)> = Vec::new();
    for (key, value) in entries(v, at)? {
        let at = &at.key(key);
        match key {
            "type" => {
                kind = Some(match text(value, at)?.as_str() {
                    "volume" => MountType::Volume,
                    "bind" => MountType::Bind,
                    "tmpfs" => MountType::Tmpfs,
                    other => {
                        return Err(at.invalid(format!("the type {other:?} isn't supported (volume, bind, tmpfs)")));
                    }
                })
            }
            "source" => m.source = opt_text(value, at)?.filter(|s| !s.is_empty()),
            "target" => m.target = text(value, at)?,
            "read_only" => m.read_only = flag(value, at)?,
            "volume" => {
                sections.push((key, MountType::Volume));
                for (k, v) in entries(value, at)? {
                    match k {
                        "nocopy" => m.no_copy = flag(v, &at.key(k))?,
                        _ => other_key(k, &at.key(k))?,
                    }
                }
            }
            "bind" => {
                sections.push((key, MountType::Bind));
                for (k, v) in entries(value, at)? {
                    match k {
                        "create_host_path" => m.create_host_path = flag(v, &at.key(k))?,
                        _ => other_key(k, &at.key(k))?,
                    }
                }
            }
            "tmpfs" => {
                sections.push((key, MountType::Tmpfs));
                for (k, v) in entries(value, at)? {
                    match k {
                        "size" => m.tmpfs_size = opt_size(v, &at.key(k))?,
                        _ => other_key(k, &at.key(k))?,
                    }
                }
            }
            _ => other_key(key, at)?,
        }
    }
    m.kind = kind.ok_or_else(|| at.bad("a mount needs its type (volume, bind or tmpfs)"))?;
    if let Some((section, _)) = sections.iter().find(|(_, k)| *k != m.kind) {
        return Err(at.invalid(format!("{section}: options are for type {section}, not {}", m.kind)));
    }
    if m.target.is_empty() {
        return Err(at.bad("a mount needs its target"));
    }
    match (m.kind, &m.source) {
        (MountType::Bind, None) => return Err(at.bad("a bind mount needs its source")),
        (MountType::Tmpfs, Some(_)) => return Err(at.bad("a tmpfs mount has no source")),
        _ => {}
    }
    check_target(&m.target, at)?;
    Ok(m)
}

/// A mount's target: a clean absolute path, not `/`.
fn check_target(target: &str, at: &At) -> Result<()> {
    if !target.starts_with('/') {
        return Err(at.bad(format!("the target {target:?} must be an absolute path")));
    }
    if target.split('/').all(|c| c.is_empty() || c == ".") {
        return Err(at.bad("can't mount over the container's root"));
    }
    if target.split('/').any(|c| c == "..") {
        return Err(at.bad(format!("the target {target:?} may not contain ..")));
    }
    Ok(())
}

/// `tmpfs:`: `TARGET[:OPTIONS]` as `--tmpfs` takes it, one or a list.
fn tmpfs(v: &Value, at: &At) -> Result<Vec<MountSpec>> {
    let parse = |s: &str, at: &At| MountSpec::parse_tmpfs(s).map_err(|e| at.bad(e));
    match v {
        Value::Null => Ok(Vec::new()),
        Value::Sequence(items) => items
            .iter()
            .enumerate()
            .map(|(i, item)| {
                let at = &at.index(i);
                parse(&text(item, at)?, at)
            })
            .collect(),
        other => Ok(vec![parse(&text(other, at)?, at)?]),
    }
}

/// A service's `networks:`: names, or a mapping of names to `{aliases,
/// ipv4_address, ipv6_address}` (or nothing).
fn service_networks(v: &Value, at: &At) -> Result<Vec<ServiceNetworkDef>> {
    let mut networks: Vec<ServiceNetworkDef> = Vec::new();
    if let Value::Sequence(items) = v {
        for (i, item) in items.iter().enumerate() {
            let at = &at.index(i);
            let key = text(item, at)?;
            if networks.iter().any(|n| n.key == key) {
                return Err(at.bad(format!("the network {key:?} is listed twice")));
            }
            networks.push(ServiceNetworkDef { key, ..ServiceNetworkDef::default() });
        }
        return Ok(networks);
    }
    for (key, def) in entries(v, at)? {
        let at = &at.key(key);
        let mut n = ServiceNetworkDef { key: key.to_owned(), ..ServiceNetworkDef::default() };
        for (k, value) in entries(def, at)? {
            let at = &at.key(k);
            match k {
                "aliases" => n.aliases = texts(value, at)?,
                "ipv4_address" => n.ipv4_address = opt_parsed(value, at, "an IPv4 address")?,
                "ipv6_address" => n.ipv6_address = opt_parsed(value, at, "an IPv6 address")?,
                _ => other_key(k, at)?,
            }
        }
        networks.push(n);
    }
    Ok(networks)
}

/// `depends_on:`: names (`service_started`), or a mapping of names to
/// `{condition, required, restart}`.
fn depends_on(v: &Value, at: &At) -> Result<Vec<DependsOnDef>> {
    let mut deps: Vec<DependsOnDef> = Vec::new();
    if let Value::Sequence(items) = v {
        for (i, item) in items.iter().enumerate() {
            let service = text(item, &at.index(i))?;
            if !deps.iter().any(|d| d.service == service) {
                deps.push(DependsOnDef { service, condition: Condition::Started, required: true });
            }
        }
        return Ok(deps);
    }
    for (service, def) in entries(v, at)? {
        let at = &at.key(service);
        let mut dep = DependsOnDef { service: service.to_owned(), condition: Condition::Started, required: true };
        for (key, value) in entries(def, at)? {
            let at = &at.key(key);
            match key {
                "condition" => {
                    dep.condition = match opt_text(value, at)?.as_deref() {
                        None | Some("service_started") => Condition::Started,
                        Some("service_healthy") => Condition::Healthy,
                        Some("service_completed_successfully") => Condition::CompletedSuccessfully,
                        Some(other) => {
                            return Err(at.invalid(format!(
                                "unknown condition {other:?} (service_started, service_healthy, \
                                 service_completed_successfully)"
                            )));
                        }
                    }
                }
                "required" => dep.required = opt_flag(value, at)?.unwrap_or(true),
                // Restarting dependents with their dependency: accepted,
                // ignored.
                "restart" => {
                    flag(value, at)?;
                }
                _ => other_key(key, at)?,
            }
        }
        deps.push(dep);
    }
    Ok(deps)
}

fn restart(v: &Value, at: &At) -> Result<Option<RestartPolicy>> {
    match v {
        Value::Null => Ok(None),
        // YAML 1.1's `no`, should a file spell it as a boolean.
        Value::Bool(false) => Ok(Some(RestartPolicy::default())),
        other => RestartPolicy::parse(&text(other, at)?).map(Some).map_err(|e| at.invalid(e)),
    }
}

/// `healthcheck:` as the daemon takes it: durations in nanoseconds, a
/// string test as `CMD-SHELL`, `disable: true` as `["NONE"]` whatever else
/// it says: a file that merges over another's `test` turns the check off
/// with `disable: true` alone, and Compose makes it `NONE` too
/// (`ToMobyHealthCheck`: `if check.Disable { test = []string{"NONE"} }`).
fn healthcheck(v: &Value, at: &At) -> Result<Option<HealthConfig>> {
    if v.is_null() {
        return Ok(None);
    }
    let mut h = HealthConfig::default();
    let mut disable = false;
    for (key, value) in entries(v, at)? {
        let at = &at.key(key);
        match key {
            "test" => h.test = health_test(value, at)?,
            "interval" => h.interval = opt_nanos(value, at)?,
            "timeout" => h.timeout = opt_nanos(value, at)?,
            "start_period" => h.start_period = opt_nanos(value, at)?,
            "start_interval" => h.start_interval = opt_nanos(value, at)?,
            "retries" => h.retries = opt_number(value, at, "a number of retries")?,
            "disable" => disable = flag(value, at)?,
            _ => other_key(key, at)?,
        }
    }
    if disable {
        return Ok(Some(HealthConfig { test: vec!["NONE".into()], ..HealthConfig::default() }));
    }
    Ok(Some(h))
}

fn health_test(v: &Value, at: &At) -> Result<Vec<String>> {
    match v {
        Value::Null => Ok(Vec::new()),
        Value::Sequence(_) => {
            let test = texts(v, at)?;
            match (test.first().map(String::as_str), test.len()) {
                (Some("NONE"), _) => Ok(vec!["NONE".into()]),
                (Some("CMD"), n) if n > 1 => Ok(test),
                (Some("CMD-SHELL"), 2) => Ok(test),
                (Some("CMD"), _) => Err(at.bad("[\"CMD\", …] needs the program to run")),
                (Some("CMD-SHELL"), _) => Err(at.bad("[\"CMD-SHELL\", …] takes one command line")),
                (Some(other), _) => Err(at.bad(format!("starts with {other:?}: expected CMD, CMD-SHELL or NONE"))),
                (None, _) => Err(at.bad("the test is empty")),
            }
        }
        other => match text(other, at)? {
            s if s.trim().is_empty() => Err(at.bad("the test is empty")),
            s => Ok(vec!["CMD-SHELL".into(), s]),
        },
    }
}

fn deploy(v: &Value, at: &At) -> Result<DeployDef> {
    let mut d = DeployDef::default();
    for (key, value) in entries(v, at)? {
        let at = &at.key(key);
        match key {
            "replicas" => d.replicas = opt_number(value, at, "a container count")?,
            "resources" => {
                for (key, value) in entries(value, at)? {
                    let at = &at.key(key);
                    match key {
                        "limits" => {
                            for (key, value) in entries(value, at)? {
                                let at = &at.key(key);
                                match key {
                                    "cpus" => d.cpus = opt_cpus(value, at)?,
                                    "memory" => d.memory = opt_size(value, at)?.filter(|&bytes| bytes > 0),
                                    "pids" => d.pids = opt_number(value, at, "a process count")?,
                                    _ => other_key(key, at)?,
                                }
                            }
                        }
                        _ => other_key(key, at)?,
                    }
                }
            }
            _ => other_key(key, at)?,
        }
    }
    Ok(d)
}

fn pull_policy(v: &Value, at: &At) -> Result<Option<PullPolicyDef>> {
    Ok(match opt_text(v, at)?.as_deref() {
        None => None,
        Some("always") => Some(PullPolicyDef::Always),
        Some("missing" | "if_not_present") => Some(PullPolicyDef::Missing),
        Some("never") => Some(PullPolicyDef::Never),
        Some("build") => Some(PullPolicyDef::Build),
        Some(other) => {
            return Err(
                at.invalid(format!("the pull policy {other:?} isn't supported (always, missing, never, build)"))
            );
        }
    })
}

/// `extra_hosts:`: `host:ip` or `host=ip` items, or a mapping of hosts to an
/// address (or a list of them); as `name:ip`.
fn extra_hosts(v: &Value, at: &At) -> Result<Vec<String>> {
    let host = |s: &str, at: &At| -> Result<String> {
        let (name, ip) = parse_extra_host(s).map_err(|e| at.bad(e))?;
        Ok(format!("{name}:{ip}"))
    };
    let mut hosts = Vec::new();
    match v {
        Value::Sequence(_) | Value::Null => {
            for (i, item) in list(v, at)?.iter().enumerate() {
                let at = &at.index(i);
                hosts.push(host(&text(item, at)?, at)?);
            }
        }
        _ => {
            for (name, ips) in entries(v, at)? {
                let at = &at.key(name);
                for ip in text_or_texts(ips, at)? {
                    hosts.push(host(&format!("{name}={ip}"), at)?);
                }
            }
        }
    }
    Ok(hosts)
}

fn network(v: &Value, at: &At) -> Result<NetworkDef> {
    let mut n = NetworkDef::default();
    let mut legacy_name = None;
    // What an external network can't have.
    let mut settings: Vec<&str> = Vec::new();
    for (key, value) in entries(v, at)? {
        let at = &at.key(key);
        match key {
            "driver" => {
                settings.push(key);
                match opt_text(value, at)?.as_deref() {
                    None | Some("bridge") => {}
                    Some(other) => {
                        return Err(at.invalid(format!("the driver {other:?} isn't supported (only bridge)")));
                    }
                }
            }
            "internal" => {
                settings.push(key);
                n.internal = flag(value, at)?;
            }
            "enable_ipv6" => {
                settings.push(key);
                n.enable_ipv6 = flag(value, at)?;
            }
            "ipam" => {
                settings.push(key);
                n.subnets = ipam(value, at)?;
            }
            "labels" => {
                settings.push(key);
                n.labels = labels(value, at)?;
            }
            "external" => (n.external, legacy_name) = external(value, at)?,
            "name" => n.name = opt_text(value, at)?.filter(|s| !s.is_empty()),
            _ => other_key(key, at)?,
        }
    }
    resolve_external_name(&mut n.name, legacy_name, at)?;
    if n.external
        && let Some(setting) = settings.first()
    {
        return Err(at.invalid(format!("an external network takes no {setting} (it isn't the project's to set up)")));
    }
    Ok(n)
}

fn ipam(v: &Value, at: &At) -> Result<Vec<String>> {
    let mut subnets = Vec::new();
    for (key, value) in entries(v, at)? {
        let at = &at.key(key);
        match key {
            "driver" => match opt_text(value, at)?.as_deref() {
                None | Some("default") => {}
                Some(other) => return Err(at.invalid(format!("the IPAM driver {other:?} isn't supported"))),
            },
            "config" => {
                for (i, item) in list(value, at)?.iter().enumerate() {
                    let at = &at.index(i);
                    for (key, value) in entries(item, at)? {
                        let at = &at.key(key);
                        match key {
                            "subnet" => subnets.extend(opt_text(value, at)?),
                            _ => other_key(key, at)?,
                        }
                    }
                }
            }
            _ => other_key(key, at)?,
        }
    }
    Ok(subnets)
}

fn volume(v: &Value, at: &At) -> Result<VolumeDef> {
    let mut d = VolumeDef::default();
    let mut legacy_name = None;
    let mut settings: Vec<&str> = Vec::new();
    for (key, value) in entries(v, at)? {
        let at = &at.key(key);
        match key {
            "driver" => {
                settings.push(key);
                match opt_text(value, at)?.as_deref() {
                    None | Some("local") => {}
                    Some(other) => return Err(at.invalid(format!("the driver {other:?} isn't supported (only local)"))),
                }
            }
            "labels" => {
                settings.push(key);
                d.labels = labels(value, at)?;
            }
            "external" => (d.external, legacy_name) = external(value, at)?,
            "name" => d.name = opt_text(value, at)?.filter(|s| !s.is_empty()),
            _ => other_key(key, at)?,
        }
    }
    resolve_external_name(&mut d.name, legacy_name, at)?;
    if d.external
        && let Some(setting) = settings.first()
    {
        return Err(at.invalid(format!("an external volume takes no {setting} (it isn't the project's to set up)")));
    }
    Ok(d)
}

/// `external: true`, or the legacy `external: {name: …}`.
fn external(v: &Value, at: &At) -> Result<(bool, Option<String>)> {
    let Value::Mapping(_) = v else { return Ok((flag(v, at)?, None)) };
    let mut name = None;
    for (key, value) in entries(v, at)? {
        match key {
            "name" => name = opt_text(value, &at.key(key))?,
            _ => other_key(key, &at.key(key))?,
        }
    }
    Ok((true, name))
}

fn resolve_external_name(name: &mut Option<String>, legacy: Option<String>, at: &At) -> Result<()> {
    if let Some(legacy) = legacy {
        if name.as_ref().is_some_and(|n| *n != legacy) {
            return Err(at.invalid("external.name and name name different things"));
        }
        *name = Some(legacy);
    }
    Ok(())
}

/// A key the settings mapping at `at`'s parent doesn't have: an extension
/// (`x-…`, ignored) or something unsupported.
fn other_key(key: &str, at: &At) -> Result<()> {
    if key.starts_with("x-") { Ok(()) } else { Err(Error::Invalid(format!("{at} is not supported"))) }
}

/// Services, networks and volumes are named `[a-zA-Z0-9._-]+`, as in the
/// Compose Specification.
fn check_name(name: &str, what: &str, at: &At) -> Result<()> {
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')) {
        return Err(at.bad(format!("{name:?} is not a valid {what} name (letters, digits, '.', '_' and '-')")));
    }
    Ok(())
}

/// Where a value is in the document, for errors: `services.web.ports[1]`;
/// and, shared by every place derived from it, where to put the warnings
/// reading finds on the way.
#[derive(Debug, Clone, Default)]
struct At {
    path: String,
    warnings: Rc<RefCell<Vec<String>>>,
}

impl At {
    fn key(&self, key: &str) -> At {
        let path = if self.path.is_empty() { key.to_owned() } else { format!("{}.{key}", self.path) };
        At { path, warnings: self.warnings.clone() }
    }

    fn index(&self, i: usize) -> At {
        At { path: format!("{}[{i}]", self.path), warnings: self.warnings.clone() }
    }

    /// Notes something accepted that Compose would too, but would say so.
    fn warn(&self, message: impl fmt::Display) {
        self.warnings.borrow_mut().push(format!("{self}: {message}"));
    }

    fn take_warnings(&self) -> Vec<String> {
        std::mem::take(&mut self.warnings.borrow_mut())
    }

    /// The value here isn't what the file format allows.
    fn bad(&self, why: impl fmt::Display) -> Error {
        Error::Parse(format!("{self}: {why}"))
    }

    /// The value here asks for something Rustlets doesn't do.
    fn invalid(&self, why: impl fmt::Display) -> Error {
        Error::Invalid(format!("{self}: {why}"))
    }
}

impl fmt::Display for At {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(if self.path.is_empty() { "the file" } else { &self.path })
    }
}

/// What kind of value `v` is, for errors.
fn kind(v: &Value) -> String {
    match v {
        Value::Null => "nothing".into(),
        Value::Bool(b) => format!("the boolean {b}"),
        Value::Number(n) => format!("the number {n}"),
        Value::String(s) => format!("the string {s:?}"),
        Value::Sequence(_) => "a list".into(),
        Value::Mapping(_) => "a mapping".into(),
        Value::Tagged(t) => format!("a value tagged {}", t.tag),
    }
}

/// A mapping's entries (nothing is an empty mapping), keys as strings.
fn entries<'a>(v: &'a Value, at: &At) -> Result<Vec<(&'a str, &'a Value)>> {
    match v {
        Value::Mapping(m) => m
            .iter()
            .map(|(k, v)| match k {
                Value::String(k) => Ok((k.as_str(), v)),
                other => Err(at.bad(format!("a key must be a string, not {}", kind(other)))),
            })
            .collect(),
        Value::Null => Ok(Vec::new()),
        other => Err(at.bad(format!("expected a mapping, found {}", kind(other)))),
    }
}

/// A list's items (nothing is an empty list).
fn list<'a>(v: &'a Value, at: &At) -> Result<&'a [Value]> {
    match v {
        Value::Sequence(items) => Ok(items),
        Value::Null => Ok(&[]),
        other => Err(at.bad(format!("expected a list, found {}", kind(other)))),
    }
}

/// A scalar as text: numbers and booleans written out, as Compose reads
/// fields that are strings.
fn text(v: &Value, at: &At) -> Result<String> {
    match v {
        Value::String(s) => Ok(s.clone()),
        Value::Number(n) => Ok(n.to_string()),
        Value::Bool(b) => Ok(b.to_string()),
        other => Err(at.bad(format!("expected a string, found {}", kind(other)))),
    }
}

fn opt_text(v: &Value, at: &At) -> Result<Option<String>> {
    if v.is_null() { Ok(None) } else { text(v, at).map(Some) }
}

fn texts(v: &Value, at: &At) -> Result<Vec<String>> {
    list(v, at)?.iter().enumerate().map(|(i, item)| text(item, &at.index(i))).collect()
}

/// One string, or a list of them.
fn text_or_texts(v: &Value, at: &At) -> Result<Vec<String>> {
    match v {
        Value::Sequence(_) | Value::Null => texts(v, at),
        other => Ok(vec![text(other, at)?]),
    }
}

/// `KEY=VALUE` items (a bare `KEY` without a value), or a mapping (a key
/// with nothing has no value).
fn key_values(v: &Value, at: &At) -> Result<Vec<(String, Option<String>)>> {
    match v {
        Value::Sequence(items) => items
            .iter()
            .enumerate()
            .map(|(i, item)| {
                let at = &at.index(i);
                let s = text(item, at)?;
                let (key, value) = match s.split_once('=') {
                    Some((k, v)) => (k.to_owned(), Some(v.to_owned())),
                    None => (s, None),
                };
                if key.is_empty() {
                    return Err(at.bad("nothing before the ="));
                }
                Ok((key, value))
            })
            .collect(),
        _ => entries(v, at)?.into_iter().map(|(k, value)| Ok((k.to_owned(), opt_text(value, &at.key(k))?))).collect(),
    }
}

/// Labels: [`key_values`] with an empty value for a bare key.
fn labels(v: &Value, at: &At) -> Result<BTreeMap<String, String>> {
    Ok(key_values(v, at)?.into_iter().map(|(k, v)| (k, v.unwrap_or_default())).collect())
}

/// A boolean (`true`, `false`, or those words as strings; `yes`, `no`, `on`,
/// `off`, `y` and `n` too, with a warning that YAML 1.2 wants `true` or
/// `false`, as compose-go's `toBoolean` has it); nothing is false.
fn flag(v: &Value, at: &At) -> Result<bool> {
    Ok(opt_flag(v, at)?.unwrap_or(false))
}

fn opt_flag(v: &Value, at: &At) -> Result<Option<bool>> {
    match v {
        Value::Null => Ok(None),
        Value::Bool(b) => Ok(Some(*b)),
        Value::String(s) => match s.to_ascii_lowercase().as_str() {
            "true" => Ok(Some(true)),
            "false" => Ok(Some(false)),
            "y" | "yes" | "on" => {
                at.warn(format!("{s:?} for boolean is not supported by YAML 1.2, please use `true`"));
                Ok(Some(true))
            }
            "n" | "no" | "off" => {
                at.warn(format!("{s:?} for boolean is not supported by YAML 1.2, please use `false`"));
                Ok(Some(false))
            }
            _ => Err(at.bad(format!("expected true or false, found the string {s:?}"))),
        },
        other => Err(at.bad(format!("expected true or false, found {}", kind(other)))),
    }
}

/// A number, or a string of one.
fn opt_number<T: FromStr>(v: &Value, at: &At, what: &str) -> Result<Option<T>> {
    let s = match v {
        Value::Null => return Ok(None),
        Value::Number(n) => n.to_string(),
        Value::String(s) => s.trim().to_owned(),
        other => return Err(at.bad(format!("expected {what}, found {}", kind(other)))),
    };
    s.parse().map(Some).map_err(|_| at.bad(format!("{s:?} is not {what}")))
}

fn opt_parsed<T: FromStr>(v: &Value, at: &At, what: &str) -> Result<Option<T>> {
    match opt_text(v, at)? {
        None => Ok(None),
        Some(s) => s.trim().parse().map(Some).map_err(|_| at.bad(format!("{s:?} is not {what}"))),
    }
}

/// `cpus`: a positive number of CPUs; 0 is no limit.
fn opt_cpus(v: &Value, at: &At) -> Result<Option<f64>> {
    match opt_number::<f64>(v, at, "a number of CPUs")? {
        Some(c) if !c.is_finite() || c < 0.0 => Err(at.bad(format!("{c} is not a number of CPUs"))),
        other => Ok(other.filter(|&c| c > 0.0)),
    }
}

/// A Go duration (`1m30s`).
fn opt_duration(v: &Value, at: &At) -> Result<Option<Duration>> {
    match opt_text(v, at)? {
        None => Ok(None),
        Some(s) => rustlet_build::config::parse_duration(&s).map(Some).map_err(|e| at.bad(e)),
    }
}

/// A Go duration, in nanoseconds (the daemon's unit for healthchecks).
fn opt_nanos(v: &Value, at: &At) -> Result<Option<u64>> {
    // `parse_duration` refuses what doesn't fit in u64 nanoseconds.
    Ok(opt_duration(v, at)?.map(|d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX)))
}

/// A size: bytes, or with a unit (`512m`).
fn opt_size(v: &Value, at: &At) -> Result<Option<u64>> {
    match v {
        Value::Null => Ok(None),
        Value::Number(n) => n.as_u64().map(Some).ok_or_else(|| at.bad(format!("{n} is not a size in bytes"))),
        other => parse_size(&text(other, at)?).map(Some).map_err(|e| at.bad(e)),
    }
}

/// `512m`, `1g`, `1.5GB`, `64k`, `100000`: bytes, as Docker reads sizes (`k`
/// is 1024; `b`, `kb`, `kib` alike).
pub fn parse_size(s: &str) -> std::result::Result<u64, String> {
    let bad = || format!("{s:?} is not a size (examples: 512m, 1g, 1048576)");
    let lower = s.trim().to_ascii_lowercase();
    let split = lower.find(|c: char| !(c.is_ascii_digit() || c == '.')).unwrap_or(lower.len());
    let (number, unit) = lower.split_at(split);
    let shift = match unit.trim() {
        "" | "b" => 0,
        "k" | "kb" | "kib" => 10,
        "m" | "mb" | "mib" => 20,
        "g" | "gb" | "gib" => 30,
        "t" | "tb" | "tib" => 40,
        _ => return Err(bad()),
    };
    if number.contains('.') {
        let n: f64 = number.parse().map_err(|_| bad())?;
        let bytes = n * (1u64 << shift) as f64;
        if !bytes.is_finite() || bytes >= u64::MAX as f64 {
            return Err(bad());
        }
        return Ok(bytes as u64);
    }
    let n: u64 = number.parse().map_err(|_| bad())?;
    n.checked_mul(1 << shift).ok_or_else(bad)
}

#[cfg(test)]
mod tests {
    use rustlet_spec::container::RestartPolicyName;
    use rustlet_spec::network::Protocol;

    use super::*;

    fn yaml(text: &str) -> Value {
        serde_yaml_ng::from_str(text).unwrap()
    }

    fn file(text: &str) -> ComposeFile {
        parse(&yaml(text)).unwrap()
    }

    fn one(text: &str) -> ServiceDef {
        file(&format!("services:\n  web:\n{}", indent(text))).services.remove(0)
    }

    fn indent(text: &str) -> String {
        text.lines().map(|l| format!("    {l}\n")).collect()
    }

    fn error(text: &str) -> String {
        parse(&yaml(text)).unwrap_err().to_string()
    }

    fn service_error(text: &str) -> String {
        error(&format!("services:\n  web:\n{}", indent(text)))
    }

    #[test]
    fn every_scalar_key_is_read() {
        let s = one("image: nginx:1.27\nworking_dir: /srv\nuser: 1000\nhostname: box\ncontainer_name: the-web\n\
             tty: true\nstdin_open: \"true\"\nread_only: TRUE\nprivileged: false\nstop_signal: SIGINT\n\
             stop_grace_period: 1m30s\nmem_limit: 512m\ncpus: \"1.5\"\npids_limit: -1\nscale: 2\n\
             pull_policy: if_not_present\nnetwork_mode: host\nrestart: on-failure:3\n");
        assert_eq!(s.image.as_deref(), Some("nginx:1.27"));
        assert_eq!(s.working_dir.as_deref(), Some("/srv"));
        assert_eq!(s.user.as_deref(), Some("1000"), "a number where a string belongs");
        assert_eq!((s.hostname.as_deref(), s.container_name.as_deref()), (Some("box"), Some("the-web")));
        assert!(s.tty && s.stdin_open && s.read_only && !s.privileged);
        assert_eq!(s.stop_signal.as_deref(), Some("SIGINT"));
        assert_eq!(s.stop_grace_period, Some(Duration::from_secs(90)));
        assert_eq!((s.mem_limit, s.cpus, s.pids_limit, s.scale), (Some(512 << 20), Some(1.5), Some(-1), Some(2)));
        assert_eq!(s.pull_policy, Some(PullPolicyDef::Missing));
        assert_eq!(s.network_mode.as_deref(), Some("host"));
        assert_eq!(s.restart, Some(RestartPolicy { name: RestartPolicyName::OnFailure, max_retries: 3 }));
    }

    #[test]
    fn every_list_key_is_read() {
        let s = one("cap_add: [NET_ADMIN]\ncap_drop: [ALL]\nsecurity_opt: [no-new-privileges]\ndevices: [/dev/fuse]\n\
             dns: 1.1.1.1\ndns_search: [corp.example]\ndns_opt: [ndots:2]\nprofiles: [debug]\nexpose: [3000, \"8000/udp\"]\n");
        assert_eq!((s.cap_add, s.cap_drop), (vec!["NET_ADMIN".to_owned()], vec!["ALL".to_owned()]));
        assert_eq!((s.security_opt, s.devices), (vec!["no-new-privileges".to_owned()], vec!["/dev/fuse".to_owned()]));
        assert_eq!(s.dns, ["1.1.1.1"], "one string is a list of one");
        assert_eq!((s.dns_search, s.dns_opt), (vec!["corp.example".to_owned()], vec!["ndots:2".to_owned()]));
        assert_eq!((s.profiles, s.expose), (vec!["debug".to_owned()], vec!["3000".to_owned(), "8000/udp".to_owned()]));
    }

    #[test]
    fn empty_values_count_as_not_given() {
        let s = one("image:\nbuild:\ncommand:\nhealthcheck:\nenvironment:\nports:\ntty:\nrestart:\n");
        assert_eq!(s, ServiceDef { name: "web".into(), ..ServiceDef::default() });
        assert_eq!(one("image: \"\"\n").image, None);
    }

    #[test]
    fn commands_are_split_like_a_shell_or_taken_as_lists() {
        let s = one("command: sh -c 'echo \"$$HOME\" && sleep 1' \"a b\" c\\ d ''\nentrypoint: [/bin/tini, --]\n");
        assert_eq!(s.command.unwrap(), ["sh", "-c", "echo \"$$HOME\" && sleep 1", "a b", "c d", ""]);
        assert_eq!(s.entrypoint.unwrap(), ["/bin/tini", "--"]);
        assert_eq!(one("entrypoint: \"\"\n").entrypoint, Some(vec![]), "empty: the image's entrypoint cleared");
        assert_eq!(split_command("  a\t b\n").unwrap(), ["a", "b"]);
        assert_eq!(split_command(r#""a\"b\\c\$d\x""#).unwrap(), [r#"a"b\c$d\x"#]);
        assert!(split_command("echo 'open").is_err() && split_command("echo \"open").is_err());
        assert!(service_error("command: \"sh -c 'x\"\n").starts_with("services.web.command: "));
    }

    #[test]
    fn environment_and_labels_take_lists_and_mappings() {
        let s = one("environment:\n  - A=1\n  - B=x=y\n  - BARE\n  - EMPTY=\nlabels:\n  - tier=front\n  - solo\n");
        let env = |pairs: &[(&str, Option<&str>)]| -> Vec<(String, Option<String>)> {
            pairs.iter().map(|(k, v)| (k.to_string(), v.map(str::to_owned))).collect()
        };
        assert_eq!(s.environment, env(&[("A", Some("1")), ("B", Some("x=y")), ("BARE", None), ("EMPTY", Some(""))]));
        assert_eq!(s.labels, [("solo".to_owned(), String::new()), ("tier".to_owned(), "front".to_owned())].into());
        let s = one("environment:\n  A: 1\n  B: true\n  C:\n  x-not-an-extension: v\nlabels:\n  a.b: \"\"\n");
        assert_eq!(
            s.environment,
            env(&[("A", Some("1")), ("B", Some("true")), ("C", None), ("x-not-an-extension", Some("v"))])
        );
        assert_eq!(s.labels["a.b"], "");
        assert!(service_error("environment: [\"=x\"]\n").starts_with("services.web.environment[0]: "));
    }

    #[test]
    fn env_files_are_paths_or_path_and_required() {
        let s = one("env_file: .env.web\n");
        assert_eq!(s.env_file, [EnvFileDef { path: ".env.web".into(), required: true }]);
        let s = one("env_file:\n  - a.env\n  - path: b.env\n    required: false\n");
        assert_eq!(
            s.env_file,
            [EnvFileDef { path: "a.env".into(), required: true }, EnvFileDef { path: "b.env".into(), required: false }]
        );
        assert_eq!(
            service_error("env_file: [{required: true}]\n"),
            "services.web.env_file[0]: an env_file needs its path"
        );
    }

    /// YAML lines, joined.
    fn lines(lines: &[&str]) -> String {
        lines.iter().map(|l| format!("{l}\n")).collect()
    }

    #[test]
    fn ports_in_short_and_long_syntax() {
        let s = one(&lines(&[
            "ports:",
            "  - 80",
            "  - \"8080:80\"",
            "  - 127.0.0.1:9000-9001:9000-9001/udp",
            "  - \"[::1]:5353:53/udp\"",
            "  - target: 443",
            "    published: \"8443\"",
            "    host_ip: 127.0.0.1",
            "    protocol: tcp",
            "  - target: 22",
            "  - target: 53",
            "    host_ip: \"::1\"",
            "    protocol: udp",
        ]));
        let shown: Vec<String> = s.ports.iter().map(|p| p.to_string()).collect();
        assert_eq!(
            shown,
            [
                "80/tcp",
                "8080:80/tcp",
                "127.0.0.1:9000:9000/udp",
                "127.0.0.1:9001:9001/udp",
                "[::1]:5353:53/udp",
                "127.0.0.1:8443:443/tcp",
                "22/tcp",
                "[::1]::53/udp",
            ]
        );
        assert_eq!(s.ports[5].protocol, Protocol::Tcp);
        let e = service_error("ports: [\"80\", \"x:80\"]\n");
        assert!(e.starts_with("services.web.ports[1]: "), "{e}");
        assert_eq!(service_error("ports: [{published: 80}]\n"), "services.web.ports[0]: a port needs its target");
        assert_eq!(service_error("ports: [{target: 80, mode: host}]\n"), "services.web.ports[0].mode is not supported");
    }

    #[test]
    fn volumes_in_short_syntax() {
        let s = one(&lines(&[
            "volumes:",
            "  - data:/var/lib/data",
            "  - ./site:/www:ro",
            "  - /etc/hosts:/etc/h:ro,rprivate",
            "  - ~/cache:/cache",
            "  - /anon",
            "  - db:/db:nocopy",
        ]));
        let m = &s.volumes;
        assert_eq!(
            (m[0].kind, m[0].source.as_deref(), m[0].target.as_str()),
            (MountType::Volume, Some("data"), "/var/lib/data")
        );
        assert!(!m[0].create_host_path && !m[0].read_only);
        assert_eq!((m[1].kind, m[1].source.as_deref()), (MountType::Bind, Some("./site")));
        assert!(m[1].read_only && m[1].create_host_path, "short-syntax host paths are created");
        assert_eq!((m[2].kind, m[2].read_only), (MountType::Bind, true));
        assert_eq!((m[3].kind, m[3].source.as_deref()), (MountType::Bind, Some("~/cache")));
        assert_eq!((m[4].kind, m[4].source.as_deref(), m[4].target.as_str()), (MountType::Volume, None, "/anon"));
        assert!(m[5].no_copy);
        for (bad, start) in [
            ("data:rel", "services.web.volumes[0]: the target \"rel\" must be an absolute path"),
            ("/data:ro", "services.web.volumes[0]: the target \"ro\""),
            ("a:b:c:d", "services.web.volumes[0]: \"a:b:c:d\": too many colons"),
            ("a::/b", "services.web.volumes[0]: \"a::/b\": an empty part"),
            ("/h:/c:nocopy", "services.web.volumes[0]: \"/h:/c:nocopy\": nocopy is for volumes"),
            ("/h:/c:z", "services.web.volumes[0]: \"/h:/c:z\": SELinux relabelling"),
            ("/h:/c:shared", "services.web.volumes[0]: \"/h:/c:shared\": shared: container mounts are always private"),
            ("/h:/c:wat", "services.web.volumes[0]: \"/h:/c:wat\": unknown option \"wat\""),
            ("data:/", "services.web.volumes[0]: can't mount over the container's root"),
            ("data:/a/../b", "services.web.volumes[0]: the target \"/a/../b\" may not contain .."),
        ] {
            let e = service_error(&format!("volumes: [\"{bad}\"]\n"));
            assert!(e.starts_with(start), "{bad}: {e}");
        }
    }

    #[test]
    fn volumes_in_long_syntax() {
        let s = one(&lines(&[
            "volumes:",
            "  - type: volume",
            "    source: data",
            "    target: /data",
            "    read_only: true",
            "    volume:",
            "      nocopy: true",
            "  - type: bind",
            "    source: ./src",
            "    target: /src",
            "    bind:",
            "      create_host_path: true",
            "  - type: tmpfs",
            "    target: /run",
            "    tmpfs:",
            "      size: 64m",
            "  - type: volume",
            "    target: /anon",
            "  - type: bind",
            "    source: /etc",
            "    target: /etc2",
        ]));
        let m = &s.volumes;
        assert_eq!((m[0].kind, m[0].source.as_deref()), (MountType::Volume, Some("data")));
        assert!(m[0].read_only && m[0].no_copy);
        assert!(m[1].create_host_path && m[1].kind == MountType::Bind);
        assert_eq!((m[2].kind, m[2].tmpfs_size), (MountType::Tmpfs, Some(64 << 20)));
        assert_eq!((m[3].kind, m[3].source.as_deref()), (MountType::Volume, None));
        assert!(!m[4].create_host_path, "long-syntax binds need their source");
        for (bad, expected) in [
            ("{source: a, target: /a}", "services.web.volumes[0]: a mount needs its type (volume, bind or tmpfs)"),
            ("{type: npipe, target: /a}", "services.web.volumes[0].type: the type \"npipe\" isn't supported"),
            ("{type: bind, target: /a}", "services.web.volumes[0]: a bind mount needs its source"),
            ("{type: tmpfs, source: x, target: /a}", "services.web.volumes[0]: a tmpfs mount has no source"),
            ("{type: volume, source: x}", "services.web.volumes[0]: a mount needs its target"),
            (
                "{type: bind, source: /x, target: /a, volume: {nocopy: true}}",
                "services.web.volumes[0]: volume: options",
            ),
            ("{type: volume, target: /a, consistency: cached}", "services.web.volumes[0].consistency is not supported"),
            (
                "{type: bind, source: /x, target: /a, bind: {propagation: shared}}",
                "services.web.volumes[0].bind.propagation is not supported",
            ),
        ] {
            let e = service_error(&format!("volumes: [{bad}]\n"));
            assert!(e.starts_with(expected), "{bad}: {e}");
        }
    }

    #[test]
    fn tmpfs_takes_a_string_or_a_list() {
        assert_eq!(one("tmpfs: /run\n").tmpfs[0].target, "/run");
        let s = one("tmpfs:\n  - /tmp:size=1m,mode=1777\n  - /run\n");
        assert_eq!((s.tmpfs[0].tmpfs_size, s.tmpfs[0].tmpfs_mode, s.tmpfs.len()), (Some(1 << 20), Some(0o1777), 2));
        assert!(service_error("tmpfs: [/run, \"/x:bogus\"]\n").starts_with("services.web.tmpfs[1]: "));
    }

    #[test]
    fn service_networks_as_names_or_settings() {
        let s = one("networks: [front, back]\n");
        assert_eq!(s.networks.iter().map(|n| n.key.as_str()).collect::<Vec<_>>(), ["front", "back"]);
        let s = one(
            "networks:\n  back:\n    aliases: [api, www]\n    ipv4_address: 10.89.5.5\n    ipv6_address: fd00::5\n  front:\n",
        );
        assert_eq!(s.networks[0].key, "back", "the file's order");
        assert_eq!(s.networks[0].aliases, ["api", "www"]);
        assert_eq!(s.networks[0].ipv4_address, Some(Ipv4Addr::new(10, 89, 5, 5)));
        assert_eq!(s.networks[0].ipv6_address, Some("fd00::5".parse().unwrap()));
        assert_eq!(s.networks[1], ServiceNetworkDef { key: "front".into(), ..ServiceNetworkDef::default() });
        assert_eq!(service_error("networks: [a, a]\n"), "services.web.networks[1]: the network \"a\" is listed twice");
        let e = service_error("networks:\n  a:\n    ipv4_address: 10.0.0.300\n");
        assert_eq!(e, "services.web.networks.a.ipv4_address: \"10.0.0.300\" is not an IPv4 address");
        assert_eq!(
            service_error("networks:\n  a:\n    priority: 5\n"),
            "services.web.networks.a.priority is not supported"
        );
    }

    #[test]
    fn depends_on_short_and_long() {
        let s = one("depends_on: [db, cache, db]\n");
        assert_eq!(s.depends_on.len(), 2);
        assert!(s.depends_on.iter().all(|d| d.condition == Condition::Started && d.required));
        let s = one(
            "depends_on:\n  db:\n    condition: service_healthy\n    restart: true\n  migrate:\n    condition: service_completed_successfully\n  cache:\n    required: false\n",
        );
        assert_eq!(
            s.depends_on,
            [
                DependsOnDef { service: "db".into(), condition: Condition::Healthy, required: true },
                DependsOnDef { service: "migrate".into(), condition: Condition::CompletedSuccessfully, required: true },
                DependsOnDef { service: "cache".into(), condition: Condition::Started, required: false },
            ]
        );
        let e = service_error("depends_on:\n  db:\n    condition: service_ready\n");
        assert!(e.starts_with("services.web.depends_on.db.condition: unknown condition \"service_ready\""), "{e}");
    }

    #[test]
    fn healthchecks_become_the_daemons() {
        let h = one(
            "healthcheck:\n  test: [\"CMD\", \"redis-cli\", \"ping\"]\n  interval: 5s\n  timeout: 1s\n  start_period: 1m\n  start_interval: 500ms\n  retries: 10\n",
        )
        .healthcheck
        .unwrap();
        assert_eq!(h.test, ["CMD", "redis-cli", "ping"]);
        assert_eq!(
            (h.interval, h.timeout, h.start_period, h.start_interval, h.retries),
            (Some(5_000_000_000), Some(1_000_000_000), Some(60_000_000_000), Some(500_000_000), Some(10))
        );
        assert_eq!(
            one("healthcheck:\n  test: curl -f http://localhost\n").healthcheck.unwrap().test,
            ["CMD-SHELL", "curl -f http://localhost"]
        );
        assert_eq!(
            one("healthcheck:\n  test: [\"CMD-SHELL\", \"exit 0\"]\n").healthcheck.unwrap().test,
            ["CMD-SHELL", "exit 0"]
        );
        assert!(one("healthcheck:\n  disable: true\n").healthcheck.unwrap().is_none());
        // `disable: true` wins over a test that another file merged in (compose's
        // `ToMobyHealthCheck`), and `disable: false` leaves the check as it is.
        assert!(
            one("healthcheck:\n  disable: true\n  test: [CMD, x]\n  interval: 5s\n").healthcheck.unwrap().is_none()
        );
        assert_eq!(one("healthcheck:\n  disable: false\n  test: [CMD, x]\n").healthcheck.unwrap().test, ["CMD", "x"]);
        assert!(one("healthcheck:\n  test: [NONE]\n").healthcheck.unwrap().is_none());
        let options_only = one("healthcheck:\n  interval: 2s\n").healthcheck.unwrap();
        assert!(options_only.test.is_empty(), "the image's test, with these options");
        for (bad, expected) in [
            ("test: [CMD]", "services.web.healthcheck.test: [\"CMD\", …] needs the program to run"),
            ("test: [CMD-SHELL, a, b]", "services.web.healthcheck.test: [\"CMD-SHELL\", …] takes one command line"),
            ("test: [RUN, x]", "services.web.healthcheck.test: starts with \"RUN\": expected CMD, CMD-SHELL or NONE"),
            ("test: []", "services.web.healthcheck.test: the test is empty"),
            ("interval: 10", "services.web.healthcheck.interval: invalid duration \"10\""),
            ("retries: many", "services.web.healthcheck.retries: \"many\" is not a number of retries"),
        ] {
            let e = service_error(&format!("healthcheck:\n  {bad}\n"));
            assert!(e.starts_with(expected), "{bad}: {e}");
        }
    }

    #[test]
    fn build_short_and_long() {
        assert_eq!(one("build: ./app\n").build.unwrap(), BuildDef { context: "./app".into(), ..BuildDef::default() });
        let b = one(
            "build:\n  dockerfile: Containerfile.dev\n  args:\n    - VERSION=1\n    - FROM_ENV\n  target: dev\n  labels: {a: b}\n  network: host\n  no_cache: true\n  x-note: hi\n",
        )
        .build
        .unwrap();
        assert_eq!(b.context, ".", "the default context");
        assert_eq!(b.dockerfile.as_deref(), Some("Containerfile.dev"));
        assert_eq!(b.args, [("VERSION".to_owned(), Some("1".to_owned())), ("FROM_ENV".to_owned(), None)]);
        assert_eq!((b.target.as_deref(), b.network.as_deref(), b.no_cache), (Some("dev"), Some("host"), true));
        assert_eq!(b.labels["a"], "b");
        let e = service_error("build: https://github.com/o/r.git\n");
        assert!(e.starts_with("services.web.build: the context \"https://github.com/o/r.git\" is remote"), "{e}");
        assert_eq!(service_error("build:\n  secrets: [x]\n"), "services.web.build.secrets is not supported");
    }

    #[test]
    fn deploy_scale_and_limits() {
        let s = one(
            "deploy:\n  replicas: \"3\"\n  resources:\n    limits:\n      cpus: '0.5'\n      memory: 1g\n      pids: 100\n",
        );
        assert_eq!(s.deploy, DeployDef { replicas: Some(3), cpus: Some(0.5), memory: Some(1 << 30), pids: Some(100) });
        assert_eq!(one("cpus: 0\n").cpus, None, "0: no limit");
        assert_eq!(
            service_error("deploy:\n  resources:\n    reservations:\n      memory: 1g\n"),
            "services.web.deploy.resources.reservations is not supported"
        );
        assert_eq!(service_error("scale: -1\n"), "services.web.scale: \"-1\" is not a container count");
        assert_eq!(service_error("cpus: -2\n"), "services.web.cpus: -2 is not a number of CPUs");
    }

    #[test]
    fn extra_hosts_as_list_or_mapping() {
        let s = one("extra_hosts:\n  - db:10.0.0.5\n  - gw=host-gateway\n  - \"v6:::1\"\n");
        assert_eq!(s.extra_hosts, ["db:10.0.0.5", "gw:host-gateway", "v6:::1"]);
        let s = one("extra_hosts:\n  db: 10.0.0.5\n  multi: [10.0.0.6, \"::1\"]\n");
        assert_eq!(s.extra_hosts, ["db:10.0.0.5", "multi:10.0.0.6", "multi:::1"]);
        assert!(service_error("extra_hosts: [nope]\n").starts_with("services.web.extra_hosts[0]: "));
    }

    #[test]
    fn restart_and_pull_policies() {
        assert_eq!(one("restart: \"no\"\n").restart, Some(RestartPolicy::default()));
        assert_eq!(one("restart: false\n").restart, Some(RestartPolicy::default()));
        assert_eq!(one("restart: unless-stopped\n").restart.unwrap().name, RestartPolicyName::UnlessStopped);
        assert!(service_error("restart: sometimes\n").starts_with("services.web.restart: unknown restart policy"));
        assert_eq!(one("pull_policy: build\n").pull_policy, Some(PullPolicyDef::Build));
        assert!(
            service_error("pull_policy: daily\n").starts_with("services.web.pull_policy: the pull policy \"daily\"")
        );
    }

    #[test]
    fn networks_and_volumes_at_the_top() {
        let f = file(
            "networks:\n  back:\n    driver: bridge\n    internal: true\n    enable_ipv6: true\n    ipam:\n      driver: default\n      config:\n        - subnet: 10.89.7.0/24\n        - subnet: fd00:7::/64\n    labels: [tier=db]\n    name: shared-back\n\
             \x20 outside:\n    external: true\n  legacy:\n    external:\n      name: old-net\n\
             volumes:\n  data:\n    driver: local\n    labels: {k: v}\n  ext:\n    external: true\n    name: precious\n  plain:\n",
        );
        let back = &f.networks["back"];
        assert!(back.internal && back.enable_ipv6 && !back.external);
        assert_eq!(back.subnets, ["10.89.7.0/24", "fd00:7::/64"]);
        assert_eq!((back.name.as_deref(), back.labels["tier"].as_str()), (Some("shared-back"), "db"));
        assert!(f.networks["outside"].external && f.networks["outside"].name.is_none());
        assert_eq!(f.networks["legacy"].name.as_deref(), Some("old-net"));
        assert!(f.networks["legacy"].external);
        assert_eq!(f.volumes["data"].labels["k"], "v");
        assert_eq!((f.volumes["ext"].external, f.volumes["ext"].name.as_deref()), (true, Some("precious")));
        assert_eq!(f.volumes["plain"], VolumeDef::default());
        for (bad, expected) in [
            ("networks:\n  n:\n    driver: overlay\n", "networks.n.driver: the driver \"overlay\" isn't supported"),
            ("networks:\n  n:\n    attachable: true\n", "networks.n.attachable is not supported"),
            (
                "networks:\n  n:\n    ipam:\n      config: [{gateway: 10.0.0.1}]\n",
                "networks.n.ipam.config[0].gateway is not supported",
            ),
            (
                "networks:\n  n:\n    external: true\n    internal: true\n",
                "networks.n: an external network takes no internal",
            ),
            ("networks:\n  n:\n    external: {name: a}\n    name: b\n", "networks.n: external.name and name"),
            ("volumes:\n  v:\n    driver: nfs\n", "volumes.v.driver: the driver \"nfs\" isn't supported"),
            ("volumes:\n  v:\n    driver_opts: {a: b}\n", "volumes.v.driver_opts is not supported"),
            ("volumes:\n  v:\n    external: true\n    labels: [a]\n", "volumes.v: an external volume takes no labels"),
        ] {
            let e = error(bad);
            assert!(e.starts_with(expected), "{bad}: {e}");
        }
    }

    #[test]
    fn unsupported_keys_are_refused_by_their_path_and_extensions_are_not() {
        assert_eq!(error("secrets: {}\n"), "secrets is not supported");
        assert_eq!(
            error("services:\n  web:\n    image: a\n    secrets: [s]\n"),
            "services.web.secrets is not supported"
        );
        assert_eq!(
            error("services:\n  web:\n    healthcheck:\n      test: [NONE]\n      log: 1\n"),
            "services.web.healthcheck.log is not supported"
        );
        assert_eq!(
            error("services:\n  web:\n    depends_on:\n      db:\n        wait: 1\n"),
            "services.web.depends_on.db.wait is not supported"
        );
        let f = file(
            "version: \"3.8\"\nx-common: &common {restart: always}\nname: demo\nservices:\n  x-db:\n    image: a\n    x-note: 1\n    deploy:\n      x-meta: 2\nnetworks:\n  n:\n    x-y: 1\nvolumes:\n  v:\n    x-z: 1\n",
        );
        assert!(f.version);
        assert_eq!(f.name.as_deref(), Some("demo"));
        assert_eq!(f.services[0].name, "x-db", "in the services mapping, x- is a name");
    }

    #[test]
    fn shapes_that_arent_a_compose_file_are_refused() {
        assert_eq!(
            parse(&yaml("[a, b]")).unwrap_err().to_string(),
            "a compose file is a mapping (services:, networks:, volumes:), not a list"
        );
        assert_eq!(error("services: [web]\n"), "services: expected a mapping, found a list");
        assert_eq!(
            error("services:\n  web: nginx\n"),
            "services.web: a service is a mapping (image:, build:, …), not the string \"nginx\""
        );
        assert_eq!(
            error("services:\n  web:\n    ports: 80\n"),
            "services.web.ports: expected a list, found the number 80"
        );
        assert_eq!(
            error("services:\n  web:\n    tty: maybe\n"),
            "services.web.tty: expected true or false, found the string \"maybe\""
        );
        assert_eq!(
            error("services:\n  web:\n    tty: 1\n"),
            "services.web.tty: expected true or false, found the number 1"
        );
        assert_eq!(
            error("services:\n  web:\n    cap_add: [[a]]\n"),
            "services.web.cap_add[0]: expected a string, found a list"
        );
        assert_eq!(
            error("services:\n  \"we b\":\n    image: a\n"),
            "services: \"we b\" is not a valid service name (letters, digits, '.', '_' and '-')"
        );
        assert_eq!(
            error("services:\n  web:\n    environment:\n      1: x\n"),
            "services.web.environment: a key must be a string, not the number 1"
        );
        assert_eq!(parse(&Value::Null).unwrap(), ComposeFile::default(), "an empty file");
    }

    /// compose-go's `toBoolean` (loader/interpolate.go): `y`, `yes`, `on` and
    /// `n`, `no`, `off` are booleans too, in any case, with a warning that
    /// names the field; `true` and `false` need none.
    #[test]
    fn booleans_may_be_written_with_yaml_1_1_words_and_warn() {
        let f = file(
            "services:\n  web:\n    image: a\n    tty: yes\n    stdin_open: \"On\"\n    read_only: n\n    privileged: \"FALSE\"\n    depends_on:\n      db:\n        required: off\n  db:\n    image: b\n    volumes:\n      - {type: volume, target: /d, read_only: Y}\nvolumes: {}\nnetworks:\n  n:\n    internal: yes\n",
        );
        let web = &f.services[0];
        assert!(web.tty && web.stdin_open && !web.read_only && !web.privileged);
        assert!(!web.depends_on[0].required);
        assert!(f.services[1].volumes[0].read_only && f.networks["n"].internal);
        assert_eq!(
            f.warnings,
            [
                "services.web.tty: \"yes\" for boolean is not supported by YAML 1.2, please use `true`",
                "services.web.stdin_open: \"On\" for boolean is not supported by YAML 1.2, please use `true`",
                "services.web.read_only: \"n\" for boolean is not supported by YAML 1.2, please use `false`",
                "services.web.depends_on.db.required: \"off\" for boolean is not supported by YAML 1.2, please use `false`",
                "services.db.volumes[0].read_only: \"Y\" for boolean is not supported by YAML 1.2, please use `true`",
                "networks.n.internal: \"yes\" for boolean is not supported by YAML 1.2, please use `true`",
            ]
        );
        assert!(file("services:\n  web:\n    image: a\n    tty: true\n    read_only: \"false\"\n").warnings.is_empty());
    }

    /// `mem_limit: 0` is no limit (Docker: 0 is the engine's "unlimited"),
    /// as `cpus: 0` is: rustletd refuses `--memory 0`.
    #[test]
    fn a_limit_of_zero_is_no_limit() {
        let s = one("mem_limit: 0\ndeploy:\n  resources:\n    limits:\n      memory: 0b\n      cpus: 0\n");
        assert_eq!((s.mem_limit, s.deploy.memory, s.deploy.cpus), (None, None, None));
        assert_eq!(one("mem_limit: 0m\n").mem_limit, None);
        assert_eq!(one("mem_limit: 1m\n").mem_limit, Some(1 << 20));
    }

    #[test]
    fn sizes() {
        assert_eq!(parse_size("512m").unwrap(), 512 << 20);
        assert_eq!(parse_size("1G").unwrap(), 1 << 30);
        assert_eq!(parse_size("1.5g").unwrap(), 3 << 29);
        assert_eq!(parse_size("64KiB").unwrap(), 64 << 10);
        assert_eq!(parse_size("100").unwrap(), 100);
        assert_eq!(parse_size("2 mb").unwrap(), 2 << 20);
        for bad in ["", "m", "1x", "-1m", "1.2.3m", "99999999999999999999"] {
            assert!(parse_size(bad).is_err(), "{bad}");
        }
        assert_eq!(one("mem_limit: 1048576\n").mem_limit, Some(1 << 20));
    }
}

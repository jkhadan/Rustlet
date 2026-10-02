//! Networks: how a container is connected (`--network`), what it publishes
//! (`-p`), and the networks themselves (`rustlet network …`).
//!
//! Every container with a network of its own sits on a **bridge network**:
//! a Linux bridge on the host with a subnet, one veth pair per container,
//! NAT to the outside. `bridge` is the default one (no DNS between its
//! containers, as with Docker's); a network you create gets its own bridge
//! and subnet, and an embedded DNS server at `127.0.0.11` that answers the
//! names of the containers on it.

use std::collections::BTreeMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// The default network's name.
pub const DEFAULT_NETWORK: &str = "bridge";

/// Names a network can't have: they mean a [`NetworkMode`].
pub const RESERVED_NETWORK_NAMES: [&str; 4] = ["bridge", "host", "none", "default"];

/// `--network`: where a container's network namespace comes from.
///
/// On the wire it is a string, as in Docker: `bridge`, `none`, `host`,
/// `container:<name or id>`, or the name of a network.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(into = "String", try_from = "String")]
pub enum NetworkMode {
    /// A network namespace of its own on the default network (`bridge`, or
    /// `default`).
    #[default]
    Bridge,
    /// A network namespace of its own with only `lo`.
    None,
    /// The host's network namespace.
    Host,
    /// Another container's network namespace: the two share interfaces,
    /// addresses and `localhost`.
    Container(String),
    /// A network namespace of its own on a user-defined network.
    Network(String),
}

impl NetworkMode {
    /// Parses `--network`'s value.
    pub fn parse(s: &str) -> Result<NetworkMode, String> {
        match s {
            "" | "bridge" | "default" => Ok(NetworkMode::Bridge),
            "none" => Ok(NetworkMode::None),
            "host" => Ok(NetworkMode::Host),
            _ => match s.strip_prefix("container:") {
                Some("") => Err("--network container: needs a container's name or id".into()),
                Some(c) => Ok(NetworkMode::Container(c.to_owned())),
                None if crate::valid_container_name(s) => Ok(NetworkMode::Network(s.to_owned())),
                None => {
                    Err(format!("--network {s:?}: give bridge, none, host, container:<name|id> or a network's name"))
                }
            },
        }
    }

    /// The name of the bridge network this mode attaches to, if any.
    pub fn network_name(&self) -> Option<&str> {
        match self {
            NetworkMode::Bridge => Some(DEFAULT_NETWORK),
            NetworkMode::Network(n) => Some(n),
            _ => None,
        }
    }

    /// A network namespace of its own (pinned by the daemon)?
    pub fn own_namespace(&self) -> bool {
        matches!(self, NetworkMode::Bridge | NetworkMode::None | NetworkMode::Network(_))
    }
}

impl fmt::Display for NetworkMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetworkMode::Bridge => f.write_str(DEFAULT_NETWORK),
            NetworkMode::None => f.write_str("none"),
            NetworkMode::Host => f.write_str("host"),
            NetworkMode::Container(c) => write!(f, "container:{c}"),
            NetworkMode::Network(n) => f.write_str(n),
        }
    }
}

impl From<NetworkMode> for String {
    fn from(m: NetworkMode) -> String {
        m.to_string()
    }
}

impl TryFrom<String> for NetworkMode {
    type Error = String;
    fn try_from(s: String) -> Result<NetworkMode, String> {
        NetworkMode::parse(&s)
    }
}

/// A transport protocol of a published port.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    #[default]
    Tcp,
    Udp,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
        })
    }
}

impl FromStr for Protocol {
    type Err = String;
    fn from_str(s: &str) -> Result<Protocol, String> {
        match s.to_ascii_lowercase().as_str() {
            "tcp" => Ok(Protocol::Tcp),
            "udp" => Ok(Protocol::Udp),
            other => Err(format!("unsupported protocol {other:?} (tcp or udp)")),
        }
    }
}

/// `-p`: a container port to publish on the host.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(default)]
pub struct PortMapping {
    /// The host address to listen on; `None` is every address (IPv4
    /// `0.0.0.0`, and IPv6 `[::]` through the proxy).
    pub host_ip: Option<Ipv4Addr>,
    /// `None`: a free port the kernel picks.
    pub host_port: Option<u16>,
    pub container_port: u16,
    pub protocol: Protocol,
}

impl PortMapping {
    /// Parses Docker's `-p` syntax:
    /// `[[HOST_IP:][HOST_PORT]:]CONTAINER_PORT[/PROTOCOL]`, where either
    /// port may be a range `A-B` (host and container ranges of the same
    /// length, or a container range alone). A range gives one mapping per
    /// port.
    ///
    /// ```
    /// # use rustlet_spec::network::{PortMapping, Protocol};
    /// let m = PortMapping::parse("127.0.0.1:8080:80/udp").unwrap();
    /// assert_eq!((m[0].host_port, m[0].container_port, m[0].protocol), (Some(8080), 80, Protocol::Udp));
    /// assert_eq!(PortMapping::parse("8000-8002:80-82").unwrap().len(), 3);
    /// ```
    pub fn parse(s: &str) -> Result<Vec<PortMapping>, String> {
        let bad = |why: &str| format!("-p {s:?}: {why} (expected [[HOST_IP:][HOST_PORT]:]CONTAINER_PORT[/tcp|udp])");
        let (ports, protocol) = match s.rsplit_once('/') {
            Some((p, proto)) => (p, proto.parse::<Protocol>().map_err(|e| bad(&e))?),
            None => (s, Protocol::Tcp),
        };
        if ports.starts_with('[') {
            return Err(bad("IPv6 host addresses aren't supported"));
        }
        let parts: Vec<&str> = ports.split(':').collect();
        let (host_ip, host_ports, container_ports) = match parts.as_slice() {
            [c] => (None, "", *c),
            [h, c] => (None, *h, *c),
            [ip, h, c] => {
                let ip = ip.parse::<Ipv4Addr>().map_err(|_| bad(&format!("{ip:?} is not an IPv4 address")))?;
                (Some(ip).filter(|ip| !ip.is_unspecified()), *h, *c)
            }
            _ => return Err(bad("too many colons")),
        };
        let container = port_range(container_ports).map_err(|e| bad(&e))?;
        let host = if host_ports.is_empty() { None } else { Some(port_range(host_ports).map_err(|e| bad(&e))?) };
        if let Some(h) = host
            && h.1 - h.0 != container.1 - container.0
        {
            return Err(bad("the host and container port ranges must be the same length"));
        }
        Ok((container.0..=container.1)
            .enumerate()
            .map(|(i, container_port)| PortMapping {
                host_ip,
                host_port: host.map(|h| h.0 + i as u16),
                container_port,
                protocol,
            })
            .collect())
    }
}

/// `80` or `8000-8010`, every port in 1..=65535.
fn port_range(s: &str) -> Result<(u16, u16), String> {
    let port = |p: &str| match p.parse::<u16>() {
        Ok(0) | Err(_) => Err(format!("{p:?} is not a port (1-65535)")),
        Ok(n) => Ok(n),
    };
    match s.split_once('-') {
        Some((a, b)) => {
            let (a, b) = (port(a)?, port(b)?);
            if a > b {
                return Err(format!("the range {s:?} goes backwards"));
            }
            Ok((a, b))
        }
        None => port(s).map(|p| (p, p)),
    }
}

impl fmt::Display for PortMapping {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ip) = self.host_ip {
            write!(f, "{ip}:")?;
        }
        match self.host_port {
            Some(p) => write!(f, "{p}:")?,
            None if self.host_ip.is_some() => f.write_str(":")?,
            None => {}
        }
        write!(f, "{}/{}", self.container_port, self.protocol)
    }
}

/// A published port as a run set it up: the host port is known.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PublishedPort {
    /// `0.0.0.0`: every address.
    pub host_ip: Ipv4Addr,
    pub host_port: u16,
    pub container_port: u16,
    pub protocol: Protocol,
}

impl fmt::Display for PublishedPort {
    /// As `docker ps` shows it: `0.0.0.0:8080->80/tcp`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}->{}/{}", self.host_ip, self.host_port, self.container_port, self.protocol)
    }
}

/// `--add-host NAME:IP` (Docker's syntax; `NAME=IP` too). The IP may be
/// [`HOST_GATEWAY`]. Returns `(name, address)`.
pub fn parse_extra_host(s: &str) -> Result<(String, String), String> {
    let (name, ip) = s
        .split_once(['=', ':'])
        .ok_or_else(|| format!("--add-host {s:?}: expected NAME:IP (or NAME:{HOST_GATEWAY})"))?;
    if !valid_hostname(name) {
        return Err(format!("--add-host {s:?}: {name:?} is not a host name"));
    }
    let ip = ip.trim_start_matches('[').trim_end_matches(']');
    if ip != HOST_GATEWAY && ip.parse::<IpAddr>().is_err() {
        return Err(format!("--add-host {s:?}: {ip:?} is not an IP address"));
    }
    Ok((name.to_owned(), ip.to_owned()))
}

/// The `--add-host` address that means "the host, as the container reaches
/// it": the gateway of its network.
pub const HOST_GATEWAY: &str = "host-gateway";

/// A DNS-style host name: dot-separated labels of letters, digits and `-`
/// (not at either end), at most 253 characters.
pub fn valid_hostname(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        })
}

/// `POST /v1/networks`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkCreate {
    pub name: String,
    /// `10.89.5.0/24`; default: the next free /24 of the daemon's pool.
    pub subnet: Option<String>,
    /// Default: the subnet's first address.
    pub gateway: Option<String>,
    /// No route out: containers reach each other, not the outside.
    pub internal: bool,
    pub labels: BTreeMap<String, String>,
}

/// `201` from `POST /v1/networks`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkCreateResponse {
    pub id: String,
    pub name: String,
}

/// A network: `GET /v1/networks` lists them, `GET /v1/networks/{id}`
/// shows one (`{id}` is its id, a unique prefix of it, or its name).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Network {
    pub id: String,
    pub name: String,
    /// Always `bridge` for now.
    pub driver: String,
    /// RFC 3339, UTC.
    pub created: String,
    /// `10.89.0.0/24`.
    pub subnet: String,
    /// `10.89.0.1`: the bridge's address, the containers' default route.
    pub gateway: String,
    /// The bridge's interface name on the host (`rustlet0`, `rlb…`).
    pub bridge: String,
    pub internal: bool,
    /// The embedded DNS server answers its containers' names (every
    /// network but the default one).
    pub dns: bool,
    pub labels: BTreeMap<String, String>,
    /// The running containers on it.
    pub containers: Vec<NetworkEndpoint>,
}

/// A container's place on a network.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkEndpoint {
    pub container_id: String,
    pub container_name: String,
    /// `10.89.0.2/24`.
    pub ip_address: String,
    pub mac_address: String,
    /// The names the embedded DNS server answers for it here.
    pub dns_names: Vec<String>,
}

/// A container's network, as `inspect` shows it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkSettings {
    /// `--network`, as given.
    pub mode: NetworkMode,
    /// The network it is (or was last) attached to.
    pub network: Option<String>,
    pub network_id: Option<String>,
    /// While it runs: `10.89.0.2`.
    pub ip_address: Option<String>,
    pub ip_prefix_len: Option<u8>,
    pub gateway: Option<String>,
    pub mac_address: Option<String>,
    /// Its names on a user-defined network (container name, aliases, short
    /// id, hostname).
    pub dns_names: Vec<String>,
    /// The pinned network namespace (`/run/rustlet/netns/<id>`), while it
    /// runs.
    pub sandbox: Option<String>,
    /// While it runs: what is published, with the host ports chosen.
    pub ports: Vec<PublishedPort>,
}

/// The answer of the prune routes (networks, volumes).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PruneResponse {
    /// Names of what was removed.
    pub deleted: Vec<String>,
    /// Bytes freed (volumes).
    pub space_reclaimed: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_modes_parse_and_print_like_dockers() {
        for (s, m) in [
            ("bridge", NetworkMode::Bridge),
            ("default", NetworkMode::Bridge),
            ("none", NetworkMode::None),
            ("host", NetworkMode::Host),
            ("container:web", NetworkMode::Container("web".into())),
            ("backend", NetworkMode::Network("backend".into())),
        ] {
            assert_eq!(NetworkMode::parse(s).unwrap(), m, "{s}");
        }
        assert_eq!(NetworkMode::Container("web".into()).to_string(), "container:web");
        assert!(NetworkMode::parse("container:").is_err());
        assert!(NetworkMode::parse("no/slash").is_err());
        // A string on the wire.
        let json = serde_json::to_string(&NetworkMode::Container("db".into())).unwrap();
        assert_eq!(json, r#""container:db""#);
        assert_eq!(serde_json::from_str::<NetworkMode>(r#""host""#).unwrap(), NetworkMode::Host);
        assert!(serde_json::from_str::<NetworkMode>(r#""a b""#).is_err());
        assert_eq!(NetworkMode::Bridge.network_name(), Some(DEFAULT_NETWORK));
        assert!(NetworkMode::None.own_namespace() && !NetworkMode::Host.own_namespace());
    }

    #[test]
    fn port_specs() {
        let one = |s| PortMapping::parse(s).unwrap().remove(0);
        assert_eq!(
            one("80"),
            PortMapping { host_ip: None, host_port: None, container_port: 80, protocol: Protocol::Tcp }
        );
        assert_eq!(one("8080:80").host_port, Some(8080));
        assert_eq!(one("8080:80/udp").protocol, Protocol::Udp);
        assert_eq!(one("8080:80/UDP").protocol, Protocol::Udp);
        let local = one("127.0.0.1:8080:80");
        assert_eq!((local.host_ip, local.host_port), (Some(Ipv4Addr::LOCALHOST), Some(8080)));
        let any = one("127.0.0.1::80");
        assert_eq!((any.host_ip, any.host_port), (Some(Ipv4Addr::LOCALHOST), None));
        assert_eq!(one("0.0.0.0:8080:80").host_ip, None, "0.0.0.0 is every address");
        let range = PortMapping::parse("8000-8002:80-82/udp").unwrap();
        assert_eq!(
            range.iter().map(|m| (m.host_port.unwrap(), m.container_port)).collect::<Vec<_>>(),
            [(8000, 80), (8001, 81), (8002, 82)]
        );
        assert_eq!(PortMapping::parse("80-81").unwrap().iter().map(|m| m.host_port).collect::<Vec<_>>(), [None; 2]);
        for bad in
            ["", "0", "65536", "x", "80/sctp", "1:2:3:4", "8000-8001:80", "90-80", "[::1]:80:80", "300.0.0.1:1:2"]
        {
            assert!(PortMapping::parse(bad).is_err(), "{bad}");
        }
        for s in ["80/tcp", "8080:80/tcp", "127.0.0.1:8080:80/udp", "127.0.0.1::80/tcp"] {
            assert_eq!(one(s).to_string(), s);
        }
        let p = PublishedPort {
            host_ip: Ipv4Addr::UNSPECIFIED,
            host_port: 8080,
            container_port: 80,
            protocol: Protocol::Tcp,
        };
        assert_eq!(p.to_string(), "0.0.0.0:8080->80/tcp");
    }

    #[test]
    fn extra_hosts() {
        assert_eq!(parse_extra_host("db:10.0.0.5").unwrap(), ("db".into(), "10.0.0.5".into()));
        assert_eq!(parse_extra_host("db=10.0.0.5").unwrap().1, "10.0.0.5");
        assert_eq!(parse_extra_host("v6:::1").unwrap().1, "::1");
        assert_eq!(parse_extra_host("v6:[fe80::1]").unwrap().1, "fe80::1");
        assert_eq!(parse_extra_host("host.internal:host-gateway").unwrap().1, HOST_GATEWAY);
        for bad in ["db", "db:", ":1.2.3.4", "d b:1.2.3.4", "db:nope", "-x:1.2.3.4"] {
            assert!(parse_extra_host(bad).is_err(), "{bad}");
        }
    }
}

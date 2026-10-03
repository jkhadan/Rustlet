//! Networks: how a container is connected (`--network`, `network
//! connect`), what it publishes (`-p`), and the networks themselves
//! (`rustlet network …`).
//!
//! Every container with a network namespace of its own sits on **bridge
//! networks**: a Linux bridge on the host per network, with an IPv4 subnet
//! (and an IPv6 one, for a network created with `--ipv6`), one veth pair per
//! container and network, NAT to the outside. `bridge` is the default one
//! (no DNS between its containers, as with Docker's); a network you create
//! gets its own bridge and subnets, and an embedded DNS server at
//! `127.0.0.11` that answers the names of the containers on it. A container
//! can be on several networks at once (`--network a --network b`, `network
//! connect`), with an interface on each (`eth0`, `eth1`, …).

use std::collections::BTreeMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use ts_rs::TS;

/// The default network's name.
pub const DEFAULT_NETWORK: &str = "bridge";

/// Names a network can't have: they mean a [`NetworkMode`].
pub const RESERVED_NETWORK_NAMES: [&str; 4] = ["bridge", "host", "none", "default"];

/// `--network`: where a container's network namespace comes from.
///
/// On the wire it is a string, as in Docker: `bridge`, `none`, `host`,
/// `container:<name or id>`, or the name of a network.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize, TS)]
#[serde(into = "String", try_from = "String")]
#[ts(type = "string")]
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
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, TS)]
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
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, TS)]
#[serde(default)]
pub struct PortMapping {
    /// The host address to listen on; `None` is every address, IPv4
    /// (`0.0.0.0`) and IPv6 (`[::]`). `[::]` alone is every IPv6 address.
    pub host_ip: Option<IpAddr>,
    /// `None`: a free port the kernel picks.
    pub host_port: Option<u16>,
    pub container_port: u16,
    pub protocol: Protocol,
}

impl PortMapping {
    /// Parses Docker's `-p` syntax:
    /// `[[HOST_IP:][HOST_PORT]:]CONTAINER_PORT[/PROTOCOL]`, where either
    /// port may be a range `A-B` (host and container ranges of the same
    /// length, or a container range alone), and an IPv6 host address is
    /// written in brackets (`[::1]:8080:80`). A range gives one mapping per
    /// port.
    ///
    /// ```
    /// # use rustlet_spec::network::{PortMapping, Protocol};
    /// let m = PortMapping::parse("127.0.0.1:8080:80/udp").unwrap();
    /// assert_eq!((m[0].host_port, m[0].container_port, m[0].protocol), (Some(8080), 80, Protocol::Udp));
    /// assert_eq!(PortMapping::parse("8000-8002:80-82").unwrap().len(), 3);
    /// assert!(PortMapping::parse("[::1]:8080:80").unwrap()[0].host_ip.unwrap().is_ipv6());
    /// ```
    pub fn parse(s: &str) -> Result<Vec<PortMapping>, String> {
        let bad = |why: &str| format!("-p {s:?}: {why} (expected [[HOST_IP:][HOST_PORT]:]CONTAINER_PORT[/tcp|udp])");
        let (ports, protocol) = match s.rsplit_once('/') {
            Some((p, proto)) => (p, proto.parse::<Protocol>().map_err(|e| bad(&e))?),
            None => (s, Protocol::Tcp),
        };
        let (host_ip, host_ports, container_ports) = if let Some(after) = ports.strip_prefix('[') {
            let (ip, rest) = after.split_once(']').ok_or_else(|| bad("an IPv6 address needs its closing ]"))?;
            let ip = ip.parse::<Ipv6Addr>().map_err(|_| bad(&format!("{ip:?} is not an IPv6 address")))?;
            let rest = rest.strip_prefix(':').ok_or_else(|| bad("a host address needs the ports after it"))?;
            match rest.split(':').collect::<Vec<_>>().as_slice() {
                [h, c] => (Some(IpAddr::V6(ip)), *h, *c),
                _ => return Err(bad("expected [HOST_IP]:[HOST_PORT]:CONTAINER_PORT")),
            }
        } else {
            match ports.split(':').collect::<Vec<_>>().as_slice() {
                [c] => (None, "", *c),
                [h, c] => (None, *h, *c),
                [ip, h, c] => {
                    let ip = ip.parse::<Ipv4Addr>().map_err(|_| {
                        bad(&format!("{ip:?} is not an IPv4 address (an IPv6 one goes in brackets: [::1])"))
                    })?;
                    // 0.0.0.0: every address, IPv6 too, as without one.
                    (Some(IpAddr::V4(ip)).filter(|ip| !ip.is_unspecified()), *h, *c)
                }
                _ => return Err(bad("too many colons (an IPv6 host address goes in brackets: [::1])")),
            }
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

/// A host address as `-p` and `ps` write it: IPv6 in brackets.
fn host_ip_text(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(ip) => ip.to_string(),
        IpAddr::V6(ip) => format!("[{ip}]"),
    }
}

impl fmt::Display for PortMapping {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ip) = self.host_ip {
            write!(f, "{}:", host_ip_text(ip))?;
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, TS)]
pub struct PublishedPort {
    /// `0.0.0.0`: every address, IPv4 and IPv6; `::`: every IPv6 address.
    pub host_ip: IpAddr,
    pub host_port: u16,
    pub container_port: u16,
    pub protocol: Protocol,
}

impl PublishedPort {
    /// Where it listens, as a socket address (`[::1]:8080` for IPv6).
    pub fn host_addr(&self) -> std::net::SocketAddr {
        std::net::SocketAddr::new(self.host_ip, self.host_port)
    }
}

impl fmt::Display for PublishedPort {
    /// As `docker ps` shows it: `0.0.0.0:8080->80/tcp`, `[::1]:8080->80/tcp`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}->{}/{}", host_ip_text(self.host_ip), self.host_port, self.container_port, self.protocol)
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

/// A DNS-style host name: dot-separated labels of letters, digits, `-` (not
/// at either end) and `_` (which container names may have), at most 253
/// characters.
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
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(default)]
pub struct NetworkCreate {
    pub name: String,
    /// `10.89.5.0/24`; default: the next free /24 of the daemon's pool.
    pub subnet: Option<String>,
    /// Default: the subnet's first address.
    pub gateway: Option<String>,
    /// IPv6 too (dual stack): its bridge and containers get IPv6 addresses
    /// as well as IPv4 ones.
    pub ipv6: bool,
    /// With `ipv6`: `fd00:89:0:5::/64`; default: the next free /64 of the
    /// daemon's IPv6 pool (unique local addresses).
    pub subnet6: Option<String>,
    /// Default: the IPv6 subnet's first address after its own (`…::1`).
    pub gateway6: Option<String>,
    /// No route out: containers reach each other, not the outside.
    pub internal: bool,
    pub labels: BTreeMap<String, String>,
}

/// `201` from `POST /v1/networks`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(default)]
pub struct NetworkCreateResponse {
    pub id: String,
    pub name: String,
}

/// A network: `GET /v1/networks` lists them, `GET /v1/networks/{id}`
/// shows one (`{id}` is its id, a unique prefix of it, or its name).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
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
    /// It has IPv6 as well (`subnet6`, `gateway6`).
    pub ipv6: bool,
    /// `fd00:89:0:1::/64`.
    pub subnet6: Option<String>,
    pub gateway6: Option<String>,
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
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(default)]
pub struct NetworkEndpoint {
    pub container_id: String,
    pub container_name: String,
    /// `10.89.0.2/24`.
    pub ip_address: String,
    /// `fd00:89:0:1::2/64`, on an IPv6 network.
    pub ipv6_address: Option<String>,
    pub mac_address: String,
    /// The names the embedded DNS server answers for it here.
    pub dns_names: Vec<String>,
}

/// A container's network, as `inspect` shows it.
///
/// The top-level addresses are those of its **primary** network: the one
/// its IPv4 default route goes through (else its first), which is also
/// where its published ports lead. `networks` has every network.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(default)]
pub struct NetworkSettings {
    /// `--network`, as given (the first, if it was given more than once).
    pub mode: NetworkMode,
    /// The primary network (or, while it doesn't run, the first it is
    /// connected to).
    pub network: Option<String>,
    pub network_id: Option<String>,
    /// While it runs: `10.89.0.2`.
    pub ip_address: Option<String>,
    pub ip_prefix_len: Option<u8>,
    pub gateway: Option<String>,
    /// While it runs, on an IPv6 network: `fd00:89:0:1::2`.
    pub ipv6_address: Option<String>,
    pub ipv6_prefix_len: Option<u8>,
    pub ipv6_gateway: Option<String>,
    pub mac_address: Option<String>,
    /// Its names on a user-defined network (container name, aliases, short
    /// id, hostname).
    pub dns_names: Vec<String>,
    /// The pinned network namespace (`/run/rustlet/netns/<id>`), while it
    /// runs.
    pub sandbox: Option<String>,
    /// While it runs: what is published, with the host ports chosen.
    pub ports: Vec<PublishedPort>,
    /// Every network it is connected to, in order: what `--network` and
    /// `network connect` asked for, and while it runs, its place there.
    pub networks: Vec<EndpointSettings>,
}

/// A container on one of its networks, as `inspect` shows it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(default)]
pub struct EndpointSettings {
    /// The network's name.
    pub network: String,
    /// `--network-alias`, `network connect --alias`: more names for the
    /// embedded DNS server.
    pub aliases: Vec<String>,
    /// `--ip`, `--ip6`, `network connect --ip/--ip6`: the addresses asked
    /// for (otherwise the next free ones).
    pub ipv4_requested: Option<Ipv4Addr>,
    pub ipv6_requested: Option<Ipv6Addr>,
    /// The rest only while it runs: the network's id,
    pub network_id: Option<String>,
    /// its interface inside (`eth0`) and the host's end of its veth pair
    /// (`rlv…`),
    pub interface: Option<String>,
    pub host_interface: Option<String>,
    /// its addresses there,
    pub ip_address: Option<String>,
    pub ip_prefix_len: Option<u8>,
    pub gateway: Option<String>,
    pub ipv6_address: Option<String>,
    pub ipv6_prefix_len: Option<u8>,
    pub ipv6_gateway: Option<String>,
    pub mac_address: Option<String>,
    /// the names the embedded DNS server answers for it there,
    pub dns_names: Vec<String>,
    /// and whether its IPv4 (IPv6) default route goes through this network.
    pub default_route: bool,
    pub default_route6: bool,
}

/// `POST /v1/networks/{id}/connect`: connects a container to the network,
/// at once if it runs, otherwise from its next start.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(default)]
pub struct NetworkConnect {
    /// Its name, id, or a unique prefix of its id.
    pub container: String,
    /// More names for it on this network (a user-defined one).
    pub aliases: Vec<String>,
    /// Its address there (a user-defined network); default: the next free.
    pub ipv4_address: Option<Ipv4Addr>,
    /// Its IPv6 address there (an IPv6 network); default: the next free.
    pub ipv6_address: Option<Ipv6Addr>,
}

/// `POST /v1/networks/{id}/disconnect`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(default)]
pub struct NetworkDisconnect {
    /// Its name, id, or a unique prefix of its id.
    pub container: String,
    /// Also when the network itself is gone: the container's own record of
    /// it is removed.
    pub force: bool,
}

/// The answer of the prune routes (networks, volumes).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
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
        assert_eq!((local.host_ip, local.host_port), (Some(IpAddr::V4(Ipv4Addr::LOCALHOST)), Some(8080)));
        let any = one("127.0.0.1::80");
        assert_eq!((any.host_ip, any.host_port), (Some(IpAddr::V4(Ipv4Addr::LOCALHOST)), None));
        assert_eq!(one("0.0.0.0:8080:80").host_ip, None, "0.0.0.0 is every address");
        let v6 = one("[::1]:8080:80/udp");
        assert_eq!((v6.host_ip, v6.host_port), (Some(IpAddr::V6(Ipv6Addr::LOCALHOST)), Some(8080)));
        assert_eq!(v6.protocol, Protocol::Udp);
        let v6 = one("[2001:db8::1]::80");
        assert_eq!((v6.host_ip, v6.host_port), (Some("2001:db8::1".parse().unwrap()), None));
        assert_eq!(one("[::]:8080:80").host_ip, Some(IpAddr::V6(Ipv6Addr::UNSPECIFIED)), "[::] is IPv6's only");
        let range = PortMapping::parse("8000-8002:80-82/udp").unwrap();
        assert_eq!(
            range.iter().map(|m| (m.host_port.unwrap(), m.container_port)).collect::<Vec<_>>(),
            [(8000, 80), (8001, 81), (8002, 82)]
        );
        assert_eq!(PortMapping::parse("80-81").unwrap().iter().map(|m| m.host_port).collect::<Vec<_>>(), [None; 2]);
        for bad in [
            "",
            "0",
            "65536",
            "x",
            "80/sctp",
            "1:2:3:4",
            "8000-8001:80",
            "90-80",
            "300.0.0.1:1:2",
            "::1:80:80",
            "[::1]",
            "[::1]:80",
            "[::1:80:80",
            "[10.0.0.1]:80:80",
            "[::1]x:80:80",
        ] {
            assert!(PortMapping::parse(bad).is_err(), "{bad}");
        }
        for s in
            ["80/tcp", "8080:80/tcp", "127.0.0.1:8080:80/udp", "127.0.0.1::80/tcp", "[::1]:8080:80/tcp", "[::]::80/udp"]
        {
            assert_eq!(one(s).to_string(), s);
        }
        let mut p = PublishedPort {
            host_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            host_port: 8080,
            container_port: 80,
            protocol: Protocol::Tcp,
        };
        assert_eq!(p.to_string(), "0.0.0.0:8080->80/tcp");
        p.host_ip = IpAddr::V6(Ipv6Addr::LOCALHOST);
        assert_eq!(p.to_string(), "[::1]:8080->80/tcp");
        assert_eq!(p.host_addr().to_string(), "[::1]:8080");
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

//! Networks: the daemon's side of `rustlet-net`.
//!
//! ```text
//!  daemon start   the pin directory; every network's bridge; the firewall
//!                 (with the published ports of the runs the database says
//!                 are going on); then IP forwarding (recorded first; IPv6
//!                 only if a network has IPv6); ufw's route rules
//!  start          pin a network namespace (lo up, sysctls)
//!                 → for each of its networks, in order: addresses, the
//!                   veth, ethN inside, DNS names (user-defined networks)
//!                 → the default routes; the embedded DNS server, if it is
//!                   on a user-defined network
//!                 → published ports: proxy sockets bound, then DNAT rules
//!                 = a NetRun, recorded before the shim starts
//!  connect        (running) one more endpoint, recorded before its veth
//!                 exists; routes, DNS, ports and files follow
//!  disconnect     (running) that endpoint undone; the same follow
//!  exit           everything the NetRun says, undone
//! ```
//!
//! A run's network lives exactly as long as the run, like its root
//! filesystem: a stopped container holds no address, no namespace, no
//! port. Its next start may get other addresses (as in Docker), unless it
//! asked for them (`--ip`, `--ip6`).
//!
//! **A container on several networks** has an interface on each (`eth0`,
//! `eth1`, … in the order it was connected), one default route per family
//! and one set of published ports. The default routes and the ports go
//! through its *first network with a way out* (not internal; for IPv6, the
//! first such one with IPv6), so they change only when that network is
//! disconnected. Its embedded DNS server answers the names of every
//! user-defined network it is on, the first network that has a name
//! answering.
//!
//! What is in use is never stored apart from the containers: the addresses
//! of each run are in its container's [`NetRun`], and at startup the daemon
//! rebuilds the addresses in use, the DNS names and the published ports
//! from those, then takes over the runs that are still going (new DNS
//! sockets and proxies: the old ones went with the old daemon) and undoes
//! the rest.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsFd, AsRawFd};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use rustlet_net::backend::{Bridge, NetworkBackend};
use rustlet_net::dns::{DnsServer, Scope, View, Zone};
use rustlet_net::files::ResolvConf;
use rustlet_net::firewall::{self, NetworkRules, PortRule, Ruleset};
use rustlet_net::ipam::{self, Allocator, Allocator6, Subnet, Subnet6};
use rustlet_net::proxy::{self, Proxy};
use rustlet_net::{Context as _, link, netns, sysctl, ufw};
use rustlet_spec::container::{ContainerConfig, ContainerStatus, UsernsMode};
use rustlet_spec::event::EventKind;
use rustlet_spec::network::{
    DEFAULT_NETWORK, Network, NetworkConnect, NetworkCreate, NetworkDisconnect, NetworkEndpoint, NetworkMode,
    PortMapping, Protocol, PruneResponse, PublishedPort, RESERVED_NETWORK_NAMES,
};

use crate::container::Container;
use crate::daemon::Daemon;
use crate::db::{EndpointConfig, EndpointRun, NetRun, NetworkRecord, route_v4, route_v6};
use crate::error::{ApiError, ApiResult};
use crate::lifecycle::blocking;

/// The networking half of the daemon's state.
pub struct Networks {
    /// Everything that touches the host's interfaces or firewall.
    backend: Arc<dyn NetworkBackend>,
    pool: Subnet,
    pool6: Subnet6,
    default_subnet: Subnet,
    default_bridge: String,
    table: String,
    resolv_conf: PathBuf,
    sysctl_record: PathBuf,
    /// This daemon keeps ufw's route rules (`rustlet_net::ufw`).
    ufw: bool,
    /// One `ufw` command at a time: it rewrites its rule files whole.
    ufw_turn: Arc<Mutex<()>>,
    state: Mutex<State>,
    /// Taken while a ruleset is computed and applied, so that two changes
    /// can't apply their rulesets in the wrong order.
    firewall: tokio::sync::Mutex<()>,
    pub zone: Arc<Zone>,
    /// Rustlets turned IP forwarding on: forward only its own bridges.
    isolate_forwarding: AtomicBool,
    isolate_forwarding6: AtomicBool,
}

#[derive(Default)]
struct State {
    /// By id.
    networks: BTreeMap<String, NetworkRecord>,
    allocators: BTreeMap<String, (Allocator, Option<Allocator6>)>,
    /// Network id → address (IPv4 and IPv6) → the container that has it.
    used: BTreeMap<String, BTreeMap<IpAddr, String>>,
    /// What each run holds from us, by container id.
    live: BTreeMap<String, Live>,
}

/// One run's share of the daemon: its endpoints and ports (what the
/// firewall's rules come from), and the servers that stop when it is
/// dropped.
struct Live {
    name: String,
    endpoints: Vec<EndpointRun>,
    ports: Vec<PublishedPort>,
    dns: Option<RunDns>,
    proxies: Vec<PortProxy>,
}

/// A run's embedded DNS server, and the view the daemon changes as the run
/// is connected to networks and disconnected from them.
struct RunDns {
    server: DnsServer,
    view: View,
}

/// One published socket's proxy and where it relays to.
#[derive(Debug)]
struct PortProxy {
    proxy: Proxy,
    backend: proxy::Backend,
    /// Bound to an IPv6 address: relays to the container's IPv6 address
    /// when it has one, else to its IPv4 one.
    v6: bool,
    container_port: u16,
}

impl Networks {
    pub fn new(config: &crate::config::Config, paths: &crate::config::Paths) -> anyhow::Result<Networks> {
        let parse = |what: &str, s: &str| Subnet::parse(s).map_err(|e| anyhow::anyhow!("{what} {s:?}: {e}"));
        let pool = parse("network_pool", &config.network_pool)?;
        let default_subnet = parse("default_subnet", &config.default_subnet)?;
        let pool6 = match &config.network_pool_v6 {
            Some(s) => Subnet6::parse(s).map_err(|e| anyhow::anyhow!("network_pool_v6 {s:?}: {e}"))?,
            // Stable across restarts, and the host's own (RFC 4193 wants the
            // 40 bits random): the machine id, or failing that the hostname.
            None => Subnet6::ula(
                &std::fs::read("/etc/machine-id")
                    .unwrap_or_else(|_| nix::unistd::gethostname().map(|h| h.into_encoded_bytes()).unwrap_or_default()),
            ),
        };
        Ok(Networks {
            backend: Arc::new(Bridge),
            pool,
            pool6,
            default_subnet,
            default_bridge: config.default_bridge.clone(),
            table: config.nft_table.clone(),
            resolv_conf: config.resolv_conf.clone(),
            sysctl_record: paths.sysctl_record.clone(),
            ufw: config.manage_ufw && ufw::manages_host(),
            ufw_turn: Arc::new(Mutex::new(())),
            state: Mutex::new(State::default()),
            firewall: tokio::sync::Mutex::new(()),
            zone: Zone::new(),
            isolate_forwarding: AtomicBool::new(false),
            isolate_forwarding6: AtomicBool::new(false),
        })
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Loads the networks, adding the default one if the database has none.
    pub fn load(&self, db: &crate::db::Db) -> anyhow::Result<()> {
        let mut networks = db.networks()?;
        if !networks.iter().any(|n| n.name == DEFAULT_NETWORK) {
            let id = crate::names::new_id(|short| networks.iter().any(|n| rustlet_spec::short_id(&n.id) == short));
            let record = NetworkRecord {
                id,
                name: DEFAULT_NETWORK.into(),
                created: rustlet_shim::logfile::now(),
                subnet: self.default_subnet.to_string(),
                gateway: self.default_subnet.first_host(),
                bridge: self.default_bridge.clone(),
                ..NetworkRecord::default()
            };
            db.insert_network(&record)?;
            networks.push(record);
        }
        let mut st = self.state();
        for n in networks {
            let (subnet, subnet6) = subnets(&n).map_err(|e| anyhow::anyhow!("network {}: {e}", n.name))?;
            let v6 = subnet6.map(|s| Allocator6::new(s, n.gateway6.unwrap_or_else(|| s.first_host())));
            st.allocators.insert(n.id.clone(), (Allocator::new(subnet, n.gateway), v6));
            st.networks.insert(n.id.clone(), n);
        }
        Ok(())
    }

    /// What the database says a run holds, before anything is taken over:
    /// its addresses stay taken, its names answer, its ports stay in the
    /// firewall. Returns the run with what its record may lack (a run
    /// recorded before several networks were possible) filled in from the
    /// networks.
    pub fn restore(&self, id: &str, name: &str, run: &NetRun) -> NetRun {
        let mut run = run.clone();
        let mut st = self.state();
        for e in &mut run.endpoints {
            if let Some(n) = st.networks.get(&e.network_id) {
                if e.bridge.is_empty() {
                    e.bridge = n.bridge.clone();
                }
                e.internal = n.internal;
            }
            let used = st.used.entry(e.network_id.clone()).or_default();
            for ip in addresses(e) {
                used.insert(ip, id.to_owned());
                if !e.dns_names.is_empty() {
                    self.zone.add(&e.network_name, ip, &e.dns_names);
                }
            }
        }
        st.live.insert(
            id.to_owned(),
            Live {
                name: name.to_owned(),
                endpoints: run.endpoints.clone(),
                ports: run.ports.clone(),
                dns: None,
                proxies: Vec::new(),
            },
        );
        run
    }

    /// At daemon start: the pin directory, every bridge, the firewall, IP
    /// forwarding, in that order (forwarding is never on without the guards
    /// in place); then ufw's rules.
    pub async fn setup_host(&self, netns_dir: PathBuf) -> anyhow::Result<()> {
        let record = self.sysctl_record.clone();
        let bridges: Vec<HostSide> = self
            .records()
            .iter()
            .filter_map(|n| {
                let (subnet, subnet6) = subnets(n).ok()?;
                let v6 = subnet6.map(|s| (n.gateway6.unwrap_or_else(|| s.first_host()), s.prefix_len()));
                Some((n.bridge.clone(), n.gateway, subnet.prefix_len(), v6))
            })
            .collect();
        let ipv6 = bridges.iter().any(|b| b.3.is_some());
        let backend = self.backend.clone();
        let (isolate, isolate6) = blocking(move || -> ApiResult<(bool, bool)> {
            netns::prepare_dir(&netns_dir).map_err(ApiError::from)?;
            for (bridge, gateway, len, v6) in &bridges {
                backend.ensure_network(bridge, *gateway, *len, *v6).map_err(ApiError::from)?;
            }
            let isolate6 = ipv6 && will_isolate(&record, sysctl::IP6_FORWARD)?;
            Ok((will_isolate(&record, sysctl::IP_FORWARD)?, isolate6))
        })
        .await
        .map_err(|e| anyhow::anyhow!("set up the host's network: {e}"))?;
        self.isolate_forwarding.store(isolate, Ordering::Relaxed);
        self.isolate_forwarding6.store(isolate6, Ordering::Relaxed);
        self.apply_firewall().await.map_err(|e| anyhow::anyhow!("{e}"))?;
        let record = self.sysctl_record.clone();
        blocking(move || -> ApiResult<()> {
            sysctl::enable_forwarding(&record)?;
            if ipv6 {
                sysctl::enable_forwarding6(&record)?;
            }
            Ok(())
        })
        .await
        .map_err(|e| anyhow::anyhow!("turn IP forwarding on: {e}"))?;
        self.sync_ufw().await;
        Ok(())
    }

    /// IPv6 forwarding for a new IPv6 network, if it isn't on already: the
    /// firewall first (it guards the network's subnet), then the sysctl.
    async fn enable_ipv6_forwarding(&self) -> ApiResult<()> {
        let record = self.sysctl_record.clone();
        let isolate6 = blocking(move || will_isolate(&record, sysctl::IP6_FORWARD)).await?;
        self.isolate_forwarding6.store(isolate6, Ordering::Relaxed);
        self.apply_firewall().await?;
        let record = self.sysctl_record.clone();
        blocking(move || sysctl::enable_forwarding6(&record).map(drop).map_err(ApiError::from))
            .await
            .map_err(|e| e.context("turn IPv6 forwarding on"))
    }

    /// ufw's route rules for every network, added where missing (one
    /// `ufw show added`, then two `ufw route allow` per network without
    /// them), if this daemon keeps them. Failures are logged: ufw is
    /// another program's, and the networks work without it while it is
    /// inactive.
    async fn sync_ufw(&self) {
        if !self.ufw {
            return;
        }
        let bridges: Vec<String> = self.records().into_iter().map(|n| n.bridge).collect();
        let turn = self.ufw_turn.clone();
        let synced = blocking(move || -> ApiResult<()> {
            let _turn = turn.lock().unwrap_or_else(|e| e.into_inner());
            let added = ufw::added()?;
            for bridge in bridges.iter().filter(|b| !ufw::has_route_rules(&added, b)) {
                tracing::info!("ufw: routing {bridge}'s traffic (ufw route allow in/out on {bridge})");
                ufw::allow(bridge)?;
            }
            Ok(())
        })
        .await;
        if let Err(e) = synced {
            tracing::warn!("ufw: {e}");
        }
    }

    /// Adds (`allow`) or removes ufw's route rules for one bridge.
    async fn ufw_rules(&self, bridge: &str, allow: bool) {
        if !self.ufw {
            return;
        }
        let (bridge, turn) = (bridge.to_owned(), self.ufw_turn.clone());
        let changed = blocking(move || -> ApiResult<()> {
            let _turn = turn.lock().unwrap_or_else(|e| e.into_inner());
            if allow {
                tracing::info!("ufw: routing {bridge}'s traffic (ufw route allow in/out on {bridge})");
                ufw::allow(&bridge)?;
            } else {
                tracing::info!("ufw: removing {bridge}'s route rules");
                ufw::forget(&bridge)?;
            }
            Ok(())
        })
        .await;
        if let Err(e) = changed {
            tracing::warn!("ufw: {e}");
        }
    }

    pub fn records(&self) -> Vec<NetworkRecord> {
        self.state().networks.values().cloned().collect()
    }

    /// A network by id, unique id prefix, or name.
    pub fn find(&self, key: &str) -> ApiResult<NetworkRecord> {
        let st = self.state();
        if let Some(n) = st.networks.get(key) {
            return Ok(n.clone());
        }
        if let Some(n) = st.networks.values().find(|n| n.name == key) {
            return Ok(n.clone());
        }
        let matches: Vec<_> =
            if key.is_empty() { Vec::new() } else { st.networks.values().filter(|n| n.id.starts_with(key)).collect() };
        match matches.as_slice() {
            [n] => Ok((*n).clone()),
            [] => Err(ApiError::no_such_network(key)),
            _ => Err(ApiError::invalid(format!("{key} matches more than one network: give more of the id"))),
        }
    }

    /// Rebuilds the firewall from the networks and the published ports of
    /// every run, and applies it.
    pub async fn apply_firewall(&self) -> ApiResult<()> {
        let _turn = self.firewall.lock().await;
        let rules = {
            let st = self.state();
            Ruleset {
                table: self.table.clone(),
                networks: st
                    .networks
                    .values()
                    .filter_map(|n| {
                        let (subnet, subnet6) = subnets(n).ok()?;
                        Some(NetworkRules { bridge: n.bridge.clone(), subnet, subnet6, internal: n.internal })
                    })
                    .collect(),
                ports: st.live.values().flat_map(port_rules).collect(),
                isolate_forwarding: self.isolate_forwarding.load(Ordering::Relaxed),
                isolate_forwarding6: self.isolate_forwarding6.load(Ordering::Relaxed),
            }
        };
        let backend = self.backend.clone();
        blocking(move || backend.apply(&rules).map_err(ApiError::from))
            .await
            .map_err(|e| e.context("apply the firewall"))
    }

    /// The servers a container's embedded DNS server forwards to: `--dns`,
    /// else the host's. The server asks them from the host's namespace, so
    /// IPv6 ones are fine.
    fn upstreams(&self, dns: &[String]) -> Vec<SocketAddr> {
        let given: Vec<IpAddr> = dns.iter().filter_map(|s| s.parse().ok()).collect();
        let servers =
            if given.is_empty() { ResolvConf::host(&self.resolv_conf).reachable_servers(true) } else { given };
        servers.into_iter().map(|ip| SocketAddr::new(ip, 53)).collect()
    }

    /// The host's resolver configuration (`resolv_conf` in daemon.toml).
    pub fn resolv_conf_path(&self) -> &Path {
        &self.resolv_conf
    }

    /// The API's view of a network, with the runs on it.
    pub fn describe(&self, n: &NetworkRecord) -> Network {
        let st = self.state();
        let containers = st
            .live
            .iter()
            .filter_map(|(id, l)| {
                let e = l.endpoints.iter().find(|e| e.network_id == n.id)?;
                Some(NetworkEndpoint {
                    container_id: id.clone(),
                    container_name: l.name.clone(),
                    ip_address: e.ip.map(|ip| format!("{ip}/{}", e.prefix_len)).unwrap_or_default(),
                    ipv6_address: e.ip6.map(|ip| format!("{ip}/{}", e.prefix6.unwrap_or(64))),
                    mac_address: e.mac.clone(),
                    dns_names: e.dns_names.clone(),
                })
            })
            .collect();
        Network {
            id: n.id.clone(),
            name: n.name.clone(),
            driver: "bridge".into(),
            created: n.created.clone(),
            subnet: n.subnet.clone(),
            gateway: n.gateway.to_string(),
            ipv6: n.subnet6.is_some(),
            subnet6: n.subnet6.clone(),
            gateway6: n.gateway6.map(|g| g.to_string()),
            bridge: n.bridge.clone(),
            internal: n.internal,
            dns: n.name != DEFAULT_NETWORK,
            labels: n.labels.clone(),
            containers,
        }
    }

    /// Is any run on the network `id`?
    fn in_use(&self, id: &str) -> bool {
        self.state().used.get(id).is_some_and(|m| !m.is_empty())
    }

    pub fn count(&self) -> usize {
        self.state().networks.len()
    }

    /// Addresses for `container` on `network`: the ones `cfg` asks for, if
    /// they are free, else the next free ones; never one in `reserved`
    /// (another container's `--ip`). Taken at once (in `used`).
    fn allocate(
        &self,
        container: &str,
        network: &NetworkRecord,
        cfg: &EndpointConfig,
        reserved: &BTreeSet<IpAddr>,
    ) -> ApiResult<(Ipv4Addr, Option<Ipv6Addr>)> {
        let mut guard = self.state();
        let st = &mut *guard;
        let used = st.used.entry(network.id.clone()).or_default();
        let in_use_by = |used: &BTreeMap<IpAddr, String>, ip: IpAddr| {
            used.get(&ip).map(|id| {
                let name = st.live.get(id).map_or(rustlet_spec::short_id(id), |l| l.name.as_str());
                ApiError::conflict(format!("{ip} is in use on {} (by {name})", network.name))
            })
        };
        let (v4, v6) = st
            .allocators
            .get_mut(&network.id)
            .ok_or_else(|| ApiError::internal(format!("no addresses for the network {}", network.name)))?;
        let ip = match cfg.ipv4 {
            Some(ip) => match in_use_by(used, ip.into()) {
                Some(e) => return Err(e),
                None => ip,
            },
            None => v4
                .allocate(|ip| used.contains_key(&ip.into()) || reserved.contains(&ip.into()))
                .ok_or_else(|| ApiError::conflict(format!("the network {} has no free address left", network.name)))?,
        };
        let ip6 = match (v6, cfg.ipv6) {
            (None, _) => None,
            (Some(_), Some(ip6)) => match in_use_by(used, ip6.into()) {
                Some(e) => return Err(e),
                None => Some(ip6),
            },
            (Some(v6), None) => {
                Some(v6.allocate(|ip| used.contains_key(&ip.into()) || reserved.contains(&ip.into())).ok_or_else(
                    || ApiError::conflict(format!("the network {} has no free IPv6 address left", network.name)),
                )?)
            }
        };
        used.insert(ip.into(), container.to_owned());
        if let Some(ip6) = ip6 {
            used.insert(ip6.into(), container.to_owned());
        }
        Ok((ip, ip6))
    }

    /// Gives `e`'s addresses back, if they are still `container`'s.
    fn release(&self, container: &str, e: &EndpointRun) {
        let mut st = self.state();
        if let Some(used) = st.used.get_mut(&e.network_id) {
            for ip in addresses(e) {
                if used.get(&ip).map(String::as_str) == Some(container) {
                    used.remove(&ip);
                }
            }
        }
    }
}

/// What [`NetworkBackend::ensure_network`] makes of a network: its bridge,
/// gateway and prefix length, and its IPv6 gateway and prefix length.
type HostSide = (String, Ipv4Addr, u8, Option<(Ipv6Addr, u8)>);

/// A network's subnets.
fn subnets(n: &NetworkRecord) -> rustlet_net::Result<(Subnet, Option<Subnet6>)> {
    Ok((Subnet::parse(&n.subnet)?, n.subnet6.as_deref().map(Subnet6::parse).transpose()?))
}

/// An endpoint's addresses, IPv4 then IPv6.
fn addresses(e: &EndpointRun) -> impl Iterator<Item = IpAddr> + '_ {
    e.ip.map(IpAddr::V4).into_iter().chain(e.ip6.map(IpAddr::V6))
}

/// Will Rustlets have turned `name` (a forwarding sysctl) on, if it turns
/// it on now: what the record says it was, else what it is.
fn will_isolate(record: &Path, name: &str) -> ApiResult<bool> {
    let now = sysctl::read(&sysctl::path(name)).map_err(ApiError::from)?;
    Ok(sysctl::recorded(record, name).unwrap_or(now) == "0")
}

/// The DNAT rules of one run's published ports: IPv4 to its address on its
/// IPv4 route network, IPv6 (for every address, or an IPv6 one) to its
/// address on its IPv6 route network, if it has one. Loopback addresses
/// are the proxy's alone.
fn port_rules(l: &Live) -> Vec<PortRule> {
    let (v4, v6) = (route_v4(&l.endpoints), route_v6(&l.endpoints));
    let mut rules = Vec::new();
    for p in l.ports.iter().filter(|p| !p.host_ip.is_loopback()) {
        let rule = |e: &EndpointRun, container_ip: IpAddr, host_ip: Option<IpAddr>| PortRule {
            protocol: p.protocol.to_string(),
            host_ip,
            host_port: p.host_port,
            container_ip,
            container_port: p.container_port,
            bridge: e.bridge.clone(),
            container: l.name.clone(),
        };
        let specific = (!p.host_ip.is_unspecified()).then_some(p.host_ip);
        if p.host_ip.is_ipv4()
            && let Some(e) = v4
            && let Some(ip) = e.ip
        {
            rules.push(rule(e, ip.into(), specific));
        }
        // 0.0.0.0 is every address, IPv6 too.
        let six = p.host_ip.is_ipv6() || p.host_ip.is_unspecified();
        if six
            && let Some(e) = v6
            && let Some(ip6) = e.ip6
        {
            rules.push(rule(e, ip6.into(), specific.filter(IpAddr::is_ipv6)));
        }
    }
    rules
}

/// What `create` decides about a container's network.
#[derive(Debug, Default)]
pub struct NetworkChoice {
    /// `--network container:<x>`: `x`'s full id.
    pub container: Option<String>,
    /// The networks it is connected to, in order (none for `host`, `none`
    /// and `container:<x>`), each named by its name.
    pub endpoints: Vec<EndpointConfig>,
    /// `-p`, plus the image's exposed ports with `-P`.
    pub ports: Vec<PortMapping>,
    /// The hostname the mode implies (the host's, or the shared container's).
    pub hostname: Option<String>,
    pub warnings: Vec<String>,
}

impl Daemon {
    /// Checks a new container's network options against its mode, as
    /// Docker does: a container sharing another's namespace can't have
    /// ports, DNS options, extra hosts, a hostname, networks or addresses
    /// of its own; `host` and `none` don't combine with other networks;
    /// aliases and static addresses exist only on user-defined networks;
    /// ports are discarded (with a warning) in the host's namespace or with
    /// none.
    pub fn choose_network(&self, config: &ContainerConfig, image: &rustlet_image::Image) -> ApiResult<NetworkChoice> {
        for d in &config.dns {
            d.parse::<IpAddr>().map_err(|_| ApiError::invalid(format!("--dns {d:?} is not an IP address")))?;
        }
        for h in &config.extra_hosts {
            rustlet_spec::network::parse_extra_host(h).map_err(ApiError::invalid)?;
        }
        let mut ports = config.ports.clone();
        if config.publish_all {
            for exposed in image.config.config().and_then(|c| c.exposed_ports().clone()).unwrap_or_default() {
                let (port, proto) = exposed.split_once('/').unwrap_or((&exposed, "tcp"));
                let (Ok(container_port), Ok(protocol)) = (port.parse::<u16>(), proto.parse::<Protocol>()) else {
                    continue;
                };
                if !ports.iter().any(|p| p.container_port == container_port && p.protocol == protocol) {
                    ports.push(PortMapping { host_ip: None, host_port: None, container_port, protocol });
                }
            }
        }
        let mut choice = NetworkChoice::default();
        let own_options = [
            (!config.network_aliases.is_empty(), "--network-alias"),
            (config.ip.is_some(), "--ip"),
            (config.ip6.is_some(), "--ip6"),
            (!config.extra_networks.is_empty(), "another --network"),
        ];
        match &config.network {
            NetworkMode::Container(x) => {
                let conflicting = [
                    (!ports.is_empty(), "-p/-P"),
                    (
                        !config.dns.is_empty() || !config.dns_search.is_empty() || !config.dns_options.is_empty(),
                        "--dns",
                    ),
                    (!config.extra_hosts.is_empty(), "--add-host"),
                    (config.hostname.as_deref().is_some_and(|h| !h.is_empty()), "--hostname"),
                ];
                if let Some((_, flag)) = conflicting.iter().chain(&own_options).find(|(set, _)| *set) {
                    return Err(ApiError::invalid(format!(
                        "conflicting options: {flag} and --network container:{x} (it shares that container's network)"
                    )));
                }
                let target = self.find(x)?;
                choice.hostname = Some(target.record.hostname.clone());
                choice.container = Some(target.id().to_owned());
                return Ok(choice);
            }
            NetworkMode::Host | NetworkMode::None => {
                if let Some((_, flag)) = own_options.iter().find(|(set, _)| *set) {
                    return Err(ApiError::invalid(format!(
                        "conflicting options: {flag} and --network {} (no networks of its own)",
                        config.network
                    )));
                }
                if !ports.is_empty() {
                    choice.warnings.push(format!("published ports are discarded with --network {}", config.network));
                    ports.clear();
                }
                if config.network == NetworkMode::Host {
                    choice.hostname = nix::unistd::gethostname().ok().map(|h| h.to_string_lossy().into_owned());
                }
            }
            NetworkMode::Bridge | NetworkMode::Network(_) => {
                let mut records = Vec::new();
                for mut ep in EndpointConfig::from_config(config) {
                    let net = self.networks.find(&ep.network)?;
                    if records.iter().any(|n: &NetworkRecord| n.id == net.id) {
                        return Err(ApiError::invalid(format!("--network {} is given twice", net.name)));
                    }
                    check_endpoint(&net, &ep)?;
                    ep.network = net.name.clone();
                    choice.endpoints.push(ep);
                    records.push(net);
                }
                if !ports.is_empty() && records.iter().all(|n| n.internal) {
                    return Err(ApiError::invalid(format!(
                        "the network {} is internal (no route to or from the host): its containers can't publish ports",
                        records.iter().map(|n| n.name.as_str()).collect::<Vec<_>>().join(", ")
                    )));
                }
            }
        }
        choice.ports = ports;
        Ok(choice)
    }

    // ── networks ──────────────────────────────────────────────────────────

    pub async fn create_network(&self, req: NetworkCreate) -> ApiResult<NetworkRecord> {
        let name = req.name.trim().to_owned();
        if !rustlet_spec::valid_container_name(&name) {
            return Err(ApiError::invalid(format!(
                "invalid network name {name:?}: use [a-zA-Z0-9][a-zA-Z0-9_.-]*, at most 128 characters"
            )));
        }
        if RESERVED_NETWORK_NAMES.contains(&name.as_str()) {
            return Err(ApiError::invalid(format!("{name} is a network mode, not a name a network can have")));
        }
        if !req.ipv6 && (req.subnet6.is_some() || req.gateway6.is_some()) {
            return Err(ApiError::invalid("an IPv6 subnet or gateway needs ipv6 (--ipv6)"));
        }
        if req.ipv6 && !sysctl::ipv6_available() {
            return Err(ApiError::invalid("the host's kernel has IPv6 turned off (ipv6.disable=1)"));
        }
        let routes = blocking(|| link::routed_blocks().map_err(ApiError::from)).await?;
        let nets = &self.networks;
        let existing = nets.records();
        if existing.iter().any(|n| n.name == name) {
            return Err(ApiError::conflict(format!("a network named {name:?} exists already")));
        }
        let (subnet, gateway) = self.new_subnet(&req, &existing, &routes)?;
        let v6 = if req.ipv6 { Some(self.new_subnet6(&req, &existing, &routes)?) } else { None };
        let id = crate::names::new_id(|short| existing.iter().any(|n| rustlet_spec::short_id(&n.id) == short));
        let record = NetworkRecord {
            bridge: format!("rlb{}", rustlet_spec::short_id(&id)),
            id,
            name,
            created: rustlet_shim::logfile::now(),
            subnet: subnet.to_string(),
            gateway,
            subnet6: v6.map(|(s, _)| s.to_string()),
            gateway6: v6.map(|(_, g)| g),
            internal: req.internal,
            labels: req.labels,
        };
        self.db.insert_network(&record)?;
        let (bridge, len, backend) = (record.bridge.clone(), subnet.prefix_len(), nets.backend.clone());
        let gw6 = v6.map(|(s, g)| (g, s.prefix_len()));
        if let Err(e) =
            blocking(move || backend.ensure_network(&bridge, gateway, len, gw6).map_err(ApiError::from)).await
        {
            let _ = self.db.remove_network(&record.id);
            let (bridge, backend) = (record.bridge.clone(), nets.backend.clone());
            let _ = blocking(move || backend.remove_network(&bridge).map_err(ApiError::from)).await;
            return Err(e.context(format!("create network {}", record.name)));
        }
        {
            let mut st = nets.state();
            let v6 = v6.map(|(s, g)| Allocator6::new(s, g));
            st.allocators.insert(record.id.clone(), (Allocator::new(subnet, gateway), v6));
            st.networks.insert(record.id.clone(), record.clone());
        }
        let applied = if v6.is_some() { nets.enable_ipv6_forwarding().await } else { nets.apply_firewall().await };
        if let Err(e) = applied {
            tracing::warn!("{e}");
        }
        nets.ufw_rules(&record.bridge, true).await;
        self.events.emit(EventKind::Network, "create", &record.id, [("name".to_owned(), record.name.clone())].into());
        Ok(record)
    }

    /// A new network's IPv4 subnet and gateway: as asked (if it overlaps
    /// nothing), else the pool's next free /24 and its first address.
    fn new_subnet(
        &self,
        req: &NetworkCreate,
        existing: &[NetworkRecord],
        routes: &[(IpAddr, u8)],
    ) -> ApiResult<(Subnet, Ipv4Addr)> {
        let routes: Vec<(Ipv4Addr, u8)> = routes
            .iter()
            .filter_map(|(a, l)| match a {
                IpAddr::V4(a) => Some((*a, *l)),
                IpAddr::V6(_) => None,
            })
            .collect();
        let theirs = |n: &NetworkRecord| Subnet::parse(&n.subnet).ok();
        let subnet = match &req.subnet {
            Some(s) => {
                let subnet = Subnet::parse(s).map_err(|e| ApiError::invalid(e.to_string()))?;
                if let Some(n) = existing.iter().find(|n| theirs(n).is_some_and(|t| t.overlaps(&subnet))) {
                    return Err(ApiError::conflict(format!("{subnet} overlaps the network {} ({})", n.name, n.subnet)));
                }
                if let Some((a, l)) = routes.iter().find(|(a, l)| subnet.overlaps_block(*a, *l)) {
                    return Err(ApiError::conflict(format!("{subnet} overlaps the host's route to {a}/{l}")));
                }
                subnet
            }
            None => {
                let taken = |s: &Subnet| {
                    existing.iter().any(|n| theirs(n).is_some_and(|t| t.overlaps(s)))
                        || routes.iter().any(|(a, l)| s.overlaps_block(*a, *l))
                };
                ipam::free_subnet(self.networks.pool, 24, taken).ok_or_else(|| {
                    ApiError::conflict(format!("no free /24 left in the pool {}: give a --subnet", self.networks.pool))
                })?
            }
        };
        let gateway = match &req.gateway {
            Some(g) => {
                let ip: Ipv4Addr = g.parse().map_err(|_| ApiError::invalid(format!("{g:?} is not an IPv4 address")))?;
                if !subnet.is_host(ip) {
                    return Err(ApiError::invalid(format!("the gateway {ip} isn't a host address of {subnet}")));
                }
                ip
            }
            None => subnet.first_host(),
        };
        Ok((subnet, gateway))
    }

    /// A new network's IPv6 subnet and gateway: as asked, else the IPv6
    /// pool's next free /64 and its first address.
    fn new_subnet6(
        &self,
        req: &NetworkCreate,
        existing: &[NetworkRecord],
        routes: &[(IpAddr, u8)],
    ) -> ApiResult<(Subnet6, Ipv6Addr)> {
        let routes: Vec<(Ipv6Addr, u8)> = routes
            .iter()
            .filter_map(|(a, l)| match a {
                IpAddr::V6(a) => Some((*a, *l)),
                IpAddr::V4(_) => None,
            })
            .collect();
        let theirs = |n: &NetworkRecord| n.subnet6.as_deref().and_then(|s| Subnet6::parse(s).ok());
        let subnet = match &req.subnet6 {
            Some(s) => {
                let subnet = Subnet6::parse(s).map_err(|e| ApiError::invalid(e.to_string()))?;
                if let Some((n, t)) =
                    existing.iter().find_map(|n| theirs(n).filter(|t| t.overlaps(&subnet)).map(|t| (n, t)))
                {
                    return Err(ApiError::conflict(format!("{subnet} overlaps the network {} ({t})", n.name)));
                }
                if let Some((a, l)) = routes.iter().find(|(a, l)| subnet.overlaps_block(*a, *l)) {
                    return Err(ApiError::conflict(format!("{subnet} overlaps the host's route to {a}/{l}")));
                }
                subnet
            }
            None => {
                let taken = |s: &Subnet6| {
                    existing.iter().any(|n| theirs(n).is_some_and(|t| t.overlaps(s)))
                        || routes.iter().any(|(a, l)| s.overlaps_block(*a, *l))
                };
                ipam::free_subnet6(self.networks.pool6, 64, taken).ok_or_else(|| {
                    ApiError::conflict(format!(
                        "no free /64 left in the IPv6 pool {}: give an IPv6 --subnet",
                        self.networks.pool6
                    ))
                })?
            }
        };
        let gateway = match &req.gateway6 {
            Some(g) => {
                let ip: Ipv6Addr = g.parse().map_err(|_| ApiError::invalid(format!("{g:?} is not an IPv6 address")))?;
                if !subnet.is_host(ip) {
                    return Err(ApiError::invalid(format!("the gateway {ip} isn't a host address of {subnet}")));
                }
                ip
            }
            None => subnet.first_host(),
        };
        Ok((subnet, gateway))
    }

    pub async fn remove_network(&self, key: &str) -> ApiResult<()> {
        let n = self.networks.find(key)?;
        if n.name == DEFAULT_NETWORK {
            return Err(ApiError::conflict("the default network can't be removed"));
        }
        if self.networks.in_use(&n.id) {
            return Err(ApiError::conflict(format!("network {} has running containers: stop them first", n.name)));
        }
        self.db.remove_network(&n.id)?;
        {
            let mut st = self.networks.state();
            st.networks.remove(&n.id);
            st.allocators.remove(&n.id);
            st.used.remove(&n.id);
        }
        let (bridge, backend) = (n.bridge.clone(), self.networks.backend.clone());
        if let Err(e) = blocking(move || backend.remove_network(&bridge).map_err(ApiError::from)).await {
            tracing::warn!("delete the bridge {}: {e}", n.bridge);
        }
        if let Err(e) = self.networks.apply_firewall().await {
            tracing::warn!("{e}");
        }
        self.networks.ufw_rules(&n.bridge, false).await;
        self.events.emit(EventKind::Network, "destroy", &n.id, [("name".to_owned(), n.name.clone())].into());
        Ok(())
    }

    /// Removes the user-defined networks no container refers to.
    pub async fn prune_networks(&self) -> ApiResult<PruneResponse> {
        let referenced: BTreeSet<String> =
            self.all_containers().iter().flat_map(|c| c.endpoint_configs().into_iter().map(|e| e.network)).collect();
        let mut deleted = Vec::new();
        for n in self.networks.records() {
            if n.name == DEFAULT_NETWORK || referenced.contains(&n.name) || self.networks.in_use(&n.id) {
                continue;
            }
            self.remove_network(&n.id).await?;
            deleted.push(n.name);
        }
        Ok(PruneResponse { deleted, space_reclaimed: 0 })
    }

    // ── connect and disconnect ────────────────────────────────────────────

    /// `network connect`: the container joins the network at once if it
    /// runs, and from its next start in any case.
    pub async fn connect_network(self: &Arc<Self>, key: &str, req: NetworkConnect) -> ApiResult<()> {
        let network = self.networks.find(key)?;
        let c = self.find(&req.container)?;
        let _op = c.op.lock().await;
        check_connectable(&c)?;
        let mut configs = c.endpoint_configs();
        if configs.iter().any(|e| e.network == network.name) {
            return Err(ApiError::conflict(format!(
                "container {} is already connected to network {}",
                c.record.name, network.name
            )));
        }
        let cfg = EndpointConfig {
            network: network.name.clone(),
            aliases: req.aliases,
            ipv4: req.ipv4_address,
            ipv6: req.ipv6_address,
        };
        check_endpoint(&network, &cfg)?;
        if c.status().is_live()
            && let Some(run) = c.persisted().network
        {
            self.connect_live(&c, run, &network, &cfg).await?;
        }
        configs.push(cfg);
        c.update(&self.db, |s| s.networks = Some(configs))
    }

    /// `network disconnect`: the container leaves the network, at once if
    /// it runs. With `force`, a network that is gone can still be left
    /// (named as the container's record has it).
    pub async fn disconnect_network(self: &Arc<Self>, key: &str, req: NetworkDisconnect) -> ApiResult<()> {
        let c = self.find(&req.container)?;
        let network = match self.networks.find(key) {
            Ok(n) => Some(n),
            Err(e) if req.force => {
                tracing::debug!("disconnect {} from {key}: {e}", c.record.name);
                None
            }
            Err(e) => return Err(e),
        };
        let name = network.as_ref().map_or(key, |n| n.name.as_str()).to_owned();
        let _op = c.op.lock().await;
        let mut configs = c.endpoint_configs();
        let Some(index) = configs.iter().position(|e| e.network == name) else {
            return Err(ApiError::conflict(format!("container {} is not connected to network {name}", c.record.name)));
        };
        if c.status().is_live()
            && let Some(run) = c.persisted().network
            && let Some(at) = run.endpoints.iter().position(|e| e.network_name == name)
        {
            self.disconnect_live(&c, run, at).await?;
        }
        configs.remove(index);
        c.update(&self.db, |s| s.networks = Some(configs))
    }

    /// One more network for a running container: its endpoint recorded,
    /// then made; then its routes, DNS, ports and files follow.
    async fn connect_live(
        self: &Arc<Self>,
        c: &Container,
        mut run: NetRun,
        network: &NetworkRecord,
        cfg: &EndpointConfig,
    ) -> ApiResult<()> {
        let pin = run.netns.clone().ok_or_else(|| ApiError::internal("a running container without its namespace"))?;
        let ep = self.plan_endpoint(c, &run.endpoints, network, cfg)?;
        run.endpoints.push(ep.clone());
        // Recorded first: a daemon that dies now leaves the next one the
        // record (it holds the addresses), not a veth nobody knows of.
        if let Err(e) = c.update(&self.db, |s| s.network = Some(run.clone())) {
            self.networks.release(c.id(), &ep);
            return Err(e);
        }
        let made = self.make_endpoint(c, &pin, &ep).await;
        let followed = match made {
            Ok(()) => self.follow_endpoints(c, &pin, &run).await,
            Err(e) => Err(e),
        };
        if let Err(e) = followed {
            // Back to what it was.
            run.endpoints.pop();
            self.unmake_endpoint(c, &ep).await;
            if let Err(e) = self.follow_endpoints(c, &pin, &run).await {
                tracing::warn!(id = %c.id(), "restore its network: {e}");
            }
            let _ = c.update(&self.db, |s| s.network = Some(run));
            return Err(e.context(format!("connect {} to {}", c.record.name, network.name)));
        }
        self.emit_endpoint(c, &ep, "connect");
        Ok(())
    }

    /// A running container's endpoint `at`, undone; then its routes, DNS,
    /// ports and files follow.
    async fn disconnect_live(self: &Arc<Self>, c: &Container, mut run: NetRun, at: usize) -> ApiResult<()> {
        let pin = run.netns.clone().ok_or_else(|| ApiError::internal("a running container without its namespace"))?;
        let ep = run.endpoints.remove(at);
        self.unmake_endpoint(c, &ep).await;
        c.update(&self.db, |s| s.network = Some(run.clone()))?;
        self.follow_endpoints(c, &pin, &run).await?;
        self.emit_endpoint(c, &ep, "disconnect");
        Ok(())
    }

    /// What follows a change to a running container's endpoints: its live
    /// entry, default routes, DNS server, published ports' targets, the
    /// firewall, and its `hosts` and `resolv.conf`.
    async fn follow_endpoints(self: &Arc<Self>, c: &Container, pin: &Path, run: &NetRun) -> ApiResult<()> {
        if let Some(live) = self.networks.state().live.get_mut(c.id()) {
            live.endpoints = run.endpoints.clone();
            retarget(&live.proxies, &live.endpoints);
        }
        self.set_routes(pin, &run.endpoints).await?;
        self.refresh_dns(c, pin, &run.endpoints).await?;
        self.networks.apply_firewall().await?;
        let [hosts, _, resolv] = self.etc_files(c, run);
        let dir = self.paths.container_dir(c.id());
        for (name, text) in [("hosts", hosts), ("resolv.conf", resolv)] {
            // In place: the container's bind mount shows this very file.
            let path = dir.join(name);
            std::fs::write(&path, text).map_err(|e| ApiError::internal(format!("write {}: {e}", path.display())))?;
        }
        Ok(())
    }

    // ── a run's network ───────────────────────────────────────────────────

    /// Sets up the network of a run of `c`, before its shim exists.
    pub async fn attach_network(self: &Arc<Self>, c: &Container) -> ApiResult<NetRun> {
        let r = &c.record;
        match &r.config.network {
            NetworkMode::Host => Ok(NetRun::default()),
            NetworkMode::Container(_) => {
                let target_id = r
                    .network_container
                    .clone()
                    .ok_or_else(|| ApiError::internal("no container recorded for --network container:"))?;
                let target = self.find(&target_id).map_err(|_| {
                    ApiError::conflict(format!("the container whose network {} shares is gone", r.name))
                })?;
                if !target.status().is_live() {
                    return Err(ApiError::conflict(format!(
                        "cannot join the network of {}: it is not running",
                        target.record.name
                    )));
                }
                let theirs = target.persisted().network.unwrap_or_default();
                Ok(NetRun { netns: theirs.netns, joined: Some(target.id().to_owned()), ..NetRun::default() })
            }
            NetworkMode::Bridge | NetworkMode::None | NetworkMode::Network(_) => {
                let mut run = NetRun { netns: Some(self.paths.netns_pin(c.id())), ..NetRun::default() };
                match self.connect_run(c, &mut run).await {
                    Ok(()) => Ok(run),
                    Err(e) => {
                        self.detach_network(c, &run).await;
                        Err(e)
                    }
                }
            }
        }
    }

    /// The steps of [`Daemon::attach_network`] for a namespace of the run's
    /// own, recording each in `run` as it is done (so that a failure can
    /// undo exactly what was done).
    async fn connect_run(self: &Arc<Self>, c: &Container, run: &mut NetRun) -> ApiResult<()> {
        let pin = run.netns.clone().expect("a namespace of its own");
        {
            let pin = pin.clone();
            blocking(move || {
                // What a run cut short may have left.
                netns::remove(&pin)?;
                netns::create(&pin, || {
                    link::loopback_up()?;
                    sysctl::set_netns_defaults()
                })
            })
            .await
            .map_err(|e: ApiError| e.context("create the container's network namespace"))?;
        }
        self.networks.state().live.insert(
            c.id().to_owned(),
            Live {
                name: c.record.name.clone(),
                endpoints: Vec::new(),
                ports: Vec::new(),
                dns: None,
                proxies: Vec::new(),
            },
        );
        for cfg in c.endpoint_configs() {
            let network =
                self.networks.find(&cfg.network).map_err(|e| e.context(format!("container {}", c.record.name)))?;
            let ep = self.plan_endpoint(c, &run.endpoints, &network, &cfg)?;
            if let Err(e) = self.make_endpoint(c, &pin, &ep).await {
                self.networks.release(c.id(), &ep);
                return Err(e);
            }
            run.endpoints.push(ep);
            if let Some(live) = self.networks.state().live.get_mut(c.id()) {
                live.endpoints = run.endpoints.clone();
            }
        }
        self.set_routes(&pin, &run.endpoints).await?;
        self.refresh_dns(c, &pin, &run.endpoints).await?;
        let (ports, proxies) = publish(&c.record.ports, &run.endpoints)?;
        run.ports = ports.clone();
        if let Some(live) = self.networks.state().live.get_mut(c.id()) {
            live.ports = ports;
            live.proxies = proxies;
        }
        self.networks.apply_firewall().await?;
        for ep in &run.endpoints {
            self.emit_endpoint(c, ep, "connect");
        }
        Ok(())
    }

    /// A container's endpoint on `network`, decided (addresses taken, names
    /// chosen) but not yet made: the lowest `ethN` the run doesn't have, the
    /// host end's name from the two ids.
    fn plan_endpoint(
        &self,
        c: &Container,
        current: &[EndpointRun],
        network: &NetworkRecord,
        cfg: &EndpointConfig,
    ) -> ApiResult<EndpointRun> {
        check_endpoint(network, cfg)?;
        let (subnet, subnet6) = subnets(network).map_err(|e| ApiError::internal(e.to_string()))?;
        let reserved = self.static_addresses(&network.name, c.id());
        let (ip, ip6) = self.networks.allocate(c.id(), network, cfg, &reserved)?;
        let ifname = (0..)
            .map(link::container_ifname)
            .find(|name| !current.iter().any(|e| &e.ifname == name))
            .expect("a free interface name");
        let dns_names = if network.name == DEFAULT_NETWORK { Vec::new() } else { dns_names(c, &cfg.aliases) };
        Ok(EndpointRun {
            network_id: network.id.clone(),
            network_name: network.name.clone(),
            bridge: network.bridge.clone(),
            internal: network.internal,
            ifname,
            veth: link::host_ifname(c.id(), &network.id),
            mac: ipam::format_mac(&ipam::mac_for(ip)),
            ip: Some(ip),
            prefix_len: subnet.prefix_len(),
            gateway: Some(network.gateway),
            ip6,
            prefix6: subnet6.map(|s| s.prefix_len()),
            gateway6: subnet6.map(|s| network.gateway6.unwrap_or_else(|| s.first_host())),
            dns_names,
        })
    }

    /// Makes a planned endpoint: the veth and the interface inside, and its
    /// names in the zone.
    async fn make_endpoint(&self, c: &Container, pin: &Path, ep: &EndpointRun) -> ApiResult<()> {
        let ip = ep.ip.ok_or_else(|| ApiError::internal("an endpoint without an IPv4 address"))?;
        let (pin, e, backend) = (pin.to_owned(), ep.clone(), self.networks.backend.clone());
        let alias = link::endpoint_alias(c.id(), &ep.network_id);
        let mac = ipam::mac_for(ip);
        blocking(move || {
            let ns = netns::open(&pin)?;
            let endpoint = link::Endpoint {
                host_ifname: &e.veth,
                alias: &alias,
                ifname: &e.ifname,
                bridge: &e.bridge,
                address: ip,
                prefix_len: e.prefix_len,
                address6: e.ip6.zip(e.prefix6),
                mac,
            };
            backend.connect(ns.as_fd(), &endpoint)
        })
        .await
        .map_err(|e: ApiError| e.context(format!("connect it to {}", ep.network_name)))?;
        if !ep.dns_names.is_empty() {
            for addr in addresses(ep) {
                self.networks.zone.add(&ep.network_name, addr, &ep.dns_names);
            }
        }
        Ok(())
    }

    /// Undoes [`Daemon::make_endpoint`] and gives its addresses back. Never
    /// fails; what can't be undone is logged.
    async fn unmake_endpoint(&self, c: &Container, ep: &EndpointRun) {
        for addr in addresses(ep) {
            self.networks.zone.remove(&ep.network_name, addr);
        }
        let (veth, backend) = (ep.veth.clone(), self.networks.backend.clone());
        if let Err(e) = blocking(move || backend.disconnect(&veth).map_err(ApiError::from)).await {
            tracing::warn!(id = %c.id(), "delete {}: {e}", ep.veth);
        }
        self.networks.release(c.id(), ep);
    }

    /// The default routes of a run's namespace: through its first network
    /// with a way out (for IPv6, the first such one with IPv6).
    async fn set_routes(&self, pin: &Path, endpoints: &[EndpointRun]) -> ApiResult<()> {
        let v4 = route_v4(endpoints).and_then(|e| Some((e.gateway?, e.ifname.clone())));
        let v6 = route_v6(endpoints).and_then(|e| Some((e.gateway6?, e.ifname.clone())));
        let (pin, backend) = (pin.to_owned(), self.networks.backend.clone());
        blocking(move || {
            let ns = netns::open(&pin)?;
            backend.set_default_routes(
                ns.as_fd(),
                v4.as_ref().map(|(gw, i)| (*gw, i.as_str())),
                v6.as_ref().map(|(gw, i)| (*gw, i.as_str())),
            )
        })
        .await
        .map_err(|e: ApiError| e.context("set its default routes"))
    }

    /// Every address another container asked for on the network `name`
    /// (`--ip`, `--ip6`, `network connect --ip`), running or not: the
    /// dynamic allocation leaves them free for their owners.
    fn static_addresses(&self, name: &str, except: &str) -> BTreeSet<IpAddr> {
        self.all_containers()
            .iter()
            .filter(|c| c.id() != except)
            .flat_map(|c| c.endpoint_configs())
            .filter(|e| e.network == name)
            .flat_map(|e| e.ipv4.map(IpAddr::V4).into_iter().chain(e.ipv6.map(IpAddr::V6)))
            .collect()
    }

    fn emit_endpoint(&self, c: &Container, ep: &EndpointRun, action: &str) {
        self.events.emit(
            EventKind::Network,
            action,
            &ep.network_id,
            [("name".to_owned(), ep.network_name.clone()), ("container".to_owned(), c.id().to_owned())].into(),
        );
    }

    /// The scope of a run's DNS server: its user-defined networks in order,
    /// and where the rest goes (nowhere if no network has a way out).
    fn dns_scope(&self, c: &Container, endpoints: &[EndpointRun]) -> Scope {
        Scope {
            networks: endpoints
                .iter()
                .filter(|e| e.network_name != DEFAULT_NETWORK)
                .map(|e| e.network_name.clone())
                .collect(),
            upstreams: if endpoints.iter().any(|e| !e.internal) {
                self.networks.upstreams(&c.record.config.dns)
            } else {
                Vec::new()
            },
        }
    }

    /// A run's DNS server as its networks now want it: started for its
    /// first user-defined network, rescoped as they change, stopped (and
    /// the `:53` redirect removed) when it has none left.
    async fn refresh_dns(&self, c: &Container, pin: &Path, endpoints: &[EndpointRun]) -> ApiResult<()> {
        let wanted = endpoints.iter().any(|e| e.network_name != DEFAULT_NETWORK);
        let view = self.networks.state().live.get(c.id()).and_then(|l| l.dns.as_ref().map(|d| d.view.clone()));
        match (wanted, view) {
            (true, Some(view)) => view.set_scope(self.dns_scope(c, endpoints)),
            (true, None) => {
                let dns = self.start_dns(c, pin, endpoints).await?;
                if let Some(live) = self.networks.state().live.get_mut(c.id()) {
                    live.dns = Some(dns);
                }
            }
            (false, Some(_)) => {
                let dns = self.networks.state().live.get_mut(c.id()).and_then(|l| l.dns.take());
                if let Some(dns) = dns {
                    dns.server.close().await;
                }
                let pin = pin.to_owned();
                blocking(move || netns::run_in_pinned(&pin, firewall::remove_dns_redirect))
                    .await
                    .map_err(|e: ApiError| e.context("remove the DNS redirect"))?;
            }
            (false, None) => {}
        }
        Ok(())
    }

    /// The embedded DNS server of a run on user-defined networks: its
    /// sockets made inside the namespace, port 53 redirected to them.
    async fn start_dns(&self, c: &Container, pin: &Path, endpoints: &[EndpointRun]) -> ApiResult<RunDns> {
        let pin = pin.to_owned();
        let (udp, tcp) = blocking(move || {
            netns::run_in_pinned(&pin, || {
                let at = SocketAddr::new(IpAddr::V4(firewall::DNS_ADDR), 0);
                let udp = std::net::UdpSocket::bind(at).context("bind the DNS server's UDP socket")?;
                let tcp = std::net::TcpListener::bind(at).context("bind the DNS server's TCP socket")?;
                let ports = (port_of(udp.local_addr()), port_of(tcp.local_addr()));
                firewall::run_nft(&firewall::dns_redirect(ports.0, ports.1))?;
                Ok((udp, tcp))
            })
        })
        .await
        .map_err(|e| e.context("start the embedded DNS server"))?;
        let view = View::new(self.networks.zone.clone(), self.dns_scope(c, endpoints));
        let server = DnsServer::spawn(udp, tcp, view.clone())
            .map_err(|e| ApiError::internal(format!("start the embedded DNS server: {e}")))?;
        Ok(RunDns { server, view })
    }

    /// Undoes a run's network, whatever part of it exists: its servers and
    /// rules, its addresses, its veths, its pin. Never fails; what can't be
    /// undone is logged.
    pub async fn detach_network(&self, c: &Container, run: &NetRun) {
        // Its DNS server and proxies, closed before anything else: a start
        // right after (a restart) may want the same port.
        let live = self.networks.state().live.remove(c.id());
        let had_ports = live.as_ref().is_some_and(|l| !l.ports.is_empty()) || !run.ports.is_empty();
        if let Some(live) = live {
            if let Some(dns) = live.dns {
                dns.server.close().await;
            }
            for p in live.proxies {
                p.proxy.close().await;
            }
        }
        for ep in &run.endpoints {
            for addr in addresses(ep) {
                self.networks.zone.remove(&ep.network_name, addr);
            }
            self.networks.release(c.id(), ep);
        }
        if had_ports && let Err(e) = self.networks.apply_firewall().await {
            tracing::warn!(id = %c.id(), "{e}");
        }
        let veths: Vec<String> = run.endpoints.iter().map(|e| e.veth.clone()).collect();
        let pin = run.netns.clone().filter(|_| run.joined.is_none());
        let backend = self.networks.backend.clone();
        let undone = blocking(move || {
            for v in &veths {
                backend.disconnect(v)?;
            }
            if let Some(p) = &pin {
                netns::remove(p)?;
            }
            Ok::<_, rustlet_net::Error>(())
        })
        .await;
        if let Err(e) = undone {
            tracing::warn!(id = %c.id(), "undo its network: {e}");
        }
        for ep in &run.endpoints {
            self.emit_endpoint(c, ep, "disconnect");
        }
    }

    /// What a run cut short left without a record: a pin named by the
    /// container's id, veths tagged with it.
    pub async fn remove_network_leftovers(&self, id: &str) {
        let pin = self.paths.netns_pin(id);
        let tag = link::container_tag(id);
        let backend = self.networks.backend.clone();
        let _ = blocking(move || {
            backend.disconnect_tagged(&tag)?;
            netns::remove(&pin)
        })
        .await
        .inspect_err(|e: &ApiError| tracing::warn!(%id, "remove what its last run left: {e}"));
    }

    /// A run the daemon takes over: new DNS sockets and proxies (the last
    /// daemon's went with it). Its addresses, names and port rules were
    /// restored at startup.
    pub async fn resume_network(self: &Arc<Self>, c: &Container, run: &NetRun) {
        let Some(pin) = run.netns.as_deref().filter(|_| run.joined.is_none()) else { return };
        // As restored (filled in from the networks).
        let endpoints = self.networks.state().live.get(c.id()).map(|l| l.endpoints.clone()).unwrap_or_default();
        let dns = if endpoints.iter().any(|e| e.network_name != DEFAULT_NETWORK) {
            match self.start_dns(c, pin, &endpoints).await {
                Ok(s) => Some(s),
                Err(e) => {
                    tracing::warn!(id = %c.id(), "{e}");
                    None
                }
            }
        } else {
            None
        };
        let proxies = match rebind(&run.ports, &endpoints) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(id = %c.id(), "published ports are reachable through DNAT only: {e}");
                Vec::new()
            }
        };
        if let Some(live) = self.networks.state().live.get_mut(c.id()) {
            live.dns = dns;
            live.proxies = proxies;
        }
    }

    /// A run's `/etc/hosts`, `/etc/hostname` and `/etc/resolv.conf` (for a
    /// run with a namespace of its own, or the host's).
    pub fn etc_files(&self, c: &Container, net: &NetRun) -> [String; 3] {
        let r = &c.record;
        let mode = &r.config.network;
        let gateway = route_v4(&net.endpoints)
            .or(net.endpoints.first())
            .and_then(|e| e.gateway)
            .or_else(|| self.networks.find(DEFAULT_NETWORK).ok().map(|n| n.gateway));
        let extra: Vec<(String, String)> = r
            .config
            .extra_hosts
            .iter()
            .filter_map(|h| rustlet_spec::network::parse_extra_host(h).ok())
            .map(|(name, ip)| {
                let ip = if ip == rustlet_spec::network::HOST_GATEWAY {
                    gateway.map(|g| g.to_string()).unwrap_or(ip)
                } else {
                    ip
                };
                (name, ip)
            })
            .collect();
        let hosts = match mode {
            NetworkMode::Host => rustlet_net::files::host_network_hosts(
                &std::fs::read_to_string("/etc/hosts").unwrap_or_default(),
                &extra,
            ),
            _ => {
                let own: Vec<IpAddr> = net.endpoints.iter().flat_map(addresses).collect();
                rustlet_net::files::hosts(&own, std::slice::from_ref(&r.hostname), &extra)
            }
        };
        let resolver = match mode {
            NetworkMode::Host => rustlet_net::files::Resolver::Host,
            _ if net.endpoints.iter().any(|e| e.network_name != DEFAULT_NETWORK) => {
                rustlet_net::files::Resolver::Embedded
            }
            _ => rustlet_net::files::Resolver::Direct,
        };
        let dns = rustlet_net::files::DnsOptions {
            servers: r.config.dns.iter().filter_map(|d| d.parse().ok()).collect(),
            search: r.config.dns_search.clone(),
            options: r.config.dns_options.clone(),
        };
        let ipv6 = net.endpoints.iter().any(|e| e.ip6.is_some());
        let resolv = rustlet_net::files::container_resolv_conf(self.networks.resolv_conf_path(), &dns, resolver, ipv6);
        [hosts, format!("{}\n", r.hostname), resolv]
    }

    /// Who owns the files of [`Daemon::etc_files`]: container root, host
    /// uid 1000000 under `--userns=remap`, so it may edit them, as in
    /// Docker.
    pub fn etc_owner(&self, c: &Container) -> Option<u32> {
        (c.record.config.userns == UsernsMode::Remap).then_some(rustlet_runtime::spec::REMAP_HOST_ID)
    }
}

/// Can `c` be connected to (or disconnected from) networks? Not one that
/// shares another's namespace or the host's, nor `none`'s, nor one being
/// removed (Docker's rules).
fn check_connectable(c: &Container) -> ApiResult<()> {
    match &c.record.config.network {
        NetworkMode::Bridge | NetworkMode::Network(_) => {}
        mode => {
            return Err(ApiError::invalid(format!(
                "container {} is on --network {mode}: it has no networks of its own to connect",
                c.record.name
            )));
        }
    }
    if matches!(c.status(), ContainerStatus::Removing | ContainerStatus::Dead) {
        return Err(ApiError::conflict(format!("container {} is being removed", c.record.name)));
    }
    Ok(())
}

/// What may be asked of a network: aliases and static addresses only on a
/// user-defined one (Docker's rule), an IPv6 address only on one with IPv6,
/// and addresses that are its hosts' (not the gateway's).
fn check_endpoint(net: &NetworkRecord, ep: &EndpointConfig) -> ApiResult<()> {
    let user_defined = net.name != DEFAULT_NETWORK;
    if let Some(a) = ep.aliases.iter().find(|a| !rustlet_spec::network::valid_hostname(a)) {
        return Err(ApiError::invalid(format!("--network-alias {a:?} is not a host name")));
    }
    if !ep.aliases.is_empty() && !user_defined {
        return Err(ApiError::invalid("--network-alias: network-scoped aliases exist only on user-defined networks"));
    }
    if (ep.ipv4.is_some() || ep.ipv6.is_some()) && !user_defined {
        return Err(ApiError::invalid(format!(
            "--ip and --ip6 are for user-defined networks only: {} hands out its own addresses",
            net.name
        )));
    }
    let (subnet, subnet6) = subnets(net).map_err(|e| ApiError::internal(e.to_string()))?;
    if let Some(ip) = ep.ipv4 {
        if !subnet.is_host(ip) {
            return Err(ApiError::invalid(format!("{ip} is not an address of {} ({subnet})", net.name)));
        }
        if ip == net.gateway {
            return Err(ApiError::invalid(format!("{ip} is the gateway of {}", net.name)));
        }
    }
    if let Some(ip6) = ep.ipv6 {
        let Some(subnet6) = subnet6 else {
            return Err(ApiError::invalid(format!(
                "--ip6: the network {} has no IPv6 (create it with --ipv6)",
                net.name
            )));
        };
        if !subnet6.is_host(ip6) {
            return Err(ApiError::invalid(format!("{ip6} is not an address of {} ({subnet6})", net.name)));
        }
        if ip6 == net.gateway6.unwrap_or_else(|| subnet6.first_host()) {
            return Err(ApiError::invalid(format!("{ip6} is the gateway of {}", net.name)));
        }
    }
    Ok(())
}

/// The names a container answers to on a user-defined network: its name,
/// short id, hostname and its aliases there, lowercased, each once.
fn dns_names(c: &Container, aliases: &[String]) -> Vec<String> {
    let r = &c.record;
    let mut names = vec![r.name.clone(), rustlet_spec::short_id(&r.id).to_owned(), r.hostname.clone()];
    names.extend(aliases.iter().cloned());
    let mut out: Vec<String> = Vec::new();
    for n in names.into_iter().map(|n| n.to_ascii_lowercase()) {
        if !n.is_empty() && !out.contains(&n) {
            out.push(n);
        }
    }
    out
}

fn port_of(addr: std::io::Result<SocketAddr>) -> u16 {
    addr.map(|a| a.port()).unwrap_or(0)
}

/// Where a proxy bound to an IPv6 (`v6`) or IPv4 address relays to: the
/// container's address on its route network of that family, an IPv6
/// client falling back to the IPv4 one; `None` without a route network.
fn backend_for(v6: bool, container_port: u16, endpoints: &[EndpointRun]) -> Option<SocketAddr> {
    if v6 && let Some(ip6) = route_v6(endpoints).and_then(|e| e.ip6) {
        return Some(SocketAddr::new(ip6.into(), container_port));
    }
    route_v4(endpoints).and_then(|e| e.ip).map(|ip| SocketAddr::new(ip.into(), container_port))
}

/// Points every proxy at where `endpoints` now say it leads.
fn retarget(proxies: &[PortProxy], endpoints: &[EndpointRun]) {
    for p in proxies {
        p.backend.set(backend_for(p.v6, p.container_port, endpoints));
    }
}

/// Binds the proxy sockets of `ports` for a container with `endpoints`,
/// choosing free host ports where none is given, and starts the proxies.
/// All or nothing: a port in use fails the whole run.
fn publish(ports: &[PortMapping], endpoints: &[EndpointRun]) -> ApiResult<(Vec<PublishedPort>, Vec<PortProxy>)> {
    let mut published = Vec::new();
    let mut proxies = Vec::new();
    for m in ports {
        let host_ip = m.host_ip.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        let (port, mut started) =
            proxy_pair(host_ip, m.host_port.unwrap_or(0), m.protocol, m.container_port, endpoints).map_err(|e| {
                let what = match m.host_port {
                    Some(p) => format!("publish {}/{}", SocketAddr::new(host_ip, p), m.protocol),
                    None => format!("publish container port {}/{}", m.container_port, m.protocol),
                };
                if e.kind() == std::io::ErrorKind::AddrInUse {
                    ApiError::conflict(format!("{what}: the port is already in use"))
                } else {
                    ApiError::internal(format!("{what}: {e}"))
                }
            })?;
        proxies.append(&mut started);
        published.push(PublishedPort {
            host_ip,
            host_port: port,
            container_port: m.container_port,
            protocol: m.protocol,
        });
    }
    Ok((published, proxies))
}

/// [`publish`] again for ports already chosen (a run taken over).
fn rebind(ports: &[PublishedPort], endpoints: &[EndpointRun]) -> std::io::Result<Vec<PortProxy>> {
    let mut proxies = Vec::new();
    for p in ports {
        proxies.append(&mut proxy_pair(p.host_ip, p.host_port, p.protocol, p.container_port, endpoints)?.1);
    }
    Ok(proxies)
}

/// The proxy sockets of one published port: `host_ip:port` (port 0: the
/// kernel picks), and for every address (`0.0.0.0`) also `[::]` on the same
/// port, IPv6 only, if the host can (an IPv6 failure only loses IPv6).
fn proxy_pair(
    host_ip: IpAddr,
    port: u16,
    protocol: Protocol,
    container_port: u16,
    endpoints: &[EndpointRun],
) -> std::io::Result<(u16, Vec<PortProxy>)> {
    let (port, first) = proxy_on(SocketAddr::new(host_ip, port), protocol, container_port, endpoints)?;
    let mut proxies = vec![first];
    if host_ip == IpAddr::V4(Ipv4Addr::UNSPECIFIED) {
        let any6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port);
        match proxy_on(any6, protocol, container_port, endpoints) {
            Ok((_, p)) => proxies.push(p),
            Err(e) => tracing::debug!("no IPv6 proxy for port {port}/{protocol}: {e}"),
        }
    }
    Ok((port, proxies))
}

fn proxy_on(
    addr: SocketAddr,
    protocol: Protocol,
    container_port: u16,
    endpoints: &[EndpointRun],
) -> std::io::Result<(u16, PortProxy)> {
    let fd = bound_socket(addr, protocol)?;
    let backend = proxy::Backend::new(backend_for(addr.is_ipv6(), container_port, endpoints));
    let (port, proxy) = match protocol {
        Protocol::Tcp => {
            let listener = std::net::TcpListener::from(fd);
            (listener.local_addr()?.port(), Proxy::tcp(listener, backend.clone())?)
        }
        Protocol::Udp => {
            let socket = std::net::UdpSocket::from(fd);
            (socket.local_addr()?.port(), Proxy::udp(socket, backend.clone())?)
        }
    };
    Ok((port, PortProxy { proxy, backend, v6: addr.is_ipv6(), container_port }))
}

/// A socket bound to `addr` (listening, for TCP), with `SO_REUSEADDR`, and
/// `IPV6_V6ONLY` for IPv6 so that `[::]` doesn't also claim the IPv4
/// port (`0.0.0.0` has it).
fn bound_socket(addr: SocketAddr, protocol: Protocol) -> std::io::Result<std::os::fd::OwnedFd> {
    use nix::sys::socket::{
        AddressFamily, Backlog, SockFlag, SockType, SockaddrStorage, bind, listen, setsockopt, socket, sockopt,
    };
    let family = if addr.is_ipv6() { AddressFamily::Inet6 } else { AddressFamily::Inet };
    let ty = match protocol {
        Protocol::Tcp => SockType::Stream,
        Protocol::Udp => SockType::Datagram,
    };
    let fd = socket(family, ty, SockFlag::SOCK_CLOEXEC, None)?;
    setsockopt(&fd, sockopt::ReuseAddr, &true)?;
    if addr.is_ipv6() {
        setsockopt(&fd, sockopt::Ipv6V6Only, &true)?;
    }
    bind(fd.as_raw_fd(), &SockaddrStorage::from(addr))?;
    if protocol == Protocol::Tcp {
        listen(&fd, Backlog::new(1024).unwrap_or(Backlog::MAXCONN))?;
    }
    Ok(fd)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(name: &str, ip: [u8; 4], ip6: Option<&str>, internal: bool) -> EndpointRun {
        EndpointRun {
            network_id: format!("{name}-id"),
            network_name: name.into(),
            bridge: format!("br-{name}"),
            internal,
            ip: Some(Ipv4Addr::from(ip)),
            prefix_len: 24,
            ip6: ip6.map(|s| s.parse().unwrap()),
            prefix6: ip6.map(|_| 64),
            ..EndpointRun::default()
        }
    }

    #[test]
    fn ports_are_published_on_the_kernel_s_choice_when_not_given() {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let m = PortMapping {
                host_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                host_port: None,
                container_port: 80,
                protocol: Protocol::Tcp,
            };
            let eps = [endpoint("bridge", [10, 89, 0, 2], None, false)];
            let (published, proxies) = publish(&[m], &eps).unwrap();
            assert_eq!(proxies.len(), 1, "a loopback address gets no IPv6 twin");
            assert!(published[0].host_port > 0);
            assert_eq!(proxies[0].backend.get(), Some("10.89.0.2:80".parse().unwrap()));
            // The port is ours now: binding it again fails as a conflict.
            let again = PortMapping { host_port: Some(published[0].host_port), ..m };
            let e = publish(&[again], &eps).unwrap_err();
            assert_eq!(e.kind, rustlet_spec::ErrorKind::Conflict, "{e}");
        });
    }

    #[test]
    fn ports_and_routes_follow_the_first_network_with_a_way_out() {
        let inner = endpoint("inner", [10, 89, 1, 2], Some("fd00:1::2"), true);
        let front = endpoint("front", [10, 89, 2, 2], None, false);
        let six = endpoint("six", [10, 89, 3, 2], Some("fd00:3::2"), false);
        let eps = [inner, front, six];
        assert_eq!(route_v4(&eps).unwrap().network_name, "front", "internal networks never route");
        assert_eq!(route_v6(&eps).unwrap().network_name, "six", "the first with IPv6");
        assert_eq!(backend_for(false, 80, &eps), Some("10.89.2.2:80".parse().unwrap()));
        assert_eq!(backend_for(true, 80, &eps), Some("[fd00:3::2]:80".parse().unwrap()));
        assert_eq!(backend_for(true, 80, &eps[..2]), Some("10.89.2.2:80".parse().unwrap()), "IPv6 to IPv4");
        assert_eq!(backend_for(false, 80, &eps[..1]), None, "nowhere to go");
        // DNAT: IPv4 to front, IPv6 to six, for 0.0.0.0; a loopback port none.
        let live = Live {
            name: "web".into(),
            endpoints: eps.to_vec(),
            ports: vec![
                PublishedPort {
                    host_ip: Ipv4Addr::UNSPECIFIED.into(),
                    host_port: 8080,
                    container_port: 80,
                    protocol: Protocol::Tcp,
                },
                PublishedPort {
                    host_ip: Ipv4Addr::LOCALHOST.into(),
                    host_port: 8081,
                    container_port: 81,
                    protocol: Protocol::Tcp,
                },
            ],
            dns: None,
            proxies: Vec::new(),
        };
        let rules = port_rules(&live);
        assert_eq!(rules.len(), 2, "{rules:?}");
        assert_eq!((rules[0].container_ip, rules[0].bridge.as_str()), ("10.89.2.2".parse().unwrap(), "br-front"));
        assert_eq!((rules[1].container_ip, rules[1].bridge.as_str()), ("fd00:3::2".parse().unwrap(), "br-six"));
        assert_eq!((rules[0].host_ip, rules[1].host_ip), (None, None));
    }
}

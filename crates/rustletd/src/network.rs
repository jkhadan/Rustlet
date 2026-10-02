//! Networks: the daemon's side of `rustlet-net`.
//!
//! ```text
//!  daemon start   the pin directory; every network's bridge; the firewall
//!                 (with the published ports of the runs the database says
//!                 are going on); then IP forwarding (recorded first)
//!  start          pin a network namespace (lo up, sysctls)
//!                 → bridge networks: an address, the veth, eth0 inside
//!                 → user-defined networks: DNS names, the server's sockets
//!                   inside, the :53 redirect
//!                 → published ports: proxy sockets bound, then DNAT rules
//!                 = a NetRun, recorded before the shim starts
//!  exit           everything the NetRun says, undone
//! ```
//!
//! A run's network lives exactly as long as the run, like its root
//! filesystem: a stopped container holds no address, no namespace, no
//! port. Its next start may get another address (as in Docker).
//!
//! What is in use is never stored apart from the containers: the address of
//! each run is in its container's [`NetRun`], and at startup the daemon
//! rebuilds the addresses in use, the DNS names and the published ports
//! from those, then takes over the runs that are still going (new DNS
//! sockets and proxies: the old ones went with the old daemon) and undoes
//! the rest.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsFd, AsRawFd};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use rustlet_net::backend::{Bridge, NetworkBackend};
use rustlet_net::dns::{DnsServer, View, Zone};
use rustlet_net::files::ResolvConf;
use rustlet_net::firewall::{self, NetworkRules, PortRule, Ruleset};
use rustlet_net::ipam::{self, Allocator, Subnet};
use rustlet_net::proxy::Proxy;
use rustlet_net::{Context as _, link, netns, sysctl, ufw};
use rustlet_spec::event::EventKind;
use rustlet_spec::network::{
    DEFAULT_NETWORK, Network, NetworkCreate, NetworkEndpoint, NetworkMode, PortMapping, Protocol, PruneResponse,
    PublishedPort, RESERVED_NETWORK_NAMES,
};

use rustlet_spec::container::ContainerConfig;

use crate::container::Container;
use crate::daemon::Daemon;
use crate::db::{NetRun, NetworkRecord};
use crate::error::{ApiError, ApiResult};
use crate::lifecycle::blocking;

/// The networking half of the daemon's state.
pub struct Networks {
    /// Everything that touches the host's interfaces or firewall.
    backend: Arc<dyn NetworkBackend>,
    pool: Subnet,
    default_subnet: Subnet,
    default_bridge: String,
    table: String,
    resolv_conf: PathBuf,
    sysctl_record: PathBuf,
    state: Mutex<State>,
    /// Taken while a ruleset is computed and applied, so that two changes
    /// can't apply their rulesets in the wrong order.
    firewall: tokio::sync::Mutex<()>,
    pub zone: Arc<Zone>,
    /// Rustlets turned IP forwarding on: forward only its own bridges.
    isolate_forwarding: AtomicBool,
}

#[derive(Default)]
struct State {
    /// By id.
    networks: BTreeMap<String, NetworkRecord>,
    allocators: BTreeMap<String, Allocator>,
    /// Network id → address → the container that has it.
    used: BTreeMap<String, BTreeMap<Ipv4Addr, String>>,
    /// What each run holds from us, by container id.
    live: BTreeMap<String, Live>,
}

/// One run's share of the daemon: its port rules, and the servers that
/// stop when it is dropped.
struct Live {
    name: String,
    bridge: Option<String>,
    ip: Option<Ipv4Addr>,
    dns_names: Vec<String>,
    ports: Vec<PublishedPort>,
    dns: Option<DnsServer>,
    proxies: Vec<Proxy>,
}

impl Networks {
    pub fn new(config: &crate::config::Config, paths: &crate::config::Paths) -> anyhow::Result<Networks> {
        let parse = |what: &str, s: &str| Subnet::parse(s).map_err(|e| anyhow::anyhow!("{what} {s:?}: {e}"));
        let pool = parse("network_pool", &config.network_pool)?;
        let default_subnet = parse("default_subnet", &config.default_subnet)?;
        Ok(Networks {
            backend: Arc::new(Bridge),
            pool,
            default_subnet,
            default_bridge: config.default_bridge.clone(),
            table: config.nft_table.clone(),
            resolv_conf: config.resolv_conf.clone(),
            sysctl_record: paths.sysctl_record.clone(),
            state: Mutex::new(State::default()),
            firewall: tokio::sync::Mutex::new(()),
            zone: Zone::new(),
            isolate_forwarding: AtomicBool::new(false),
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
                internal: false,
                labels: BTreeMap::new(),
            };
            db.insert_network(&record)?;
            networks.push(record);
        }
        let mut st = self.state();
        for n in networks {
            let subnet = Subnet::parse(&n.subnet).map_err(|e| anyhow::anyhow!("network {}: {e}", n.name))?;
            st.allocators.insert(n.id.clone(), Allocator::new(subnet, n.gateway));
            st.networks.insert(n.id.clone(), n);
        }
        Ok(())
    }

    /// What the database says a run holds, before anything is taken over:
    /// its address stays taken, its ports stay in the firewall.
    pub fn restore(&self, id: &str, name: &str, run: &NetRun) {
        let mut st = self.state();
        if let (Some(net), Some(ip)) = (&run.network_id, run.ip) {
            st.used.entry(net.clone()).or_default().insert(ip, id.to_owned());
        }
        let bridge = run.network_id.as_ref().and_then(|n| st.networks.get(n)).map(|n| n.bridge.clone());
        st.live.insert(
            id.to_owned(),
            Live {
                name: name.to_owned(),
                bridge,
                ip: run.ip,
                dns_names: run.dns_names.clone(),
                ports: run.ports.clone(),
                dns: None,
                proxies: Vec::new(),
            },
        );
        if let (Some(net), Some(ip)) = (&run.network_name, run.ip)
            && !run.dns_names.is_empty()
        {
            self.zone.add(net, ip, &run.dns_names);
        }
    }

    /// At daemon start: the pin directory, every bridge, the firewall, IP
    /// forwarding, in that order: forwarding is never on without the
    /// guards in place.
    pub async fn setup_host(&self, netns_dir: PathBuf) -> anyhow::Result<()> {
        let record = self.sysctl_record.clone();
        let bridges: Vec<(String, Ipv4Addr, u8)> = self
            .state()
            .networks
            .values()
            .filter_map(|n| Some((n.bridge.clone(), n.gateway, Subnet::parse(&n.subnet).ok()?.prefix_len())))
            .collect();
        let backend = self.backend.clone();
        let isolate = blocking(move || -> ApiResult<bool> {
            netns::prepare_dir(&netns_dir).map_err(ApiError::from)?;
            for (bridge, gateway, len) in &bridges {
                backend.ensure_network(bridge, *gateway, *len).map_err(ApiError::from)?;
            }
            // What the record will say: Rustlets turns forwarding on if it
            // is off now and nobody recorded it before.
            let now = sysctl::read(&sysctl::path(sysctl::IP_FORWARD)).map_err(ApiError::from)?;
            Ok(sysctl::recorded(&record, sysctl::IP_FORWARD).unwrap_or(now) == "0")
        })
        .await
        .map_err(|e| anyhow::anyhow!("set up the host's network: {e}"))?;
        self.isolate_forwarding.store(isolate, Ordering::Relaxed);
        self.apply_firewall().await.map_err(|e| anyhow::anyhow!("{e}"))?;
        let record = self.sysctl_record.clone();
        blocking(move || sysctl::enable_forwarding(&record).map_err(ApiError::from))
            .await
            .map_err(|e| anyhow::anyhow!("turn IP forwarding on: {e}"))?;
        if ufw::active() {
            for n in self.records() {
                tracing::warn!("ufw is active: asking it to route {}'s traffic", n.bridge);
                if let Err(e) = ufw::allow(&n.bridge) {
                    tracing::warn!("{e}");
                }
            }
        }
        Ok(())
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
                        Some(NetworkRules {
                            bridge: n.bridge.clone(),
                            subnet: Subnet::parse(&n.subnet).ok()?,
                            internal: n.internal,
                        })
                    })
                    .collect(),
                ports: st
                    .live
                    .values()
                    .flat_map(|l| {
                        let (Some(ip), Some(bridge)) = (l.ip, &l.bridge) else { return Vec::new() };
                        l.ports
                            .iter()
                            .filter(|p| !p.host_ip.is_loopback())
                            .map(|p| PortRule {
                                protocol: p.protocol.to_string(),
                                host_ip: Some(p.host_ip).filter(|ip| !ip.is_unspecified()),
                                host_port: p.host_port,
                                container_ip: ip,
                                container_port: p.container_port,
                                bridge: bridge.clone(),
                                container: l.name.clone(),
                            })
                            .collect()
                    })
                    .collect(),
                isolate_forwarding: self.isolate_forwarding.load(Ordering::Relaxed),
            }
        };
        let backend = self.backend.clone();
        blocking(move || backend.apply(&rules).map_err(ApiError::from))
            .await
            .map_err(|e| e.context("apply the firewall"))
    }

    /// The servers a container's embedded DNS server forwards to: `--dns`,
    /// else the host's (those reachable from a container namespace); none on
    /// an internal network.
    fn upstreams(&self, internal: bool, dns: &[String]) -> Vec<SocketAddr> {
        if internal {
            return Vec::new();
        }
        let given: Vec<IpAddr> = dns.iter().filter_map(|s| s.parse().ok()).collect();
        let servers = if given.is_empty() { ResolvConf::host(&self.resolv_conf).reachable_servers() } else { given };
        servers.into_iter().map(|ip| SocketAddr::new(ip, 53)).collect()
    }

    /// The host's resolver configuration (`resolv_conf` in daemon.toml).
    pub fn resolv_conf_path(&self) -> &std::path::Path {
        &self.resolv_conf
    }

    /// The API's view of a network, with the runs on it.
    pub fn describe(&self, n: &NetworkRecord) -> Network {
        let st = self.state();
        let prefix = Subnet::parse(&n.subnet).map(|s| s.prefix_len()).unwrap_or(24);
        let containers = st
            .used
            .get(&n.id)
            .into_iter()
            .flatten()
            .filter_map(|(ip, id)| {
                let l = st.live.get(id)?;
                Some(NetworkEndpoint {
                    container_id: id.clone(),
                    container_name: l.name.clone(),
                    ip_address: format!("{ip}/{prefix}"),
                    mac_address: ipam::format_mac(&ipam::mac_for(*ip)),
                    dns_names: l.dns_names.clone(),
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
}

/// What `create` decides about a container's network.
#[derive(Debug, Default)]
pub struct NetworkChoice {
    /// `--network container:<x>`: `x`'s full id.
    pub container: Option<String>,
    /// `-p`, plus the image's exposed ports with `-P`.
    pub ports: Vec<PortMapping>,
    /// The hostname the mode implies (the host's, or the shared container's).
    pub hostname: Option<String>,
    pub warnings: Vec<String>,
}

impl Daemon {
    /// Checks a new container's network options against its mode, as
    /// Docker does: a container sharing another's namespace can't have
    /// ports, DNS options, extra hosts, a hostname or aliases of its own;
    /// aliases only exist on user-defined networks; ports are discarded
    /// (with a warning) in the host's namespace or with none.
    pub fn choose_network(&self, config: &ContainerConfig, image: &rustlet_image::Image) -> ApiResult<NetworkChoice> {
        for d in &config.dns {
            d.parse::<IpAddr>().map_err(|_| ApiError::invalid(format!("--dns {d:?} is not an IP address")))?;
        }
        for h in &config.extra_hosts {
            rustlet_spec::network::parse_extra_host(h).map_err(ApiError::invalid)?;
        }
        if let Some(a) = config.network_aliases.iter().find(|a| !rustlet_spec::network::valid_hostname(a)) {
            return Err(ApiError::invalid(format!("--network-alias {a:?} is not a host name")));
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
        let aliases_need_a_network =
            || Err(ApiError::invalid("--network-alias: network-scoped aliases exist only on user-defined networks"));
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
                    (!config.network_aliases.is_empty(), "--network-alias"),
                ];
                if let Some((_, flag)) = conflicting.iter().find(|(set, _)| *set) {
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
                if !config.network_aliases.is_empty() {
                    return aliases_need_a_network();
                }
                if !ports.is_empty() {
                    choice.warnings.push(format!("published ports are discarded with --network {}", config.network));
                    ports.clear();
                }
                if config.network == NetworkMode::Host {
                    choice.hostname = nix::unistd::gethostname().ok().map(|h| h.to_string_lossy().into_owned());
                }
            }
            NetworkMode::Bridge => {
                if !config.network_aliases.is_empty() {
                    return aliases_need_a_network();
                }
            }
            NetworkMode::Network(n) => {
                let net = self.networks.find(n)?;
                if net.internal && !ports.is_empty() {
                    return Err(ApiError::invalid(format!(
                        "the network {} is internal (no route to or from the host): its containers can't publish ports",
                        net.name
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
        let routes = blocking(|| link::routed_blocks().map_err(ApiError::from)).await?;
        let nets = &self.networks;
        let existing = nets.records();
        if existing.iter().any(|n| n.name == name) {
            return Err(ApiError::conflict(format!("a network named {name:?} exists already")));
        }
        let taken = |s: &Subnet| {
            existing.iter().any(|n| Subnet::parse(&n.subnet).is_ok_and(|t| t.overlaps(s)))
                || routes.iter().any(|(addr, len)| s.overlaps_block(*addr, *len))
        };
        let subnet = match &req.subnet {
            Some(s) => {
                let subnet = Subnet::parse(s).map_err(|e| ApiError::invalid(e.to_string()))?;
                if let Some(n) = existing.iter().find(|n| Subnet::parse(&n.subnet).is_ok_and(|t| t.overlaps(&subnet))) {
                    return Err(ApiError::conflict(format!("{subnet} overlaps the network {} ({})", n.name, n.subnet)));
                }
                if let Some((a, l)) = routes.iter().find(|(a, l)| subnet.overlaps_block(*a, *l)) {
                    return Err(ApiError::conflict(format!("{subnet} overlaps the host's route to {a}/{l}")));
                }
                subnet
            }
            None => ipam::free_subnet(nets.pool, 24, taken).ok_or_else(|| {
                ApiError::conflict(format!("no free /24 left in the pool {}: give a --subnet", nets.pool))
            })?,
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
        let id = crate::names::new_id(|short| existing.iter().any(|n| rustlet_spec::short_id(&n.id) == short));
        let record = NetworkRecord {
            bridge: format!("rlb{}", rustlet_spec::short_id(&id)),
            id,
            name,
            created: rustlet_shim::logfile::now(),
            subnet: subnet.to_string(),
            gateway,
            internal: req.internal,
            labels: req.labels,
        };
        self.db.insert_network(&record)?;
        let (bridge, len, backend) = (record.bridge.clone(), subnet.prefix_len(), nets.backend.clone());
        if let Err(e) = blocking(move || backend.ensure_network(&bridge, gateway, len).map_err(ApiError::from)).await {
            let _ = self.db.remove_network(&record.id);
            let (bridge, backend) = (record.bridge.clone(), nets.backend.clone());
            let _ = blocking(move || backend.remove_network(&bridge).map_err(ApiError::from)).await;
            return Err(e.context(format!("create network {}", record.name)));
        }
        {
            let mut st = nets.state();
            st.allocators.insert(record.id.clone(), Allocator::new(subnet, gateway));
            st.networks.insert(record.id.clone(), record.clone());
        }
        if let Err(e) = nets.apply_firewall().await {
            tracing::warn!("{e}");
        }
        if ufw::active() {
            tracing::warn!("ufw is active: asking it to route {}'s traffic", record.bridge);
            if let Err(e) = ufw::allow(&record.bridge) {
                tracing::warn!("{e}");
            }
        }
        self.events.emit(EventKind::Network, "create", &record.id, [("name".to_owned(), record.name.clone())].into());
        Ok(record)
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
        if ufw::active()
            && let Err(e) = ufw::forget(&n.bridge)
        {
            tracing::warn!("{e}");
        }
        self.events.emit(EventKind::Network, "destroy", &n.id, [("name".to_owned(), n.name.clone())].into());
        Ok(())
    }

    /// Removes the user-defined networks no container refers to.
    pub async fn prune_networks(&self) -> ApiResult<PruneResponse> {
        let referenced: Vec<String> = self
            .all_containers()
            .iter()
            .filter_map(|c| c.record.config.network.network_name().map(str::to_owned))
            .collect();
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
            mode => {
                let network = match mode.network_name() {
                    Some(name) => {
                        Some(self.networks.find(name).map_err(|e| e.context(format!("container {}", r.name)))?)
                    }
                    None => None,
                };
                let mut run = NetRun { netns: Some(self.paths.netns_pin(c.id())), ..NetRun::default() };
                let result = self.connect(c, network.as_ref(), &mut run).await;
                match result {
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
    async fn connect(
        self: &Arc<Self>,
        c: &Container,
        network: Option<&NetworkRecord>,
        run: &mut NetRun,
    ) -> ApiResult<()> {
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
        let Some(network) = network else { return Ok(()) };
        let subnet = Subnet::parse(&network.subnet).map_err(|e| ApiError::internal(e.to_string()))?;
        let ip = {
            let mut guard = self.networks.state();
            let st = &mut *guard;
            let used = st.used.entry(network.id.clone()).or_default();
            let ip =
                st.allocators.get_mut(&network.id).and_then(|a| a.allocate(|ip| used.contains_key(&ip))).ok_or_else(
                    || ApiError::conflict(format!("the network {} has no free address left", network.name)),
                )?;
            used.insert(ip, c.id().to_owned());
            ip
        };
        run.network_id = Some(network.id.clone());
        run.network_name = Some(network.name.clone());
        run.ip = Some(ip);
        run.prefix_len = Some(subnet.prefix_len());
        run.gateway = Some(network.gateway);
        let mac = ipam::mac_for(ip);
        run.mac = Some(ipam::format_mac(&mac));
        let veth = format!("rlv{}", rustlet_spec::short_id(c.id()));
        run.veth = Some(veth.clone());
        {
            let (pin, bridge, gateway, internal) =
                (pin.clone(), network.bridge.clone(), network.gateway, network.internal);
            let (prefix_len, backend) = (subnet.prefix_len(), self.networks.backend.clone());
            blocking(move || {
                let ns = netns::open(&pin)?;
                let ep = link::Endpoint {
                    host_ifname: &veth,
                    bridge: &bridge,
                    address: ip,
                    prefix_len,
                    gateway: (!internal).then_some(gateway),
                    mac,
                };
                backend.connect(ns.as_fd(), &ep)
            })
            .await
            .map_err(|e: ApiError| e.context(format!("connect it to {}", network.name)))?;
        }
        let mut live = Live {
            name: c.record.name.clone(),
            bridge: Some(network.bridge.clone()),
            ip: Some(ip),
            dns_names: Vec::new(),
            ports: Vec::new(),
            dns: None,
            proxies: Vec::new(),
        };
        if network.name != DEFAULT_NETWORK {
            run.dns_names = dns_names(c);
            live.dns_names = run.dns_names.clone();
            self.networks.zone.add(&network.name, ip, &run.dns_names);
            live.dns = Some(self.start_dns(c, network, &pin).await?);
        }
        let (ports, proxies) = publish(&c.record.ports, ip)?;
        run.ports = ports.clone();
        live.ports = ports;
        live.proxies = proxies;
        self.networks.state().live.insert(c.id().to_owned(), live);
        self.networks.apply_firewall().await?;
        self.events.emit(
            EventKind::Network,
            "connect",
            &network.id,
            [("name".to_owned(), network.name.clone()), ("container".to_owned(), c.id().to_owned())].into(),
        );
        Ok(())
    }

    /// The embedded DNS server of a run on a user-defined network: its
    /// sockets made inside the namespace, port 53 redirected to them.
    async fn start_dns(&self, c: &Container, network: &NetworkRecord, pin: &std::path::Path) -> ApiResult<DnsServer> {
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
        let view = View {
            network: network.name.clone(),
            zone: self.networks.zone.clone(),
            upstreams: self.networks.upstreams(network.internal, &c.record.config.dns),
        };
        DnsServer::spawn(udp, tcp, view).map_err(|e| ApiError::internal(format!("start the embedded DNS server: {e}")))
    }

    /// Undoes a run's network, whatever part of it exists: its servers and
    /// rules, its address, its veth, its pin. Never fails; what can't be
    /// undone is logged.
    pub async fn detach_network(&self, c: &Container, run: &NetRun) {
        // Its DNS server and proxies, closed before anything else: a start
        // right after (a restart) may want the same port.
        let live = self.networks.state().live.remove(c.id());
        if let Some(live) = live {
            if let Some(dns) = live.dns {
                dns.close().await;
            }
            for p in live.proxies {
                p.close().await;
            }
        }
        if let (Some(net), Some(ip)) = (&run.network_name, run.ip) {
            self.networks.zone.remove(net, ip);
        }
        if let (Some(net), Some(ip)) = (&run.network_id, run.ip) {
            let mut st = self.networks.state();
            if let Some(used) = st.used.get_mut(net)
                && used.get(&ip).map(String::as_str) == Some(c.id())
            {
                used.remove(&ip);
            }
        }
        if !run.ports.is_empty()
            && let Err(e) = self.networks.apply_firewall().await
        {
            tracing::warn!(id = %c.id(), "{e}");
        }
        let veth = run.veth.clone();
        let pin = run.netns.clone().filter(|_| run.joined.is_none());
        let backend = self.networks.backend.clone();
        let undone = blocking(move || {
            if let Some(v) = &veth {
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
        if let (Some(net), Some(name)) = (&run.network_id, &run.network_name) {
            self.events.emit(
                EventKind::Network,
                "disconnect",
                net,
                [("name".to_owned(), name.clone()), ("container".to_owned(), c.id().to_owned())].into(),
            );
        }
    }

    /// What a run cut short left without a record: a pin named by the
    /// container's id, a veth named by its short id.
    pub async fn remove_network_leftovers(&self, id: &str) {
        let pin = self.paths.netns_pin(id);
        let veth = format!("rlv{}", rustlet_spec::short_id(id));
        let backend = self.networks.backend.clone();
        let _ = blocking(move || {
            backend.disconnect(&veth)?;
            netns::remove(&pin)
        })
        .await
        .inspect_err(|e: &ApiError| tracing::warn!(%id, "remove what its last run left: {e}"));
    }

    /// A run the daemon takes over: new DNS sockets and proxies (the last
    /// daemon's went with it). Its address, names and port rules were
    /// restored at startup.
    pub async fn resume_network(self: &Arc<Self>, c: &Container, run: &NetRun) {
        let (Some(net_id), Some(ip), Some(pin)) = (&run.network_id, run.ip, &run.netns) else { return };
        let Ok(network) = self.networks.find(net_id) else {
            tracing::warn!(id = %c.id(), "its network {net_id} is gone");
            return;
        };
        let dns = if network.name != DEFAULT_NETWORK && run.joined.is_none() {
            match self.start_dns(c, &network, pin).await {
                Ok(s) => Some(s),
                Err(e) => {
                    tracing::warn!(id = %c.id(), "{e}");
                    None
                }
            }
        } else {
            None
        };
        let proxies = match rebind(&run.ports, ip) {
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
}

/// The names a container answers to on a user-defined network: its name,
/// short id, hostname and aliases, lowercased, each once.
fn dns_names(c: &Container) -> Vec<String> {
    let r = &c.record;
    let mut names = vec![r.name.clone(), rustlet_spec::short_id(&r.id).to_owned(), r.hostname.clone()];
    names.extend(r.config.network_aliases.iter().cloned());
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

/// Binds the proxy sockets of `ports` for a container at `ip`, choosing
/// free host ports where none is given, and starts the proxies. All or
/// nothing: a port in use fails the whole run.
fn publish(ports: &[PortMapping], ip: Ipv4Addr) -> ApiResult<(Vec<PublishedPort>, Vec<Proxy>)> {
    let mut published = Vec::new();
    let mut proxies = Vec::new();
    for m in ports {
        let host_ip = m.host_ip.unwrap_or(Ipv4Addr::UNSPECIFIED);
        let backend = SocketAddr::new(IpAddr::V4(ip), m.container_port);
        let (port, mut started) = proxy_pair(host_ip, m.host_port.unwrap_or(0), m.protocol, backend).map_err(|e| {
            let what = match m.host_port {
                Some(p) => format!("publish {host_ip}:{p}/{}", m.protocol),
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
fn rebind(ports: &[PublishedPort], ip: Ipv4Addr) -> std::io::Result<Vec<Proxy>> {
    let mut proxies = Vec::new();
    for p in ports {
        let backend = SocketAddr::new(IpAddr::V4(ip), p.container_port);
        proxies.append(&mut proxy_pair(p.host_ip, p.host_port, p.protocol, backend)?.1);
    }
    Ok(proxies)
}

/// The proxy sockets of one published port: `host_ip:port` (port 0: the
/// kernel picks), and for every address (`0.0.0.0`) also `[::]` on the same
/// port, IPv6 only, if the host can (an IPv6 failure only loses IPv6).
fn proxy_pair(
    host_ip: Ipv4Addr,
    port: u16,
    protocol: Protocol,
    backend: SocketAddr,
) -> std::io::Result<(u16, Vec<Proxy>)> {
    let v4 = SocketAddr::new(IpAddr::V4(host_ip), port);
    let (port, first) = proxy_on(v4, protocol, backend)?;
    let mut proxies = vec![first];
    if host_ip.is_unspecified() {
        match proxy_on(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port), protocol, backend) {
            Ok((_, p)) => proxies.push(p),
            Err(e) => tracing::debug!("no IPv6 proxy for port {port}/{protocol}: {e}"),
        }
    }
    Ok((port, proxies))
}

fn proxy_on(addr: SocketAddr, protocol: Protocol, backend: SocketAddr) -> std::io::Result<(u16, Proxy)> {
    let fd = bound_socket(addr, protocol)?;
    match protocol {
        Protocol::Tcp => {
            let listener = std::net::TcpListener::from(fd);
            let port = listener.local_addr()?.port();
            Ok((port, Proxy::tcp(listener, backend)?))
        }
        Protocol::Udp => {
            let socket = std::net::UdpSocket::from(fd);
            let port = socket.local_addr()?.port();
            Ok((port, Proxy::udp(socket, backend)?))
        }
    }
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

    #[test]
    fn ports_are_published_on_the_kernel_s_choice_when_not_given() {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let m = PortMapping {
                host_ip: Some(Ipv4Addr::LOCALHOST),
                host_port: None,
                container_port: 80,
                protocol: Protocol::Tcp,
            };
            let (published, proxies) = publish(&[m], Ipv4Addr::new(10, 89, 0, 2)).unwrap();
            assert_eq!(proxies.len(), 1, "a loopback address gets no IPv6 twin");
            assert!(published[0].host_port > 0);
            // The port is ours now: binding it again fails as a conflict.
            let again = PortMapping { host_port: Some(published[0].host_port), ..m };
            let e = publish(&[again], Ipv4Addr::new(10, 89, 0, 3)).unwrap_err();
            assert_eq!(e.kind, rustlet_spec::ErrorKind::Conflict, "{e}");
        });
    }
}

//! `rustlet network …`: create, list, inspect, remove and prune networks,
//! and connect containers to them and disconnect them.
//!
//! Lists are sorted by name, naturally (`net2` before `net10`), as
//! Docker's are. `rm` acts on each network in turn like the container
//! commands: a name printed for each one removed, failures reported on
//! the way and an exit code of 1 at the end. `connect` and `disconnect`
//! print nothing when they succeed, as Docker's do.

use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::bail;
use rustlet_client::Error;
use rustlet_spec::network::{NetworkConnect, NetworkCreate, NetworkDisconnect, valid_hostname};
use rustlet_spec::short_id;

use crate::Ctx;
use crate::config::parse_labels;
use crate::containers::{self, ObjectType};
use crate::format::{Table, natural_cmp};

/// `rustlet network`.
#[derive(clap::Subcommand, Debug)]
pub enum NetworkCommand {
    /// Create a network (and print its ID)
    Create {
        /// Subnet in CIDR form, 10.89.5.0/24; with --ipv6, an IPv6 one too (default: the next free /24, and /64, of the daemon's pools)
        #[arg(long, value_name = "CIDR")]
        subnet: Vec<String>,
        /// Gateway in the --subnet of its family (default: the subnet's first address)
        #[arg(long, value_name = "IP")]
        gateway: Vec<String>,
        /// Give the network IPv6 too (dual stack): an IPv6 subnet beside its IPv4 one
        #[arg(long)]
        ipv6: bool,
        /// No route out: the containers reach each other, not the outside
        #[arg(long)]
        internal: bool,
        /// Set a label (repeatable)
        #[arg(long, value_name = "KEY[=VALUE]")]
        label: Vec<String>,
        #[arg(value_name = "NETWORK")]
        name: String,
    },
    /// List networks
    #[command(visible_alias = "list")]
    Ls {
        /// Only print network IDs
        #[arg(short, long)]
        quiet: bool,
        /// Don't truncate IDs
        #[arg(long)]
        no_trunc: bool,
    },
    /// Show low-level information on one or more networks, as JSON
    Inspect {
        #[arg(value_name = "NETWORK", required = true)]
        networks: Vec<String>,
    },
    /// Connect a container to a network: at once if it runs, else from its next start
    Connect {
        /// Another name for the container on this network (repeatable)
        #[arg(long, value_name = "ALIAS")]
        alias: Vec<String>,
        /// IPv4 address on this network (default: the next free one)
        #[arg(long, value_name = "IPV4")]
        ip: Option<Ipv4Addr>,
        /// IPv6 address on this network, if it has IPv6 (default: the next free one)
        #[arg(long, value_name = "IPV6")]
        ip6: Option<Ipv6Addr>,
        #[arg(value_name = "NETWORK")]
        network: String,
        #[arg(value_name = "CONTAINER")]
        container: String,
    },
    /// Disconnect a container from a network
    Disconnect {
        /// Even from a network that is gone (the container forgets it)
        #[arg(short, long)]
        force: bool,
        #[arg(value_name = "NETWORK")]
        network: String,
        #[arg(value_name = "CONTAINER")]
        container: String,
    },
    /// Remove one or more networks
    #[command(visible_alias = "remove")]
    Rm {
        #[arg(value_name = "NETWORK", required = true)]
        networks: Vec<String>,
    },
    /// Remove the user-defined networks no container uses
    Prune {
        /// Don't ask for confirmation
        #[arg(short, long)]
        force: bool,
    },
}

/// Docker's question before `network prune`.
const PRUNE_WARNING: &str = "WARNING! This will remove all custom networks not used by at least one container.\n\
                             Are you sure you want to continue?";

pub async fn network(ctx: &mut Ctx, command: NetworkCommand) -> anyhow::Result<i32> {
    match command {
        NetworkCommand::Create { subnet, gateway, ipv6, internal, label, name } => {
            let mut config =
                NetworkCreate { name, ipv6, internal, labels: parse_labels(&label)?, ..Default::default() };
            sort_by_family(&mut config, subnet, gateway)?;
            let created = ctx.client.create_network(&config).await?;
            writeln!(ctx.console.stdout, "{}", created.id)?;
            Ok(0)
        }
        NetworkCommand::Ls { quiet, no_trunc } => ls(ctx, quiet, no_trunc).await,
        NetworkCommand::Inspect { networks } => containers::inspect(ctx, Some(ObjectType::Network), &networks).await,
        NetworkCommand::Connect { alias, ip, ip6, network, container } => {
            // Names for the embedded DNS server to answer: host names, as the
            // daemon has a `--network-alias` be.
            if let Some(bad) = alias.iter().find(|a| !valid_hostname(a)) {
                bail!("--alias {bad:?} is not a host name");
            }
            let body = NetworkConnect { container, aliases: alias, ipv4_address: ip, ipv6_address: ip6 };
            ctx.client.connect_network(&network, &body).await?;
            Ok(0)
        }
        NetworkCommand::Disconnect { force, network, container } => {
            ctx.client.disconnect_network(&network, &NetworkDisconnect { container, force }).await?;
            Ok(0)
        }
        NetworkCommand::Rm { networks } => rm(ctx, &networks).await,
        NetworkCommand::Prune { force } => prune(ctx, force).await,
    }
}

/// `network create`'s `--subnet`s and `--gateway`s, each to the request's
/// field for its family: one subnet of each at most, an IPv6 one only for a
/// network with `--ipv6`, and each gateway with the subnet it belongs to.
/// What the values say beyond their family (prefix lengths, host bits,
/// overlaps) is the daemon's to check.
fn sort_by_family(config: &mut NetworkCreate, subnets: Vec<String>, gateways: Vec<String>) -> anyhow::Result<()> {
    for subnet in subnets {
        let address = subnet.split('/').next().unwrap_or_default();
        let Ok(address) = address.parse::<IpAddr>() else {
            bail!("--subnet {subnet:?}: not a subnet in CIDR form (10.89.5.0/24, fd00:89:0:5::/64)");
        };
        let (field, family) = match address {
            IpAddr::V4(_) => (&mut config.subnet, "IPv4"),
            IpAddr::V6(_) if !config.ipv6 => bail!("--subnet {subnet}: an IPv6 subnet needs --ipv6"),
            IpAddr::V6(_) => (&mut config.subnet6, "IPv6"),
        };
        if let Some(first) = field {
            bail!("--subnet {first} and --subnet {subnet}: a network has one {family} subnet at most");
        }
        *field = Some(subnet);
    }
    for gateway in gateways {
        let Ok(address) = gateway.parse::<IpAddr>() else {
            bail!("--gateway {gateway:?}: not an IP address");
        };
        let (subnet, field) = match address {
            IpAddr::V4(_) => (&config.subnet, &mut config.gateway),
            IpAddr::V6(_) => (&config.subnet6, &mut config.gateway6),
        };
        // Docker's rule, checked by its CLI too: the daemon would have to
        // guess a subnet around the gateway.
        if subnet.is_none() {
            bail!("--gateway needs the --subnet it belongs to");
        }
        if let Some(first) = field {
            bail!("--gateway {first} and --gateway {gateway}: a subnet has one gateway");
        }
        *field = Some(gateway);
    }
    Ok(())
}

/// `network ls`: ID, name, driver and subnets of each.
async fn ls(ctx: &mut Ctx, quiet: bool, no_trunc: bool) -> anyhow::Result<i32> {
    let mut networks = ctx.client.list_networks().await?;
    networks.sort_by(|a, b| natural_cmp(&a.name, &b.name));
    let id = |id: &str| if no_trunc { id.to_owned() } else { short_id(id).to_owned() };
    if quiet {
        for n in &networks {
            writeln!(ctx.console.stdout, "{}", id(&n.id))?;
        }
        return Ok(0);
    }
    let mut table = Table::new(&["NETWORK ID", "NAME", "DRIVER", "SUBNET"]);
    for n in &networks {
        // A dual-stack network's IPv6 subnet after its IPv4 one.
        let subnet = match &n.subnet6 {
            Some(subnet6) => format!("{}, {subnet6}", n.subnet),
            None => n.subnet.clone(),
        };
        table.row(vec![id(&n.id), n.name.clone(), n.driver.clone(), subnet]);
    }
    table.write(&mut *ctx.console.stdout)?;
    Ok(0)
}

/// `network rm`: each name as typed once removed; exits 1 if any failed.
async fn rm(ctx: &mut Ctx, names: &[String]) -> anyhow::Result<i32> {
    let mut failed = false;
    for name in names {
        match ctx.client.remove_network(name).await {
            Ok(()) => writeln!(ctx.console.stdout, "{name}")?,
            Err(e @ Error::Connect { .. }) => return Err(e.into()),
            Err(e) => {
                writeln!(ctx.console.stderr, "rustlet: error: {e}")?;
                failed = true;
            }
        }
    }
    Ok(i32::from(failed))
}

/// `network prune`, after asking (unless `force`): what went, as Docker
/// prints it. Declined, nothing is removed and the exit code is 0, as with
/// Docker; with no answer at all, it fails ([`Console::confirm`]).
///
/// [`Console::confirm`]: crate::console::Console::confirm
async fn prune(ctx: &mut Ctx, force: bool) -> anyhow::Result<i32> {
    if !force && !ctx.console.confirm(PRUNE_WARNING).await? {
        return Ok(0);
    }
    let pruned = ctx.client.prune_networks().await?;
    if !pruned.deleted.is_empty() {
        let out = &mut ctx.console.stdout;
        writeln!(out, "Deleted Networks:")?;
        for name in &pruned.deleted {
            writeln!(out, "{name}")?;
        }
        writeln!(out)?;
    }
    Ok(0)
}

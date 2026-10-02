//! `rustlet network …`: create, list, inspect, remove and prune networks.
//!
//! Lists are sorted by name, naturally (`net2` before `net10`), as
//! Docker's are. `rm` acts on each network in turn like the container
//! commands: a name printed for each one removed, failures reported on
//! the way and an exit code of 1 at the end.

use std::io::Write;

use anyhow::bail;
use rustlet_client::Error;
use rustlet_spec::network::NetworkCreate;
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
        /// Subnet in CIDR form, 10.89.5.0/24 (default: the next free /24 of the daemon's pool)
        #[arg(long, value_name = "CIDR")]
        subnet: Option<String>,
        /// Gateway in the subnet (default: its first address)
        #[arg(long, value_name = "IP")]
        gateway: Option<String>,
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
        NetworkCommand::Create { subnet, gateway, internal, label, name } => {
            // Docker's rule, checked by its CLI too: the daemon would have to
            // guess a subnet around the gateway.
            if gateway.is_some() && subnet.is_none() {
                bail!("--gateway needs the --subnet it belongs to");
            }
            let config =
                NetworkCreate { name, subnet, gateway, internal, labels: parse_labels(&label)?, ..Default::default() };
            let created = ctx.client.create_network(&config).await?;
            writeln!(ctx.console.stdout, "{}", created.id)?;
            Ok(0)
        }
        NetworkCommand::Ls { quiet, no_trunc } => ls(ctx, quiet, no_trunc).await,
        NetworkCommand::Inspect { networks } => containers::inspect(ctx, Some(ObjectType::Network), &networks).await,
        NetworkCommand::Rm { networks } => rm(ctx, &networks).await,
        NetworkCommand::Prune { force } => prune(ctx, force).await,
    }
}

/// `network ls`: ID, name, driver and subnet of each.
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
        table.row(vec![id(&n.id), n.name.clone(), n.driver.clone(), n.subnet.clone()]);
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

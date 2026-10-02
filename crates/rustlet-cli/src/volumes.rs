//! `rustlet volume …`: create, list, inspect, remove and prune volumes.
//!
//! Lists are sorted by name, naturally, as Docker's are. `rm` acts on
//! each volume in turn like the container commands: a name printed for
//! each one removed, failures reported on the way and an exit code of 1
//! at the end.

use std::io::Write;

use rustlet_client::Error;
use rustlet_spec::volume::VolumeCreate;

use crate::Ctx;
use crate::config::parse_labels;
use crate::containers::{self, ObjectType};
use crate::format::{Table, human_size, natural_cmp};

/// `rustlet volume`.
#[derive(clap::Subcommand, Debug)]
pub enum VolumeCommand {
    /// Create a volume (and print its name)
    Create {
        /// Set a label (repeatable)
        #[arg(long, value_name = "KEY[=VALUE]")]
        label: Vec<String>,
        /// Its name (default: a generated one, for an anonymous volume)
        #[arg(value_name = "VOLUME")]
        name: Option<String>,
    },
    /// List volumes
    #[command(visible_alias = "list")]
    Ls {
        /// Only print volume names
        #[arg(short, long)]
        quiet: bool,
    },
    /// Show low-level information on one or more volumes, as JSON
    Inspect {
        #[arg(value_name = "VOLUME", required = true)]
        volumes: Vec<String>,
    },
    /// Remove one or more volumes
    #[command(visible_alias = "remove")]
    Rm {
        /// No error for a volume that doesn't exist
        #[arg(short, long)]
        force: bool,
        #[arg(value_name = "VOLUME", required = true)]
        volumes: Vec<String>,
    },
    /// Remove the anonymous volumes no container uses
    Prune {
        /// Remove named volumes too, not only anonymous ones
        #[arg(short, long)]
        all: bool,
        /// Don't ask for confirmation
        #[arg(short, long)]
        force: bool,
    },
}

/// Docker's questions before `volume prune` and `volume prune --all`.
const PRUNE_WARNING: &str = "WARNING! This will remove anonymous local volumes not used by at least one container.\n\
                             Are you sure you want to continue?";
const PRUNE_ALL_WARNING: &str = "WARNING! This will remove all local volumes not used by at least one container.\n\
                                 Are you sure you want to continue?";

pub async fn volume(ctx: &mut Ctx, command: VolumeCommand) -> anyhow::Result<i32> {
    match command {
        VolumeCommand::Create { label, name } => {
            let created = ctx.client.create_volume(&VolumeCreate { name, labels: parse_labels(&label)? }).await?;
            writeln!(ctx.console.stdout, "{}", created.name)?;
            Ok(0)
        }
        VolumeCommand::Ls { quiet } => ls(ctx, quiet).await,
        VolumeCommand::Inspect { volumes } => containers::inspect(ctx, Some(ObjectType::Volume), &volumes).await,
        VolumeCommand::Rm { force, volumes } => rm(ctx, force, &volumes).await,
        VolumeCommand::Prune { all, force } => prune(ctx, all, force).await,
    }
}

/// `volume ls`: driver and name of each.
async fn ls(ctx: &mut Ctx, quiet: bool) -> anyhow::Result<i32> {
    let mut volumes = ctx.client.list_volumes().await?;
    volumes.sort_by(|a, b| natural_cmp(&a.name, &b.name));
    if quiet {
        for v in &volumes {
            writeln!(ctx.console.stdout, "{}", v.name)?;
        }
        return Ok(0);
    }
    let mut table = Table::new(&["DRIVER", "VOLUME NAME"]);
    for v in &volumes {
        table.row(vec![v.driver.clone(), v.name.clone()]);
    }
    table.write(&mut *ctx.console.stdout)?;
    Ok(0)
}

/// `volume rm`: each name as typed once removed; exits 1 if any failed.
async fn rm(ctx: &mut Ctx, force: bool, names: &[String]) -> anyhow::Result<i32> {
    let mut failed = false;
    for name in names {
        match ctx.client.remove_volume(name, force).await {
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

/// `volume prune`, after asking (unless `force`): what went and the space
/// it took, as Docker prints them. Declined, nothing is removed and the
/// exit code is 0, as with Docker; with no answer at all, it fails
/// ([`Console::confirm`]).
///
/// [`Console::confirm`]: crate::console::Console::confirm
async fn prune(ctx: &mut Ctx, all: bool, force: bool) -> anyhow::Result<i32> {
    let warning = if all { PRUNE_ALL_WARNING } else { PRUNE_WARNING };
    if !force && !ctx.console.confirm(warning).await? {
        return Ok(0);
    }
    let pruned = ctx.client.prune_volumes(all).await?;
    let out = &mut ctx.console.stdout;
    if !pruned.deleted.is_empty() {
        writeln!(out, "Deleted Volumes:")?;
        for name in &pruned.deleted {
            writeln!(out, "{name}")?;
        }
        writeln!(out)?;
    }
    writeln!(out, "Total reclaimed space: {}", human_size(pruned.space_reclaimed))?;
    Ok(0)
}

//! The container commands that don't stay attached: `ps`, `stop`, `kill`,
//! `restart`, `rm`, `pause`, `unpause`, `start` (detached), `wait`, `logs`
//! and `inspect`.
//!
//! The commands that take several containers act on each in turn, print
//! each name as it was typed once done (scripts rely on that, as with
//! Docker), and carry on past a failure, which is reported on the way
//! and turns the exit code to 1 at the end. Only a daemon that can't be
//! reached at all stops them at once.

use std::io::Write;

use anyhow::anyhow;
use chrono::{DateTime, Utc};
use futures::StreamExt;
use rustlet_client::Error;
use rustlet_spec::container::WaitCondition;
use rustlet_spec::logs::{LogStream, LogsQuery};
use rustlet_spec::short_id;

use crate::Ctx;
use crate::format::{Table, ago, command_text, parse_time_arg, status_text};

/// `rustlet ps`.
#[derive(clap::Args, Debug)]
pub struct PsArgs {
    /// Show all containers (default: running ones)
    #[arg(short, long)]
    pub all: bool,
    /// Only print container IDs
    #[arg(short, long)]
    pub quiet: bool,
    /// Don't truncate IDs and commands
    #[arg(long)]
    pub no_trunc: bool,
}

pub async fn ps(ctx: &mut Ctx, args: PsArgs) -> anyhow::Result<i32> {
    let mut containers = ctx.client.list_containers(args.all).await?;
    // Newest first, as Docker lists them.
    containers.sort_by(|a, b| created(&b.created).cmp(&created(&a.created)).then_with(|| a.name.cmp(&b.name)));
    let id = |id: &str| if args.no_trunc { id.to_owned() } else { short_id(id).to_owned() };
    if args.quiet {
        for c in &containers {
            writeln!(ctx.console.stdout, "{}", id(&c.id))?;
        }
        return Ok(0);
    }
    let now = Utc::now();
    let mut table = Table::new(&["CONTAINER ID", "IMAGE", "COMMAND", "CREATED", "STATUS", "NAMES"]);
    for c in &containers {
        table.row(vec![
            id(&c.id),
            c.image.clone(),
            command_text(&c.command, args.no_trunc),
            ago(&c.created, now),
            status_text(&c.state, now),
            c.name.clone(),
        ]);
    }
    table.write(&mut *ctx.console.stdout)?;
    Ok(0)
}

fn created(ts: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(ts).ok().map(|t| t.with_timezone(&Utc))
}

/// What [`each`] does to each container.
#[derive(Debug, Clone)]
pub enum Op {
    Start,
    Stop(Option<u32>),
    Kill(String),
    Restart(Option<u32>),
    Remove { force: bool },
    Pause,
    Unpause,
}

/// Does `op` to every one of `names`, printing each name once done.
/// Exits 1 if any failed.
pub async fn each(ctx: &mut Ctx, names: &[String], op: Op) -> anyhow::Result<i32> {
    let mut failed = false;
    for name in names {
        let done = match &op {
            Op::Start => ctx.client.start(name).await,
            Op::Stop(timeout) => ctx.client.stop(name, *timeout).await,
            Op::Kill(signal) => ctx.client.kill(name, Some(signal)).await,
            Op::Restart(timeout) => ctx.client.restart(name, *timeout).await,
            Op::Remove { force } => ctx.client.remove_container(name, *force).await,
            Op::Pause => ctx.client.pause(name).await,
            Op::Unpause => ctx.client.unpause(name).await,
        };
        match done {
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

/// `rustlet wait`: each container's exit status, once it has stopped.
pub async fn wait(ctx: &mut Ctx, names: &[String]) -> anyhow::Result<i32> {
    let mut failed = false;
    for name in names {
        match ctx.client.wait(name, WaitCondition::NotRunning).await {
            Ok(r) => writeln!(ctx.console.stdout, "{}", r.status_code)?,
            Err(e @ Error::Connect { .. }) => return Err(e.into()),
            Err(e) => {
                writeln!(ctx.console.stderr, "rustlet: error: {e}")?;
                failed = true;
            }
        }
    }
    Ok(i32::from(failed))
}

/// `rustlet logs`.
#[derive(clap::Args, Debug)]
pub struct LogsArgs {
    /// Follow the log until the container exits
    #[arg(short, long)]
    pub follow: bool,
    /// Number of lines to show from the end ("all" for everything)
    #[arg(short = 'n', long, default_value = "all", value_name = "N")]
    pub tail: String,
    /// Show each line's timestamp
    #[arg(short, long)]
    pub timestamps: bool,
    /// Only lines since this time (2026-10-01T15:04:05Z, or relative: 10m)
    #[arg(long, value_name = "TIME")]
    pub since: Option<String>,
    /// Only lines before this time (2026-10-01T15:04:05Z, or relative: 10m)
    #[arg(long, value_name = "TIME")]
    pub until: Option<String>,
    pub container: String,
}

pub async fn logs(ctx: &mut Ctx, args: LogsArgs) -> anyhow::Result<i32> {
    let now = Utc::now();
    let time =
        |t: &Option<String>| t.as_deref().map(|t| parse_time_arg(t, now)).transpose().map_err(anyhow::Error::msg);
    let query = LogsQuery {
        follow: args.follow,
        tail: parse_tail(&args.tail)?,
        since: time(&args.since)?,
        until: time(&args.until)?,
        stdout: true,
        stderr: true,
    };
    let mut entries = ctx.client.logs(&args.container, &query).await?;
    while let Some(entry) = entries.next().await {
        let entry = entry?;
        let out = match entry.stream {
            LogStream::Stdout => &mut ctx.console.stdout,
            LogStream::Stderr => &mut ctx.console.stderr,
        };
        if args.timestamps {
            write!(out, "{} ", entry.ts)?;
        }
        out.write_all(entry.log.as_bytes())?;
        if args.follow {
            out.flush()?;
        }
    }
    Ok(0)
}

/// `--tail`: `all`, or a number of lines (a negative one means all, as
/// with Docker).
fn parse_tail(s: &str) -> anyhow::Result<Option<u64>> {
    if s.eq_ignore_ascii_case("all") {
        return Ok(None);
    }
    match s.parse::<i64>() {
        Ok(n) if n < 0 => Ok(None),
        Ok(n) => Ok(Some(n.unsigned_abs())),
        Err(_) => Err(anyhow!("--tail {s:?}: expected a number of lines or \"all\"")),
    }
}

/// `--type` of `inspect`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum ObjectType {
    Container,
    Image,
}

/// `rustlet inspect`: a JSON array, one object per name found; names that
/// are neither (or not the `--type` asked for) are reported on stderr.
pub async fn inspect(ctx: &mut Ctx, kind: Option<ObjectType>, names: &[String]) -> anyhow::Result<i32> {
    let mut found = Vec::new();
    let mut failed = false;
    for name in names {
        let object = match kind {
            Some(ObjectType::Container) => ctx.client.inspect_container(name).await.map(serde_json::to_value),
            Some(ObjectType::Image) => ctx.client.inspect_image(name).await.map(serde_json::to_value),
            None => match ctx.client.inspect_container(name).await {
                Err(e) if e.is_not_found() => ctx.client.inspect_image(name).await.map(serde_json::to_value),
                container => container.map(serde_json::to_value),
            },
        };
        match object {
            Ok(value) => found.push(value?),
            Err(e @ Error::Connect { .. }) => return Err(e.into()),
            Err(e) if e.is_not_found() && kind.is_none() => {
                writeln!(ctx.console.stderr, "rustlet: error: no such object: {name}")?;
                failed = true;
            }
            Err(e) => {
                writeln!(ctx.console.stderr, "rustlet: error: {e}")?;
                failed = true;
            }
        }
    }
    writeln!(ctx.console.stdout, "{}", serde_json::to_string_pretty(&found)?)?;
    Ok(i32::from(failed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tails() {
        assert_eq!(parse_tail("all").unwrap(), None);
        assert_eq!(parse_tail("ALL").unwrap(), None);
        assert_eq!(parse_tail("-1").unwrap(), None);
        assert_eq!(parse_tail("0").unwrap(), Some(0));
        assert_eq!(parse_tail("25").unwrap(), Some(25));
        assert!(parse_tail("some").is_err());
    }
}

//! `version`, `info` and `events`.

use std::io::Write;

use anyhow::bail;
use chrono::Utc;
use futures::StreamExt;
use rustlet_spec::event::{Event, EventKind, EventsQuery};

use crate::Ctx;
use crate::format::{bytes_iec, parse_time_arg};

/// The client's half is printed before the daemon is asked, so that it
/// shows even when the daemon can't be reached.
pub async fn version(ctx: &mut Ctx) -> anyhow::Result<i32> {
    let out = &mut ctx.console.stdout;
    writeln!(out, "Client:")?;
    writeln!(out, " Version:      {}", env!("CARGO_PKG_VERSION"))?;
    writeln!(out, " API version:  {}", rustlet_spec::API_VERSION)?;
    writeln!(out, " OS/Arch:      {}/{}", std::env::consts::OS, go_arch(std::env::consts::ARCH))?;
    out.flush()?;
    let server = ctx.client.version().await?;
    let out = &mut ctx.console.stdout;
    writeln!(out)?;
    writeln!(out, "Server:")?;
    writeln!(out, " Version:      {}", server.version)?;
    writeln!(out, " API version:  {}", server.api_version)?;
    writeln!(out, " OS/Arch:      {}/{}", server.os, go_arch(&server.arch))?;
    writeln!(out, " Kernel:       {}", server.kernel)?;
    Ok(0)
}

/// Architectures by the names Docker (Go) gives them.
fn go_arch(arch: &str) -> &str {
    match arch {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "x86" => "386",
        other => other,
    }
}

pub async fn info(ctx: &mut Ctx) -> anyhow::Result<i32> {
    let (info, version) = tokio::try_join!(ctx.client.info(), ctx.client.version())?;
    let out = &mut ctx.console.stdout;
    writeln!(out, "Containers: {}", info.containers)?;
    writeln!(out, " Running: {}", info.running)?;
    writeln!(out, " Paused: {}", info.paused)?;
    writeln!(out, " Stopped: {}", info.stopped)?;
    writeln!(out, "Images: {}", info.images)?;
    writeln!(out, "Networks: {}", info.networks)?;
    writeln!(out, "Volumes: {}", info.volumes)?;
    writeln!(out, "Server Version: {}", version.version)?;
    writeln!(out, "Storage Driver: {}", info.storage_driver)?;
    writeln!(out, "Cgroup Parent: {}", info.cgroup_parent)?;
    writeln!(out, "Runtime: {}", info.runtime)?;
    writeln!(out, "Shim: {}", info.shim)?;
    writeln!(out, "Kernel Version: {}", info.kernel)?;
    writeln!(out, "CPUs: {}", info.cpus)?;
    writeln!(out, "Total Memory: {}", bytes_iec(info.memory))?;
    writeln!(out, "Data Root: {}", info.data_root)?;
    writeln!(out, "Run Root: {}", info.run_root)?;
    Ok(0)
}

/// `rustlet events`.
#[derive(clap::Args, Debug)]
pub struct EventsArgs {
    /// Replay events since this time first (2026-10-01T15:04:05Z, or relative: 10m)
    #[arg(long, value_name = "TIME")]
    pub since: Option<String>,
    /// Only some events; supported: container=NAME
    #[arg(short, long, value_name = "FILTER")]
    pub filter: Vec<String>,
}

pub async fn events(ctx: &mut Ctx, args: EventsArgs) -> anyhow::Result<i32> {
    let mut query = EventsQuery {
        since: args.since.as_deref().map(|s| parse_time_arg(s, Utc::now())).transpose().map_err(anyhow::Error::msg)?,
        container: None,
    };
    for filter in &args.filter {
        match filter.split_once('=') {
            Some(("container", name)) if query.container.is_none() => query.container = Some(name.to_owned()),
            Some(("container", _)) => bail!("only one container filter is supported"),
            _ => bail!("unsupported filter {filter:?} (supported: container=NAME)"),
        }
    }
    let mut events = ctx.client.events(&query).await?;
    while let Some(event) = events.next().await {
        writeln!(ctx.console.stdout, "{}", event_line(&event?))?;
        ctx.console.stdout.flush()?;
    }
    Ok(0)
}

/// One line per event, as `docker events` prints them: time, type,
/// action, id, then the attributes in key order.
pub fn event_line(e: &Event) -> String {
    let kind = match e.kind {
        EventKind::Container => "container",
        EventKind::Image => "image",
        EventKind::Network => "network",
        EventKind::Volume => "volume",
    };
    let mut line = format!("{} {kind} {} {}", e.time, e.action, e.id);
    if !e.attributes.is_empty() {
        let attributes: Vec<String> = e.attributes.iter().map(|(k, v)| format!("{k}={v}")).collect();
        line.push_str(&format!(" ({})", attributes.join(", ")));
    }
    line
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_lines() {
        let mut e = Event {
            time: "2026-10-01T12:00:00.000000001Z".into(),
            kind: EventKind::Container,
            action: "die".into(),
            id: "0123456789ab".into(),
            attributes: [("name", "web"), ("exit_code", "0"), ("image", "alpine")]
                .into_iter()
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
                .collect(),
        };
        assert_eq!(
            event_line(&e),
            "2026-10-01T12:00:00.000000001Z container die 0123456789ab (exit_code=0, image=alpine, name=web)"
        );
        e.attributes.clear();
        e.kind = EventKind::Image;
        assert_eq!(event_line(&e), "2026-10-01T12:00:00.000000001Z image die 0123456789ab");
    }
}

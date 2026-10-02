//! `rustlet stats`: a live table of what containers use.
//!
//! Every container shown has a task following its stats stream (a sample
//! a second) and keeping the last two samples; the table is drawn every
//! second from those. The numbers are computed as `docker stats` computes
//! them on a cgroup v2 host:
//!
//! - **CPU %**: CPU time used between two samples over the wall time
//!   between them (their `read` times), × 100. A container keeping two
//!   CPUs busy shows 200%. With one sample there is no rate yet: 0.00%.
//! - **MEM USAGE**: `memory.current` less `inactive_file` from
//!   `memory.stat`: page cache the kernel can drop at once isn't counted.
//!   **LIMIT** is `memory.max`, or the host's memory when there is none.
//! - **NET I/O** and **BLOCK I/O**: received/sent bytes over the
//!   container's interfaces but loopback, and read/written bytes over all
//!   devices.
//!
//! Without names, the set of containers is looked up again every second
//! (running ones, or all with `-a`), so containers that start show up and
//! ones that stop go away; a stream that ends (a container that stopped)
//! leaves zeros in its row.

use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use chrono::DateTime;
use futures::StreamExt;
use rustlet_client::Client;
use rustlet_spec::short_id;
use rustlet_spec::stats::StatsSample;
use tokio::task::JoinHandle;

use crate::Ctx;
use crate::format::{Table, bytes_iec, bytes_si};

/// `rustlet stats`.
#[derive(clap::Args, Debug)]
pub struct StatsArgs {
    /// Show all containers (default: running ones)
    #[arg(short, long)]
    pub all: bool,
    /// Print one table and exit
    #[arg(long)]
    pub no_stream: bool,
    /// Don't truncate IDs
    #[arg(long)]
    pub no_trunc: bool,
    #[arg(value_name = "CONTAINER")]
    pub containers: Vec<String>,
}

/// One row's numbers.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Usage {
    pub cpu_percent: f64,
    pub memory: u64,
    pub memory_limit: u64,
    pub memory_percent: f64,
    pub net_rx: u64,
    pub net_tx: u64,
    pub block_read: u64,
    pub block_written: u64,
    pub pids: u64,
}

impl Usage {
    /// From the latest sample, and the one before for the CPU rate.
    pub fn new(previous: Option<&StatsSample>, current: &StatsSample, host_memory: u64) -> Usage {
        let memory = memory_usage(current);
        let memory_limit = current.memory_max.unwrap_or(host_memory);
        let memory_percent = if memory_limit > 0 { memory as f64 / memory_limit as f64 * 100.0 } else { 0.0 };
        let sum = |key: &str| current.io.values().filter_map(|d| d.get(key)).sum();
        // Traffic a container sends itself isn't network I/O (Docker
        // counts only the interfaces it made).
        let interfaces = || current.network.iter().filter(|n| n.name != "lo");
        Usage {
            cpu_percent: previous.map_or(0.0, |p| cpu_percent(p, current)),
            memory,
            memory_limit,
            memory_percent,
            net_rx: interfaces().map(|n| n.rx_bytes).sum(),
            net_tx: interfaces().map(|n| n.tx_bytes).sum(),
            block_read: sum("rbytes"),
            block_written: sum("wbytes"),
            pids: current.pids_current,
        }
    }

    fn cells(&self) -> [String; 6] {
        [
            format!("{:.2}%", self.cpu_percent),
            format!("{} / {}", bytes_iec(self.memory), bytes_iec(self.memory_limit)),
            format!("{:.2}%", self.memory_percent),
            format!("{} / {}", bytes_si(self.net_rx), bytes_si(self.net_tx)),
            format!("{} / {}", bytes_si(self.block_read), bytes_si(self.block_written)),
            self.pids.to_string(),
        ]
    }
}

/// CPU time used between two samples over the wall time between them,
/// in percent of one CPU.
pub fn cpu_percent(previous: &StatsSample, current: &StatsSample) -> f64 {
    let usage = |s: &StatsSample| s.cpu.get("usage_usec").copied().unwrap_or(0);
    let used = usage(current).saturating_sub(usage(previous)) as f64;
    let read = |s: &StatsSample| DateTime::parse_from_rfc3339(&s.read).ok();
    let (Some(then), Some(now)) = (read(previous), read(current)) else { return 0.0 };
    match (now - then).num_microseconds() {
        Some(wall) if wall > 0 => used / wall as f64 * 100.0,
        _ => 0.0,
    }
}

/// Memory in use without the inactive page cache (Docker's rule for
/// cgroup v2, shared with cAdvisor and containerd).
pub fn memory_usage(s: &StatsSample) -> u64 {
    match s.memory_stat.get("inactive_file") {
        Some(&inactive) if inactive < s.memory_current => s.memory_current - inactive,
        _ => s.memory_current,
    }
}

/// The last two samples of a container's stream.
#[derive(Debug, Default)]
struct Samples {
    previous: Option<StatsSample>,
    current: Option<StatsSample>,
}

type Shared = Arc<Mutex<HashMap<String, Samples>>>;

fn lock(shared: &Shared) -> MutexGuard<'_, HashMap<String, Samples>> {
    // A panicked follower can't have left a sample half-written.
    shared.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// A row of the table, and the task feeding it.
struct Row {
    id: String,
    name: String,
    follower: Option<JoinHandle<()>>,
}

impl Drop for Row {
    fn drop(&mut self) {
        if let Some(task) = &self.follower {
            task.abort();
        }
    }
}

/// Keeps the last two samples of `id`'s stream in `shared`; once it ends,
/// the row is zeros.
async fn follow(client: Client, id: String, shared: Shared) {
    if let Ok(mut samples) = client.stats(&id).await {
        while let Some(Ok(sample)) = samples.next().await {
            let mut map = lock(&shared);
            let entry = map.entry(id.clone()).or_default();
            entry.previous = entry.current.replace(sample);
        }
    }
    lock(&shared).remove(&id);
}

pub async fn stats(ctx: &mut Ctx, args: StatsArgs) -> anyhow::Result<i32> {
    let host_memory = ctx.client.info().await?.memory;
    // Named containers must exist before anything is drawn.
    let mut named = Vec::new();
    for name in &args.containers {
        let info = ctx.client.inspect_container(name).await?;
        named.push((info.id, info.name));
    }
    let shared: Shared = Arc::default();
    let mut rows: Vec<Row> = Vec::new();
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut first = true;
    loop {
        tick.tick().await;
        refresh(ctx, &args, &named, &mut rows, &shared).await?;
        if args.no_stream {
            settle(&rows, &shared, 2).await;
            draw(ctx, &args, &rows, &shared, host_memory, false)?;
            return Ok(0);
        }
        if first {
            // A first frame of zeros would only flash by.
            settle(&rows, &shared, 1).await;
            first = false;
        }
        draw(ctx, &args, &rows, &shared, host_memory, ctx.console.stdout_tty)?;
    }
}

/// Brings `rows` up to date with the daemon: the containers to show, each
/// live one with a follower.
async fn refresh(
    ctx: &mut Ctx,
    args: &StatsArgs,
    named: &[(String, String)],
    rows: &mut Vec<Row>,
    shared: &Shared,
) -> anyhow::Result<()> {
    let list = ctx.client.list_containers(true).await?;
    let live: HashSet<&str> = list.iter().filter(|c| c.state.status.is_live()).map(|c| c.id.as_str()).collect();
    let wanted: Vec<(String, String)> = if named.is_empty() {
        list.iter()
            .filter(|c| args.all || live.contains(c.id.as_str()))
            .map(|c| (c.id.clone(), c.name.clone()))
            .collect()
    } else {
        named.to_vec()
    };
    rows.retain(|r| wanted.iter().any(|(id, _)| *id == r.id));
    for (id, name) in wanted {
        if !rows.iter().any(|r| r.id == id) {
            rows.push(Row { id, name, follower: None });
        }
    }
    for row in rows.iter_mut() {
        let following = row.follower.as_ref().is_some_and(|t| !t.is_finished());
        if live.contains(row.id.as_str()) && !following {
            // An aborted follower (of a row that went and came back) left
            // its last samples behind.
            lock(shared).remove(&row.id);
            row.follower = Some(tokio::spawn(follow(ctx.client.clone(), row.id.clone(), shared.clone())));
        }
    }
    Ok(())
}

/// Waits until every followed container has `samples` samples (two for
/// a CPU rate, which `--no-stream` needs) or its stream has ended, for a
/// few seconds at most.
async fn settle(rows: &[Row], shared: &Shared, samples: usize) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while tokio::time::Instant::now() < deadline {
        let ready = {
            let map = lock(shared);
            rows.iter().all(|r| {
                let ended = r.follower.as_ref().is_none_or(JoinHandle::is_finished);
                let have =
                    map.get(&r.id).map_or(0, |s| usize::from(s.current.is_some()) + usize::from(s.previous.is_some()));
                ended || have >= samples
            })
        };
        if ready {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn draw(
    ctx: &mut Ctx,
    args: &StatsArgs,
    rows: &[Row],
    shared: &Shared,
    host_memory: u64,
    redraw: bool,
) -> anyhow::Result<()> {
    let mut table =
        Table::new(&["CONTAINER ID", "NAME", "CPU %", "MEM USAGE / LIMIT", "MEM %", "NET I/O", "BLOCK I/O", "PIDS"]);
    {
        let map = lock(shared);
        for row in rows {
            let usage = map
                .get(&row.id)
                .and_then(|s| Some(Usage::new(s.previous.as_ref(), s.current.as_ref()?, host_memory)))
                .unwrap_or_default();
            let id = if args.no_trunc { row.id.clone() } else { short_id(&row.id).to_owned() };
            let mut cells = vec![id, row.name.clone()];
            cells.extend(usage.cells());
            table.row(cells);
        }
    }
    let out = &mut ctx.console.stdout;
    if redraw {
        // Clear the screen and start at the top, as `docker stats` does.
        out.write_all(b"\x1b[2J\x1b[H")?;
    }
    table.write(&mut **out)?;
    out.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use rustlet_spec::stats::NetDev;

    use super::*;

    fn sample(read: &str, usage_usec: u64) -> StatsSample {
        StatsSample {
            read: read.into(),
            cpu: [("usage_usec".to_owned(), usage_usec)].into(),
            memory_current: 100 << 20,
            memory_stat: [("inactive_file".to_owned(), 30 << 20), ("anon".to_owned(), 60 << 20)].into(),
            pids_current: 3,
            io: [
                ("8:0".to_owned(), BTreeMap::from([("rbytes".to_owned(), 1000), ("wbytes".to_owned(), 24)])),
                ("8:16".to_owned(), BTreeMap::from([("rbytes".to_owned(), 200), ("rios".to_owned(), 7)])),
            ]
            .into(),
            network: vec![
                NetDev { name: "lo".into(), rx_bytes: 100, tx_bytes: 100, ..NetDev::default() },
                NetDev { name: "eth0".into(), rx_bytes: 1100, tx_bytes: 548, ..NetDev::default() },
            ],
            ..StatsSample::default()
        }
    }

    #[test]
    fn cpu_is_time_used_over_wall_time() {
        let a = sample("2026-10-01T12:00:00.000000000Z", 1_000_000);
        // Two CPUs busy for half a second: 200%.
        let b = sample("2026-10-01T12:00:00.500000000Z", 2_000_000);
        assert!((cpu_percent(&a, &b) - 200.0).abs() < 1e-9);
        // A quarter of one CPU over a second.
        let c = sample("2026-10-01T12:00:01.500000000Z", 2_250_000);
        assert!((cpu_percent(&b, &c) - 25.0).abs() < 1e-9);
        // No time between them, or times that don't parse: no rate.
        assert_eq!(cpu_percent(&a, &a), 0.0);
        assert_eq!(cpu_percent(&sample("?", 0), &b), 0.0);
        // A counter that went backwards (a restarted container) isn't negative.
        assert_eq!(cpu_percent(&b, &sample("2026-10-01T12:00:02Z", 10)), 0.0);
    }

    #[test]
    fn memory_leaves_out_inactive_page_cache() {
        let s = sample("2026-10-01T12:00:00Z", 0);
        assert_eq!(memory_usage(&s), 70 << 20);
        let mut odd = s.clone();
        odd.memory_stat.insert("inactive_file".into(), 200 << 20);
        assert_eq!(memory_usage(&odd), 100 << 20);
        odd.memory_stat.clear();
        assert_eq!(memory_usage(&odd), 100 << 20);
    }

    #[test]
    fn usage_rows() {
        let a = sample("2026-10-01T12:00:00Z", 0);
        let mut b = sample("2026-10-01T12:00:01Z", 50_000);
        let host = 2 << 30;
        let u = Usage::new(Some(&a), &b, host);
        assert_eq!(u.memory_limit, host);
        assert_eq!((u.net_rx, u.net_tx, u.block_read, u.block_written, u.pids), (1100, 548, 1200, 24, 3));
        assert_eq!(
            u.cells(),
            [
                "5.00%".to_owned(),
                "70MiB / 2GiB".to_owned(),
                "3.42%".to_owned(),
                "1.1kB / 548B".to_owned(),
                "1.2kB / 24B".to_owned(),
                "3".to_owned(),
            ]
        );
        b.memory_max = Some(512 << 20);
        let u = Usage::new(None, &b, host);
        assert_eq!((u.cpu_percent, u.memory_limit), (0.0, 512 << 20));
        assert_eq!(u.cells()[2], "13.67%");
        assert_eq!(Usage::default().cells()[1], "0B / 0B");
    }
}

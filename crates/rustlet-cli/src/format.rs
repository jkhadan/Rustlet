//! How the CLI shows things: tables, sizes, durations, states, ports and
//! names, the way `docker` shows them and in its order.
//!
//! People read these outputs by eye and scripts by column, and both know
//! Docker's, so the wording and arithmetic are Docker's (its CLI and the
//! `go-units` package it uses): `Up 5 minutes`, `Exited (0) 3 seconds
//! ago`, memory in binary units with four significant digits (`5.629MiB`),
//! transfer and image sizes in decimal ones with three (`7.81MB`), the
//! space a prune freed with four (`7.812MB`). Where Docker prints
//! something odd (`1e+03kB` for a value that rounds up to the next unit)
//! this prints the plain number instead.
//!
//! Everything that depends on the time takes "now" as an argument, so the
//! tests can pin it.

use std::cmp::Ordering;
use std::io::{self, Write};
use std::time::Duration;

use chrono::{DateTime, Local, NaiveDate, NaiveDateTime, TimeZone, Utc};
use rustlet_spec::container::{ContainerState, ContainerStatus};
use rustlet_spec::network::PublishedPort;

/// A table laid out as `docker` lays them out (Go's `tabwriter` with a
/// minimum width of 10 and a padding of 3): every column but the last is
/// as wide as its widest cell plus three spaces, and at least ten.
#[derive(Debug, Clone)]
pub struct Table {
    rows: Vec<Vec<String>>,
}

impl Table {
    pub fn new(header: &[&str]) -> Table {
        Table { rows: vec![header.iter().map(|h| (*h).to_owned()).collect()] }
    }

    pub fn row(&mut self, cells: Vec<String>) {
        self.rows.push(cells);
    }

    pub fn write(&self, out: &mut dyn Write) -> io::Result<()> {
        out.write_all(self.render().as_bytes())
    }

    pub fn render(&self) -> String {
        let columns = self.rows.iter().map(Vec::len).max().unwrap_or(0);
        let width = |c: usize| {
            let widest = self.rows.iter().filter_map(|r| r.get(c)).map(|s| s.chars().count()).max().unwrap_or(0);
            (widest + 3).max(10)
        };
        let widths: Vec<usize> = (0..columns.saturating_sub(1)).map(width).collect();
        let mut out = String::new();
        for row in &self.rows {
            for (c, cell) in row.iter().enumerate() {
                out.push_str(cell);
                if let Some(&w) = widths.get(c)
                    && c + 1 < row.len()
                {
                    out.extend(std::iter::repeat_n(' ', w - cell.chars().count()));
                }
            }
            out.push('\n');
        }
        out
    }
}

/// Docker's `HumanDuration`: "Less than a second", "About a minute",
/// "3 hours", "2 weeks"…
pub fn human_duration(d: Duration) -> String {
    let seconds = d.as_secs();
    if seconds < 1 {
        return "Less than a second".to_owned();
    }
    if seconds == 1 {
        return "1 second".to_owned();
    }
    if seconds < 60 {
        return format!("{seconds} seconds");
    }
    let minutes = seconds / 60;
    if minutes == 1 {
        return "About a minute".to_owned();
    }
    if minutes < 60 {
        return format!("{minutes} minutes");
    }
    // Hours are rounded, everything else is truncated, as in go-units.
    let hours = (d.as_secs_f64() / 3600.0 + 0.5) as u64;
    match hours {
        1 => "About an hour".to_owned(),
        h if h < 48 => format!("{h} hours"),
        h if h < 24 * 7 * 2 => format!("{} days", h / 24),
        h if h < 24 * 30 * 2 => format!("{} weeks", h / 24 / 7),
        h if h < 24 * 365 * 2 => format!("{} months", h / 24 / 30),
        _ => format!("{} years", (d.as_secs_f64() / 3600.0) as u64 / 24 / 365),
    }
}

/// How long ago the RFC 3339 time `ts` was (zero if it is in the future).
pub fn elapsed(ts: &str, now: DateTime<Utc>) -> Option<Duration> {
    let then = DateTime::parse_from_rfc3339(ts).ok()?;
    Some((now - then.with_timezone(&Utc)).to_std().unwrap_or_default())
}

/// "5 minutes ago", or "N/A" for a time that doesn't parse.
pub fn ago(ts: &str, now: DateTime<Utc>) -> String {
    elapsed(ts, now).map_or_else(|| "N/A".to_owned(), |d| format!("{} ago", human_duration(d)))
}

/// The STATUS column of `ps`.
pub fn status_text(state: &ContainerState, now: DateTime<Utc>) -> String {
    let since = |ts: &Option<String>| ts.as_deref().and_then(|t| elapsed(t, now)).map(human_duration);
    let code = state.exit_code.unwrap_or(0);
    let up = || since(&state.started_at).unwrap_or_else(|| human_duration(Duration::ZERO));
    match state.status {
        ContainerStatus::Created => "Created".to_owned(),
        ContainerStatus::Running => format!("Up {}", up()),
        ContainerStatus::Paused => format!("Up {} (Paused)", up()),
        ContainerStatus::Restarting => match since(&state.finished_at) {
            Some(d) => format!("Restarting ({code}) {d} ago"),
            None => format!("Restarting ({code})"),
        },
        ContainerStatus::Exited => match since(&state.finished_at) {
            Some(d) => format!("Exited ({code}) {d} ago"),
            None => format!("Exited ({code})"),
        },
        ContainerStatus::Removing => "Removing".to_owned(),
        ContainerStatus::Dead => "Dead".to_owned(),
    }
}

/// The COMMAND column of `ps`: the command line, cut to 20 characters
/// (`…` included) unless `full`, then quoted.
pub fn command_text(command: &[String], full: bool) -> String {
    let line = command.join(" ");
    let line = if full { line } else { ellipsis(&line, 20) };
    format!("{line:?}")
}

/// The PORTS column of `ps`: `0.0.0.0:8080->80/tcp, …`, in Docker's order
/// (by container port, then host address, host port and protocol). Unlike
/// Docker's, a range is shown port by port.
pub fn ports_text(ports: &[PublishedPort]) -> String {
    let mut ports = ports.to_vec();
    ports.sort_by_key(|p| (p.container_port, p.host_ip, p.host_port, p.protocol));
    ports.iter().map(PublishedPort::to_string).collect::<Vec<_>>().join(", ")
}

/// Docker's order for names in a list (`sortorder.NaturalLess`): a run of
/// digits compares as a number (`net2` before `net10`) and comes before
/// any other character; the rest compares byte by byte. Of two equal
/// numbers, the one with fewer leading zeros comes first.
pub fn natural_cmp(a: &str, b: &str) -> Ordering {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    // The first index from `i` on whose byte isn't of `class`, or the end.
    let end =
        |s: &[u8], i: usize, class: fn(&u8) -> bool| s[i..].iter().position(|c| !class(c)).map_or(s.len(), |n| i + n);
    let (mut i, mut j) = (0, 0);
    while i < a.len() && j < b.len() {
        match (a[i].is_ascii_digit(), b[j].is_ascii_digit()) {
            (true, false) => return Ordering::Less,
            (false, true) => return Ordering::Greater,
            (false, false) if a[i] != b[j] => return a[i].cmp(&b[j]),
            (false, false) => (i, j) = (i + 1, j + 1),
            (true, true) => {
                // Each number's significant digits, after its leading zeros.
                let (start_a, start_b) = (end(a, i, |c| *c == b'0'), end(b, j, |c| *c == b'0'));
                let (end_a, end_b) = (end(a, start_a, u8::is_ascii_digit), end(b, start_b, u8::is_ascii_digit));
                // Fewer digits is smaller; else the first digit that differs
                // decides; else fewer zeros comes first.
                let order = (end_a - start_a)
                    .cmp(&(end_b - start_b))
                    .then_with(|| a[start_a..end_a].cmp(&b[start_b..end_b]))
                    .then_with(|| (start_a - i).cmp(&(start_b - j)));
                if order != Ordering::Equal {
                    return order;
                }
                (i, j) = (end_a, end_b);
            }
        }
    }
    // Equal so far: the one that ended first comes first.
    (a.len() - i).cmp(&(b.len() - j))
}

/// `s` cut to `max` characters, the last of them `…`.
pub fn ellipsis(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_owned();
    }
    let mut cut: String = s.chars().take(max.saturating_sub(1)).collect();
    cut.push('…');
    cut
}

/// Bytes in binary units, four significant digits: `5.629MiB`. For
/// memory, as `docker stats` shows it.
pub fn bytes_iec(n: u64) -> String {
    scaled(n, 1024.0, &["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"], 4)
}

/// Bytes in decimal units, three significant digits: `7.81MB`. For
/// network and block I/O and image sizes.
pub fn bytes_si(n: u64) -> String {
    scaled(n, 1000.0, &SI_UNITS, 3)
}

/// Bytes in decimal units, four significant digits: `7.812MB`, as Docker's
/// `HumanSize`. For the space a prune reclaimed.
pub fn human_size(n: u64) -> String {
    scaled(n, 1000.0, &SI_UNITS, 4)
}

const SI_UNITS: [&str; 7] = ["B", "kB", "MB", "GB", "TB", "PB", "EB"];

fn scaled(n: u64, base: f64, units: &[&str], digits: usize) -> String {
    let mut v = n as f64;
    let mut unit = 0;
    while v >= base && unit + 1 < units.len() {
        v /= base;
        unit += 1;
    }
    format!("{}{}", significant(v, digits), units[unit])
}

/// Go's `%.Ng` for the values sizes take: `digits` significant digits,
/// trailing zeros dropped, never an exponent.
fn significant(v: f64, digits: usize) -> String {
    if v <= 0.0 || !v.is_finite() {
        return "0".to_owned();
    }
    let integer_digits = if v >= 1.0 { v.log10().floor() as usize + 1 } else { 1 };
    let s = format!("{v:.*}", digits.saturating_sub(integer_digits));
    if s.contains('.') { s.trim_end_matches('0').trim_end_matches('.').to_owned() } else { s }
}

/// A size as Docker's `--memory` takes it (go-units' `RAMInBytes`): a
/// number, possibly with a fraction, and an optional unit `b`, `k`, `m`,
/// `g`, `t` or `p` in binary multiples, any case, optionally followed by
/// `i` and/or `b`: `512m`, `1g`, `64M`, `1.5GiB`, `100b`, `1024`.
pub fn parse_size(s: &str) -> Result<u64, String> {
    let bad = || format!("invalid size {s:?}: expected a number of bytes, or one with a unit like 512m or 1g");
    let t = s.trim();
    let digits = t.find(|c: char| !(c.is_ascii_digit() || c == '.')).unwrap_or(t.len());
    let (number, unit) = t.split_at(digits);
    if number.is_empty() || number.starts_with('.') || number.ends_with('.') {
        return Err(bad());
    }
    let number: f64 = number.parse().map_err(|_| bad())?;
    let unit = unit.strip_prefix(' ').unwrap_or(unit).to_ascii_lowercase();
    let (scale, rest) = match unit.chars().next() {
        Some(c @ ('k' | 'm' | 'g' | 't' | 'p')) => {
            let power = "kmgtp".find(c).map_or(0, |i| i as i32 + 1);
            (1024f64.powi(power), &unit[1..])
        }
        _ => (1.0, unit.as_str()),
    };
    let rest = if scale > 1.0 { rest.strip_prefix('i').unwrap_or(rest) } else { rest };
    if !(rest.is_empty() || rest == "b") {
        return Err(bad());
    }
    let bytes = number * scale;
    if bytes >= u64::MAX as f64 {
        return Err(format!("invalid size {s:?}: too large"));
    }
    Ok(bytes as u64)
}

/// A repository and tag as `docker images` shows them: Docker Hub's host
/// and its `library/` are left out (`docker.io/library/alpine:latest` →
/// `alpine`, `latest`), other registries keep theirs; a name pinned by
/// digest has no tag (`<none>`).
pub fn split_image_name(name: &str) -> (String, String) {
    let (repo, tag) = match name.split_once('@') {
        Some((repo, _digest)) => (repo, "<none>"),
        None => match name.rsplit_once(':') {
            // A colon in the last path component is a tag's; before a
            // slash it is a registry's port.
            Some((repo, tag)) if !tag.contains('/') => (repo, tag),
            _ => (name, "<none>"),
        },
    };
    (familiar_repo(repo).to_owned(), tag.to_owned())
}

/// A repository without `docker.io/` (and `library/`, for Docker Hub's
/// official images), as Docker's `FamiliarName`.
pub fn familiar_repo(repo: &str) -> &str {
    match repo.strip_prefix("docker.io/") {
        Some(rest) => match rest.strip_prefix("library/") {
            Some(name) if !name.contains('/') => name,
            _ => rest,
        },
        None => repo,
    }
}

/// The first 12 hex digits of a digest (`sha256:9824c27679d3…` →
/// `9824c27679d3`): an image or layer id as Docker shows one.
pub fn short_digest(digest: &str) -> &str {
    let hex = digest.split_once(':').map_or(digest, |(_, hex)| hex);
    &hex[..hex.len().min(12)]
}

/// A `--since`/`--until` value in the form the daemon takes (Unix seconds
/// with nanoseconds), from anything Docker's CLI accepts there: a Go
/// duration back from `now` (`10m`, `1h30m`), RFC 3339, a date or local
/// time without a zone (`2026-10-01`, `2026-10-01T15:04:05`), or Unix
/// seconds, which pass unchanged.
pub fn parse_time_arg(s: &str, now: DateTime<Utc>) -> Result<String, String> {
    let unix = |t: DateTime<Utc>| format!("{}.{:09}", t.timestamp(), t.timestamp_subsec_nanos());
    let s = s.trim();
    if s != "0"
        && let Some(nanos) = parse_go_duration(s)
    {
        return Ok(unix(now - chrono::Duration::nanoseconds(nanos)));
    }
    if let Ok(t) = DateTime::parse_from_rfc3339(s) {
        return Ok(unix(t.with_timezone(&Utc)));
    }
    let local = ["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%dT%H:%M"]
        .iter()
        .find_map(|f| NaiveDateTime::parse_from_str(s, f).ok())
        .or_else(|| NaiveDate::parse_from_str(s, "%Y-%m-%d").ok().and_then(|d| d.and_hms_opt(0, 0, 0)));
    if let Some(naive) = local {
        let t = Local.from_local_datetime(&naive).earliest().ok_or_else(|| format!("{s:?} doesn't exist here"))?;
        return Ok(unix(t.with_timezone(&Utc)));
    }
    let (whole, fraction) = s.split_once('.').unwrap_or((s, "0"));
    let numeric = |p: &str| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit());
    if numeric(whole) && numeric(fraction) {
        return Ok(s.to_owned());
    }
    Err(format!("{s:?} is not a time or a duration (10m, 2026-10-01T15:04:05Z, a Unix timestamp)"))
}

/// Go's `time.ParseDuration`, in nanoseconds: `300ms`, `-1.5h`, `2h45m`.
fn parse_go_duration(s: &str) -> Option<i64> {
    let (negative, mut rest) = match s.as_bytes().first() {
        Some(b'-') => (true, &s[1..]),
        Some(b'+') => (false, &s[1..]),
        _ => (false, s),
    };
    if rest == "0" {
        return Some(0);
    }
    if rest.is_empty() {
        return None;
    }
    let mut total = 0f64;
    while !rest.is_empty() {
        let n = rest.find(|c: char| !(c.is_ascii_digit() || c == '.')).unwrap_or(rest.len());
        let number: f64 = rest[..n].parse().ok()?;
        rest = &rest[n..];
        let u = rest.find(|c: char| c.is_ascii_digit() || c == '.').unwrap_or(rest.len());
        let scale = match &rest[..u] {
            "ns" => 1.0,
            "us" | "µs" | "μs" => 1e3,
            "ms" => 1e6,
            "s" => 1e9,
            "m" => 60e9,
            "h" => 3600e9,
            _ => return None,
        };
        total += number * scale;
        rest = &rest[u..];
    }
    let total = total as i64;
    Some(if negative { -total } else { total })
}

#[cfg(test)]
mod tests {
    use rustlet_spec::network::Protocol;

    use super::*;

    fn at(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    #[test]
    fn tables_pad_like_tabwriter() {
        let mut t = Table::new(&["REPOSITORY", "TAG", "SIZE"]);
        t.row(vec!["alpine".into(), "latest".into(), "3.62MB".into()]);
        t.row(vec!["ghcr.io/o/n".into(), "1".into(), "1kB".into()]);
        assert_eq!(
            t.render(),
            "REPOSITORY    TAG       SIZE\n\
             alpine        latest    3.62MB\n\
             ghcr.io/o/n   1         1kB\n"
        );
    }

    #[test]
    fn durations_read_like_dockers() {
        let d = Duration::from_secs;
        let cases = [
            (Duration::from_millis(400), "Less than a second"),
            (d(1), "1 second"),
            (d(59), "59 seconds"),
            (d(60), "About a minute"),
            (d(119), "About a minute"),
            (d(120), "2 minutes"),
            (d(59 * 60 + 59), "59 minutes"),
            (d(3600), "About an hour"),
            (d(5399), "About an hour"),
            (d(5400), "2 hours"),
            (d(47 * 3600), "47 hours"),
            (d(48 * 3600), "2 days"),
            (d(13 * 86400), "13 days"),
            (d(14 * 86400), "2 weeks"),
            (d(59 * 86400), "8 weeks"),
            (d(60 * 86400), "2 months"),
            (d(729 * 86400), "24 months"),
            (d(730 * 86400), "2 years"),
        ];
        for (duration, text) in cases {
            assert_eq!(human_duration(duration), text, "{duration:?}");
        }
        let now = at("2026-10-01T12:00:00Z");
        assert_eq!(ago("2026-10-01T11:55:00.123456789Z", now), "4 minutes ago");
        assert_eq!(ago("2026-10-01T12:00:05Z", now), "Less than a second ago");
        assert_eq!(ago("yesterday", now), "N/A");
    }

    #[test]
    fn ps_statuses() {
        let now = at("2026-10-01T12:00:00Z");
        let state = |status, exit_code, started: Option<&str>, finished: Option<&str>| ContainerState {
            status,
            exit_code,
            started_at: started.map(str::to_owned),
            finished_at: finished.map(str::to_owned),
            ..ContainerState::default()
        };
        let five_min = Some("2026-10-01T11:55:00Z");
        let two_hours = Some("2026-10-01T10:00:00Z");
        let three_s = Some("2026-10-01T11:59:57Z");
        let cases = [
            (state(ContainerStatus::Created, None, None, None), "Created"),
            (state(ContainerStatus::Running, None, five_min, None), "Up 5 minutes"),
            (state(ContainerStatus::Paused, None, two_hours, None), "Up 2 hours (Paused)"),
            (state(ContainerStatus::Exited, Some(0), five_min, three_s), "Exited (0) 3 seconds ago"),
            (state(ContainerStatus::Exited, Some(137), None, None), "Exited (137)"),
            (
                state(ContainerStatus::Restarting, Some(1), five_min, Some("2026-10-01T11:59:58Z")),
                "Restarting (1) 2 seconds ago",
            ),
            (state(ContainerStatus::Removing, Some(0), None, None), "Removing"),
            (state(ContainerStatus::Dead, None, None, None), "Dead"),
        ];
        for (state, text) in cases {
            assert_eq!(status_text(&state, now), text, "{state:?}");
        }
    }

    #[test]
    fn commands_are_cut_then_quoted() {
        let cmd = |s: &str| s.split(' ').map(str::to_owned).collect::<Vec<_>>();
        assert_eq!(command_text(&cmd("sh"), false), r#""sh""#);
        assert_eq!(
            command_text(&cmd("/docker-entrypoint.sh nginx -g daemon off;"), false),
            r#""/docker-entrypoint.…""#
        );
        assert_eq!(command_text(&cmd("echo \"hi\""), true), r#""echo \"hi\"""#);
        assert_eq!(ellipsis("12345678901234567890", 20), "12345678901234567890");
    }

    #[test]
    fn sizes_parse_like_ram_in_bytes() {
        let ok = [
            ("512m", 512 << 20),
            ("1g", 1 << 30),
            ("64M", 64 << 20),
            ("1024", 1024),
            ("100b", 100),
            ("2KiB", 2048),
            ("1.5g", 3 << 29),
            ("1 GB", 1 << 30),
            ("4mb", 4 << 20),
            ("1t", 1 << 40),
        ];
        for (s, n) in ok {
            assert_eq!(parse_size(s), Ok(n), "{s}");
        }
        for bad in ["", "m", "-1m", "1x", "1.", ".5m", "1mm", "1ib", "1e3", "12 34"] {
            assert!(parse_size(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn sizes_display_like_go_units() {
        assert_eq!(bytes_iec(0), "0B");
        assert_eq!(bytes_iec(1023), "1023B");
        assert_eq!(bytes_iec(1024), "1KiB");
        assert_eq!(bytes_iec(5_662_310), "5.4MiB");
        assert_eq!(bytes_iec(5_902_336), "5.629MiB");
        assert_eq!(bytes_iec(2_040_109_465), "1.9GiB");
        assert_eq!(bytes_iec(2_087_354_368), "1.944GiB");
        assert_eq!(bytes_si(0), "0B");
        assert_eq!(bytes_si(999), "999B");
        assert_eq!(bytes_si(1200), "1.2kB");
        assert_eq!(bytes_si(13_287), "13.3kB");
        assert_eq!(bytes_si(7_800_000), "7.8MB");
        assert_eq!(bytes_si(7_812_345), "7.81MB");
        assert_eq!(bytes_si(187_430_000), "187MB");
        assert_eq!(bytes_si(1_234_567_890), "1.23GB");
        assert_eq!(human_size(0), "0B");
        assert_eq!(human_size(999), "999B");
        assert_eq!(human_size(1200), "1.2kB");
        assert_eq!(human_size(7_812_345), "7.812MB");
        assert_eq!(human_size(1_234_567_890), "1.235GB");
    }

    #[test]
    fn ports_are_shown_in_dockers_order() {
        let port = |ip: [u8; 4], host_port, container_port, protocol| PublishedPort {
            host_ip: ip.into(),
            host_port,
            container_port,
            protocol,
        };
        let ports = [
            port([127, 0, 0, 1], 8443, 443, Protocol::Tcp),
            port([0, 0, 0, 0], 5353, 53, Protocol::Udp),
            port([0, 0, 0, 0], 8081, 80, Protocol::Tcp),
            port([0, 0, 0, 0], 8080, 80, Protocol::Udp),
        ];
        // By container port, then host address and port, then protocol.
        assert_eq!(
            ports_text(&ports),
            "0.0.0.0:5353->53/udp, 0.0.0.0:8080->80/udp, 0.0.0.0:8081->80/tcp, 127.0.0.1:8443->443/tcp"
        );
        assert_eq!(ports_text(&[]), "");
    }

    #[test]
    fn names_sort_naturally() {
        let mut names = ["net10", "net2", "Net1", "a", "net02", "net2a", "9e", "10", "net", "web"];
        names.sort_by(|a, b| natural_cmp(a, b));
        // Numbers by value, before letters; of equal ones, fewer zeros first,
        // whatever follows (sortorder's rule).
        assert_eq!(names, ["9e", "10", "Net1", "a", "net", "net2", "net2a", "net02", "net10", "web"]);
        assert_eq!(natural_cmp("db", "db"), Ordering::Equal);
        assert_eq!(natural_cmp("a00", "a0"), Ordering::Greater);
    }

    #[test]
    fn image_names_split_like_dockers() {
        let split = |n| split_image_name(n);
        assert_eq!(split("docker.io/library/alpine:latest"), ("alpine".into(), "latest".into()));
        assert_eq!(split("docker.io/user/app:1"), ("user/app".into(), "1".into()));
        assert_eq!(split("docker.io/library/a/b:2"), ("library/a/b".into(), "2".into()));
        assert_eq!(split("ghcr.io/o/n:v1.2"), ("ghcr.io/o/n".into(), "v1.2".into()));
        assert_eq!(split("localhost:5000/app:dev"), ("localhost:5000/app".into(), "dev".into()));
        assert_eq!(split("localhost:5000/app"), ("localhost:5000/app".into(), "<none>".into()));
        assert_eq!(split("docker.io/library/alpine@sha256:abc"), ("alpine".into(), "<none>".into()));
        assert_eq!(short_digest("sha256:9824c27679d3b27c0e1cb00b2b5cdbc2d1ae6e8f"), "9824c27679d3");
        assert_eq!(short_digest("abc"), "abc");
    }

    #[test]
    fn time_args() {
        let now = at("2026-10-01T12:00:00Z");
        assert_eq!(parse_time_arg("10m", now).unwrap(), format!("{}.000000000", now.timestamp() - 600));
        assert_eq!(parse_time_arg("1h30m", now).unwrap(), format!("{}.000000000", now.timestamp() - 5400));
        assert_eq!(parse_time_arg("1.5s", now).unwrap(), format!("{}.500000000", now.timestamp() - 2));
        assert_eq!(
            parse_time_arg("2026-10-01T11:00:00.25Z", now).unwrap(),
            format!("{}.250000000", now.timestamp() - 3600)
        );
        assert_eq!(
            parse_time_arg("2026-10-01T13:00:00+02:00", now).unwrap(),
            format!("{}.000000000", now.timestamp() - 3600)
        );
        assert_eq!(parse_time_arg("1727780000", now).unwrap(), "1727780000");
        assert_eq!(parse_time_arg("1727780000.5", now).unwrap(), "1727780000.5");
        assert_eq!(parse_time_arg("0", now).unwrap(), "0");
        // Local times: whatever the zone, a date is its midnight there.
        let midnight =
            Local.from_local_datetime(&NaiveDate::from_ymd_opt(2026, 9, 30).unwrap().and_hms_opt(0, 0, 0).unwrap());
        assert_eq!(parse_time_arg("2026-09-30", now).unwrap(), format!("{}.000000000", midnight.unwrap().timestamp()));
        assert!(parse_time_arg("2026-09-30T10:15", now).is_ok());
        for bad in ["soon", "10", "1x", "2026-13-01", ""] {
            if bad == "10" {
                // A bare number is a Unix timestamp, not a duration.
                assert_eq!(parse_time_arg(bad, now).unwrap(), "10");
                continue;
            }
            assert!(parse_time_arg(bad, now).is_err(), "{bad}");
        }
    }
}

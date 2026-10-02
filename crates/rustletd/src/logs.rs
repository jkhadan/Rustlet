//! Reading container logs for `GET /v1/containers/{id}/logs`: the files
//! the shim writes ([`rustlet_shim::logfile`]), oldest first, then (with
//! `follow`) what is appended while the container runs.
//!
//! Following polls: every 200 ms, or at once when the container's state
//! changes, the current file is read to its end. The shim only ever appends
//! whole lines and rotates by renaming, so an open file keeps being the one
//! we were reading; once it ends and `container.log` is a different file
//! (another inode), the new one is opened from its start. When the container
//! stops, the shim has written its last output already (it reports the exit
//! only after that), so one last read finishes the stream.

use std::collections::VecDeque;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use chrono::{DateTime, Utc};
use rustlet_spec::container::ContainerStatus;
use rustlet_spec::logs::{LogEntry, LogStream, LogsQuery};
use tokio::sync::{mpsc, watch};

use crate::container::Shared;
use crate::error::{ApiError, ApiResult};

const POLL: Duration = Duration::from_millis(200);

/// What a query lets through.
#[derive(Debug, Clone)]
pub struct Filter {
    since: Option<DateTime<Utc>>,
    until: Option<DateTime<Utc>>,
    stdout: bool,
    stderr: bool,
}

impl Filter {
    pub fn new(q: &LogsQuery) -> ApiResult<Filter> {
        Ok(Filter {
            since: q.since.as_deref().map(parse_time).transpose()?,
            until: q.until.as_deref().map(parse_time).transpose()?,
            stdout: q.stdout,
            stderr: q.stderr,
        })
    }

    fn passes(&self, e: &LogEntry) -> bool {
        let stream = match e.stream {
            LogStream::Stdout => self.stdout,
            LogStream::Stderr => self.stderr,
        };
        if !stream {
            return false;
        }
        if self.since.is_none() && self.until.is_none() {
            return true;
        }
        let Ok(t) = DateTime::parse_from_rfc3339(&e.ts) else { return true };
        let t = t.with_timezone(&Utc);
        self.since.is_none_or(|s| t >= s) && self.until.is_none_or(|u| t < u)
    }
}

/// RFC 3339, or Unix seconds with an optional fraction.
pub fn parse_time(s: &str) -> ApiResult<DateTime<Utc>> {
    if let Ok(t) = DateTime::parse_from_rfc3339(s) {
        return Ok(t.with_timezone(&Utc));
    }
    let (secs, frac) = s.split_once('.').unwrap_or((s, ""));
    let secs: i64 =
        secs.parse().map_err(|_| ApiError::invalid(format!("{s:?} is neither RFC 3339 nor Unix seconds")))?;
    let nanos: u32 = if frac.is_empty() {
        0
    } else {
        let digits: String = frac.chars().take(9).collect();
        let n: u32 = digits.parse().map_err(|_| ApiError::invalid(format!("bad fraction in {s:?}")))?;
        n * 10u32.pow(9 - digits.len() as u32)
    };
    DateTime::from_timestamp(secs, nanos).ok_or_else(|| ApiError::invalid(format!("{s:?} is out of range")))
}

/// Where a reader stands in the current file.
pub struct Position {
    file: Option<File>,
    ino: u64,
    /// Bytes of an entry not complete yet (the shim is writing it).
    partial: Vec<u8>,
}

/// The entries already written (the last `tail`, if given), and where the
/// current file ends.
pub fn existing(path: &Path, filter: &Filter, tail: Option<u64>) -> ApiResult<(Vec<LogEntry>, Position)> {
    let files = rustlet_shim::logfile::log_files(path);
    let mut out: VecDeque<LogEntry> = VecDeque::new();
    let keep = |out: &mut VecDeque<LogEntry>, e: LogEntry| {
        if tail == Some(0) {
            return;
        }
        out.push_back(e);
        if let Some(n) = tail
            && out.len() as u64 > n
        {
            out.pop_front();
        }
    };
    let mut pos = Position { file: None, ino: 0, partial: Vec::new() };
    for f in &files {
        let mut file = match File::open(f) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(ApiError::internal(format!("open {}: {e}", f.display()))),
        };
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        let partial = parse_lines(&bytes, |e| {
            if filter.passes(&e) {
                keep(&mut out, e);
            }
        });
        if f == path {
            pos.ino = file.metadata()?.ino();
            pos.partial = partial.to_vec();
            pos.file = Some(file);
        }
    }
    Ok((out.into(), pos))
}

/// Calls `each` for every complete line; returns the incomplete rest.
fn parse_lines(bytes: &[u8], mut each: impl FnMut(LogEntry)) -> &[u8] {
    let mut rest = bytes;
    while let Some(i) = rest.iter().position(|&b| b == b'\n') {
        let line = &rest[..i];
        rest = &rest[i + 1..];
        match serde_json::from_slice::<LogEntry>(line) {
            Ok(e) => each(e),
            Err(e) => tracing::debug!("skipping an unreadable log line: {e}"),
        }
    }
    rest
}

/// Sends what is appended to the log while the container runs, then ends.
pub async fn follow(
    path: PathBuf,
    mut pos: Position,
    filter: Filter,
    mut state: watch::Receiver<Shared>,
    tx: mpsc::Sender<LogEntry>,
) {
    loop {
        let running = {
            let s = state.borrow_and_update();
            !s.removed
                && matches!(
                    s.persisted.state.status,
                    ContainerStatus::Running | ContainerStatus::Paused | ContainerStatus::Restarting
                )
        };
        match read_new(&path, &mut pos, &filter) {
            Ok(entries) => {
                for e in entries {
                    if tx.send(e).await.is_err() {
                        return; // the client went away
                    }
                }
            }
            Err(e) => {
                tracing::warn!("following {}: {e}", path.display());
                return;
            }
        }
        if !running {
            return;
        }
        tokio::select! {
            () = tokio::time::sleep(POLL) => {}
            changed = state.changed() => if changed.is_err() { return },
            () = tx.closed() => return,
        }
    }
}

/// Whatever was appended since the last read, including a switch to a new
/// file after a rotation.
fn read_new(path: &Path, pos: &mut Position, filter: &Filter) -> std::io::Result<Vec<LogEntry>> {
    let mut out = Vec::new();
    loop {
        if let Some(f) = pos.file.as_mut() {
            let mut bytes = std::mem::take(&mut pos.partial);
            f.read_to_end(&mut bytes)?;
            let rest = parse_lines(&bytes, |e| {
                if filter.passes(&e) {
                    out.push(e);
                }
            })
            .to_vec();
            pos.partial = rest;
        }
        // A new file under the name: the one we read was rotated away.
        match std::fs::metadata(path) {
            Ok(m) if m.ino() != pos.ino => {
                let mut f = File::open(path)?;
                f.seek(SeekFrom::Start(0))?;
                pos.ino = m.ino();
                pos.file = Some(f);
                pos.partial.clear();
                continue;
            }
            _ => return Ok(out),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustlet_shim::logfile::{LogWriter, entry};

    fn write(w: &mut LogWriter, stream: LogStream, text: &str) {
        w.write(&entry(stream, text.as_bytes())).unwrap();
    }

    #[test]
    fn tail_and_streams_across_rotated_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("container.log");
        let mut w = LogWriter::open(&path, 300, 3).unwrap();
        for i in 0..8 {
            write(&mut w, if i % 2 == 0 { LogStream::Stdout } else { LogStream::Stderr }, &format!("{i}\n"));
        }
        let all = LogsQuery::default();
        let (entries, _) = existing(&path, &Filter::new(&all).unwrap(), None).unwrap();
        let texts: Vec<_> = entries.iter().map(|e| e.log.trim()).collect();
        assert_eq!(*texts.last().unwrap(), "7");
        let (last2, _) = existing(&path, &Filter::new(&all).unwrap(), Some(2)).unwrap();
        assert_eq!(last2.iter().map(|e| e.log.as_str()).collect::<Vec<_>>(), ["6\n", "7\n"]);
        let only_err = LogsQuery { stdout: false, ..LogsQuery::default() };
        let (errs, _) = existing(&path, &Filter::new(&only_err).unwrap(), None).unwrap();
        assert!(errs.iter().all(|e| e.stream == LogStream::Stderr));
        let (none, _) = existing(&path, &Filter::new(&all).unwrap(), Some(0)).unwrap();
        assert!(none.is_empty());
    }

    #[test]
    fn new_output_and_rotation_are_followed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("container.log");
        let mut w = LogWriter::open(&path, 250, 3).unwrap();
        write(&mut w, LogStream::Stdout, "before\n");
        let filter = Filter::new(&LogsQuery::default()).unwrap();
        let (_, mut pos) = existing(&path, &filter, None).unwrap();
        assert!(read_new(&path, &mut pos, &filter).unwrap().is_empty());
        let mut seen = Vec::new();
        for i in 0..10 {
            write(&mut w, LogStream::Stdout, &format!("after {i}\n"));
            seen.extend(read_new(&path, &mut pos, &filter).unwrap().into_iter().map(|e| e.log));
        }
        let expected: Vec<String> = (0..10).map(|i| format!("after {i}\n")).collect();
        assert_eq!(seen, expected, "every entry exactly once, across rotations");
    }

    #[test]
    fn times() {
        assert_eq!(parse_time("1700000000").unwrap().timestamp(), 1_700_000_000);
        assert_eq!(parse_time("1700000000.5").unwrap().timestamp_subsec_millis(), 500);
        assert_eq!(parse_time("2026-10-01T00:00:00Z").unwrap().timestamp(), 1_790_812_800);
        assert!(parse_time("yesterday").is_err());
        let f = Filter::new(&LogsQuery { since: Some("2026-10-01T00:00:00Z".into()), ..Default::default() }).unwrap();
        let at = |ts: &str| LogEntry { ts: ts.into(), stream: LogStream::Stdout, log: String::new() };
        assert!(f.passes(&at("2026-10-01T00:00:00.000000001Z")));
        assert!(!f.passes(&at("2026-09-30T23:59:59Z")));
    }
}

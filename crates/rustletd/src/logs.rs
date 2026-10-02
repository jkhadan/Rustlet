//! Reading container logs for `GET /v1/containers/{id}/logs`: the files
//! the shim writes ([`rustlet_shim::logfile`]), oldest first, then (with
//! `follow`) what is appended while the container runs.
//!
//! Following polls: every 200 ms, or at once when the container's state
//! changes, the current file is read to its end. The shim only ever appends
//! whole lines and rotates by renaming, so an open file keeps being the one
//! we were reading. Once `container.log` is a different file (another
//! inode), ours is read to its end once more (the shim may have added a
//! last entry just before renaming it), then every file newer than ours,
//! oldest first: a slow reader may be more than one rotation behind. When
//! the container stops, the shim has written its last output already (it
//! reports the exit only after that), so one last read finishes the stream.
//!
//! Files are told apart by inode, never by name: a name may stand for
//! another file by the time it is opened. To find the files newer than
//! ours, the names are opened from the newest (`container.log`) to the
//! oldest; rotation moves files the same way (`container.log` → `.1` →
//! `.2`), so the walk may meet a file twice but never misses one, unless
//! it was deleted meanwhile (`log_max_files`).

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
    let files = open_newest_first(path, None)?;
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
    // Oldest first; the newest is where a follower goes on.
    for (mut file, ino) in files.into_iter().rev() {
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        let partial = parse_lines(&bytes, |e| {
            if filter.passes(&e) {
                keep(&mut out, e);
            }
        });
        pos = Position { file: Some(file), ino, partial: partial.to_vec() };
    }
    Ok((out.into(), pos))
}

/// The log's files, opened, newest first, each once, back to the one whose
/// inode is `stop` (not included) or to the oldest.
fn open_newest_first(path: &Path, stop: Option<u64>) -> std::io::Result<Vec<(File, u64)>> {
    // A rotation during the walk shifts the names up by one.
    let last = rustlet_shim::logfile::highest_number(path) + 2;
    let mut out: Vec<(File, u64)> = Vec::new();
    for n in 0..=last {
        let file = match File::open(rustlet_shim::logfile::numbered(path, n)) {
            Ok(f) => f,
            // A gap while a rotation renames, or no such file.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        let ino = file.metadata()?.ino();
        if Some(ino) == stop {
            break;
        }
        if !out.iter().any(|(_, i)| *i == ino) {
            out.push((file, ino));
        }
    }
    Ok(out)
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

/// Whatever was appended since the last read, including the files that
/// rotations started meanwhile.
fn read_new(path: &Path, pos: &mut Position, filter: &Filter) -> std::io::Result<Vec<LogEntry>> {
    let mut out = Vec::new();
    drain(pos, filter, &mut out)?;
    after_rotation(path, pos, filter, &mut out)?;
    Ok(out)
}

/// If `container.log` is no longer our file: the rest of ours, then every
/// newer file, the current one last (where we go on from).
fn after_rotation(path: &Path, pos: &mut Position, filter: &Filter, out: &mut Vec<LogEntry>) -> std::io::Result<()> {
    let current = match std::fs::metadata(path) {
        Ok(m) => m.ino(),
        // Between a rotation's rename and the new file: next time.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    if pos.file.is_some() && current == pos.ino {
        return Ok(());
    }
    // The shim may have written to ours after it was last read, and then
    // renamed it.
    drain(pos, filter, out)?;
    let newer = open_newest_first(path, pos.file.is_some().then_some(pos.ino))?;
    for (file, ino) in newer.into_iter().rev() {
        *pos = Position { file: Some(file), ino, partial: Vec::new() };
        drain(pos, filter, out)?;
    }
    Ok(())
}

/// Reads the position's file from where it stands to its end.
fn drain(pos: &mut Position, filter: &Filter, out: &mut Vec<LogEntry>) -> std::io::Result<()> {
    let Some(f) = pos.file.as_mut() else { return Ok(()) };
    // Shorter than where we are: truncated (`log_max_files` 1). Its start
    // has what came since (or some of it, if it grew back past us).
    if f.metadata()?.len() < f.stream_position()? {
        f.seek(SeekFrom::Start(0))?;
        pos.partial.clear();
    }
    let mut bytes = std::mem::take(&mut pos.partial);
    f.read_to_end(&mut bytes)?;
    pos.partial = parse_lines(&bytes, |e| {
        if filter.passes(&e) {
            out.push(e);
        }
    })
    .to_vec();
    Ok(())
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

    #[test]
    fn a_follower_two_rotations_behind_reads_every_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("container.log");
        let mut w = LogWriter::open(&path, 250, 3).unwrap();
        write(&mut w, LogStream::Stdout, "before\n");
        let filter = Filter::new(&LogsQuery::default()).unwrap();
        let (_, mut pos) = existing(&path, &filter, None).unwrap();
        // Three rotations before the next read: our file is gone, and the
        // one after it is container.log.2 by now.
        for i in 0..10 {
            write(&mut w, LogStream::Stdout, &format!("after {i}\n"));
        }
        let seen: Vec<String> = read_new(&path, &mut pos, &filter).unwrap().into_iter().map(|e| e.log).collect();
        assert_eq!(seen, (0..10).map(|i| format!("after {i}\n")).collect::<Vec<_>>());
    }

    #[test]
    fn an_entry_written_just_before_its_file_is_renamed_is_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("container.log");
        let mut w = LogWriter::open(&path, 100, 3).unwrap();
        let filter = Filter::new(&LogsQuery::default()).unwrap();
        let (_, mut pos) = existing(&path, &filter, None).unwrap();
        let mut out = Vec::new();
        // The reader has read its file to the end...
        drain(&mut pos, &filter, &mut out).unwrap();
        // ...when the shim appends one more entry, and the next one
        // rotates the file away before the reader looks at the name.
        write(&mut w, LogStream::Stdout, "last in the old file\n");
        write(&mut w, LogStream::Stdout, "first in the new one\n");
        after_rotation(&path, &mut pos, &filter, &mut out).unwrap();
        let seen: Vec<&str> = out.iter().map(|e| e.log.as_str()).collect();
        assert_eq!(seen, ["last in the old file\n", "first in the new one\n"]);
    }

    #[test]
    fn rotations_racing_the_reader_lose_nothing() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("container.log");
        let filter = Filter::new(&LogsQuery::default()).unwrap();
        // Every entry starts a file of its own.
        let mut w = LogWriter::open(&path, 1, 3).unwrap();
        let (_, pos) = existing(&path, &filter, None).unwrap();
        let (seen, done) = (AtomicUsize::new(0), AtomicBool::new(false));
        std::thread::scope(|s| {
            s.spawn(|| {
                let mut pos = pos;
                while !done.load(SeqCst) {
                    seen.fetch_add(read_new(&path, &mut pos, &filter).unwrap().len(), SeqCst);
                }
            });
            // Two at a time: the first can land in a file just before the
            // second renames it away.
            for i in (0..5000).step_by(2) {
                write(&mut w, LogStream::Stdout, "x\n");
                write(&mut w, LogStream::Stdout, "y\n");
                let deadline = std::time::Instant::now() + Duration::from_secs(2);
                while seen.load(SeqCst) < i + 2 {
                    if std::time::Instant::now() > deadline {
                        done.store(true, SeqCst);
                        panic!("entry {i} was never read");
                    }
                    std::hint::spin_loop();
                }
            }
            done.store(true, SeqCst);
        });
        assert_eq!(seen.load(SeqCst), 5000, "each entry once");
    }

    #[test]
    fn every_file_is_read_once_gaps_and_all() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("container.log");
        // Two entries a file: [0, 1] [2, 3] [4, 5].
        let mut w = LogWriter::open(&path, 200, 4).unwrap();
        for i in 0..6 {
            write(&mut w, LogStream::Stdout, &format!("{i}\n"));
        }
        let filter = Filter::new(&LogsQuery::default()).unwrap();
        let all = |path: &Path| -> Vec<String> {
            existing(path, &filter, None).unwrap().0.into_iter().map(|e| e.log.trim().to_owned()).collect()
        };
        let before = all(&path);
        assert_eq!(before, ["0", "1", "2", "3", "4", "5"]);
        // A gap in the names, as while a rotation renames: the older files
        // still count.
        let one = rustlet_shim::logfile::numbered(&path, 1);
        std::fs::rename(&one, dir.path().join("aside")).unwrap();
        assert_eq!(all(&path), ["0", "1", "4", "5"]);
        // One file under two names, as a rotation may show it to the walk:
        // read once.
        std::fs::hard_link(&path, &one).unwrap();
        assert_eq!(all(&path), ["0", "1", "4", "5"]);
    }

    #[test]
    fn a_follower_starts_over_after_truncation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("container.log");
        let mut w = LogWriter::open(&path, 300, 1).unwrap();
        let filter = Filter::new(&LogsQuery::default()).unwrap();
        let (_, mut pos) = existing(&path, &filter, None).unwrap();
        let mut seen = Vec::new();
        for i in 0..12 {
            write(&mut w, LogStream::Stdout, &format!("after {i}\n"));
            seen.extend(read_new(&path, &mut pos, &filter).unwrap().into_iter().map(|e| e.log));
        }
        assert_eq!(seen, (0..12).map(|i| format!("after {i}\n")).collect::<Vec<_>>());
    }

    #[test]
    fn a_line_written_in_two_parts_is_read_once() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("container.log");
        let line = serde_json::to_vec(&entry(LogStream::Stdout, b"split\n")).unwrap();
        let (a, b) = line.split_at(20);
        let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&path).unwrap();
        f.write_all(a).unwrap();
        let filter = Filter::new(&LogsQuery::default()).unwrap();
        let (got, mut pos) = existing(&path, &filter, None).unwrap();
        assert!(got.is_empty());
        f.write_all(b).unwrap();
        f.write_all(b"\n").unwrap();
        let got = read_new(&path, &mut pos, &filter).unwrap();
        assert_eq!(got.iter().map(|e| e.log.as_str()).collect::<Vec<_>>(), ["split\n"]);
    }
}

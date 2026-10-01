//! The container log: JSON lines, one [`LogEntry`] per line of output,
//! rotated by size (format: `rustlet_spec::logs`).
//!
//! ```text
//! container.log       the current file
//! container.log.1     the one before it
//! container.log.2     … up to max_files - 1 old files; older ones are deleted
//! ```
//!
//! The shim writes ([`LogWriter`], [`LineSplitter`]); the daemon reads, in
//! [`log_files`] order.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use rustlet_spec::logs::{LogEntry, LogStream, MAX_LINE};

/// Appends entries to the log, rotating it once it reaches `max_size`.
#[derive(Debug)]
pub struct LogWriter {
    path: PathBuf,
    file: File,
    size: u64,
    max_size: u64,
    max_files: u32,
}

impl LogWriter {
    /// Opens `path` for appending (creating it, mode 0600: the output of a
    /// container is nobody else's business). `max_files` counts the current
    /// file: 1 means "truncate instead of keeping old files".
    pub fn open(path: &Path, max_size: u64, max_files: u32) -> io::Result<LogWriter> {
        let file = open_append(path)?;
        let size = file.metadata()?.len();
        Ok(LogWriter { path: path.to_owned(), file, size, max_size: max_size.max(1), max_files: max_files.max(1) })
    }

    /// Writes one entry, as one line, with one `write` call (a reader never
    /// sees half an entry, except while the call is in progress).
    pub fn write(&mut self, entry: &LogEntry) -> io::Result<()> {
        let mut line = serde_json::to_vec(entry).map_err(io::Error::other)?;
        line.push(b'\n');
        self.file.write_all(&line)?;
        self.size += line.len() as u64;
        if self.size >= self.max_size {
            self.rotate()?;
        }
        Ok(())
    }

    fn rotate(&mut self) -> io::Result<()> {
        let keep = self.max_files - 1;
        if keep == 0 {
            self.file.set_len(0)?;
            self.size = 0;
            return Ok(());
        }
        // container.log.(keep-1) → .keep, …, container.log → .1; the oldest
        // one beyond `keep` is replaced by the rename onto it.
        for n in (1..keep).rev() {
            match std::fs::rename(rotated(&self.path, n), rotated(&self.path, n + 1)) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        std::fs::rename(&self.path, rotated(&self.path, 1))?;
        self.file = open_append(&self.path)?;
        self.size = 0;
        Ok(())
    }
}

fn open_append(path: &Path) -> io::Result<File> {
    OpenOptions::new().create(true).append(true).mode(0o600).custom_flags(libc::O_NOFOLLOW).open(path)
}

/// `container.log.N`.
fn rotated(path: &Path, n: u32) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(format!(".{n}"));
    PathBuf::from(s)
}

/// The log's files that exist, oldest first (the order to read them in).
pub fn log_files(path: &Path) -> Vec<PathBuf> {
    let mut old: Vec<(u32, PathBuf)> = Vec::new();
    if let (Some(dir), Some(name)) = (path.parent(), path.file_name().and_then(|n| n.to_str())) {
        let prefix = format!("{name}.");
        for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
            let file = entry.file_name();
            let Some(n) = file.to_str().and_then(|f| f.strip_prefix(&prefix)).and_then(|n| n.parse().ok()) else {
                continue;
            };
            old.push((n, entry.path()));
        }
    }
    old.sort_by_key(|(n, _)| std::cmp::Reverse(*n));
    let mut files: Vec<PathBuf> = old.into_iter().map(|(_, p)| p).collect();
    if path.exists() {
        files.push(path.to_owned());
    }
    files
}

/// Cuts one stream's output into lines: an entry per `\n`-terminated line,
/// and per [`MAX_LINE`] bytes of a longer one. What is left over waits for
/// more output, or for [`flush`](LineSplitter::flush) at the end.
#[derive(Debug, Default)]
pub struct LineSplitter {
    partial: Vec<u8>,
}

impl LineSplitter {
    /// Feeds `data`; calls `emit` with each complete line (including its
    /// `\n`) or full-size piece.
    pub fn push(&mut self, mut data: &[u8], mut emit: impl FnMut(&[u8])) {
        while !data.is_empty() {
            let room = MAX_LINE - self.partial.len();
            let window = &data[..data.len().min(room)];
            match window.iter().position(|&b| b == b'\n') {
                Some(i) => {
                    self.partial.extend_from_slice(&window[..=i]);
                    emit(&self.partial);
                    self.partial.clear();
                    data = &data[i + 1..];
                }
                None => {
                    self.partial.extend_from_slice(window);
                    data = &data[window.len()..];
                    if self.partial.len() == MAX_LINE {
                        emit(&self.partial);
                        self.partial.clear();
                    }
                }
            }
        }
    }

    /// Emits what is left (a last line without `\n`).
    pub fn flush(&mut self, mut emit: impl FnMut(&[u8])) {
        if !self.partial.is_empty() {
            emit(&self.partial);
            self.partial.clear();
        }
    }
}

/// A log entry for `bytes` of `stream`, read now.
pub fn entry(stream: LogStream, bytes: &[u8]) -> LogEntry {
    LogEntry { ts: now(), stream, log: String::from_utf8_lossy(bytes).into_owned() }
}

/// RFC 3339 with nanoseconds, UTC: the timestamps of the protocol and logs.
pub fn now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(splitter: &mut LineSplitter, chunks: &[&[u8]]) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        for c in chunks {
            splitter.push(c, |l| out.push(l.to_vec()));
        }
        out
    }

    #[test]
    fn output_is_cut_at_newlines_across_chunks() {
        let mut s = LineSplitter::default();
        let got = lines(&mut s, &[b"hel", b"lo\nwor", b"ld\n\nlast"]);
        assert_eq!(got, [b"hello\n".to_vec(), b"world\n".to_vec(), b"\n".to_vec()]);
        let mut rest = Vec::new();
        s.flush(|l| rest.push(l.to_vec()));
        assert_eq!(rest, [b"last".to_vec()]);
        s.flush(|_| panic!("nothing left"));
    }

    #[test]
    fn long_lines_are_split_at_the_limit() {
        let mut s = LineSplitter::default();
        let long = vec![b'x'; MAX_LINE * 2 + 10];
        let mut input = long.clone();
        input.push(b'\n');
        let got = lines(&mut s, &[&input[..100], &input[100..]]);
        assert_eq!(got.iter().map(Vec::len).collect::<Vec<_>>(), [MAX_LINE, MAX_LINE, 11]);
        assert_eq!(got.concat(), input);
    }

    #[test]
    fn rotation_keeps_max_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("container.log");
        let mut w = LogWriter::open(&path, 200, 3).unwrap();
        for i in 0..20 {
            w.write(&entry(LogStream::Stdout, format!("line {i}\n").as_bytes())).unwrap();
        }
        let files = log_files(&path);
        assert_eq!(files, [rotated(&path, 2), rotated(&path, 1), path.clone()]);
        // Read back in order: the newest entries, contiguous, ending with the last.
        let mut logged = Vec::new();
        for f in &files {
            for line in std::fs::read_to_string(f).unwrap().lines() {
                let e: LogEntry = serde_json::from_str(line).unwrap();
                logged.push(e.log);
            }
        }
        assert_eq!(logged.last().unwrap(), "line 19\n");
        let first: usize = logged[0].trim_start_matches("line ").trim().parse().unwrap();
        let expected: Vec<String> = (first..20).map(|i| format!("line {i}\n")).collect();
        assert_eq!(logged, expected);
        // A reopened writer appends (and may rotate right after).
        drop(w);
        let mut w = LogWriter::open(&path, 200, 3).unwrap();
        w.write(&entry(LogStream::Stderr, b"again")).unwrap();
        let all: String = log_files(&path).iter().map(|f| std::fs::read_to_string(f).unwrap()).collect();
        let last: LogEntry = serde_json::from_str(all.lines().last().unwrap()).unwrap();
        assert_eq!((last.stream, last.log.as_str()), (LogStream::Stderr, "again"));
        // (JSON escapes the newline.)
        assert!(all.contains(r"line 19\n"));
    }

    #[test]
    fn a_single_file_is_truncated_instead() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("container.log");
        let mut w = LogWriter::open(&path, 100, 1).unwrap();
        for _ in 0..10 {
            w.write(&entry(LogStream::Stdout, b"0123456789\n")).unwrap();
        }
        assert_eq!(log_files(&path), std::slice::from_ref(&path));
        assert!(std::fs::metadata(&path).unwrap().len() < 200);
    }

    #[test]
    fn invalid_utf8_is_replaced() {
        let e = entry(LogStream::Stdout, b"a\xffb\n");
        assert_eq!(e.log, "a\u{fffd}b\n");
        assert!(e.ts.ends_with('Z') && e.ts.len() == "2026-10-01T00:00:00.000000000Z".len());
    }
}

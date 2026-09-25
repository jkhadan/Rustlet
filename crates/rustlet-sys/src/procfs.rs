//! Small, safe readers for `/proc` files the runtime depends on.

use std::path::PathBuf;

use nix::unistd::Pid;

use crate::{Errno, Result};

fn io_errno(e: std::io::Error) -> Errno {
    Errno::from_raw(e.raw_os_error().unwrap_or(libc::EIO))
}

/// The process start time (field 22 of `/proc/<pid>/stat`, in clock ticks
/// since boot). Stored in the runtime state; if a PID is later recycled, the
/// new process's start time differs, so we never signal the wrong process.
pub fn start_time(pid: Pid) -> Result<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).map_err(io_errno)?;
    parse_start_time(&stat).ok_or(Errno::EINVAL)
}

/// Parses field 22 out of a `/proc/<pid>/stat` line. The `comm` field (2) may
/// contain spaces and parentheses, so we split after the *last* `)`.
pub fn parse_start_time(stat: &str) -> Option<u64> {
    let after = &stat[stat.rfind(')')? + 1..];
    // after ") " the next field is #3 (state); #22 is 19 fields later.
    after.split_whitespace().nth(19)?.parse().ok()
}

/// Process state letter (field 3): `R`, `S`, `D`, `Z` (zombie), `T`, …
pub fn state(pid: Pid) -> Result<char> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).map_err(io_errno)?;
    let after = &stat[stat.rfind(')').ok_or(Errno::EINVAL)? + 1..];
    after.split_whitespace().next().and_then(|s| s.chars().next()).ok_or(Errno::EINVAL)
}

/// The process's `comm` (its name, at most 15 bytes: set from the program
/// at `execve`, or by `PR_SET_NAME`). Readable for zombies too.
pub fn comm(pid: Pid) -> Result<String> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/comm")).map_err(io_errno)?;
    Ok(s.trim_end_matches('\n').to_owned())
}

/// The namespace kinds that appear in `/proc/<pid>/ns/`.
pub const NS_KINDS: [&str; 8] = ["cgroup", "ipc", "mnt", "net", "pid", "time", "user", "uts"];

/// Identity of a namespace: (device, inode) of its nsfs file.
pub fn ns_id(pid: Option<Pid>, kind: &str) -> Result<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let p = match pid {
        Some(pid) => PathBuf::from(format!("/proc/{pid}/ns/{kind}")),
        None => PathBuf::from(format!("/proc/self/ns/{kind}")),
    };
    let m = std::fs::metadata(p).map_err(io_errno)?;
    Ok((m.dev(), m.ino()))
}

/// A `key: value` field from `/proc/<pid>/status` (e.g. `CapEff`, `Seccomp`).
pub fn status_field(pid: Option<Pid>, key: &str) -> Result<String> {
    let p = match pid {
        Some(pid) => format!("/proc/{pid}/status"),
        None => "/proc/self/status".to_owned(),
    };
    let s = std::fs::read_to_string(p).map_err(io_errno)?;
    s.lines()
        .find_map(|l| l.strip_prefix(key).and_then(|r| r.strip_prefix(':')))
        .map(|v| v.trim().to_owned())
        .ok_or(Errno::ENOENT)
}

/// The cgroup v2 path of a process (the `0::/…` line of `/proc/<pid>/cgroup`).
pub fn cgroup_path(pid: Option<Pid>) -> Result<String> {
    let p = match pid {
        Some(pid) => format!("/proc/{pid}/cgroup"),
        None => "/proc/self/cgroup".to_owned(),
    };
    let s = std::fs::read_to_string(p).map_err(io_errno)?;
    s.lines().find_map(|l| l.strip_prefix("0::")).map(str::to_owned).ok_or(Errno::ENOENT)
}

/// Is the process alive (exists and isn't a zombie) with the given start time?
pub fn is_alive(pid: Pid, expected_start: Option<u64>) -> bool {
    match (state(pid), start_time(pid)) {
        (Ok('Z'), _) | (Ok('X'), _) => false,
        (Ok(_), Ok(st)) => expected_start.is_none_or(|e| e == st),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_time_with_tricky_comm() {
        let line = "1234 (we ird) name)) S 1 1234 1234 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 987654 1000 10";
        assert_eq!(parse_start_time(line), Some(987654));
    }

    #[test]
    fn self_is_alive() {
        let me = nix::unistd::getpid();
        let st = start_time(me).unwrap();
        assert!(is_alive(me, Some(st)));
        assert!(!is_alive(me, Some(st + 1)));
    }
}

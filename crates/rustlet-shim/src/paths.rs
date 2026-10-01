//! A shim's files.
//!
//! ```text
//! <run root>/shims/<short id>/         0700, made by the daemon
//! ├─ shim.sock      the control socket (protocol)
//! ├─ shim.log       the shim's own log (its stderr)
//! ├─ init.pid       written by `rustlet-runc create --pid-file`
//! ├─ runc.log       `rustlet-runc --log`: its errors, as JSON lines
//! ├─ exit.json      the container's ExitStatus, once it has exited
//! ├─ tty.sock       the console socket while `create` runs (with a terminal)
//! └─ x<N>.sock, x<N>.pid   the same for exec N
//! ```
//!
//! The directory is named by the *short* id: a Unix socket's path must fit
//! in 108 bytes (`sun_path`), and a full 64-digit id would leave too little
//! room. The daemon never gives two containers the same short id.

use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShimPaths {
    dir: PathBuf,
}

impl ShimPaths {
    pub fn new(dir: impl Into<PathBuf>) -> ShimPaths {
        ShimPaths { dir: dir.into() }
    }
    /// `<run root>/shims/<short id>`.
    pub fn for_container(run_root: &Path, id: &str) -> ShimPaths {
        ShimPaths::new(run_root.join("shims").join(rustlet_spec::short_id(id)))
    }
    pub fn dir(&self) -> &Path {
        &self.dir
    }
    pub fn socket(&self) -> PathBuf {
        self.dir.join("shim.sock")
    }
    pub fn shim_log(&self) -> PathBuf {
        self.dir.join("shim.log")
    }
    pub fn init_pid(&self) -> PathBuf {
        self.dir.join("init.pid")
    }
    pub fn runc_log(&self) -> PathBuf {
        self.dir.join("runc.log")
    }
    pub fn exit_json(&self) -> PathBuf {
        self.dir.join("exit.json")
    }
    pub fn console_socket(&self) -> PathBuf {
        self.dir.join("tty.sock")
    }
    pub fn exec_console_socket(&self, n: u64) -> PathBuf {
        self.dir.join(format!("x{n}.sock"))
    }
    pub fn exec_pid(&self, n: u64) -> PathBuf {
        self.dir.join(format!("x{n}.pid"))
    }
}

/// The longest path `connect(2)` takes for a Unix socket (`sun_path` minus
/// its terminating NUL).
pub const MAX_SOCKET_PATH: usize = 107;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_paths_fit_sun_path_for_long_run_roots() {
        let id = "f".repeat(64);
        // A generous test run root.
        let p = ShimPaths::for_container(Path::new("/run/rustlet/itest-dm-4194304-99"), &id);
        for s in [p.socket(), p.console_socket(), p.exec_console_socket(u64::MAX)] {
            assert!(s.as_os_str().len() <= MAX_SOCKET_PATH, "{}", s.display());
        }
        assert!(p.dir().ends_with("shims/ffffffffffff"));
    }
}

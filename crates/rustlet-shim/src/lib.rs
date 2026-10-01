//! # rustlet-shim: one process per running container
//!
//! ```text
//!  rustletd ──spawn──► rustlet-shim ──► rustlet-runc create|start|kill|exec|delete
//!     │                   │ setsid, PR_SET_CHILD_SUBREAPER
//!     │   shim.sock       │ owns the container's stdio: PTY master or pipes
//!     └───────────────────┤ writes container.log, serves attach and exec
//!                         │ reaps init (re-parented to it) and exec'd processes
//!                         ▼ reports the exit (code, signal, OOM), exit.json
//!                    container init
//! ```
//!
//! Why a process per container, between the daemon and the runtime:
//!
//! * **The container outlives the daemon.** `systemctl restart rustletd`
//!   only stops the daemon (`KillMode=process`). Someone must still hold the
//!   container's stdio (or its PTY master), keep writing its log and be its
//!   parent to collect its exit status. The shim does; the new daemon finds
//!   it again through `shims/<id>/shim.sock`.
//! * **Somebody has to reap.** `rustlet-runc create` exits as soon as init is
//!   set up, and init is re-parented to the nearest ancestor that is a
//!   *child subreaper*: the shim. Its exit status goes to the shim, and only
//!   to the shim.
//! * **The daemon stays out of `fork`.** It is multi-threaded (tokio) and
//!   forbids `unsafe`; the shim is a small single-threaded program that
//!   `setsid()`s itself and does the subreaper work.
//!
//! This library half is what the daemon needs to drive a shim: the wire
//! [`protocol`], the [`paths`] of a shim's files, the command line it is
//! started with ([`ShimArgs`]) and an async [`client`].

#![forbid(unsafe_code)]

pub mod client;
pub mod paths;
pub mod protocol;

use std::path::PathBuf;

/// How the daemon starts a shim (`rustlet-shim <args>`). Everything the shim
/// needs, so that it never reads the daemon's configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShimArgs {
    /// The container (and runtime) id.
    pub id: String,
    /// The OCI bundle: `config.json` and the mounted rootfs.
    pub bundle: PathBuf,
    /// The shim's directory (`<run root>/shims/<short id>`, [`paths::ShimPaths`]).
    pub dir: PathBuf,
    /// `rustlet-runc`.
    pub runtime: PathBuf,
    /// `rustlet-runc --root`.
    pub runtime_root: PathBuf,
    /// The cgroup (a path below `/sys/fs/cgroup`) the shim moves itself into
    /// before it starts anything.
    pub cgroup: Option<String>,
    /// The container's log file.
    pub log_path: PathBuf,
    /// Rotate the log at this size, keeping this many old files.
    pub log_max_size: u64,
    pub log_max_files: u32,
    /// Keep a stdin open for attach clients (`-i`).
    pub stdin: bool,
    /// Close that stdin when the first attached client's input ends.
    pub stdin_once: bool,
}

impl ShimArgs {
    /// The command-line arguments (after the program name).
    pub fn to_args(&self) -> Vec<std::ffi::OsString> {
        let mut a: Vec<std::ffi::OsString> = Vec::new();
        let mut opt = |k: &str, v: std::ffi::OsString| {
            a.push(k.into());
            a.push(v);
        };
        opt("--id", self.id.clone().into());
        opt("--bundle", self.bundle.clone().into());
        opt("--dir", self.dir.clone().into());
        opt("--runtime", self.runtime.clone().into());
        opt("--runtime-root", self.runtime_root.clone().into());
        if let Some(cg) = &self.cgroup {
            opt("--cgroup", cg.clone().into());
        }
        opt("--log-path", self.log_path.clone().into());
        opt("--log-max-size", self.log_max_size.to_string().into());
        opt("--log-max-files", self.log_max_files.to_string().into());
        if self.stdin {
            a.push("--stdin".into());
        }
        if self.stdin_once {
            a.push("--stdin-once".into());
        }
        a
    }
}

/// Default log rotation: 10 MiB per file, three files.
pub const DEFAULT_LOG_MAX_SIZE: u64 = 10 << 20;
pub const DEFAULT_LOG_MAX_FILES: u32 = 3;

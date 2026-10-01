//! # rustlet-runtime: the OCI runtime library
//!
//! `rustlet-runc` is a thin, runc-compatible CLI over this crate. Its input
//! is an OCI *bundle* (`config.json` + a rootfs directory); its job is to
//! turn that into a running process inside fresh namespaces.
//!
//! ## How `run` works (Phase 1)
//!
//! ```text
//!  rustlet-runc (parent)                     container init (child)
//!  ─────────────────────                     ──────────────────────
//!  config.json ──► Plan (validated)           [plan.rs, mounts.rs]
//!  setns() into namespaces given by path      [namespaces.rs]
//!  socketpair(SEQPACKET), block signals       [sync.rs]
//!  clone3(CLONE_NEW* | CLONE_PIDFD) ────────► restore signal mask/dispositions
//!                                             unshare(CLONE_NEWCGROUP)
//!                                             assert: new mount namespace
//!                                             / → rprivate, verify  [rootfs.rs]
//!                                             bind rootfs onto itself
//!                                             mount /proc /dev /sys … (fd-based)
//!                                             /dev nodes + symlinks
//!                                             pivot_root(".", "."), detach old /
//!                                             hostname, rlimits, uid/gid, cwd
//!  recv() on sync socket ◄── error msg ─────  (on failure, then _exit)
//!                        ◄── EOF ───────────  execve(args)  (CLOEXEC closes it)
//!  forward signals, wait on pidfd             [run.rs]
//!  exit with the container's status
//! ```
//!
//! Phase 2a split this into `create` + `start` (the exec.fifo gate) and
//! added cgroups and terminals; Phase 2b the hardening (capabilities,
//! seccomp, masked paths, sysctls, the sealed self re-exec) and `exec`;
//! Phase 2c user namespaces (`userns`), for which the parent now opens the
//! rootfs and bind sources itself (`rootfs::HostTrees`) and sets init's
//! rlimits, before letting init proceed.
//!
//! ## What this build does *not* do yet
//!
//! Features that `config.json` can ask for but this build can't enforce are
//! rejected with the phase that adds them (see `plan::reject_unsupported`):
//! device rules, `CAP_MKNOD` and `--privileged` wait for the eBPF device
//! filter, the second half of Phase 2c.

#![forbid(unsafe_code)]

pub mod bundle;
pub mod caps;
pub mod cgroups;
pub mod console;
pub mod create;
pub mod dev;
pub mod error;
pub mod exec;
mod init;
mod inroot;
pub mod mounts;
pub mod namespaces;
pub mod ops;
pub mod paths;
pub mod plan;
mod proc_handle;
pub mod process;
pub mod reexec;
pub mod rootfs;
pub mod run;
pub mod seccomp;
pub mod spec;
pub mod state;
mod sync;
pub mod sysctl;
pub mod userns;

pub use bundle::Bundle;
pub use create::{CreateOptions, create};
pub use error::{Error, Result};
pub use exec::{ExecArgs, ExecOptions, ExecProcess, exec};
/// Signal types, re-exported for the CLI.
pub use nix::sys::signal as nix_signal;
/// Re-exported so the CLI and xtask use exactly the same spec types.
pub use oci_spec;
pub use plan::Plan;
pub use run::{RunOptions, run};
pub use rustlet_sys::Errno;
pub use state::{State, Status};

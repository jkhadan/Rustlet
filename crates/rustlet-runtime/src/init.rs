//! Container init: everything the child does between `clone3` and `execve`.
//!
//! This code runs in a *copy* of `rustlet-runc` (clone3 without `CLONE_VM`
//! duplicates the address space like `fork`), already inside the new
//! namespaces and, if there is one, already in the container's cgroup
//! (`CLONE_INTO_CGROUP`). It must never return into the parent's code paths:
//! it either `execve`s the user's program or reports an error and `_exit`s.
//!
//! The order of the steps is the design; see `docs/architecture.md` §2.2
//! and the comments on each module for the reasons. Phase 2a added the
//! *gate*: after all setup, init reports `Ready` and blocks opening
//! `exec.fifo` for writing, which only returns once `rustlet-runc start` (or
//! `run`) opens the other end. Phase 2b added the hardening: a session
//! keyring, sysctls, masked and read-only paths, capabilities and seccomp.
//! Phase 2c added user namespaces: init first waits for the parent to map
//! it, then becomes root of its namespace. Later, when its setup as root is
//! done, it asks the parent to set its rlimits, which it might not be
//! allowed to raise itself.

use std::convert::Infallible;
use std::io::Write;
use std::os::fd::{AsFd, OwnedFd};

use nix::fcntl::OFlag;
use nix::sys::signal::{SigSet, SigmaskHow, Signal, sigprocmask};
use nix::sys::stat::Mode;
use rustlet_sys::process::{self, CloneFlags};

use crate::error::{Context, Error, Result};
use crate::plan::Plan;
use crate::proc_handle::ProcHandle;
use crate::rootfs::HostTrees;
use crate::sync::{SyncMsg, SyncSocket};
use crate::{console, namespaces, paths, process as proc_setup, rootfs, sysctl, userns};

/// Everything init gets from its parent besides the plan. The fds are the
/// child's copies (inherited through the address-space copy of `clone3`).
pub(crate) struct InitContext<'a> {
    pub plan: &'a Plan,
    /// The mount namespace `rustlet-runc` started in, and host init's (for
    /// the safety check).
    pub parent_mnt_ns: (u64, u64),
    pub host_init_mnt_ns: (u64, u64),
    /// The rootfs and bind-mount sources, opened by the parent.
    pub trees: HostTrees,
    pub sync: &'a SyncSocket,
    /// `O_PATH` fd of `<state dir>/exec.fifo`. After `pivot_root` the path
    /// is unreachable, the fd is not.
    pub exec_fifo: &'a OwnedFd,
    /// Connected console socket, when `process.terminal` is set.
    pub console: Option<OwnedFd>,
    /// Foreground `run`: tie the container's life to `rustlet-runc`.
    pub foreground: bool,
    /// `--preserve-fds N`: fds 3..3+N go to the program.
    pub preserve_fds: u32,
    /// `--no-new-keyring`: keep the caller's session keyring.
    pub no_new_keyring: bool,
}

/// Runs init. Only returns if something failed.
pub(crate) fn container_init(ctx: InitContext<'_>) -> Error {
    match try_init(ctx) {
        Ok(never) => match never {},
        Err(e) => e,
    }
}

fn try_init(ctx: InitContext<'_>) -> Result<Infallible> {
    let InitContext {
        plan,
        parent_mnt_ns,
        host_init_mnt_ns,
        trees,
        sync,
        exec_fifo,
        mut console,
        foreground,
        preserve_fds,
        no_new_keyring,
    } = ctx;
    // ── signals ───────────────────────────────────────────────────────────
    // The parent blocked the signals it forwards *before* clone3 (so none
    // can slip through between clone3 and its signalfd). A blocked mask
    // survives execve, so clear it here: to an *empty* mask, not whatever
    // rustlet-runc's caller had blocked (as crun does), so `kill TERM`
    // always reaches a program with a TERM handler. And reset every
    // disposition, because Rust's runtime left SIGPIPE ignored and an
    // ignored signal also survives execve (see `rustlet_sys::signal`).
    sigprocmask(SigmaskHow::SIG_SETMASK, Some(&SigSet::empty()), None).context("clear signal mask")?;
    rustlet_sys::signal::reset_all_to_default().context("reset signal dispositions")?;
    // Mode bits of the device nodes and directories we create are exact;
    // the process gets its real umask right before execve.
    nix::sys::stat::umask(Mode::empty());

    // ── namespaces ────────────────────────────────────────────────────────
    // The parent maps our user namespace and idmaps mounts; nothing here
    // may run before that.
    sync.wait_proceed()?;
    if plan.namespaces.new_user() {
        userns::become_root()?;
    }
    if plan.namespaces.new_cgroup {
        // We were born in the container's cgroup (CLONE_INTO_CGROUP), so the
        // new cgroup namespace is rooted there: /proc/self/cgroup = "0::/".
        process::unshare(CloneFlags::NEWCGROUP).context("unshare(CLONE_NEWCGROUP)")?;
    }
    // Hard stop before the first mount: never touch the host's mount table.
    namespaces::assert_new_mount_ns(parent_mnt_ns, host_init_mnt_ns)?;
    // A procfs instance of our own, attached nowhere: sysctls are written
    // through it, so no mount in the container can redirect those writes.
    let proc = ProcHandle::new()?;
    if !no_new_keyring {
        proc_setup::join_session_keyring(&plan.id)?;
    }

    // ── filesystem ────────────────────────────────────────────────────────
    rootfs::setup(plan, trees)?;

    // ── terminal ──────────────────────────────────────────────────────────
    // After pivot_root (the PTY must come from the container's own devpts),
    // before the identity switch (bind-mounting /dev/console needs root).
    if plan.process.terminal {
        let sock = console.take().ok_or_else(|| Error::invalid("terminal requested without a console socket"))?;
        console::setup_container_tty(sock, plan.process.console_size)?;
    }

    // ── process ───────────────────────────────────────────────────────────
    if let Some(h) = &plan.hostname {
        process::sethostname(h).with_context(|| format!("sethostname {h:?}"))?;
    }
    if let Some(d) = &plan.domainname {
        process::setdomainname(d).with_context(|| format!("setdomainname {d:?}"))?;
    }
    // Kernel knobs (through the private handle, which the read-only
    // /proc/sys mount below doesn't cover), then the read-only and masked
    // paths close off the container's own view of /proc and /sys.
    sysctl::apply(&proc, &plan.sysctls)?;
    if plan.namespaces.clone_flags.contains(CloneFlags::NEWNET) {
        bring_up_loopback()?;
    }
    paths::apply(&plan.paths)?;
    drop(proc);
    // The parent sets our rlimits and oom_score_adj now: late enough that
    // the setup above (an fd per mount, …) didn't run under the container's
    // limits, and before the identity switch, which RLIMIT_NPROC is
    // checked against.
    sync.request_limits()?;

    // ── identity ──────────────────────────────────────────────────────────
    // Mark every fd above stderr and the preserved ones close-on-exec:
    // nothing of the runtime's may leak into the container (CVE-2024-21626
    // was a leaked directory fd). Nothing is closed *now*, so no OwnedFd is
    // pulled out from under us; the sync socket and the fifo fd are still
    // needed until execve. Inside the preserved range 3..3+N only the
    // caller's fds survive: every fd the runtime opens is close-on-exec
    // from birth (O_CLOEXEC, SOCK_CLOEXEC, OPEN_TREE_CLOEXEC, …), so one that
    // landed in a hole of that range still closes at execve. (runc behaves
    // the same: `--preserve-fds 5` with only fd 3 open is not an error.)
    // Before the identity switch, which may load the seccomp filter: a
    // profile that doesn't allow close_range must not break the container.
    rustlet_sys::fs::close_range_cloexec(3 + preserve_fds).context("close_range(CLOEXEC)")?;
    proc_setup::switch_identity(&plan.process, plan.seccomp.as_ref())?;
    proc_setup::enter_cwd(&plan.process)?;
    let prepared = proc_setup::prepare_exec(&plan.process)?;
    if foreground {
        // Foreground `run`: if rustlet-runc dies, so does the container.
        // (Set after the identity switch: the kernel clears it when
        // credentials change.) Detached containers outlive `create` on purpose.
        rustlet_sys::prctl::set_pdeathsig(Some(Signal::SIGKILL)).context("PR_SET_PDEATHSIG")?;
    }

    // ── the gate ──────────────────────────────────────────────────────────
    sync.send(&SyncMsg::Ready)?;
    wait_for_start(exec_fifo)?;

    Err(proc_setup::exec(&plan.process, &prepared, plan.seccomp.as_ref()))
}

/// A new network namespace starts with only `lo`, and it is *down*: even
/// `127.0.0.1` doesn't work until someone brings it up. runc and crun do
/// that for every new network namespace, and programs rely on it; the rest
/// of the network (veth pairs, addresses, routes) is the daemon's job.
fn bring_up_loopback() -> Result<()> {
    let mut nl = rustlet_sys::netlink::RtNetlink::open().context("open an rtnetlink socket")?;
    let lo = nl
        .link_by_name("lo")
        .context("look up lo")?
        .ok_or_else(|| Error::Init { message: "the new network namespace has no `lo`".into(), errno: None })?;
    nl.set_link_up(lo.index).context("bring lo up")
}

/// Blocks until `start`: opening a FIFO for writing waits for a reader.
///
/// We reopen the inherited `O_PATH` fd through `/proc/self/fd/N` (our own
/// fd table is always accessible to us, even after the uid switch made the
/// process non-dumpable), which is why `exec.fifo` is mode 0622: init may
/// be running as an unprivileged user by now. The byte we write tells
/// `start` that init really got past the gate.
fn wait_for_start(fifo: &OwnedFd) -> Result<()> {
    let w = rustlet_sys::fs::reopen(fifo.as_fd(), OFlag::O_WRONLY).context("open exec.fifo for writing")?;
    let mut f = std::fs::File::from(w);
    f.write_all(b"0").context("write exec.fifo")
}

//! `rustlet-runc exec`: start another process inside a running container.
//!
//! The new process must end up exactly where init is: in the same
//! namespaces, the same cgroup, with the same capabilities, rlimits and
//! seccomp filter, and with nothing of the host attached to it.
//!
//! ```text
//!  rustlet-runc exec (parent, stays on the host)    child
//!  ─────────────────────────────────────────────    ─────
//!  lock; state must be created/running
//!  process = stored config.json + CLI overrides
//!  pidfd for init; which of its namespaces differ from ours?
//!  setns(init pidfd, PID)                 (only affects children)
//!  clone3(CLONE_INTO_CGROUP | CLONE_PIDFD) ─────────► born in the container's
//!                                                     PID namespace and cgroup
//!                                                     rlimits, oom_score_adj
//!                                                     setns(init pidfd, USER|MNT|UTS|IPC|NET|CGROUP|TIME)
//!                                                     user namespace: become its root
//!                                                     keyring, PTY (if -t), identity, caps, seccomp
//!  recv ◄──────────────────────────── EOF on execve (or Error)
//!  pid file, unlock; -d: exit 0
//!  otherwise: relay, forward signals, wait → exit status
//! ```
//!
//! ## Why the parent never joins the mount namespace
//!
//! `setns(CLONE_NEWNS)` would move `rustlet-runc` itself into the
//! container's filesystem, where the container controls every path, while
//! it still has host work to do (the pid file, the console socket, the
//! state directory). So the parent only joins the **PID** namespace. That is
//! safe because `setns(CLONE_NEWPID)` changes nothing about the caller: it
//! only decides where the caller's *future children* are born. (A time
//! namespace is different: `setns(CLONE_NEWTIME)` switches the caller's own
//! clocks too, so that one is the child's job.) The child, born inside,
//! joins everything else itself, with a single `setns` on init's pidfd
//! (Linux 5.8+ accepts several namespace types at once for a pidfd).
//!
//! A user namespace is the child's to join too, in the same `setns` (the
//! kernel enters it first). The child then becomes root of the namespace,
//! as init did, before anything that creates or looks up something owned
//! by a uid: the session keyring (keyring names are per user namespace, and
//! the container's belongs to container root) and the PTY.
//!
//! Joining the PID namespace in the parent also means no double fork is
//! needed (runc's `nsexec` forks twice for this): our child is a direct
//! child, so `waitid` on its pidfd gives us its exit status.
//!
//! ## Why `/proc` is only used before the mount namespace join
//!
//! After joining, `/proc` is the container's, and a process in there could
//! have mounted anything over it. So everything that reads or writes procfs
//! happens before: `oom_score_adj` through a private procfs instance,
//! `cap_last_cap` was read in the parent at plan time. The child is also
//! non-dumpable (inherited from the parent) until it `execve`s, so container
//! processes can't `ptrace` it or open its `/proc/<pid>/fd/*`
//! (CVE-2016-9962).

use std::convert::Infallible;
use std::os::fd::{AsFd, OwnedFd};
use std::panic::AssertUnwindSafe;
use std::path::PathBuf;
use std::time::Duration;

use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::signal::{SigSet, SigmaskHow, Signal, sigprocmask};
use nix::sys::signalfd::SignalFd;
use nix::sys::socket::{AddressFamily, SockFlag, SockType, socketpair};
use nix::sys::stat::Mode;
use nix::unistd::Pid;
use oci_spec::runtime::{Capabilities, Capability, LinuxCapabilities, Process, Spec};
use rustlet_sys::Errno;
use rustlet_sys::process::{self, Clone3, CloneFlags, Forked, WaitResult, WaitTarget};

use crate::console::{self, Relay};
use crate::create::{self, block_signals};
use crate::error::{Context, Error, Result};
use crate::plan::{self, ProcessPlan};
use crate::proc_handle::ProcHandle;
use crate::seccomp::{self, Filter};
use crate::state::{StateDir, Status};
use crate::sync::{self, SyncMsg, SyncSocket};
use crate::{namespaces, process as proc_setup, run, userns};

/// Options for [`exec`].
#[derive(Debug, Clone)]
pub struct ExecOptions {
    /// State directory root (`--root`).
    pub root: PathBuf,
    pub id: String,
    pub process: ExecProcess,
    /// `-t`: give the process a PTY of its own.
    pub tty: bool,
    /// Send the PTY master here (required with `-t -d`).
    pub console_socket: Option<PathBuf>,
    /// Return once the process runs.
    pub detach: bool,
    /// Write the process's host PID here.
    pub pid_file: Option<PathBuf>,
    /// Pass fds 3..3+N on to the process.
    pub preserve_fds: u32,
    /// `--cgroup`: a sub-cgroup of the container's to start in, relative to
    /// it (`/` = the container's own).
    pub cgroup: Option<String>,
    /// `--ignore-paused`: exec into a paused container anyway (the process
    /// then waits, frozen, until `resume`).
    pub ignore_paused: bool,
}

/// What to run.
#[derive(Debug, Clone)]
pub enum ExecProcess {
    /// `--process FILE`: a complete OCI `process` object. If it has no
    /// `capabilities`, the container's are used.
    Json(PathBuf),
    /// A command line: the container's own `process`, with these changes.
    Args(ExecArgs),
}

/// Command-line overrides of the container's `process`.
#[derive(Debug, Clone, Default)]
pub struct ExecArgs {
    pub args: Vec<String>,
    /// `KEY=VALUE`, replacing the container's `KEY` or added to its env.
    pub env: Vec<String>,
    pub cwd: Option<PathBuf>,
    /// `uid` and, optionally, `gid`.
    pub user: Option<(u32, Option<u32>)>,
    /// Added to the container's additional gids.
    pub additional_gids: Vec<u32>,
    /// Added to bounding, effective and permitted, never to inheritable
    /// (CVE-2022-29162); to ambient only where the container's inheritable
    /// set already has it. So for a non-root user, whose capabilities only
    /// survive `execve` through ambient, `--cap` alone gives nothing: that
    /// takes a `process.json` (or container spec) with the capability in
    /// inheritable and ambient.
    pub caps: Vec<String>,
    /// Force `noNewPrivileges` on.
    pub no_new_privs: bool,
}

/// Starts the process. Foreground: waits for it and returns its exit status
/// shell-style; detached: returns 0 once it runs.
pub fn exec(opts: &ExecOptions) -> Result<i32> {
    process::ensure_single_threaded().context("rustlet-runc must be single-threaded before joining namespaces")?;
    // Non-dumpable, and inherited by the child until it execs: see above.
    rustlet_sys::prctl::set_dumpable(false).context("PR_SET_DUMPABLE")?;
    let sfd = block_signals()?;

    let dir = StateDir::new(&opts.root, &opts.id)?;
    // Held until clone3 has placed the process in the container's cgroup:
    // `delete` can't pull the cgroup away meanwhile. (Not until the process
    // runs: with --ignore-paused it waits, frozen, for a `resume`, which
    // needs this lock.)
    let lock = dir.lock()?;
    let state = dir.load()?;
    match state.status {
        Status::Running | Status::Created => {}
        Status::Paused if opts.ignore_paused => {}
        Status::Paused => {
            return Err(Error::container(format!(
                "cannot exec in container {:?}: it is paused (resume it first)",
                state.id
            )));
        }
        other => return Err(Error::container(format!("cannot exec in container {:?}: it is {other}", state.id))),
    }
    let spec = dir.load_config()?;
    let process = exec_process(&spec, &opts.process, opts.tty)?;
    let plan = plan::process_plan(&process)?;
    if let Some(linux) = spec.linux() {
        // With a user namespace, the process's ids must exist in it.
        let ns = namespaces::plan(linux.namespaces().as_deref().unwrap_or_default())?;
        if let Some(maps) = userns::plan(linux, &ns)? {
            maps.check_process(&plan)?;
        }
    }
    let seccomp = spec.linux().as_ref().and_then(|l| l.seccomp().as_ref()).map(seccomp::compile).transpose()?;
    if plan.terminal && opts.detach && opts.console_socket.is_none() {
        return Err(Error::container("exec -t -d needs --console-socket (somewhere to send the terminal)"));
    }

    let init = create::open_init(&state)?;
    let (parent_ns, child_ns) = namespaces_to_join(state.init_pid())?;
    let cgroup_fd = Some(target_cgroup(&state, opts.cgroup.as_deref())?);
    let (console_parent, console_child) = match (plan.terminal, &opts.console_socket) {
        (false, _) => (None, None),
        (true, Some(path)) => (None, Some(console::connect_console_socket(path)?)),
        (true, None) => {
            let (a, b) = socketpair(AddressFamily::Unix, SockType::Stream, None, SockFlag::SOCK_CLOEXEC)
                .context("socketpair (console)")?;
            (Some(a), Some(b))
        }
    };
    let (parent_sock, child_sock) = sync::pair()?;

    if !parent_ns.is_empty() {
        // Only our future children are affected (see the module docs).
        process::setns(init.as_fd(), parent_ns).with_context(|| format!("setns({parent_ns:?}) into the container"))?;
    }
    // The child inherits this name, and keeps it until execve gives it the
    // program's: that's how `wait_exec` tells a child that died during
    // setup from a program that already finished. Set here rather than in
    // the child, which may be frozen (`--ignore-paused`) before it runs a
    // single instruction.
    rustlet_sys::prctl::set_name(SETUP_NAME).context("PR_SET_NAME")?;
    let mut clone = Clone3::new().flags(CloneFlags::PIDFD);
    if let Some(fd) = &cgroup_fd {
        clone = clone.into_cgroup(fd.as_fd());
    }
    match clone.spawn().context("clone3 into the container")? {
        Forked::Child => {
            drop(cgroup_fd);
            drop(parent_sock);
            drop(console_parent);
            drop(sfd);
            // A POSIX record lock belongs to the parent process: closing our
            // copy of the fd doesn't release it.
            drop(lock);
            let child = Child {
                id: &state.id,
                plan: &plan,
                seccomp: seccomp.as_ref(),
                init: &init,
                namespaces: child_ns,
                console: console_child,
                foreground: !opts.detach,
                preserve_fds: opts.preserve_fds,
                no_new_keyring: state.rustlet.no_new_keyring,
            };
            let err = std::panic::catch_unwind(AssertUnwindSafe(|| child.run()))
                .unwrap_or_else(|_| Error::Init { message: "exec child panicked".into(), errno: None });
            let code = match &err {
                Error::Exec { errno: Errno::ENOENT, .. } => 127,
                Error::Exec { .. } => 126,
                _ => 1,
            };
            let _ = child_sock.send(&SyncMsg::from_error(&err));
            process::exit_now(code)
        }
        Forked::Parent { pid, pidfd } => {
            drop(child_sock);
            drop(console_child);
            drop(cgroup_fd);
            // The process is in the cgroup now (a cgroup with a process in
            // it can't be removed): the container may be changed again.
            drop(lock);
            let pidfd = pidfd.expect("CLONE_PIDFD was requested");
            let mut guard = KillGuard(Some(&pidfd));
            wait_exec(&parent_sock, &sfd, &pidfd, pid)?;
            if let Some(path) = &opts.pid_file {
                create::write_pid_file(path, pid)?;
            }
            tracing::debug!(%pid, "exec'd process is running");
            if opts.detach {
                guard.0 = None;
                return Ok(0);
            }
            let mut relay = match console_parent {
                Some(sock) => Some(Relay::new(console::receive_master(sock.as_fd())?)?),
                None => None,
            };
            let status = run::supervise(&pidfd, &sfd, relay.as_mut(), plan.terminal);
            drop(relay);
            guard.0 = None;
            status
        }
    }
}

/// The cgroup the new process starts in (an fd for `CLONE_INTO_CGROUP`):
/// the container's cgroup or, for a container without one of its own, the
/// cgroup init was born in (as runc does: not wherever init has moved since),
/// falling back to init's current one if that is gone; then `sub` below
/// that, if given.
///
/// `sub` is resolved beneath the base directory (`RESOLVE_BENEATH`, no
/// symlinks, no mount crossings), so `..` or an absolute path can't lead out
/// of the container's cgroup. cgroup v2 has one hierarchy, so v1's
/// `controller:path` form is refused.
fn target_cgroup(state: &crate::state::State, sub: Option<&str>) -> Result<OwnedFd> {
    use nix::fcntl::OFlag;
    use rustlet_sys::fs::{ResolveFlags, fs_magic, magic, openat2};
    let base = match state.cgroup()? {
        Some(cg) => cg.dir_fd()?,
        None => {
            let root = nix::fcntl::open(
                "/sys/fs/cgroup",
                OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
                Mode::empty(),
            )
            .context("open /sys/fs/cgroup")?;
            let open = |path: &str| {
                let rel = path.trim().trim_start_matches('/');
                let rel = if rel.is_empty() { "." } else { rel };
                let resolve = ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV;
                openat2(Some(root.as_fd()), rel, OFlag::O_RDONLY | OFlag::O_DIRECTORY, Mode::empty(), resolve)
            };
            match state.rustlet.init_cgroup.as_deref().map(open) {
                Some(Ok(fd)) => fd,
                _ => {
                    let now = rustlet_sys::procfs::cgroup_path(Some(state.init_pid())).context("read init's cgroup")?;
                    open(&now).with_context(|| format!("open init's cgroup {now}"))?
                }
            }
        }
    };
    let Some(sub) = sub else { return Ok(base) };
    if sub.contains(':') {
        return Err(Error::invalid(format!(
            "exec --cgroup {sub:?}: `controller:path` is cgroup v1 syntax; give a path relative to the container's cgroup"
        )));
    }
    let rel = sub.trim_start_matches('/');
    let rel = if rel.is_empty() { "." } else { rel };
    let resolve =
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV | ResolveFlags::NO_MAGICLINKS;
    let fd = openat2(Some(base.as_fd()), rel, OFlag::O_RDONLY | OFlag::O_DIRECTORY, Mode::empty(), resolve)
        .with_context(|| format!("exec --cgroup {sub:?}: not a cgroup inside the container's"))?;
    if fs_magic(fd.as_fd()).context("fstatfs the exec cgroup")? != magic::CGROUP2_SUPER_MAGIC {
        return Err(Error::invalid(format!("exec --cgroup {sub:?}: not a cgroup")));
    }
    Ok(fd)
}

/// The OCI `process` to run: the container's own (from the `config.json`
/// copy made at `create`) with the command line's changes, or a
/// `process.json`.
fn exec_process(spec: &Spec, how: &ExecProcess, tty: bool) -> Result<Process> {
    let base = spec.process().clone().ok_or_else(|| Error::container("the container's config.json has no process"))?;
    let mut p = match how {
        ExecProcess::Json(path) => {
            let text = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
            let mut p: Process =
                serde_json::from_slice(&text).map_err(|e| Error::invalid(format!("{}: {e}", path.display())))?;
            if p.capabilities().is_none() {
                p.set_capabilities(base.capabilities().clone());
            }
            if tty {
                p.set_terminal(Some(true));
            }
            p
        }
        ExecProcess::Args(a) => {
            if a.args.is_empty() {
                return Err(Error::invalid("exec needs a command to run (or --process)"));
            }
            let mut p = base;
            p.set_args(Some(a.args.clone()));
            p.set_terminal(Some(tty));
            let mut env = p.env().clone().unwrap_or_default();
            for kv in &a.env {
                let key = kv.split_once('=').map_or(kv.as_str(), |(k, _)| k);
                env.retain(|e| e.split_once('=').map_or(e.as_str(), |(k, _)| k) != key);
                env.push(kv.clone());
            }
            p.set_env(Some(env));
            if let Some(cwd) = &a.cwd {
                p.set_cwd(cwd.clone());
            }
            let mut user = p.user().clone();
            if let Some((uid, gid)) = a.user {
                user.set_uid(uid);
                if let Some(gid) = gid {
                    user.set_gid(gid);
                }
            }
            if !a.additional_gids.is_empty() {
                let mut gids = user.additional_gids().clone().unwrap_or_default();
                gids.extend(&a.additional_gids);
                user.set_additional_gids(Some(gids));
            }
            p.set_user(user);
            if !a.caps.is_empty() {
                let mut caps = p.capabilities().clone().unwrap_or_default();
                add_caps(&mut caps, &a.caps)?;
                p.set_capabilities(Some(caps));
            }
            if a.no_new_privs {
                p.set_no_new_privileges(Some(true));
            }
            p
        }
    };
    if p.terminal() == Some(false) {
        // A console size means nothing without a terminal.
        p.set_console_size(None);
    }
    Ok(p)
}

/// `exec --cap`, as runc does it since CVE-2022-29162: runc used to put
/// `--cap` capabilities into the *inheritable* set too, and a non-empty
/// inheritable set lets any binary with matching inheritable *file*
/// capabilities gain them at `execve`. So: bounding, effective and
/// permitted; ambient only for capabilities the spec already made
/// inheritable (the kernel refuses ambient ones that aren't).
fn add_caps(caps: &mut LinuxCapabilities, names: &[String]) -> Result<()> {
    let parsed: Vec<Capability> = names
        .iter()
        .map(|n| {
            serde_json::from_value(serde_json::Value::String(n.clone()))
                .map_err(|_| Error::container(format!("exec --cap {n}: unknown capability")))
        })
        .collect::<Result<_>>()?;
    // Checked again with the rest of the process by `CapsPlan::from_spec`,
    // but then the message would blame config.json.
    if parsed.contains(&Capability::Mknod) {
        return Err(Error::container(
            "exec --cap MKNOD: not supported until Phase 2c (the eBPF device filter that makes it safe)",
        ));
    }
    let add = |set: &Option<Capabilities>, which: &[Capability]| -> Option<Capabilities> {
        let mut s = set.clone().unwrap_or_default();
        s.extend(which.iter().copied());
        Some(s)
    };
    caps.set_bounding(add(caps.bounding(), &parsed));
    caps.set_effective(add(caps.effective(), &parsed));
    caps.set_permitted(add(caps.permitted(), &parsed));
    let inheritable = caps.inheritable().clone().unwrap_or_default();
    let ambient: Vec<Capability> = parsed.iter().copied().filter(|c| inheritable.contains(c)).collect();
    if !ambient.is_empty() {
        caps.set_ambient(add(caps.ambient(), &ambient));
    }
    Ok(())
}

/// The namespace kinds a container can have, in `/proc/<pid>/ns/` terms.
const KINDS: [(&str, CloneFlags); 8] = [
    ("user", CloneFlags::NEWUSER),
    ("mnt", CloneFlags::NEWNS),
    ("uts", CloneFlags::NEWUTS),
    ("ipc", CloneFlags::NEWIPC),
    ("net", CloneFlags::NEWNET),
    ("pid", CloneFlags::NEWPID),
    ("cgroup", CloneFlags::NEWCGROUP),
    ("time", CloneFlags::NEWTIME),
];

/// Compares init's namespaces with ours (both through the host's `/proc`)
/// and returns the ones to join: `(parent, child)`. PID goes to the parent
/// (it only affects children), everything else to the child. A
/// namespace init shares with us (`--net=host`) is simply not joined: we
/// are already in it.
fn namespaces_to_join(init: Pid) -> Result<(CloneFlags, CloneFlags)> {
    let differs = |kind: &str| -> Result<bool> {
        let theirs = rustlet_sys::procfs::ns_id(Some(init), kind).with_context(|| format!("read init's {kind} ns"))?;
        let ours = rustlet_sys::procfs::ns_id(None, kind).with_context(|| format!("read our {kind} ns"))?;
        Ok(theirs != ours)
    };
    let (mut parent, mut child) = (CloneFlags::empty(), CloneFlags::empty());
    for (kind, flag) in KINDS {
        if differs(kind)? {
            if kind == "pid" {
                parent |= flag;
            } else {
                child |= flag;
            }
        }
    }
    if !child.contains(CloneFlags::NEWNS) {
        // Every container has its own mount namespace; if init shares ours,
        // it isn't a container we created.
        return Err(Error::container("container init is in our mount namespace; refusing to exec"));
    }
    Ok((parent, child))
}

/// Everything the child needs; its fds are copies from the address-space
/// copy of `clone3`.
struct Child<'a> {
    id: &'a str,
    plan: &'a ProcessPlan,
    seccomp: Option<&'a Filter>,
    init: &'a OwnedFd,
    namespaces: CloneFlags,
    console: Option<OwnedFd>,
    foreground: bool,
    preserve_fds: u32,
    no_new_keyring: bool,
}

impl Child<'_> {
    /// Only returns if something failed.
    fn run(self) -> Error {
        match self.try_run() {
            Ok(never) => match never {},
            Err(e) => e,
        }
    }

    fn try_run(mut self) -> Result<Infallible> {
        let p = self.plan;
        // The same clean slate init starts from (see init.rs).
        sigprocmask(SigmaskHow::SIG_SETMASK, Some(&SigSet::empty()), None).context("clear signal mask")?;
        rustlet_sys::signal::reset_all_to_default().context("reset signal dispositions")?;
        nix::sys::stat::umask(Mode::empty());

        // Still on the host's filesystem: everything that needs procfs
        // happens now. We were born in the container's PID namespace, so a
        // procfs instance made now shows the container's processes.
        let proc = ProcHandle::new()?;
        proc_setup::set_limits(p, &proc)?;
        drop(proc);

        process::setns(self.init.as_fd(), self.namespaces)
            .with_context(|| format!("setns({:?}) into the container", self.namespaces))?;
        // setns(CLONE_NEWNS) put us at the container's `/`; the pidfd has
        // done its job.
        if self.namespaces.contains(CloneFlags::NEWUSER) {
            userns::become_root()?;
        }
        if !self.no_new_keyring {
            // Finds the container's `_ses.<id>` keyring by name and joins it.
            proc_setup::join_session_keyring(self.id)?;
        }
        if p.terminal {
            let sock =
                self.console.take().ok_or_else(|| Error::invalid("terminal requested without a console socket"))?;
            console::setup_exec_tty(sock, p.console_size)?;
        }
        // Before the seccomp filter can refuse close_range (see init.rs).
        rustlet_sys::fs::close_range_cloexec(3 + self.preserve_fds).context("close_range(CLOEXEC)")?;
        proc_setup::switch_identity(p, self.seccomp)?;
        proc_setup::enter_cwd(p)?;
        let prepared = proc_setup::prepare_exec(p)?;
        if self.foreground {
            // As for `run`: if rustlet-runc dies, so does the process. Set
            // after the identity switch, which clears it.
            rustlet_sys::prctl::set_pdeathsig(Some(Signal::SIGKILL)).context("PR_SET_PDEATHSIG")?;
        }
        Err(proc_setup::exec(p, &prepared, self.seccomp))
    }
}

/// Waits for the child's verdict: EOF (its sync socket is close-on-exec, so
/// a successful `execve` closes it) or an error. A SIGTERM/SIGINT/… to us
/// meanwhile aborts the exec.
fn wait_exec(sock: &SyncSocket, sfd: &SignalFd, child: &OwnedFd, pid: Pid) -> Result<()> {
    loop {
        let mut fds = [PollFd::new(sock.as_fd(), PollFlags::POLLIN), PollFd::new(sfd.as_fd(), PollFlags::POLLIN)];
        match poll(&mut fds, PollTimeout::NONE) {
            Ok(_) | Err(Errno::EINTR) => {}
            Err(e) => return Err(e).context("poll"),
        }
        if fds[1].revents().is_some_and(|r| r.contains(PollFlags::POLLIN)) {
            while let Some(info) = sfd.read_signal().context("read signalfd")? {
                let sig = Signal::try_from(info.ssi_signo as i32).ok();
                if sig.is_some_and(|s| s != Signal::SIGCHLD && s != Signal::SIGWINCH) {
                    return Err(Error::container(format!("exec interrupted by {sig:?}")));
                }
            }
        }
        if fds[0].revents().is_some_and(|r| !r.is_empty()) {
            return match sock.recv()? {
                None => confirm_execve(child, pid),
                Some(msg) => {
                    // The child exits right after reporting; reap it.
                    let _ = process::waitid(WaitTarget::PidFd(child.as_fd()), false);
                    Err(match msg.into_error() {
                        // It wasn't container init that failed.
                        Error::Init { message, errno } => Error::Init { message: format!("exec: {message}"), errno },
                        e => e,
                    })
                }
            };
        }
    }
}

/// The exec child's name (`comm`) until `execve` gives it the program's.
const SETUP_NAME: &str = "rustlet-exec";

/// EOF on the sync socket means the child's fds were closed: either by a
/// successful `execve` (close-on-exec), or because it died during setup
/// (`kill --all`, the OOM killer, a seccomp kill). Which one?
///
/// The kernel's order of events answers it. `execve` switches the process's
/// executable (`/proc/<pid>/exe`) *before* it closes the close-on-exec fds,
/// so after an EOF from a successful exec, `exe` already shows the program.
/// A dying process closes its fds and *then* becomes a zombie, which
/// `waitid(WNOWAIT)` sees without reaping it, and a zombie keeps its
/// `comm`: still [`SETUP_NAME`] means it never got to the program. Between
/// those two moments `exe` is unreadable and the process isn't a zombie yet,
/// so we look again for a moment.
fn confirm_execve(child: &OwnedFd, pid: Pid) -> Result<()> {
    let ours = std::fs::read_link("/proc/self/exe").ok();
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        if let Ok(exe) = std::fs::read_link(format!("/proc/{pid}/exe"))
            && Some(&exe) != ours.as_ref()
        {
            return Ok(());
        }
        match process::waitid_peek(WaitTarget::PidFd(child.as_fd())).context("waitid")? {
            WaitResult::StillAlive => {}
            done if rustlet_sys::procfs::comm(pid).is_ok_and(|c| c == SETUP_NAME) => {
                return Err(Error::Init {
                    message: format!(
                        "exec: the process died before it could run the program (exit status {})",
                        done.exit_code().unwrap_or(1)
                    ),
                    errno: None,
                });
            }
            // It ran the program, which has finished already.
            _ => return Ok(()),
        }
        if std::time::Instant::now() > deadline {
            // Alive, and still our binary: stuck in execve? Don't guess
            // "failed" for a process that may well be running.
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// Kills and reaps the child if `exec` fails after it was created.
struct KillGuard<'a>(Option<&'a OwnedFd>);

impl Drop for KillGuard<'_> {
    fn drop(&mut self) {
        if let Some(fd) = self.0 {
            let _ = process::pidfd_send_signal(fd.as_fd(), Signal::SIGKILL);
            let _ = process::waitid(WaitTarget::PidFd(fd.as_fd()), false);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::default_spec;

    fn args(a: ExecArgs) -> Process {
        exec_process(&default_spec(), &ExecProcess::Args(a), false).unwrap()
    }

    #[test]
    fn env_overrides_replace_and_extend() {
        let p = args(ExecArgs {
            args: vec!["env".into()],
            env: vec!["PATH=/x".into(), "NEW=1".into()],
            ..Default::default()
        });
        let env = p.env().clone().unwrap();
        assert_eq!(env.iter().filter(|e| e.starts_with("PATH=")).collect::<Vec<_>>(), ["PATH=/x"]);
        assert!(env.contains(&"NEW=1".to_string()));
    }

    #[test]
    fn user_and_caps() {
        let p = args(ExecArgs {
            args: vec!["id".into()],
            user: Some((1000, None)),
            caps: vec!["NET_RAW".into()],
            ..Default::default()
        });
        assert_eq!((p.user().uid(), p.user().gid()), (1000, 0));
        let c = p.capabilities().clone().unwrap();
        for set in [c.bounding(), c.effective(), c.permitted()] {
            assert!(set.as_ref().unwrap().contains(&Capability::NetRaw));
        }
        // Never inheritable (CVE-2022-29162), so not ambient either: the
        // default spec's inheritable set is empty.
        for set in [c.inheritable(), c.ambient()] {
            assert!(!set.as_ref().is_some_and(|s| s.contains(&Capability::NetRaw)));
        }
        let e = exec_process(
            &default_spec(),
            &ExecProcess::Args(ExecArgs { args: vec!["x".into()], caps: vec!["BOGUS".into()], ..Default::default() }),
            false,
        );
        assert!(e.unwrap_err().to_string().contains("BOGUS"));
    }

    #[test]
    fn a_command_is_required() {
        let e = exec_process(&default_spec(), &ExecProcess::Args(ExecArgs::default()), false);
        assert!(e.is_err());
    }
}

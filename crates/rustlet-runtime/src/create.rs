//! Creating a container: everything up to "init is set up and waiting".
//!
//! `rustlet-runc create` and `rustlet-runc run` share this path; they only
//! differ in what happens after init reports `Ready`:
//!
//! ```text
//!  parent (rustlet-runc)                      container init
//!  ─────────────────────                      ──────────────
//!  Plan (validated config.json)
//!  mkdir <root>/<id>                          (atomic: ids are unique)
//!  cgroup: create under the delegated root, write limits, open dirfd
//!  mkfifo exec.fifo (0622), open O_PATH
//!  console: connect --console-socket, or a socketpair (foreground run)
//!  open_tree: rootfs, bind sources            (rootfs::HostTrees)
//!  setns() joins, block signals
//!  clone3(CLONE_NEW* | CLONE_PIDFD | CLONE_INTO_CGROUP) ─► init::container_init
//!  uid_map/gid_map, idmaps, rlimits, oom          waits
//!  send Proceed ────────────────────────────────► … setup …
//!  recv ◄──────────────────────────────── Ready (or Error)
//!  write state.json, pid file                   open(exec.fifo, O_WRONLY) blocks
//!  create: exit 0      run: release() ────────► write "0", execve
//! ```
//!
//! If anything fails after the state directory exists, [`CreateGuard`]
//! undoes it all: kills init, removes the cgroup, removes the directory. A
//! failed `create` leaves nothing behind.

use std::os::fd::{AsFd, OwnedFd};
use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};
use std::time::Duration;

use nix::fcntl::OFlag;
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::signal::{SigSet, SigmaskHow, Signal, sigprocmask};
use nix::sys::signalfd::{SfdFlags, SignalFd};
use nix::sys::socket::{AddressFamily, SockFlag, SockType, socketpair};
use nix::sys::stat::Mode;
use nix::unistd::Pid;
use rustlet_sys::Errno;
use rustlet_sys::process::{self, Clone3, CloneFlags, Forked, WaitTarget};

use crate::bundle::Bundle;
use crate::cgroups::{Cgroup, SystemdDelegated};
use crate::error::{Context, Error, Result};
use crate::init::{self, InitContext};
use crate::plan::Plan;
use crate::rootfs::HostTrees;
use crate::state::{Lock, Private, State, StateDir, Status, now_rfc3339};
use crate::sync::{self, SyncMsg, SyncSocket};
use crate::userns::{DirectIdMapper, IdMapper};
use crate::{console, namespaces};

/// Signals the parent intercepts (and so blocks before `clone3`) while a
/// foreground container runs.
pub(crate) const FORWARDED: [Signal; 7] = [
    Signal::SIGHUP,
    Signal::SIGINT,
    Signal::SIGQUIT,
    Signal::SIGTERM,
    Signal::SIGUSR1,
    Signal::SIGUSR2,
    Signal::SIGWINCH,
];

/// How long teardown waits for processes to die before giving up.
pub(crate) const TEARDOWN_TIMEOUT: Duration = Duration::from_secs(10);

/// Options shared by `create` and `run`.
#[derive(Debug, Clone)]
pub struct CreateOptions {
    pub id: String,
    pub bundle: PathBuf,
    /// State directory root (`--root`).
    pub root: PathBuf,
    /// Write the container init's host PID here.
    pub pid_file: Option<PathBuf>,
    /// Send the PTY master to this listening Unix socket.
    pub console_socket: Option<PathBuf>,
    /// Pass fds 3..3+N on to the container's program.
    pub preserve_fds: u32,
    /// Keep the caller's session keyring instead of creating one.
    pub no_new_keyring: bool,
}

/// A container whose init has reported `Ready`.
pub(crate) struct Spawned {
    pub dir: StateDir,
    pub state: State,
    pub pidfd: OwnedFd,
    pub sync: SyncSocket,
    pub cgroup: Option<Cgroup>,
    /// Our end of the internal console socketpair (foreground run with a
    /// terminal and no `--console-socket`): the PTY master arrives here.
    pub console: Option<OwnedFd>,
    /// Reads the signals blocked before `clone3` (foreground forwarding).
    pub sfd: SignalFd,
    /// Whether the container got its own PTY.
    pub terminal: bool,
    /// The container's lock, held until the caller is done setting it up.
    pub lock: Option<Lock>,
    guard: CreateGuard,
}

impl Spawned {
    /// The container is fully created; stop undoing it on drop.
    pub(crate) fn keep(&mut self) {
        self.guard.armed = false;
    }
}

/// `rustlet-runc create`: set the container up and leave init waiting on
/// `exec.fifo` for `start`.
pub fn create(opts: &CreateOptions) -> Result<()> {
    let mut spawned = spawn(opts, false)?;
    spawned.keep();
    Ok(())
}

/// Shared by `create` and `run`. `foreground` = `run` without `--detach`.
pub(crate) fn spawn(opts: &CreateOptions, foreground: bool) -> Result<Spawned> {
    process::ensure_single_threaded().context("rustlet-runc must be single-threaded before creating namespaces")?;
    let bundle = Bundle::load(&opts.bundle)?;
    let plan = Plan::new(&opts.id, &bundle)?;
    tracing::debug!(?plan, "validated config.json");
    if plan.process.terminal && opts.console_socket.is_none() && !foreground {
        return Err(Error::container(
            "process.terminal is true but no --console-socket was given (a detached container needs somewhere to send its terminal)",
        ));
    }
    // Non-dumpable before any namespace is touched (and inherited by
    // init): our /proc/<pid> files become root-owned and we can't be
    // ptrace-attached, so nothing in a container can reach into us.
    rustlet_sys::prctl::set_dumpable(false).context("PR_SET_DUMPABLE")?;

    // From here on, a SIGTERM/SIGINT aborts the create cleanly (see
    // `wait_for`) instead of killing us halfway.
    let sfd = block_signals()?;

    // The sync channel exists before the guard, so it is dropped after it:
    // when a create fails, the guard kills init while this end is still
    // open. (Closed first, init would see EOF, report "rustlet-runc went
    // away" on the same stderr, and so add a second, misleading error.)
    let (parent_sock, child_sock) = sync::pair()?;
    let mut dir = StateDir::new(&opts.root, &opts.id)?;
    let lock = dir.create()?;
    let mut guard = CreateGuard { dir: dir.clone(), cgroup: None, pidfd: None, in_parent: true, armed: true };

    // A provisional state first: whatever happens from here on, `delete`
    // can find the cgroup and (once it exists) init.
    let mut state = State {
        oci_version: bundle.spec.version().clone(),
        id: opts.id.clone(),
        status: Status::Creating,
        pid: 0,
        bundle: bundle.dir.clone(),
        annotations: bundle.spec.annotations().clone().unwrap_or_default().into_iter().collect(),
        rootfs: plan.root.clone(),
        created: now_rfc3339(),
        rustlet: Private {
            cgroup: plan.cgroup.as_ref().map(|c| c.path.clone()),
            no_new_keyring: opts.no_new_keyring,
            ..Default::default()
        },
    };
    dir.write(&state)?;
    dir.write_config(&bundle.spec)?;

    // cgroup: created (and limited) before init exists, so init is born
    // inside it and never runs a single instruction unlimited.
    let cgroup = match &plan.cgroup {
        Some(c) => {
            let cg = Cgroup::create(&c.path, &c.settings, &SystemdDelegated)?;
            guard.cgroup = Some(cg.clone());
            cg.mark_container(&opts.id)?;
            state.rustlet.cgroup_ino = Some(cg.inode()?);
            dir.write(&state)?;
            Some(cg)
        }
        None => None,
    };
    let cgroup_fd = cgroup.as_ref().map(Cgroup::dir_fd).transpose()?;

    // exec.fifo: 0622 because init opens it *after* switching to the
    // container user; umask would strip the write bits, so set them after.
    let fifo_path = dir.fifo();
    rustlet_sys::fs::mkfifo(&fifo_path, Mode::from_bits_truncate(0o600)).context("mkfifo exec.fifo")?;
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&fifo_path, std::fs::Permissions::from_mode(0o622)).context("chmod exec.fifo")?;
    }
    let fifo =
        nix::fcntl::open(&fifo_path, OFlag::O_PATH | OFlag::O_CLOEXEC, Mode::empty()).context("open exec.fifo")?;

    // Console: where init sends its PTY master.
    let (console_parent, console_child) = match (plan.process.terminal, &opts.console_socket) {
        (false, _) => (None, None),
        (true, Some(path)) => (None, Some(console::connect_console_socket(path)?)),
        (true, None) => {
            let (a, b) = socketpair(AddressFamily::Unix, SockType::Stream, None, SockFlag::SOCK_CLOEXEC)
                .context("socketpair (console)")?;
            (Some(a), Some(b))
        }
    };

    // The host side of every mount, opened while we are still only in the
    // host's namespaces (see `HostTrees` for why not in init).
    let trees = HostTrees::open(&plan)?;
    let parent_mnt_ns = namespaces::current_mnt_ns()?;
    let host_init_mnt_ns = namespaces::host_init_mnt_ns()?;
    namespaces::join_all(&plan.namespaces)?;

    let mut clone = Clone3::new().flags(plan.namespaces.clone_flags | CloneFlags::PIDFD);
    if let Some(fd) = &cgroup_fd {
        clone = clone.into_cgroup(fd.as_fd());
    }
    let forked = clone.spawn().with_context(|| format!("clone3({:?})", plan.namespaces.clone_flags))?;
    match forked {
        Forked::Child => {
            // Close the child's copies of everything that belongs to the
            // parent, first of all the host cgroup directory fd: an open fd
            // to a host directory inside a container is exactly the leak
            // behind CVE-2024-21626.
            drop(cgroup_fd);
            drop(parent_sock);
            drop(console_parent);
            drop(sfd);
            // Closing our copy is safe: the lock is a POSIX record lock
            // owned by the parent process, so this doesn't release it.
            drop(lock);
            guard.in_parent = false; // never tear anything down from here
            guard.armed = false;
            let ctx = InitContext {
                plan: &plan,
                parent_mnt_ns,
                host_init_mnt_ns,
                trees,
                sync: &child_sock,
                exec_fifo: &fifo,
                console: console_child,
                foreground,
                preserve_fds: opts.preserve_fds,
                no_new_keyring: opts.no_new_keyring,
            };
            // A panic must not unwind out of here into the parent's code
            // (we are a copy of the parent). Report it like any error.
            let err = std::panic::catch_unwind(AssertUnwindSafe(|| init::container_init(ctx)))
                .unwrap_or_else(|_| Error::Init { message: "container init panicked".into(), errno: None });
            let code = match &err {
                Error::Exec { errno: Errno::ENOENT, .. } => 127,
                Error::Exec { .. } => 126,
                _ => 1,
            };
            if child_sock.send(&SyncMsg::from_error(&err)).is_err() {
                // Detached: `create` exited long ago. The container's own
                // stderr is the only place left to say what went wrong.
                // (`writeln!`, not `eprintln!`: a failed write must not
                // panic and unwind into the parent's code.)
                use std::io::Write;
                let _ = writeln!(std::io::stderr(), "rustlet-runc: error: {err}");
            }
            process::exit_now(code)
        }
        Forked::Parent { pid, pidfd } => {
            drop(child_sock);
            drop(console_child);
            drop(cgroup_fd);
            drop(fifo);
            let pidfd = pidfd.expect("CLONE_PIDFD was requested");
            // Hand init to the guard before anything else can fail.
            match pidfd.try_clone() {
                Ok(fd) => guard.pidfd = Some(fd),
                Err(e) => {
                    let _ = process::pidfd_send_signal(pidfd.as_fd(), Signal::SIGKILL);
                    let _ = process::waitid(WaitTarget::PidFd(pidfd.as_fd()), false);
                    return Err(e).context("dup pidfd");
                }
            }
            // The start time is what tells "our init" apart from a later
            // process that got the same PID.
            state.pid = pid.as_raw();
            state.rustlet.init_start_time = rustlet_sys::procfs::start_time(pid).context("read init's start time")?;
            if cgroup.is_none() {
                state.rustlet.init_cgroup =
                    Some(rustlet_sys::procfs::cgroup_path(Some(pid)).context("read init's cgroup")?.trim().to_owned());
            }
            dir.write(&state)?;

            prepare_init(&plan, pid, &trees)?;
            // Init holds its own copies of the trees until it attaches them.
            drop(trees);
            proceed(&parent_sock)?;
            let mut failed = wait_for(&parent_sock, &sfd, &SyncMsg::SetLimits)?;
            if failed.is_none() {
                set_limits(&plan, pid)?;
                proceed(&parent_sock)?;
                failed = wait_for(&parent_sock, &sfd, &SyncMsg::Ready)?;
            }
            if let Some(msg) = failed {
                // Init exits after reporting; reap it, then let the guard
                // remove the cgroup and the state directory.
                let _ = process::waitid(WaitTarget::PidFd(pidfd.as_fd()), false);
                return Err(msg.into_error());
            }
            state.status = Status::Created;
            dir.write(&state)?;
            if let Some(path) = &opts.pid_file {
                write_pid_file(path, pid)?;
            }
            tracing::debug!(%pid, "container created");
            Ok(Spawned {
                dir,
                state,
                pidfd,
                sync: parent_sock,
                cgroup,
                console: console_parent,
                sfd,
                terminal: plan.process.terminal,
                lock: Some(lock),
                guard,
            })
        }
    }
}

/// The parent's first part of init's setup, done while init waits for its
/// first `Proceed`: the user namespace's maps (only a process outside the
/// namespace may write them), then the idmapped mounts, which need the
/// mapped namespace.
fn prepare_init(plan: &Plan, pid: Pid, trees: &HostTrees) -> Result<()> {
    if let Some(maps) = &plan.userns {
        DirectIdMapper.write(pid, maps)?;
        if plan.mounts.iter().any(|m| m.idmap.is_some()) {
            let ns = process::open_ns(format!("/proc/{pid}/ns/user")).context("open init's user namespace")?;
            trees.idmap(plan, ns.as_fd())?;
        }
    }
    Ok(())
}

/// The second part, when init asks with `SetLimits`: its rlimits and
/// `oom_score_adj`. In a user namespace, init could lower its limits but
/// not raise a hard one, nor lower its OOM score: both need
/// `CAP_SYS_RESOURCE` in the *initial* user namespace. So they are set from
/// outside, for every container (one code path). Init asks once its setup
/// as root is done, so the mounts' fds don't count against the container's
/// `RLIMIT_NOFILE`, and before it changes its uid, which matters for
/// `RLIMIT_NPROC`: the kernel checks it against the new user's process
/// count at that moment. (runc sets them at the same point, `procReady`.)
fn set_limits(plan: &Plan, pid: Pid) -> Result<()> {
    for r in &plan.process.rlimits {
        process::prlimit(pid, r.resource, r.soft, r.hard)
            .with_context(|| format!("set container init's {:?} (prlimit)", r.resource))?;
    }
    if let Some(adj) = plan.process.oom_score_adj {
        // Init is our unreaped child, so its PID can't have been reused.
        let path = format!("/proc/{pid}/oom_score_adj");
        std::fs::write(&path, adj.to_string()).with_context(|| format!("write {path}"))?;
    }
    Ok(())
}

/// Lets init go on. If it is already gone, what it reported before dying
/// says more than our `EPIPE`.
fn proceed(sock: &SyncSocket) -> Result<()> {
    match sock.send(&SyncMsg::Proceed) {
        Ok(()) => Ok(()),
        Err(e) => match sock.recv() {
            Ok(Some(msg)) => Err(msg.into_error()),
            _ => Err(e),
        },
    }
}

/// Blocks the [`FORWARDED`] signals and SIGCHLD and returns a signalfd for
/// them. Called before `clone3`, so no signal can slip through between the
/// child's birth and the moment we start reading them.
pub(crate) fn block_signals() -> Result<SignalFd> {
    let mut blocked = SigSet::empty();
    for s in FORWARDED {
        blocked.add(s);
    }
    blocked.add(Signal::SIGCHLD);
    sigprocmask(SigmaskHow::SIG_BLOCK, Some(&blocked), None).context("block signals")?;
    SignalFd::with_flags(&blocked, SfdFlags::SFD_CLOEXEC | SfdFlags::SFD_NONBLOCK).context("signalfd")
}

/// Waits for init to send `want` (`SetLimits`, then `Ready`). Returns
/// `Some(msg)` if init reported an error instead. A
/// SIGTERM/SIGINT/SIGHUP/SIGQUIT to `rustlet-runc` meanwhile aborts the
/// create (the guard then removes everything), so a create stuck on, say, a
/// hung network mount can always be interrupted.
fn wait_for(sock: &SyncSocket, sfd: &SignalFd, want: &SyncMsg) -> Result<Option<SyncMsg>> {
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
                    return Err(Error::container(format!("create interrupted by {sig:?}; removing the container")));
                }
            }
        }
        if fds[0].revents().is_some_and(|r| !r.is_empty()) {
            return match sock.recv()? {
                Some(msg) if msg == *want => Ok(None),
                Some(msg) => Ok(Some(msg)),
                None => Err(Error::Init {
                    message: "container init exited during setup without saying why".into(),
                    errno: None,
                }),
            };
        }
    }
}

/// Opens the gate: lets a created container's init `execve`.
///
/// The FIFO is opened `O_RDONLY|O_NONBLOCK` (so `start` never hangs if init
/// died meanwhile) and **unlinked right away**: its absence is what makes
/// the status `running`, so even if we die before reading the byte, nobody
/// will later mistake the running program for a created container; and a
/// second `start` finds no FIFO. The open unblocks init's `open(O_WRONLY)`;
/// init writes one byte, which we read to be sure it got through.
pub(crate) fn release(dir: &StateDir, init: &OwnedFd) -> Result<()> {
    let path = dir.fifo();
    let fifo = nix::fcntl::open(&path, OFlag::O_RDONLY | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC, Mode::empty()).map_err(
        |e| match e {
            Errno::ENOENT => Error::container(format!("container {:?} has already been started", dir.id())),
            e => Error::Sys { context: format!("open {}", path.display()), errno: e },
        },
    )?;
    std::fs::remove_file(&path).with_context(|| format!("remove {}", path.display()))?;
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let mut fds = [PollFd::new(fifo.as_fd(), PollFlags::POLLIN), PollFd::new(init.as_fd(), PollFlags::POLLIN)];
        match poll(&mut fds, poll_timeout(deadline)) {
            Ok(0) => {
                return Err(Error::Init { message: "container init did not respond to start".into(), errno: None });
            }
            Ok(_) | Err(Errno::EINTR) => {}
            Err(e) => return Err(e).context("poll exec.fifo"),
        }
        let ready = |i: usize| fds[i].revents().is_some_and(|r| !r.is_empty());
        if ready(0) {
            let mut b = [0u8; 1];
            match nix::unistd::read(&fifo, &mut b) {
                Ok(1) => return Ok(()),
                Err(Errno::EAGAIN | Errno::EINTR) => continue,
                // EOF: init closed its end without the byte. Don't spin.
                Ok(_) | Err(_) => {
                    return Err(Error::Init {
                        message: "container init exited before it could start".into(),
                        errno: None,
                    });
                }
            }
        }
        if ready(1) {
            return Err(Error::Init { message: "container init exited before it could start".into(), errno: None });
        }
    }
}

/// The time left until `deadline`, as a poll timeout.
fn poll_timeout(deadline: std::time::Instant) -> PollTimeout {
    let left = deadline.saturating_duration_since(std::time::Instant::now());
    PollTimeout::try_from(left).unwrap_or(PollTimeout::MAX)
}

/// Opens a pidfd for the container's init and checks that it still is the
/// process we created (not a recycled PID).
pub(crate) fn open_init(state: &State) -> Result<OwnedFd> {
    let gone = || Error::container(format!("container {:?} is not running", state.id));
    if state.pid == 0 {
        return Err(gone());
    }
    let fd = process::pidfd_open(state.init_pid()).map_err(|_| gone())?;
    // Open first, check second: a pidfd keeps referring to the process it
    // was opened for, even if that process dies and its PID is reused. So if
    // the start time still matches *after* the open, the pidfd is our init.
    if !state.init_alive() {
        return Err(gone());
    }
    Ok(fd)
}

/// Atomically writes a PID file: a private temp file next to it (created
/// `O_EXCL|O_NOFOLLOW`, so it can't clobber or follow anything), renamed
/// into place.
pub(crate) fn write_pid_file(path: &Path, pid: Pid) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let name = path.file_name().ok_or_else(|| Error::container(format!("bad pid file path {}", path.display())))?;
    let tmp = path.with_file_name(format!(".{}.{}.tmp", name.to_string_lossy(), std::process::id()));
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&tmp)
        .with_context(|| format!("create {}", tmp.display()))?;
    f.write_all(pid.as_raw().to_string().as_bytes()).with_context(|| format!("write {}", tmp.display()))?;
    drop(f);
    std::fs::rename(&tmp, path).with_context(|| format!("rename to {}", path.display()))
}

/// Kills everything in a container and waits for it to be gone: the whole
/// cgroup at once if there is one (`cgroup.kill`, which also works on a
/// frozen cgroup), else init (the PID namespace dies with it).
pub(crate) fn kill_everything(cgroup: Option<&Cgroup>, init: Option<&OwnedFd>) -> Result<()> {
    if let Some(cg) = cgroup {
        cg.kill()?;
    } else if let Some(fd) = init {
        match process::pidfd_send_signal(fd.as_fd(), Signal::SIGKILL) {
            Ok(()) | Err(Errno::ESRCH) => {}
            Err(e) => return Err(e).context("SIGKILL container init"),
        }
    }
    if let Some(fd) = init {
        wait_exit(fd, TEARDOWN_TIMEOUT)?;
    }
    if let Some(cg) = cgroup {
        cg.wait_empty(TEARDOWN_TIMEOUT)?;
    }
    Ok(())
}

/// Waits until the process behind `pidfd` has exited (a pidfd becomes
/// readable then, whether or not we are its parent).
pub(crate) fn wait_exit(pidfd: &OwnedFd, timeout: Duration) -> Result<()> {
    let deadline = std::time::Instant::now() + timeout;
    let mut fds = [PollFd::new(pidfd.as_fd(), PollFlags::POLLIN)];
    loop {
        match poll(&mut fds, poll_timeout(deadline)) {
            Ok(0) => return Err(Error::Init { message: "container init did not exit in time".into(), errno: None }),
            Ok(_) => return Ok(()),
            Err(Errno::EINTR) => continue,
            Err(e) => return Err(e).context("poll pidfd"),
        }
    }
}

/// Undoes a half-finished create on drop.
struct CreateGuard {
    dir: StateDir,
    cgroup: Option<Cgroup>,
    pidfd: Option<OwnedFd>,
    /// False in the forked child, which must never tear anything down.
    in_parent: bool,
    armed: bool,
}

impl Drop for CreateGuard {
    fn drop(&mut self) {
        if !self.armed || !self.in_parent {
            return;
        }
        if let Err(e) = kill_everything(self.cgroup.as_ref(), self.pidfd.as_ref()) {
            tracing::warn!(%e, "cleanup after failed create: could not kill the container");
        }
        if let Some(fd) = &self.pidfd {
            // We are init's parent here: reap it.
            let _ = process::waitid(WaitTarget::PidFd(fd.as_fd()), true);
        }
        if let Some(cg) = &self.cgroup
            && let Err(e) = cg.remove()
        {
            tracing::warn!(%e, cgroup = %cg.path(), "cleanup after failed create: could not remove the cgroup");
        }
        if let Err(e) = self.dir.remove() {
            tracing::warn!(%e, "cleanup after failed create: could not remove the state directory");
        }
    }
}

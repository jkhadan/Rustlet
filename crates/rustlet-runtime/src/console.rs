//! Terminals: a PTY for the container, the OCI console-socket protocol, and
//! the foreground relay behind `rustlet-runc run` with `terminal: true`.
//!
//! ## The picture
//!
//! ```text
//!  your terminal ── rustlet-runc run (relay) ── PTY master ═══ PTY slave ── container
//!   (raw mode)       stdin→master, master→stdout            (/dev/pts/0 = /dev/console,
//!                                                            the shell's controlling tty)
//! ```
//!
//! The PTY pair is created *inside* the container (from its own devpts
//! instance), so the slave is a real `/dev/pts/N` there and `tty` works.
//! Container init keeps the slave (as stdin/stdout/stderr and controlling
//! terminal) and passes the master out through a Unix socket with
//! `SCM_RIGHTS` (the OCI "console socket"): to whoever asked for it with
//! `--console-socket` (the shim, from Phase 4), or to `rustlet-runc run`
//! itself, which relays between the master and your terminal.
//!
//! ## Why raw mode
//!
//! Two line disciplines sit on the path: your terminal's and the one on the
//! container's slave. Only one of them should turn Ctrl-C into SIGINT, handle
//! backspace and echo what you type, and that is the container's, because
//! that is where the shell and its jobs live. So the relay switches your
//! terminal to *raw* mode: every key travels as a plain byte into the master
//! and the container's line discipline does the rest. Output needs no
//! processing on our side either: the slave already turned `\n` into `\r\n`
//! (`ONLCR`) on its way out.
//!
//! ## End of input
//!
//! A terminal has no "close the write end". The only way a program reading
//! a tty learns that input is over is the EOF character (`VEOF`, normally
//! Ctrl-D) typed at the start of a line: the line discipline then makes
//! `read()` return 0. So when the relay's own input ends (a script piped
//! into `rustlet-runc run -t`), it types that character once, as a user
//! would, and stops reading input.
//!
//! ## Back-pressure
//!
//! The kernel buffers only a little between master and slave: about 18 KiB
//! each way on Linux 7.0, when nobody reads. If the container stops reading
//! its input, a *blocking* write to the master waits for as long as it likes;
//! and if the container is itself stuck writing output that only the relay
//! can read, both sides wait for each other forever. So the master is
//! non-blocking: input that doesn't fit stays in the relay, and while the
//! relay waits for room it keeps copying the container's output.

use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

use nix::fcntl::{FcntlArg, OFlag, fcntl};
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::stat::Mode;
use nix::sys::termios::{self, SetArg, SpecialCharacterIndices, Termios};
use rustlet_sys::Errno;
use rustlet_sys::mount::{OpenTreeFlags, move_mount_fd, open_tree};
use rustlet_sys::socket;
use rustlet_sys::term::{self, WinSize};

use crate::error::{Context, Error, Result};

/// Payload sent along with the master fd, as runc does (receivers ignore it).
pub const CONSOLE_MSG: &[u8] = b"/dev/ptmx";

/// Container side, called by init **after `pivot_root`** when
/// `process.terminal` is true:
///
/// 1. open `/dev/ptmx` (→ the container's `pts/ptmx`) and its peer (the
///    slave, via `TIOCGPTPEER`, no path lookup);
/// 2. apply `size` (`process.consoleSize`) if given;
/// 3. bind-mount the slave onto `/dev/console` (creating the file in the
///    `/dev` tmpfs), fd-based via `open_tree(slave, "", AT_EMPTY_PATH)`;
/// 4. `setsid()` + `TIOCSCTTY`: init becomes a session leader whose
///    controlling terminal is the slave (this is what makes job control
///    work);
/// 5. `dup2` the slave onto 0, 1 and 2;
/// 6. send the master over `socket` (`SCM_RIGHTS`, payload [`CONSOLE_MSG`])
///    and close init's copies of the master and the socket.
///
/// It must run while init is still root (step 3 mounts), and before
/// anything that wants to write to the container's stdio. When it returns,
/// fds 0–2 are the slave (not close-on-exec, so they survive `execve`) and
/// init holds no other fd of the terminal: the master lives on only in the
/// receiver's process, so once the receiver closes it, the container sees
/// a hangup.
pub(crate) fn setup_container_tty(socket: OwnedFd, size: Option<WinSize>) -> Result<()> {
    setup_tty(socket, size, true)
}

/// The same for a process started by `exec`, which gets a PTY of its own
/// but leaves `/dev/console` (init's terminal) alone: steps 1, 2, 4, 5, 6.
pub(crate) fn setup_exec_tty(socket: OwnedFd, size: Option<WinSize>) -> Result<()> {
    setup_tty(socket, size, false)
}

fn setup_tty(socket: OwnedFd, size: Option<WinSize>, console: bool) -> Result<()> {
    // 1. The pair comes from the container's own devpts instance, so the
    //    slave is a `/dev/pts/N` that exists in here, not on the host.
    let master = open_container_ptmx()?;
    let slave = term::open_peer(master.as_fd()).context("open the pty slave (TIOCGPTPEER)")?;

    // 2. Before anything runs on the terminal, so the first program already
    //    sees the right size and nobody gets a spurious SIGWINCH.
    if let Some(size) = size {
        term::set_winsize(master.as_fd(), size).context("set the console size (TIOCSWINSZ)")?;
    }

    // 3.
    if console {
        bind_console(slave.as_fd())?;
    }

    // 4. TIOCSCTTY only works for a session leader without a controlling
    //    terminal, and init inherited rustlet-runc's session (and with it,
    //    possibly, your terminal). `setsid()` fails with EPERM only for a
    //    process-group leader, and init isn't one: clone3 put it in
    //    rustlet-runc's process group, whose ID is rustlet-runc's pid, not
    //    init's. So it succeeds and leaves us leading a new session with no
    //    terminal, ready to adopt the slave.
    nix::unistd::setsid().context("setsid")?;
    term::set_controlling_tty(slave.as_fd()).context("make the pty the controlling terminal (TIOCSCTTY)")?;

    // 5. dup2 clears close-on-exec on the new fds, so these three copies are
    //    what the user's program inherits.
    for stdio in 0..=2 {
        term::dup2_stdio(slave.as_fd(), stdio).with_context(|| format!("dup2 the pty slave onto fd {stdio}"))?;
    }

    // 6. The receiver gets its own fd for the same open master. Ours must not
    //    reach the container: a process in there holding the master could
    //    type into its own terminal, and it would keep the terminal alive
    //    after the receiver let go.
    socket::send_fds(socket.as_fd(), CONSOLE_MSG, &[master.as_fd()])
        .context("send the pty master over the console socket")?;
    drop(master);
    drop(slave);
    drop(socket);
    Ok(())
}

/// Opens `/dev/pts/ptmx` directly rather than through the `/dev/ptmx`
/// symlink: for `exec` the container has been running for a while, and
/// whatever its root put at `/dev/ptmx` (a FIFO that blocks the open, a
/// symlink to some other file) would be opened by us, still with every
/// capability. So: no symlinks at all, `O_NONBLOCK` (a FIFO can't block us),
/// and it must be a devpts file before we treat it as a PTY.
fn open_container_ptmx() -> Result<OwnedFd> {
    use rustlet_sys::fs::{ResolveFlags, fs_magic, magic, openat2};
    let root = nix::fcntl::open("/", OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC, Mode::empty())
        .context("open /")?;
    let flags = OFlag::O_RDWR | OFlag::O_NOCTTY | OFlag::O_NONBLOCK;
    let resolve = ResolveFlags::IN_ROOT | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS;
    let master = openat2(Some(root.as_fd()), "dev/pts/ptmx", flags, Mode::empty(), resolve)
        .context("open /dev/pts/ptmx (is devpts mounted on /dev/pts?)")?;
    if fs_magic(master.as_fd()).context("fstatfs /dev/pts/ptmx")? != magic::DEVPTS_SUPER_MAGIC {
        return Err(Error::invalid("/dev/pts/ptmx is not on a devpts filesystem"));
    }
    // Blocking again: receivers of the master (and our relay, which sets its
    // own flags) expect an ordinary fd.
    fcntl(&master, FcntlArg::F_SETFL(OFlag::empty())).context("clear O_NONBLOCK on the pty master")?;
    term::unlock_pty(master.as_fd()).context("unlock the pty (TIOCSPTLCK)")?;
    Ok(master)
}

/// Step 3: bind-mounts the slave onto `/dev/console`, the terminal that
/// init systems, `getty` and some daemons open by name.
///
/// A file bind mount needs a file to sit on, so we create an empty one in
/// the `/dev` tmpfs first (0o666, and init's umask is 0, so that is the real
/// mode; the mount hides it anyway). The mount itself is fd-based: the
/// source is the slave we already hold, the target an `O_PATH` fd, so no
/// path is resolved twice.
fn bind_console(slave: BorrowedFd<'_>) -> Result<()> {
    const CONSOLE: &str = "/dev/console";
    let create = OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
    match nix::fcntl::open(CONSOLE, create, Mode::from_bits_truncate(0o666)) {
        Ok(fd) => drop(fd),
        // /dev is our own fresh tmpfs, so only a mount from config.json can
        // have put something here already. Checked below.
        Err(Errno::EEXIST) => {}
        Err(e) => return Err(e).context("create /dev/console"),
    }
    let target = nix::fcntl::open(CONSOLE, OFlag::O_PATH | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC, Mode::empty())
        .context("open /dev/console")?;
    // With O_NOFOLLOW, an O_PATH open of a symlink returns the symlink
    // itself. Mounting on top of that (or on a directory) makes no sense.
    let kind = nix::sys::stat::fstat(&target).context("stat /dev/console")?.st_mode & libc::S_IFMT;
    if kind != libc::S_IFREG && kind != libc::S_IFCHR {
        return Err(Error::invalid("/dev/console must be a file or a device (the container's pty is mounted there)"));
    }
    let tree = open_tree(Some(slave), Path::new(""), OpenTreeFlags::CLONE | OpenTreeFlags::EMPTY_PATH)
        .context("bind the pty slave (open_tree)")?;
    move_mount_fd(tree.as_fd(), target.as_fd()).context("mount the pty slave on /dev/console")
}

/// Connects to a listening `--console-socket` (resolved on the host, before
/// the container exists; the connected fd is inherited by init).
///
/// std makes the socket close-on-exec, which is what we want: init inherits
/// it through the address-space copy of `clone3`, not across an `execve`,
/// and it must not leak into the user's program if something goes wrong.
/// Like every `connect` to a path, the path must fit `sun_path` (107 bytes).
pub fn connect_console_socket(path: &Path) -> Result<OwnedFd> {
    let stream =
        UnixStream::connect(path).with_context(|| format!("connect to the console socket {}", path.display()))?;
    Ok(OwnedFd::from(stream))
}

/// Receives the PTY master that init sends over a connected console socket.
/// Fails if the message carries no fd or the fd is not a terminal.
pub fn receive_master(socket: BorrowedFd<'_>) -> Result<OwnedFd> {
    // The payload is only CONSOLE_MSG; what matters rides in the ancillary data.
    let mut buf = [0u8; 64];
    let (n, fds) = loop {
        match socket::recv_fds(socket, &mut buf, 1) {
            Err(Errno::EINTR) => continue,
            r => break r.context("receive the pty master from the console socket")?,
        }
    };
    let Some(master) = fds.into_iter().next() else {
        return if n == 0 {
            Err(Errno::ECONNRESET).context("console socket closed before the pty master arrived (did init fail?)")
        } else {
            Err(Errno::EBADMSG).context("console socket: the message carried no file descriptor")
        };
    };
    // Whoever is on the other end decides what we get: make sure it is a
    // terminal before we set its window size and relay a user's keys to it.
    // TIOCGPTN only works on a PTY *master*: this rejects any other fd,
    // including a slave, which `isatty` alone would accept.
    if !term::isatty(master.as_fd()) || term::pty_number(master.as_fd()).is_err() {
        return Err(Errno::ENOTTY).context("console socket: the received fd is not a PTY master");
    }
    Ok(master)
}

/// Largest chunk read from either side at once.
const CHUNK: usize = 64 * 1024;

/// How long one [`Relay::pump`] may wait for room in a full master before it
/// returns to the caller's loop (which also has signals to forward).
const WRITE_BUDGET: Duration = Duration::from_millis(50);

/// Upper bound for one [`Relay::drain`]: a process that outlived init and
/// keeps writing must not keep `rustlet-runc` from exiting.
const DRAIN_LIMIT: usize = 4 << 20;

/// Ctrl-D, the EOF character of a terminal with default settings.
const DEFAULT_VEOF: u8 = 0x04;

/// The foreground relay for `rustlet-runc run` with a terminal.
///
/// It is driven by the caller's `poll` loop (which also watches the signalfd
/// and the container's pidfd), so it never waits long on its own:
///
/// ```ignore
/// loop {
///     let mut fds: Vec<PollFd> = relay.fds().iter().map(|fd| PollFd::new(*fd, PollFlags::POLLIN)).collect();
///     poll(&mut fds, relay.poll_timeout())?;
///     let revents: Vec<PollFlags> = fds.iter().map(|f| f.revents().unwrap_or(PollFlags::empty())).collect();
///     if !relay.pump(&revents)? { break } // the container closed its terminal
/// }
/// ```
///
/// Call `pump` after *every* `poll`, even when none of the relay's fds is
/// ready (an empty `revents` entry is fine): that is when it retries input
/// the container hasn't accepted yet. Once it has returned `false`, stop
/// polling the relay's fds: a master whose slave is gone stays `POLLHUP`
/// forever, and `poll` would return at once, every time.
///
/// If input is a terminal it is switched to raw mode (so Ctrl-C, Ctrl-Z, …
/// reach the container's line discipline instead of generating signals for
/// `rustlet-runc`) and restored when the relay is dropped. When input
/// reaches EOF (piped input), the relay sends the terminal's EOF character
/// (Ctrl-D) to the master once and stops reading input, so a shell reading
/// the script exits normally.
pub struct Relay {
    /// The PTY master, switched to `O_NONBLOCK` (see "Back-pressure" in the
    /// module docs). Its open file is ours alone: init closed its copy.
    master: OwnedFd,
    /// Keystrokes or a piped script: a dup of stdin in [`Relay::new`].
    input: OwnedFd,
    /// Where the container's output goes: a dup of stdout in [`Relay::new`].
    output: OwnedFd,
    /// Input is a terminal: it is in raw mode and has a window size to copy.
    input_is_tty: bool,
    /// The input terminal's settings from before raw mode, put back by `Drop`.
    saved_termios: Option<Termios>,
    /// Input the master hasn't accepted yet, because the container isn't
    /// reading. No new input is read until this is delivered, so it never
    /// holds more than one chunk (plus the EOF character).
    pending: Vec<u8>,
    /// Input has ended: the EOF character is queued (or sent) and input is
    /// no longer polled.
    input_done: bool,
    /// Scratch buffer for reads, allocated once.
    buf: Vec<u8>,
}

impl Relay {
    /// Relays between this process's stdin/stdout and `master`, copying the
    /// window size of stdin (if it is a terminal) to the master first.
    pub fn new(master: OwnedFd) -> Result<Relay> {
        // Dups rather than fds 0 and 1 themselves: dropping the relay closes
        // its fds, and closing stdin/stdout would be a surprise. A dup refers
        // to the same open file, so terminal settings made through it apply
        // to the real stdin.
        let input = std::io::stdin().as_fd().try_clone_to_owned().context("dup stdin")?;
        let output = std::io::stdout().as_fd().try_clone_to_owned().context("dup stdout")?;
        Relay::with_io(master, input, output)
    }

    /// Same, with explicit input/output fds (for tests).
    ///
    /// Only the master's flags are changed (`O_NONBLOCK`). Input and output
    /// are left blocking: they are usually shared with the shell that
    /// started us, and non-blocking mode is a property of the shared open
    /// file, so setting it would break the shell once we exit.
    pub fn with_io(master: OwnedFd, input: OwnedFd, output: OwnedFd) -> Result<Relay> {
        set_nonblocking(master.as_fd()).context("make the pty master non-blocking")?;
        let input_is_tty = term::isatty(input.as_fd());
        let mut relay = Relay {
            master,
            input,
            output,
            input_is_tty,
            saved_termios: None,
            pending: Vec::with_capacity(CHUNK + 1),
            input_done: false,
            buf: vec![0; CHUNK],
        };
        // Size first: if that fails, the terminal hasn't been touched yet.
        relay.resize()?;
        if input_is_tty {
            relay.enter_raw_mode()?;
        }
        Ok(relay)
    }

    /// The fds to poll for `POLLIN`, in a fixed order that [`Relay::pump`]
    /// expects its `revents` in: `[input, master]`, or `[master]` once input
    /// has reached EOF (an input at EOF is always "ready", and polling it
    /// would spin).
    pub fn fds(&self) -> Vec<BorrowedFd<'_>> {
        if self.input_done { vec![self.master.as_fd()] } else { vec![self.input.as_fd(), self.master.as_fd()] }
    }

    /// The timeout to give the caller's `poll`: none (wait for an event)
    /// normally, zero while input is waiting for room in the master. In that
    /// state no fd of ours may become readable for a while (the container is
    /// reading, not writing), so `pump` must be called anyway to push the
    /// rest; it does its own bounded waiting on the master, so this doesn't
    /// spin.
    pub fn poll_timeout(&self) -> PollTimeout {
        if self.pending.is_empty() { PollTimeout::NONE } else { PollTimeout::ZERO }
    }

    /// Moves whatever is ready. Returns `Ok(false)` once the master reports
    /// that the container side is gone (`EIO`/`POLLHUP`) and its output has
    /// been fully written out.
    ///
    /// Blocks only while writing to the output (like any writer) and for at
    /// most `WRITE_BUDGET` (50 ms) while the master is full. Input is read
    /// only when `poll` said it is ready, so the relay never waits for keys.
    pub fn pump(&mut self, revents: &[PollFlags]) -> Result<bool> {
        debug_assert_eq!(revents.len(), self.fds().len(), "pump wants one revents entry per fd of fds()");
        let ev = |i: usize| revents.get(i).copied().unwrap_or(PollFlags::empty());
        let (input_ev, master_ev) = if self.input_done { (PollFlags::empty(), ev(0)) } else { (ev(0), ev(1)) };
        if (input_ev | master_ev).contains(PollFlags::POLLNVAL) {
            return Err(Errno::EBADF).context("poll: a terminal relay fd is not open");
        }

        // Output first: it may be exactly what the container is blocked on.
        // One chunk per call; if there is more, the next poll says so at once.
        if !master_ev.is_empty() && !self.copy_output()? {
            return self.finish();
        }
        if self.pending.is_empty() && !self.input_done && !input_ev.is_empty() {
            self.read_input(input_ev)?;
        }
        if !self.pending.is_empty() && !self.flush_input()? {
            return self.finish();
        }
        Ok(true)
    }

    /// Reads whatever the master still has without blocking, writes it out,
    /// and returns (used after the container's init exited).
    ///
    /// Stops at `EAGAIN` (nothing buffered right now: some process still has
    /// the slave open), at `EIO` (every slave fd is closed and the buffer is
    /// empty), or after 4 MiB, in case a leftover process keeps writing.
    pub fn drain(&mut self) -> Result<()> {
        let mut copied = 0;
        while copied < DRAIN_LIMIT {
            // The master is O_NONBLOCK since `with_io`, so this never waits.
            match nix::unistd::read(&self.master, &mut self.buf) {
                Ok(0) | Err(Errno::EIO | Errno::EAGAIN) => break,
                Ok(n) => {
                    write_all(self.output.as_fd(), &self.buf[..n])?;
                    copied += n;
                }
                Err(Errno::EINTR) => {}
                Err(e) => return Err(e).context("read from the pty master"),
            }
        }
        Ok(())
    }

    /// SIGWINCH: copy the input terminal's size to the master (no-op if the
    /// input is not a terminal).
    ///
    /// `TIOCSWINSZ` on the master raises SIGWINCH in the container's
    /// foreground process group (if the size changed), which is how a
    /// full-screen program in there learns to redraw. The container is in
    /// its own session, so it never sees *our* terminal's SIGWINCH.
    pub fn resize(&self) -> Result<()> {
        if !self.input_is_tty {
            return Ok(());
        }
        let size = term::get_winsize(self.input.as_fd()).context("read the terminal's window size")?;
        term::set_winsize(self.master.as_fd(), size).context("set the pty's window size")
    }

    /// Saves the input terminal's settings and switches it to raw mode:
    /// no echo, no line editing, no signal keys, no CR/NL translation, and
    /// `read` returns as soon as one byte is there (`VMIN = 1`).
    fn enter_raw_mode(&mut self) -> Result<()> {
        let saved = termios::tcgetattr(&self.input).context("read the terminal's settings")?;
        let mut raw = saved.clone();
        termios::cfmakeraw(&mut raw);
        termios::tcsetattr(&self.input, SetArg::TCSANOW, &raw).context("switch the terminal to raw mode")?;
        // Only now: `Drop` must not "restore" settings it never changed.
        self.saved_termios = Some(saved);
        Ok(())
    }

    /// Moves one chunk of the container's output. Returns `false` once the
    /// master says every slave fd is closed: `EIO` from `read` (Linux hands
    /// out what is still buffered first, and only then `EIO`), or 0 after a
    /// hangup.
    fn copy_output(&mut self) -> Result<bool> {
        match nix::unistd::read(&self.master, &mut self.buf) {
            Ok(0) | Err(Errno::EIO) => Ok(false),
            Ok(n) => {
                write_all(self.output.as_fd(), &self.buf[..n])?;
                Ok(true)
            }
            Err(Errno::EAGAIN | Errno::EINTR) => Ok(true),
            Err(e) => Err(e).context("read from the pty master"),
        }
    }

    /// Reads one chunk of input into `pending`; on EOF queues the EOF
    /// character instead and stops polling input.
    fn read_input(&mut self, ev: PollFlags) -> Result<()> {
        let eof = if ev.contains(PollFlags::POLLIN) {
            match nix::unistd::read(&self.input, &mut self.buf) {
                Ok(0) => true,
                Ok(n) => {
                    self.pending.extend_from_slice(&self.buf[..n]);
                    false
                }
                Err(Errno::EAGAIN | Errno::EINTR) => false,
                // A terminal that hung up, or one we may no longer read
                // (orphaned background process group): input is over.
                Err(Errno::EIO) => true,
                Err(e) => return Err(e).context("read input"),
            }
        } else {
            // POLLHUP (or POLLERR) without POLLIN: the writer is gone and
            // nothing is left to read.
            true
        };
        if eof {
            self.input_done = true;
            // Queued behind any input that is still pending, so it can only
            // arrive after the last byte of the script.
            let veof = self.veof();
            self.pending.push(veof);
        }
        Ok(())
    }

    /// The EOF character the container's terminal uses right now. Terminal
    /// ioctls on a PTY master act on its slave (Linux's `tty_mode_ioctl`
    /// redirects them), so `tcgetattr(master)` reads the container's
    /// settings. Ctrl-D if unset or unreadable.
    fn veof(&self) -> u8 {
        match termios::tcgetattr(&self.master) {
            Ok(t) => match t.control_chars[SpecialCharacterIndices::VEOF as usize] {
                termios::_POSIX_VDISABLE => DEFAULT_VEOF,
                c => c,
            },
            Err(_) => DEFAULT_VEOF,
        }
    }

    /// Writes `pending` to the master for at most `WRITE_BUDGET`; whatever
    /// doesn't fit stays for the next call. Returns `false` if the container
    /// side is gone.
    fn flush_input(&mut self) -> Result<bool> {
        let deadline = Instant::now() + WRITE_BUDGET;
        while !self.pending.is_empty() {
            match nix::unistd::write(&self.master, &self.pending) {
                Ok(n) if n > 0 => {
                    self.pending.drain(..n);
                }
                Err(Errno::EINTR) => {}
                // The terminal was hung up.
                Err(Errno::EIO) => return Ok(false),
                Ok(_) | Err(Errno::EAGAIN) => {
                    // Full: the container isn't reading right now. Wait for
                    // room, but keep moving its output meanwhile, or a
                    // container blocked writing to its terminal would never
                    // get back to reading.
                    //
                    // A closed slave does *not* make the write fail: the
                    // kernel keeps accepting input until the buffer is full,
                    // then says EAGAIN. It is `poll` that tells: POLLHUP
                    // (without POLLOUT), after which `read` returns EIO.
                    let left = deadline.saturating_duration_since(Instant::now());
                    if left.is_zero() {
                        break;
                    }
                    // +1 ms: poll takes whole milliseconds, and rounding a
                    // sub-millisecond rest down to 0 would spin.
                    let timeout = PollTimeout::try_from(left + Duration::from_millis(1)).unwrap_or(PollTimeout::MAX);
                    let mut pfd = [PollFd::new(self.master.as_fd(), PollFlags::POLLIN | PollFlags::POLLOUT)];
                    match poll(&mut pfd, timeout) {
                        Ok(_) | Err(Errno::EINTR) => {}
                        Err(e) => return Err(e).context("poll the pty master"),
                    }
                    let rev = pfd[0].revents().unwrap_or(PollFlags::empty());
                    if rev.intersects(PollFlags::POLLIN | PollFlags::POLLHUP | PollFlags::POLLERR)
                        && !self.copy_output()?
                    {
                        return Ok(false);
                    }
                }
                Err(e) => return Err(e).context("write to the pty master"),
            }
        }
        Ok(true)
    }

    /// The container side is gone: write out what it said last, then report it.
    fn finish(&mut self) -> Result<bool> {
        self.pending.clear();
        self.drain()?;
        Ok(false)
    }
}

impl Drop for Relay {
    /// Puts the input terminal back the way we found it. This runs on every
    /// path that returns or unwinds, errors included. It cannot run if the
    /// process is SIGKILLed or calls `std::process::exit` while the relay is
    /// alive, so drop the relay before exiting (`reset` fixes a terminal
    /// left in raw mode).
    fn drop(&mut self) {
        if let Some(saved) = self.saved_termios.take()
            && let Err(e) = termios::tcsetattr(&self.input, SetArg::TCSANOW, &saved)
        {
            tracing::warn!(%e, "could not restore the terminal's settings");
        }
    }
}

/// Sets `O_NONBLOCK` on the open file behind `fd` (shared by all its dups).
fn set_nonblocking(fd: BorrowedFd<'_>) -> rustlet_sys::Result<()> {
    let flags = OFlag::from_bits_retain(fcntl(fd, FcntlArg::F_GETFL)?);
    fcntl(fd, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK)).map(drop)
}

/// Writes all of `data` to the relay's output: a terminal, a file or a pipe
/// (which may take only part of a write), possibly even a non-blocking one
/// that somebody else set up, hence the `EAGAIN` case.
fn write_all(fd: BorrowedFd<'_>, mut data: &[u8]) -> Result<()> {
    while !data.is_empty() {
        match nix::unistd::write(fd, data) {
            Ok(0) => return Err(Errno::EIO).context("write the container's output: no progress"),
            Ok(n) => data = &data[n..],
            Err(Errno::EINTR) => {}
            Err(Errno::EAGAIN) => {
                let mut pfd = [PollFd::new(fd, PollFlags::POLLOUT)];
                match poll(&mut pfd, PollTimeout::NONE) {
                    Ok(_) | Err(Errno::EINTR) => {}
                    Err(e) => return Err(e).context("poll the output"),
                }
            }
            Err(e) => return Err(e).context("write the container's output"),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::sys::socket::{AddressFamily, SockFlag, SockType, socketpair};
    use nix::sys::termios::{LocalFlags, cfmakeraw, tcgetattr, tcsetattr};
    use std::io::Write;
    use std::thread;

    /// Every loop in these tests gives up after this long, so a relay bug
    /// fails the test instead of hanging the whole run.
    const DEADLINE: Duration = Duration::from_secs(10);

    /// A fresh PTY pair `(master, slave)`, or `None` where there is no
    /// devpts (some CI sandboxes). Works as an ordinary user.
    fn pty() -> Option<(OwnedFd, OwnedFd)> {
        let master = term::open_ptmx(Path::new("/dev/ptmx")).ok()?;
        let slave = term::open_peer(master.as_fd()).unwrap();
        Some((master, slave))
    }

    fn pipe() -> (OwnedFd, OwnedFd) {
        nix::unistd::pipe2(OFlag::O_CLOEXEC).unwrap()
    }

    /// Raw mode on the container's slave: bytes arrive exactly as sent,
    /// immediately, without echo.
    fn make_raw(fd: BorrowedFd<'_>) {
        let mut t = tcgetattr(fd).unwrap();
        cfmakeraw(&mut t);
        tcsetattr(fd, SetArg::TCSANOW, &t).unwrap();
    }

    /// One round of the caller's loop: poll (bounded), then pump.
    fn step(relay: &mut Relay) -> bool {
        let revents: Vec<PollFlags> = {
            let fds = relay.fds();
            let mut pfds: Vec<PollFd<'_>> = fds.iter().map(|fd| PollFd::new(*fd, PollFlags::POLLIN)).collect();
            poll(&mut pfds, 50u16).unwrap();
            pfds.iter().map(|p| p.revents().unwrap_or(PollFlags::empty())).collect()
        };
        relay.pump(&revents).unwrap()
    }

    /// Reads what a non-blocking `fd` has right now; `None` means EOF.
    fn read_now(fd: BorrowedFd<'_>) -> Option<Vec<u8>> {
        let mut buf = [0u8; 4096];
        match nix::unistd::read(fd, &mut buf) {
            Ok(0) => None,
            Ok(n) => Some(buf[..n].to_vec()),
            Err(Errno::EAGAIN) => Some(Vec::new()),
            Err(e) => panic!("read: {e}"),
        }
    }

    /// Pumps `relay` and collects what arrives on the non-blocking `fd` until
    /// `want` bytes are there (or the deadline passes).
    fn pump_and_collect(relay: &mut Relay, fd: BorrowedFd<'_>, want: usize) -> Vec<u8> {
        let start = Instant::now();
        let mut got = Vec::new();
        while got.len() < want && start.elapsed() < DEADLINE {
            assert!(step(relay), "the relay stopped early");
            got.extend(read_now(fd).unwrap_or_default());
        }
        got
    }

    #[test]
    fn input_reaches_the_container() {
        let Some((master, slave)) = pty() else { return };
        make_raw(slave.as_fd());
        set_nonblocking(slave.as_fd()).unwrap();
        let (in_r, in_w) = pipe();
        let (_out_r, out_w) = pipe();
        let mut relay = Relay::with_io(master, in_r, out_w).unwrap();
        assert_eq!(relay.fds().len(), 2);
        assert_eq!(relay.poll_timeout(), PollTimeout::NONE);

        let msg = b"hello\x03world";
        nix::unistd::write(&in_w, msg).unwrap();
        assert_eq!(pump_and_collect(&mut relay, slave.as_fd(), msg.len()), msg);
    }

    #[test]
    fn output_reaches_the_caller() {
        let Some((master, slave)) = pty() else { return };
        let (in_r, _in_w) = pipe();
        let (out_r, out_w) = pipe();
        set_nonblocking(out_r.as_fd()).unwrap();
        let mut relay = Relay::with_io(master, in_r, out_w).unwrap();

        nix::unistd::write(&slave, b"from the container\n").unwrap();
        // The slave's default ONLCR turned "\n" into "\r\n"; the relay
        // passes bytes on untouched.
        let want = b"from the container\r\n";
        assert_eq!(pump_and_collect(&mut relay, out_r.as_fd(), want.len()), want);
    }

    /// Pumps until the canonical-mode `slave` reports EOF (`read` = 0);
    /// returns the lines read before it, or `None` if EOF never came.
    fn lines_until_eof(relay: &mut Relay, slave: BorrowedFd<'_>) -> Option<Vec<u8>> {
        let start = Instant::now();
        let mut lines = Vec::new();
        while start.elapsed() < DEADLINE {
            step(relay);
            match read_now(slave) {
                None => return Some(lines),
                Some(b) => lines.extend(b),
            }
        }
        None
    }

    #[test]
    fn end_of_input_becomes_veof() {
        let Some((master, slave)) = pty() else { return };
        // Canonical mode (the default): a ^D at the start of a line makes
        // read() return 0, exactly what a shell sees at the end of a script.
        set_nonblocking(slave.as_fd()).unwrap();
        let (in_r, in_w) = pipe();
        let (_out_r, out_w) = pipe(); // the slave's echo ends up here
        let mut relay = Relay::with_io(master, in_r, out_w).unwrap();

        nix::unistd::write(&in_w, b"echo hi\n").unwrap();
        drop(in_w);
        let lines = lines_until_eof(&mut relay, slave.as_fd()).expect("the slave never saw end of input");
        assert_eq!(lines, b"echo hi\n");
        assert_eq!(relay.fds().len(), 1, "input is no longer polled after EOF");
    }

    #[test]
    fn veof_is_the_containers_own() {
        let Some((master, slave)) = pty() else { return };
        // The container chose Ctrl-A as its EOF character. Sending Ctrl-D
        // would be just another byte of an unfinished line, and no EOF.
        let mut t = tcgetattr(&slave).unwrap();
        t.control_chars[SpecialCharacterIndices::VEOF as usize] = 0x01;
        tcsetattr(&slave, SetArg::TCSANOW, &t).unwrap();
        set_nonblocking(slave.as_fd()).unwrap();
        let (in_r, in_w) = pipe();
        let (_out_r, out_w) = pipe();
        let mut relay = Relay::with_io(master, in_r, out_w).unwrap();

        drop(in_w);
        let lines = lines_until_eof(&mut relay, slave.as_fd()).expect("the slave never saw end of input");
        assert!(lines.is_empty(), "{lines:?}");
    }

    #[test]
    fn closing_the_slave_ends_the_relay() {
        let Some((master, slave)) = pty() else { return };
        let (in_r, _in_w) = pipe();
        let (out_r, out_w) = pipe();
        set_nonblocking(out_r.as_fd()).unwrap();
        let mut relay = Relay::with_io(master, in_r, out_w).unwrap();

        nix::unistd::write(&slave, b"bye\n").unwrap();
        drop(slave);
        let start = Instant::now();
        let mut open = true;
        while open && start.elapsed() < DEADLINE {
            open = step(&mut relay);
        }
        assert!(!open, "pump never noticed that the slave was closed");
        // What was written before the close came out before `pump` gave up.
        assert_eq!(read_now(out_r.as_fd()).unwrap(), b"bye\r\n");
        // Draining a dead master is harmless.
        relay.drain().unwrap();
    }

    /// Input far larger than the kernel's PTY buffers, into a container that
    /// copies everything back out (like `cat`) and starts late. With
    /// blocking writes to the master this would deadlock: the relay waits
    /// for room, the container waits for the relay to read its output.
    #[test]
    fn big_transfers_do_not_deadlock() {
        let Some((master, slave)) = pty() else { return };
        make_raw(slave.as_fd());
        let (in_r, in_w) = pipe();
        let (out_r, out_w) = pipe();
        let mut relay = Relay::with_io(master, in_r, out_w).unwrap();

        let data: Vec<u8> = (0..1024 * 1024).map(|i| (i % 251) as u8).collect();
        // Raw mode has no ICANON, so the EOF character is just one more byte.
        let mut want = data.clone();
        want.push(DEFAULT_VEOF);
        let total = want.len();

        let writer = thread::spawn(move || std::fs::File::from(in_w).write_all(&data).unwrap());
        // The "container": blocking reads and writes on the slave, as a
        // real program does.
        let cat = thread::spawn(move || {
            thread::sleep(Duration::from_millis(200)); // let the master fill up
            let (mut copied, start) = (0, Instant::now());
            let mut buf = [0u8; 4096];
            while copied < total && start.elapsed() < DEADLINE {
                let mut pfd = [PollFd::new(slave.as_fd(), PollFlags::POLLIN)];
                if poll(&mut pfd, 50u16).unwrap() == 0 {
                    continue;
                }
                let n = nix::unistd::read(&slave, &mut buf).unwrap();
                std::fs::File::from(slave.try_clone().unwrap()).write_all(&buf[..n]).unwrap();
                copied += n;
            }
        });
        let reader = thread::spawn(move || {
            let (mut got, start) = (Vec::new(), Instant::now());
            let mut buf = vec![0u8; CHUNK];
            while got.len() < total && start.elapsed() < DEADLINE {
                let mut pfd = [PollFd::new(out_r.as_fd(), PollFlags::POLLIN)];
                if poll(&mut pfd, 50u16).unwrap() > 0 {
                    let n = nix::unistd::read(&out_r, &mut buf).unwrap();
                    got.extend_from_slice(&buf[..n]);
                }
            }
            got
        });

        let start = Instant::now();
        while !reader.is_finished() && start.elapsed() < DEADLINE {
            // The caller's poll timeout matters here: once input is at EOF and
            // the rest waits for room, no fd of ours becomes readable.
            let revents: Vec<PollFlags> = {
                let fds = relay.fds();
                let mut pfds: Vec<PollFd<'_>> = fds.iter().map(|fd| PollFd::new(*fd, PollFlags::POLLIN)).collect();
                let timeout = match relay.poll_timeout() {
                    PollTimeout::NONE => PollTimeout::from(50u16),
                    t => t,
                };
                poll(&mut pfds, timeout).unwrap();
                pfds.iter().map(|p| p.revents().unwrap_or(PollFlags::empty())).collect()
            };
            // `cat` closes the slave once it has copied everything; the
            // relay then flushes the rest and reports the end.
            if !relay.pump(&revents).unwrap() {
                break;
            }
        }
        // The reader gives up on its own at the deadline, so this can't hang.
        let got = reader.join().unwrap();
        writer.join().unwrap();
        cat.join().unwrap();
        assert_eq!(got.len(), total);
        assert!(got == want, "output differs from input");
    }

    #[test]
    fn resize_without_a_terminal_is_a_no_op() {
        let Some((master, slave)) = pty() else { return };
        let size = WinSize { rows: 12, cols: 34 };
        term::set_winsize(master.as_fd(), size).unwrap();
        let (in_r, _in_w) = pipe();
        let (_out_r, out_w) = pipe();
        let relay = Relay::with_io(master, in_r, out_w).unwrap();
        relay.resize().unwrap();
        assert_eq!(term::get_winsize(slave.as_fd()).unwrap(), size);
    }

    #[test]
    fn a_terminal_input_is_raw_until_drop() {
        // `user_*` plays your terminal: the relay reads keys from its slave,
        // we "type" into its master.
        let Some((user_m, user_s)) = pty() else { return };
        let Some((master, slave)) = pty() else { return };
        make_raw(slave.as_fd());
        set_nonblocking(slave.as_fd()).unwrap();
        term::set_winsize(user_m.as_fd(), WinSize { rows: 30, cols: 100 }).unwrap();
        let before = tcgetattr(&user_s).unwrap();
        assert!(before.local_flags.contains(LocalFlags::ICANON | LocalFlags::ECHO | LocalFlags::ISIG));
        let (_out_r, out_w) = pipe();

        let mut relay = Relay::with_io(master, user_s.try_clone().unwrap(), out_w).unwrap();
        let during = tcgetattr(&user_s).unwrap();
        assert!(!during.local_flags.intersects(LocalFlags::ICANON | LocalFlags::ECHO | LocalFlags::ISIG));
        // Window size copied on creation.
        assert_eq!(term::get_winsize(slave.as_fd()).unwrap(), WinSize { rows: 30, cols: 100 });

        // Keys arrive untouched. In cooked mode ^C would have been eaten
        // (ISIG) and \r turned into \n (ICRNL).
        nix::unistd::write(&user_m, b"a\x03b\r").unwrap();
        assert_eq!(pump_and_collect(&mut relay, slave.as_fd(), 4), b"a\x03b\r");

        // SIGWINCH.
        term::set_winsize(user_m.as_fd(), WinSize { rows: 40, cols: 120 }).unwrap();
        relay.resize().unwrap();
        assert_eq!(term::get_winsize(slave.as_fd()).unwrap(), WinSize { rows: 40, cols: 120 });

        drop(relay);
        let after = tcgetattr(&user_s).unwrap();
        assert_eq!(after.local_flags, before.local_flags);
        assert_eq!(after.input_flags, before.input_flags);
        assert_eq!(after.output_flags, before.output_flags);
        assert_eq!(after.control_flags, before.control_flags);
        assert_eq!(after.control_chars, before.control_chars);
    }

    #[test]
    fn master_travels_over_the_console_socket() {
        let Ok(master) = term::open_ptmx(Path::new("/dev/ptmx")) else { return };
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("console.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let init_side = connect_console_socket(&path).unwrap();
        let (receiver_side, _) = listener.accept().unwrap();

        socket::send_fds(init_side.as_fd(), CONSOLE_MSG, &[master.as_fd()]).unwrap();
        let got = receive_master(receiver_side.as_fd()).unwrap();
        // A new fd, but the same terminal.
        assert_eq!(term::pty_number(got.as_fd()).unwrap(), term::pty_number(master.as_fd()).unwrap());
    }

    #[test]
    fn receive_master_rejects_what_is_not_a_master() {
        let (a, b) = socketpair(AddressFamily::Unix, SockType::Stream, None, SockFlag::SOCK_CLOEXEC).unwrap();

        socket::send_fds(a.as_fd(), CONSOLE_MSG, &[]).unwrap();
        assert_eq!(receive_master(b.as_fd()).unwrap_err().errno(), Some(Errno::EBADMSG));

        let (r, _w) = pipe();
        socket::send_fds(a.as_fd(), CONSOLE_MSG, &[r.as_fd()]).unwrap();
        assert_eq!(receive_master(b.as_fd()).unwrap_err().errno(), Some(Errno::ENOTTY));

        drop(a);
        assert_eq!(receive_master(b.as_fd()).unwrap_err().errno(), Some(Errno::ECONNRESET));
    }
}

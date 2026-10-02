//! The shim proper: create the container, report on stdout, then serve
//! `shim.sock` until the daemon says `Shutdown`.
//!
//! Everything runs on one thread (a tokio `LocalSet`), so state is plain
//! `Cell`/`RefCell`: no request can see another one half-done except
//! across an `.await`. Requests that change the container (`Start`,
//! `Pause`, `Resume`, `Delete`) take `op_lock` around their `.await`s.
//!
//! ```text
//!  container stdout/stderr ──► pump ──┬─► container.log (one entry per line)
//!   (pipes, or the PTY master)        └─► broadcast ──► each attach stream
//!  attach streams' stdin ──► mpsc ──► stdin pump ──► the container's stdin
//!  reaper ── init exited ──► drain pumps, read memory.events, exit.json ──► Wait, attach: Exited
//! ```

use std::cell::{Cell, RefCell};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::Duration;

use bytes::Bytes;
use rustlet_runtime::oci_spec::runtime::{Process, Spec};
use rustlet_shim::logfile::{LineSplitter, LogWriter, entry, now};
use rustlet_shim::paths::ShimPaths;
use rustlet_shim::protocol::{
    CHUNK, ExecRequest, ExitStatus, Frame, Handshake, KIND_STDERR, KIND_STDOUT, Request, Response, ShimState,
    ShimStatus, decode, read_frame, write_frame,
};
use rustlet_spec::logs::LogStream;
use rustlet_sys::process::WaitResult;
use rustlet_sys::term::{WinSize, set_winsize};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Mutex, Notify, broadcast, mpsc, watch};
use tokio::task::{JoinHandle, spawn_local};

use crate::reaper::Reaper;
use crate::runc::{Runc, RuncError, Stdio3};
use crate::stdio::{ConsoleSocket, FdIo, PipeEnds, host_ids, pipes};

/// How long the shim waits, after a process exited, for the last of its
/// output (a process that inherited its stdout may hold the pipe a little
/// longer). Then the exit is reported anyway.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(2);
/// How long `create` may take to send the terminal after it has exited.
const MASTER_TIMEOUT: Duration = Duration::from_secs(5);
/// How long `Shutdown` waits for an exit that is under way.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// What `main` got on the command line.
pub struct Config {
    pub id: String,
    pub bundle: PathBuf,
    pub dir: PathBuf,
    pub runtime: PathBuf,
    pub runtime_root: PathBuf,
    pub log_path: PathBuf,
    pub log_max_size: u64,
    pub log_max_files: u32,
    pub stdin: bool,
    pub stdin_once: bool,
}

/// A chunk of a process's output: [`KIND_STDOUT`] or [`KIND_STDERR`].
#[derive(Clone, Debug)]
struct Output {
    kind: u8,
    data: Bytes,
}

enum StdinMsg {
    Data(Vec<u8>),
    Close,
}

struct Shim {
    id: String,
    paths: ShimPaths,
    runc: Runc,
    reaper: Rc<Reaper>,
    spec: Spec,
    init_pid: i32,
    state: Cell<ShimState>,
    exit: watch::Sender<Option<ExitStatus>>,
    output: broadcast::Sender<Output>,
    stdin: RefCell<Option<mpsc::Sender<StdinMsg>>>,
    stdin_once: bool,
    /// Whether the first attach with stdin has come (`stdin_once`).
    stdin_claimed: Cell<bool>,
    /// The container's terminal.
    master: Option<Rc<FdIo>>,
    op_lock: Mutex<()>,
    shutdown: Notify,
    execs: Cell<u64>,
}

/// Creates the container and serves its socket. Returns once the daemon
/// sent `Shutdown`, or with an error if the container couldn't be created
/// (after reporting that on stdout).
pub async fn run(config: Config) -> anyhow::Result<()> {
    let paths = ShimPaths::new(&config.dir);
    let reaper = Reaper::start()?;
    let prepared = prepare(&config, &paths, reaper.clone()).await;
    let (shim, listener, pumps) = match prepared {
        Ok(p) => p,
        Err(e) => {
            crate::handshake(&Handshake::Failed { message: e.message.clone(), exit_code: e.exit_code });
            anyhow::bail!("create failed: {}", e.message);
        }
    };
    tracing::info!(id = %shim.id, init = shim.init_pid, "container created");
    crate::handshake(&Handshake::Ready { init_pid: shim.init_pid, shim_pid: std::process::id() as i32 });
    spawn_local(watch_init(shim.clone(), pumps));
    loop {
        tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => {
                    spawn_local(serve(shim.clone(), stream));
                }
                Err(e) => tracing::warn!("accept on shim.sock: {e}"),
            },
            () = shim.shutdown.notified() => break,
        }
    }
    let _ = std::fs::remove_file(paths.socket());
    tracing::info!(id = %shim.id, "shutting down");
    Ok(())
}

/// Everything up to "created": the socket, the stdio, `rustlet-runc create`.
async fn prepare(
    config: &Config,
    paths: &ShimPaths,
    reaper: Rc<Reaper>,
) -> Result<(Rc<Shim>, UnixListener, Vec<JoinHandle<()>>), RuncError> {
    let fail = |message: String| RuncError { message, exit_code: None };
    let spec = Spec::load(config.bundle.join("config.json"))
        .map_err(|e| fail(format!("read {}/config.json: {e}", config.bundle.display())))?;
    let process = spec.process().clone().ok_or_else(|| fail("config.json has no process".into()))?;
    let tty = process.terminal().unwrap_or(false);
    let _ = std::fs::remove_file(paths.socket());
    let listener = UnixListener::bind(paths.socket()).map_err(|e| fail(format!("listen on shim.sock: {e}")))?;
    let logger = Rc::new(RefCell::new(
        Logger::open(&config.log_path, config.log_max_size, config.log_max_files)
            .map_err(|e| fail(format!("open {}: {e}", config.log_path.display())))?,
    ));
    let runc = Runc::new(config.runtime.clone(), config.runtime_root.clone(), paths.dir().to_owned());
    let mut args: Vec<OsString> = vec!["create".into(), "--bundle".into(), config.bundle.clone().into()];
    args.extend(["--pid-file".into(), paths.init_pid().into()]);
    let (output, _) = broadcast::channel(1024);
    let mut pumps = Vec::new();
    let mut stdin_io: Option<Rc<FdIo>> = None;
    let master = if tty {
        let console = ConsoleSocket::bind(&paths.console_socket()).map_err(|e| fail(format!("console socket: {e}")))?;
        args.extend(["--console-socket".into(), console.path().into(), config.id.clone().into()]);
        let master = create_with_terminal(&runc, &reaper, args, &console).await?;
        let master = Rc::new(FdIo::new(master).map_err(|e| fail(format!("terminal: {e}")))?);
        pumps.push(spawn_local(pump(master.clone(), LogStream::Stdout, logger.clone(), output.clone())));
        if config.stdin {
            stdin_io = Some(master.clone());
        }
        Some(master)
    } else {
        let user = process.user();
        let owner = host_ids(&spec, user.uid(), user.gid());
        let (child, ours) = pipes(config.stdin, owner).map_err(|e| fail(format!("stdio pipes: {e}")))?;
        args.push(config.id.clone().into());
        runc.run(&reaper, args, child.into_stdio()).await?;
        let PipeEnds { stdin, stdout, stderr } = ours;
        pumps.push(spawn_local(pump(Rc::new(stdout), LogStream::Stdout, logger.clone(), output.clone())));
        pumps.push(spawn_local(pump(Rc::new(stderr), LogStream::Stderr, logger.clone(), output.clone())));
        stdin_io = stdin.map(Rc::new);
        None
    };
    let init_pid = read_pid(&paths.init_pid()).map_err(fail)?;
    let stdin = stdin_io.map(|io| {
        let (tx, rx) = mpsc::channel(64);
        spawn_local(pump_stdin(io, rx));
        tx
    });
    let shim = Rc::new(Shim {
        id: config.id.clone(),
        paths: paths.clone(),
        runc,
        reaper,
        spec,
        init_pid,
        state: Cell::new(ShimState::Created),
        exit: watch::Sender::new(None),
        output,
        stdin: RefCell::new(stdin),
        stdin_once: config.stdin_once,
        stdin_claimed: Cell::new(false),
        master,
        op_lock: Mutex::new(()),
        shutdown: Notify::new(),
        execs: Cell::new(0),
    });
    Ok((shim, listener, pumps))
}

/// `create` with `--console-socket`: the master arrives while it runs.
async fn create_with_terminal(
    runc: &Runc,
    reaper: &Reaper,
    args: Vec<OsString>,
    console: &ConsoleSocket,
) -> Result<std::os::fd::OwnedFd, RuncError> {
    let create = runc.run(reaper, args, Stdio3::null());
    tokio::pin!(create);
    let receive = console.receive_master();
    tokio::pin!(receive);
    let mut master = None;
    let mut created = false;
    while !(created && master.is_some()) {
        tokio::select! {
            r = &mut create, if !created => {
                r?;
                created = true;
                if master.is_none() {
                    // It succeeded, so init sent the master already: it is
                    // in the socket, at most a moment away.
                    let m = tokio::time::timeout(MASTER_TIMEOUT, &mut receive).await.map_err(|_| RuncError {
                        message: "create succeeded but the terminal never arrived".into(),
                        exit_code: None,
                    })?;
                    master = Some(m.map_err(|e| RuncError { message: format!("receive the terminal: {e}"), exit_code: None })?);
                }
            }
            m = &mut receive, if master.is_none() => {
                master = Some(m.map_err(|e| RuncError { message: format!("receive the terminal: {e}"), exit_code: None })?);
            }
        }
    }
    Ok(master.expect("loop ends with the master"))
}

fn read_pid(path: &Path) -> Result<i32, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    text.trim().parse().map_err(|_| format!("{}: {text:?} is not a pid", path.display()))
}

/// The container's log: one splitter per stream.
struct Logger {
    writer: LogWriter,
    out: LineSplitter,
    err: LineSplitter,
    /// A write failed (disk full?): said once, then quietly retried.
    warned: bool,
}

impl Logger {
    fn open(path: &Path, max_size: u64, max_files: u32) -> std::io::Result<Logger> {
        Ok(Logger {
            writer: LogWriter::open(path, max_size, max_files)?,
            out: LineSplitter::default(),
            err: LineSplitter::default(),
            warned: false,
        })
    }

    fn push(&mut self, stream: LogStream, data: &[u8]) {
        let Logger { writer, out, err, warned } = self;
        let splitter = if stream == LogStream::Stdout { out } else { err };
        splitter.push(data, |line| write(writer, warned, stream, line));
    }

    fn flush(&mut self, stream: LogStream) {
        let Logger { writer, out, err, warned } = self;
        let splitter = if stream == LogStream::Stdout { out } else { err };
        splitter.flush(|line| write(writer, warned, stream, line));
    }
}

fn write(writer: &mut LogWriter, warned: &mut bool, stream: LogStream, line: &[u8]) {
    if let Err(e) = writer.write(&entry(stream, line))
        && !*warned
    {
        tracing::warn!("writing the container log: {e}");
        *warned = true;
    }
}

/// Copies one output stream of the container into the log and to the
/// attached clients, until it ends.
async fn pump(io: Rc<FdIo>, stream: LogStream, logger: Rc<RefCell<Logger>>, out: broadcast::Sender<Output>) {
    let kind = if stream == LogStream::Stdout { KIND_STDOUT } else { KIND_STDERR };
    let mut buf = vec![0u8; CHUNK];
    loop {
        match io.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                logger.borrow_mut().push(stream, &buf[..n]);
                // No receivers (nobody attached) is fine.
                let _ = out.send(Output { kind, data: Bytes::copy_from_slice(&buf[..n]) });
            }
            Err(e) => {
                tracing::warn!("reading the container's {stream:?}: {e}");
                break;
            }
        }
    }
    logger.borrow_mut().flush(stream);
}

/// Writes what attach clients send into the container's stdin, until it is
/// closed. Dropping `io` closes a pipe's write end (the container sees EOF);
/// a terminal's master stays open, since the output pump holds it too.
async fn pump_stdin(io: Rc<FdIo>, mut rx: mpsc::Receiver<StdinMsg>) {
    while let Some(msg) = rx.recv().await {
        match msg {
            StdinMsg::Data(data) => {
                if let Err(e) = io.write_all(&data).await {
                    tracing::debug!("the container's stdin: {e}");
                    break;
                }
            }
            StdinMsg::Close => break,
        }
    }
}

/// Waits for init to exit, then reports it once its output is in.
async fn watch_init(shim: Rc<Shim>, pumps: Vec<JoinHandle<()>>) {
    let status = match shim.reaper.watch(shim.init_pid).await {
        Ok(s) => s,
        Err(_) => return,
    };
    let _ = tokio::time::timeout(DRAIN_TIMEOUT, async {
        for p in pumps {
            let _ = p.await;
        }
    })
    .await;
    let exit = ExitStatus {
        code: status.exit_code().unwrap_or(255),
        signal: match status {
            WaitResult::Signaled { signal, .. } => Some(signal),
            _ => None,
        },
        oom_killed: oom_killed(&shim.spec),
        finished_at: now(),
    };
    tracing::info!(id = %shim.id, code = exit.code, oom = exit.oom_killed, "container exited");
    if let Err(e) = write_atomic(&shim.paths.exit_json(), &serde_json::to_vec(&exit).expect("serializes")) {
        tracing::warn!("write exit.json: {e}");
    }
    shim.state.set(ShimState::Exited);
    // No more input can matter.
    shim.stdin.borrow_mut().take();
    shim.exit.send_replace(Some(exit));
}

/// Did the kernel OOM-kill something in the container's cgroup? It is the
/// container's own cgroup, made for this run, so any `oom_kill` counts.
fn oom_killed(spec: &Spec) -> bool {
    let Some(path) = spec.linux().as_ref().and_then(|l| l.cgroups_path().clone()) else { return false };
    let file = Path::new("/sys/fs/cgroup").join(path.strip_prefix("/").unwrap_or(&path)).join("memory.events");
    std::fs::read_to_string(file).is_ok_and(|text| {
        text.lines().any(|l| l.strip_prefix("oom_kill ").and_then(|n| n.trim().parse::<u64>().ok()).unwrap_or(0) > 0)
    })
}

fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)
}

impl Shim {
    fn status(&self) -> ShimStatus {
        ShimStatus {
            id: self.id.clone(),
            shim_pid: std::process::id() as i32,
            init_pid: self.init_pid,
            state: self.state.get(),
            exit: self.exit.borrow().clone(),
        }
    }

    fn exited(&self) -> bool {
        self.exit.borrow().is_some()
    }

    async fn send_stdin(&self, data: Vec<u8>) {
        let tx = self.stdin.borrow().clone();
        if let Some(tx) = tx {
            let _ = tx.send(StdinMsg::Data(data)).await;
        }
    }

    fn close_stdin(&self) {
        // A terminal has no "end of input" to send; the client types
        // Ctrl-D itself. Only a pipe is closed.
        if self.master.is_some() {
            return;
        }
        if let Some(tx) = self.stdin.borrow_mut().take() {
            spawn_local(async move {
                let _ = tx.send(StdinMsg::Close).await;
            });
        }
    }

    fn resize(&self, rows: u16, cols: u16) -> Result<(), String> {
        let master = self.master.as_ref().ok_or("the container has no terminal")?;
        set_winsize(master.fd(), WinSize { rows, cols }).map_err(|e| format!("resize the terminal: {e}"))
    }

    async fn runc(&self, args: Vec<OsString>) -> Response {
        match self.runc.run(&self.reaper, args, Stdio3::null()).await {
            Ok(()) => Response::Ok,
            Err(e) => Response::Error { message: e.message, exit_code: e.exit_code },
        }
    }
}

fn error(message: impl Into<String>) -> Response {
    Response::Error { message: message.into(), exit_code: None }
}

/// One connection: a request, its response, and for attach and exec the
/// stream that follows.
async fn serve(shim: Rc<Shim>, stream: UnixStream) {
    let (mut r, mut w) = stream.into_split();
    let request = match read_frame(&mut r).await {
        Ok(Some(Frame::Message(json))) => match decode::<Request>(&json) {
            Ok(req) => req,
            Err(e) => {
                let _ = write_frame(&mut w, &Frame::response(&error(format!("bad request: {e}")))).await;
                return;
            }
        },
        _ => return,
    };
    tracing::debug!(?request, "request");
    let id: OsString = shim.id.clone().into();
    let response = match request {
        Request::Status => Response::Status(shim.status()),
        Request::Start => {
            let _op = shim.op_lock.lock().await;
            if shim.state.get() != ShimState::Created || shim.exited() {
                error(format!("cannot start: the container is {:?}", shim.state.get()).to_lowercase())
            } else {
                let r = shim.runc(vec!["start".into(), id]).await;
                if r == Response::Ok && !shim.exited() {
                    shim.state.set(ShimState::Running);
                }
                r
            }
        }
        Request::Kill { signal, all } => {
            let mut args: Vec<OsString> = vec!["kill".into()];
            if all {
                args.push("--all".into());
            }
            args.extend([id, signal.to_string().into()]);
            shim.runc(args).await
        }
        Request::Pause | Request::Resume => {
            let _op = shim.op_lock.lock().await;
            let pause = request == Request::Pause;
            let r = shim.runc(vec![if pause { "pause" } else { "resume" }.into(), id]).await;
            if r == Response::Ok && !shim.exited() {
                shim.state.set(if pause { ShimState::Paused } else { ShimState::Running });
            }
            r
        }
        Request::Wait => {
            let mut rx = shim.exit.subscribe();
            match rx.wait_for(Option::is_some).await {
                Ok(exit) => Response::Exited(exit.clone().expect("waited for Some")),
                Err(_) => return,
            }
        }
        Request::Attach { stdin } => return attach(shim, r, w, stdin).await,
        Request::Exec(req) => return exec(shim, req, r, w).await,
        Request::Resize { rows, cols } => match shim.resize(rows, cols) {
            Ok(()) => Response::Ok,
            Err(e) => error(e),
        },
        Request::CloseStdin => {
            shim.close_stdin();
            Response::Ok
        }
        Request::Delete { force } => {
            let _op = shim.op_lock.lock().await;
            let mut args: Vec<OsString> = vec!["delete".into()];
            if force {
                args.push("--force".into());
            }
            args.push(id);
            shim.runc(args).await
        }
        Request::Shutdown => {
            // Right after a forced delete, init may not be reaped yet: give
            // its exit a moment to arrive.
            let mut rx = shim.exit.subscribe();
            let _ = tokio::time::timeout(SHUTDOWN_GRACE, rx.wait_for(Option::is_some)).await;
            if !shim.exited() {
                error("the container is still running (delete it first)")
            } else {
                let _ = write_frame(&mut w, &Frame::response(&Response::Ok)).await;
                shim.shutdown.notify_one();
                return;
            }
        }
    };
    let _ = write_frame(&mut w, &Frame::response(&response)).await;
}

/// `Attach`: the container's output from now on; its input, with `stdin`.
async fn attach(shim: Rc<Shim>, mut r: OwnedReadHalf, mut w: OwnedWriteHalf, stdin: bool) {
    // Subscribe before answering: whatever the container prints after the
    // daemon sees `Ok` reaches it.
    let mut out = shim.output.subscribe();
    let mut exit = shim.exit.subscribe();
    if write_frame(&mut w, &Frame::response(&Response::Ok)).await.is_err() {
        return;
    }
    let once = stdin && shim.stdin_once && !shim.stdin_claimed.replace(true);
    let writer = spawn_local(async move {
        loop {
            tokio::select! {
                biased;
                o = out.recv() => match o {
                    Ok(o) => {
                        if write_frame(&mut w, &output_frame(&o)).await.is_err() {
                            return;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!("an attach client fell behind; {n} chunks of output dropped for it");
                    }
                    Err(broadcast::error::RecvError::Closed) => return,
                },
                done = exit.wait_for(Option::is_some) => {
                    let status = match done {
                        Ok(s) => s.clone().expect("waited for Some"),
                        Err(_) => return,
                    };
                    // All output was sent before the exit was published.
                    while let Ok(o) = out.try_recv() {
                        if write_frame(&mut w, &output_frame(&o)).await.is_err() {
                            return;
                        }
                    }
                    let _ = write_frame(&mut w, &Frame::response(&Response::Exited(status))).await;
                    return;
                }
            }
        }
    });
    loop {
        match read_frame(&mut r).await {
            Ok(Some(Frame::Stdin(data))) if stdin => shim.send_stdin(data).await,
            Ok(Some(Frame::Message(json))) => match decode::<Request>(&json) {
                Ok(Request::Resize { rows, cols }) => {
                    if let Err(e) = shim.resize(rows, cols) {
                        tracing::debug!("{e}");
                    }
                }
                Ok(Request::CloseStdin) if once => shim.close_stdin(),
                _ => {}
            },
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => break,
        }
    }
    // The first stdin client is gone: with stdin_once, so is the input.
    if once {
        shim.close_stdin();
    }
    // The daemon went away (or sent everything after the exit).
    writer.abort();
}

fn output_frame(o: &Output) -> Frame {
    if o.kind == KIND_STDOUT { Frame::Stdout(o.data.to_vec()) } else { Frame::Stderr(o.data.to_vec()) }
}

/// The container's `process`, changed for an exec.
fn exec_process(spec: &Spec, req: &ExecRequest) -> Result<Process, String> {
    let mut p = spec.process().clone().ok_or("config.json has no process")?;
    if req.args.is_empty() {
        return Err("exec needs a command".into());
    }
    p.set_args(Some(req.args.clone()));
    p.set_terminal(Some(req.tty));
    p.set_console_size(None);
    let mut env = p.env().clone().unwrap_or_default();
    for kv in &req.env {
        let key = kv.split_once('=').map_or(kv.as_str(), |(k, _)| k);
        env.retain(|e| e.split_once('=').map_or(e.as_str(), |(k, _)| k) != key);
        env.push(kv.clone());
    }
    p.set_env(Some(env));
    if let Some(cwd) = &req.cwd {
        p.set_cwd(cwd.into());
    }
    if let Some(u) = &req.user {
        let mut user = p.user().clone();
        user.set_uid(u.uid);
        user.set_gid(u.gid);
        user.set_additional_gids(Some(u.additional_gids.clone()));
        user.set_umask(None);
        p.set_user(user);
    }
    Ok(p)
}

/// `Exec`: `rustlet-runc exec -d` with stdio of its own, then the stream
/// until the process exits. The process is re-parented to the shim when
/// `rustlet-runc` exits, so the reaper gets its status.
async fn exec(shim: Rc<Shim>, req: ExecRequest, mut r: OwnedReadHalf, mut w: OwnedWriteHalf) {
    let respond = |resp: Response| Frame::response(&resp);
    if shim.exited() || shim.state.get() == ShimState::Created {
        let _ = write_frame(&mut w, &respond(error("the container is not running"))).await;
        return;
    }
    let process = match exec_process(&shim.spec, &req) {
        Ok(p) => p,
        Err(e) => {
            let _ = write_frame(&mut w, &respond(error(e))).await;
            return;
        }
    };
    let n = shim.execs.get();
    shim.execs.set(n + 1);
    let json = shim.paths.dir().join(format!("x{n}.json"));
    let pid_file = shim.paths.exec_pid(n);
    if let Err(e) = std::fs::write(&json, serde_json::to_vec(&process).expect("serializes")) {
        let _ = write_frame(&mut w, &respond(error(format!("write {}: {e}", json.display())))).await;
        return;
    }
    let mut args: Vec<OsString> = vec!["exec".into(), "--detach".into(), "--pid-file".into(), pid_file.clone().into()];
    args.extend(["--process".into(), json.clone().into()]);
    let started = if req.tty {
        start_exec_tty(&shim, n, args).await
    } else {
        let user = process.user();
        let owner = host_ids(&shim.spec, user.uid(), user.gid());
        start_exec_pipes(&shim, args, req.stdin, owner).await
    };
    let _ = std::fs::remove_file(&json);
    let (io, stdin, out_pumps) = match started {
        Ok(s) => s,
        Err(e) => {
            let _ = std::fs::remove_file(&pid_file);
            let _ = write_frame(&mut w, &respond(Response::Error { message: e.message, exit_code: e.exit_code })).await;
            return;
        }
    };
    // Input only if the client asked to send some.
    let stdin = if req.stdin { stdin } else { None };
    let pid = match read_pid(&pid_file) {
        Ok(p) => p,
        Err(e) => {
            let _ = write_frame(&mut w, &respond(error(e))).await;
            return;
        }
    };
    let _ = std::fs::remove_file(&pid_file);
    let exited = shim.reaper.watch(pid);
    tracing::info!(id = %shim.id, exec = %req.exec_id, pid, "exec started");
    let (frames_tx, mut frames_rx) = mpsc::channel::<Frame>(64);
    if write_frame(&mut w, &respond(Response::Started { pid })).await.is_err() {
        // Keep draining its output anyway, below.
    }
    // Output: the pumps forward frames; the writer sends them on, and once
    // the connection is gone, keeps reading so the process never blocks on
    // a full pipe.
    let pumps: Vec<JoinHandle<()>> = out_pumps
        .into_iter()
        .map(|(fd, kind)| {
            let tx = frames_tx.clone();
            spawn_local(async move {
                let mut buf = vec![0u8; CHUNK];
                loop {
                    match fd.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            let data = buf[..n].to_vec();
                            let frame = if kind == KIND_STDOUT { Frame::Stdout(data) } else { Frame::Stderr(data) };
                            if tx.send(frame).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            })
        })
        .collect();
    let exec_id = req.exec_id.clone();
    let id = shim.id.clone();
    spawn_local(async move {
        let status = exited.await.unwrap_or(WaitResult::Signaled {
            pid: nix::unistd::Pid::from_raw(pid),
            signal: 9,
            core_dumped: false,
        });
        let _ = tokio::time::timeout(DRAIN_TIMEOUT, async {
            for p in pumps {
                let _ = p.await;
            }
        })
        .await;
        let exit = ExitStatus {
            code: status.exit_code().unwrap_or(255),
            signal: match status {
                WaitResult::Signaled { signal, .. } => Some(signal),
                _ => None,
            },
            oom_killed: false,
            finished_at: now(),
        };
        tracing::info!(%id, exec = %exec_id, code = exit.code, "exec exited");
        let _ = frames_tx.send(Frame::response(&Response::Exited(exit))).await;
    });
    let writer = spawn_local(async move {
        let mut connected = true;
        while let Some(frame) = frames_rx.recv().await {
            let last = matches!(frame, Frame::Message(_));
            if connected && write_frame(&mut w, &frame).await.is_err() {
                connected = false;
            }
            if last {
                break;
            }
        }
    });
    let stdin = RefCell::new(stdin);
    loop {
        match read_frame(&mut r).await {
            Ok(Some(Frame::Stdin(data))) => {
                let target = stdin.borrow().clone();
                if let Some(s) = target
                    && let Err(e) = s.write_all(&data).await
                {
                    tracing::debug!("exec stdin: {e}");
                    stdin.borrow_mut().take();
                }
            }
            Ok(Some(Frame::Message(json))) => match decode::<Request>(&json) {
                Ok(Request::Resize { rows, cols }) => {
                    if let Some(m) = io.as_ref()
                        && let Err(e) = set_winsize(m.fd(), WinSize { rows, cols })
                    {
                        tracing::debug!("resize exec terminal: {e}");
                    }
                }
                // A pipe is closed by dropping our end; a terminal's input
                // ends with the Ctrl-D the client types.
                Ok(Request::CloseStdin) if io.is_none() => {
                    stdin.borrow_mut().take();
                }
                _ => {}
            },
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => break,
        }
    }
    drop(stdin);
    // The writer finishes with the exit (the process keeps running, and its
    // output is drained, if the daemon hung up first).
    let _ = writer.await;
}

type ExecIo = (Option<Rc<FdIo>>, Option<Rc<FdIo>>, Vec<(Rc<FdIo>, u8)>);

/// `exec -d` with three pipes: (no terminal, stdin, output pumps).
async fn start_exec_pipes(
    shim: &Shim,
    args: Vec<OsString>,
    stdin: bool,
    owner: (u32, u32),
) -> Result<ExecIo, RuncError> {
    let (child, ours) =
        pipes(stdin, owner).map_err(|e| RuncError { message: format!("stdio pipes: {e}"), exit_code: None })?;
    let mut args = args;
    args.push(shim.id.clone().into());
    shim.runc.run(&shim.reaper, args, child.into_stdio()).await?;
    let PipeEnds { stdin, stdout, stderr } = ours;
    Ok((None, stdin.map(Rc::new), vec![(Rc::new(stdout), KIND_STDOUT), (Rc::new(stderr), KIND_STDERR)]))
}

/// `exec -d -t`: the terminal arrives on a console socket of its own.
async fn start_exec_tty(shim: &Shim, n: u64, args: Vec<OsString>) -> Result<ExecIo, RuncError> {
    let console = ConsoleSocket::bind(&shim.paths.exec_console_socket(n))
        .map_err(|e| RuncError { message: format!("console socket: {e}"), exit_code: None })?;
    let mut args = args;
    args.extend(["--tty".into(), "--console-socket".into(), console.path().into(), shim.id.clone().into()]);
    let master = create_with_terminal(&shim.runc, &shim.reaper, args, &console).await?;
    let master =
        Rc::new(FdIo::new(master).map_err(|e| RuncError { message: format!("terminal: {e}"), exit_code: None })?);
    Ok((Some(master.clone()), Some(master.clone()), vec![(master, KIND_STDOUT)]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustlet_runtime::spec::default_spec;
    use rustlet_shim::protocol::ExecUser;

    #[test]
    fn exec_processes_start_from_the_containers() {
        let spec = default_spec();
        let req = ExecRequest {
            args: vec!["id".into()],
            env: vec!["PATH=/bin".into(), "NEW=1".into()],
            cwd: Some("/tmp".into()),
            user: Some(ExecUser { uid: 101, gid: 102, additional_gids: vec![102, 5] }),
            tty: true,
            ..Default::default()
        };
        let p = exec_process(&spec, &req).unwrap();
        assert_eq!(p.args().as_deref().unwrap(), ["id"]);
        let env = p.env().clone().unwrap();
        assert_eq!(env.iter().filter(|e| e.starts_with("PATH=")).collect::<Vec<_>>(), ["PATH=/bin"]);
        assert!(env.contains(&"NEW=1".to_string()));
        assert_eq!(p.cwd(), Path::new("/tmp"));
        assert_eq!((p.user().uid(), p.user().gid()), (101, 102));
        assert_eq!(p.user().additional_gids().as_deref().unwrap(), [102, 5]);
        assert_eq!(p.terminal(), Some(true));
        // Capabilities, rlimits and NNP stay the container's.
        assert_eq!(p.capabilities(), spec.process().as_ref().unwrap().capabilities());
        assert!(exec_process(&spec, &ExecRequest::default()).is_err());
    }
}

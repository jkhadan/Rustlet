//! `rustlet exec`: another process in a running container, through its
//! shim (which runs `rustlet-runc exec -d` and reaps the process).
//!
//! Two steps, as in Docker: create (checks the request, resolves the user
//! in the container's own `/etc/passwd`, returns an id), then start,
//! attached over a WebSocket or detached. Sessions that never start are
//! forgotten after a minute; finished ones after ten.

use std::os::fd::AsFd;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::ws::WebSocket;
use futures::StreamExt;
use rustlet_shim::client::{ShimClient, ShimStream, StreamEvent};
use rustlet_shim::protocol::{ExecRequest, ExecUser, Request, Response};
use rustlet_spec::container::ContainerStatus;
use rustlet_spec::exec::{ExecConfig, ExecCreated, ExecInspect, ExecStarted};
use rustlet_spec::stream::Control;

use crate::container::Container;
use crate::daemon::Daemon;
use crate::error::{ApiError, ApiResult};

const UNSTARTED_TTL: Duration = Duration::from_secs(60);
const FINISHED_TTL: Duration = Duration::from_secs(600);

pub struct ExecSession {
    pub id: String,
    pub container: Arc<Container>,
    pub config: ExecConfig,
    user: Option<ExecUser>,
    created: Instant,
    state: Mutex<ExecState>,
}

#[derive(Debug, Default, Clone)]
struct ExecState {
    started: bool,
    running: bool,
    pid: Option<i32>,
    exit_code: Option<i32>,
    finished: Option<Instant>,
}

impl ExecSession {
    pub fn inspect(&self) -> ExecInspect {
        let s = self.state.lock().unwrap_or_else(|e| e.into_inner()).clone();
        ExecInspect {
            id: self.id.clone(),
            container_id: self.container.id().to_owned(),
            config: self.config.clone(),
            running: s.running,
            pid: s.pid,
            exit_code: s.exit_code,
        }
    }

    fn finish(&self, code: Option<i32>) {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        s.running = false;
        s.exit_code = code;
        s.finished = Some(Instant::now());
    }
}

impl Daemon {
    pub fn create_exec(&self, c: Arc<Container>, config: ExecConfig) -> ApiResult<ExecCreated> {
        if c.status() != ContainerStatus::Running {
            return Err(ApiError::conflict(format!("container {} is {}, not running", c.record.name, c.status())));
        }
        if config.cmd.is_empty() || config.cmd[0].is_empty() {
            return Err(ApiError::invalid("exec needs a command"));
        }
        let user = match &config.user {
            Some(u) if !u.is_empty() => {
                let rootfs = self.paths.container_dir(c.id()).join("rootfs");
                let fd = nix::fcntl::open(
                    &rootfs,
                    nix::fcntl::OFlag::O_PATH | nix::fcntl::OFlag::O_DIRECTORY | nix::fcntl::OFlag::O_CLOEXEC,
                    nix::sys::stat::Mode::empty(),
                )
                .map_err(|e| ApiError::internal(format!("open {}: {e}", rootfs.display())))?;
                let r = rustlet_image::user::resolve(fd.as_fd(), Some(u))?;
                Some(ExecUser { uid: r.uid, gid: r.gid, additional_gids: r.additional_gids })
            }
            _ => None,
        };
        let id = crate::names::new_id(|_| false);
        let session = Arc::new(ExecSession {
            id: id.clone(),
            container: c.clone(),
            config,
            user,
            created: Instant::now(),
            state: Mutex::new(ExecState::default()),
        });
        let mut execs = self.execs.lock().unwrap_or_else(|e| e.into_inner());
        execs.retain(|_, s| {
            let st = s.state.lock().unwrap_or_else(|e| e.into_inner());
            match st.finished {
                Some(t) => t.elapsed() < FINISHED_TTL,
                None => st.started || s.created.elapsed() < UNSTARTED_TTL,
            }
        });
        execs.insert(id.clone(), session);
        self.events.emit(
            rustlet_spec::event::EventKind::Container,
            "exec_create",
            c.id(),
            [("exec_id".to_owned(), id.clone()), ("name".to_owned(), c.record.name.clone())].into(),
        );
        Ok(ExecCreated { id })
    }

    pub fn find_exec(&self, id: &str) -> ApiResult<Arc<ExecSession>> {
        self.execs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(id)
            .cloned()
            .ok_or_else(|| ApiError::new(rustlet_spec::ErrorKind::NoSuchExec, format!("no such exec: {id}")))
    }

    /// Starts the process; it runs once.
    async fn open_exec(&self, s: &ExecSession) -> ApiResult<(i32, ShimStream)> {
        {
            let mut st = s.state.lock().unwrap_or_else(|e| e.into_inner());
            if st.started {
                return Err(ApiError::conflict(format!("exec {} has been started already", s.id)));
            }
            st.started = true;
        }
        let c = &s.container;
        if c.status() != ContainerStatus::Running {
            return Err(ApiError::conflict(format!("container {} is {}, not running", c.record.name, c.status())));
        }
        let request = Request::Exec(ExecRequest {
            exec_id: s.id.clone(),
            args: s.config.cmd.clone(),
            env: s.config.env.clone(),
            cwd: s.config.workdir.clone().filter(|w| !w.is_empty()),
            user: s.user.clone(),
            tty: s.config.tty,
            stdin: s.config.stdin,
            console_size: s.config.console_size,
            kill_on_disconnect: false,
        });
        let socket = self.paths.shim(c.id()).socket();
        let client =
            ShimClient::connect(&socket).await.map_err(|e| ApiError::internal(format!("the container's shim: {e}")))?;
        match client.open_stream(&request).await {
            Ok((Response::Started { pid }, Some(stream))) => {
                let mut st = s.state.lock().unwrap_or_else(|e| e.into_inner());
                st.running = true;
                st.pid = Some(pid);
                drop(st);
                self.events.emit(
                    rustlet_spec::event::EventKind::Container,
                    "exec_start",
                    c.id(),
                    [("exec_id".to_owned(), s.id.clone()), ("name".to_owned(), c.record.name.clone())].into(),
                );
                Ok((pid, stream))
            }
            Ok((Response::Error { message, exit_code }, _)) => {
                s.finish(exit_code);
                Err(ApiError::runtime(message, exit_code))
            }
            Ok((other, _)) => Err(ApiError::internal(format!("exec: the shim said {other:?}"))),
            Err(e) => Err(ApiError::internal(format!("exec: {e}"))),
        }
    }

    fn exec_died(&self, s: &ExecSession, code: Option<i32>) {
        s.finish(code);
        let mut attrs: std::collections::BTreeMap<String, String> =
            [("exec_id".to_owned(), s.id.clone()), ("name".to_owned(), s.container.record.name.clone())].into();
        if let Some(code) = code {
            attrs.insert("exit_code".into(), code.to_string());
        }
        self.events.emit(rustlet_spec::event::EventKind::Container, "exec_die", s.container.id(), attrs);
    }

    pub async fn start_exec_detached(self: &Arc<Self>, s: Arc<ExecSession>) -> ApiResult<ExecStarted> {
        let (pid, mut stream) = self.open_exec(&s).await?;
        // Nobody will send it input.
        let _ = stream.writer().close_stdin().await;
        let d = self.clone();
        tokio::spawn(async move {
            // Nobody reads the output; the exit status still counts.
            let mut code = None;
            while let Ok(Some(ev)) = stream.recv().await {
                if let StreamEvent::Exited(e) = ev {
                    code = Some(e.code);
                    break;
                }
            }
            d.exec_died(&s, code);
        });
        Ok(ExecStarted { pid })
    }

    /// `GET /v1/exec/{id}/start`, once upgraded.
    pub async fn run_exec_attached(self: Arc<Self>, s: Arc<ExecSession>, ws: WebSocket) {
        match self.open_exec(&s).await {
            Ok((_, stream)) => {
                let (sink, source) = ws.split();
                // Recorded before the client hears of it, so an inspect
                // right after sees the exit code.
                let recorded = async |exit: &rustlet_shim::protocol::ExitStatus| self.exec_died(&s, Some(exit.code));
                // A client that detaches leaves the process running; its
                // exit isn't seen here then.
                crate::attach::bridge(sink, source, stream, s.config.stdin, crate::attach::Peer::Exec, recorded).await;
            }
            Err(e) => {
                let (mut sink, _) = ws.split();
                use futures::SinkExt;
                let msg = serde_json::to_string(&Control::Error { message: e.message.clone(), kind: e.kind })
                    .expect("serializes");
                let _ = sink.send(axum::extract::ws::Message::Text(msg.into())).await;
                let _ = sink.close().await;
            }
        }
    }
}

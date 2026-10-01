//! Driving `rustlet-shim` directly, as the daemon does: spawn it for a
//! bundle, read its handshake, then talk to it over `shim.sock`.

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use rustlet_runtime::oci_spec::runtime::Spec;
use rustlet_shim::client::{ShimClient, ShimStream, StreamEvent};
use rustlet_shim::paths::ShimPaths;
use rustlet_shim::protocol::{ExitStatus, Handshake, Request, Response};

use crate::{TestBundle, itest_scope, runc_binary, runtime_root, workspace_binary};

/// A shim for one container, and its files.
pub struct TestShim {
    pub bundle: TestBundle,
    pub paths: ShimPaths,
    pub log: PathBuf,
    pub handshake: Handshake,
    child: Child,
    _scratch: tempfile::TempDir,
}

/// What an attach or exec stream delivered.
#[derive(Debug, Default)]
pub struct Collected {
    pub stdout: String,
    pub stderr: String,
    pub exit: Option<ExitStatus>,
}

impl TestShim {
    /// Starts a shim for `spec` (which should have a cgroup) and waits for
    /// its handshake. `stdin`: keep a stdin for attach clients.
    pub fn start(spec: &Spec, stdin: bool, stdin_once: bool) -> TestShim {
        itest_scope();
        let bundle = TestBundle::new(spec);
        let scratch = tempfile::Builder::new().prefix("rustlet-itest-shim-").tempdir().unwrap();
        let paths = ShimPaths::new(runtime_root().join("shims").join(&bundle.id));
        std::fs::create_dir_all(paths.dir()).unwrap();
        let shims_cgroup = format!("{}/shims", itest_scope());
        let _ = std::fs::create_dir(format!("/sys/fs/cgroup{shims_cgroup}"));
        let log = scratch.path().join("container.log");
        let args = rustlet_shim::ShimArgs {
            id: bundle.id.clone(),
            bundle: bundle.dir.path().to_owned(),
            dir: paths.dir().to_owned(),
            runtime: runc_binary(),
            runtime_root: runtime_root(),
            cgroup: Some(shims_cgroup),
            log_path: log.clone(),
            log_max_size: rustlet_shim::DEFAULT_LOG_MAX_SIZE,
            log_max_files: rustlet_shim::DEFAULT_LOG_MAX_FILES,
            stdin,
            stdin_once,
        };
        let shim_log = std::fs::File::create(paths.shim_log()).unwrap();
        let mut child = Command::new(workspace_binary("rustlet-shim"))
            .args(args.to_args())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(shim_log)
            .spawn()
            .unwrap();
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap()).read_line(&mut line).unwrap();
        let handshake: Handshake = serde_json::from_str(&line)
            .unwrap_or_else(|e| panic!("bad handshake {line:?} ({e}); shim.log: {}", shim_log_text(paths.dir())));
        TestShim { bundle, paths, log, handshake, child, _scratch: scratch }
    }

    pub fn shim_log(&self) -> String {
        shim_log_text(self.paths.dir())
    }

    pub async fn call(&self, request: Request) -> Response {
        let mut c = ShimClient::connect(&self.paths.socket()).await.unwrap();
        c.call(&request).await.unwrap()
    }

    pub async fn ok(&self, request: Request) {
        let r = self.call(request.clone()).await;
        assert_eq!(r, Response::Ok, "{request:?}: {r:?}; shim.log: {}", self.shim_log());
    }

    /// Opens an attach (or exec) stream.
    pub async fn stream(&self, request: Request) -> (Response, Option<ShimStream>) {
        ShimClient::connect(&self.paths.socket()).await.unwrap().open_stream(&request).await.unwrap()
    }

    /// The log file's entries as `(stream, text)`.
    pub fn log_entries(&self) -> Vec<(String, String)> {
        std::fs::read_to_string(&self.log)
            .unwrap_or_default()
            .lines()
            .map(|l| {
                let v: serde_json::Value = serde_json::from_str(l).unwrap();
                (v["stream"].as_str().unwrap().to_owned(), v["log"].as_str().unwrap().to_owned())
            })
            .collect()
    }

    /// Delete + Shutdown, then waits for the shim to exit.
    pub async fn finish(mut self) {
        self.ok(Request::Delete { force: true }).await;
        self.ok(Request::Shutdown).await;
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            if self.child.try_wait().unwrap().is_some() {
                break;
            }
            assert!(std::time::Instant::now() < deadline, "the shim didn't exit after Shutdown");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(!runtime_root().join(&self.bundle.id).exists(), "the runtime state is still there");
    }
}

impl Drop for TestShim {
    fn drop(&mut self) {
        if let Ok(None) = self.child.try_wait() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        let _ =
            crate::runc(&["delete", "--force", &self.bundle.id]).stdout(Stdio::null()).stderr(Stdio::null()).status();
        let _ = std::fs::remove_dir_all(self.paths.dir());
        // `shims/` itself, once the last test's shim is gone.
        if let Some(parent) = self.paths.dir().parent() {
            let _ = std::fs::remove_dir(parent);
        }
    }
}

fn shim_log_text(dir: &Path) -> String {
    std::fs::read_to_string(dir.join("shim.log")).unwrap_or_default()
}

/// Reads a stream to its end (the exit), with a timeout.
pub async fn collect(stream: &mut ShimStream) -> Collected {
    let mut c = Collected::default();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let ev = tokio::time::timeout_at(deadline, stream.recv()).await.expect("the stream never ended");
        match ev.unwrap() {
            Some(StreamEvent::Stdout(b)) => c.stdout.push_str(&String::from_utf8_lossy(&b)),
            Some(StreamEvent::Stderr(b)) => c.stderr.push_str(&String::from_utf8_lossy(&b)),
            Some(StreamEvent::Exited(s)) => {
                c.exit = Some(s);
                return c;
            }
            None => return c,
        }
    }
}

/// A current-thread runtime for one test.
pub fn block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(f)
}

//! A `rustletd` of a test's own: its own socket, data root (a temp dir),
//! run root (under /run/rustlet, so `scripts/cleanup.sh` sweeps it), cgroup
//! parent (inside the itest scope) and network: it runs in a "host" network
//! namespace of its own, beside a "LAN" one (`crate::net::TestLan`), so its
//! bridges, firewall table and `ip_forward` never touch the real host's.
//! Its containers' resolver is the LAN machine, 192.0.2.1. Dropping it
//! kills everything the daemon started, unmounts what it mounted and
//! removes its directories.

use std::fs::OpenOptions;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use rustlet_client::Client;
use rustlet_image::Store;
use rustlet_image::import::{config, import};

use crate::images::alpine_layer;
use crate::net::TestLan;
use crate::{itest_scope, workspace_binary};

pub struct TestDaemon {
    pub data: PathBuf,
    pub run: PathBuf,
    pub socket: PathBuf,
    pub cgroup_parent: String,
    /// The daemon's "host" network namespace and the LAN beside it.
    pub net: TestLan,
    config: PathBuf,
    log: PathBuf,
    child: Option<Child>,
    _dir: tempfile::TempDir,
}

impl TestDaemon {
    /// A daemon on fresh, empty directories, ready to answer.
    pub fn start() -> TestDaemon {
        static N: AtomicU32 = AtomicU32::new(0);
        let scope = itest_scope();
        let n = N.fetch_add(1, Ordering::Relaxed);
        let dir = tempfile::Builder::new().prefix("rustlet-itest-daemon-").tempdir().unwrap();
        let run = PathBuf::from(format!("/run/rustlet/itest-{}-d{n}", std::process::id()));
        let cgroup_parent = format!("{scope}/d{n}");
        std::fs::create_dir(format!("/sys/fs/cgroup{cgroup_parent}")).unwrap();
        let resolv = dir.path().join("resolv.conf");
        std::fs::write(&resolv, format!("nameserver {}\nsearch test.lan\n", TestLan::LAN_IP)).unwrap();
        let config = dir.path().join("daemon.toml");
        std::fs::write(&config, format!("resolv_conf = {:?}\n", resolv.display().to_string())).unwrap();
        let mut d = TestDaemon {
            data: dir.path().join("data"),
            socket: run.join("rustlet.sock"),
            run,
            cgroup_parent,
            net: TestLan::new(),
            config,
            log: dir.path().join("rustletd.log"),
            child: None,
            _dir: dir,
        };
        d.spawn();
        d
    }

    fn spawn(&mut self) {
        let log = OpenOptions::new().create(true).append(true).open(&self.log).unwrap();
        let mut cmd = Command::new(workspace_binary("rustletd"));
        cmd.arg("--config")
            .arg(&self.config)
            .arg("--socket")
            .arg(&self.socket)
            .args(["--socket-group", ""])
            .arg("--data-root")
            .arg(&self.data)
            .arg("--run-root")
            .arg(&self.run)
            .args(["--cgroup-parent", &self.cgroup_parent, "--log-level", "debug"])
            .stdin(Stdio::null())
            .stdout(log.try_clone().unwrap())
            .stderr(log);
        let child = self.net.host.spawn(&mut cmd);
        self.child = Some(child);
        let deadline = Instant::now() + Duration::from_secs(30);
        while std::os::unix::net::UnixStream::connect(&self.socket).is_err() {
            if let Some(status) = self.child.as_mut().unwrap().try_wait().unwrap() {
                panic!("rustletd exited ({status}):\n{}", self.log());
            }
            assert!(Instant::now() < deadline, "rustletd didn't start listening:\n{}", self.log());
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    pub fn client(&self) -> Client {
        Client::new(&self.socket)
    }

    /// The daemon's log so far.
    pub fn log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    /// SIGKILL: the daemon dies without a word, as in a crash. Containers
    /// and shims go on.
    pub fn crash(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }

    /// A crash, then a new daemon on the same directories.
    pub fn restart(&mut self) {
        self.crash();
        self.spawn();
    }

    /// Imports the cached Alpine minirootfs as `name` (`alpine` is
    /// `docker.io/library/alpine:latest`), running `sh` by default.
    pub fn import_alpine(&self, name: &str) {
        self.import_alpine_with(name, |_| {});
    }

    /// [`TestDaemon::import_alpine`], with the image config changed by `f`
    /// (its exposed ports, its volumes, …).
    pub fn import_alpine_with(&self, name: &str, f: impl FnOnce(&mut rustlet_runtime::oci_spec::image::Config)) {
        let store = Store::open(&self.data).unwrap();
        let env = ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"];
        let mut cfg = config(&["/bin/sh"], &env, None).unwrap();
        f(&mut cfg);
        import(store.content(), name, &[alpine_layer()], cfg).unwrap();
    }

    /// The mounts the daemon made below its data root.
    pub fn mounts(&self) -> Vec<String> {
        let data = self.data.canonicalize().unwrap_or_else(|_| self.data.clone());
        crate::host_mounts()
            .into_iter()
            .map(|(mp, _, _)| mp)
            .filter(|mp| mp.starts_with(&*data.to_string_lossy()))
            .collect()
    }
}

impl Drop for TestDaemon {
    fn drop(&mut self) {
        let cg = PathBuf::from(format!("/sys/fs/cgroup{}", self.cgroup_parent));
        // Containers, shims and workers all live below the cgroup parent.
        let _ = std::fs::write(cg.join("cgroup.kill"), "1");
        let deadline = Instant::now() + Duration::from_secs(10);
        while std::fs::read_to_string(cg.join("cgroup.events")).is_ok_and(|e| e.contains("populated 1")) {
            if Instant::now() > deadline {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        self.crash();
        let leftover = self.mounts();
        let _ = rustlet_sys::tree::unmount_under(&self.data);
        // The private bind of containers/ is the daemon's on purpose; any
        // other mount still there at the end is a leak.
        let containers = self.data.join("containers");
        let leaked: Vec<_> = leftover
            .iter()
            .filter(|m| std::path::Path::new(m) != containers.canonicalize().unwrap_or_default())
            .collect();
        // The pins of its containers' network namespaces and their shared
        // directory are mounts under the run root.
        let _ = rustlet_sys::tree::unmount_under(&self.run);
        let _ = std::fs::remove_dir_all(&self.run);
        remove_cgroups(&cg);
        if !std::thread::panicking() {
            assert!(leaked.is_empty(), "mounts left under the data root: {leaked:?}\n{}", self.log());
        }
    }
}

fn remove_cgroups(dir: &std::path::Path) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            if e.file_type().is_ok_and(|t| t.is_dir()) {
                remove_cgroups(&e.path());
            }
        }
    }
    let _ = std::fs::remove_dir(dir);
}

/// A runtime for one test.
pub fn block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(f)
}

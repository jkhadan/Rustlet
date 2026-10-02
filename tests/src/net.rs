//! Network namespaces of a test's own, so that no test ever changes the
//! real host's network: a test daemon runs in a "host" namespace of its own
//! (its bridges, its nftables table, its `ip_forward`), and a second
//! namespace beside it plays the LAN.
//!
//! ```text
//!  "lan" netns                      "host" netns (the test daemon's)
//!   lan0 192.0.2.1/24 ═══ veth ═══  lan0 192.0.2.2/24, default via 192.0.2.1
//!                                   rustlet0 10.89.0.1/24 … containers
//! ```
//!
//! 192.0.2.0/24 is TEST-NET-1 (RFC 5737), reserved for documentation, so it
//! can't collide with anything real. The namespaces are held by fds, not
//! pinned: they vanish with the test.

use std::net::Ipv4Addr;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::Duration;

use rustlet_net::link;
use rustlet_sys::netlink::{RtNetlink, VethPeer};
use rustlet_sys::process::{CloneFlags, unshare};

/// A network namespace held by an fd, with `lo` up.
pub struct TestNetns {
    fd: OwnedFd,
}

impl TestNetns {
    pub fn new() -> TestNetns {
        let fd = std::thread::scope(|s| {
            s.spawn(|| {
                unshare(CloneFlags::NEWNET).expect("unshare a network namespace");
                link::loopback_up().expect("bring lo up");
                rustlet_sys::process::open_ns("/proc/thread-self/ns/net").expect("open the new namespace")
            })
            .join()
            .unwrap()
        });
        TestNetns { fd }
    }

    /// The namespace pinned at `pin`, held by an fd of its own.
    pub fn from_pin(pin: &Path) -> TestNetns {
        TestNetns { fd: rustlet_net::netns::open(pin).expect("open the pinned namespace") }
    }

    pub fn fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    /// Runs `f` on a thread inside.
    pub fn run<T: Send>(&self, f: impl FnOnce() -> T + Send) -> T {
        rustlet_net::netns::run_in(self.fd(), || Ok(f())).expect("enter the test namespace")
    }

    /// Spawns `cmd` inside (it starts in this namespace, and so does
    /// everything it starts).
    pub fn spawn(&self, cmd: &mut Command) -> Child {
        self.run(|| cmd.spawn()).expect("spawn in the test namespace")
    }

    /// Connects to `other` with a veth pair named `name` on both sides:
    /// `ip/prefix_len` here, `peer_ip/prefix_len` there, both up.
    pub fn connect(&self, other: &TestNetns, name: &str, ip: Ipv4Addr, peer_ip: Ipv4Addr, prefix_len: u8) {
        self.run(|| {
            let mut nl = RtNetlink::open().unwrap();
            nl.create_veth(name, &VethPeer { name, netns: Some(other.fd()), mac: None }).unwrap();
            let here = nl.link_by_name(name).unwrap().unwrap();
            nl.add_address(here.index, ip, prefix_len).unwrap();
            nl.set_link_up(here.index).unwrap();
        });
        other.run(|| {
            let mut nl = RtNetlink::open().unwrap();
            let there = nl.link_by_name(name).unwrap().unwrap();
            nl.add_address(there.index, peer_ip, prefix_len).unwrap();
            nl.set_link_up(there.index).unwrap();
        });
    }

    /// `ip route add dst/len via gateway`.
    pub fn route(&self, dst: Ipv4Addr, len: u8, gateway: Ipv4Addr) {
        self.run(|| RtNetlink::open().unwrap().add_route(dst, len, Some(gateway), None).unwrap());
    }

    /// Writes a sysctl of this namespace (`net.ipv4.ip_forward`).
    pub fn sysctl(&self, name: &str, value: &str) {
        self.run(|| rustlet_net::sysctl::write(&rustlet_net::sysctl::path(name), value).unwrap());
    }

    pub fn read_sysctl(&self, name: &str) -> String {
        self.run(|| rustlet_net::sysctl::read(&rustlet_net::sysctl::path(name)).unwrap())
    }
}

impl Default for TestNetns {
    fn default() -> TestNetns {
        TestNetns::new()
    }
}

/// A "host" namespace and the "LAN" it is connected to.
pub struct TestLan {
    pub host: TestNetns,
    pub lan: TestNetns,
}

impl TestLan {
    /// The host's address on the LAN.
    pub const HOST_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);
    /// The LAN's other machine (also the host's default gateway).
    pub const LAN_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

    pub fn new() -> TestLan {
        let (host, lan) = (TestNetns::new(), TestNetns::new());
        host.connect(&lan, "lan0", Self::HOST_IP, Self::LAN_IP, 24);
        host.route(Ipv4Addr::UNSPECIFIED, 0, Self::LAN_IP);
        TestLan { host, lan }
    }
}

impl Default for TestLan {
    fn default() -> TestLan {
        TestLan::new()
    }
}

/// A directory for pins (`rustlet_net::netns::prepare_dir`), unmounted and
/// removed when dropped.
pub struct PinDir {
    pub path: PathBuf,
}

impl PinDir {
    pub fn new(name: &str) -> PinDir {
        let path = crate::runtime_root().join(format!("netns-{name}"));
        let _ = std::fs::remove_dir_all(&path);
        rustlet_net::netns::prepare_dir(&path).expect("prepare the pin directory");
        PinDir { path }
    }

    pub fn pin(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
}

impl Drop for PinDir {
    fn drop(&mut self) {
        if let Ok(entries) = std::fs::read_dir(&self.path) {
            for e in entries.flatten() {
                let _ = rustlet_net::netns::remove(&e.path());
            }
        }
        let _ = nix::mount::umount2(&self.path, nix::mount::MntFlags::MNT_DETACH);
        let _ = std::fs::remove_dir(&self.path);
    }
}

/// Connects to `addr` from inside `ns` and returns what the server sent
/// before closing, or the error (a refused or timed-out connection).
pub fn fetch(ns: &TestNetns, addr: std::net::SocketAddr, send: &[u8]) -> std::io::Result<String> {
    ns.run(|| {
        use std::io::{Read, Write};
        let mut s = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(2))?;
        s.set_read_timeout(Some(Duration::from_secs(5)))?;
        s.write_all(send)?;
        s.shutdown(std::net::Shutdown::Write)?;
        let mut out = String::new();
        s.read_to_string(&mut out)?;
        Ok(out)
    })
}

/// A TCP server inside `ns` on `addr`, answering every connection with
/// `reply` followed by the address the connection came from, until the
/// test ends.
pub fn serve(ns: &TestNetns, addr: std::net::SocketAddr, reply: &'static str) -> std::net::SocketAddr {
    let listener = ns.run(|| std::net::TcpListener::bind(addr)).expect("bind the test server");
    let local = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        use std::io::Write;
        for mut s in listener.incoming().flatten() {
            let peer = s.peer_addr().map(|p| p.ip().to_string()).unwrap_or_default();
            let _ = write!(s, "{reply} {peer}");
        }
    });
    local
}

/// Does `path` exist and is it a mount point (as `/proc/self/mountinfo`
/// says)?
pub fn is_mounted(path: &Path) -> bool {
    crate::host_mounts().iter().any(|(mp, _, _)| Path::new(mp) == path)
}

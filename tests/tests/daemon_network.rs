//! Phase 5 through the daemon: networks (`dn_`) and volumes (`vol_`), each
//! test with a daemon of its own in a network namespace of its own, beside
//! a LAN namespace (`rustlet_itests::net::TestLan`: the host is 192.0.2.2
//! and 2001:db8::2, the LAN machine 192.0.2.1 and 2001:db8::1). Run with
//! `cargo xtask itest -- dn_ vol_`.
//!
//! A binary of its own: its daemons mount overlays and pins on the host,
//! which other binaries' mount-table checks would see.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::Duration;

use futures::StreamExt;
use rustlet_client::{Client, SessionEvent};
use rustlet_itests::daemon::{TestDaemon, block_on};
use rustlet_itests::net::{TestLan, TestNetns, fetch, serve};
use rustlet_spec::ErrorKind;
use rustlet_spec::container::{ContainerConfig, ContainerStatus, UsernsMode, WaitCondition};
use rustlet_spec::exec::ExecConfig;
use rustlet_spec::logs::LogsQuery;
use rustlet_spec::network::{NetworkConnect, NetworkCreate, NetworkDisconnect, NetworkMode, PortMapping, Protocol};
use rustlet_spec::volume::{MountSpec, MountType};
use rustlet_sys::netlink::RtNetlink;

fn daemon() -> TestDaemon {
    let d = TestDaemon::start();
    d.import_alpine("alpine");
    d
}

fn sh(script: &str) -> ContainerConfig {
    ContainerConfig { image: "alpine".into(), cmd: vec!["sh".into(), "-c".into(), script.into()], ..Default::default() }
}

fn v4(a: u8, b: u8, c: u8, d: u8, port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), port)
}

/// A server in a container: every connection to `port` gets `reply`, and
/// is closed (busybox `nc -lk -e`: the listening socket stays, and each
/// connection runs `echo`, whatever the client sends or closes).
fn server(port: u16, reply: &str) -> ContainerConfig {
    sh(&format!("exec nc -lk -p {port} -e echo {reply}"))
}

/// Runs `cfg` to its end: its exit status and stdout.
async fn run(c: &Client, cfg: &ContainerConfig) -> (i32, String) {
    let id = c.create_container(cfg).await.unwrap().id;
    c.start(&id).await.unwrap();
    let w = c.wait(&id, WaitCondition::NotRunning).await.unwrap();
    let mut out = String::new();
    let mut logs = c.logs(&id, &LogsQuery { stderr: false, ..Default::default() }).await.unwrap();
    while let Some(e) = tokio::time::timeout(Duration::from_secs(20), logs.next()).await.expect("logs never ended") {
        out.push_str(&e.unwrap().log);
    }
    c.remove_container(&id, true).await.unwrap();
    (w.status_code, out)
}

/// Runs `sh -c script` in the running container `id`: its exit status, and
/// its stdout and stderr together.
async fn exec(c: &Client, id: &str, script: &str) -> (i32, String) {
    let cfg = ExecConfig { cmd: vec!["sh".into(), "-c".into(), script.into()], ..Default::default() };
    let x = c.create_exec(id, &cfg).await.unwrap();
    let (_, mut rx) = c.start_exec(&x.id).await.unwrap().split();
    let mut out = String::new();
    loop {
        let ev = tokio::time::timeout(Duration::from_secs(30), rx.recv()).await.expect("the exec never ended");
        match ev.expect("the exec session") {
            Some(SessionEvent::Stdout(b) | SessionEvent::Stderr(b)) => out.push_str(&String::from_utf8_lossy(&b)),
            Some(SessionEvent::Exit { code, .. }) => return (code, out),
            Some(SessionEvent::Error { message, .. }) => panic!("exec {script:?}: {message}"),
            None => return (-1, out),
        }
    }
}

/// `--network name`.
fn on(network: &str, cfg: ContainerConfig) -> ContainerConfig {
    ContainerConfig { network: NetworkMode::Network(network.into()), ..cfg }
}

async fn network(c: &Client, name: &str, ipv6: bool) {
    c.create_network(&NetworkCreate { name: name.into(), ipv6, ..Default::default() }).await.unwrap();
}

/// A running container's network namespace, entered from the test.
async fn netns_of(c: &Client, id: &str) -> TestNetns {
    let i = c.inspect_container(id).await.unwrap();
    TestNetns::from_pin(Path::new(i.network.sandbox.as_deref().expect("its namespace")))
}

/// The gateways of `ns`'s default routes.
fn default_gateways(ns: &TestNetns) -> Vec<IpAddr> {
    let routes = ns.run(|| RtNetlink::open().unwrap().routes().unwrap());
    routes.iter().filter(|r| r.dst_len == 0 && r.table == 254).filter_map(|r| r.gateway).collect()
}

fn links(ns: &TestNetns) -> Vec<String> {
    let mut names: Vec<String> =
        ns.run(|| RtNetlink::open().unwrap().links().unwrap()).into_iter().map(|l| l.name).collect();
    names.sort();
    names
}

async fn until(what: &str, mut f: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while !f() {
        assert!(tokio::time::Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// A container on the default network: its address, MAC, route and
/// generated files; the LAN through NAT; nothing left after it.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn dn_a_container_on_the_default_network() {
    let d = daemon();
    serve(&d.net.lan, v4(192, 0, 2, 1, 9000), "lan");
    block_on(async {
        let c = d.client();
        let script = "ip -4 -o addr show eth0; ip route; cat /sys/class/net/eth0/address; \
                      cat /proc/sys/net/ipv4/ip_unprivileged_port_start; echo ---; cat /etc/hosts; echo ---; \
                      cat /etc/resolv.conf; echo ---; cat /etc/hostname; echo ---; nc 192.0.2.1 9000 </dev/null";
        let (code, out) = run(&c, &sh(script)).await;
        assert_eq!(code, 0, "{out}");
        let parts: Vec<&str> = out.split("---\n").collect();
        let (net, hosts, resolv, hostname, lan) = (parts[0], parts[1], parts[2], parts[3].trim(), parts[4]);
        assert!(net.contains("inet 10.89.0.2/24"), "{net}");
        assert!(net.contains("default via 10.89.0.1 dev eth0"), "{net}");
        assert!(net.contains("02:52:0a:59:00:02"), "the MAC follows the address: {net}");
        assert!(net.trim_end().ends_with('0'), "ports below 1024 for anyone: {net}");
        assert!(hosts.contains(&format!("10.89.0.2\t{hostname}\n")), "{hosts}");
        assert!(hosts.starts_with("127.0.0.1\tlocalhost\n"), "{hosts}");
        assert!(
            resolv.contains("nameserver 192.0.2.1\nsearch test.lan\n"),
            "the default network asks the host's servers: {resolv}"
        );
        assert_eq!(lan.trim(), "lan 192.0.2.2", "the LAN sees the host's address (masquerade)");
    });
    // Its veth and pin went with it.
    let links = d.net.host.run(|| rustlet_sys::netlink::RtNetlink::open().unwrap().links().unwrap());
    assert!(!links.iter().any(|l| l.name.starts_with("rlv")), "{links:?}");
    assert!(std::fs::read_dir(d.run.join("netns")).unwrap().next().is_none(), "a pin is left");
}

/// `-p`: the LAN through DNAT, the host's loopback and IPv6 through the
/// proxy; a second container can't take the port; stopping frees it; and
/// the LAN still can't reach the container directly.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn dn_published_ports() {
    let d = daemon();
    block_on(async {
        let c = d.client();
        let mut cfg = server(80, "hello");
        cfg.ports = PortMapping::parse("8080:80").unwrap();
        cfg.ports.extend(PortMapping::parse("127.0.0.1::80").unwrap());
        let id = c.create_container(&cfg).await.unwrap().id;
        c.start(&id).await.unwrap();
        let lan = &d.net.lan;
        until("the server", || fetch(lan, v4(192, 0, 2, 2, 8080), b"").is_ok_and(|s| s == "hello\n")).await;
        let i = c.inspect_container(&id).await.unwrap();
        assert_eq!(i.network.ports.len(), 2, "{:?}", i.network.ports);
        let random = i.network.ports.iter().find(|p| p.host_ip == Ipv4Addr::LOCALHOST).unwrap().host_port;
        assert!(random > 1024, "the kernel's choice: {random}");
        assert_eq!(i.network.ports[0].to_string(), "0.0.0.0:8080->80/tcp");
        let host = &d.net.host;
        assert_eq!(fetch(host, v4(127, 0, 0, 1, 8080), b"").unwrap(), "hello\n", "loopback, through the proxy");
        assert_eq!(fetch(host, v4(127, 0, 0, 1, random), b"").unwrap(), "hello\n");
        assert!(fetch(lan, v4(192, 0, 2, 2, random), b"").is_err(), "a 127.0.0.1 port is the host's only");
        assert_eq!(
            fetch(host, SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 8080), b"").unwrap(),
            "hello\n",
            "IPv6, through the proxy"
        );
        // A container on the same network, through the host's address
        // (hairpin: DNAT, masqueraded on the way back out of the bridge).
        let (_, out) = run(&c, &sh("nc 192.0.2.2 8080 </dev/null")).await;
        assert_eq!(out, "hello\n");
        let summary = c.list_containers(false).await.unwrap();
        assert_eq!(summary[0].ports.len(), 2);
        // The port is taken: a second container's start fails, cleanly.
        let mut other = server(80, "other");
        other.ports = PortMapping::parse("8080:80").unwrap();
        let other = c.create_container(&other).await.unwrap().id;
        let e = c.start(&other).await.unwrap_err();
        assert_eq!(e.kind(), Some(ErrorKind::Conflict), "{e}");
        assert_eq!(c.inspect_container(&other).await.unwrap().state.status, ContainerStatus::Created);
        // The LAN can't go around the published port.
        lan.route(Ipv4Addr::new(10, 89, 0, 0), 16, TestLan::HOST_IP);
        assert!(fetch(lan, v4(10, 89, 0, 2, 80), b"").is_err());
        c.stop(&id, Some(1)).await.unwrap();
        assert!(fetch(lan, v4(192, 0, 2, 2, 8080), b"").is_err());
        assert!(host.run(|| std::net::TcpListener::bind("0.0.0.0:8080")).is_ok(), "the port is free again");
        // Now the second one can have it.
        c.start(&other).await.unwrap();
        until("the other server", || fetch(lan, v4(192, 0, 2, 2, 8080), b"").is_ok_and(|s| s == "other\n")).await;
        c.remove_container(&other, true).await.unwrap();
        c.remove_container(&id, true).await.unwrap();
    });
}

/// `-P` publishes what the image exposes; `--network host` discards ports
/// with a warning.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn dn_publish_all_and_host_networking() {
    let d = TestDaemon::start();
    d.import_alpine_with("alpine", |cfg| {
        cfg.set_exposed_ports(Some(vec!["80/tcp".into(), "53/udp".into()]));
    });
    block_on(async {
        let c = d.client();
        let id = c.create_container(&ContainerConfig { publish_all: true, ..server(80, "all") }).await.unwrap().id;
        c.start(&id).await.unwrap();
        let ports = c.inspect_container(&id).await.unwrap().network.ports;
        let mut protos: Vec<_> = ports.iter().map(|p| (p.container_port, p.protocol)).collect();
        protos.sort();
        assert_eq!(protos, [(53, Protocol::Udp), (80, Protocol::Tcp)]);
        let tcp = ports.iter().find(|p| p.protocol == Protocol::Tcp).unwrap().host_port;
        until("the server", || fetch(&d.net.lan, v4(192, 0, 2, 2, tcp), b"").is_ok_and(|s| s == "all\n")).await;
        c.remove_container(&id, true).await.unwrap();

        // The host's namespace: its interfaces, its hostname, its resolver.
        let mut host = sh("ip -4 -o addr show lan0; hostname; cat /etc/resolv.conf");
        host.network = NetworkMode::Host;
        host.ports = PortMapping::parse("80").unwrap();
        let created = c.create_container(&host).await.unwrap();
        assert!(created.warnings.iter().any(|w| w.contains("discarded")), "{:?}", created.warnings);
        c.start(&created.id).await.unwrap();
        c.wait(&created.id, WaitCondition::NotRunning).await.unwrap();
        let mut out = String::new();
        let mut logs = c.logs(&created.id, &LogsQuery::default()).await.unwrap();
        while let Some(e) = logs.next().await {
            out.push_str(&e.unwrap().log);
        }
        let hostname = nix::unistd::gethostname().unwrap().into_string().unwrap();
        assert!(out.contains("inet 192.0.2.2/24"), "{out}");
        assert!(out.contains(&format!("\n{hostname}\n")), "the host's hostname: {out}");
        assert!(out.contains("nameserver 192.0.2.1"), "{out}");
        c.remove_container(&created.id, true).await.unwrap();

        // None: only lo.
        let none = ContainerConfig { network: NetworkMode::None, ..sh("ip -o link | cut -d: -f2; cat /etc/hosts") };
        let (_, out) = run(&c, &none).await;
        assert_eq!(out.lines().next().map(str::trim), Some("lo"), "{out}");
        assert!(!out.contains("eth0") && !out.contains("10.89"), "{out}");
    });
}

/// `--network container:X`: X's localhost, hostname and files; not without
/// X running; conflicting options refused at create.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn dn_sharing_another_containers_network() {
    let d = daemon();
    block_on(async {
        let c = d.client();
        let x =
            c.create_container(&ContainerConfig { name: Some("x".into()), ..server(9999, "from-x") }).await.unwrap();
        c.start(&x.id).await.unwrap();
        let joined = |script: &str| ContainerConfig { network: NetworkMode::Container("x".into()), ..sh(script) };
        let script = "for i in 1 2 3 4 5 6 7 8 9 10; do nc 127.0.0.1 9999 </dev/null && break; sleep 0.2; done; \
                      hostname; ip -4 -o addr show eth0";
        let (code, out) = run(&c, &joined(script)).await;
        assert_eq!(code, 0, "{out}");
        let mut lines = out.lines();
        assert_eq!(lines.next(), Some("from-x"), "{out}");
        assert_eq!(lines.next(), Some(rustlet_spec::short_id(&x.id)), "X's hostname: {out}");
        assert!(out.contains("inet 10.89.0.2/24"), "X's address: {out}");
        // Options of its own conflict with sharing.
        let e = c
            .create_container(&ContainerConfig { ports: PortMapping::parse("80").unwrap(), ..joined("true") })
            .await
            .unwrap_err();
        assert_eq!(e.kind(), Some(ErrorKind::Invalid), "{e}");
        let e =
            c.create_container(&ContainerConfig { network: NetworkMode::Container("nope".into()), ..sh("true") }).await;
        assert_eq!(e.unwrap_err().kind(), Some(ErrorKind::NoSuchContainer));
        // Not without X.
        let later = c.create_container(&joined("true")).await.unwrap().id;
        c.stop(&x.id, Some(1)).await.unwrap();
        assert_eq!(c.start(&later).await.unwrap_err().kind(), Some(ErrorKind::Conflict));
        c.remove_container(&later, true).await.unwrap();
        c.remove_container(&x.id, true).await.unwrap();
    });
}

/// A daemon that dies and comes back: published ports still answer (DNAT
/// never stopped; the proxy is bound again), and the container still runs.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn dn_networking_survives_a_daemon_restart() {
    let mut d = daemon();
    let id = block_on(async {
        let c = d.client();
        let mut cfg = server(80, "still-here");
        cfg.ports = PortMapping::parse("8080:80").unwrap();
        let id = c.create_container(&cfg).await.unwrap().id;
        c.start(&id).await.unwrap();
        until("the server", || fetch(&d.net.lan, v4(192, 0, 2, 2, 8080), b"").is_ok()).await;
        id
    });
    d.crash();
    // While no daemon runs: the kernel's DNAT rules still do their job.
    assert_eq!(fetch(&d.net.lan, v4(192, 0, 2, 2, 8080), b"").unwrap(), "still-here\n");
    d.restart();
    block_on(async {
        let c = d.client();
        assert_eq!(c.inspect_container(&id).await.unwrap().state.status, ContainerStatus::Running);
        let host = &d.net.host;
        until("the proxy again", || fetch(host, v4(127, 0, 0, 1, 8080), b"").is_ok_and(|s| s == "still-here\n")).await;
        assert_eq!(fetch(&d.net.lan, v4(192, 0, 2, 2, 8080), b"").unwrap(), "still-here\n");
        // The address is still its own: a new container gets another.
        let (_, out) = run(&c, &sh("ip -4 -o addr show eth0")).await;
        assert!(out.contains("inet 10.89.0.3/24"), "{out}");
        c.remove_container(&id, true).await.unwrap();
    });
}

/// A named volume: the image's files copied in when it is empty, kept
/// across containers, never copied over again.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn vol_named_volumes_copy_up_once_and_persist() {
    let d = daemon();
    block_on(async {
        let c = d.client();
        let vol = |target: &str| MountSpec {
            kind: MountType::Volume,
            source: Some("apkdata".into()),
            target: target.into(),
            ..Default::default()
        };
        let first =
            ContainerConfig { mounts: vec![vol("/etc/apk")], ..sh("ls /etc/apk; echo marker > /etc/apk/marker") };
        let (code, out) = run(&c, &first).await;
        assert_eq!(code, 0, "{out}");
        assert!(out.contains("repositories") && out.contains("world"), "copied up from the image: {out}");
        let data = d.data.join("volumes/apkdata/_data");
        assert_eq!(std::fs::read_to_string(data.join("marker")).unwrap(), "marker\n");
        assert_eq!(std::fs::metadata(data.join("world")).unwrap().uid(), 0);
        // Elsewhere, the volume's own content (not empty: no copy).
        let (_, out) =
            run(&c, &ContainerConfig { mounts: vec![vol("/mnt")], ..sh("cat /mnt/marker; ls /mnt | wc -l") }).await;
        assert!(out.starts_with("marker\n"), "{out}");
        // Removing the containers left it.
        assert!(data.join("marker").exists());
    });
}

/// Anonymous volumes (`-v /path`, the image's `VOLUME`) go with `--rm`;
/// a bind mount read-only; a tmpfs with its options.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn vol_anonymous_bind_and_tmpfs_mounts() {
    let d = TestDaemon::start();
    d.import_alpine_with("alpine", |cfg| {
        cfg.set_volumes(Some(vec!["/var/cache/".into()]));
    });
    let host_dir = tempfile::tempdir().unwrap();
    std::fs::write(host_dir.path().join("f"), "from the host").unwrap();
    let missing = host_dir.path().join("made/by/v");
    block_on(async {
        let c = d.client();
        let mounts = vec![
            MountSpec::parse_volume("/scratch").unwrap(),
            MountSpec::parse_volume(&format!("{}:/h:ro", host_dir.path().display())).unwrap(),
            MountSpec::parse_volume(&format!("{}:/made", missing.display())).unwrap(),
            MountSpec::parse_tmpfs("/fast:size=1m,mode=700").unwrap(),
        ];
        let script = "cat /h/f; echo; touch /h/x 2>&1 | grep -o 'Read-only file system'; grep ' /fast ' /proc/mounts; \
                      touch /scratch/s /var/cache/c /made/m && echo wrote";
        let cfg = ContainerConfig { mounts, ..sh(script) };
        let id = c.create_container(&cfg).await.unwrap().id;
        let i = c.inspect_container(&id).await.unwrap();
        let anonymous: Vec<_> = i.mounts.iter().filter(|m| m.kind == MountType::Volume).collect();
        assert_eq!(anonymous.len(), 2, "-v /scratch and the image's /var/cache: {:?}", i.mounts);
        assert!(anonymous.iter().all(|m| m.name.as_ref().is_some_and(|n| n.len() == 64)));
        assert!(i.mounts.iter().any(|m| m.destination == "/var/cache"), "the image's VOLUME, cleaned");
        assert!(missing.is_dir(), "-v made the missing host directory");
        c.start(&id).await.unwrap();
        c.wait(&id, WaitCondition::NotRunning).await.unwrap();
        let mut out = String::new();
        let mut logs = c.logs(&id, &LogsQuery::default()).await.unwrap();
        while let Some(e) = logs.next().await {
            out.push_str(&e.unwrap().log);
        }
        assert!(out.starts_with("from the host\nRead-only file system\n"), "{out}");
        assert!(
            out.contains("tmpfs /fast tmpfs rw,nosuid,nodev,noexec") && out.contains("size=1024k,mode=700"),
            "{out}"
        );
        assert!(out.ends_with("wrote\n"), "{out}");
        assert!(missing.join("m").exists());
        // Kept by a plain rm…
        let names: Vec<String> = anonymous.iter().map(|m| m.name.clone().unwrap()).collect();
        c.remove_container(&id, false).await.unwrap();
        assert!(names.iter().all(|n| d.data.join("volumes").join(n).exists()));
        // …and removed with --rm.
        let rm = ContainerConfig {
            auto_remove: true,
            mounts: vec![MountSpec::parse_volume("/tmpdata").unwrap()],
            ..sh("true")
        };
        let id = c.create_container(&rm).await.unwrap().id;
        let name = c.inspect_container(&id).await.unwrap().mounts[0].name.clone().unwrap();
        c.start(&id).await.unwrap();
        c.wait(&id, WaitCondition::Removed).await.unwrap();
        assert!(!d.data.join("volumes").join(&name).exists(), "--rm took its anonymous volume");
    });
    // An image's VOLUME on the runtime's own paths is refused at create,
    // and leaves no volume behind.
    d.import_alpine_with("badvolume", |cfg| {
        cfg.set_volumes(Some(vec!["/data".into(), "/proc".into()]));
    });
    block_on(async {
        let c = d.client();
        let before = c.list_volumes().await.unwrap().len();
        let e = c.create_container(&ContainerConfig { image: "badvolume".into(), ..sh("true") }).await.unwrap_err();
        assert_eq!(e.kind(), Some(ErrorKind::Invalid), "{e}");
        assert!(e.to_string().contains("VOLUME /proc"), "{e}");
        assert_eq!(c.list_volumes().await.unwrap().len(), before, "the /data volume made for it is gone again");
    });
}

/// Under `--userns=remap` a volume is idmapped: container root's files are
/// uid 0 on disk, and the image's owners are copied up unshifted.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn vol_userns_volumes_are_idmapped() {
    let d = daemon();
    block_on(async {
        let c = d.client();
        let cfg = ContainerConfig {
            userns: UsernsMode::Remap,
            mounts: vec![MountSpec {
                kind: MountType::Volume,
                source: Some("shared".into()),
                target: "/etc/apk".into(),
                ..Default::default()
            }],
            ..sh(
                "touch /etc/apk/by-remapped-root; stat -c '%u %g' /etc/apk/by-remapped-root /etc/apk/world; cat /proc/self/uid_map",
            )
        };
        let (code, out) = run(&c, &cfg).await;
        assert_eq!(code, 0, "{out}");
        assert!(out.starts_with("0 0\n0 0\n"), "root inside: {out}");
        let data = d.data.join("volumes/shared/_data");
        let meta = std::fs::metadata(data.join("by-remapped-root")).unwrap();
        assert_eq!((meta.uid(), meta.gid()), (0, 0), "idmapped: uid 0 on disk, not 1000000");
        assert_eq!(std::fs::metadata(data.join("world")).unwrap().uid(), 0, "copied up unshifted");
        // A container without a user namespace sees the same owners.
        let plain = ContainerConfig { userns: UsernsMode::Host, ..cfg.clone() };
        let plain = ContainerConfig {
            cmd: vec!["stat".into(), "-c".into(), "%u".into(), "/etc/apk/by-remapped-root".into()],
            ..plain
        };
        let (_, out) = run(&c, &plain).await;
        assert_eq!(out.trim(), "0");
    });
}

/// A DNS server on the LAN machine (192.0.2.1:53, UDP) for the names under
/// `example.`: `A` is 198.51.100.7, other types have no records; any other
/// name doesn't exist (NXDOMAIN), so a name that should have been answered
/// locally can't pass for one the upstream knows.
fn fake_upstream(d: &TestDaemon) {
    let sock = d.net.lan.run(|| std::net::UdpSocket::bind("192.0.2.1:53")).unwrap();
    std::thread::spawn(move || {
        let mut buf = [0u8; 1500];
        while let Ok((n, from)) = sock.recv_from(&mut buf) {
            let q = &buf[..n];
            // The question: labels up to the root's zero, then type and class.
            let mut i = 12;
            while i < n && q[i] != 0 {
                i += 1 + q[i] as usize;
            }
            if i + 5 > n {
                continue;
            }
            // The last label before the root: its length is the byte that
            // starts it.
            let mut last = 12;
            let mut j = 12;
            while j < i {
                last = j;
                j += 1 + q[j] as usize;
            }
            let ours = q[last + 1..i].eq_ignore_ascii_case(b"example");
            let a = ours && u16::from_be_bytes([q[i + 1], q[i + 2]]) == 1;
            let mut r = q[..i + 5].to_vec();
            r[2] = 0x80 | (q[2] & 0x01); // a response; RD as asked
            r[3] = if ours { 0x80 } else { 0x83 }; // RA; NOERROR or NXDOMAIN
            r[4..12].copy_from_slice(&[0, 1, 0, a as u8, 0, 0, 0, 0]);
            if a {
                r.extend([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 198, 51, 100, 7]);
            }
            let _ = sock.send_to(&r, from);
        }
    });
}

/// A user-defined network: its own bridge and subnet, the embedded DNS
/// server (names, aliases, short ids, `name.network`, PTR, forwarding the
/// rest), isolation from the default network, and the rules for removing
/// it.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn dn_user_defined_networks_resolve_their_containers() {
    use rustlet_spec::network::NetworkCreate;
    let d = daemon();
    fake_upstream(&d);
    block_on(async {
        let c = d.client();
        let created = c.create_network(&NetworkCreate { name: "backend".into(), ..Default::default() }).await.unwrap();
        let net = c.inspect_network("backend").await.unwrap();
        assert_eq!(
            (net.id.as_str(), net.subnet.as_str(), net.gateway.as_str()),
            (created.id.as_str(), "10.89.1.0/24", "10.89.1.1")
        );
        assert_eq!(net.bridge, format!("rlb{}", &created.id[..12]));
        assert!(net.dns);
        let on = |cfg: ContainerConfig| ContainerConfig { network: NetworkMode::Network("backend".into()), ..cfg };
        let db = ContainerConfig {
            name: Some("db".into()),
            network_aliases: vec!["database".into()],
            ..on(server(5432, "db-here"))
        };
        let db = c.create_container(&db).await.unwrap().id;
        c.start(&db).await.unwrap();
        // getent: musl's resolver, as programs in the container use it.
        let script = format!(
            "cat /etc/resolv.conf; for n in db database db.backend DB {short} external.example; do \
             getent hosts $n | cut -d' ' -f1; done; echo ---; getent hosts 10.89.1.2; getent hosts nowhere.invalid; \
             echo nowhere=$?; nc db 5432 </dev/null",
            short = &db[..12]
        );
        let (code, out) = run(&c, &on(sh(&script))).await;
        assert_eq!(code, 0, "{out}");
        assert!(out.contains("nameserver 127.0.0.11\n") && out.contains("ndots:0"), "{out}");
        let answers: Vec<&str> =
            out.lines().filter(|l| l.starts_with("10.") || l.starts_with("198.")).take(6).collect();
        assert_eq!(
            answers,
            ["10.89.1.2", "10.89.1.2", "10.89.1.2", "10.89.1.2", "10.89.1.2", "198.51.100.7"],
            "names, alias, qualified, any case, short id; then forwarded to the LAN's server: {out}"
        );
        let after = out.split("---\n").nth(1).unwrap();
        assert!(after.starts_with("10.89.1.2") && after.lines().next().unwrap().contains("db.backend"), "PTR: {out}");
        assert!(after.contains("nowhere=2"), "an unknown name doesn't resolve: {out}");
        assert!(out.trim_end().ends_with("db-here"), "{out}");
        let net = c.inspect_network("backend").await.unwrap();
        assert_eq!(net.containers.len(), 1);
        assert!(net.containers[0].dns_names.contains(&"database".to_owned()), "{:?}", net.containers);
        // The default network has no embedded server, and can't reach in.
        let (_, out) = run(&c, &sh("getent hosts db; nc -w 2 10.89.1.2 5432 </dev/null && echo reached")).await;
        assert!(!out.contains("10.89.1.2") && !out.contains("reached"), "{out}");
        // In use: not removable; the default network never.
        assert_eq!(c.remove_network("backend").await.unwrap_err().kind(), Some(ErrorKind::Conflict));
        assert_eq!(c.remove_network("bridge").await.unwrap_err().kind(), Some(ErrorKind::Conflict));
        let overlap = NetworkCreate { name: "again".into(), subnet: Some("10.89.1.0/24".into()), ..Default::default() };
        assert_eq!(c.create_network(&overlap).await.unwrap_err().kind(), Some(ErrorKind::Conflict));
        c.remove_container(&db, true).await.unwrap();
        c.remove_network("backend").await.unwrap();
        let links = d.net.host.run(|| rustlet_sys::netlink::RtNetlink::open().unwrap().links().unwrap());
        assert!(!links.iter().any(|l| l.name.starts_with("rlb")), "its bridge went with it");
    });
}

/// An internal network: neighbours, but no way out and no published ports.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn dn_internal_networks_stay_inside() {
    use rustlet_spec::network::NetworkCreate;
    let d = daemon();
    serve(&d.net.lan, v4(192, 0, 2, 1, 9000), "lan");
    block_on(async {
        let c = d.client();
        c.create_network(&NetworkCreate { name: "inner".into(), internal: true, ..Default::default() }).await.unwrap();
        let on = |cfg: ContainerConfig| ContainerConfig { network: NetworkMode::Network("inner".into()), ..cfg };
        let peer = c
            .create_container(&ContainerConfig { name: Some("peer".into()), ..on(server(7, "peer")) })
            .await
            .unwrap()
            .id;
        c.start(&peer).await.unwrap();
        let (_, out) =
            run(&c, &on(sh("ip route; nc -w 2 192.0.2.1 9000 </dev/null; sleep 0.5; nc peer 7 </dev/null"))).await;
        assert!(!out.contains("default"), "no default route: {out}");
        assert!(!out.contains("lan "), "the LAN is out of reach: {out}");
        assert!(out.trim_end().ends_with("peer"), "{out}");
        let ports = ContainerConfig { ports: PortMapping::parse("80").unwrap(), ..on(sh("true")) };
        assert_eq!(c.create_container(&ports).await.unwrap_err().kind(), Some(ErrorKind::Invalid));
        c.remove_container(&peer, true).await.unwrap();
    });
}

/// `network connect` and `disconnect` while containers run: an interface
/// comes and goes, names answer on each network a container is on (its own
/// server sees them all), its default route and published port move to the
/// network left with a way out, its `/etc` files follow; then a stopped
/// container's connection, which waits for its start, and the refusals.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn dn_connect_and_disconnect() {
    let d = daemon();
    block_on(async {
        let c = d.client();
        // back is 10.89.1.0/24, front 10.89.2.0/24.
        network(&c, "back", false).await;
        network(&c, "front", false).await;
        let mut web = ContainerConfig { name: Some("web".into()), ..on("back", server(80, "web")) };
        web.ports = PortMapping::parse("8080:80").unwrap();
        let web = c.create_container(&web).await.unwrap().id;
        c.start(&web).await.unwrap();
        let (lan, host) = (&d.net.lan, &d.net.host);
        until("web's port", || fetch(lan, v4(192, 0, 2, 2, 8080), b"").is_ok_and(|s| s == "web\n")).await;
        let client = ContainerConfig { name: Some("client".into()), ..on("front", sh("sleep 600")) };
        let client = c.create_container(&client).await.unwrap().id;
        c.start(&client).await.unwrap();
        let (_, out) = exec(&c, &client, "getent ahostsv4 web || echo none").await;
        assert_eq!(out, "none\n", "web isn't on front yet");

        // Connected while it runs: eth1 on front, with a name more there.
        let connect = NetworkConnect { container: "web".into(), aliases: vec!["www".into()], ..Default::default() };
        c.connect_network("front", &connect).await.unwrap();
        let i = c.inspect_container(&web).await.unwrap();
        let eps: Vec<_> = i.network.networks.iter().map(|e| (e.network.as_str(), e.interface.as_deref())).collect();
        assert_eq!(eps, [("back", Some("eth0")), ("front", Some("eth1"))]);
        assert_eq!(i.network.networks[1].ip_address.as_deref(), Some("10.89.2.3"));
        assert!(i.network.networks[0].default_route && !i.network.networks[1].default_route);
        let (code, out) =
            exec(&c, &client, "getent ahostsv4 web | head -1; getent ahostsv4 www | head -1; nc web 80 </dev/null")
                .await;
        assert_eq!(code, 0, "{out}");
        let lines: Vec<&str> = out.lines().collect();
        assert!(lines[0].starts_with("10.89.2.3 ") && lines[1].starts_with("10.89.2.3 "), "{out}");
        assert_eq!(lines[2], "web");
        let ns = netns_of(&c, &web).await;
        assert_eq!(links(&ns), ["eth0", "eth1", "lo"]);
        assert_eq!(default_gateways(&ns), [IpAddr::V4(Ipv4Addr::new(10, 89, 1, 1))], "still through back");
        let files = d.data.join("containers").join(&web);
        let hosts = std::fs::read_to_string(files.join("hosts")).unwrap();
        assert!(hosts.contains("10.89.1.2\t") && hosts.contains("10.89.2.3\t"), "{hosts}");
        // web's own server sees front's names now.
        let (_, out) = exec(&c, &web, "getent ahostsv4 client | head -1").await;
        assert!(out.starts_with("10.89.2.2 "), "{out}");

        // Disconnected from back, which its route and port went through:
        // both move to front, and back forgets it.
        let leave = |net: &str| (net.to_owned(), NetworkDisconnect { container: "web".into(), force: false });
        let (net, req) = leave("back");
        c.disconnect_network(&net, &req).await.unwrap();
        assert_eq!(links(&ns), ["eth1", "lo"]);
        assert_eq!(default_gateways(&ns), [IpAddr::V4(Ipv4Addr::new(10, 89, 2, 1))]);
        until("web's port through front", || fetch(lan, v4(192, 0, 2, 2, 8080), b"").is_ok_and(|s| s == "web\n")).await;
        assert_eq!(fetch(host, v4(127, 0, 0, 1, 8080), b"").unwrap(), "web\n", "the proxy followed");
        let i = c.inspect_container(&web).await.unwrap();
        assert_eq!((i.network.network.as_deref(), i.network.ip_address.as_deref()), (Some("front"), Some("10.89.2.3")));
        let hosts = std::fs::read_to_string(files.join("hosts")).unwrap();
        assert!(!hosts.contains("10.89.1.2\t"), "{hosts}");
        assert!(c.inspect_network("back").await.unwrap().containers.is_empty());

        // What isn't allowed.
        let again = NetworkConnect { container: "web".into(), ..Default::default() };
        assert_eq!(c.connect_network("front", &again).await.unwrap_err().kind(), Some(ErrorKind::Conflict));
        let (net, req) = leave("back");
        assert_eq!(c.disconnect_network(&net, &req).await.unwrap_err().kind(), Some(ErrorKind::Conflict));
        let on_host =
            c.create_container(&ContainerConfig { network: NetworkMode::Host, ..sh("true") }).await.unwrap().id;
        let host_connect = NetworkConnect { container: on_host.clone(), ..Default::default() };
        assert_eq!(c.connect_network("front", &host_connect).await.unwrap_err().kind(), Some(ErrorKind::Invalid));
        let static_on_default = NetworkConnect {
            container: "web".into(),
            ipv4_address: Some(Ipv4Addr::new(10, 89, 0, 50)),
            ..Default::default()
        };
        assert_eq!(c.connect_network("bridge", &static_on_default).await.unwrap_err().kind(), Some(ErrorKind::Invalid));

        // Disconnected from everything: only lo, the host's servers again.
        let (net, req) = leave("front");
        c.disconnect_network(&net, &req).await.unwrap();
        assert_eq!(links(&ns), ["lo"]);
        let resolv = std::fs::read_to_string(files.join("resolv.conf")).unwrap();
        assert!(resolv.contains("nameserver 192.0.2.1") && !resolv.contains("127.0.0.11"), "{resolv}");
        let (_, out) = exec(&c, &web, "cat /etc/resolv.conf").await;
        assert_eq!(out, resolv, "the container sees the file rewritten in place");

        // A stopped container connected now joins at its next start, behind
        // its first network.
        let script = "ip -o -4 addr show | awk '/eth/ {print $2, $4}'; grep nameserver /etc/resolv.conf; \
                      getent ahostsv4 client | head -1";
        let later = c.create_container(&ContainerConfig { name: Some("later".into()), ..sh(script) }).await.unwrap().id;
        c.connect_network("front", &NetworkConnect { container: "later".into(), ..Default::default() }).await.unwrap();
        c.start(&later).await.unwrap();
        c.wait(&later, WaitCondition::NotRunning).await.unwrap();
        let mut out = String::new();
        let mut logs = c.logs(&later, &LogsQuery::default()).await.unwrap();
        while let Some(e) = logs.next().await {
            out.push_str(&e.unwrap().log);
        }
        let lines: Vec<&str> = out.lines().collect();
        // (.3 was web's: a released address is the last to be reused.)
        assert_eq!(&lines[..3], ["eth0 10.89.0.2/24", "eth1 10.89.2.4/24", "nameserver 127.0.0.11"], "{out}");
        assert!(lines[3].starts_with("10.89.2.2 "), "{out}");
        for id in [&web, &client, &later, &on_host] {
            c.remove_container(id, true).await.unwrap();
        }
    });
}

/// `--network` given twice, `--ip`: two interfaces from the start, its own
/// address; an address asked for is never handed to another container,
/// and two can't run with the same; what is refused at create.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn dn_several_networks_and_static_addresses() {
    let d = daemon();
    block_on(async {
        let c = d.client();
        network(&c, "back", false).await;
        network(&c, "front", false).await;
        let both = ContainerConfig {
            extra_networks: vec!["front".into()],
            ip: Some(Ipv4Addr::new(10, 89, 1, 50)),
            network_aliases: vec!["db".into()],
            ..on("back", sh("ip -o -4 addr show | awk '/eth/ {print $2, $4}'; ip route | grep default"))
        };
        let (code, out) = run(&c, &both).await;
        assert_eq!(code, 0, "{out}");
        assert_eq!(out, "eth0 10.89.1.50/24\neth1 10.89.2.2/24\ndefault via 10.89.1.1 dev eth0 \n");
        // holder asks for 10.89.1.2 and doesn't run: a container given the
        // next free address gets .3, not .2.
        let holder = on("back", ContainerConfig { ip: Some(Ipv4Addr::new(10, 89, 1, 2)), ..sh("sleep 600") });
        let holder = c.create_container(&holder).await.unwrap().id;
        let (_, out) = run(&c, &on("back", sh("ip -o -4 addr show eth0 | awk '{print $4}'"))).await;
        assert_eq!(out, "10.89.1.3/24\n");
        // Two can't run with one address: the second start is a conflict.
        c.start(&holder).await.unwrap();
        let twin = on("back", ContainerConfig { ip: Some(Ipv4Addr::new(10, 89, 1, 2)), ..sh("true") });
        let twin = c.create_container(&twin).await.unwrap().id;
        let e = c.start(&twin).await.unwrap_err();
        assert_eq!(e.kind(), Some(ErrorKind::Conflict), "{e}");
        assert!(e.to_string().contains("10.89.1.2 is in use"), "{e}");
        // Refused at create.
        let bad = [
            ContainerConfig { ip: Some(Ipv4Addr::new(10, 89, 0, 9)), ..sh("true") },
            on("back", ContainerConfig { ip: Some(Ipv4Addr::new(10, 89, 7, 9)), ..sh("true") }),
            on("back", ContainerConfig { ip: Some(Ipv4Addr::new(10, 89, 1, 1)), ..sh("true") }),
            on("back", ContainerConfig { ip6: Some("fd00:89::9".parse().unwrap()), ..sh("true") }),
            on("back", ContainerConfig { extra_networks: vec!["back".into()], ..sh("true") }),
            ContainerConfig { network: NetworkMode::None, extra_networks: vec!["back".into()], ..sh("true") },
        ];
        for cfg in bad {
            let e = c.create_container(&cfg).await.unwrap_err();
            assert_eq!(e.kind(), Some(ErrorKind::Invalid), "{e}: {cfg:?}");
        }
        for id in [&holder, &twin] {
            c.remove_container(id, true).await.unwrap();
        }
    });
}

/// A network with IPv6: its subnet from the pool, IPv6 forwarding turned on
/// (and recorded); a container's address, route, names (AAAA, ip6.arpa)
/// and hosts line; NAT66 to the LAN; a published port over IPv6 through
/// DNAT from the LAN and through the proxy on `::1`; the LAN kept from the
/// container's address; `--ip6`; IPv4-only networks without any IPv6.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn dn_ipv6_networks() {
    let mut d = daemon();
    let v6 = |ip: &str, port| SocketAddr::new(IpAddr::V6(ip.parse().unwrap()), port);
    serve(&d.net.lan, v6("2001:db8::1", 9000), "lan6");
    block_on(async {
        let c = d.client();
        network(&c, "six", true).await;
        let net = c.inspect_network("six").await.unwrap();
        assert_eq!(
            (net.ipv6, net.subnet6.as_deref(), net.gateway6.as_deref()),
            (true, Some("fd00:89::/64"), Some("fd00:89::1"))
        );
        assert_eq!(d.net.host.read_sysctl("net.ipv6.conf.all.forwarding"), "1");
        let record = std::fs::read_to_string(d.run.join("host-sysctl.orig")).unwrap();
        assert!(record.contains("net.ipv6.conf.all.forwarding=0"), "{record}");

        let mut web = ContainerConfig { name: Some("web6".into()), ..on("six", server(80, "web6")) };
        web.ports = PortMapping::parse("8086:80").unwrap();
        let web = c.create_container(&web).await.unwrap().id;
        c.start(&web).await.unwrap();
        let (lan, host) = (&d.net.lan, &d.net.host);
        until("web6 over IPv6", || fetch(lan, v6("2001:db8::2", 8086), b"").is_ok_and(|s| s == "web6\n")).await;
        assert_eq!(fetch(lan, v4(192, 0, 2, 2, 8086), b"").unwrap(), "web6\n", "and over IPv4");
        assert_eq!(fetch(host, v6("::1", 8086), b"").unwrap(), "web6\n", "::1 through the proxy");
        let i = c.inspect_container(&web).await.unwrap();
        assert_eq!(
            (i.network.ipv6_address.as_deref(), i.network.ipv6_gateway.as_deref()),
            (Some("fd00:89::2"), Some("fd00:89::1"))
        );

        let script = "ip -o -6 addr show eth0 scope global | awk '{print $4}'; ip -6 route | grep default; \
                      getent ahostsv6 web6 | head -1; getent ahostsv4 web6 | head -1; getent hosts fd00:89::2; \
                      nc 2001:db8::1 9000 </dev/null; echo; grep fd00 /etc/hosts";
        let (code, out) = run(&c, &on("six", sh(script))).await;
        assert_eq!(code, 0, "{out}");
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines[0], "fd00:89::3/64", "{out}");
        assert!(lines[1].starts_with("default via fd00:89::1 dev eth0"), "{out}");
        assert!(lines[2].starts_with("fd00:89::2 "), "AAAA: {out}");
        assert!(lines[3].starts_with("10.89.1.2 "), "A: {out}");
        assert!(lines[4].starts_with("fd00:89::2") && lines[4].ends_with("web6.six"), "PTR: {out}");
        assert_eq!(lines[5], "lan6 2001:db8::2", "NAT66: the LAN sees the host: {out}");
        assert!(lines[6].starts_with("fd00:89::3\t"), "{out}");

        // The LAN can't go around the published port.
        lan.route("fd00:89::".parse::<Ipv6Addr>().unwrap(), 48, TestLan::HOST_IP6);
        assert!(fetch(lan, v6("fd00:89::2", 80), b"").is_err());
        // --ip6.
        let fixed = on(
            "six",
            ContainerConfig {
                ip6: Some("fd00:89::99".parse().unwrap()),
                ..sh("ip -o -6 addr show eth0 scope global | awk '{print $4}'")
            },
        );
        assert_eq!(run(&c, &fixed).await.1, "fd00:89::99/64\n");
        // On an IPv4-only network: no IPv6 on eth0 at all, not even a
        // link-local address.
        let (_, out) =
            run(&c, &sh("ip -6 addr show dev eth0 | wc -l; cat /proc/sys/net/ipv6/conf/eth0/disable_ipv6")).await;
        assert_eq!(out, "0\n1\n");
        c.remove_container(&web, true).await.unwrap();
        c.remove_network("six").await.unwrap();
    });
    // IPv6 forwarding stays on without an IPv6 network, as ip_forward does,
    // and a new daemon keeps it to Rustlets' bridges all the same.
    d.restart();
    assert_eq!(d.net.host.read_sysctl("net.ipv6.conf.all.forwarding"), "1");
    let mut nft = std::process::Command::new("nft");
    nft.args(["list", "table", "inet", "rustlet"]).stdout(std::process::Stdio::piped());
    let table = String::from_utf8(d.net.host.spawn(&mut nft).wait_with_output().unwrap().stdout).unwrap();
    assert!(table.contains("meta nfproto ipv6 drop"), "{table}");
}

/// A container on two networks, one with IPv6, through a daemon crash:
/// afterwards its names still answer on both, its port still works, its
/// addresses aren't handed out again, and it can still be disconnected.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn dn_several_networks_survive_a_daemon_restart() {
    let mut d = daemon();
    let id = block_on(async {
        let c = d.client();
        network(&c, "back", false).await;
        network(&c, "six", true).await;
        let mut cfg = ContainerConfig { name: Some("multi".into()), ..on("back", server(80, "multi")) };
        cfg.ports = PortMapping::parse("8090:80").unwrap();
        let id = c.create_container(&cfg).await.unwrap().id;
        c.start(&id).await.unwrap();
        c.connect_network("six", &NetworkConnect { container: "multi".into(), ..Default::default() }).await.unwrap();
        until("multi's port", || fetch(&d.net.lan, v4(192, 0, 2, 2, 8090), b"").is_ok_and(|s| s == "multi\n")).await;
        id
    });
    d.restart();
    block_on(async {
        let c = d.client();
        assert_eq!(c.inspect_container(&id).await.unwrap().state.status, ContainerStatus::Running);
        until("the proxy again", || fetch(&d.net.host, v4(127, 0, 0, 1, 8090), b"").is_ok_and(|s| s == "multi\n"))
            .await;
        // Its own server, started again, sees both networks.
        let (_, out) = exec(&c, &id, "getent ahostsv6 multi | head -1; getent ahostsv4 multi | head -1").await;
        assert!(out.starts_with("fd00:89::2 ") && out.contains("\n10.89.1.2 "), "{out}");
        // Its addresses are still its own.
        let (_, out) = run(&c, &on("six", sh("ip -o -4 addr show eth0 | awk '{print $4}'; ip -o -6 addr show eth0 scope global | awk '{print $4}'"))).await;
        assert_eq!(out, "10.89.2.3/24\nfd00:89::3/64\n");
        // And it can still leave a network.
        c.disconnect_network("six", &NetworkDisconnect { container: "multi".into(), force: false }).await.unwrap();
        let ns = netns_of(&c, &id).await;
        assert_eq!(links(&ns), ["eth0", "lo"]);
        let (_, out) = run(&c, &on("six", sh("getent ahostsv6 multi || echo gone"))).await;
        assert_eq!(out, "gone\n");
        c.remove_container(&id, true).await.unwrap();
    });
}

//! Phase 5 through the daemon: networks (`dn_`) and volumes (`vol_`), each
//! test with a daemon of its own in a network namespace of its own, beside
//! a LAN namespace (`rustlet_itests::net::TestLan`: the host is 192.0.2.2,
//! the LAN machine 192.0.2.1). Run with `cargo xtask itest -- dn_ vol_`.
//!
//! A binary of its own: its daemons mount overlays and pins on the host,
//! which other binaries' mount-table checks would see.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::unix::fs::MetadataExt;
use std::time::Duration;

use futures::StreamExt;
use rustlet_client::Client;
use rustlet_itests::daemon::{TestDaemon, block_on};
use rustlet_itests::net::{TestLan, fetch, serve};
use rustlet_spec::ErrorKind;
use rustlet_spec::container::{ContainerConfig, ContainerStatus, UsernsMode, WaitCondition};
use rustlet_spec::logs::LogsQuery;
use rustlet_spec::network::{NetworkMode, PortMapping, Protocol};
use rustlet_spec::volume::{MountSpec, MountType};

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

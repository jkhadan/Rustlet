//! `net_`: rustlet-net's host side on its own, in throwaway network
//! namespaces (`rustlet_itests::net`): pinning, a bridge and a container's
//! veth, the firewall's NAT, published ports and guards against a
//! simulated LAN, and the DNS port redirect. Nothing here touches the real
//! host's network. Run with `cargo xtask itest -- net_`.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::fd::AsFd;
use std::path::Path;
use std::time::Duration;

use rustlet_itests::net::{PinDir, TestLan, TestNetns, fetch, is_mounted, serve};
use rustlet_itests::{PRIVILEGED, assert_host_mounts_unchanged, host_mounts};
use rustlet_net::firewall::{NetworkRules, PortRule, Ruleset, dns_redirect, run_nft};
use rustlet_net::{ipam, link, netns, sysctl};
use rustlet_sys::netlink::RtNetlink;

fn addr(ip: Ipv4Addr, port: u16) -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(ip, port))
}

const GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 89, 0, 1);
const C1: Ipv4Addr = Ipv4Addr::new(10, 89, 0, 2);

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn net_a_pinned_namespace_outlives_its_thread_and_unpins() {
    let _ = PRIVILEGED;
    let before = host_mounts();
    {
        let dir = PinDir::new("pin");
        assert!(is_mounted(&dir.path), "the pin directory is a mount point");
        let pin = dir.pin("c1");
        netns::create(&pin, || {
            link::loopback_up()?;
            sysctl::set_netns_defaults()
        })
        .unwrap();
        // Its own namespace, alive with no process in it, set up as asked.
        assert_ne!(netns::inode(&pin).unwrap(), netns::inode(Path::new("/proc/self/ns/net")).unwrap());
        let (lo_up, port_start) = netns::run_in_pinned(&pin, || {
            let lo = RtNetlink::open().unwrap().link_by_name("lo").unwrap().unwrap();
            Ok((lo.flags & 1 != 0, sysctl::read(&sysctl::path("net.ipv4.ip_unprivileged_port_start"))?))
        })
        .unwrap();
        assert!(lo_up);
        assert_eq!(port_start, "0");
        // The test's own namespace kept its value.
        assert_ne!(sysctl::read(&sysctl::path("net.ipv4.ip_unprivileged_port_start")).unwrap(), "0");
        // A pin that exists is not overwritten.
        assert!(netns::create(&pin, || Ok(())).is_err());
        netns::remove(&pin).unwrap();
        assert!(!pin.exists());
        // A setup that fails leaves nothing behind.
        let failed = dir.pin("c2");
        assert!(netns::create(&failed, || Err(rustlet_net::Error::Invalid("no".into()))).is_err());
        assert!(!failed.exists());
    }
    assert_host_mounts_unchanged(&before, &host_mounts());
}

/// The whole path of a published port and the guards around it, against a
/// LAN namespace that routes `10.89.0.0/16` through the host, as an
/// attacker on the LAN could.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn net_bridge_nat_published_ports_and_guards() {
    let world = TestLan::new();
    let host = &world.host;
    let dir = PinDir::new("nat");
    let pin = dir.pin("c1");
    netns::create(&pin, link::loopback_up).unwrap();
    let c1 = TestNetns::from_pin(&pin);

    host.sysctl("net.ipv4.ip_forward", "1");
    host.run(|| link::ensure_bridge("rustlet0", GATEWAY, 24)).unwrap();
    // Twice: the setup is idempotent.
    host.run(|| link::ensure_bridge("rustlet0", GATEWAY, 24)).unwrap();
    let ns = netns::open(&pin).unwrap();
    let ep = link::Endpoint {
        host_ifname: "rlvtest0000001",
        bridge: "rustlet0",
        address: C1,
        prefix_len: 24,
        gateway: Some(GATEWAY),
        mac: ipam::mac_for(C1),
    };
    host.run(|| link::attach(ns.as_fd(), &ep)).unwrap();
    let rules = Ruleset {
        table: "rustlet".into(),
        networks: vec![NetworkRules {
            bridge: "rustlet0".into(),
            subnet: "10.89.0.0/24".parse().unwrap(),
            internal: false,
        }],
        ports: vec![PortRule {
            protocol: "tcp".into(),
            host_ip: None,
            host_port: 8080,
            container_ip: C1,
            container_port: 80,
            bridge: "rustlet0".into(),
            container: "c1".into(),
        }],
        isolate_forwarding: true,
    };
    host.run(|| rules.apply()).unwrap();
    // Applying it again replaces it rather than adding to it.
    host.run(|| rules.apply()).unwrap();

    // The container's side: eth0 with its address and MAC, a default route.
    let (mac, routes) = c1.run(|| {
        let mut nl = RtNetlink::open().unwrap();
        let eth0 = nl.link_by_name("eth0").unwrap().unwrap();
        (ipam::format_mac(&eth0.mac.clone().try_into().unwrap()), nl.routes().unwrap())
    });
    assert_eq!(mac, "02:52:0a:59:00:02");
    assert!(routes.iter().any(|r| r.dst_len == 0 && r.gateway == Some(GATEWAY)), "{routes:?}");

    serve(&c1, addr(Ipv4Addr::UNSPECIFIED, 80), "container");
    serve(&world.lan, addr(TestLan::LAN_IP, 9000), "lan");

    // 1. The LAN reaches the published port; the container sees the LAN
    //    client's own address (DNAT leaves the source alone).
    assert_eq!(fetch(&world.lan, addr(TestLan::HOST_IP, 8080), b"").unwrap(), "container 192.0.2.1");
    // 2. The host reaches it through its own LAN address (output DNAT)…
    //    (its source stays the address it connected to).
    assert_eq!(fetch(host, addr(TestLan::HOST_IP, 8080), b"").unwrap(), "container 192.0.2.2");
    //    …and the container directly; but not through 127.0.0.1, which
    //    DNAT leaves alone (the daemon's proxy serves it).
    assert!(fetch(host, addr(C1, 80), b"").unwrap().starts_with("container"));
    assert!(fetch(host, addr(Ipv4Addr::LOCALHOST, 8080), b"").is_err());
    // 3. The container reaches the LAN, masqueraded as the host.
    assert_eq!(fetch(&c1, addr(TestLan::LAN_IP, 9000), b"").unwrap(), "lan 192.0.2.2");
    // 4. The LAN can't reach the container directly, even with a route to
    //    its subnet through the host.
    world.lan.route(Ipv4Addr::new(10, 89, 0, 0), 16, TestLan::HOST_IP);
    let direct = fetch(&world.lan, addr(C1, 80), b"");
    assert!(direct.is_err(), "the LAN reached a container directly: {direct:?}");
    //    Nor with the raw guard gone: the forward chain drops it too.
    host.run(|| {
        run_nft(&serde_json::json!({"nftables": [{"flush": {"chain": {"family": "inet", "table": "rustlet", "name": "raw_prerouting"}}}]}))
    })
    .unwrap();
    assert!(fetch(&world.lan, addr(C1, 80), b"").is_err());
    // …while the published port still works.
    assert!(fetch(&world.lan, addr(TestLan::HOST_IP, 8080), b"").is_ok());

    // Deleting the host's end takes eth0 with it.
    assert!(host.run(|| link::delete_link("rlvtest0000001")).unwrap());
    assert!(c1.run(|| RtNetlink::open().unwrap().link_by_name("eth0").unwrap()).is_none());
}

/// A query for 127.0.0.11:53 inside a namespace reaches the socket the
/// redirect names, and the answer comes back from port 53.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn net_dns_port_53_is_redirected_to_the_servers_socket() {
    let ns = TestNetns::new();
    let (server, client) = ns.run(|| {
        let server = std::net::UdpSocket::bind("127.0.0.11:0").unwrap();
        let tcp = std::net::TcpListener::bind("127.0.0.11:0").unwrap();
        let (u, t) = (server.local_addr().unwrap().port(), tcp.local_addr().unwrap().port());
        run_nft(&dns_redirect(u, t)).unwrap();
        // Replaced, not added to.
        run_nft(&dns_redirect(u, t)).unwrap();
        let client = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        client.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        client.send_to(b"question", "127.0.0.11:53").unwrap();
        (server, client)
    });
    server.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut buf = [0u8; 64];
    let (n, from) = server.recv_from(&mut buf).expect("the redirected query");
    assert_eq!(&buf[..n], b"question");
    server.send_to(b"answer", from).unwrap();
    let (n, src) = client.recv_from(&mut buf).expect("the answer");
    assert_eq!((&buf[..n], src), (&b"answer"[..], addr(Ipv4Addr::new(127, 0, 0, 11), 53)));
}

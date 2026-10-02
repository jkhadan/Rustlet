//! `net_`: rustlet-net's host side on its own, in throwaway network
//! namespaces (`rustlet_itests::net`): pinning, a bridge and a container's
//! veth, the firewall's NAT, published ports and guards against a
//! simulated LAN (IPv4, and IPv6 on a dual-stack bridge), and the DNS port
//! redirect. Nothing here touches the real host's network. Run with
//! `cargo xtask itest -- net_`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};
use std::os::fd::AsFd;
use std::path::Path;
use std::time::Duration;

use rustlet_itests::net::{PinDir, TestLan, TestNetns, fetch, is_mounted, serve};
use rustlet_itests::{PRIVILEGED, host_mounts};
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
    let path;
    {
        let dir = PinDir::new("pin");
        path = dir.path.clone();
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
    // (The other tests here run alongside, with pins of their own.)
    let ours: Vec<_> = host_mounts().into_iter().filter(|(mp, _, _)| Path::new(mp).starts_with(&path)).collect();
    assert!(ours.is_empty(), "left mounted: {ours:?}");
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
    host.run(|| link::ensure_bridge("rustlet0", GATEWAY, 24, None)).unwrap();
    // Twice: the setup is idempotent.
    host.run(|| link::ensure_bridge("rustlet0", GATEWAY, 24, None)).unwrap();
    let ns = netns::open(&pin).unwrap();
    let ep = link::Endpoint {
        host_ifname: "rlvtest0000001",
        alias: "rustlet test c1",
        ifname: "eth0",
        bridge: "rustlet0",
        address: C1,
        prefix_len: 24,
        address6: None,
        mac: ipam::mac_for(C1),
    };
    host.run(|| link::attach(ns.as_fd(), &ep)).unwrap();
    host.run(|| link::set_default_routes(ns.as_fd(), Some((GATEWAY, "eth0")), None)).unwrap();
    // A link of the host end's name that isn't the container's is never
    // replaced: the same endpoint under another alias fails, and leaves it.
    let other = link::Endpoint { alias: "rustlet someone else", ..ep };
    let e = host.run(|| link::attach(ns.as_fd(), &other)).unwrap_err().to_string();
    assert!(e.contains("isn't this container's"), "{e}");
    assert!(c1.run(|| RtNetlink::open().unwrap().link_by_name("eth0").unwrap()).is_some(), "eth0 is still there");
    assert_eq!(host.run(|| link::links_tagged("rustlet test")).unwrap(), ["rlvtest0000001"]);
    let rules = Ruleset {
        table: "rustlet".into(),
        networks: vec![NetworkRules {
            bridge: "rustlet0".into(),
            subnet: "10.89.0.0/24".parse().unwrap(),
            subnet6: None,
            internal: false,
        }],
        ports: vec![PortRule {
            protocol: "tcp".into(),
            host_ip: None,
            host_port: 8080,
            container_ip: C1.into(),
            container_port: 80,
            container: "c1".into(),
        }],
        isolate_forwarding: true,
        isolate_forwarding6: false,
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
    assert!(routes.iter().any(|r| r.dst_len == 0 && r.gateway == Some(GATEWAY.into())), "{routes:?}");

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
    //    And its own published port through the host's address (hairpin:
    //    DNAT, then masqueraded to the bridge's address on the way back
    //    out of the bridge, so that the answer returns through the host).
    assert_eq!(fetch(&c1, addr(TestLan::HOST_IP, 8080), b"").unwrap(), "container 10.89.0.1");
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

/// The same on a dual-stack bridge, over IPv6: the container's address
/// usable at once and ignoring router advertisements, NAT66 out, a
/// published port DNATed to its IPv6 address from the LAN and from the
/// host's own address (not `::1`, the proxy's), and the LAN kept from the
/// container's IPv6 address. The default route moves when asked.
#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn net_ipv6_bridge_nat66_published_ports_and_guards() {
    let world = TestLan::new();
    let host = &world.host;
    let dir = PinDir::new("nat6");
    let pin = dir.pin("c6");
    netns::create(&pin, || {
        link::loopback_up()?;
        sysctl::set_netns_defaults()
    })
    .unwrap();
    let c6 = TestNetns::from_pin(&pin);
    let (gw, ip) = (Ipv4Addr::new(10, 89, 5, 1), Ipv4Addr::new(10, 89, 5, 2));
    let gw6: Ipv6Addr = "fd00:89:0:5::1".parse().unwrap();
    let ip6: Ipv6Addr = "fd00:89:0:5::2".parse().unwrap();
    host.sysctl("net.ipv6.conf.all.forwarding", "1");
    host.run(|| link::ensure_bridge("rlb6test", gw, 24, Some((gw6, 64)))).unwrap();
    host.run(|| link::ensure_bridge("rlb6test", gw, 24, Some((gw6, 64)))).unwrap();
    let ns = netns::open(&pin).unwrap();
    let ep = link::Endpoint {
        host_ifname: "rlvtest6000001",
        alias: "rustlet test c6",
        ifname: "eth0",
        bridge: "rlb6test",
        address: ip,
        prefix_len: 24,
        address6: Some((ip6, 64)),
        mac: ipam::mac_for(ip),
    };
    host.run(|| link::attach(ns.as_fd(), &ep)).unwrap();
    host.run(|| link::set_default_routes(ns.as_fd(), Some((gw, "eth0")), Some((gw6, "eth0")))).unwrap();
    let rules = Ruleset {
        table: "rustlet".into(),
        networks: vec![NetworkRules {
            bridge: "rlb6test".into(),
            subnet: "10.89.5.0/24".parse().unwrap(),
            subnet6: Some("fd00:89:0:5::/64".parse().unwrap()),
            internal: false,
        }],
        ports: vec![PortRule {
            protocol: "tcp".into(),
            host_ip: None,
            host_port: 8086,
            container_ip: ip6.into(),
            container_port: 80,
            container: "c6".into(),
        }],
        isolate_forwarding: false,
        isolate_forwarding6: true,
    };
    host.run(|| rules.apply()).unwrap();

    // Inside: the address, router advertisements ignored, new interfaces
    // without IPv6 until they are given some, the default route.
    let (addrs, routes, accept_ra, default_off) = c6.run(|| {
        let mut nl = RtNetlink::open().unwrap();
        let read = |p: &str| sysctl::read(Path::new(p)).unwrap();
        (
            nl.addresses().unwrap(),
            nl.routes().unwrap(),
            read("/proc/sys/net/ipv6/conf/eth0/accept_ra"),
            read("/proc/sys/net/ipv6/conf/default/disable_ipv6"),
        )
    });
    assert!(addrs.iter().any(|a| a.address == IpAddr::V6(ip6) && a.prefix_len == 64), "{addrs:?}");
    assert!(routes.iter().any(|r| r.dst_len == 0 && r.gateway == Some(gw6.into())), "{routes:?}");
    assert_eq!((accept_ra.as_str(), default_off.as_str()), ("0", "1"));

    let v6 = |ip: Ipv6Addr, port| SocketAddr::new(IpAddr::V6(ip), port);
    serve(&c6, v6(Ipv6Addr::UNSPECIFIED, 80), "c6");
    serve(&world.lan, v6(TestLan::LAN_IP6, 9000), "lan");
    // 1. The LAN reaches the published port over IPv6 (DNAT to the
    //    container's IPv6 address), which sees the client's own address,
    //    at once: the bridge's link-local address needs no duplicate
    //    address detection first (`sysctl::enable_ipv6`).
    assert_eq!(fetch(&world.lan, v6(TestLan::HOST_IP6, 8086), b"").unwrap(), "c6 2001:db8::1");
    // 2. The host through its own address; not through ::1 (the proxy's).
    assert_eq!(fetch(host, v6(TestLan::HOST_IP6, 8086), b"").unwrap(), "c6 2001:db8::2");
    assert!(fetch(host, v6(Ipv6Addr::LOCALHOST, 8086), b"").is_err());
    // 3. The container reaches the LAN, masqueraded as the host (NAT66),
    //    and its own published port through the host's address (hairpin).
    assert_eq!(fetch(&c6, v6(TestLan::LAN_IP6, 9000), b"").unwrap(), "lan 2001:db8::2");
    assert_eq!(fetch(&c6, v6(TestLan::HOST_IP6, 8086), b"").unwrap(), "c6 fd00:89:0:5::1");
    // 4. The LAN can't reach the container's IPv6 address, even with a route.
    world.lan.route("fd00:89::".parse::<Ipv6Addr>().unwrap(), 48, TestLan::HOST_IP6);
    assert!(fetch(&world.lan, v6(ip6, 80), b"").is_err());
    host.run(|| {
        run_nft(&serde_json::json!({"nftables": [{"flush": {"chain": {"family": "inet", "table": "rustlet", "name": "raw_prerouting"}}}]}))
    })
    .unwrap();
    assert!(fetch(&world.lan, v6(ip6, 80), b"").is_err(), "the forward chain drops it too");
    // 5. No default routes at all, then back.
    host.run(|| link::set_default_routes(ns.as_fd(), None, None)).unwrap();
    let routes = c6.run(|| RtNetlink::open().unwrap().routes().unwrap());
    assert!(!routes.iter().any(|r| r.dst_len == 0 && r.table == 254), "{routes:?}");
    assert!(fetch(&c6, v6(TestLan::LAN_IP6, 9000), b"").is_err(), "no way out without a route");
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

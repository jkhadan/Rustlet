//! The firewall: one nftables table, `inet rustlet`, regenerated whole from
//! the daemon's state whenever a network or a published port changes.
//!
//! ```text
//!  packet in ─► raw prerouting ──► nat prerouting ──► routing ─┬─► forward ──► nat postrouting ─► out
//!               (-300)             (-100: DNAT -p)             │   (filter)    (100: masquerade)
//!               drop: to a subnet                              └─► local ◄── nat output (-100: DNAT -p
//!               not via its bridge                                            for the host's own clients)
//! ```
//!
//! | chain | rules |
//! |---|---|
//! | `raw_prerouting` | a packet for a container subnet (IPv4 or IPv6) that didn't arrive on that subnet's bridge is dropped before anything else sees it (the LAN can't route to `10.89.0.0/24` through us; containers of another network can't either). As Docker 28 does. |
//! | `prerouting` (nat) | published ports: a packet for a local address (or the given host address) and the port is rewritten to the container's address and port, from wherever it came, a container on the same bridge included (hairpin traffic, see `postrouting`); IPv4 to its IPv4 address and, on a network with IPv6, IPv6 to its IPv6 address |
//! | `output` (nat) | the same for the host's own connections to one of its non-loopback addresses (`127.0.0.1` and `::1` are the proxy's: DNAT to a container would need `route_localnet`) |
//! | `postrouting` (nat) | traffic from a subnet that leaves through anything but its bridge is masqueraded, IPv6 as well as IPv4 (except internal networks); and so is DNATed traffic that goes back out of the bridge it came from (hairpin: a container reaching a port published on its own network through the host's address), to the bridge's address, so that the server's answer comes back through the host and is un-NATed on the way |
//! | `forward` (filter) | to a bridge: only replies (`ct state established,related`), published ports (`ct status dnat`) and traffic within the bridge; from a bridge: out (internal networks: nowhere); and for each family whose forwarding Rustlets turned on, nothing else of that family is forwarded at all |
//!
//! The whole table is replaced in one `nft -j -f -` transaction: "add" (so
//! the "delete" can't fail), "delete", then the full definition. Either the
//! new table is in place or the old one still is; there is never a moment
//! without the guards. The input is JSON (libnftables-json(5)), generated
//! with `serde_json`, so no rule is ever assembled from strings.

use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::process::{Command, Stdio};

use serde_json::{Value, json};

use crate::error::{Context, Error, Result};
use crate::ipam::{Subnet, Subnet6};

/// The default table name (`inet rustlet`).
pub const TABLE: &str = "rustlet";

/// The table each container network namespace on a user-defined network
/// gets, which redirects the embedded DNS server's port 53.
pub const DNS_TABLE: &str = "rustlet_dns";

/// The embedded DNS server's address.
pub const DNS_ADDR: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 11);

/// What the table is generated from.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ruleset {
    /// `rustlet` (`inet rustlet`).
    pub table: String,
    pub networks: Vec<NetworkRules>,
    pub ports: Vec<PortRule>,
    /// Rustlets turned IPv4 forwarding on (it was off): forward no IPv4
    /// that isn't to or from one of its bridges, as Docker sets its
    /// `FORWARD` chain's policy to `DROP` then.
    pub isolate_forwarding: bool,
    /// The same for IPv6 (Rustlets turned it on for an IPv6 network).
    pub isolate_forwarding6: bool,
}

/// One network's bridge and subnets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkRules {
    pub bridge: String,
    pub subnet: Subnet,
    /// Its IPv6 subnet, on a network with IPv6.
    pub subnet6: Option<Subnet6>,
    /// No masquerading, nothing forwarded out.
    pub internal: bool,
}

/// One published port that DNAT handles (not one on a loopback address:
/// those are the proxy's alone), for one family: the container address's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortRule {
    /// `tcp` or `udp`.
    pub protocol: String,
    /// `None`: any local address of the container address's family. A
    /// host address of the other family makes no rule.
    pub host_ip: Option<IpAddr>,
    pub host_port: u16,
    /// IPv4 or IPv6: the rule is of that family.
    pub container_ip: IpAddr,
    pub container_port: u16,
    /// For the rule's comment: whose port it is.
    pub container: String,
}

impl Ruleset {
    /// The nftables JSON that replaces the table with this ruleset.
    pub fn to_json(&self) -> Value {
        let t = self.table.as_str();
        let mut cmds = vec![
            json!({"add": {"table": {"family": "inet", "name": t}}}),
            json!({"delete": {"table": {"family": "inet", "name": t}}}),
            json!({"add": {"table": {"family": "inet", "name": t}}}),
        ];
        let chain = |name: &str, typ: &str, hook: &str, prio: i32| {
            json!({"add": {"chain": {
                "family": "inet", "table": t, "name": name,
                "type": typ, "hook": hook, "prio": prio, "policy": "accept",
            }}})
        };
        cmds.push(chain("raw_prerouting", "filter", "prerouting", -300));
        cmds.push(chain("prerouting", "nat", "prerouting", -100));
        cmds.push(chain("output", "nat", "output", -100));
        cmds.push(chain("postrouting", "nat", "postrouting", 100));
        cmds.push(chain("forward", "filter", "forward", 0));
        let rule = |chain: &str, expr: Vec<Value>, comment: String| json!({"add": {"rule": {"family": "inet", "table": t, "chain": chain, "expr": expr, "comment": comment}}});

        // (A network's IPv4 subnet, then its IPv6 one, as `(family, prefix,
        // text)`.)
        let subnets = |n: &NetworkRules| {
            let v4 = (Family::V4, prefix(n.subnet.network().into(), n.subnet.prefix_len()), n.subnet.to_string());
            let v6 = n.subnet6.map(|s| (Family::V6, prefix(s.network().into(), s.prefix_len()), s.to_string()));
            std::iter::once(v4).chain(v6)
        };

        for n in &self.networks {
            for (family, net, text) in subnets(n) {
                cmds.push(rule(
                    "raw_prerouting",
                    vec![
                        family.only(),
                        family.addr_match("daddr", "==", net),
                        ifname("iifname", "!=", &n.bridge),
                        verdict("drop"),
                    ],
                    format!("{text} is only reachable through {}", n.bridge),
                ));
            }
        }

        for p in &self.ports {
            let family = Family::of(p.container_ip);
            if p.host_ip.is_some_and(|ip| Family::of(ip) != family) {
                continue;
            }
            let to = || json!({"dnat": {"family": family.nat(), "addr": p.container_ip.to_string(), "port": p.container_port}});
            let dport = port_match(&p.protocol, p.host_port);
            let what = format!(
                "{} {}/{} -> {}",
                p.container,
                p.host_port,
                p.protocol,
                std::net::SocketAddr::new(p.container_ip, p.container_port)
            );
            let local = || match p.host_ip {
                Some(ip) => family.addr_match("daddr", "==", json!(ip.to_string())),
                None => fib_local(),
            };
            cmds.push(rule("prerouting", vec![family.only(), local(), dport.clone(), to()], what.clone()));
            let mut out = vec![family.only(), local()];
            if p.host_ip.is_none() {
                out.push(family.addr_match("daddr", "!=", family.loopback()));
            }
            out.extend([dport, to()]);
            cmds.push(rule("output", out, what));
        }

        for n in self.networks.iter().filter(|n| !n.internal) {
            for (family, net, text) in subnets(n) {
                cmds.push(rule(
                    "postrouting",
                    vec![
                        family.only(),
                        family.addr_match("saddr", "==", net.clone()),
                        ifname("oifname", "!=", &n.bridge),
                        json!({"masquerade": null}),
                    ],
                    format!("{text} out"),
                ));
                // Hairpin: without it, the server would answer the client
                // straight across the bridge, from its own address rather
                // than the one the client connected to, and the client
                // would drop the answer. Only DNATed traffic: the rest of
                // what stays on a bridge never reaches these hooks (it is
                // switched, not routed), unless br_netfilter makes it, and
                // then it must keep its addresses.
                cmds.push(rule(
                    "postrouting",
                    vec![
                        family.only(),
                        family.addr_match("saddr", "==", net),
                        ifname("oifname", "==", &n.bridge),
                        json!({"match": {"op": "in", "left": {"ct": {"key": "status"}}, "right": "dnat"}}),
                        json!({"masquerade": null}),
                    ],
                    format!("{text} hairpin"),
                ));
            }
        }

        // Every rule about what may reach a bridge comes before any that lets
        // traffic leave one: a packet from bridge A to bridge B must meet B's
        // drop before A's accept.
        for n in &self.networks {
            let to_bridge = || ifname("oifname", "==", &n.bridge);
            cmds.push(rule(
                "forward",
                vec![
                    to_bridge(),
                    json!({"match": {"op": "in", "left": {"ct": {"key": "state"}}, "right": ["established", "related"]}}),
                    verdict("accept"),
                ],
                format!("replies to {}", n.bridge),
            ));
            if !n.internal {
                cmds.push(rule(
                    "forward",
                    vec![
                        to_bridge(),
                        json!({"match": {"op": "in", "left": {"ct": {"key": "status"}}, "right": "dnat"}}),
                        verdict("accept"),
                    ],
                    format!("published ports on {}", n.bridge),
                ));
            }
            cmds.push(rule(
                "forward",
                vec![ifname("iifname", "==", &n.bridge), to_bridge(), verdict("accept")],
                format!("within {}", n.bridge),
            ));
            cmds.push(rule("forward", vec![to_bridge(), verdict("drop")], format!("nothing else into {}", n.bridge)));
        }
        for n in &self.networks {
            let (v, why) = if n.internal { ("drop", "internal: no way out") } else { ("accept", "out") };
            cmds.push(rule(
                "forward",
                vec![ifname("iifname", "==", &n.bridge), verdict(v)],
                format!("{} {why}", n.bridge),
            ));
        }
        for (family, isolate) in [(Family::V4, self.isolate_forwarding), (Family::V6, self.isolate_forwarding6)] {
            if isolate {
                cmds.push(rule(
                    "forward",
                    vec![family.only(), verdict("drop")],
                    format!(
                        "Rustlets turned {} forwarding on: nothing but its own bridges is forwarded",
                        family.name()
                    ),
                ));
            }
        }
        json!({"nftables": cmds})
    }

    /// Replaces the table in the caller's network namespace.
    pub fn apply(&self) -> Result<()> {
        run_nft(&self.to_json())
    }
}

/// The table of a container's network namespace that sends its DNS traffic
/// for `127.0.0.11:53` to the ports the embedded server's sockets have, as
/// Docker's resolver does: the server can't own port 53 itself, or a
/// program in the container couldn't bind `0.0.0.0:53`. Replaced whole,
/// like the main table; applied from a thread inside that namespace.
pub fn dns_redirect(udp_port: u16, tcp_port: u16) -> Value {
    let t = DNS_TABLE;
    let addr = DNS_ADDR.to_string();
    let redirect = |proto: &str, port: u16| {
        json!({"add": {"rule": {"family": "ip", "table": t, "chain": "output", "expr": [
            {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}}, "right": addr}},
            {"match": {"op": "==", "left": {"payload": {"protocol": proto, "field": "dport"}}, "right": 53}},
            {"dnat": {"addr": addr, "port": port}},
        ]}}})
    };
    json!({"nftables": [
        {"add": {"table": {"family": "ip", "name": t}}},
        {"delete": {"table": {"family": "ip", "name": t}}},
        {"add": {"table": {"family": "ip", "name": t}}},
        {"add": {"chain": {"family": "ip", "table": t, "name": "output", "type": "nat", "hook": "output", "prio": -100, "policy": "accept"}}},
        redirect("udp", udp_port),
        redirect("tcp", tcp_port),
    ]})
}

/// Removes [`dns_redirect`]'s table (the container left its last
/// user-defined network); applied from a thread inside the namespace.
/// Fine if it isn't there.
pub fn remove_dns_redirect() -> Result<()> {
    match run_nft(&json!({"nftables": [{"delete": {"table": {"family": "ip", "name": DNS_TABLE}}}]})) {
        Err(Error::Nft(e)) if e.contains("No such file or directory") => Ok(()),
        other => other,
    }
}

/// Applies nftables JSON in the caller's network namespace.
pub fn run_nft(json: &Value) -> Result<()> {
    let mut child = Command::new(nft())
        .args(["-j", "-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("run nft")?;
    let input = serde_json::to_vec(json).expect("JSON serializes");
    child.stdin.take().expect("piped").write_all(&input).context("write the ruleset to nft")?;
    let out = child.wait_with_output().context("wait for nft")?;
    if !out.status.success() {
        return Err(Error::Nft(String::from_utf8_lossy(&out.stderr).trim().to_owned()));
    }
    Ok(())
}

/// Deletes the table `inet <name>` if it exists.
pub fn delete_table(name: &str) -> Result<()> {
    match run_nft(&json!({"nftables": [{"delete": {"table": {"family": "inet", "name": name}}}]})) {
        Err(Error::Nft(e)) if e.contains("No such file or directory") => Ok(()),
        other => other,
    }
}

/// `nft`: `/usr/sbin/nft`, else whatever `PATH` finds.
fn nft() -> &'static str {
    if std::path::Path::new("/usr/sbin/nft").exists() { "/usr/sbin/nft" } else { "nft" }
}

/// An address family, as the rules need to say it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Family {
    V4,
    V6,
}

impl Family {
    fn of(ip: IpAddr) -> Family {
        if ip.is_ipv4() { Family::V4 } else { Family::V6 }
    }

    /// `meta nfproto ipv4`: the rule is for this family's packets only (an
    /// `inet` table sees both).
    fn only(self) -> Value {
        let proto = match self {
            Family::V4 => "ipv4",
            Family::V6 => "ipv6",
        };
        json!({"match": {"op": "==", "left": {"meta": {"key": "nfproto"}}, "right": proto}})
    }

    /// `ip daddr == …` / `ip6 daddr == …`.
    fn addr_match(self, field: &str, op: &str, right: Value) -> Value {
        json!({"match": {"op": op, "left": {"payload": {"protocol": self.payload(), "field": field}}, "right": right}})
    }

    fn payload(self) -> &'static str {
        match self {
            Family::V4 => "ip",
            Family::V6 => "ip6",
        }
    }

    /// The `family` of a `dnat` in an `inet` table.
    fn nat(self) -> &'static str {
        self.payload()
    }

    /// The loopback block: `127.0.0.0/8`, `::1`.
    fn loopback(self) -> Value {
        match self {
            Family::V4 => prefix(Ipv4Addr::new(127, 0, 0, 0).into(), 8),
            Family::V6 => json!("::1"),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Family::V4 => "IPv4",
            Family::V6 => "IPv6",
        }
    }
}

fn ifname(key: &str, op: &str, name: &str) -> Value {
    json!({"match": {"op": op, "left": {"meta": {"key": key}}, "right": name}})
}

fn prefix(addr: IpAddr, len: u8) -> Value {
    json!({"prefix": {"addr": addr.to_string(), "len": len}})
}

fn fib_local() -> Value {
    json!({"match": {"op": "==", "left": {"fib": {"result": "type", "flags": ["daddr"]}}, "right": "local"}})
}

fn port_match(protocol: &str, port: u16) -> Value {
    json!({"match": {"op": "==", "left": {"payload": {"protocol": protocol, "field": "dport"}}, "right": port}})
}

fn verdict(v: &str) -> Value {
    json!({v: null})
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Ruleset {
        Ruleset {
            table: TABLE.into(),
            networks: vec![
                NetworkRules {
                    bridge: "rustlet0".into(),
                    subnet: "10.89.0.0/24".parse().unwrap(),
                    subnet6: None,
                    internal: false,
                },
                NetworkRules {
                    bridge: "rlb0123456789ab".into(),
                    subnet: "10.89.1.0/24".parse().unwrap(),
                    subnet6: None,
                    internal: true,
                },
                NetworkRules {
                    bridge: "rlbfedcba987654".into(),
                    subnet: "10.89.2.0/24".parse().unwrap(),
                    subnet6: Some("fd00:89:0:2::/64".parse().unwrap()),
                    internal: false,
                },
            ],
            ports: vec![
                PortRule {
                    protocol: "tcp".into(),
                    host_ip: None,
                    host_port: 8080,
                    container_ip: Ipv4Addr::new(10, 89, 0, 2).into(),
                    container_port: 80,
                    container: "web".into(),
                },
                PortRule {
                    protocol: "udp".into(),
                    host_ip: Some(Ipv4Addr::new(192, 168, 50, 143).into()),
                    host_port: 5353,
                    container_ip: Ipv4Addr::new(10, 89, 0, 3).into(),
                    container_port: 53,
                    container: "dns".into(),
                },
                PortRule {
                    protocol: "tcp".into(),
                    host_ip: None,
                    host_port: 8443,
                    container_ip: "fd00:89:0:2::2".parse().unwrap(),
                    container_port: 443,
                    container: "web6".into(),
                },
            ],
            isolate_forwarding: true,
            isolate_forwarding6: true,
        }
    }

    #[test]
    fn the_whole_table_as_json() {
        insta::assert_json_snapshot!(sample().to_json());
    }

    #[test]
    fn replacement_is_one_transaction_that_cant_fail_on_a_missing_table() {
        let json = sample().to_json();
        let cmds = json["nftables"].as_array().unwrap();
        assert!(cmds[0]["add"]["table"].is_object());
        assert!(cmds[1]["delete"]["table"].is_object());
        assert!(cmds[2]["add"]["table"].is_object());
    }

    #[test]
    fn forward_drops_into_a_bridge_come_before_any_way_out() {
        let json = sample().to_json();
        let forward: Vec<&Value> = json["nftables"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|c| c["add"]["rule"].as_object().filter(|r| r["chain"] == "forward").map(|_| &c["add"]["rule"]))
            .collect();
        let comment = |r: &Value| r["comment"].as_str().unwrap().to_owned();
        let last_drop_in = forward.iter().rposition(|r| comment(r).starts_with("nothing else into")).unwrap();
        let first_out =
            forward.iter().position(|r| comment(r).ends_with(" out") || comment(r).contains("no way out")).unwrap();
        assert!(last_drop_in < first_out, "{:?}", forward.iter().map(|r| comment(r)).collect::<Vec<_>>());
        let last: Vec<String> = forward[forward.len() - 2..].iter().map(|r| comment(r)).collect();
        assert_eq!(
            last,
            [
                "Rustlets turned IPv4 forwarding on: nothing but its own bridges is forwarded",
                "Rustlets turned IPv6 forwarding on: nothing but its own bridges is forwarded"
            ]
        );
        // Each for its own family only: IPv6 forwarding the host did before
        // Rustlets (a router) goes on when only IPv4 was Rustlets' doing.
        let only_v4 = Ruleset { isolate_forwarding6: false, ..sample() }.to_json().to_string();
        assert!(only_v4.contains("IPv4 forwarding on") && !only_v4.contains("IPv6 forwarding on"));
    }

    #[test]
    fn internal_networks_are_not_masqueraded() {
        let json = sample().to_json().to_string();
        assert!(json.contains("10.89.0.0/24 out") && json.contains("10.89.0.0/24 hairpin"));
        assert!(!json.contains("10.89.1.0/24 out") && !json.contains("10.89.1.0/24 hairpin"));
        assert!(json.contains("fd00:89:0:2::/64 out") && json.contains("fd00:89:0:2::/64 hairpin"), "NAT66 too");
    }

    #[test]
    fn hairpin_traffic_is_dnated_and_masqueraded() {
        let json = sample().to_json();
        let rules: Vec<&Value> = json["nftables"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|c| c["add"]["rule"].as_object().map(|_| &c["add"]["rule"]))
            .collect();
        // A published port's DNAT applies whatever the packet came in on.
        let dnat = rules.iter().find(|r| r["chain"] == "prerouting").unwrap();
        assert!(!dnat.to_string().contains("iifname"), "{dnat}");
        // Back out of the bridge it came from: masqueraded, if DNATed only.
        let hairpin = rules.iter().find(|r| r["comment"] == "10.89.0.0/24 hairpin").unwrap().to_string();
        assert!(hairpin.contains(r#""right":"rustlet0""#) && hairpin.contains(r#""op":"==""#), "{hairpin}");
        assert!(hairpin.contains(r#""right":"dnat""#), "{hairpin}");
    }

    #[test]
    fn ipv6_networks_get_guards_and_ports_of_their_own_family() {
        let json = sample().to_json();
        let rules: Vec<&Value> = json["nftables"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|c| c["add"]["rule"].as_object().map(|_| &c["add"]["rule"]))
            .collect();
        let by_comment = |c: &str| rules.iter().filter(|r| r["comment"] == c).count();
        assert_eq!(by_comment("fd00:89:0:2::/64 is only reachable through rlbfedcba987654"), 1);
        // An IPv6 port: a DNAT to the IPv6 address, in prerouting and output.
        let v6 = rules.iter().filter(|r| r["comment"] == "web6 8443/tcp -> [fd00:89:0:2::2]:443").count();
        assert_eq!(v6, 2);
        // A host address of the other family makes no rule.
        let mixed = Ruleset {
            ports: vec![PortRule { host_ip: Some(Ipv4Addr::LOCALHOST.into()), ..sample().ports[2].clone() }],
            ..sample()
        };
        assert!(!mixed.to_json().to_string().contains("web6"));
    }

    #[test]
    fn the_dns_redirect() {
        insta::assert_json_snapshot!(dns_redirect(40001, 40002));
    }
}

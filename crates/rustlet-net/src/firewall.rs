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
//! | `raw_prerouting` | a packet for a container subnet that didn't arrive on that subnet's bridge is dropped before anything else sees it (the LAN can't route to `10.89.0.0/24` through us; containers of another network can't either). As Docker 28 does. |
//! | `prerouting` (nat) | published ports: a packet for a local address (or the given host address) and the port is rewritten to the container's address and port, unless it came from the port's own bridge (hairpin traffic goes to the proxy instead) |
//! | `output` (nat) | the same for the host's own connections to one of its non-loopback addresses (`127.0.0.1` is the proxy's: DNAT to a container would need `route_localnet`) |
//! | `postrouting` (nat) | traffic from a subnet that leaves through anything but its bridge is masqueraded (except internal networks) |
//! | `forward` (filter) | to a bridge: only replies (`ct state established,related`), published ports (`ct status dnat`) and traffic within the bridge; from a bridge: out (internal networks: nowhere); and if Rustlets turned IP forwarding on, nothing else is forwarded at all |
//!
//! The whole table is replaced in one `nft -j -f -` transaction: "add" (so
//! the "delete" can't fail), "delete", then the full definition. Either the
//! new table is in place or the old one still is; there is never a moment
//! without the guards. The input is JSON (libnftables-json(5)), generated
//! with `serde_json`, so no rule is ever assembled from strings.

use std::io::Write;
use std::net::Ipv4Addr;
use std::process::{Command, Stdio};

use serde_json::{Value, json};

use crate::error::{Context, Error, Result};
use crate::ipam::Subnet;

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
    /// Rustlets turned IP forwarding on (it was off): forward nothing that
    /// isn't to or from one of its bridges, as Docker sets its `FORWARD`
    /// chain's policy to `DROP` then.
    pub isolate_forwarding: bool,
}

/// One network's bridge and subnet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkRules {
    pub bridge: String,
    pub subnet: Subnet,
    /// No masquerading, nothing forwarded out.
    pub internal: bool,
}

/// One published port that DNAT handles (not one on a loopback address:
/// those are the proxy's alone).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortRule {
    /// `tcp` or `udp`.
    pub protocol: String,
    /// `None`: any local address.
    pub host_ip: Option<Ipv4Addr>,
    pub host_port: u16,
    pub container_ip: Ipv4Addr,
    pub container_port: u16,
    /// The bridge the container is on.
    pub bridge: String,
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

        for n in &self.networks {
            cmds.push(rule(
                "raw_prerouting",
                vec![
                    ipv4(),
                    ip_match("daddr", "==", subnet(&n.subnet)),
                    ifname("iifname", "!=", &n.bridge),
                    verdict("drop"),
                ],
                format!("{} is only reachable through {}", n.subnet, n.bridge),
            ));
        }

        for p in &self.ports {
            let to = || json!({"dnat": {"family": "ip", "addr": p.container_ip.to_string(), "port": p.container_port}});
            let dport = port_match(&p.protocol, p.host_port);
            let what =
                format!("{} {}/{} -> {}:{}", p.container, p.host_port, p.protocol, p.container_ip, p.container_port);
            let local = || match p.host_ip {
                Some(ip) => ip_match("daddr", "==", json!(ip.to_string())),
                None => fib_local(),
            };
            cmds.push(rule(
                "prerouting",
                vec![ipv4(), ifname("iifname", "!=", &p.bridge), local(), dport.clone(), to()],
                what.clone(),
            ));
            let mut out = vec![ipv4(), local()];
            if p.host_ip.is_none() {
                out.push(ip_match("daddr", "!=", json!({"prefix": {"addr": "127.0.0.0", "len": 8}})));
            }
            out.extend([dport, to()]);
            cmds.push(rule("output", out, what));
        }

        for n in self.networks.iter().filter(|n| !n.internal) {
            cmds.push(rule(
                "postrouting",
                vec![
                    ipv4(),
                    ip_match("saddr", "==", subnet(&n.subnet)),
                    ifname("oifname", "!=", &n.bridge),
                    json!({"masquerade": null}),
                ],
                format!("{} out", n.subnet),
            ));
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
        if self.isolate_forwarding {
            cmds.push(rule(
                "forward",
                vec![verdict("drop")],
                "Rustlets turned forwarding on: nothing but its own bridges is forwarded".into(),
            ));
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

fn ipv4() -> Value {
    json!({"match": {"op": "==", "left": {"meta": {"key": "nfproto"}}, "right": "ipv4"}})
}

fn ifname(key: &str, op: &str, name: &str) -> Value {
    json!({"match": {"op": op, "left": {"meta": {"key": key}}, "right": name}})
}

fn ip_match(field: &str, op: &str, right: Value) -> Value {
    json!({"match": {"op": op, "left": {"payload": {"protocol": "ip", "field": field}}, "right": right}})
}

fn subnet(s: &Subnet) -> Value {
    json!({"prefix": {"addr": s.network().to_string(), "len": s.prefix_len()}})
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
                NetworkRules { bridge: "rustlet0".into(), subnet: "10.89.0.0/24".parse().unwrap(), internal: false },
                NetworkRules {
                    bridge: "rlb0123456789ab".into(),
                    subnet: "10.89.1.0/24".parse().unwrap(),
                    internal: true,
                },
            ],
            ports: vec![
                PortRule {
                    protocol: "tcp".into(),
                    host_ip: None,
                    host_port: 8080,
                    container_ip: Ipv4Addr::new(10, 89, 0, 2),
                    container_port: 80,
                    bridge: "rustlet0".into(),
                    container: "web".into(),
                },
                PortRule {
                    protocol: "udp".into(),
                    host_ip: Some(Ipv4Addr::new(192, 168, 50, 143)),
                    host_port: 5353,
                    container_ip: Ipv4Addr::new(10, 89, 0, 3),
                    container_port: 53,
                    bridge: "rustlet0".into(),
                    container: "dns".into(),
                },
            ],
            isolate_forwarding: true,
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
        assert_eq!(
            comment(forward.last().unwrap()),
            "Rustlets turned forwarding on: nothing but its own bridges is forwarded"
        );
    }

    #[test]
    fn internal_networks_are_not_masqueraded() {
        let json = sample().to_json().to_string();
        assert!(json.contains("10.89.0.0/24 out"));
        assert!(!json.contains("10.89.1.0/24 out"));
    }

    #[test]
    fn the_dns_redirect() {
        insta::assert_json_snapshot!(dns_redirect(40001, 40002));
    }
}

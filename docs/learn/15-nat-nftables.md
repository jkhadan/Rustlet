# 15 — NAT and nftables: out, in, and not past the bridge

[Chapter 14](14-veth-bridges-netlink.md) gave each container an address on a bridge:
10.89.0.2 on `rustlet0`. That address means something on this host and
nowhere else. Three things follow. A packet a container sends to the
internet carries a source address nobody out there can answer, so it has
to leave with the host's (**masquerading**). A port published with `-p
8080:80` is a packet for the *host's* address that has to reach the
container's (**DNAT**). And for the host to pass packets between the bridge
and `ens18` at all, IP forwarding has to be on, which, left unguarded,
makes the host a router onto `10.89.0.0/24` for anyone on the LAN who adds
a route to it. This chapter is about the nftables table that does the
first two and prevents the third, the order in which the daemon sets it
up, the userland proxy that handles the traffic NAT can't reach, the same
for IPv6 on networks that have it, and how all of it lives with ufw,
which this host now runs.

Code: [`firewall.rs`](../../crates/rustlet-net/src/firewall.rs) (`Ruleset::to_json`, `Ruleset::apply`,
`run_nft`, `dns_redirect`) and its snapshots in
[`snapshots/`](../../crates/rustlet-net/src/snapshots/), [`sysctl.rs`](../../crates/rustlet-net/src/sysctl.rs) (`enable_forwarding`,
`enable_forwarding6`, `recorded`), [`proxy.rs`](../../crates/rustlet-net/src/proxy.rs) (`Proxy::tcp`, `Proxy::udp`,
`Proxy::close`, `Backend`), [`ufw.rs`](../../crates/rustlet-net/src/ufw.rs) (`manages_host`, `added`, `allow`, `forget`); the
daemon's [`network.rs`](../../crates/rustletd/src/network.rs) (`Networks::setup_host`, `apply_firewall`, `port_rules`,
`sync_ufw`, `publish`, `proxy_pair`, `backend_for`, `retarget`, `bound_socket`, `resume_network`).
Tests: `net_bridge_nat_published_ports_and_guards` and `net_ipv6_bridge_nat66_published_ports_and_guards`
in [`network.rs`](../../tests/tests/network.rs); `dn_published_ports`, `dn_publish_all_and_host_networking`,
`dn_ipv6_networks`, `dn_connect_and_disconnect` and `dn_networking_survives_a_daemon_restart` in
[`daemon_network.rs`](../../tests/tests/daemon_network.rs); the proxy's 19 unit tests; and steps 3, 6 and 9
of [`scripts/smoke.sh`](../../scripts/smoke.sh) on the real host. Design:
[architecture.md §2.5](../architecture.md#25-rustlet-net--host-side-networking) (Firewall, Published ports, ufw).

The transcripts were recorded on 2026-10-02 against the installed service,
kernel 7.0.0-34-generic, nftables 1.0.9, with one container running:
`rustlet run -d --name web -p 8080:80 nginx`, at 10.89.0.2. The host is
192.168.50.143 on `ens18`. `rustlet` is `sudo target/debug/rustlet`;
commands that need root ran through `sudo` or `sudo systemd-run --pipe
--wait`. ufw was enabled on this host later that day (§8); the table of §2,
the hairpin request of §5 and everything about IPv6 and ufw were recorded
after that, with the rules as they are now.

## 1. Netfilter in one picture

Every packet the kernel handles passes **hooks** where netfilter programs
may look at it, change it or drop it:

```text
 in on an interface                                                      out on an interface
   │                                                                              ▲
   ▼                                                                              │
 PREROUTING ──► routing decision ──► FORWARD (not for us) ──────────► POSTROUTING ┘
   raw  -300       │                    filter 0                        srcnat 100
   conntrack -200  │ for us                                                ▲
   dstnat -100     ▼                                                       │
                 INPUT ──► a local socket ··· a local socket ──► OUTPUT ───┘
                                                                  raw, conntrack,
                                                                  dstnat -100, filter
```

At each hook, chains run in order of their **priority**; the names are
the conventional ones. `raw` (−300) comes before connection tracking.
**Connection tracking** (−200) gives every packet a flow, a
`ct state` (`new`, `established`, `related`, …) and, once one is decided,
its NAT. `dstnat` (−100) rewrites destinations. `filter` (0) accepts or
drops. `srcnat` (100) rewrites sources. NAT is decided **once per flow**,
on its first packet; conntrack applies the same rewrite to the rest of it,
and the reverse to its replies. That is why no rule anywhere below handles
replies.

Three flows matter here:

```text
container → internet:  eth0 ─► rustlet0 ─ PREROUTING ─ routing ─ FORWARD ─ POSTROUTING (masquerade) ─► ens18
LAN → host:8080:       ens18 ─ PREROUTING (dnat to 10.89.0.2:80) ─ routing ─ FORWARD ─ POSTROUTING ─► rustlet0
LAN → 10.89.0.2:80:    ens18 ─ PREROUTING (raw: drop)
```

and a fourth, once §5 has explained it:

```text
container → host:8080: rustlet0 ─ PREROUTING (dnat) ─ routing ─ FORWARD ─ POSTROUTING (masquerade: hairpin) ─► rustlet0
```

## 2. One table of our own

nftables organises rules into **tables** (each of a family: `ip`, `ip6`,
`inet` for both, …), tables into **chains** (a *base* chain is attached
to a hook with a type, a priority and a default policy), and chains into
**rules** (matches, then a statement such as `accept`, `drop`, `dnat`).
Several tables can attach chains to the same hook. A packet then meets all
of them, in priority order: a `drop` anywhere is final, while an `accept`
only ends the chain it is in.

Rustlets keeps everything in one table of its own, `inet rustlet`, and
touches no one else's. One command removes it all (`nft delete table inet
rustlet`, step 6 of `scripts/cleanup.sh`), and nothing Rustlets does can
disturb another program's rules, or be disturbed by them, except through
the drop rule just described (ufw's, §8). With one published port it looks like
this:

```text
$ sudo nft list table inet rustlet
table inet rustlet {
	chain raw_prerouting {
		type filter hook prerouting priority raw; policy accept;
		ip daddr 10.89.0.0/24 iifname != "rustlet0" drop comment "10.89.0.0/24 is only reachable through rustlet0"
	}

	chain prerouting {
		type nat hook prerouting priority dstnat; policy accept;
		meta nfproto ipv4 fib daddr type local tcp dport 8080 dnat ip to 10.89.0.2:80 comment "web 8080/tcp -> 10.89.0.2:80"
	}

	chain output {
		type nat hook output priority dstnat; policy accept;
		fib daddr type local ip daddr != 127.0.0.0/8 tcp dport 8080 dnat ip to 10.89.0.2:80 comment "web 8080/tcp -> 10.89.0.2:80"
	}

	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		ip saddr 10.89.0.0/24 oifname != "rustlet0" masquerade comment "10.89.0.0/24 out"
		ip saddr 10.89.0.0/24 oifname "rustlet0" ct status dnat masquerade comment "10.89.0.0/24 hairpin"
	}

	chain forward {
		type filter hook forward priority filter; policy accept;
		oifname "rustlet0" ct state established,related accept comment "replies to rustlet0"
		oifname "rustlet0" ct status dnat accept comment "published ports on rustlet0"
		iifname "rustlet0" oifname "rustlet0" accept comment "within rustlet0"
		oifname "rustlet0" drop comment "nothing else into rustlet0"
		iifname "rustlet0" accept comment "rustlet0 out"
		meta nfproto ipv4 drop comment "Rustlets turned IPv4 forwarding on: nothing but its own bridges is forwarded"
		meta nfproto ipv6 drop comment "Rustlets turned IPv6 forwarding on: nothing but its own bridges is forwarded"
	}
}
```

(The last rule is there because a network with IPv6 had existed on this
host, and Rustlets turned IPv6 forwarding on for it: §6 and §7. This
listing was recorded before the independent review, whose fixes add
`iifname != "lo"` to the guard and, for an internal network, a first
`forward` rule: §5.) The
sections below go through the table chain by chain. Two things about how
it gets there first.

**It is generated as JSON, never as text.** `nft -j -f -` reads the JSON
form of the ruleset (libnftables-json(5)), and
[`Ruleset::to_json`](../../crates/rustlet-net/src/firewall.rs) builds it with `serde_json`, from
typed values (a `Subnet`, an `Ipv4Addr`, a port number), so a rule is
never assembled by pasting strings that could carry an unexpected quote
or keyword. The same table read back as JSON starts like this:

```text
$ sudo nft -j list table inet rustlet
{"nftables": [{"metainfo": {…}}, {"table": {"family": "inet", "name": "rustlet", "handle": 40}},
 {"chain": {"family": "inet", "table": "rustlet", "name": "raw_prerouting", "handle": 1, "type": "filter",
   "hook": "prerouting", "prio": -300, "policy": "accept"}}, …
 {"rule": {"family": "inet", "table": "rustlet", "chain": "raw_prerouting", "handle": 6,
   "comment": "10.89.0.0/24 is only reachable through rustlet0",
   "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}},
                       "right": {"prefix": {"addr": "10.89.0.0", "len": 24}}}},
            {"match": {"op": "!=", "left": {"meta": {"key": "iifname"}}, "right": "rustlet0"}},
            {"drop": null}]}}, …
```

The unit tests snapshot the JSON of a sample ruleset (three networks, one
with IPv6, three ports, forwarding isolated for both families:
[`snapshots/`](../../crates/rustlet-net/src/snapshots/)); each time it changes, the snapshot is also fed to
`nft --check -j -f`, which has the kernel validate the whole transaction
without committing it.

**It is replaced whole, atomically.** The daemon never edits the table.
Whenever a network or a published port changes, it computes the whole
ruleset from its state ([`Networks::apply_firewall`](../../crates/rustletd/src/network.rs): every
network, every running container's ports) and sends it as one
transaction that begins:

```json
{"add": {"table": {"family": "inet", "name": "rustlet"}}},
{"delete": {"table": {"family": "inet", "name": "rustlet"}}},
{"add": {"table": {"family": "inet", "name": "rustlet"}}}, …
```

The first `add` makes sure the `delete` has something to delete; the
`delete` drops the old table, chains, rules and all; the rest builds the
new one. `nft -f` applies a file as a single netlink batch, so either the
new table is in place or the old one still is: there is no instant without
the guards, and no state in which half the rules are old. Rebuilding
rather than diffing also means the table can never drift from the daemon's
idea of it. Applies are serialised by a lock taken while the ruleset is
computed, so two changes can't apply their rulesets in the wrong order.

## 3. Out: masquerading

```text
ip saddr 10.89.0.0/24 oifname != "rustlet0" masquerade comment "10.89.0.0/24 out"
```

A packet from the default network's subnet that leaves through anything but
its own bridge gets the address of the interface it leaves by as its
source. On this host that is `ens18`'s 192.168.50.143; masquerading,
unlike plain SNAT, uses whatever address that interface has now, which
suits a DHCP address. The reply comes back to 192.168.50.143, conntrack
recognises the flow and rewrites its destination back to 10.89.0.2 before
routing, and it is forwarded onto the bridge. `/proc/sys/net/netfilter/nf_conntrack_count`
counted 57 tracked flows when the transcripts were made; this kernel has
no `/proc/net/nf_conntrack` to list them (`conntrack -L` from
conntrack-tools would).

The test plays both ends: a server in the LAN namespace answers with the
address it sees, and from a container it says `lan 192.0.2.2`, the test
host's address, not the container's. Internal networks get no
masquerading rule at all.

**IPv6 too.** A network with IPv6 gets the same rule for its IPv6 subnet:

```text
ip6 saddr fd9a:7b:7e99::/64 oifname != "rlbbd6e48557003" masquerade comment "fd9a:7b:7e99::/64 out"
```

NAT for IPv6 (NAT66) is frowned upon where every machine can have a
global address: IPv6 was meant to end the need for it. But a container
network's unique local addresses ([chapter 14](14-veth-bridges-netlink.md) §7) are routed nowhere
beyond the host, any more than 10.89/16 is, and the LAN's routers don't
know where they are; masquerading lets containers reach IPv6 destinations
without teaching the LAN a route. Docker does the same by default (its
`gateway_mode_ipv6=nat`; a `routed` mode needs the LAN to route the
containers' prefix to the host). In `dn_ipv6_networks` the LAN machine
sees the test host's address, `lan6 2001:db8::2`.

## 4. In: DNAT for published ports

```text
meta nfproto ipv4 fib daddr type local tcp dport 8080 dnat ip to 10.89.0.2:80
```

Left to right:

- `meta nfproto ipv4`: the table is `inet`, so it sees IPv6 too, and this
  rule is for the container's IPv4 address. (`nft` leaves this match out
  when it prints a rule with an `ip` match, which implies it.)
- no `iifname`: wherever the packet came from, a container on the same
  bridge included (that is §5's hairpin traffic).
- `fib daddr type local`: the destination is one of the host's own
  addresses, whichever: what "every address" means for `-p 8080:80`. With
  `-p 192.168.50.143:8080:80` this becomes `ip daddr 192.168.50.143`.
- `tcp dport 8080 dnat ip to 10.89.0.2:80`: rewrite the destination. From
  here on the routing decision sees 10.89.0.2, and the packet is forwarded
  to the bridge.

DNAT leaves the source alone, so the container sees the real client. In
`net_bridge_nat_published_ports_and_guards` the LAN machine's request to the
host's port is answered with `container 192.0.2.1`.

On a network with IPv6 a published port gets a rule of each family, the
IPv6 one to the container's IPv6 address:

```text
meta nfproto ipv6 fib daddr type local tcp dport 8080 dnat ip6 to [fd9a:7b:7e99::2]:80 comment "web 8080/tcp -> [fd9a:7b:7e99::2]:80"
```

so the LAN and the host reach it over either family (`-p [::]:8080:80`, or
an IPv6 address in brackets, publishes on IPv6 alone). A container on
several networks has one set of published ports, which lead to its
addresses on the network its default route goes through, a network of
each family ([chapter 14](14-veth-bridges-netlink.md) §10): when that network is disconnected,
the next ruleset has them lead to the next one.

Packets the host sends itself never pass `prerouting`. The **`output`**
chain has the same rule for them, with one more match, `ip daddr !=
127.0.0.0/8`: a process on the host connecting to 192.168.50.143:8080 is
DNATed; one connecting to 127.0.0.1:8080 is not. A port published on a
loopback address (`-p 127.0.0.1:8080:80`) gets no DNAT rule at all
([`apply_firewall`](../../crates/rustletd/src/network.rs) leaves loopback ports out). Both cases are
the proxy's.

```text
$ curl -s http://127.0.0.1:8080/ | head -4; curl -s http://192.168.50.143:8080/ | head -4
<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
$ curl -s http://localhost:8080/ | grep -o '<title>.*</title>'; curl -s -6 'http://[::1]:8080/' | grep -o '<title>.*</title>'
<title>Welcome to nginx!</title>
<title>Welcome to nginx!</title>
```

The first goes through the proxy, the second through `output`'s DNAT, the
third through either of the proxy's sockets (curl tries `::1` first for
`localhost`), the last through its IPv6 socket.

## 5. What NAT can't reach, and the proxy

Two kinds of traffic to a published port never meet a DNAT rule that
could work for them:

- **To `127.0.0.1`.** Rewriting a loopback destination to 10.89.0.2 is
  only possible with the `route_localnet` sysctl, which makes the kernel
  route packets for `127.0.0.0/8`, and also accept them from the wire.
  Kubernetes' kube-proxy once set it, and neighbours on the LAN could then
  reach services bound to the host's loopback (CVE-2020-8558). Rustlets
  never sets it.
- **Over IPv6, to a container without an IPv6 address** (one on an
  IPv4-only network): NAT can't turn an IPv6 connection into an IPv4 one.
  A container on a network with IPv6 gets DNAT over IPv6 (§4).

A third kind was the proxy's at first, hairpin traffic; the end of this
section tells why it no longer is.

So the daemon also listens on the published port itself and relays what
arrives there, as Docker's `docker-proxy` does
([`proxy.rs`](../../crates/rustlet-net/src/proxy.rs)). The daemon binds the sockets
([`bound_socket`](../../crates/rustletd/src/network.rs)): for IPv6 with `IPV6_V6ONLY`,
so that `[::]:8080` doesn't also try to take the IPv4 port `0.0.0.0:8080`
already has, and for TCP with `SO_REUSEADDR`, so that a port whose last
connections are still in `TIME_WAIT` can be bound again. **Not** for UDP:
there, two sockets that both set `SO_REUSEADDR` may bind the same port,
and a second container publishing `5353/udp` would have bound it beside
the first instead of failing (the independent review found it; the
daemon's `a_udp_port_is_taken_too` test checks it):

```text
$ ss -tlnp 'sport = :8080'
State  Recv-Q Send-Q Local Address:Port Peer Address:PortProcess
LISTEN 0      1024         0.0.0.0:8080      0.0.0.0:*    users:(("rustletd",pid=132185,fd=15))
LISTEN 0      1024            [::]:8080         [::]:*    users:(("rustletd",pid=132185,fd=16))
```

Binding has three more uses. It **reserves** the port: a second container
asking for 8080 fails its start with a conflict, before anything else
happens to it, and so would any other program on the host
(`dn_published_ports` checks the second container, and that it can have the
port once the first one stops). It **chooses** one: `-p 80` and `-P` bind
port 0 and publish whatever the kernel picked; the DNAT rule is written
afterwards, for that port. And it puts the daemon's error message, not a
runtime's, in front of the user.

- **TCP**: each accepted client gets a connection of its own to the
  container (given up after `CONNECT_TIMEOUT`, 5 s; the client is then
  closed), `TCP_NODELAY` on both, and `tokio::io::copy_bidirectional`
  between them. When one side's input ends, the other side's output is
  shut down (a half-close): request/response protocols that close their
  writing side and wait for the answer keep working.
- **UDP**: each client gets a socket of its own, connected to the
  container; what the container answers on it goes back to the client
  through the published socket. A client that has sent nothing for
  `UDP_IDLE` (90 s, docker-proxy's value) is forgotten, at most
  `MAX_UDP_CLIENTS` (1024) are kept, and datagrams from more are dropped.

**Answering from the right address.** A UDP socket bound to `0.0.0.0` or
`[::]` sends from whichever address the kernel picks for the route back:
to a client that wrote to one of the host's addresses, perhaps another (a
hairpin client, while that was the proxy's, got the bridge's 10.89.0.1
instead of the 192.168.50.143 it wrote to); over IPv6, perhaps one of the
host's temporary addresses. A client takes such an answer for somebody else's (a connected
client socket never even sees it). So the proxy asks the kernel for each
datagram's destination (`IP_PKTINFO`, `IPV6_PKTINFO` on the published
socket) and sends each answer with that address as its source, in a
control message:

```rust
Some(IpAddr::V4(ip)) => {
    let ip = libc::in_addr { s_addr: u32::from(ip).to_be() };
    v4 = libc::in_pktinfo { ipi_ifindex: 0, ipi_spec_dst: ip, ipi_addr: libc::in_addr { s_addr: 0 } };
    Some(ControlMessage::Ipv4PacketInfo(&v4))
}
…
Ok(sendmsg(socket.as_raw_fd(), &iov, source.as_slice(), MsgFlags::empty(), Some(&to))?)
```

A client is therefore its address *and* the address of ours it sent to.
docker-proxy does the same; the proxy's author found the problem on this
host, which has two global IPv6 addresses and temporary addresses
turned on.

**Datagrams from ourselves.** A datagram whose source is the published
address itself, or one of the host's addresses arriving from outside (the
host's own datagrams to itself come in on `lo`), is forged: relayed, its
answers would go back to the proxy and come in again, for ever, the Loop
DoS of §16's DNS server, here between the proxy and any container that
answers what it gets. IPv4 drops such packets itself (a local source
arriving from outside is a martian); IPv6 has no such check, and the LAN
could start the loop with one spoofed datagram to an IPv4-only container's
port, which only the proxy serves over IPv6. The proxy drops them (the
interface comes with the destination, in the same control message); the
independent review found it relaying one such datagram 5,625 times in 300
ms (`udp_drops_datagrams_from_its_own_address`).

**Stopping.** A `Proxy` is one tokio task owning its socket and the tasks
of its connections or clients; dropping it aborts them all. An aborted
task ends when the runtime next polls it, so the socket isn't closed yet
when `drop` returns, and a container restarted on the same port could find
it still taken. `Proxy::close` aborts *and* waits for the task, and for the
clients' answer tasks, which hold the UDP socket too, and the daemon
closes a run's proxies that way before it undoes the rest of its network
(`udp_close_frees_the_port_before_it_returns`: since UDP ports are bound
without `SO_REUSEADDR`, a socket still open makes the next bind fail).

**The cost.** The container sees the proxy's connection, from the bridge's
gateway (10.89.0.1), instead of the client's. And because the proxy is tasks of the
daemon rather than a process per port (Docker runs a `docker-proxy`
process each), while the daemon restarts only DNAT'd traffic flows: the
rules are the kernel's and stay, the sockets are the daemon's and go. The
new daemon binds them again as it takes the container over
(`resume_network`); `dn_networking_survives_a_daemon_restart` fetches the
page from the LAN while no daemon runs, then waits for `127.0.0.1` to
answer again. (§2.5 records this as a deviation.)

**Where it relays to can change.** A container disconnected from the
network its ports led to (§4) needs its proxies to lead elsewhere, but
closing and binding again would leave the port free for a moment, for
anyone. So a proxy's backend is a value the daemon changes while the proxy
runs ([`proxy::Backend`](../../crates/rustlet-net/src/proxy.rs)): a TCP connection keeps the backend it
started with, new ones get the new one; a UDP client whose socket leads to
the old one gets a new socket with its next datagram; and with no backend
at all (no network with a way out) a TCP client is closed at once and a
datagram dropped, while the socket stays bound. `dn_connect_and_disconnect`
fetches the page through `127.0.0.1` after the move.

**Hairpin traffic.** A container on `rustlet0` connecting to
192.168.50.143:8080, published by another container on `rustlet0` (or by
itself): DNATed like any other, its packets go back onto the bridge they
came from, and the server answers the client straight across the bridge,
from 10.89.0.2 rather than from the address the client connected to; the
client drops the answer. Phase 5 first dealt with it by leaving such
traffic alone (`iifname != "rustlet0"` in the DNAT rule), so that it
reached the proxy instead, as Docker's userland proxy does. Traffic the
proxy gets is the host's own input, though, and when ufw was enabled on
this host its incoming policy dropped it: a container timed out on a
neighbour's published port through the host's address, and through its
gateway's, while one on another network got through (DNATed, forwarded).

Now the DNAT rule applies whatever the packet came in on, and one more
rule per subnet masquerades DNATed traffic that goes back out of the
bridge it came from:

```text
ip saddr 10.89.0.0/24 oifname "rustlet0" ct status dnat masquerade comment "10.89.0.0/24 hairpin"
```

The server sees the bridge's address as its client and answers the host,
which undoes both rewrites on the way back. `ct status dnat` keeps
everything else alone: traffic between two containers on a bridge is
switched, not routed, and never reaches these hooks, unless the
`br_netfilter` module makes bridged frames pass them, and then it must
keep its addresses. Hairpin traffic is forwarded traffic now, which ufw's
route rules let through (§8), and it costs no relay:

```text
$ rustlet run --rm alpine wget -qO- http://192.168.50.143:8080/ | grep title; rustlet logs web | tail -1
<title>Welcome to nginx!</title>
10.89.0.1 - - [02/Oct/2026:18:40:24 +0000] "GET / HTTP/1.1" 200 896 "-" "Wget" "-"
```

nginx logs the gateway, 10.89.0.1, as its client: the masquerade. Podman's
netavark handles hairpin traffic the same way, and Docker does with
`--userland-proxy=false`, where it also turns on hairpin mode on the bridge
ports. That matters with `br_netfilter` loaded, when the bridge itself
runs these hooks on the frames it switches and a container connecting to
*its own* published port could need hairpin mode on its port; Rustlets
doesn't set it, and this host doesn't load `br_netfilter`. Here even that
case works: the host routes the packet, and it leaves through the bridge
from the host's side. `net_bridge_nat_published_ports_and_guards` has the
container fetch its own published port through the host's address and get
`container 10.89.0.1`; `dn_published_ports`, a neighbour. Without the
masquerade rule the first times out.

## 6. Not past the bridge

With `ip_forward` on, the host forwards any packet that arrives for an
address it can route. A machine on the LAN that adds `10.89.0.0/16 via
192.168.50.143` to its own routing table could then reach every container
directly, whether it published anything or not, if nothing stopped it.
Two things do, in two different chains.

**The raw guard**, first in the whole path (priority −300, before
conntrack or NAT):

```text
ip daddr 10.89.0.0/24 iifname != "rustlet0" iifname != "lo" drop
```

A packet for the subnet that didn't arrive on the subnet's own bridge is
dropped, unless it came in on `lo`: the host's own traffic to one of its
addresses there, the gateway's, which the first version dropped too
(`--network host` with `--add-host h:host-gateway` couldn't reach `h`). At this point a packet for a published port still has the host's
address as its destination (DNAT comes later), and so does a reply to a
masqueraded flow (conntrack hasn't undone the NAT yet), so neither is
affected. Docker 28 added rules to its `raw` table for the same reason,
one per container address; Rustlets has one per subnet. The same rule also
keeps containers on *another* network from reaching this one: their packets
arrive on their own bridge. A network with IPv6 has the same guard for its
IPv6 subnet (`ip6 daddr fd9a:7b:7e99::/64 iifname != "rlbbd6e48557003"
drop`).

**The forward chain** decides what may be forwarded at all:

```text
oifname "rustlet0" ct state established,related accept   # replies to what containers started
oifname "rustlet0" ct status dnat accept                  # published ports
iifname "rustlet0" oifname "rustlet0" accept              # container to container on the bridge
oifname "rustlet0" drop                                   # nothing else into the bridge
iifname "rustlet0" accept                                 # containers out
meta nfproto ipv4 drop                                    # (IPv4 forwarding was off: nothing else)
meta nfproto ipv6 drop                                    # (the same for IPv6)
```

Into a bridge go only replies, published ports and traffic within the
bridge (which normally doesn't pass the IP layer at all; it does when the
`br_netfilter` module is loaded). Out of a bridge goes anything; an
internal network's chain starts with `iifname "rlb…" oifname != "rlb…"
drop`, before every rule above. The first version had that drop after
them, as "nothing out of an internal network": but a container there
could send to its gateway's address (the host's) on a port another
network's container publishes, DNAT took it to that container, and
"published ports on rustlet0" accepted it first. TCP's replies met the
raw guard, but a UDP datagram got out (`dn_internal_networks_stay_inside`
sends one to a UDP sink; the independent review found it). **Every rule into a bridge comes before
any rule out of one**, for all networks: a packet from bridge A to bridge
B matches both "out of A" and "into B", and the first match wins. With the
rules grouped per network, A's `accept` could come first and bypass B's
`drop`. The unit test `forward_drops_into_a_bridge_come_before_any_way_out`
pins the order down.

`net_bridge_nat_published_ports_and_guards` gives the LAN namespace exactly
that route through the test host and connects to the container: it fails.
Then it flushes `raw_prerouting` and tries again: the forward chain alone
still drops it, while the published port still answers.
`net_ipv6_bridge_nat66_published_ports_and_guards` does the same over
IPv6. On the real host, `scripts/smoke.sh` does both with a throwaway
namespace behind a veth (`rlsmoke`, which has 2001:db8:5::/64 too), with
the real rules and ufw active:

```text
==> 3. the LAN can't reach containers directly (container 10.89.0.3)
    ok: the LAN reaches the published port
    ok: the LAN can't reach 10.89.0.3:80 directly
…
==> 6. an IPv6 network
    ok: smoke-net6 has fd9a:7b:7e99::/64
    ok: IPv6 forwarding is on
    ok: curl [::1]:18086 (the proxy, to fd9a:7b:7e99::2)
    ok: curl [fd4b:a90d:1d5c:63:6cb3:e6d9:5b01:25b3]:18086 (DNAT)
    ok: the LAN reaches it over IPv6 (DNAT, forwarded)
    ok: the LAN can't reach [fd9a:7b:7e99::2]:80 directly
    ok: AAAA: smoke-web6 is fd9a:7b:7e99::2
```

**When Rustlets turned forwarding on**, the chain ends with a `drop` for
that family: nothing of it that involves none of its bridges is
forwarded. A host
that didn't forward before Rustlets came along doesn't start forwarding
between its other interfaces (a LAN and a VPN, say) because containers
needed it. Docker does the same by setting the iptables `FORWARD` policy
to `DROP` when it enables forwarding itself. The cost is the same as
Docker's: other software that later wants this host to forward (libvirt,
a VPN server) finds it dropped by Rustlets' table, until `scripts/cleanup.sh`
removes the table. When forwarding was already on (the record says 1),
the drop is left out: someone else forwards, and it isn't Rustlets' place
to stop them. Each family is judged on its own (`meta nfproto ipv4`,
`ipv6`): a host that routed IPv6 before Rustlets turned IPv4 forwarding on
goes on routing IPv6.

## 7. The order at startup

[`Networks::setup_host`](../../crates/rustletd/src/network.rs) does the host's half in an order that
never leaves forwarding on without the guards:

1. the runs the database says are going are restored first (their
   addresses and published ports), so the first ruleset still contains
   their DNAT rules: published ports keep working across a daemon
   restart;
2. the pin directory, then every network's bridge (idempotent:
   `link::ensure_bridge`);
3. the firewall;
4. only then `ip_forward`, after recording its old value, and IPv6
   forwarding (`net.ipv6.conf.all.forwarding`) the same way, if a network
   has IPv6;
5. ufw's route rules (§8).

```text
$ cat /proc/sys/net/ipv4/ip_forward; cat /run/rustlet/host-sysctl.orig
1
net.ipv4.ip_forward=0
net.ipv6.conf.all.forwarding=0
```

The record ([`sysctl::enable_forwarding`](../../crates/rustlet-net/src/sysctl.rs), `enable_forwarding6`) holds a
line per sysctl, written once, before the first change, and never
overwritten: a second daemon must not record the value the first one set.
`scripts/cleanup.sh` reads it back and restores every line (step 8). It
lives under `/run`, a tmpfs: a reboot resets the sysctls and forgets the
record together. The same record tells the firewall whether it may add the
final drops of §6. IPv6 forwarding is turned on when the first network with
IPv6 is created, in the same order (the firewall with the network's guards
first), and like `ip_forward` it then stays on; the drop must too, so a
daemon that starts with no IPv6 network left still adds it, because the
record says IPv6 forwarding was Rustlets' doing (`dn_ipv6_networks` checks
it after a restart). After reconciliation (chapter 13) has taken over or
undone every run, the ruleset is applied once more.

## 8. ufw

ufw, Ubuntu's firewall front end, keeps its rules in iptables (nftables
underneath, tables `ip filter` and `ip6 filter`), with its own policy for
forwarded traffic, `DROP` on this host (`DEFAULT_FORWARD_POLICY` in
`/etc/default/ufw`). Rustlets' `accept`s can't overrule another table's
`drop` (§2), so with ufw active, containers' traffic would be forwarded by
one table and dropped by the other. So for every network the daemon asks
ufw itself to route the bridge's traffic, both ways
([`ufw.rs`](../../crates/rustlet-net/src/ufw.rs)): `ufw route allow in on <bridge>` and `ufw route allow
out on <bridge>`. Rustlets' own table still decides what may reach a
container (§6); the two rules only keep ufw from dropping what it lets
through.

ufw was inactive on this host while Phase 5 was built, and this code
first ran when ufw was enabled, after the rest of the phase. With the
daemon started and two networks created:

```text
$ journalctl -u rustletd | grep ufw
… INFO rustletd::network: ufw: routing rustlet0's traffic (ufw route allow in/out on rustlet0)
$ sudo ufw status verbose
Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), deny (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
Anywhere                   ALLOW FWD   Anywhere on rustlet0
Anywhere on rustlet0       ALLOW FWD   Anywhere
Anywhere                   ALLOW FWD   Anywhere on rlb5b9b1acf3190
Anywhere on rlb5b9b1acf3190 ALLOW FWD   Anywhere
Anywhere                   ALLOW FWD   Anywhere on rlbbd6e48557003
Anywhere on rlbbd6e48557003 ALLOW FWD   Anywhere
Anywhere (v6)              ALLOW FWD   Anywhere (v6) on rustlet0
Anywhere (v6) on rustlet0  ALLOW FWD   Anywhere (v6)
…
```

ufw adds each rule for IPv6 as well ("(v6)"). Its routed default reads
"deny" since `ip_forward` is on; before the daemon first started, ufw
reported it "disabled".

Three things were decided by running it:

- **Kept whether ufw is active or not.** An inactive ufw only writes the
  rules into its configuration (`/etc/ufw/user.rules`, `user6.rules`), and
  they take effect the day someone runs `ufw enable`. Keeping them only
  while ufw is active would cut every container off the moment ufw is
  enabled under a running daemon, which is how this host got its ufw.
- **Only by a daemon in the host's own network namespace.** `ufw status`
  checks for ufw's chains in the namespace it runs in, so in a test
  daemon's namespace it says "inactive" whatever the host's ufw does; but
  `ufw route allow` would still write the host's configuration files, once
  for every test network. [`ufw::manages_host`](../../crates/rustlet-net/src/ufw.rs) compares the daemon's
  network namespace with PID 1's, and the tests' daemons never touch ufw.
- **What's missing, once per start.** Each `ufw` call starts a Python
  program. At startup the daemon reads `ufw show added` once and adds only
  the rules a network lacks; the calls take turns, because ufw rewrites
  its rule files whole. Creating a network adds its two rules, removing it
  takes them away, and `scripts/cleanup.sh` (step 7) removes every rule of
  a `rustlet*` or `rlb*` bridge. `manage_ufw = false` in `daemon.toml`
  turns all of it off.

`scripts/smoke.sh` checks it on the real host, and its other steps ran
with ufw active (the LAN namespace reached published ports over IPv4 and
IPv6, forwarded, and couldn't reach containers directly):

```text
==> 9. ufw
    ok: ufw routes rustlet0's traffic (Status: active)
    ok: ufw routes rlb5e10250e9ec2's traffic (Status: active)
    ok: ufw routes rlb01482e772d2b's traffic (Status: active)
    ok: removing smoke-net2 removed rlb4f3e2a43803e's rules
```

**What ufw still decides.** Traffic delivered to the host itself is for
ufw's incoming policy to judge, Rustlets' or not. Of a published port's
traffic, that is what the proxy serves: loopback clients, which ufw always
lets in (`-i lo`), and IPv6 clients of a container without IPv6, which it
drops unless the port is allowed (`sudo ufw allow 8080/tcp`), as it does
docker-proxy's. Hairpin traffic was in that list, and ufw dropped it,
until it became forwarded traffic (§5). A container reaching one of the
host's own services (`--add-host db:host-gateway`) is incoming traffic
too, from the bridge: allow it per port (`sudo ufw allow in on rustlet0 to
any port 5432`), or the whole bridge.

## 9. Testing without touching the host

The `net_` and `dn_` tests never change the real host's firewall: their
daemons run in a network namespace of their own (chapter 14), which has
its own netfilter tables and its own `ip_forward`, beside a "LAN"
namespace that plays 192.0.2.1 and 2001:db8::1. (Nor its ufw: §8.) The rules are real, the kernel is real,
the LAN is a namespace. Only the installed service, and `scripts/smoke.sh`
against it, use the host's own tables.

## 10. Differences from Docker

- Docker writes iptables rules into the host's shared `filter`, `nat` and
  `raw` tables (its own chains, `DOCKER`, `DOCKER-USER`, …, jumped to from
  the built-in ones). Rustlets has one nftables table of its own and
  replaces it whole.
- Docker runs a `docker-proxy` process per published port; Rustlets'
  proxy is tasks of the daemon.
- Docker's userland proxy serves hairpin traffic, and with
  `--userland-proxy=false` it handles hairpin and loopback traffic with NAT
  instead (hairpin mode on the bridge ports, `route_localnet`). Rustlets
  handles hairpin traffic with NAT always, as Podman does, and loopback
  traffic with its proxy always, never `route_localnet`.
- Docker inserts its own chains ahead of ufw's in iptables' `FORWARD`, so
  published ports bypass ufw (a common surprise); Rustlets asks ufw to
  route its bridges, so `ufw status` shows what is let through.
- Both NAT IPv6 by default on networks with IPv6 (Docker 27 and later,
  with `ip6tables` on).
- Docker's raw guards are per container address, Rustlets' per subnet.

## 11. Try it

```sh
R="sudo target/debug/rustlet"
$R run -d --name web -p 8080:80 nginx
sudo nft list table inet rustlet                 # one DNAT rule per published port
curl -s localhost:8080 | head -4                 # the proxy (loopback)
curl -s 192.168.50.143:8080 | head -4            # DNAT (your host's address)
sudo ss -tlnp 'sport = :8080'                    # rustletd holds 0.0.0.0 and [::]
$R run -d -p 80 --name any nginx && $R port any  # the kernel's choice
$R run -d --name dup -p 8080:80 nginx            # taken: a conflict (dup stays created)
cat /run/rustlet/host-sysctl.orig                # what cleanup.sh restores
$R run --rm alpine wget -qO- http://192.168.50.143:8080/ | head -4   # hairpin: DNAT, masqueraded
$R logs web | tail -1                            # nginx saw 10.89.0.1
$R network create --ipv6 six && $R run -d --name web6 --network six -p 8086:80 nginx
sudo nft list table inet rustlet                 # ip6 rules: guard, DNAT, NAT66, hairpin
curl -s "http://[::1]:8086/" | head -4           # the proxy, to the container's IPv6 address
sudo ufw status verbose; sudo ufw show added     # the route rules (if ufw is installed)
scripts/smoke.sh                                 # steps 3, 6, 9: the LAN, IPv6, ufw
$R rm -f web any dup
cargo xtask itest -- net_ dn_                    # the tests behind this chapter
```

## Check yourself

1. Why does no rule in the table handle replies to masqueraded or DNATed
   flows?
2. The raw guard runs before NAT. Why doesn't it drop a packet for a
   published port, or a reply to a container's outgoing connection?
3. Why does every rule into a bridge come before any rule out of one? Give
   a packet that the other order would let through.
4. Why can't `curl 127.0.0.1:8080` on the host be served by a DNAT rule,
   and what would it take to make it possible? Why doesn't Rustlets do
   that?
5. A container on `rustlet0` connects to 192.168.50.143:8080, published by
   another container on `rustlet0`. Follow its packets through the hooks.
   What would go wrong without the hairpin masquerade, and why does that
   rule match `ct status dnat`?
6. Why does the daemon bind the published port itself, even though DNAT
   delivers external traffic without any socket?
7. A UDP client on IPv6 sends to the host's stable address and gets an
   answer from its temporary one. What does the client do with it, and how
   does the proxy avoid this?
8. The daemon restarts. Which published traffic keeps flowing while it is
   down, and which doesn't? Why is that different from Docker's?
9. Why is `ip_forward` turned on only after the firewall is applied, and
   why is its old value recorded only once?
10. ufw is active and its forward policy is `DROP`. Why doesn't Rustlets'
    `iifname "rustlet0" accept` help, and what does the daemon do instead?
    Why does it keep those rules while ufw is inactive, and why never from
    a test daemon?
11. The last network with IPv6 is removed, and the daemon restarts. Is
    IPv6 forwarding on? Must the forward chain's IPv6 drop still be there,
    and how does the daemon know?
12. Why masquerade IPv6 at all, when IPv6 was meant to end NAT? What would
    the LAN need for containers to be reached without it?

## Experiments

- **Watch NAT happen.** Install `conntrack` (conntrack-tools) and run
  `sudo conntrack -E` while a container fetches a page (`$R run --rm
  alpine wget -qO- example.org`) and while you curl a published port from
  another machine. Which addresses does each flow's reply direction show?
- **Remove a guard.** On a test host, or in the `net_` test's namespaces,
  delete the `forward` chain's `oifname "rustlet0" drop` rule (`nft -a
  list table inet rustlet` shows handles; `nft delete rule inet rustlet
  forward handle N`) and route 10.89.0.0/16 to the host from another
  machine. What gets through now, and what does the raw guard still stop?
  (The next change to any container rebuilds the table: why?)
- **A port on loopback only.** `$R run -d -p 127.0.0.1:8081:80 nginx`:
  compare `nft list table inet rustlet` with the `-p 8080:80` case, and
  try the port from the host and from another machine.
- **Hairpin.** From a container on the default network, `wget -qO-
  http://192.168.50.143:8080` (your host's address), and look at nginx's
  log. Then delete the hairpin rule (`nft -a list chain inet rustlet
  postrouting` shows handles) and try again; with `ufw` active, also put
  `iifname != "rustlet0"` back into the DNAT rule by hand so that the
  request reaches the proxy, and watch ufw drop it (`sudo dmesg | grep
  UFW` with ufw's logging on). Which path did each request take?

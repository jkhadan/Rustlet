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
up, and the userland proxy that handles the traffic NAT can't reach.

Code: [`firewall.rs`](../../crates/rustlet-net/src/firewall.rs) (`Ruleset::to_json`, `Ruleset::apply`,
`run_nft`, `dns_redirect`) and its snapshots in
[`snapshots/`](../../crates/rustlet-net/src/snapshots/), [`sysctl.rs`](../../crates/rustlet-net/src/sysctl.rs) (`enable_forwarding`,
`recorded`), [`proxy.rs`](../../crates/rustlet-net/src/proxy.rs) (`Proxy::tcp`, `Proxy::udp`, `Proxy::close`),
[`ufw.rs`](../../crates/rustlet-net/src/ufw.rs); the daemon's [`network.rs`](../../crates/rustletd/src/network.rs)
(`Networks::setup_host`, `apply_firewall`, `publish`, `proxy_pair`, `bound_socket`,
`resume_network`). Tests: `net_bridge_nat_published_ports_and_guards` in
[`network.rs`](../../tests/tests/network.rs), `dn_published_ports`, `dn_publish_all_and_host_networking` and
`dn_networking_survives_a_daemon_restart` in [`daemon_network.rs`](../../tests/tests/daemon_network.rs), the
proxy's 15 unit tests, and step 3 of [`scripts/smoke.sh`](../../scripts/smoke.sh) on the real host.
Design: [architecture.md §2.5](../architecture.md#25-rustlet-net--host-side-networking) (Firewall, Published ports).

The transcripts were recorded on 2026-10-02 against the installed service,
kernel 7.0.0-34-generic, nftables 1.0.9, with one container running:
`rustlet run -d --name web -p 8080:80 nginx`, at 10.89.0.2. The host is
192.168.50.143 on `ens18`. `rustlet` is `sudo target/debug/rustlet`;
commands that need root ran through `sudo` or `sudo systemd-run --pipe
--wait`.

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
		meta nfproto ipv4 iifname != "rustlet0" fib daddr type local tcp dport 8080 dnat ip to 10.89.0.2:80 comment "web 8080/tcp -> 10.89.0.2:80"
	}

	chain output {
		type nat hook output priority dstnat; policy accept;
		fib daddr type local ip daddr != 127.0.0.0/8 tcp dport 8080 dnat ip to 10.89.0.2:80 comment "web 8080/tcp -> 10.89.0.2:80"
	}

	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		ip saddr 10.89.0.0/24 oifname != "rustlet0" masquerade comment "10.89.0.0/24 out"
	}

	chain forward {
		type filter hook forward priority filter; policy accept;
		oifname "rustlet0" ct state established,related accept comment "replies to rustlet0"
		oifname "rustlet0" ct status dnat accept comment "published ports on rustlet0"
		iifname "rustlet0" oifname "rustlet0" accept comment "within rustlet0"
		oifname "rustlet0" drop comment "nothing else into rustlet0"
		iifname "rustlet0" accept comment "rustlet0 out"
		drop comment "Rustlets turned forwarding on: nothing but its own bridges is forwarded"
	}
}
```

The sections below go through it chain by chain. Two things about how it
gets there first.

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

The unit tests snapshot the JSON of a sample ruleset (two networks, two
ports, forwarding isolated: [`snapshots/`](../../crates/rustlet-net/src/snapshots/)); while it was
written, each snapshot was also fed to `nft --check -j -f`, which has the
kernel validate the whole transaction without committing it.

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

## 4. In: DNAT for published ports

```text
meta nfproto ipv4 iifname != "rustlet0" fib daddr type local tcp dport 8080 dnat ip to 10.89.0.2:80
```

Left to right:

- `meta nfproto ipv4`: the table is `inet`, so it sees IPv6 too, and a
  container has only an IPv4 address. (`nft` leaves this match out when it
  prints a rule with an `ip` match, which implies it.)
- `iifname != "rustlet0"`: not from the port's own bridge (§5).
- `fib daddr type local`: the destination is one of the host's own
  addresses, whichever: what "every address" means for `-p 8080:80`. With
  `-p 192.168.50.143:8080:80` this becomes `ip daddr 192.168.50.143`.
- `tcp dport 8080 dnat ip to 10.89.0.2:80`: rewrite the destination. From
  here on the routing decision sees 10.89.0.2, and the packet is forwarded
  to the bridge.

DNAT leaves the source alone, so the container sees the real client. In
`net_bridge_nat_published_ports_and_guards` the LAN machine's request to the
host's port is answered with `container 192.0.2.1`.

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

Three kinds of traffic to a published port never meet a DNAT rule that
could work for them:

- **To `127.0.0.1`.** Rewriting a loopback destination to 10.89.0.2 is
  only possible with the `route_localnet` sysctl, which makes the kernel
  route packets for `127.0.0.0/8`, and also accept them from the wire.
  Kubernetes' kube-proxy once set it, and neighbours on the LAN could then
  reach services bound to the host's loopback (CVE-2020-8558). Rustlets
  never sets it.
- **Over IPv6.** The containers have IPv4 addresses only; NAT can't turn
  an IPv6 connection into an IPv4 one.
- **Hairpin traffic**: a container connecting to the host's address and a
  port another container on the *same bridge* publishes. DNATed, its
  packets would go back onto the bridge, and the server's replies would
  go straight to the client across the bridge, from 10.89.0.2 rather than
  from the address the client connected to; the client would drop them.
  The DNAT rule therefore skips traffic from the port's own bridge
  (`iifname != "rustlet0"`).

So the daemon also listens on the published port itself and relays what
arrives there, as Docker's `docker-proxy` does
([`proxy.rs`](../../crates/rustlet-net/src/proxy.rs)). The daemon binds the sockets
([`bound_socket`](../../crates/rustletd/src/network.rs)): `SO_REUSEADDR`, and for IPv6 `IPV6_V6ONLY`,
so that `[::]:8080` doesn't also try to take the IPv4 port `0.0.0.0:8080`
already has:

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
to a hairpin client, the bridge's 10.89.0.1 rather than the
192.168.50.143 it wrote to; over IPv6, perhaps one of the host's temporary
addresses. A client takes such an answer for somebody else's (a connected
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

**Stopping.** A `Proxy` is one tokio task owning its socket and the tasks
of its connections or clients; dropping it aborts them all. An aborted
task ends when the runtime next polls it, so the socket isn't closed yet
when `drop` returns, and a container restarted on the same port could find
it still taken. `Proxy::close` aborts *and* waits for the task, and the
daemon closes a run's proxies that way before it undoes the rest of its
network.

**The cost.** The container sees the proxy's connection, from the bridge's
gateway (10.89.0.1), instead of the client's. And because the proxy is tasks of the
daemon rather than a process per port (Docker runs a `docker-proxy`
process each), while the daemon restarts only DNAT'd traffic flows: the
rules are the kernel's and stay, the sockets are the daemon's and go. The
new daemon binds them again as it takes the container over
(`resume_network`); `dn_networking_survives_a_daemon_restart` fetches the
page from the LAN while no daemon runs, then waits for `127.0.0.1` to
answer again. (§2.5 records this as a deviation.)

## 6. Not past the bridge

With `ip_forward` on, the host forwards any packet that arrives for an
address it can route. A machine on the LAN that adds `10.89.0.0/16 via
192.168.50.143` to its own routing table could then reach every container
directly, whether it published anything or not, if nothing stopped it.
Two things do, in two different chains.

**The raw guard**, first in the whole path (priority −300, before
conntrack or NAT):

```text
ip daddr 10.89.0.0/24 iifname != "rustlet0" drop
```

A packet for the subnet that didn't arrive on the subnet's own bridge is
dropped. At this point a packet for a published port still has the host's
address as its destination (DNAT comes later), and so does a reply to a
masqueraded flow (conntrack hasn't undone the NAT yet), so neither is
affected. Docker 28 added rules to its `raw` table for the same reason,
one per container address; Rustlets has one per subnet. The same rule also
keeps containers on *another* network from reaching this one: their packets
arrive on their own bridge.

**The forward chain** decides what may be forwarded at all:

```text
oifname "rustlet0" ct state established,related accept   # replies to what containers started
oifname "rustlet0" ct status dnat accept                  # published ports
iifname "rustlet0" oifname "rustlet0" accept              # container to container on the bridge
oifname "rustlet0" drop                                   # nothing else into the bridge
iifname "rustlet0" accept                                 # containers out
drop                                                      # (forwarding was off: nothing else)
```

Into a bridge go only replies, published ports and traffic within the
bridge (which normally doesn't pass the IP layer at all; it does when the
`br_netfilter` module is loaded). Out of a bridge goes anything, or
nothing on an internal network. **Every rule into a bridge comes before
any rule out of one**, for all networks: a packet from bridge A to bridge
B matches both "out of A" and "into B", and the first match wins. With the
rules grouped per network, A's `accept` could come first and bypass B's
`drop`. The unit test `forward_drops_into_a_bridge_come_before_any_way_out`
pins the order down.

`net_bridge_nat_published_ports_and_guards` gives the LAN namespace exactly
that route through the test host and connects to the container: it fails.
Then it flushes `raw_prerouting` and tries again: the forward chain alone
still drops it, while the published port still answers. On the real host,
`scripts/smoke.sh` does the same with a throwaway namespace behind a veth
(`rlsmoke`), with the real rules:

```text
==> 3. the LAN can't reach containers directly (container 10.89.0.3)
    ok: the LAN reaches the published port
    ok: the LAN can't reach 10.89.0.3:80 directly
```

**When Rustlets turned forwarding on**, the chain ends with a plain
`drop`: nothing that involves none of its bridges is forwarded. A host
that didn't forward before Rustlets came along doesn't start forwarding
between its other interfaces (a LAN and a VPN, say) because containers
needed it. Docker does the same by setting the iptables `FORWARD` policy
to `DROP` when it enables forwarding itself. The cost is the same as
Docker's: other software that later wants this host to forward (libvirt,
a VPN server) finds it dropped by Rustlets' table, until `scripts/cleanup.sh`
removes the table. When forwarding was already on (the record says 1),
the drop is left out: someone else forwards, and it isn't Rustlets' place
to stop them.

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
4. only then `ip_forward`, after recording its old value.

```text
$ cat /proc/sys/net/ipv4/ip_forward; cat /run/rustlet/host-sysctl.orig
1
net.ipv4.ip_forward=0
```

The record ([`sysctl::enable_forwarding`](../../crates/rustlet-net/src/sysctl.rs)) is written once, before the
first change, and never overwritten: a second daemon must not record the
value the first one set. `scripts/cleanup.sh` reads it back and restores
the sysctl (step 7). It lives under `/run`, a tmpfs: a reboot resets the
sysctl and forgets the record together. The same record tells the
firewall whether it may add the final drop of §6. After reconciliation
(chapter 13) has taken over or undone every run, the ruleset is applied
once more.

## 8. ufw

ufw, Ubuntu's firewall front end, keeps its rules in iptables (nftables
underneath, tables `ip filter` and `ip6 filter`), with its own policy for
forwarded traffic, `DROP` on this host (`DEFAULT_FORWARD_POLICY` in
`/etc/default/ufw`). Rustlets' `accept`s can't overrule another table's
`drop` (§2), so with ufw active, containers' traffic would be forwarded by
one table and dropped by the other. When a bridge is set up and ufw is
active, the daemon says so in its log and asks ufw itself to route the
bridge ([`ufw.rs`](../../crates/rustlet-net/src/ufw.rs)): `ufw route allow in on rustlet0` and `ufw route
allow out on rustlet0`; removing the network removes them. ufw is inactive
on this host, so this code has only run in its unit test.

## 9. Testing without touching the host

The `net_` and `dn_` tests never change the real host's firewall: their
daemons run in a network namespace of their own (chapter 14), which has
its own netfilter tables and its own `ip_forward`, beside a "LAN"
namespace that plays 192.0.2.1. The rules are real, the kernel is real,
the LAN is a namespace. Only the installed service, and `scripts/smoke.sh`
against it, use the host's own tables.

## 10. Differences from Docker

- Docker writes iptables rules into the host's shared `filter`, `nat` and
  `raw` tables (its own chains, `DOCKER`, `DOCKER-USER`, …, jumped to from
  the built-in ones). Rustlets has one nftables table of its own and
  replaces it whole.
- Docker runs a `docker-proxy` process per published port; Rustlets'
  proxy is tasks of the daemon.
- With `--userland-proxy=false` Docker handles hairpin and loopback traffic
  with NAT instead (hairpin mode on the bridge ports, `route_localnet`).
  Rustlets has no such mode.
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
scripts/smoke.sh                                 # step 3: a LAN namespace can't reach the container
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
   another container on `rustlet0`. Follow its packets. What would go
   wrong if the DNAT rule didn't skip `iifname "rustlet0"`?
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
  http://192.168.50.143:8080` (your host's address). Then publish nginx on
  a user-defined network instead and try again from the default one.
  Which path does each request take?

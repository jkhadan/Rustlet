# 14 — veth pairs, bridges and netlink: a container's place on the network

Until Phase 5 a container had a network namespace of its own and nothing
in it but `lo`. It could talk to itself and to nobody else, which is what
`--network none` still gives you. Now `rustlet run nginx` gets an `eth0`
with an address, a default route out, and a cable to a switch on the host
that every other container on the same network is plugged into; and a
container can be on several networks at once, with an interface on each,
some of them with IPv6 as well as IPv4. None of
that is the runtime's doing: `rustlet-runc` still only joins a network
namespace by path. The daemon builds the namespace, the cable and the
switch before the container exists, through the kernel's routing netlink
interface, with a codec of our own. This chapter follows that work from
the host's side: pinning a namespace nothing runs in yet, why every step
inside it happens on a thread made for it, veth pairs and bridges, the
netlink messages byte by byte, addresses, routes and MACs, which address a
container gets, what a run's network looks like from start to exit, a
container on several networks, and IPv6 on a bridge.
[Chapter 15](15-nat-nftables.md) adds the firewall that lets the outside
in and keeps the LAN out; [chapter 16](16-dns.md) the DNS server that lets
containers find each other by name.

Code: the codec, [`netlink.rs`](../../crates/rustlet-sys/src/netlink.rs) (`MsgBuilder`, `attrs`,
`RtNetlink::{create_bridge, create_veth, set_master, set_alias, add_address, add_address6, add_route,
replace_route, delete_route, links, addresses, routes}`).
[`rustlet-net`](../../crates/rustlet-net/src/lib.rs): [`netns.rs`](../../crates/rustlet-net/src/netns.rs)
(`create`, `remove`, `run_in`, `prepare_dir`), [`link.rs`](../../crates/rustlet-net/src/link.rs)
(`ensure_bridge`, `attach`, `configure_inside`, `set_default_routes`, `host_ifname`, `endpoint_alias`,
`links_tagged`, `routed_blocks`), [`ipam.rs`](../../crates/rustlet-net/src/ipam.rs)
(`Subnet`, `Subnet6`, `free_subnet`, `free_subnet6`, `Allocator`, `Allocator6`, `mac_for`),
[`sysctl.rs`](../../crates/rustlet-net/src/sysctl.rs) (`NETNS_DEFAULTS`, `NETNS_DEFAULTS6`, `disable_ipv6`,
`enable_ipv6`), [`backend.rs`](../../crates/rustlet-net/src/backend.rs) (`NetworkBackend`).
The daemon: [`network.rs`](../../crates/rustletd/src/network.rs) (`attach_network`, `connect_run`,
`plan_endpoint`, `make_endpoint`, `connect_network`, `disconnect_network`, `follow_endpoints`, `set_routes`,
`detach_network`, `restore`, `resume_network`, `choose_network`), [`lifecycle.rs`](../../crates/rustletd/src/lifecycle.rs)
(`start_on`, `clear_leftovers`, `handle_exit`), [`spec.rs`](../../crates/rustletd/src/spec.rs)
(`set_network_namespace`), [`db.rs`](../../crates/rustletd/src/db.rs) (`NetRun`, `EndpointRun`,
`EndpointConfig`). Tests: [`network.rs`](../../tests/tests/network.rs) (`net_`, 4: rustlet-net alone, in
throwaway namespaces) and [`daemon_network.rs`](../../tests/tests/daemon_network.rs) (`dn_`, 11, and `vol_`),
on the harness in [`tests/src/net.rs`](../../tests/src/net.rs); `cargo xtask itest -- net_ dn_`. Design:
[architecture.md §2.5](../architecture.md#25-rustlet-net--host-side-networking) and §2.6.

The transcripts were recorded on 2026-10-02 against the installed service
(`cargo xtask daemon install`), kernel 7.0.0-34-generic, on this host:
`ens18` at 192.168.50.143 on the LAN 192.168.50.0/24. The API socket is
root's, so every `rustlet` below is really `sudo target/debug/rustlet`,
and commands that need root on the host (`nsenter`, `readlink` of another
process's namespace) ran through `sudo systemd-run --pipe --wait`. Ids are
64 hex digits. The transcripts of the host's ends of veths, of §5's
`IFLA_IFALIAS` and of §7's IPv6 subnet, §10 and §11 were recorded later
the same day, once a container could have several networks (and with ufw
active, which this chapter doesn't need: [chapter 15](15-nat-nftables.md) §8).

## 1. What a network namespace holds

A network namespace is a whole network stack: its own interfaces
(including its own `lo`), addresses, routing tables, neighbour (ARP)
tables, netfilter tables, sockets and the port numbers they hold, and its
own `/proc/sys/net`. A process sees exactly one of them. Two containers can
both listen on port 80 because their sockets live in different stacks; the
host's `ip_forward` and a container's are different files.

A namespace starts with `lo`, down, and nothing else. The runtime brought
that `lo` up in Phases 1–4 and stopped there; [chapter 01](01-namespaces-intro.md)
showed the bare result. Every namespace has an inode on the `nsfs` pseudo
filesystem, and two processes are in the same namespace exactly when
their `/proc/<pid>/ns/net` name the same inode:

```text
$ rustlet run -d --name inode alpine sleep 120
a4370a04d0b0fd0e6ba28cf4dc790f5e43739cda8837579d0fb8b68332f18d72
$ readlink /proc/156614/ns/net /proc/self/ns/net; stat -L -c '%i %n' /run/rustlet/netns/a4370a04d0b0…
net:[4026532492]
net:[4026531833]
4026532492 /run/rustlet/netns/a4370a04d0b0…
```

The container's `sleep` (host pid 156614) is in namespace 4026532492, the
host in 4026531833, and the file under `/run/rustlet/netns/` *is*
4026532492. That file is the subject of the next section. Some sysctls
differ inside and out, too:

```text
$ cat /proc/sys/net/ipv4/ip_unprivileged_port_start /proc/sys/net/ipv4/ping_group_range   # on the host
1024
1	0
$ rustlet exec inode cat /proc/sys/net/ipv4/ip_unprivileged_port_start /proc/sys/net/ipv4/ping_group_range
0
0	2147483647
```

These are the defaults Docker gives its containers (§2.2.2,
[`sysctl::NETNS_DEFAULTS`](../../crates/rustlet-net/src/sysctl.rs)): any process may bind a port
below 1024 (container root in a user namespace has no `CAP_NET_BIND_SERVICE`
over a namespace the host owns), and `ping` works through ICMP datagram
sockets, without `CAP_NET_RAW`, which Rustlets' default capability set
leaves out.

## 2. Pinning: a namespace with nothing in it

A namespace lives as long as something refers to it: a process in it, an
open file descriptor of its `ns/net` file, or a **bind mount** of that
file. The daemon needs the namespace *before* the container's first
process exists: it has to give it an address and a route while nothing
runs. So it does what `ip netns add` does, and pins it with a bind mount
([`netns::create`](../../crates/rustlet-net/src/netns.rs)):

```rust
pub fn create(pin: &Path, setup: impl FnOnce() -> Result<()> + Send) -> Result<()> {
    on_own_thread(|| {
        unshare(CloneFlags::NEWNET).context("unshare a network namespace")?;
        setup()?;
        File::options()
            .write(true)
            .create_new(true)
            .mode(0o444)
            .open(pin)
            .with_context(|| format!("create {}", pin.display()))?;
        let pinned = mount(Some("/proc/thread-self/ns/net"), pin, None::<&str>, MsFlags::MS_BIND, None::<&str>)
            .with_context(|| format!("pin the network namespace at {}", pin.display()));
        …
```

`unshare(CLONE_NEWNET)` moves the calling thread into a new namespace;
`setup` brings its `lo` up and writes the sysctls above; the bind mount
of `/proc/thread-self/ns/net` onto an empty file keeps the namespace alive
after the thread ends. If `setup` fails, there is no pin yet and the
namespace simply dies with the thread: nothing to clean up.

The runtime never learns how the namespace came to be. The spec the daemon
writes says only "join this path" ([`spec::set_network_namespace`](../../crates/rustletd/src/spec.rs)):

```json
{ "type": "network", "path": "/run/rustlet/netns/1c250f9bdbc9a74f14feb6be201253e3c768338f6cf72f4c495e04d40a60dd1f" }
```

and `rustlet-runc` `setns`es into it in the parent before `clone3`, as it
does for any namespace given by path (§2.2 step 4.1). That is the split the
architecture chose in its first section: the runtime needs no networking
code, the daemon can configure the namespace while nothing runs in it,
and `--network container:web` is just another container's path.

The mount table shows the pin twice:

```text
$ ls -l /run/rustlet/netns/; grep rustlet/netns /proc/self/mountinfo | awk '{print $5, $9, $10}'
total 0
-r--r--r-- 1 root root 0 Oct  2 04:05 1c250f9bdbc9a74f14feb6be201253e3c768338f6cf72f4c495e04d40a60dd1f
/run/rustlet/netns tmpfs tmpfs
/run/rustlet/netns/1c250f9bdbc9… nsfs nsfs
/run/rustlet/netns/1c250f9bdbc9… nsfs nsfs
```

The first line is the pin *directory*: [`netns::prepare_dir`](../../crates/rustlet-net/src/netns.rs)
makes it a bind mount of itself with shared propagation, as iproute2 does
for `/run/netns`. A service started later with a private copy of the host's
mount table (`PrivateTmp=`, say) gets its copies of the pins as *slaves* of
these, so unpinning here unmounts them there too; otherwise such a copy
would keep a dead container's namespace alive for as long as the service
runs. The price is the second line: the directory is mounted on top of
itself in the same peer group, so a pin mounted on one propagates to the
other, and `mountinfo` lists both. `netns::remove` unmounts one and the
other goes with it.

A pin is made at every start and removed after every exit
(§8 below), like the container's overlay: a stopped container holds no
namespace.

## 3. Threads and namespaces

`unshare` and `setns` change the namespace of the **calling thread**, not
of the process. That is a gift (the daemon can do work inside a
container's namespace without leaving its own) and a trap: a tokio worker
or a `spawn_blocking` thread that `setns`es would stay in the container's
namespace and carry the next unrelated task there. So every step that has
to happen inside a namespace runs on a thread made for it and ended after
it:

```rust
fn on_own_thread<T: Send>(f: impl FnOnce() -> Result<T> + Send) -> Result<T> {
    std::thread::scope(|s| match s.spawn(f).join() {
        Ok(r) => r,
        Err(panic) => std::panic::resume_unwind(panic),
    })
}
```

`netns::create` uses it as shown, and `netns::run_in(ns, f)` is the same
with a `setns(ns, CLONE_NEWNET)` before `f`. A scoped thread may borrow
from its caller, so `f` can take references; a panic inside comes back to
the caller as a panic.

What such a thread creates belongs to the namespace it was created in, for
good, wherever it is used afterwards:

- a **netlink socket** talks to the namespace it was opened in, so the
  thread inside opens its own to configure `eth0` (§6);
- a **listening socket** listens there: the embedded DNS server's sockets
  are made this way and then served by the daemon's ordinary tokio runtime
  ([chapter 16](16-dns.md));
- a **child process** starts there: `nft`, spawned from a thread inside a
  container's namespace, edits *that* namespace's firewall
  ([chapter 16](16-dns.md) again).

The test harness plays the same trick on the daemon itself: every test
daemon is spawned from a thread inside a fresh namespace
([`TestNetns::spawn`](../../tests/src/net.rs)), so its bridges, its firewall table and its
`ip_forward` live and die with the test, and the suite never changes the
host's network (§10).

## 4. A cable and a switch

A **veth pair** is two network interfaces joined back to back: a frame sent
into one comes out of the other. Put one end in the container's namespace
and the other on the host, and the two namespaces are connected like two
machines by a cable. A **bridge** is a software Ethernet switch: interfaces
are attached to it as its ports, it learns which MAC addresses sit behind
which port (its forwarding database), and it forwards each frame to the
right port, or floods it to all of them if it doesn't know yet. The bridge
is also an interface of the host's own, and giving it an address makes the
host a machine on that switch: the containers' gateway.

```text
  host netns                                          container netns
  ┌───────────────────────────────────────────┐      ┌───────────────────────────────┐
  │ ens18 192.168.50.143 ── the LAN            │      │ lo 127.0.0.1                  │
  │                                            │      │                               │
  │ rustlet0 (bridge) 10.89.0.1/24             │      │ eth0 10.89.0.2/24             │
  │   ├─ rlv1c250f9bdbc9 ══════ veth pair ═════╪══════╪═ (02:52:0a:59:00:02)          │
  │   ├─ rlv… (another container)              │      │ default via 10.89.0.1         │
  │   └─ …                                     │      └───────────────────────────────┘
  └───────────────────────────────────────────┘
```

Before any container runs, the default network's bridge exists but has no
port, so it is `NO-CARRIER` and its route `linkdown`:

```text
$ ip -br link; ip -4 route; cat /proc/sys/net/ipv4/ip_forward
lo               UNKNOWN        00:00:00:00:00:00 <LOOPBACK,UP,LOWER_UP>
ens18            UP             bc:24:11:d5:fc:b3 <BROADCAST,MULTICAST,UP,LOWER_UP>
rustlet0         DOWN           d2:f7:5f:45:7f:c4 <NO-CARRIER,BROADCAST,MULTICAST,UP>
default via 192.168.50.1 dev ens18 proto dhcp src 192.168.50.143 metric 100
10.89.0.0/24 dev rustlet0 proto kernel scope link src 10.89.0.1 linkdown
192.168.50.0/24 dev ens18 proto kernel scope link src 192.168.50.143 metric 100
1
```

(`ip_forward` is 1: chapter 15 explains why, and in which order.) After
`rustlet run -d --name web -p 8080:80 nginx`:

```text
$ ip -br link
…
rustlet0         UP             d2:f7:5f:45:7f:c4 <BROADCAST,MULTICAST,UP,LOWER_UP>
rlv1c250f9bdbc9@if2 UP             e6:87:7f:65:0a:00 <BROADCAST,MULTICAST,UP,LOWER_UP>
$ ip -d link show type veth; bridge link
14: rlv1c250f9bdbc9@if2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master rustlet0 state UP …
    link/ether e6:87:7f:65:0a:00 brd ff:ff:ff:ff:ff:ff link-netnsid 0 promiscuity 1 …
    veth
    bridge_slave state forwarding priority 32 cost 2 hairpin off … learning on flood on …
14: rlv1c250f9bdbc9@ens18: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 master rustlet0 state forwarding priority 32 cost 2
```

Read the first line right to left: interface 14, the host's end, whose peer
is interface 2 (`@if2`) in another namespace (`link-netnsid 0`, the
host's local number for the container's namespace), attached to `rustlet0`
(`master rustlet0`), with the bridge port forwarding and learning MACs.
(`bridge link` prints `@ens18` because it looks the peer's index up in the
*host's* namespace, where 2 happens to be `ens18`: a display quirk.)

The names follow a scheme, because the kernel allows 15 characters
(`IFNAMSIZ` is 16, with the terminating NUL): `rustlet0` for the default
network's bridge, `rlb` + 12 hex digits of the network's id for a network
you create, and for the host's end of a container's veth on a network,
`rlv` + 12 hex digits of the SHA-256 of `<container id>/<network id>`
([`link::host_ifname`](../../crates/rustlet-net/src/link.rs)). (The transcript above is from before a
container could have several networks, when that name was `rlv` + the
container's short id: it had one veth.) A hash, because a container now
has a veth per network and 12 characters can't hold two ids; the same
container on the same network always gets the same name. What the name no
longer says, an **alias** does: right after creating the pair the daemon
tags the host's end with `rustlet <container id> <network id>`
(`IFLA_IFALIAS`, which `ip -d link` prints):

```text
$ ip -d link show type veth | grep -E "^[0-9]|alias"
77: rlv45ca9602c0e8@if2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master rlb5b9b1acf3190 state UP …
    alias rustlet 93f30e0340028a676f65f5bdff35f185d1383a8c93578a0b03ad27c64843da5c 5b9b1acf31902e2e4d07aa406efb17152aef28b40eabbf7a663de47eed341585
78: rlvb3290721304c@if3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master rlbbd6e48557003 state UP …
    alias rustlet 93f30e0340028a676f65f5bdff35f185d1383a8c93578a0b03ad27c64843da5c bd6e485570032a15a2899a0d43160514a9ef2124108b084a849f502cd7737ddc
```

One container, `93f30e034002…`, on two networks, with a veth on each
bridge. The tag is how a daemon that crashed finds what a run left (§8),
and it decides what the daemon may delete: a link with the name a new
endpoint wants is removed as a leftover only if its alias names the same
container on the same network; any other link of that name is left
alone, and the connection fails ([`link::attach`](../../crates/rustlet-net/src/link.rs)). A hash can
collide, in principle; an alias can't lie about whose link it is. The
container's ends are `eth0`, `eth1`, … in the order of its networks (§10).

Interfaces on an IPv4-only network get IPv6 turned off
(`net.ipv6.conf.<name>.disable_ipv6`, [`sysctl::disable_ipv6`](../../crates/rustlet-net/src/sysctl.rs)): an
interface coming up with IPv6 enabled would get a link-local address and
start sending router solicitations. The host's ends of veths are bridge
ports, which switch frames and need no addresses of their own, so they
never get IPv6. Networks with IPv6 are §11's.

## 5. rtnetlink: how `ip link add` talks to the kernel

`ip`, NetworkManager and Rustlets all configure interfaces the same way: by
sending messages to the kernel over a **netlink socket**
(`socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)`), the "routing netlink" or
rtnetlink family. A request is a 16-byte header (`nlmsghdr`: length,
type, flags, sequence number, port id), a fixed header for the kind of
object (`ifinfomsg` for links, `ifaddrmsg` for addresses, `rtmsg` for
routes), and then **attributes**: type-length-value records, each padded to
4 bytes, which can nest. The kernel answers each request that asked for an
acknowledgement (`NLM_F_ACK`) with an `NLMSG_ERROR` message whose error is 0
on success or a negative errno, and a dump (`NLM_F_DUMP`) with a series of
messages ending in `NLMSG_DONE`. [`RtNetlink::request`](../../crates/rustlet-sys/src/netlink.rs)
sends one request and reads until one of those.

The veth pair is the most interesting request, because its peer is a whole
link description nested three levels deep. [`RtNetlink::create_veth`](../../crates/rustlet-sys/src/netlink.rs):

```rust
let mut msg = MsgBuilder::new(RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL)
    .header(&IfInfoMsg::default().to_bytes())
    .attr_str(IFLA_IFNAME, name)
    .begin_nest(IFLA_LINKINFO)
    .attr_str(IFLA_INFO_KIND, "veth")
    .begin_nest(IFLA_INFO_DATA)
    .begin_nest(VETH_INFO_PEER)
    .header(&IfInfoMsg::default().to_bytes())
    .attr_str(IFLA_IFNAME, peer.name);
if let Some(ns) = peer.netns {
    msg = msg.attr_u32(IFLA_NET_NS_FD, ns.as_raw_fd() as u32);
}
if let Some(mac) = peer.mac {
    msg = msg.attr(IFLA_ADDRESS, &mac);
}
self.request(msg.end_nest().end_nest().end_nest()).map(drop)
```

`begin_nest` writes a placeholder length and remembers where; `end_nest`
fills it in once the nest's contents are known; `finish` fills in the
message's own length and sequence number. Here is the message for the
container `9104cfe7cba7…`, whose namespace fd was 21 and whose address was
10.89.0.3 (little-endian integers; printed 4 bytes a line by a throwaway
test that built it with `MsgBuilder`; recorded when the host's end was
still named after the short id, where today the 15 bytes of its name are
§4's hash):

```text
offset  bytes         meaning
  0     7c 00 00 00   nlmsg_len = 124
  4     10 00 05 06   type 16 = RTM_NEWLINK; flags 0x0605 = REQUEST | ACK | EXCL | CREATE
  8     03 00 00 00   sequence 3
 12     00 00 00 00   port id 0 (the kernel)
 16–31  00 … 00       ifinfomsg: family, type, index, flags, change all 0 (a new link)
 32     14 00 03 00   attribute, 20 bytes, IFLA_IFNAME (3)
 36–51  "rlv9104cfe7cba7\0"
 52     48 00 12 80   72 bytes, IFLA_LINKINFO (18) | NLA_F_NESTED (0x8000)
 56     09 00 01 00     9 bytes, IFLA_INFO_KIND (1): "veth\0", padded to 12
 68     38 00 02 80     56 bytes, IFLA_INFO_DATA (2), nested
 72     34 00 01 80       52 bytes, VETH_INFO_PEER (1), nested: a link of its own
 76–91  00 … 00             its ifinfomsg
 92     09 00 03 00         9 bytes, IFLA_IFNAME: "eth0\0", padded to 12
104     08 00 1c 00         8 bytes, IFLA_NET_NS_FD (28): 15 00 00 00 = fd 21
112     0a 00 01 00         10 bytes, IFLA_ADDRESS (1): 02 52 0a 59 00 03, padded to 12
```

The strace of the daemon during one start shows the kernel's side of the
same conversation, decoded (cut short where strace prints the nested bytes
raw):

```text
sendto(22, [{nlmsg_len=124, nlmsg_type=RTM_NEWLINK, nlmsg_flags=NLM_F_REQUEST|NLM_F_ACK|NLM_F_EXCL|NLM_F_CREATE, nlmsg_seq=3, …},
  {ifi_family=AF_UNSPEC, ifi_type=ARPHRD_NETROM, ifi_index=0, …},
  [[{nla_len=20, nla_type=IFLA_IFNAME}, "rlv9104cfe7cba7\0"…],
   [{nla_len=72, nla_type=NLA_F_NESTED|IFLA_LINKINFO}, [[{nla_len=9, nla_type=IFLA_INFO_KIND}, "veth"],
    [{nla_len=56, nla_type=NLA_F_NESTED|IFLA_INFO_DATA}, "\x34\x00\x01\x80…"…
sendto(22, [{nlmsg_len=40, nlmsg_type=RTM_NEWLINK, …}, {…, ifi_index=if_nametoindex("rlv9104cfe7cba7"), …},
  [{nla_len=8, nla_type=IFLA_MASTER}, 3]], 40, 0, NULL, 0) = 40
sendto(22, [{nlmsg_len=32, nlmsg_type=RTM_NEWLINK, …}, {…, ifi_index=if_nametoindex("rlv9104cfe7cba7"), ifi_flags=IFF_UP, ifi_change=0x1}], …)
…  (and at the exit)
sendto(14, [{nlmsg_len=32, nlmsg_type=RTM_DELLINK, …}, {…, ifi_index=if_nametoindex("rlv9104cfe7cba7"), …}], …)
```

Create the pair; make bridge 3 (`rustlet0`) the host end's master; bring it
up; and at the exit, delete it. (strace calls `ifi_type` 0 `ARPHRD_NETROM`,
the hardware type numbered 0; the kernel ignores the field in a request.)
Today one more request comes between the first two: the alias of §4, set
by a request of its own for the existing link, as `ip link set … alias`
sends it (once the link exists and has an index, it can be looked up by
name and tagged). From `rustlet network connect six web`:

```text
sendto(22, [{nlmsg_len=176, nlmsg_type=RTM_NEWLINK, …}, {…, ifi_index=if_nametoindex("rlvb3290721304c"), …},
  [{nla_len=141, nla_type=IFLA_IFALIAS},
   "rustlet 93f30e0340028a676f65f5bdff35f185d1383a8c93578a0b03ad27c64843da5c bd6e485570032a15a2899a0d43160514a9ef2124108b…"]], …)
```

**The peer is created inside the container's namespace, in the same
message.** `IFLA_NET_NS_FD` sits among the *peer's* attributes, so the
kernel creates the host's end here and the peer directly in the namespace
the fd names, already called `eth0`, with its MAC. The architecture
planned the older way, which many tools still use: create both ends on the
host, move the peer with a second request, then rename it from inside.
That briefly puts an extra interface on the host under a temporary name,
needs a rename, and leaves a half-moved pair if the daemon dies between
the steps. One message is all or nothing. (§2.5 records it as a
deviation.)

The codec is about 800 lines of safe Rust (a third of them tests) over
`nix`'s socket calls. The
decoding side (`parse_messages`, `attrs`, `LinkInfo`, `AddrInfo`,
`RouteInfo`) reads the link, address and route dumps. Its unit tests
encode a veth request and walk the nesting back, decode address and route
messages, and dump the host's links, addresses and routes as an ordinary
user (dumps need no privilege; creating does, and `creating_needs_privileges`
checks the `EPERM`).

## 6. Addresses, routes and MACs

Once the pair exists, a thread inside the container's namespace finishes
the job ([`link::configure_inside`](../../crates/rustlet-net/src/link.rs)):

```rust
let link = nl.link_by_name(ep.ifname)…;
match ep.address6 {
    Some((ip, len)) => {
        sysctl::enable_ipv6(ep.ifname)?;
        nl.add_address6(link.index, ip, len, true)…;
    }
    None => sysctl::disable_ipv6(ep.ifname)?,
}
nl.add_address(link.index, ep.address, ep.prefix_len)…;
nl.set_link_up(link.index)…;
```

The address request is short (`RTM_NEWADDR`, an `ifaddrmsg` with family
`AF_INET`, prefix length 24 and the interface's index, then
`IFA_LOCAL`, `IFA_ADDRESS` and `IFA_BROADCAST`: 10.89.0.3, 10.89.0.3,
10.89.0.255; the broadcast address is what `ip addr add … brd +` computes,
`netlink::broadcast`). Adding the address also makes the kernel add the
*connected* route for its subnet (`proto kernel` below).

The default routes are the only routes the daemon adds, and it adds them
apart, once every interface exists ([`link::set_default_routes`](../../crates/rustlet-net/src/link.rs)):
which network a container's default route goes through depends on all of
its networks (§10), and changes when they do. So it asks with
`NLM_F_CREATE | NLM_F_REPLACE`, as `ip route replace` does: one request
that adds the route or moves it. strace decodes netlink only for sockets
it knows the protocol of, and it can't tell for one made in another
namespace, so inside the container the requests show up raw. These are
from the same `network connect` (decoded by hand; `web` was already on
`back`, IPv4 only, and `six` has IPv6):

```text
nlmsg_type 0x14 RTM_NEWADDR, flags CREATE|EXCL
  0a 40 02 00 03 00 00 00      ifaddrmsg: AF_INET6, /64, flags 02 = IFA_F_NODAD, scope 0, eth1 (index 3)
  14 00 01 00 fd 9a 00 7b 7e 99 00 00 00 00 00 00 00 00 00 02    IFA_ADDRESS fd9a:7b:7e99::2
  08 00 08 00 02 00 00 00      IFA_FLAGS: IFA_F_NODAD again, as a 32-bit field
nlmsg_type 0x18 RTM_NEWROUTE, flags CREATE|REPLACE
  02 00 00 00 fe 03 00 01 …    rtmsg: AF_INET, dst/0, table 254 (main), proto 3 (boot), scope 0, unicast
  08 00 05 00 0a 59 01 01      RTA_GATEWAY 10.89.1.1 (back's gateway)
  08 00 04 00 02 00 00 00      RTA_OIF 2 (eth0)
nlmsg_type 0x18 RTM_NEWROUTE, flags CREATE|REPLACE
  0a 00 00 00 fe 03 00 01 …    rtmsg: AF_INET6, the same
  14 00 05 00 fd 9a … 00 01    RTA_GATEWAY fd9a:7b:7e99::1 (six's gateway)
  08 00 04 00 03 00 00 00      RTA_OIF 3 (eth1)
```

An internal network never carries a default route ([chapter 15](15-nat-nftables.md)); without a
network that has a way out, the route is deleted (`RTM_DELROUTE`, which
for a route that isn't there answers `ESRCH` for IPv4 and `ENOENT` for
IPv6). What a container on one network sees:

```text
$ nsenter -t 132321 -n ip -d addr; nsenter -t 132321 -n ip route
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    inet 127.0.0.1/8 scope host lo
    inet6 ::1/128 scope host
2: eth0@if14: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 02:52:0a:59:00:02 brd ff:ff:ff:ff:ff:ff link-netnsid 0 …
    veth …
    inet 10.89.0.2/24 brd 10.89.0.255 scope global eth0
default via 10.89.0.1 dev eth0
10.89.0.0/24 dev eth0 proto kernel scope link src 10.89.0.2
```

`eth0@if14`: its peer is interface 14 in the host's namespace, the
`rlv1c250f9bdbc9` of §4. `lo` keeps its IPv6 `::1`; `eth0` has none.

**The MAC follows the address.** `02:52:0a:59:00:02` is `02:52:` and the
four bytes of 10.89.0.2 ([`ipam::mac_for`](../../crates/rustlet-net/src/ipam.rs)), as Docker derives
`02:42:…`. The `02` sets the "locally administered" bit and clears the
multicast bit, so no vendor's MAC can clash with it. The reason to derive
it: when an address is released and handed to the next container, its
neighbours' ARP caches still map that address to a MAC, and with a random
MAC per container they would send frames to a port that no longer has it
until the cache entry expires. With the MAC derived from the address, the
stale entry is right.

ARP itself needs nothing from us. The container asks "who has 10.89.0.1?",
the frame floods across the bridge, the bridge's own interface answers,
and from then on the bridge knows which port each MAC is behind (`bridge
fdb show br rustlet0`).

**The bridge's own MAC is set too**, to `02:52:` and its gateway's address
(`02:52:0a:59:00:01`; no container has the gateway's address, so no
container has that MAC). A bridge created without one gets a random MAC,
and then, at each port added or removed, takes the lowest of its ports'
MACs (the kernel's `br_stp_recalculate_bridge_id`), unless its MAC was set
explicitly: the host ends of veths have random MACs, so one container
starting or stopping could change the gateway's MAC under all the others,
whose ARP and neighbour entries for 10.89.0.1 then led to a MAC nothing
answers to, for the 15 to 50 s until those entries expired. Docker sets
its bridges' MACs for the same reason. The independent review found it
(`net_a_bridge_keeps_its_mac`).

## 7. Which address: IPAM

Every network is an IPv4 subnet ([`ipam.rs`](../../crates/rustlet-net/src/ipam.rs)). The default
network, `bridge`, is `10.89.0.0/24`. A network you create gets the next
free `/24` of the pool `10.89.0.0/16`, or the `--subnet` you give it, which
must not overlap another network or any route the host already has (the
LAN's, a VPN's: [`link::routed_blocks`](../../crates/rustlet-net/src/link.rs) dumps the main routing
table). The architecture first planned a `/16` for the default network;
that would have left no room for other networks in the same block, so it
is a `/24` (§2.5 records the deviation). The subnet's first address is the
gateway, the bridge's own; containers get the others, never the network
address or the broadcast address. A subnet is checked when it is parsed:
no host bits (`10.89.0.5/24` is refused with "did you mean
10.89.0.0/24?"), a prefix of 8 to 30.

Addresses are handed out next after the last one given, wrapping around
([`Allocator::allocate`](../../crates/rustlet-net/src/ipam.rs)):

```rust
let after = self.last.map(u32::from).filter(|&a| (first..=last).contains(&a)).map_or(first, |a| a + 1);
for i in 0..count {
    let candidate = first + (after - first + i) % count;
    let ip = Ipv4Addr::from(candidate);
    if ip != self.gateway && !in_use(ip) {
        self.last = Some(ip);
        return Some(ip);
    }
}
```

So an address that was just released is the last to be reused: another
way, besides the MAC, to let stale caches and cached DNS answers expire.

**IPv6.** A network created with `--ipv6` has an IPv6 subnet as well
([`Subnet6`, `Allocator6`](../../crates/rustlet-net/src/ipam.rs)): the next free `/64` of the daemon's IPv6
pool, or the one given. The pool is a `/48` of *unique local addresses*
(`fd00::/8`, RFC 4193), IPv6's counterpart of `10/8`: routed nowhere beyond
the host, which NATs them as it does the IPv4 ones ([chapter 15](15-nat-nftables.md)). RFC 4193
wants the 40 bits after `fd` chosen at random, so that two sites' blocks
almost never collide when their networks are joined; [`Subnet6::ula`](../../crates/rustlet-net/src/ipam.rs)
takes them from the SHA-256 of the host's machine id: random-looking, and
the same at every start without being written down. On this host:

```text
$ rustlet network create --ipv6 six; rustlet network ls
bd6e485570032a15a2899a0d43160514a9ef2124108b084a849f502cd7737ddc
NETWORK ID     NAME      DRIVER    SUBNET
5b9b1acf3190   back      bridge    10.89.1.0/24
cac3b9f59cd5   bridge    bridge    10.89.0.0/24
bd6e48557003   six       bridge    10.89.2.0/24, fd9a:7b:7e99::/64
```

IPv6 has no broadcast address, and a subnet's first address (host bits
all zero) is the *subnet-router anycast* address, which no host may have:
the gateway is the one after it (`fd9a:7b:7e99::1`), and containers get the
rest, next after the last as with IPv4. The `/64`s taken are checked
against the other networks and the host's IPv6 routes (this host's LAN
is `fd4b:a90d:1d5c:63::/64`, learned from its router's advertisements).
The default network has no IPv6, as Docker's hasn't unless configured.

**Addresses asked for.** `--ip 10.89.1.50` (and `--ip6`, and `network
connect --ip/--ip6`) give a container a fixed address, on a user-defined
network only: the default network's addresses are the daemon's to hand
out (Docker's rule too). It must be a host address of the subnet, not the
gateway; that is checked at create, and whether another running container
has it, at start, as a conflict. Docker gives a stopped container's fixed
address to the next container that asks for any address, after which the
stopped one can't start; Rustlets' allocator skips every address that any
container on the network asked for, running or not
([`static_addresses`](../../crates/rustletd/src/network.rs)). `dn_several_networks_and_static_addresses`
checks both.

**IPAM keeps nothing.** Which addresses are in use is recorded in one place
only: each running container's `NetRun`, in its row of `state.db`. At
startup the daemon rebuilds its table of addresses in use from those rows
(`Networks::restore`) before it does anything else with the network; the
allocator's "last" is forgotten and starts over. inspect shows a run's
share:

```text
$ rustlet inspect web | grep -A12 '"network"'
…
    "network": {
      "dns_names": [],
      "gateway": "10.89.0.1",
      "ip_address": "10.89.0.2",
      "ip_prefix_len": 24,
      "mac_address": "02:52:0a:59:00:02",
      "mode": "bridge",
      "network": "bridge",
      "network_id": "cac3b9f59cd50606dfae2eeaa04eff0b747f0a064f4b647ebf1858b7fccde254",
      "ports": [ { "container_port": 80, "host_ip": "0.0.0.0", "host_port": 8080, "protocol": "tcp" } ],
      "sandbox": "/run/rustlet/netns/1c250f9bdbc9…"
    },
```

(`dns_names` is empty because the default network has no DNS server;
[chapter 16](16-dns.md).)

## 8. The life of a run's network

A run's network is made at its start and undone after its exit, exactly
like its root filesystem ([`lifecycle::start_on`](../../crates/rustletd/src/lifecycle.rs)):

```rust
let net = self.attach_network(c).await?;
if let Err(e) = c.update(&self.db, |s| s.network = Some(net.clone())) {
    self.detach_network(c, &net).await;
    return Err(e);
}
let started = async {
    self.prepare_volumes(c, rootfs).await?;
    let plan = self.run_plan(c, &net).await?;
    self.start_shim(c, image, rootfs, &plan).await
}
.await;
if started.is_err() {
    self.detach_network(c, &net).await;
    …
```

`attach_network` (`network.rs`) pins the namespace, takes an address,
creates the veth and configures `eth0`, registers DNS names on a
user-defined network and starts its DNS server ([chapter 16](16-dns.md)), binds
the published ports' sockets and puts their rules in the firewall
([chapter 15](15-nat-nftables.md)). Each step records what it did in the `NetRun`
it is building, so that a failure part way undoes exactly what exists.
The finished `NetRun` is written to the database **before anything else
can fail**, before the volumes, the generated files or the shim: a daemon
that dies after this point leaves its successor a record of every
resource the run holds.

For a daemon that dies *during* `attach_network`, before that write, the
names are the record: the pin is `<run>/netns/<container id>`, and the
veths carry the container's id in their alias (§4), so the next start (or
removal) of the container deletes the pin and every link tagged `rustlet
<container id>` first ([`remove_network_leftovers`](../../crates/rustletd/src/network.rs), called from
`clear_leftovers`, through `NetworkBackend::disconnect_tagged`). The
addresses were never written down, so they were never taken. A network
connected while the container runs is recorded the other way round,
before its veth exists (§10).

After the exit, `handle_exit` unmounts the overlay, then
`detach_network` closes the run's DNS server and proxies (and waits until
their sockets are gone), forgets its DNS names and its address, takes its
ports out of the firewall, deletes the host's end of the veth and unpins
the namespace; only then is the exit published, so a `run --rm` followed at
once by a run with the same port works. The veth is
deleted explicitly rather than left to die with the namespace, because the
namespace may not die: a container started with `--network container:web`
keeps `web`'s namespace alive after `web` exits, and with the veth still
in it, it would keep using an address the daemon now considers free.
Deleting either end of a pair deletes both, so the joiner is left with
`lo`, as in Docker.

At daemon startup, every run the database says holds a network is
restored first (addresses, DNS names, port rules); then the host's
network is set up (chapter 15); then reconciliation takes over the runs
that are still going, giving them new DNS sockets and proxies (the old
ones died with the old daemon), and undoes the networks of those that
ended while there was no daemon. `dn_networking_survives_a_daemon_restart`
kills the daemon and checks that the published port still answers while
there is none, and that a new container afterwards gets the next address,
not the old one's.

## 9. Five modes

`--network` chooses where the namespace comes from
([`NetworkMode`](../../crates/rustlet-spec/src/network.rs), checked by `Daemon::choose_network`
at create):

| `--network` | namespace (the spec) | eth0 | hostname | `hosts`, `resolv.conf` |
|---|---|---|---|---|
| `bridge` (default) | its own pin | on `rustlet0` | the short id | generated; the host's resolvers |
| a network's name | its own pin | on `rlb<id>` | the short id | generated; `127.0.0.11` ([ch. 16](16-dns.md)) |
| `none` | its own pin, `lo` only | none | the short id | generated |
| `host` | none at all: the runtime's, the host's | the host's interfaces | the host's | copies of the host's |
| `container:<x>` | `x`'s pin (`x` must be running) | `x`'s | `x`'s | `x`'s files |

`host` removes the `network` entry from the spec, so the container shares
the namespace `rustlet-runc` runs in, which is the daemon's (it keeps a
UTS namespace of its own, with the host's name in it, as Docker does).
Published ports are discarded there, with a warning in the create
response: every port the program opens is the host's already.
`container:<x>` takes `x`'s id at create, so a later container named `x`
isn't confused with it, and refuses what would contradict sharing: `-p`,
`--dns*`, `--add-host`, `--hostname`, `--network-alias`, `--ip`, `--ip6`
and more networks. Network aliases exist only on user-defined networks,
where there is a DNS server to answer them.

`--network` can be given more than once: the first is the mode (and gets
`--network-alias`, `--ip` and `--ip6`), the others are more networks the
container is connected to (`extra_networks`), each a bridge network;
`host`, `none` and `container:<x>` combine with nothing.

## 10. Several networks

A container can be on several networks: `--network a --network b` at
create, or `rustlet network connect b web` later, running or stopped; and
`network disconnect` takes one away. Each network is an interface, in the
order the container was connected to them: `eth0`, `eth1`, … (one
connected later takes the lowest number free). Here `web`, started on
`back` (IPv4 only), was then connected to `six` (IPv6 too):

```text
$ nsenter -t 276388 -n ip addr
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    inet 127.0.0.1/8 scope host lo
    inet6 ::1/128 scope host
2: eth0@if77: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 02:52:0a:59:01:02 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 10.89.1.2/24 brd 10.89.1.255 scope global eth0
3: eth1@if78: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 02:52:0a:59:02:02 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 10.89.2.2/24 brd 10.89.2.255 scope global eth1
    inet6 fd9a:7b:7e99::2/64 scope global nodad
    inet6 fe80::52:aff:fe59:202/64 scope link
$ nsenter -t 276388 -n ip route; nsenter -t 276388 -n ip -6 route
default via 10.89.1.1 dev eth0
10.89.1.0/24 dev eth0 proto kernel scope link src 10.89.1.2
10.89.2.0/24 dev eth1 proto kernel scope link src 10.89.2.2
fd9a:7b:7e99::/64 dev eth1 proto kernel metric 256 pref medium
fe80::/64 dev eth1 proto kernel metric 256 pref medium
default via fd9a:7b:7e99::1 dev eth1 metric 1024 pref medium
```

**One default route per family.** Two interfaces, but still one default
route for IPv4 and one for IPv6, so the daemon chooses: the first of the
container's networks, in its order, that has a way out (isn't internal),
and for IPv6 the first such one with IPv6 ([`route_v4`, `route_v6`](../../crates/rustletd/src/db.rs)).
Here IPv4 goes out through `back` (eth0) and IPv6 through `six` (eth1),
the only network with IPv6. A network connected later comes later in the
order, so connecting one never moves a route; disconnecting the network a
route goes through does. Docker's choice depended on an order of its own
until 28.0 added `--gw-priority`. The container's **published ports**
follow the same networks, IPv4 and IPv6 each: they lead to the addresses
its default routes leave from. inspect says which is which:

```text
$ rustlet inspect web     # "networks", cut short
        { "network": "back", "interface": "eth0", "host_interface": "rlv45ca9602c0e8",
          "ip_address": "10.89.1.2", "gateway": "10.89.1.1", "ipv6_address": null,
          "default_route": true, "default_route6": false, … },
        { "network": "six", "interface": "eth1", "host_interface": "rlvb3290721304c",
          "ip_address": "10.89.2.2", "gateway": "10.89.2.1", "ipv6_address": "fd9a:7b:7e99::2",
          "ipv6_gateway": "fd9a:7b:7e99::1", "default_route": false, "default_route6": true, … }
```

**Connecting a running container** is a start's work for one network,
done live ([`connect_network`](../../crates/rustletd/src/network.rs), `connect_live`): its addresses, the veth
and `ethN` inside, its names in the zone. Then everything that depends on
the whole set of networks follows (`follow_endpoints`): the default
routes, the DNS server's view ([chapter 16](16-dns.md)), the published ports'
targets, the firewall, and the container's `/etc/hosts` and
`/etc/resolv.conf`. Those two are rewritten **in place**: they are bind
mounts of files in the container's directory, and a write to the same
inode shows inside at once, where replacing the file (a rename) wouldn't.
The new endpoint is written to the container's `NetRun` *before* its veth
exists: a daemon that dies in between leaves its successor the record of
the addresses and the link, not a veth nobody knows of.

**Disconnecting** undoes one network: its names leave the zone, its veth
is deleted (and its `ethN` with it, inside), its addresses are freed, and
the same things follow. Disconnected from `back`, `web`'s IPv4 route and
its published port moved to `six`, through DNAT and the proxy alike:

```text
$ rustlet network disconnect back web
$ nsenter -t 276388 -n ip -br addr; nsenter -t 276388 -n ip route
lo               UNKNOWN        127.0.0.1/8 ::1/128
eth1@if78        UP             10.89.2.2/24 fd9a:7b:7e99::2/64 fe80::52:aff:fe59:202/64
default via 10.89.2.1 dev eth1
10.89.2.0/24 dev eth1 proto kernel scope link src 10.89.2.2
$ curl -s 192.168.50.143:8080 | grep title; curl -s localhost:8080 | grep title
<title>Welcome to nginx!</title>
<title>Welcome to nginx!</title>
```

`dn_connect_and_disconnect` takes the same steps with a client on the
other network, and ends with a container disconnected from everything
(`lo` only, and the host's servers in its `resolv.conf` again, which the
container reads as rewritten). A stopped container can be connected and
disconnected too: the change is recorded with it (`Persisted.networks`,
its networks and what it asked for on each) and takes effect at its next
start. A container created with `host`, `none` or `container:<x>` has no
networks of its own to change, and refuses.

## 11. IPv6 on a bridge

On a network with IPv6 the bridge gets the gateway's IPv6 address, the
containers' interfaces get theirs, and both come up with three sysctls
set first, in this order ([`sysctl::enable_ipv6`](../../crates/rustlet-net/src/sysctl.rs)):

```text
$ ip -6 addr show dev rlbbd6e48557003
76: rlbbd6e48557003: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    inet6 fd9a:7b:7e99::1/64 scope global nodad
    inet6 fe80::a88b:44ff:fe2c:a711/64 scope link
net.ipv6.conf.rlbbd6e48557003.accept_ra = 0
net.ipv6.conf.rlbbd6e48557003.accept_dad = 0
net.ipv6.conf.rlbbd6e48557003.forwarding = 1
net.ipv6.conf.rlbbd6e48557003.disable_ipv6 = 0
```

- `accept_ra = 0`: router advertisements are ignored. The daemon gives
  every address and route; and a container that can send raw packets
  (`CAP_NET_RAW`, not in the default set) could otherwise advertise itself
  as a router to its neighbours, or to the host, across the bridge.
- `accept_dad = 0`: no duplicate address detection, so the link-local
  address is usable as soon as it exists; the global addresses are added
  with `IFA_F_NODAD` for the same reason. A test found why that matters
  (below).
- `disable_ipv6 = 0`, last, so that the other two are in place first.

A pinned namespace's own defaults are the opposite
([`sysctl::NETNS_DEFAULTS6`](../../crates/rustlet-net/src/sysctl.rs): `default.disable_ipv6 = 1`,
`default.accept_ra = 0`): every interface created in it starts without
IPv6, and only those on IPv6 networks are given some. That is why `eth0`
in §10, on `back`, has no `inet6` line at all, not even a link-local one.

**The second that went missing.** The first version left duplicate
address detection on, and `net_ipv6_bridge_nat66_published_ports_and_guards`
failed: the LAN's first connection to a published port over IPv6 timed
out, and a second one, made right after, worked. Timing the setup showed
the pattern:

```text
1.390 s  the container's link-local address valid (its DAD done)
1.846 s  the bridge's link-local address valid
2.081 s  the first connection from the LAN namespace that got through
```

The global addresses had `nodad` and were valid from the start, so the
host could reach the container, and the container the LAN. What failed
was traffic the host *forwarded* to the container. To send it, the host
needs the container's MAC, so it sends a Neighbor Solicitation out of the
bridge. The kernel's `ndisc_solicit` (`net/ipv6/ndisc.c`) uses the
packet's own source address for the solicitation only if it is one of the
interface's addresses, which a forwarded packet's isn't; otherwise
`ndisc_send_ns` takes the interface's link-local address, and while that
is still tentative it **sends nothing at all**. The packet waits on a
neighbour entry that nobody is resolving, and the client gives up. With
DAD off, the bridge's link-local address is valid at once. It can't
collide with a neighbour's: the containers' MACs, from which their
link-local addresses are made, come from their unique IPv4 addresses
(§6), and the bridge's is the kernel's random one.

IPv6 forwarding is one host-wide switch, `net.ipv6.conf.all.forwarding`.
The daemon turns it on only once there is a network with IPv6, records its
old value first, in the same file as `ip_forward`, and the firewall
forwards no IPv6 but its own bridges' ([chapter 15](15-nat-nftables.md) §6–§7). Forwarding on
also makes the *kernel* ignore router advertisements on the host's own
interfaces. On this host NetworkManager configures `ens18`'s IPv6 from
them in user space (the kernel's `accept_ra` is 0 there anyway), so
nothing changed for the host: at the next advertisement, with forwarding
on, its addresses were refreshed as before (`valid_lft` back to 1800 s).
On a host where the kernel takes the advertisements itself, keeping them
with forwarding on needs `accept_ra = 2` on that interface.

## 12. Leaving the rest of the host alone

**NetworkManager** manages interfaces as they appear, and Rustlets doesn't
want it near its bridges and veths. `cargo xtask daemon install` installs
[`packaging/networkmanager-zz-rustlet.conf`](../../packaging/networkmanager-zz-rustlet.conf):

```ini
[keyfile]
unmanaged-devices+=interface-name:rustlet*;interface-name:rlb*;interface-name:rlv*
```

The milestone found that its first version did nothing. `conf.d` files are
read in alphabetical order, each overriding the ones before, and Ubuntu
ships `ubuntu-system-adjustments.conf` with `unmanaged-devices=none`; read
after `rustlet.conf`, it undid it, and `nmcli device status` kept showing
`rustlet0` as "connected (externally)". The file is now named to sort
last, and appends (`+=`) to whatever the earlier files set:

```text
$ nmcli device status
DEVICE    TYPE      STATE                   CONNECTION
ens18     ethernet  connected               Wired connection 1
lo        loopback  connected (externally)  lo
rustlet0  bridge    unmanaged               --
```

**The tests** never touch the host's network. [`TestLan`](../../tests/src/net.rs)
makes a "host" namespace for a test daemon and a "LAN" namespace beside
it, joined by a veth (192.0.2.0/24, TEST-NET-1, and 2001:db8::/64, both
reserved for documentation): the host is .2 (and ::2), the LAN machine .1
(::1), which also serves the fake DNS upstream of chapter 16. The `net_`
tests drive rustlet-net directly in such namespaces;
`net_bridge_nat_published_ports_and_guards` builds a bridge, a pinned
container namespace and its veth, then checks the container's MAC and
route, before chapter 15's firewall checks;
`net_ipv6_bridge_nat66_published_ports_and_guards` does the same on a
dual-stack bridge, and checks the sysctls of §11. The
`dn_` tests do the same through a daemon. When a test ends its namespaces
go, and with them every bridge and veth it made.

**The seam.** Everything that touches the host's interfaces or firewall
goes through [`NetworkBackend`](../../crates/rustlet-net/src/backend.rs): ensure or remove a
network's host side, connect or disconnect a namespace (or all of one
container's, by tag), set its default routes, apply the firewall. `Bridge` is the only implementation; rootless mode (Phase 8)
can't create interfaces on the host at all and will plug `pasta` in there.

## 13. Differences from Docker

- Docker's default bridge is `docker0` on `172.17.0.0/16`; Rustlets'
  is `rustlet0` on `10.89.0.0/24`, and user-defined networks are `/24`s of
  `10.89.0.0/16` (Docker's are `/16`s from `172.18`–`172.31`, then
  `192.168.0.0/16` in `/20`s).
- Docker names the host's end `veth` + 7 random hex digits; Rustlets
  `rlv` + a hash of the container's and the network's ids, tagged with an
  alias naming both, which tells you whose it is and lets a restarted
  daemon find a leftover.
- Docker (libnetwork) creates the pair on the host and moves the peer into
  the sandbox; Rustlets creates the peer inside, in one request.
- Both pin a namespace per container (Docker under `/var/run/docker/netns/`),
  derive the MAC from the address, and release the address when the
  container stops; both connect and disconnect networks while a container
  runs. Docker's default route goes, since 28.0, through the network with
  the highest `--gw-priority`; Rustlets' through the first network
  connected that has a way out.
- Both give a network IPv6 with `--ipv6`; Docker 27 and later pick a ULA
  `/64` when none is given, as Rustlets does from a `/48` derived from the
  machine id. Docker keeps duplicate address detection; Rustlets turns it
  off on its bridges and containers (§11).
- A fixed address (`--ip`) is reserved for its container while it is
  stopped, which Docker doesn't do.

## 14. Try it

```sh
export PATH=$HOME/.cargo/bin:$PATH
cargo xtask daemon install
R="sudo target/debug/rustlet"
ip -br link; ip -4 route                       # rustlet0, no ports yet
$R run -d --name web nginx
ip -d link show type veth; bridge link; bridge fdb show br rustlet0
$R inspect web | grep -A10 '"network": {'      # address, MAC, sandbox
PID=$($R inspect web | sed -n 's/.*"pid": \([0-9]*\).*/\1/p' | head -1)
sudo nsenter -t $PID -n ip addr; sudo nsenter -t $PID -n ip route
grep rustlet/netns /proc/self/mountinfo        # the pin, twice
sudo strace -f -e trace=sendto -p $(systemctl show -p MainPID --value rustletd) &
$R run --rm alpine true; sudo pkill strace     # the RTM_NEWLINK of §5
$R network create --ipv6 six && $R network connect six web
ip -d link show type veth | grep -E '^[0-9]|alias'      # whose veth is whose
sudo nsenter -t $PID -n ip addr; sudo nsenter -t $PID -n ip -6 route
$R network disconnect bridge web; sudo nsenter -t $PID -n ip route   # the route moved
sysctl net.ipv6.conf.all.forwarding; cat /run/rustlet/host-sysctl.orig
$R rm -f web; $R network rm six; ip -br link   # the veths are gone
cargo xtask itest -- net_ dn_                  # the tests behind this chapter
```

## Check yourself

1. The daemon creates a container's namespace before the container
   exists. What keeps that namespace alive, and what frees it?
2. Why does `netns::create` run on a thread of its own, rather than in a
   `spawn_blocking` closure? What would go wrong, and when?
3. A thread inside a container's namespace opens a TCP listening socket
   and hands it to the daemon's tokio runtime. In which namespace does the
   socket listen, and why?
4. In the hex dump of §5, which bytes would change if the peer were to be
   created in the host's namespace instead, and what would the daemon then
   have to do before the container could use it?
5. Why does the pin appear twice in `mountinfo`? What would go wrong in a
   service started with `PrivateTmp=yes` if the pin directory were a
   private mount instead?
6. A container's address is released when it exits, and the next
   container gets it. Why derive the MAC from the address, rather than
   let the kernel pick one at random?
7. Where is the record of which addresses are in use? What happens to it
   when the daemon dies between pinning a namespace and writing the
   container's `NetRun`?
8. `x` runs; `y` was started with `--network container:x`. `x` exits.
   What does `y` still have, and why does the daemon delete `x`'s veth
   instead of letting it go with the namespace?
9. Why is the default network a `/24` and not the `/16` first planned?
   What does `rustlet network create` check before it takes a subnet?
10. NetworkManager kept managing `rustlet0` despite a drop-in naming it.
    Why, and what are the two changes that fixed it?
11. Why is the host's end of a veth named by a hash now, and what keeps
    the daemon from deleting another container's link that happens to
    have the name it wants?
12. A container on `back` (IPv4 only) is connected to `six` (with IPv6).
    Through which network does each family's default route go, where do
    its published ports lead, and what changes when `back` is
    disconnected?
13. With duplicate address detection on, the host could reach a new
    container over IPv6 at once, but the LAN's first connection to its
    published port was lost. Why the difference?

## Experiments

- **Be the daemon.** With `sudo`, make a namespace and a pair by hand,
  the old way and the new: `ip netns add c1; ip link add rlvtest type
  veth peer name eth0 netns c1` (one message, as Rustlets sends it), then
  attach `rlvtest` to `rustlet0`, give `eth0` an address from the
  network's subnet that no container has, and ping it from the host. Watch
  `ip monitor link` in another terminal while you do it. Remove it with
  `ip link del rlvtest; ip netns del c1` (and note that `ip netns`
  leaves `/run/netns` mounted).
- **Bytes.** Write a test in `crates/rustlet-sys` that builds the
  `RTM_NEWADDR` of §6 with `MsgBuilder` and prints it in hex, and match
  each field against `struct ifaddrmsg` in `linux/if_addr.h`.
- **ARP.** In a container, `ip neigh` before and after `ping -c1
  10.89.0.1`; on the host, `bridge fdb show br rustlet0` and `ip neigh
  show dev rustlet0`. Which MACs appear where?
- **Watch a connection.** Run `ip monitor link address route` on the host
  and `sudo nsenter -t $PID -n ip monitor` in another terminal, then
  `network connect` and `disconnect` a running container. Match each event
  to a step of §10. Which events does the container's namespace see that
  the host's doesn't?
- **The missing second, again.** In the `net_` IPv6 test, comment out the
  `accept_dad` line of `sysctl::enable_ipv6`, add a loop that times the
  first connection from the LAN namespace (as §11 did), and watch `ip -6
  neigh show dev rlb6test` in the host namespace while it waits. Which
  state does the container's entry sit in, and for how long?
- **An exit nobody saw.** Start `rustlet run -d --name e -p 8090:80
  nginx`, kill the daemon (`sudo systemctl kill -s KILL rustletd`), then
  kill the container's init (`sudo kill -9 <pid from inspect>`). With no
  daemon, what do `ip -br link`, `ls /run/rustlet/netns` and `curl
  localhost:8090` show? Start the daemon again (`sudo systemctl start
  rustletd`) and look again, and at `journalctl -u rustletd`: which part
  of reconciliation undid the network, and from what record?

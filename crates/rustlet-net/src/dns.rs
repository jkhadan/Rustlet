//! The embedded DNS server: what `127.0.0.11` answers inside a container on
//! a user-defined network.
//!
//! ```text
//!  container netns                         daemon (host netns)
//!  ┌──────────────────────────────┐
//!  │ app → 127.0.0.11:53          │
//!  │   nft (table ip rustlet_dns) │
//!  │   DNAT :53 → :<port>         │
//!  │ socket 127.0.0.11:<port> ────┼──► DnsServer task ── Zone (names on the network)
//!  └──────────────────────────────┘        │ not ours?
//!                                          └──► upstream servers, from the host's netns
//! ```
//!
//! The daemon creates each container's two sockets (UDP and TCP, bound to
//! `127.0.0.11` on ports the kernel picks) from a thread that has
//! `setns`'d into the container's network namespace: a socket belongs to
//! the namespace it was created in, wherever it is used afterwards. The
//! daemon's tokio runtime then serves them like any other socket. A
//! per-namespace nftables rule redirects port 53 to them (as Docker does),
//! so a program in the container can still bind `0.0.0.0:53` itself.
//!
//! ## What it answers
//!
//! One [`Zone`] holds every network's names; each container's server sees
//! it through a [`View`] (its network, its upstream servers).
//!
//! - **`A` for a name on the network** (a container's name, aliases, short
//!   id, hostname; registered by the daemon with [`Zone::add`]): every
//!   address registered under that name (several containers can share an
//!   alias), in random order, TTL [`TTL`], authoritative. Names match
//!   without regard to case, with or without a trailing dot, bare
//!   (`web`) or qualified by the network's name (`web.backend`).
//! - **Any other type for such a name** (`AAAA`, `MX`, …): `NOERROR` with
//!   no answers. Containers have no IPv6 address, and an empty answer stops
//!   the client from trying elsewhere.
//! - **`PTR` for an address on the network**
//!   (`2.0.89.10.in-addr.arpa`): `<first name>.<network>.`, as Docker's.
//! - **Everything else** is forwarded to the view's upstream servers, one
//!   after the other until one answers ([`FORWARD_TIMEOUT`] each): the
//!   query's bytes as they came, with a fresh random ID (restored in the
//!   answer), over the transport it came in on (UDP over UDP, TCP over
//!   TCP), from a socket of its own in the daemon's (the host's) network
//!   namespace; the answer is relayed as it is, truncated or not. With no
//!   upstream servers (an internal network) the answer is `REFUSED`; when
//!   none answers, `SERVFAIL`. At most [`MAX_FORWARDS`] forwards per server
//!   are in flight; beyond that a query gets `SERVFAIL` at once.
//! - **Not a query** (a response, an opcode other than `QUERY`, not exactly
//!   one question): `FORMERR` (`NOTIMP` for another opcode); a message that
//!   doesn't parse at all is dropped.
//!
//! TCP: messages framed by a two-byte length, several per connection,
//! [`TCP_IDLE`] without a message closes it, at most [`MAX_TCP_CONNECTIONS`]
//! connections per server.
//!
//! `hickory-proto` parses and builds messages; everything else is here.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

/// TTL of local answers, as Docker's.
pub const TTL: u32 = 600;
/// How long one upstream server gets to answer a forwarded query.
pub const FORWARD_TIMEOUT: Duration = Duration::from_secs(2);
/// Forwards in flight per server.
pub const MAX_FORWARDS: usize = 100;
/// A TCP connection without a message for this long is closed.
pub const TCP_IDLE: Duration = Duration::from_secs(10);
/// TCP connections per server.
pub const MAX_TCP_CONNECTIONS: usize = 64;

/// The names of every network's containers. Shared (`Arc`) by the daemon,
/// which adds and removes containers as they start and stop, and every
/// container's [`DnsServer`], which reads it for each query.
#[derive(Debug, Default)]
pub struct Zone {
    _private: (),
}

impl Zone {
    pub fn new() -> Arc<Zone> {
        unimplemented!()
    }

    /// Registers `ip` on `network` under `names` (the first is what `PTR`
    /// answers). Names are stored lowercased; adding an address a name
    /// already has is a no-op.
    pub fn add(&self, network: &str, ip: Ipv4Addr, names: &[String]) {
        let _ = (network, ip, names);
        unimplemented!()
    }

    /// Forgets `ip` on `network`, under every name.
    pub fn remove(&self, network: &str, ip: Ipv4Addr) {
        let _ = (network, ip);
        unimplemented!()
    }

    /// The addresses `name` (bare or `name.<network>`, any case, an
    /// optional trailing dot) has on `network`.
    pub fn lookup(&self, network: &str, name: &str) -> Vec<Ipv4Addr> {
        let _ = (network, name);
        unimplemented!()
    }

    /// The name `PTR` answers for `ip` on `network`: `<first name>.<network>`.
    pub fn reverse(&self, network: &str, ip: Ipv4Addr) -> Option<String> {
        let _ = (network, ip);
        unimplemented!()
    }
}

/// How one container's server answers.
#[derive(Debug, Clone)]
pub struct View {
    /// The network it answers for.
    pub network: String,
    pub zone: Arc<Zone>,
    /// Where other questions go (port 53, usually); empty: nowhere
    /// (`REFUSED`).
    pub upstreams: Vec<SocketAddr>,
}

/// One container's DNS server: serves its two sockets until dropped.
#[derive(Debug)]
pub struct DnsServer {
    _private: (),
}

impl DnsServer {
    /// Starts serving `udp` and `tcp` (bound already, in the container's
    /// network namespace; made non-blocking here). Must be called inside a
    /// tokio runtime; the tasks end when the server is dropped.
    pub fn spawn(udp: std::net::UdpSocket, tcp: std::net::TcpListener, view: View) -> std::io::Result<DnsServer> {
        let _ = (udp, tcp, view);
        unimplemented!()
    }
}

/// The answer to `query` (a whole DNS message) if this server can give it
/// without asking anyone: `Some(bytes)` for a local name, a `PTR` of the
/// network, a malformed query or no upstreams; `None` when it must be
/// forwarded. What [`DnsServer`] does for each message, as a pure function.
pub fn answer_locally(query: &[u8], view: &View) -> Option<Vec<u8>> {
    let _ = (query, view);
    unimplemented!()
}

//! The userland proxy: published ports for the traffic NAT can't reach.
//!
//! A published port is mostly the firewall's job: a `DNAT` rule rewrites a
//! packet arriving for `host:8080` to `10.89.0.2:80` before routing, and
//! the kernel does the rest. Three kinds of traffic never pass such a rule:
//!
//! - **to `127.0.0.1`**: rewriting a loopback destination to a container
//!   address would need `route_localnet`, which lets anyone on the LAN
//!   reach the host's loopback services (CVE-2020-8558);
//! - **over IPv6**: the containers have IPv4 addresses only;
//! - **from a container on the same bridge** to the host's address
//!   (hairpin): the DNAT rules skip traffic from the port's own bridge.
//!
//! So the daemon also listens on the published port itself (which
//! reserves it, too: nothing else on the host can take it) and relays
//! whatever arrives there to the container, as Docker's `docker-proxy`
//! does. The daemon binds the sockets (it needs the port number, and an
//! error it can report); a [`Proxy`] serves one of them until dropped.
//!
//! - **TCP**: each accepted client gets its own connection to the backend
//!   (given up after [`CONNECT_TIMEOUT`]; the client is then closed), and
//!   bytes are copied both ways until both sides are done; one side's end
//!   of input is passed on as a half-close, so request/response protocols
//!   that shut down their write side keep working.
//! - **UDP**: each client address gets a socket of its own, connected to
//!   the backend; what it sends goes there, and what the backend answers
//!   comes back to it from the published socket. A client that has sent
//!   nothing for [`UDP_IDLE`] is forgotten (its socket closed). At most
//!   [`MAX_UDP_CLIENTS`] at once; datagrams from more are dropped.
//!
//! The source address the container sees is the host's (its bridge
//! gateway), not the client's: the cost of a proxy, as with Docker's.

use std::net::SocketAddr;
use std::time::Duration;

/// How long a TCP client waits for the backend's connection.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// A UDP client silent for this long is forgotten (docker-proxy's value).
pub const UDP_IDLE: Duration = Duration::from_secs(90);
/// UDP clients tracked at once per proxy.
pub const MAX_UDP_CLIENTS: usize = 1024;

/// Relays one published socket to a container address, until dropped
/// (which stops accepting and ends every relayed connection).
#[derive(Debug)]
pub struct Proxy {
    _private: (),
}

impl Proxy {
    /// Accepts on `listener` (bound and listening already; made
    /// non-blocking here) and relays each connection to `backend`. Must be
    /// called inside a tokio runtime.
    pub fn tcp(listener: std::net::TcpListener, backend: SocketAddr) -> std::io::Result<Proxy> {
        let _ = (listener, backend);
        unimplemented!()
    }

    /// Relays the datagrams arriving on `socket` (bound already) to
    /// `backend`, and the backend's answers back. Must be called inside a
    /// tokio runtime.
    pub fn udp(socket: std::net::UdpSocket, backend: SocketAddr) -> std::io::Result<Proxy> {
        let _ = (socket, backend);
        unimplemented!()
    }
}

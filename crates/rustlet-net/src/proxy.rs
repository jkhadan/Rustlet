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
//! - **UDP**: each client gets a socket of its own, connected to the
//!   backend; what it sends goes there, and what the backend answers comes
//!   back to it from the published socket, *from the address the client
//!   sent to*. A client is an address and port, and the address of ours it
//!   sends to. A client that has sent nothing for [`UDP_IDLE`] is forgotten
//!   (its socket closed). At most [`MAX_UDP_CLIENTS`] at once; datagrams
//!   from more are dropped.
//!
//! Answering from the right address takes asking. A socket bound to
//! `0.0.0.0` or `[::]` sends from whichever address the kernel picks for
//! the route: to a container's hairpin datagram, the bridge gateway's; over
//! IPv6, perhaps a temporary address. The client would take such an answer
//! for somebody else's (a connected socket never even sees it). So the
//! kernel is asked for each datagram's destination (`IP_PKTINFO`,
//! `IPV6_PKTINFO`), and the answers name it as their source, as
//! docker-proxy's do.
//!
//! The source address the container sees is the host's (its bridge
//! gateway), not the client's: the cost of a proxy, as with Docker's.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::io::{self, IoSlice, IoSliceMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::Duration;

use nix::sys::socket::{
    ControlMessage, ControlMessageOwned, MsgFlags, SockaddrStorage, recvmsg, sendmsg, setsockopt, sockopt,
};
use tokio::io::Interest;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::{AbortHandle, JoinHandle, JoinSet};
use tokio::time::Instant;

/// How long a TCP client waits for the backend's connection.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// A UDP client silent for this long is forgotten (docker-proxy's value).
pub const UDP_IDLE: Duration = Duration::from_secs(90);
/// UDP clients tracked at once per proxy.
pub const MAX_UDP_CLIENTS: usize = 1024;

/// Room for any datagram (a UDP payload is at most 65,527 bytes; 65,507
/// over IPv4).
const MAX_DATAGRAM: usize = 65_535;

/// Relays one published socket to a container address, until dropped
/// (which stops accepting and ends every relayed connection).
///
/// The drop aborts the proxy's task, which owns the socket and the tasks
/// of the connections or clients. They end, and the socket closes, when
/// the runtime next gets to them: right after the drop, not during it, so
/// a bind of the same port straight after can still find it taken.
#[derive(Debug)]
pub struct Proxy {
    task: JoinHandle<()>,
}

impl Proxy {
    /// Accepts on `listener` (bound and listening already; made
    /// non-blocking here) and relays each connection to `backend`. Must be
    /// called inside a tokio runtime.
    pub fn tcp(listener: std::net::TcpListener, backend: SocketAddr) -> std::io::Result<Proxy> {
        Proxy::tcp_with(listener, backend, CONNECT_TIMEOUT)
    }

    /// [`Proxy::tcp`], giving up on the backend after `connect_timeout`.
    fn tcp_with(listener: std::net::TcpListener, backend: SocketAddr, connect_timeout: Duration) -> io::Result<Proxy> {
        listener.set_nonblocking(true)?;
        let listener = TcpListener::from_std(listener)?;
        Ok(Proxy { task: tokio::spawn(serve_tcp(listener, backend, connect_timeout)) })
    }

    /// Relays the datagrams arriving on `socket` (bound already; made
    /// non-blocking here) to `backend`, and the backend's answers back.
    /// Must be called inside a tokio runtime.
    pub fn udp(socket: std::net::UdpSocket, backend: SocketAddr) -> std::io::Result<Proxy> {
        Proxy::udp_with(socket, backend, UDP_IDLE, MAX_UDP_CLIENTS)
    }

    /// [`Proxy::udp`], forgetting clients after `idle` and keeping at most
    /// `max_clients`.
    fn udp_with(
        socket: std::net::UdpSocket,
        backend: SocketAddr,
        idle: Duration,
        max_clients: usize,
    ) -> io::Result<Proxy> {
        socket.set_nonblocking(true)?;
        want_destinations(&socket)?;
        let relay = UdpRelay {
            published: Arc::new(UdpSocket::from_std(socket)?),
            backend,
            idle,
            max_clients,
            clients: HashMap::new(),
            turned_away: false,
        };
        Ok(Proxy { task: tokio::spawn(relay.serve()) })
    }
}

impl Proxy {
    /// Stops the proxy and waits until its task is gone, and with it the
    /// published socket: the port can be bound again as soon as this
    /// returns (a container restarted on the same port).
    pub async fn close(mut self) {
        self.task.abort();
        let _ = (&mut self.task).await;
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Accepts until the proxy is dropped; each connection is relayed by a
/// task of its own.
async fn serve_tcp(listener: TcpListener, backend: SocketAddr, connect_timeout: Duration) {
    // Dropped with this task, which aborts every connection's task.
    let mut connections = JoinSet::new();
    let mut backoff = Backoff::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((client, _)) => {
                    backoff.reset();
                    connections.spawn(relay_tcp(client, backend, connect_timeout));
                }
                Err(e) => {
                    tracing::warn!(%backend, "accept on a published port: {e}");
                    backoff.wait().await;
                }
            },
            // Connections leave the set as they end.
            Some(_) = connections.join_next() => {}
        }
    }
}

/// Relays one client: a connection of its own to the backend, then bytes
/// both ways.
async fn relay_tcp(mut client: TcpStream, backend: SocketAddr, connect_timeout: Duration) {
    // Returning drops `client`, which closes it: a connection accepted
    // already can't be refused any more, only ended.
    let mut upstream = match tokio::time::timeout(connect_timeout, TcpStream::connect(backend)).await {
        Ok(Ok(upstream)) => upstream,
        Ok(Err(e)) => {
            tracing::debug!(%backend, "connect to the backend: {e}");
            return;
        }
        Err(_) => {
            tracing::debug!(%backend, "connect to the backend: no answer in {connect_timeout:?}");
            return;
        }
    };
    // The bytes come batched by whoever wrote them, and are passed on as
    // they come: holding small writes back again (Nagle's algorithm, for up
    // to a delayed ACK's 40 ms) would only add latency. Go sets this on
    // every connection, so docker-proxy has it too.
    for stream in [&client, &upstream] {
        let _ = stream.set_nodelay(true);
    }
    // When one side's input ends, the other side's output is shut down (the
    // half-close); this returns once both directions have ended.
    if let Err(e) = tokio::io::copy_bidirectional(&mut client, &mut upstream).await {
        tracing::debug!(%backend, "relayed connection: {e}");
    }
}

/// The pause after an error on a published socket, which would mostly
/// come straight back if tried again at once: `accept` fails with `EMFILE`
/// for as long as the daemon is out of file descriptors, and the connection
/// stays queued meanwhile. 10 ms, doubling while the errors go on, up to a
/// second.
struct Backoff(Duration);

impl Backoff {
    const FIRST: Duration = Duration::from_millis(10);
    const LONGEST: Duration = Duration::from_secs(1);

    fn new() -> Backoff {
        Backoff(Backoff::FIRST)
    }

    async fn wait(&mut self) {
        tokio::time::sleep(self.0).await;
        self.0 = (self.0 * 2).min(Backoff::LONGEST);
    }

    fn reset(&mut self) {
        self.0 = Backoff::FIRST;
    }
}

/// The UDP side of a proxy: the clients the published socket has heard
/// from, each with a socket of its own connected to the backend.
struct UdpRelay {
    published: Arc<UdpSocket>,
    backend: SocketAddr,
    idle: Duration,
    max_clients: usize,
    /// By the client's address and the address of ours it sent to.
    clients: HashMap<(SocketAddr, Option<IpAddr>), Client>,
    /// Whether a client has been turned away since there was last room:
    /// the log says so once, not for every datagram.
    turned_away: bool,
}

impl UdpRelay {
    /// Relays until the proxy is dropped; the clients go with it.
    async fn serve(mut self) {
        let published = self.published.clone();
        let mut datagram = vec![0u8; MAX_DATAGRAM];
        // Room for either kind of pktinfo (the IPv6 one is the larger).
        let mut cmsg = nix::cmsg_space!(libc::in6_pktinfo);
        let mut backoff = Backoff::new();
        // Set for when the first client is due to be forgotten, as of the
        // last sweep: never late, and early if that client has sent
        // something since (the sweep then finds nothing to do but set it
        // again).
        let mut expiry = std::pin::pin!(tokio::time::sleep(self.idle));
        loop {
            tokio::select! {
                received = recv_datagram(&published, &mut datagram, &mut cmsg) => match received {
                    Ok((len, from, local)) => {
                        backoff.reset();
                        self.forward(&datagram[..len], from, local).await;
                    }
                    Err(e) => {
                        tracing::warn!(backend = %self.backend, "receive on a published port: {e}");
                        backoff.wait().await;
                    }
                },
                () = &mut expiry, if !self.clients.is_empty() => {
                    if let Some(next) = self.expire(Instant::now()) {
                        expiry.as_mut().reset(next);
                    }
                }
            }
        }
    }

    /// Sends `datagram` on to the backend through the socket of the client
    /// that sent it (from `from` to our address `local`), made now for a new
    /// client if there is room for one.
    async fn forward(&mut self, datagram: &[u8], from: SocketAddr, local: Option<IpAddr>) {
        let full = self.clients.len() >= self.max_clients;
        let client = match self.clients.entry((from, local)) {
            Entry::Occupied(known) => known.into_mut(),
            Entry::Vacant(_) if full => {
                if !self.turned_away {
                    tracing::warn!(
                        backend = %self.backend,
                        "{} UDP clients already: datagrams from new ones are dropped",
                        self.max_clients
                    );
                    self.turned_away = true;
                }
                return;
            }
            Entry::Vacant(new) => match Client::new(&self.published, self.backend, from, local).await {
                Ok(client) => new.insert(client),
                Err(e) => {
                    tracing::warn!(backend = %self.backend, %from, "a socket for a new UDP client: {e}");
                    return;
                }
            },
        };
        client.last_sent = Instant::now();
        if let Err(e) = client.socket.send(datagram).await {
            tracing::debug!(backend = %self.backend, %from, "forward a datagram: {e}");
        }
    }

    /// Forgets the clients that have sent nothing for `idle`. Returns when
    /// the first of the others will have, if any are left.
    fn expire(&mut self, now: Instant) -> Option<Instant> {
        self.clients.retain(|_, client| now.duration_since(client.last_sent) < self.idle);
        if self.clients.len() < self.max_clients {
            self.turned_away = false;
        }
        self.clients.values().map(|client| client.last_sent + self.idle).min()
    }
}

/// A UDP client, as the relay remembers it.
struct Client {
    /// Connected to the backend, so the kernel hands it the backend's
    /// datagrams only: whatever arrives on it is an answer for this client.
    socket: Arc<UdpSocket>,
    /// When the client last sent something. Answers don't count: the
    /// backend can't keep a client that has gone away remembered.
    last_sent: Instant,
    /// The task passing the answers on; it ends with the entry.
    answers: AbortHandle,
}

impl Client {
    /// A socket for the client at `from`, which sent to our address `local`,
    /// connected to `backend`, and the task that passes its answers on.
    async fn new(
        published: &Arc<UdpSocket>,
        backend: SocketAddr,
        from: SocketAddr,
        local: Option<IpAddr>,
    ) -> io::Result<Client> {
        // Of the backend's family, whatever the client's: an IPv6 client of
        // an IPv4 container is the usual case.
        let any: SocketAddr = match backend {
            SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
            SocketAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
        };
        let socket = UdpSocket::bind(any).await?;
        socket.connect(backend).await?;
        let socket = Arc::new(socket);
        let answers = tokio::spawn(relay_answers(socket.clone(), published.clone(), from, local)).abort_handle();
        Ok(Client { socket, last_sent: Instant::now(), answers })
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        self.answers.abort();
    }
}

/// Passes the backend's answers on to one client: through the published
/// socket, from the address of ours the client sent to.
async fn relay_answers(socket: Arc<UdpSocket>, published: Arc<UdpSocket>, client: SocketAddr, local: Option<IpAddr>) {
    // Capacity, not length: `recv_buf` receives into memory that hasn't
    // been zeroed first, so the buffer only takes up memory as far as the
    // answers reach, not 64 KiB for each of up to 1024 clients.
    let mut answer = Vec::with_capacity(MAX_DATAGRAM);
    loop {
        answer.clear();
        if let Err(e) = socket.recv_buf(&mut answer).await {
            // An ICMP error that an earlier datagram met (`ECONNREFUSED`:
            // nothing listens on the backend's port yet). Each is reported
            // to one read, and the client may well try again.
            tracing::debug!(%client, "an answer from the backend: {e}");
            continue;
        }
        if let Err(e) = send_answer(&published, &answer, client, local).await {
            tracing::debug!(%client, "pass an answer on: {e}");
        }
    }
}

/// Asks the kernel to tell, with each datagram, the address of ours it was
/// sent to.
fn want_destinations(socket: &std::net::UdpSocket) -> io::Result<()> {
    match socket.local_addr()? {
        SocketAddr::V4(_) => setsockopt(socket, sockopt::Ipv4PacketInfo, &true)?,
        // A dual-stack socket's IPv4 datagrams get one too, as a mapped
        // address.
        SocketAddr::V6(_) => setsockopt(socket, sockopt::Ipv6RecvPacketInfo, &true)?,
    }
    Ok(())
}

/// Receives a datagram on the published socket: its length, its sender,
/// and the address of ours it was sent to (see [`want_destinations`]).
async fn recv_datagram(
    socket: &UdpSocket,
    buf: &mut [u8],
    cmsg: &mut [u8],
) -> io::Result<(usize, SocketAddr, Option<IpAddr>)> {
    socket
        .async_io(Interest::READABLE, || {
            let mut iov = [IoSliceMut::new(buf)];
            let msg = recvmsg::<SockaddrStorage>(socket.as_raw_fd(), &mut iov, Some(&mut *cmsg), MsgFlags::empty())?;
            let from = msg
                .address
                .as_ref()
                .and_then(socket_addr)
                .ok_or_else(|| io::Error::other("a datagram without a sender address"))?;
            let local = msg.cmsgs().into_iter().flatten().find_map(|c| match c {
                // `ipi_spec_dst` rather than the header's `ipi_addr`: the
                // same for a datagram sent to one of our addresses, and our
                // own address (not the broadcast one) for a broadcast.
                ControlMessageOwned::Ipv4PacketInfo(info) => {
                    Some(IpAddr::from(Ipv4Addr::from(u32::from_be(info.ipi_spec_dst.s_addr))))
                }
                ControlMessageOwned::Ipv6PacketInfo(info) => Some(IpAddr::from(Ipv6Addr::from(info.ipi6_addr.s6_addr))),
                _ => None,
            });
            Ok((msg.bytes, from, local.filter(|ip| !ip.is_unspecified())))
        })
        .await
}

/// An IPv4 or IPv6 address from the kernel, as std's.
fn socket_addr(addr: &SockaddrStorage) -> Option<SocketAddr> {
    let v4 = addr.as_sockaddr_in().map(|a| SocketAddr::V4(SocketAddrV4::from(*a)));
    v4.or_else(|| addr.as_sockaddr_in6().map(|a| SocketAddr::V6(SocketAddrV6::from(*a))))
}

/// Sends `answer` to `client` through the published socket, from our
/// address `local` (without one, the kernel picks the source address).
async fn send_answer(
    socket: &UdpSocket,
    answer: &[u8],
    client: SocketAddr,
    local: Option<IpAddr>,
) -> io::Result<usize> {
    let to = SockaddrStorage::from(client);
    let iov = [IoSlice::new(answer)];
    socket
        .async_io(Interest::WRITABLE, || {
            let (v4, v6);
            let source = match local {
                Some(IpAddr::V4(ip)) => {
                    let ip = libc::in_addr { s_addr: u32::from(ip).to_be() };
                    v4 = libc::in_pktinfo { ipi_ifindex: 0, ipi_spec_dst: ip, ipi_addr: libc::in_addr { s_addr: 0 } };
                    Some(ControlMessage::Ipv4PacketInfo(&v4))
                }
                Some(IpAddr::V6(ip)) => {
                    v6 = libc::in6_pktinfo { ipi6_addr: libc::in6_addr { s6_addr: ip.octets() }, ipi6_ifindex: 0 };
                    Some(ControlMessage::Ipv6PacketInfo(&v6))
                }
                None => None,
            };
            Ok(sendmsg(socket.as_raw_fd(), &iov, source.as_slice(), MsgFlags::empty(), Some(&to))?)
        })
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::mpsc;

    /// Fails the test rather than hang it.
    async fn within<T>(f: impl Future<Output = T>) -> T {
        tokio::time::timeout(Duration::from_secs(10), f).await.expect("timed out")
    }

    /// How long something that shouldn't come is given to come.
    const QUIET: Duration = Duration::from_millis(300);

    // TCP

    fn tcp_proxy(backend: SocketAddr) -> (Proxy, SocketAddr) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let published = listener.local_addr().unwrap();
        (Proxy::tcp(listener, backend).unwrap(), published)
    }

    /// A backend that echoes each connection until its input ends.
    async fn tcp_echo() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let (mut input, mut output) = stream.split();
                    let _ = tokio::io::copy(&mut input, &mut output).await;
                });
            }
        });
        addr
    }

    /// Whether `stream` has been closed from the other end: the end of its
    /// input, or a reset.
    async fn is_closed(stream: &mut TcpStream) -> bool {
        let mut buf = [0u8; 1];
        matches!(within(stream.read(&mut buf)).await, Ok(0) | Err(_))
    }

    #[tokio::test]
    async fn tcp_relays_both_ways() {
        let (_proxy, published) = tcp_proxy(tcp_echo().await);
        let mut client = TcpStream::connect(published).await.unwrap();
        client.write_all(b"hello").await.unwrap();
        let mut got = [0u8; 5];
        within(client.read_exact(&mut got)).await.unwrap();
        assert_eq!(&got, b"hello");

        // Far more than the buffers on the way hold, read back while it is
        // being written.
        let data: Vec<u8> = (0..1 << 20).map(|i| (i % 251) as u8).collect();
        let (mut input, mut output) = client.into_split();
        let writer = tokio::spawn({
            let data = data.clone();
            async move { output.write_all(&data).await.unwrap() }
        });
        let mut echoed = vec![0u8; data.len()];
        within(input.read_exact(&mut echoed)).await.unwrap();
        assert!(echoed == data, "the echo differs");
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn tcp_passes_a_half_close_on() {
        // A backend that answers once its input has ended, then closes.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            stream.read_to_end(&mut request).await.unwrap();
            stream.write_all(format!("got {} bytes", request.len()).as_bytes()).await.unwrap();
        });
        let (_proxy, published) = tcp_proxy(backend);
        let mut client = TcpStream::connect(published).await.unwrap();
        client.write_all(b"request").await.unwrap();
        client.shutdown().await.unwrap();
        let mut answer = String::new();
        within(client.read_to_string(&mut answer)).await.unwrap();
        assert_eq!(answer, "got 7 bytes");
    }

    #[tokio::test]
    async fn tcp_closes_the_client_when_the_backend_refuses() {
        // A port nothing listens on any more.
        let backend = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
        let (_proxy, published) = tcp_proxy(backend);
        let mut client = TcpStream::connect(published).await.unwrap();
        // Well before CONNECT_TIMEOUT: a refusal is final.
        let mut buf = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(2), client.read(&mut buf)).await;
        assert!(matches!(read, Ok(Ok(0) | Err(_))), "{read:?}");
    }

    #[tokio::test]
    async fn tcp_closes_the_client_when_the_backend_does_not_answer() {
        // A listener that accepts nothing, its queue full: the kernel drops
        // further SYNs, so connecting to it hangs.
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let silent = socket.listen(1).unwrap();
        let backend = silent.local_addr().unwrap();
        let mut queued = Vec::new();
        while let Ok(connected) = tokio::time::timeout(Duration::from_millis(200), TcpStream::connect(backend)).await {
            queued.push(connected.unwrap());
            assert!(queued.len() < 16, "the listen queue doesn't fill up");
        }

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let published = listener.local_addr().unwrap();
        let connect_timeout = Duration::from_millis(300);
        let _proxy = Proxy::tcp_with(listener, backend, connect_timeout).unwrap();
        let mut client = TcpStream::connect(published).await.unwrap();
        let connected = Instant::now();
        assert!(is_closed(&mut client).await);
        let waited = connected.elapsed();
        assert!(waited >= connect_timeout - Duration::from_millis(50), "closed after {waited:?}");
    }

    #[tokio::test]
    async fn tcp_relays_connections_side_by_side() {
        let (_proxy, published) = tcp_proxy(tcp_echo().await);
        let mut clients = Vec::new();
        for _ in 0..8 {
            clients.push(TcpStream::connect(published).await.unwrap());
        }
        for round in 0..3 {
            for (i, client) in clients.iter_mut().enumerate() {
                client.write_all(format!("client {i}, round {round};").as_bytes()).await.unwrap();
            }
            for (i, client) in clients.iter_mut().enumerate() {
                let expected = format!("client {i}, round {round};");
                let mut got = vec![0u8; expected.len()];
                within(client.read_exact(&mut got)).await.unwrap();
                assert_eq!(String::from_utf8(got).unwrap(), expected);
            }
        }
    }

    #[tokio::test]
    async fn tcp_relays_an_ipv6_client_to_an_ipv4_backend() {
        let Ok(listener) = std::net::TcpListener::bind("[::1]:0") else {
            eprintln!("no IPv6 loopback address here: skipping");
            return;
        };
        let published = listener.local_addr().unwrap();
        let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let _proxy = Proxy::tcp(listener, backend.local_addr().unwrap()).unwrap();
        let mut client = TcpStream::connect(published).await.unwrap();
        client.write_all(b"over IPv6").await.unwrap();

        let (mut stream, peer) = within(backend.accept()).await.unwrap();
        // The proxy's own connection, over IPv4.
        assert!(peer.is_ipv4(), "the backend sees {peer}");
        let mut got = [0u8; 9];
        within(stream.read_exact(&mut got)).await.unwrap();
        assert_eq!(&got, b"over IPv6");
        stream.write_all(b"back").await.unwrap();
        let mut answer = [0u8; 4];
        within(client.read_exact(&mut answer)).await.unwrap();
        assert_eq!(&answer, b"back");
    }

    #[tokio::test]
    async fn tcp_drop_ends_the_connections_and_the_listener() {
        let (proxy, published) = tcp_proxy(tcp_echo().await);
        let mut client = TcpStream::connect(published).await.unwrap();
        client.write_all(b"ping").await.unwrap();
        let mut got = [0u8; 4];
        within(client.read_exact(&mut got)).await.unwrap();

        drop(proxy);
        assert!(is_closed(&mut client).await);
        // The listener went before the connection did: its task's end is
        // what aborts the connections'.
        let refused = TcpStream::connect(published).await.unwrap_err();
        assert_eq!(refused.kind(), io::ErrorKind::ConnectionRefused);
    }

    // UDP

    fn udp_proxy_with(backend: SocketAddr, idle: Duration, max_clients: usize) -> (Proxy, SocketAddr) {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let published = socket.local_addr().unwrap();
        (Proxy::udp_with(socket, backend, idle, max_clients).unwrap(), published)
    }

    fn udp_proxy(backend: SocketAddr) -> (Proxy, SocketAddr) {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let published = socket.local_addr().unwrap();
        (Proxy::udp(socket, backend).unwrap(), published)
    }

    /// A backend that echoes each datagram, and tells who sent it.
    async fn udp_echo() -> (SocketAddr, mpsc::UnboundedReceiver<SocketAddr>) {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let (senders, heard) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_DATAGRAM];
            loop {
                let (n, from) = socket.recv_from(&mut buf).await.unwrap();
                let _ = senders.send(from);
                socket.send_to(&buf[..n], from).await.unwrap();
            }
        });
        (addr, heard)
    }

    /// A client on `local`, connected to `published`: the kernel drops
    /// whatever comes from anywhere else, so what it receives came from
    /// there.
    async fn udp_client(local: &str, published: SocketAddr) -> UdpSocket {
        let socket = UdpSocket::bind(local).await.unwrap();
        socket.connect(published).await.unwrap();
        socket
    }

    /// Sends `request`, returns the answer.
    async fn exchange(client: &UdpSocket, request: &[u8]) -> Vec<u8> {
        client.send(request).await.unwrap();
        let mut buf = vec![0u8; MAX_DATAGRAM];
        let n = within(client.recv(&mut buf)).await.unwrap();
        buf.truncate(n);
        buf
    }

    /// Fails if a datagram arrives on `client` for a while (an ICMP error
    /// is no datagram).
    async fn nothing_arrives(client: &UdpSocket) {
        let mut buf = vec![0u8; MAX_DATAGRAM];
        if let Ok(Ok(n)) = tokio::time::timeout(QUIET, client.recv(&mut buf)).await {
            panic!("received {:?}", String::from_utf8_lossy(&buf[..n]));
        }
    }

    #[tokio::test]
    async fn udp_relays_requests_and_answers() {
        let (backend, _) = udp_echo().await;
        let (_proxy, published) = udp_proxy(backend);
        let client = udp_client("127.0.0.1:0", published).await;
        assert_eq!(exchange(&client, b"ping").await, b"ping");
        // The largest datagram IPv4 carries.
        let large: Vec<u8> = (0..65_507).map(|i| (i % 251) as u8).collect();
        assert!(exchange(&client, &large).await == large, "the echo differs");
    }

    #[tokio::test]
    async fn udp_clients_get_sockets_and_answers_of_their_own() {
        let (backend, mut heard) = udp_echo().await;
        let (_proxy, published) = udp_proxy(backend);
        let a = udp_client("127.0.0.1:0", published).await;
        let b = udp_client("127.0.0.1:0", published).await;
        a.send(b"from a").await.unwrap();
        b.send(b"from b").await.unwrap();
        let mut buf = [0u8; 16];
        let n = within(b.recv(&mut buf)).await.unwrap();
        assert_eq!(&buf[..n], b"from b");
        let n = within(a.recv(&mut buf)).await.unwrap();
        assert_eq!(&buf[..n], b"from a");
        let (via_a, via_b) = (heard.recv().await.unwrap(), heard.recv().await.unwrap());
        assert_ne!(via_a, via_b, "both came through the same socket");
        // A client's next datagram goes through its socket again.
        assert_eq!(exchange(&a, b"again").await, b"again");
        assert_eq!(heard.recv().await.unwrap(), via_a);
    }

    #[tokio::test]
    async fn udp_relays_an_ipv6_client_to_an_ipv4_backend() {
        let Ok(socket) = std::net::UdpSocket::bind("[::1]:0") else {
            eprintln!("no IPv6 loopback address here: skipping");
            return;
        };
        let published = socket.local_addr().unwrap();
        let (backend, mut heard) = udp_echo().await;
        let _proxy = Proxy::udp(socket, backend).unwrap();
        let client = udp_client("[::1]:0", published).await;
        assert_eq!(exchange(&client, b"over IPv6").await, b"over IPv6");
        let via = heard.recv().await.unwrap();
        assert!(via.is_ipv4(), "the backend heard from {via}");
    }

    #[tokio::test]
    async fn udp_answers_come_from_the_address_the_client_sent_to() {
        // All of 127/8 is ours: a socket bound to 0.0.0.0 would receive a
        // datagram sent to 127.0.0.2, and the kernel would answer it from
        // 127.0.0.1 (the route's source address). The tests keep to sockets
        // bound to one loopback address, so the two halves are checked on
        // their own here, on a socket bound to 127.0.0.1.
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_nonblocking(true).unwrap();
        want_destinations(&socket).unwrap();
        let published = UdpSocket::from_std(socket).unwrap();
        let port = published.local_addr().unwrap().port();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();

        // A datagram comes with the address it was sent to...
        client.send_to(b"hello", (Ipv4Addr::LOCALHOST, port)).await.unwrap();
        let mut buf = [0u8; 32];
        let mut cmsg = nix::cmsg_space!(libc::in6_pktinfo);
        let (n, from, local) = within(recv_datagram(&published, &mut buf, &mut cmsg)).await.unwrap();
        assert_eq!((&buf[..n], from, local), (&b"hello"[..], client_addr, Some(IpAddr::from(Ipv4Addr::LOCALHOST))));

        // ...and an answer leaves from the address it is given, which is
        // all that a client connected to 127.0.0.2 accepts.
        client.connect((Ipv4Addr::new(127, 0, 0, 2), port)).await.unwrap();
        send_answer(&published, b"from the bound address", client_addr, None).await.unwrap();
        nothing_arrives(&client).await;
        let other = Some(IpAddr::from(Ipv4Addr::new(127, 0, 0, 2)));
        send_answer(&published, b"from 127.0.0.2", client_addr, other).await.unwrap();
        let n = within(client.recv(&mut buf)).await.unwrap();
        assert_eq!(&buf[..n], b"from 127.0.0.2");
    }

    #[tokio::test]
    async fn udp_forgets_an_idle_client() {
        let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let idle = Duration::from_millis(500);
        let (_proxy, published) = udp_proxy_with(backend.local_addr().unwrap(), idle, MAX_UDP_CLIENTS);
        let client = udp_client("127.0.0.1:0", published).await;
        let mut buf = [0u8; 16];

        client.send(b"one").await.unwrap();
        let (_, via) = within(backend.recv_from(&mut buf)).await.unwrap();
        // While the client is remembered, its socket at the proxy reaches it.
        backend.send_to(b"unprompted", via).await.unwrap();
        let n = within(client.recv(&mut buf)).await.unwrap();
        assert_eq!(&buf[..n], b"unprompted");

        tokio::time::sleep(idle * 3).await;
        // Forgotten: that socket is closed.
        backend.send_to(b"too late", via).await.unwrap();
        nothing_arrives(&client).await;

        // The next datagram makes it a client again.
        client.send(b"two").await.unwrap();
        let (n, via) = within(backend.recv_from(&mut buf)).await.unwrap();
        assert_eq!(&buf[..n], b"two");
        backend.send_to(b"answer", via).await.unwrap();
        let n = within(client.recv(&mut buf)).await.unwrap();
        assert_eq!(&buf[..n], b"answer");
    }

    #[tokio::test]
    async fn udp_turns_away_clients_beyond_the_limit() {
        let (backend, _) = udp_echo().await;
        let (_proxy, published) = udp_proxy_with(backend, UDP_IDLE, 2);
        let a = udp_client("127.0.0.1:0", published).await;
        let b = udp_client("127.0.0.1:0", published).await;
        let c = udp_client("127.0.0.1:0", published).await;
        assert_eq!(exchange(&a, b"a").await, b"a");
        assert_eq!(exchange(&b, b"b").await, b"b");
        c.send(b"c").await.unwrap();
        nothing_arrives(&c).await;
        // The two it has are still served.
        assert_eq!(exchange(&a, b"a again").await, b"a again");
        assert_eq!(exchange(&b, b"b again").await, b"b again");
    }

    #[tokio::test]
    async fn udp_a_forgotten_client_makes_room() {
        let (backend, _) = udp_echo().await;
        let idle = Duration::from_millis(500);
        let (_proxy, published) = udp_proxy_with(backend, idle, 1);
        let a = udp_client("127.0.0.1:0", published).await;
        let b = udp_client("127.0.0.1:0", published).await;
        assert_eq!(exchange(&a, b"a").await, b"a");
        b.send(b"b").await.unwrap();
        nothing_arrives(&b).await;
        tokio::time::sleep(idle * 2).await;
        assert_eq!(exchange(&b, b"b again").await, b"b again");
    }

    #[tokio::test]
    async fn udp_drop_stops_relaying() {
        let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (proxy, published) = udp_proxy(backend.local_addr().unwrap());
        let client = udp_client("127.0.0.1:0", published).await;
        let mut buf = [0u8; 16];
        client.send(b"one").await.unwrap();
        let (_, via) = within(backend.recv_from(&mut buf)).await.unwrap();

        drop(proxy);
        // Its tasks end when the runtime gets to them.
        tokio::time::sleep(Duration::from_millis(100)).await;
        backend.send_to(b"answer", via).await.unwrap();
        nothing_arrives(&client).await;
        client.send(b"two").await.unwrap();
        let heard = tokio::time::timeout(QUIET, backend.recv_from(&mut buf)).await;
        assert!(heard.is_err(), "the backend heard {heard:?}");
        // The published socket is closed: its port can be bound again.
        std::net::UdpSocket::bind(published).unwrap();
    }
}

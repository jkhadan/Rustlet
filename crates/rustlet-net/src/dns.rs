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
//!   (UDP and TCP together) are in flight; beyond that a query gets
//!   `SERVFAIL` at once.
//! - **Not a query** (an opcode other than `QUERY`, not exactly one
//!   question, or a body that doesn't parse): `FORMERR` (`NOTIMP` for
//!   another opcode), a bare header. A **response** is dropped without a
//!   word, as Unbound and miekg/dns (Docker's library) do: answering one
//!   with `FORMERR`, itself a response, could start a reply loop with any
//!   other UDP service that answers what it receives (the "Loop DoS" class,
//!   CVE-2024-2169). Less than a header (12 bytes) is dropped too: it has
//!   no ID to answer.
//!
//! A question of another class than `IN` goes the way of everything else,
//! whatever its name. The server's own answers to queries carry the question
//! as it was asked, case and all (some resolvers randomise the case and
//! check it), and `RA` when there is somewhere to forward to.
//!
//! UDP: a local answer longer than the client takes (512 bytes, or what its
//! `EDNS` record offers) is cut to the records that fit, with `TC` set, so
//! the client asks again over TCP. A datagram from the socket's own address
//! is ignored as well: only a forged one comes from there (`CAP_NET_RAW` in
//! the container), and the server has no business talking to itself.
//!
//! TCP: messages framed by a two-byte length, several per connection,
//! answered in turn; [`TCP_IDLE`] without a message (or without the client
//! taking an answer) closes it. At most [`MAX_TCP_CONNECTIONS`] connections
//! per server: further ones wait in the listen backlog until one ends.
//!
//! `hickory-proto` parses and builds messages; everything else is here.

use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::Duration;

use hickory_proto::op::{Header, Message, MessageType, Metadata, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, PTR};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable, BinEncoder};
use rand::seq::SliceRandom;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tracing::Instrument;

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

/// The length of a DNS header: anything shorter is not a message.
const HEADER_LEN: usize = 12;
/// The QR bit, in a header's third byte: set in responses.
const QR: u8 = 0x80;
/// The longest message: a TCP frame's length is two bytes, and no UDP
/// datagram is longer.
const MAX_MESSAGE: usize = u16::MAX as usize;
/// What a UDP client takes unless its `EDNS` record says more (RFC 1035).
const UDP_SIZE: u16 = 512;
/// How long accepting pauses after an error (out of file descriptors,
/// usually), so that it doesn't spin.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// The names of every network's containers. Shared (`Arc`) by the daemon,
/// which adds and removes containers as they start and stop, and every
/// container's [`DnsServer`], which reads it for each query.
#[derive(Debug, Default)]
pub struct Zone {
    /// By network name.
    networks: RwLock<HashMap<String, NetworkNames>>,
}

/// One network's part of the zone: each address under a name in
/// `addresses` has that name in `names`, and the other way round.
#[derive(Debug, Default)]
struct NetworkNames {
    /// Each name and its addresses, in the order they were added.
    addresses: HashMap<String, Vec<Ipv4Addr>>,
    /// Each address and its names, in the order they were added: the first
    /// is what `PTR` answers.
    names: HashMap<Ipv4Addr, Vec<String>>,
}

impl Zone {
    /// An empty zone, to share.
    pub fn new() -> Arc<Zone> {
        Arc::new(Zone::default())
    }

    /// Registers `ip` on `network` under `names` (the first is what `PTR`
    /// answers). Names are stored lowercased; adding an address a name
    /// already has is a no-op.
    pub fn add(&self, network: &str, ip: Ipv4Addr, names: &[String]) {
        let names: Vec<String> = names.iter().map(|n| normalize(n)).filter(|n| !n.is_empty()).collect();
        if names.is_empty() {
            return;
        }
        let mut networks = self.write();
        let net = networks.entry(network.to_owned()).or_default();
        for name in names {
            let addresses = net.addresses.entry(name.clone()).or_default();
            if !addresses.contains(&ip) {
                addresses.push(ip);
                net.names.entry(ip).or_default().push(name);
            }
        }
    }

    /// Forgets `ip` on `network`, under every name.
    pub fn remove(&self, network: &str, ip: Ipv4Addr) {
        let mut networks = self.write();
        let Some(net) = networks.get_mut(network) else { return };
        for name in net.names.remove(&ip).unwrap_or_default() {
            if let Some(addresses) = net.addresses.get_mut(&name) {
                addresses.retain(|a| *a != ip);
                if addresses.is_empty() {
                    net.addresses.remove(&name);
                }
            }
        }
        if net.names.is_empty() {
            networks.remove(network);
        }
    }

    /// The addresses `name` (bare or `name.<network>`, any case, an
    /// optional trailing dot) has on `network`.
    pub fn lookup(&self, network: &str, name: &str) -> Vec<Ipv4Addr> {
        let name = normalize(name);
        let networks = self.read();
        let Some(net) = networks.get(network) else { return Vec::new() };
        // A name as it is first: a container may well be called `web.backend`.
        if let Some(addresses) = net.addresses.get(&name) {
            return addresses.clone();
        }
        let suffix = format!(".{}", network.to_ascii_lowercase());
        name.strip_suffix(&suffix).and_then(|bare| net.addresses.get(bare)).cloned().unwrap_or_default()
    }

    /// The name `PTR` answers for `ip` on `network`: `<first name>.<network>`.
    pub fn reverse(&self, network: &str, ip: Ipv4Addr) -> Option<String> {
        let networks = self.read();
        let first = networks.get(network)?.names.get(&ip)?.first()?;
        Some(format!("{first}.{network}"))
    }

    // The maps are consistent after every statement, so a writer that
    // panicked (none can) would leave nothing to repair: a poisoned lock is
    // used as it is.
    fn read(&self) -> RwLockReadGuard<'_, HashMap<String, NetworkNames>> {
        self.networks.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn write(&self) -> RwLockWriteGuard<'_, HashMap<String, NetworkNames>> {
        self.networks.write().unwrap_or_else(PoisonError::into_inner)
    }
}

/// A name as the zone keeps it: lowercase (DNS ignores the case of ASCII
/// letters only), without a trailing dot.
fn normalize(name: &str) -> String {
    name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase()
}

/// How one container's server answers.
#[derive(Debug, Clone)]
pub struct View {
    /// The network it answers for.
    pub network: String,
    /// Every network's names.
    pub zone: Arc<Zone>,
    /// Where other questions go (port 53, usually); empty: nowhere
    /// (`REFUSED`).
    pub upstreams: Vec<SocketAddr>,
}

/// One container's DNS server: serves its two sockets until dropped.
///
/// It is two tasks, one per socket, and each owns the work it starts (the
/// UDP task its forwards, the TCP task its connections), so dropping the
/// server, which aborts both, ends everything in progress and closes the
/// sockets.
#[derive(Debug)]
pub struct DnsServer {
    tasks: JoinSet<()>,
}

impl DnsServer {
    /// Starts serving `udp` and `tcp` (bound already, in the container's
    /// network namespace; made non-blocking here). Must be called inside a
    /// tokio runtime; the tasks end when the server is dropped. They log in
    /// the span that is current here.
    pub fn spawn(udp: std::net::UdpSocket, tcp: std::net::TcpListener, view: View) -> std::io::Result<DnsServer> {
        DnsServer::start(udp, tcp, view, Timeouts { forward: FORWARD_TIMEOUT, tcp_idle: TCP_IDLE })
    }

    fn start(
        udp: std::net::UdpSocket,
        tcp: std::net::TcpListener,
        view: View,
        timeouts: Timeouts,
    ) -> io::Result<DnsServer> {
        udp.set_nonblocking(true)?;
        tcp.set_nonblocking(true)?;
        let udp = UdpSocket::from_std(udp)?;
        let tcp = TcpListener::from_std(tcp)?;
        let shared = Arc::new(Shared { view, forwards: Arc::new(Semaphore::new(MAX_FORWARDS)), timeouts });
        let mut tasks = JoinSet::new();
        tasks.spawn(serve_udp(udp, shared.clone()).in_current_span());
        tasks.spawn(serve_tcp(tcp, shared).in_current_span());
        Ok(DnsServer { tasks })
    }
}

impl Drop for DnsServer {
    fn drop(&mut self) {
        // An aborted task's future is dropped, and with it the `JoinSet` of
        // forwards or connections it owns, which aborts those in turn.
        self.tasks.abort_all();
    }
}

/// What a server's tasks share.
#[derive(Debug)]
struct Shared {
    view: View,
    /// A permit per forward in flight, UDP and TCP together ([`MAX_FORWARDS`]).
    forwards: Arc<Semaphore>,
    timeouts: Timeouts,
}

/// How long a server waits: [`FORWARD_TIMEOUT`] and [`TCP_IDLE`], but for
/// tests, which can't wait that long.
#[derive(Debug, Clone, Copy)]
struct Timeouts {
    /// For each upstream server's answer.
    forward: Duration,
    /// For a TCP client's next message, or for it to take an answer.
    tcp_idle: Duration,
}

/// What a query came in over, and is forwarded over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Transport {
    Udp,
    Tcp,
}

/// Answers the queries arriving on `socket`: local ones at once, the others
/// from a task each, which this task owns.
async fn serve_udp(socket: UdpSocket, shared: Arc<Shared>) {
    let socket = Arc::new(socket);
    let own = socket.local_addr().ok();
    let mut forwards = JoinSet::new();
    let mut buf = vec![0; MAX_MESSAGE];
    loop {
        let received = tokio::select! {
            received = socket.recv_from(&mut buf) => received,
            // (Reaps the forwards that are done.)
            Some(_) = forwards.join_next() => continue,
        };
        let (len, client) = match received {
            Ok(received) => received,
            Err(e) => {
                tracing::debug!("dns: receive a query: {e}");
                continue;
            }
        };
        // Only a forged datagram comes from there (see the module docs).
        if Some(client) == own {
            continue;
        }
        let query = &buf[..len];
        match answer_locally(query, &shared.view) {
            Some(answer) => send_answer(&socket, &fit_udp(query, answer), client).await,
            None => match shared.forwards.clone().try_acquire_owned() {
                Ok(permit) => {
                    let (socket, shared, query) = (socket.clone(), shared.clone(), query.to_vec());
                    let forward = async move {
                        let answer = shared.forward(Transport::Udp, &query).await;
                        send_answer(&socket, &answer, client).await;
                        drop(permit);
                    };
                    forwards.spawn(forward.in_current_span());
                }
                Err(_) => send_answer(&socket, &failure(query, ResponseCode::ServFail, &shared.view), client).await,
            },
        }
    }
}

/// Sends `answer` to `client`: nothing, if it is empty (no answer).
async fn send_answer(socket: &UdpSocket, answer: &[u8], client: SocketAddr) {
    if answer.is_empty() {
        return;
    }
    if let Err(e) = socket.send_to(answer, client).await {
        tracing::debug!("dns: answer {client}: {e}");
    }
}

/// Accepts connections on `listener` and serves each from a task of its
/// own, which this task owns, [`MAX_TCP_CONNECTIONS`] at a time.
async fn serve_tcp(listener: TcpListener, shared: Arc<Shared>) {
    let mut connections = JoinSet::new();
    loop {
        if connections.len() >= MAX_TCP_CONNECTIONS {
            // The next ones wait in the listen backlog until one ends.
            connections.join_next().await;
            continue;
        }
        tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => {
                    connections.spawn(serve_connection(stream, shared.clone()).in_current_span());
                }
                Err(e) => {
                    tracing::warn!(network = %shared.view.network, "dns: accept a TCP connection: {e}");
                    tokio::time::sleep(ACCEPT_BACKOFF).await;
                }
            },
            // (Reaps the connections that ended.)
            Some(_) = connections.join_next() => {}
        }
    }
}

/// One TCP connection: a message, its answer, the next message, and so on,
/// until the client closes it or idles.
async fn serve_connection(mut stream: TcpStream, shared: Arc<Shared>) {
    let idle = shared.timeouts.tcp_idle;
    loop {
        let query = match tokio::time::timeout(idle, read_message(&mut stream)).await {
            Ok(Ok(Some(query))) => query,
            Ok(Ok(None)) | Err(_) => return,
            Ok(Err(e)) => {
                tracing::debug!("dns: read a TCP query: {e}");
                return;
            }
        };
        let answer = match answer_locally(&query, &shared.view) {
            Some(answer) => answer,
            None => match shared.forwards.try_acquire() {
                // The permit is held until the answer is in.
                Ok(_permit) => shared.forward(Transport::Tcp, &query).await,
                Err(_) => failure(&query, ResponseCode::ServFail, &shared.view),
            },
        };
        if answer.is_empty() {
            continue;
        }
        match tokio::time::timeout(idle, write_message(&mut stream, &answer)).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                tracing::debug!("dns: send a TCP answer: {e}");
                return;
            }
            Err(_) => return,
        }
    }
}

/// Reads one message, after its two-byte length; `None` if the peer closed
/// the connection instead.
async fn read_message(stream: &mut (impl AsyncRead + Unpin)) -> io::Result<Option<Vec<u8>>> {
    let mut len = [0; 2];
    match stream.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let mut message = vec![0; usize::from(u16::from_be_bytes(len))];
    stream.read_exact(&mut message).await?;
    Ok(Some(message))
}

/// Writes one message after its two-byte length, both in one write: with
/// Nagle's algorithm, a second small write would wait for the first one's
/// acknowledgement.
async fn write_message(stream: &mut (impl AsyncWrite + Unpin), message: &[u8]) -> io::Result<()> {
    let len = u16::try_from(message.len()).map_err(|_| io::Error::other("a DNS message longer than 65535 bytes"))?;
    let mut framed = Vec::with_capacity(2 + message.len());
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(message);
    stream.write_all(&framed).await
}

impl Shared {
    /// The answer to `query` from the first upstream server that gives one
    /// in time, with the client's ID back in it; `SERVFAIL` if none does.
    async fn forward(&self, transport: Transport, query: &[u8]) -> Vec<u8> {
        for &upstream in &self.view.upstreams {
            let exchange = async {
                match transport {
                    Transport::Udp => exchange_udp(query, upstream).await,
                    Transport::Tcp => exchange_tcp(query, upstream).await,
                }
            };
            match tokio::time::timeout(self.timeouts.forward, exchange).await {
                Ok(Ok(mut answer)) => {
                    answer[..2].copy_from_slice(&query[..2]);
                    return answer;
                }
                Ok(Err(e)) => tracing::debug!("dns: forward to {upstream} over {transport:?}: {e}"),
                Err(_) => tracing::debug!("dns: forward to {upstream} over {transport:?}: no answer in time"),
            }
        }
        failure(query, ResponseCode::ServFail, &self.view)
    }
}

/// Asks `upstream` over UDP, from a socket of its own: a port the kernel
/// picks at random, and connected, so the kernel passes on only that
/// address's datagrams.
async fn exchange_udp(query: &[u8], upstream: SocketAddr) -> io::Result<Vec<u8>> {
    let any: SocketAddr = match upstream {
        SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        SocketAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let socket = UdpSocket::bind(any).await?;
    socket.connect(upstream).await?;
    let (query, id) = with_fresh_id(query);
    socket.send(&query).await?;
    loop {
        // A buffer only once there is a datagram to read: a forward spends
        // its time waiting, and there can be `MAX_FORWARDS` of them.
        socket.readable().await?;
        let mut buf = vec![0; MAX_MESSAGE];
        match socket.try_recv(&mut buf) {
            // Anything else (a late answer to an earlier user of the port,
            // a forgery) is passed over.
            Ok(len) if is_answer_to(&buf[..len], id) => return Ok(buf[..len].to_vec()),
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e),
        }
    }
}

/// Asks `upstream` over TCP, on a connection of its own.
async fn exchange_tcp(query: &[u8], upstream: SocketAddr) -> io::Result<Vec<u8>> {
    let mut stream = TcpStream::connect(upstream).await?;
    let (query, id) = with_fresh_id(query);
    write_message(&mut stream, &query).await?;
    loop {
        match read_message(&mut stream).await? {
            Some(answer) if is_answer_to(&answer, id) => return Ok(answer),
            Some(_) => {}
            None => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "closed without an answer")),
        }
    }
}

/// `query` under a random ID of the server's, and that ID.
fn with_fresh_id(query: &[u8]) -> (Vec<u8>, [u8; 2]) {
    let id = rand::random::<u16>().to_be_bytes();
    let mut ours = query.to_vec();
    ours[..2].copy_from_slice(&id);
    (ours, id)
}

/// Whether `message` is a response (a header's worth, at least) with ID `id`.
fn is_answer_to(message: &[u8], id: [u8; 2]) -> bool {
    message.len() >= HEADER_LEN && message[..2] == id && message[2] & QR != 0
}

/// The answer to `query` (a whole DNS message) if this server can give it
/// without asking anyone: `Some(bytes)` for a local name, a `PTR` of the
/// network, a malformed query or no upstreams; `None` when it must be
/// forwarded. What [`DnsServer`] does for each message, as a pure function
/// (but for cutting a long answer to fit a UDP datagram). Something too
/// short to be a DNS message gets no answer at all: `Some` of no bytes.
pub fn answer_locally(query: &[u8], view: &View) -> Option<Vec<u8>> {
    let Ok(header) = Header::from_bytes(query) else {
        return Some(Vec::new());
    };
    // The header is all that is certain here, and all that is answered.
    let reject = |code| Some(encode(&response(&header.metadata, None, code, view)));
    if header.message_type == MessageType::Response {
        return Some(Vec::new());
    }
    // Before the count: the sections of other opcodes mean other things.
    if header.op_code != OpCode::Query {
        return reject(ResponseCode::NotImp);
    }
    if header.counts.queries != 1 {
        return reject(ResponseCode::FormErr);
    }
    let Ok(message) = Message::from_vec(query) else {
        return reject(ResponseCode::FormErr);
    };
    let question = &message.queries[0];
    if let Some(records) = local_records(question, view) {
        let mut answer = response(&message.metadata, Some(question), ResponseCode::NoError, view);
        answer.metadata.authoritative = true;
        answer.answers = records;
        return Some(encode(&answer));
    }
    if view.upstreams.is_empty() {
        return Some(encode(&response(&message.metadata, Some(question), ResponseCode::Refused, view)));
    }
    None
}

/// What the zone has for `question`, if it is about the network: the
/// records (none, for another type than `A` of a name) for a name or an
/// address on it; `None` for anything else.
fn local_records(question: &Query, view: &View) -> Option<Vec<Record>> {
    if question.query_class != DNSClass::IN {
        return None;
    }
    let name = &question.name;
    if question.query_type == RecordType::PTR
        && let Some(target) = reverse_address(name).and_then(|ip| view.zone.reverse(&view.network, ip))
    {
        let target = Name::from_ascii(format!("{target}.")).ok()?;
        return Some(vec![Record::from_rdata(name.clone(), TTL, RData::PTR(PTR(target)))]);
    }
    let mut addresses = view.zone.lookup(&view.network, &name.to_ascii());
    if addresses.is_empty() {
        return None;
    }
    if question.query_type != RecordType::A {
        return Some(Vec::new());
    }
    addresses.shuffle(&mut rand::rng());
    Some(addresses.into_iter().map(|ip| Record::from_rdata(name.clone(), TTL, RData::A(A(ip)))).collect())
}

/// The address a reverse name stands for (`2.0.89.10.in-addr.arpa.`:
/// 10.89.0.2), if `name` is one: four octets, written as numbers usually are.
fn reverse_address(name: &Name) -> Option<Ipv4Addr> {
    let labels: Vec<&[u8]> = name.iter().collect();
    let &[d, c, b, a, in_addr, arpa] = labels.as_slice() else { return None };
    if !in_addr.eq_ignore_ascii_case(b"in-addr") || !arpa.eq_ignore_ascii_case(b"arpa") {
        return None;
    }
    let octet = |label: &[u8]| {
        let text = std::str::from_utf8(label).ok()?;
        let n: u8 = text.parse().ok()?;
        // `02` and `+2` parse too, but they are other names.
        (n.to_string() == text).then_some(n)
    };
    Some(Ipv4Addr::new(octet(a)?, octet(b)?, octet(c)?, octet(d)?))
}

/// The start of a response to a message with `metadata`: its ID and opcode,
/// its `RD` and `CD` bits, `question` if it is to be echoed, `code`, and
/// `RA` if the view has somewhere to forward to.
fn response(metadata: &Metadata, question: Option<&Query>, code: ResponseCode, view: &View) -> Message {
    let mut response = Message::response(metadata.id, metadata.op_code);
    response.metadata = Metadata::response_from_request(metadata);
    response.metadata.response_code = code;
    response.metadata.recursion_available = !view.upstreams.is_empty();
    if let Some(question) = question {
        response.add_query(question.clone());
    }
    response
}

/// A `code` response to `query` (one that parses: it was to be forwarded),
/// with its question.
fn failure(query: &[u8], code: ResponseCode, view: &View) -> Vec<u8> {
    match Message::from_vec(query) {
        Ok(query) => encode(&response(&query.metadata, query.queries.first(), code, view)),
        Err(_) => Vec::new(),
    }
}

/// `message` as bytes: none (so no answer) in the unlikely event that it
/// can't be encoded.
fn encode(message: &Message) -> Vec<u8> {
    message.to_vec().unwrap_or_else(|e| {
        tracing::warn!("dns: encode an answer: {e}");
        Vec::new()
    })
}

/// A local `answer` as a UDP client takes it: whole if it fits in what the
/// client said it takes (512 bytes, or the size in its `EDNS` record), else
/// cut to the records that fit, with `TC` set. (Forwarded answers are the
/// upstream's to size: it saw the client's `EDNS` record.)
fn fit_udp(query: &[u8], answer: Vec<u8>) -> Vec<u8> {
    if answer.len() <= usize::from(UDP_SIZE) {
        return answer;
    }
    let limit = Message::from_vec(query).map_or(UDP_SIZE, |query| query.max_payload());
    if answer.len() <= usize::from(limit) {
        return answer;
    }
    let Ok(message) = Message::from_vec(&answer) else { return answer };
    let mut cut = Vec::new();
    let emitted = {
        let mut encoder = BinEncoder::new(&mut cut);
        // hickory's own truncation: the records past the limit are left
        // out (whole), and the header counts what is left and sets TC.
        encoder.set_max_size(limit);
        message.emit(&mut encoder)
    };
    match emitted {
        Ok(()) => cut,
        Err(e) => {
            tracing::warn!("dns: cut an answer to {limit} bytes: {e}");
            answer
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::sync::Mutex;
    use std::time::Instant;

    use hickory_proto::op::Edns;

    use super::*;

    const WEB: Ipv4Addr = Ipv4Addr::new(10, 89, 0, 2);
    const WEB2: Ipv4Addr = Ipv4Addr::new(10, 89, 0, 3);
    const DB: Ipv4Addr = Ipv4Addr::new(10, 89, 0, 4);
    const CACHE: Ipv4Addr = Ipv4Addr::new(10, 90, 0, 2);
    /// No addresses (what an unknown name has).
    const NONE: [Ipv4Addr; 0] = [];
    /// What the fake upstream servers answer.
    const FAR: A = A::new(192, 0, 2, 1);
    /// What they answer when they answer something else.
    const WRONG: A = A::new(192, 0, 2, 66);
    /// What they send after each message, as a check: a server that
    /// re-encoded answers would lose it (hickory, reading them, ignores it).
    const TRAILER: u8 = 0xee;
    /// Containers with one name in [`crowd`].
    const CROWD: u8 = 100;

    /// Short timeouts, so that the tests that wait for them don't take long.
    const QUICK: Timeouts = Timeouts { forward: Duration::from_millis(200), tcp_idle: Duration::from_millis(300) };
    /// How long a test waits for an answer that should come.
    const PATIENCE: Duration = Duration::from_secs(5);
    /// How long a test waits for an answer that shouldn't.
    const SILENCE: Duration = Duration::from_millis(300);

    fn names(names: &[&str]) -> Vec<String> {
        names.iter().map(|n| n.to_string()).collect()
    }

    /// The network `backend`: `web` (alias `app`, shared with `web2`) and
    /// `db`; and `cache`, on `frontend`.
    fn view(upstreams: Vec<SocketAddr>) -> View {
        let zone = Zone::new();
        zone.add("backend", WEB, &names(&["web", "app"]));
        zone.add("backend", WEB2, &names(&["web2", "app"]));
        zone.add("backend", DB, &names(&["db"]));
        zone.add("frontend", CACHE, &names(&["cache"]));
        View { network: "backend".into(), zone, upstreams }
    }

    /// Somewhere to forward to, for tests that never get that far.
    fn somewhere() -> Vec<SocketAddr> {
        vec!["192.0.2.53:53".parse().unwrap()]
    }

    /// A query with recursion desired, as stub resolvers send them.
    fn query(id: u16, name: &str, record_type: RecordType) -> Vec<u8> {
        let mut message = Message::query();
        message.metadata.id = id;
        message.metadata.recursion_desired = true;
        message.add_query(Query::query(Name::from_ascii(name).unwrap(), record_type));
        message.to_vec().unwrap()
    }

    fn edit(query: &[u8], change: impl FnOnce(&mut Message)) -> Vec<u8> {
        let mut message = Message::from_vec(query).unwrap();
        change(&mut message);
        message.to_vec().unwrap()
    }

    /// The local answer to `query`, parsed.
    fn local(query: &[u8], view: &View) -> Message {
        Message::from_vec(&answer_locally(query, view).expect("a local answer")).unwrap()
    }

    fn addresses(answer: &Message) -> Vec<Ipv4Addr> {
        answer
            .answers
            .iter()
            .map(|r| match r.data {
                RData::A(A(ip)) => ip,
                ref other => panic!("not an address: {other:?}"),
            })
            .collect()
    }

    #[test]
    fn names_match_in_any_case_bare_or_qualified() {
        let zone = Zone::new();
        zone.add("Backend", WEB, &names(&["Web"]));
        for name in ["web", "WEB", "web.", "web.backend", "Web.BACKEND.", "web.Backend"] {
            assert_eq!(zone.lookup("Backend", name), [WEB], "{name}");
        }
        for name in ["we", "web.backend.example", "web.frontend", "backend", ".backend", "", "."] {
            assert_eq!(zone.lookup("Backend", name), NONE, "{name}");
        }
    }

    #[test]
    fn a_name_can_be_a_qualified_one() {
        let zone = Zone::new();
        zone.add("backend", WEB, &names(&["web.backend"]));
        zone.add("backend", DB, &names(&["web"]));
        assert_eq!(zone.lookup("backend", "web.backend"), [WEB]);
        assert_eq!(zone.lookup("backend", "web.backend.backend"), [WEB]);
        assert_eq!(zone.lookup("backend", "web"), [DB]);
    }

    #[test]
    fn several_containers_can_share_a_name() {
        let zone = view(Vec::new()).zone;
        // Already there: nothing changes.
        zone.add("backend", WEB, &names(&["APP", "app."]));
        assert_eq!(zone.lookup("backend", "app"), [WEB, WEB2]);
        assert_eq!(zone.lookup("backend", "web"), [WEB]);
        assert_eq!(zone.lookup("backend", "web2"), [WEB2]);
    }

    #[test]
    fn removing_a_container_leaves_the_others() {
        let zone = view(Vec::new()).zone;
        zone.remove("backend", WEB);
        assert_eq!(zone.lookup("backend", "app"), [WEB2]);
        assert_eq!(zone.lookup("backend", "web"), NONE);
        assert_eq!(zone.reverse("backend", WEB), None);
        assert_eq!(zone.reverse("backend", WEB2).as_deref(), Some("web2.backend"));
        assert_eq!(zone.lookup("frontend", "cache"), [CACHE]);
        // Again, or on another network: nothing to do.
        zone.remove("backend", WEB);
        zone.remove("frontend", WEB2);
        assert_eq!(zone.lookup("backend", "app"), [WEB2]);
        // A network without names is forgotten.
        zone.remove("backend", WEB2);
        zone.remove("backend", DB);
        assert_eq!(zone.read().keys().collect::<Vec<_>>(), ["frontend"]);
    }

    #[test]
    fn reverse_names_the_first_name() {
        let zone = Zone::new();
        zone.add("backend", WEB, &names(&["Web", "app"]));
        zone.add("backend", WEB, &names(&["later"]));
        assert_eq!(zone.reverse("backend", WEB).as_deref(), Some("web.backend"));
        assert_eq!(zone.lookup("backend", "later"), [WEB]);
        assert_eq!(zone.reverse("backend", WEB2), None);
        // Nothing to register under: nothing registered.
        zone.add("backend", WEB2, &names(&["", "."]));
        assert_eq!(zone.reverse("backend", WEB2), None);
    }

    #[test]
    fn names_on_another_network_do_not_answer() {
        let zone = view(Vec::new()).zone;
        assert_eq!(zone.lookup("backend", "cache"), NONE);
        assert_eq!(zone.lookup("backend", "cache.frontend"), NONE);
        assert_eq!(zone.reverse("backend", CACHE), None);
        assert_eq!(zone.lookup("frontend", "web"), NONE);
        assert_eq!(zone.lookup("elsewhere", "web"), NONE);
        assert_eq!(zone.lookup("frontend", "cache.frontend"), [CACHE]);
    }

    #[test]
    fn a_name_on_the_network_gets_its_addresses() {
        let view = view(somewhere());
        let asked = query(0x1234, "App.Backend.", RecordType::A);
        let answer = local(&asked, &view);
        assert_eq!((answer.id, answer.message_type, answer.op_code), (0x1234, MessageType::Response, OpCode::Query));
        assert_eq!(answer.response_code, ResponseCode::NoError);
        assert!(answer.authoritative && answer.recursion_desired && answer.recursion_available);
        assert!(!answer.truncation);
        // The question as it was asked, case and all.
        assert_eq!(answer.queries.len(), 1);
        assert!(answer.queries[0].name.eq_case(&Name::from_ascii("App.Backend.").unwrap()));
        assert_eq!(answer.queries[0].query_type, RecordType::A);
        for record in &answer.answers {
            assert!(record.name.eq_case(&answer.queries[0].name));
            assert_eq!((record.ttl, record.dns_class), (TTL, DNSClass::IN));
        }
        let mut got = addresses(&answer);
        got.sort();
        assert_eq!(got, [WEB, WEB2]);
    }

    #[test]
    fn addresses_come_in_random_order() {
        let view = view(somewhere());
        let asked = query(1, "app", RecordType::A);
        let orders: HashSet<Vec<Ipv4Addr>> = (0..64).map(|_| addresses(&local(&asked, &view))).collect();
        assert_eq!(orders.len(), 2, "64 answers, all in one order");
    }

    #[test]
    fn other_types_of_a_name_on_the_network_are_empty() {
        let view = view(somewhere());
        for record_type in [RecordType::AAAA, RecordType::MX, RecordType::TXT, RecordType::PTR] {
            let answer = local(&query(7, "web.backend", record_type), &view);
            assert_eq!((answer.id, answer.response_code), (7, ResponseCode::NoError), "{record_type}");
            assert!(answer.authoritative);
            assert_eq!(answer.queries[0].query_type, record_type);
            assert!(answer.answers.is_empty() && answer.authorities.is_empty() && answer.additionals.is_empty());
        }
    }

    #[test]
    fn ptr_of_an_address_on_the_network_names_it() {
        let view = view(somewhere());
        let answer = local(&query(9, "2.0.89.10.In-Addr.Arpa.", RecordType::PTR), &view);
        assert_eq!((answer.id, answer.response_code), (9, ResponseCode::NoError));
        assert!(answer.authoritative);
        let [record] = answer.answers.as_slice() else { panic!("{:?}", answer.answers) };
        assert_eq!(record.ttl, TTL);
        assert!(record.name.eq_case(&answer.queries[0].name));
        match &record.data {
            RData::PTR(PTR(name)) => assert_eq!(name.to_ascii(), "web.backend."),
            other => panic!("not a PTR: {other:?}"),
        }
    }

    #[test]
    fn ptr_of_any_other_address_is_forwarded() {
        let view = view(somewhere());
        let others = [
            "9.0.89.10.in-addr.arpa.",  // nobody's
            "2.0.90.10.in-addr.arpa.",  // on frontend
            "02.0.89.10.in-addr.arpa.", // another name
            "0.89.10.in-addr.arpa.",    // a network, not an address
            "1.1.1.1.in-addr.arpa.",
            "2.0.89.10.ip6.arpa.",
        ];
        for name in others {
            assert_eq!(answer_locally(&query(1, name, RecordType::PTR), &view), None, "{name}");
        }
    }

    #[test]
    fn other_names_are_forwarded() {
        let view = view(somewhere());
        for name in ["example.com.", "cache", "cache.frontend.", "web.example.com.", "backend."] {
            assert_eq!(answer_locally(&query(1, name, RecordType::A), &view), None, "{name}");
        }
        // Whatever the name, a question of another class than IN.
        let chaos = edit(&query(1, "web", RecordType::TXT), |m| m.queries[0].query_class = DNSClass::CH);
        assert_eq!(answer_locally(&chaos, &view), None);
    }

    #[test]
    fn without_upstreams_other_names_are_refused() {
        let view = view(Vec::new());
        let answer = local(&query(5, "example.com.", RecordType::A), &view);
        assert_eq!((answer.id, answer.response_code), (5, ResponseCode::Refused));
        assert!(!answer.authoritative && !answer.recursion_available && answer.recursion_desired);
        assert_eq!(answer.queries[0].name.to_ascii(), "example.com.");
        assert!(answer.answers.is_empty());
        // Names on the network still answer.
        assert_eq!(addresses(&local(&query(6, "web", RecordType::A), &view)), [WEB]);
    }

    #[test]
    fn what_is_not_one_question_is_a_format_error() {
        let view = view(somewhere());
        let asked = query(1, "web", RecordType::A);
        let response = edit(&asked, |m| m.metadata.message_type = MessageType::Response);
        let two = edit(&asked, |m| {
            m.add_query(Query::query(Name::from_ascii("db.").unwrap(), RecordType::A));
        });
        let none = edit(&asked, |m| m.queries.clear());
        // A header that promises a question the message doesn't have.
        let cut = asked[..HEADER_LEN + 3].to_vec();
        // A response gets nothing back: answering it could start a loop.
        assert_eq!(answer_locally(&response, &view), Some(Vec::new()));
        for (what, bytes) in [("two", two), ("none", none), ("cut", cut)] {
            let answer = local(&bytes, &view);
            assert_eq!((answer.id, answer.response_code), (1, ResponseCode::FormErr), "{what}");
            assert_eq!(answer.message_type, MessageType::Response, "{what}");
            assert!(answer.queries.is_empty() && answer.answers.is_empty(), "{what}");
        }
    }

    #[test]
    fn other_opcodes_are_not_implemented() {
        let view = view(somewhere());
        for op_code in [OpCode::Status, OpCode::Notify, OpCode::Update, OpCode::Unknown(1)] {
            let asked = edit(&query(8, "web", RecordType::A), |m| m.metadata.op_code = op_code);
            let answer = local(&asked, &view);
            assert_eq!((answer.id, answer.op_code, answer.response_code), (8, op_code, ResponseCode::NotImp));
            assert!(answer.queries.is_empty() && answer.answers.is_empty());
        }
        // Whatever the count of questions.
        let bare = edit(&query(8, "web", RecordType::A), |m| {
            m.metadata.op_code = OpCode::Status;
            m.queries.clear();
        });
        assert_eq!(local(&bare, &view).response_code, ResponseCode::NotImp);
    }

    #[test]
    fn less_than_a_header_is_dropped() {
        let view = view(somewhere());
        for garbage in [&b""[..], b"\x12", b"\x12\x34\x01\x00junk"] {
            assert_eq!(answer_locally(garbage, &view), Some(Vec::new()), "{garbage:?}");
        }
    }

    /// Registers [`CROWD`] containers under `many` on `backend`: more
    /// addresses than 512 bytes hold.
    fn crowd(zone: &Zone) {
        for i in 0..CROWD {
            zone.add("backend", Ipv4Addr::new(10, 89, 1, i), &names(&["many"]));
        }
    }

    #[test]
    fn long_local_answers_are_cut_to_fit_a_datagram() {
        let view = view(somewhere());
        crowd(&view.zone);
        let plain = query(1, "many", RecordType::A);
        let whole = answer_locally(&plain, &view).unwrap();
        assert_eq!(
            Message::from_vec(&whole).unwrap().answers.len(),
            usize::from(CROWD),
            "all of them, as TCP gets them"
        );

        let cut = fit_udp(&plain, whole.clone());
        assert!(cut.len() <= 512, "{} bytes", cut.len());
        let cut = Message::from_vec(&cut).unwrap();
        assert!(cut.truncation);
        assert_eq!((cut.id, cut.response_code, cut.queries.len()), (1, ResponseCode::NoError, 1));
        assert!((20..usize::from(CROWD)).contains(&cut.answers.len()), "{} records", cut.answers.len());

        // A client that takes more (EDNS) gets them all.
        let mut edns = Edns::new();
        edns.set_max_payload(4096);
        let roomy = edit(&plain, |m| {
            m.set_edns(edns);
        });
        assert_eq!(fit_udp(&roomy, whole.clone()), whole);
        // As does anyone with a short answer.
        let short = answer_locally(&query(2, "many", RecordType::AAAA), &view).unwrap();
        assert_eq!(fit_udp(&plain, short.clone()), short);
    }

    #[test]
    fn servers_and_zones_can_be_shared_between_threads() {
        fn send_sync<T: Send + Sync>() {}
        send_sync::<DnsServer>();
        send_sync::<Zone>();
        send_sync::<View>();
    }

    /// A UDP socket and a TCP listener on 127.0.0.1, on ports the kernel
    /// picks, and their addresses.
    fn sockets() -> (std::net::UdpSocket, std::net::TcpListener, SocketAddr, SocketAddr) {
        let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let (udp_address, tcp_address) = (udp.local_addr().unwrap(), tcp.local_addr().unwrap());
        (udp, tcp, udp_address, tcp_address)
    }

    /// A server for `view` on [`sockets`], waiting as `timeouts` says.
    fn serve(view: View, timeouts: Timeouts) -> (DnsServer, SocketAddr, SocketAddr) {
        let (udp, tcp, udp_address, tcp_address) = sockets();
        (DnsServer::start(udp, tcp, view, timeouts).unwrap(), udp_address, tcp_address)
    }

    /// Asks `server` over UDP: its answer, or `None` if none comes within
    /// `wait` (or an ICMP error does: nothing listens).
    async fn ask_udp(server: SocketAddr, query: &[u8], wait: Duration) -> Option<Vec<u8>> {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket.connect(server).await.unwrap();
        socket.send(query).await.unwrap();
        let mut buf = vec![0; MAX_MESSAGE];
        let len = tokio::time::timeout(wait, socket.recv(&mut buf)).await.ok()?.ok()?;
        buf.truncate(len);
        Some(buf)
    }

    /// Asks on a TCP connection: the answer, as it came.
    async fn ask_tcp_raw(stream: &mut TcpStream, query: &[u8]) -> Vec<u8> {
        write_message(stream, query).await.unwrap();
        let answer = tokio::time::timeout(PATIENCE, read_message(stream)).await.expect("an answer in time");
        answer.unwrap().expect("an answer, not the end")
    }

    /// Asks on a TCP connection: the answer.
    async fn ask_tcp(stream: &mut TcpStream, query: &[u8]) -> Message {
        Message::from_vec(&ask_tcp_raw(stream, query).await).unwrap()
    }

    fn parse(answer: Option<Vec<u8>>) -> Message {
        Message::from_vec(&answer.expect("an answer")).unwrap()
    }

    #[tokio::test]
    async fn names_on_the_network_answer_over_udp_and_tcp() {
        let (udp, tcp, udp_address, tcp_address) = sockets();
        // The daemon's way in, with the real timeouts.
        let _server = DnsServer::spawn(udp, tcp, view(Vec::new())).unwrap();
        let answer = parse(ask_udp(udp_address, &query(1, "web", RecordType::A), PATIENCE).await);
        assert_eq!((answer.id, addresses(&answer)), (1, vec![WEB]));
        // Two questions on one connection.
        let mut stream = TcpStream::connect(tcp_address).await.unwrap();
        let answer = ask_tcp(&mut stream, &query(2, "app", RecordType::A)).await;
        assert_eq!((answer.id, answer.answers.len()), (2, 2));
        let answer = ask_tcp(&mut stream, &query(3, "db.backend.", RecordType::A)).await;
        assert_eq!((answer.id, addresses(&answer)), (3, vec![DB]));
    }

    #[tokio::test]
    async fn long_answers_are_cut_over_udp_but_not_tcp() {
        let view = view(Vec::new());
        crowd(&view.zone);
        let (_server, udp, tcp) = serve(view, QUICK);
        let asked = query(4, "many", RecordType::A);
        let over_udp = ask_udp(udp, &asked, PATIENCE).await.expect("an answer");
        assert!(over_udp.len() <= 512, "{} bytes", over_udp.len());
        let over_udp = Message::from_vec(&over_udp).unwrap();
        assert!(over_udp.truncation && over_udp.answers.len() < usize::from(CROWD));
        let mut stream = TcpStream::connect(tcp).await.unwrap();
        let over_tcp = ask_tcp(&mut stream, &asked).await;
        assert!(!over_tcp.truncation);
        assert_eq!(over_tcp.answers.len(), usize::from(CROWD));
    }

    #[tokio::test]
    async fn what_is_not_dns_gets_no_answer() {
        let (_server, udp, tcp) = serve(view(Vec::new()), QUICK);
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.connect(udp).await.unwrap();
        client.send(b"junk").await.unwrap();
        client.send(&query(5, "web", RecordType::A)).await.unwrap();
        let mut buf = vec![0; MAX_MESSAGE];
        let len = tokio::time::timeout(PATIENCE, client.recv(&mut buf)).await.expect("an answer").unwrap();
        assert_eq!(Message::from_vec(&buf[..len]).unwrap().id, 5, "the first answer is the query's");
        // A TCP connection goes on after it.
        let mut stream = TcpStream::connect(tcp).await.unwrap();
        write_message(&mut stream, b"junk").await.unwrap();
        assert_eq!(ask_tcp(&mut stream, &query(6, "web", RecordType::A)).await.id, 6);
    }

    /// What a fake upstream server answers a query with: the messages it
    /// sends, in order (none: it says nothing).
    type Reply = fn(&Message, Transport) -> Vec<Message>;

    /// An answer to `query`: its question, and `address`.
    fn answer_with(query: &Message, address: A) -> Message {
        let mut answer = Message::response(query.id, query.op_code);
        answer.metadata.recursion_desired = query.recursion_desired;
        answer.metadata.recursion_available = true;
        answer.add_query(query.queries[0].clone());
        answer.add_answer(Record::from_rdata(query.queries[0].name.clone(), 60, RData::A(address)));
        answer
    }

    /// An upstream server's usual answer.
    fn address(query: &Message, _: Transport) -> Vec<Message> {
        vec![answer_with(query, FAR)]
    }

    /// Too long for a datagram: TC and no records over UDP, the address
    /// over TCP.
    fn truncating(query: &Message, transport: Transport) -> Vec<Message> {
        let mut answer = answer_with(query, FAR);
        if transport == Transport::Udp {
            answer.answers.clear();
            answer.metadata.truncation = true;
        }
        vec![answer]
    }

    /// The answer, after an answer to another ID and a query with this one.
    fn confused(query: &Message, _: Transport) -> Vec<Message> {
        let mut another = answer_with(query, WRONG);
        another.metadata.id = query.id.wrapping_add(1);
        let mut not_an_answer = answer_with(query, WRONG);
        not_an_answer.metadata.message_type = MessageType::Query;
        vec![another, not_an_answer, answer_with(query, FAR)]
    }

    fn silent(_: &Message, _: Transport) -> Vec<Message> {
        Vec::new()
    }

    /// A fake upstream server on 127.0.0.1, UDP and TCP on one port, as a
    /// real one has them on 53.
    struct Upstream {
        address: SocketAddr,
        /// The queries it got, as they came.
        seen: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl Upstream {
        async fn start(reply: Reply) -> Upstream {
            let (udp, tcp) = loop {
                let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                // The same port for TCP, unless something has it already.
                if let Ok(tcp) = TcpListener::bind(udp.local_addr().unwrap()).await {
                    break (udp, tcp);
                }
            };
            let upstream = Upstream { address: udp.local_addr().unwrap(), seen: Arc::default() };
            let seen = upstream.seen.clone();
            tokio::spawn(async move {
                let mut buf = vec![0; MAX_MESSAGE];
                loop {
                    let (len, from) = udp.recv_from(&mut buf).await.unwrap();
                    for answer in respond(&seen, reply, &buf[..len], Transport::Udp) {
                        udp.send_to(&answer, from).await.unwrap();
                    }
                }
            });
            let seen = upstream.seen.clone();
            tokio::spawn(async move {
                loop {
                    let (mut stream, _) = tcp.accept().await.unwrap();
                    let seen = seen.clone();
                    tokio::spawn(async move {
                        while let Ok(Some(query)) = read_message(&mut stream).await {
                            for answer in respond(&seen, reply, &query, Transport::Tcp) {
                                let _ = write_message(&mut stream, &answer).await;
                            }
                        }
                    });
                }
            });
            upstream
        }

        fn seen(&self) -> Vec<Vec<u8>> {
            self.seen.lock().unwrap().clone()
        }
    }

    /// Notes `query` in `seen`, and puts `reply`'s answers to it in bytes.
    fn respond(seen: &Mutex<Vec<Vec<u8>>>, reply: Reply, query: &[u8], transport: Transport) -> Vec<Vec<u8>> {
        seen.lock().unwrap().push(query.to_vec());
        reply(&Message::from_vec(query).unwrap(), transport).iter().map(wire).collect()
    }

    /// `message` as the fake upstream servers send it: with [`TRAILER`].
    fn wire(message: &Message) -> Vec<u8> {
        let mut bytes = message.to_vec().unwrap();
        bytes.push(TRAILER);
        bytes
    }

    #[tokio::test]
    async fn other_names_are_forwarded_with_the_id_restored() {
        let upstream = Upstream::start(address).await;
        let (_server, udp, tcp) = serve(view(vec![upstream.address]), QUICK);
        let asked = query(0xbeef, "Example.com.", RecordType::A);
        let over_udp = ask_udp(udp, &asked, PATIENCE).await.expect("an answer");
        let mut stream = TcpStream::connect(tcp).await.unwrap();
        let over_tcp = ask_tcp_raw(&mut stream, &asked).await;

        // The query as it came, but for the ID: the server's own (equal to
        // the client's for both queries one time in 2^32).
        let seen = upstream.seen();
        assert_eq!(seen.len(), 2, "one query over each transport");
        assert!(seen.iter().all(|forwarded| forwarded[2..] == asked[2..]));
        assert!(seen.iter().any(|forwarded| forwarded[..2] != asked[..2]), "the client's ID went upstream");
        // The upstream's answers as they came (trailer and all), but for the
        // ID: the client's.
        for (answer, forwarded) in [(over_udp, &seen[0]), (over_tcp, &seen[1])] {
            let sent = wire(&address(&Message::from_vec(forwarded).unwrap(), Transport::Udp)[0]);
            assert_eq!(answer[..2], [0xbe, 0xef]);
            assert_eq!(answer[2..], sent[2..]);
        }
    }

    #[tokio::test]
    async fn only_the_answer_to_the_query_is_relayed() {
        let upstream = Upstream::start(confused).await;
        let (_server, udp, tcp) = serve(view(vec![upstream.address]), QUICK);
        let asked = query(0x0202, "example.com.", RecordType::A);
        let over_udp = parse(ask_udp(udp, &asked, PATIENCE).await);
        let mut stream = TcpStream::connect(tcp).await.unwrap();
        let over_tcp = ask_tcp(&mut stream, &asked).await;
        for answer in [over_udp, over_tcp] {
            assert_eq!((answer.id, addresses(&answer)), (0x0202, vec![FAR.0]));
        }
    }

    #[tokio::test]
    async fn a_truncated_answer_is_relayed_and_tcp_gets_the_whole() {
        let upstream = Upstream::start(truncating).await;
        let (_server, udp, tcp) = serve(view(vec![upstream.address]), QUICK);
        let asked = query(0x0101, "big.example.", RecordType::A);
        let answer = parse(ask_udp(udp, &asked, PATIENCE).await);
        assert!(answer.truncation);
        assert_eq!((answer.id, answer.answers.len()), (0x0101, 0));
        // So the client asks again over TCP, and so does the server.
        let mut stream = TcpStream::connect(tcp).await.unwrap();
        let answer = ask_tcp(&mut stream, &asked).await;
        assert!(!answer.truncation);
        assert_eq!((answer.id, addresses(&answer)), (0x0101, vec![FAR.0]));
    }

    #[tokio::test]
    async fn an_upstream_that_does_not_answer_is_passed_over() {
        let (quiet, answering) = (Upstream::start(silent).await, Upstream::start(address).await);
        let (_server, udp, _) = serve(view(vec![quiet.address, answering.address]), QUICK);
        let started = Instant::now();
        let answer = parse(ask_udp(udp, &query(2, "example.com.", RecordType::A), PATIENCE).await);
        assert!(started.elapsed() >= QUICK.forward, "the first one had its time");
        assert_eq!((answer.id, addresses(&answer)), (2, vec![FAR.0]));
        assert_eq!((quiet.seen().len(), answering.seen().len()), (1, 1));
    }

    #[tokio::test]
    async fn no_answer_from_any_upstream_is_servfail() {
        let (one, two) = (Upstream::start(silent).await, Upstream::start(silent).await);
        let (_server, udp, tcp) = serve(view(vec![one.address, two.address]), QUICK);
        let asked = query(3, "example.com.", RecordType::A);
        let answer = parse(ask_udp(udp, &asked, PATIENCE).await);
        assert_eq!((answer.id, answer.response_code), (3, ResponseCode::ServFail));
        assert_eq!(answer.queries[0].name.to_ascii(), "example.com.");
        let mut stream = TcpStream::connect(tcp).await.unwrap();
        let answer = ask_tcp(&mut stream, &asked).await;
        assert_eq!((answer.id, answer.response_code), (3, ResponseCode::ServFail));
        assert_eq!((one.seen().len(), two.seen().len()), (2, 2));
    }

    #[tokio::test]
    async fn forwards_beyond_the_limit_get_servfail_at_once() {
        let quiet = Upstream::start(silent).await;
        // Time enough that no forward ends during the test.
        let (_server, udp, _) =
            serve(view(vec![quiet.address]), Timeouts { forward: Duration::from_secs(60), ..QUICK });
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.connect(udp).await.unwrap();
        let ids = 0..=MAX_FORWARDS as u16;
        for id in ids.clone() {
            client.send(&query(id, "example.com.", RecordType::A)).await.unwrap();
        }
        let mut buf = vec![0; MAX_MESSAGE];
        let len = tokio::time::timeout(PATIENCE, client.recv(&mut buf)).await.expect("an answer").unwrap();
        let answer = Message::from_vec(&buf[..len]).unwrap();
        assert_eq!((answer.id, answer.response_code), (*ids.end(), ResponseCode::ServFail));
    }

    #[tokio::test]
    async fn an_idle_connection_is_closed() {
        let (_server, _, tcp) = serve(view(Vec::new()), QUICK);
        let mut stream = TcpStream::connect(tcp).await.unwrap();
        ask_tcp(&mut stream, &query(1, "web", RecordType::A)).await;
        let started = Instant::now();
        let mut byte = [0; 1];
        let read = tokio::time::timeout(PATIENCE, stream.read(&mut byte)).await.expect("closed in time");
        assert_eq!(read.unwrap(), 0, "the end of the stream");
        // (The server's clock started a little before the client's.)
        assert!(started.elapsed() >= QUICK.tcp_idle / 2, "closed after {:?}", started.elapsed());
    }

    #[tokio::test]
    async fn connections_beyond_the_limit_wait_for_one_to_end() {
        let (_server, _, tcp) = serve(view(Vec::new()), Timeouts { tcp_idle: Duration::from_secs(60), ..QUICK });
        let asked = query(6, "web", RecordType::A);
        let mut served = Vec::new();
        for _ in 0..MAX_TCP_CONNECTIONS {
            let mut stream = TcpStream::connect(tcp).await.unwrap();
            ask_tcp(&mut stream, &asked).await;
            served.push(stream);
        }
        // One more gets in (the kernel completes it, into the backlog)...
        let mut waiting = TcpStream::connect(tcp).await.unwrap();
        write_message(&mut waiting, &asked).await.unwrap();
        assert!(tokio::time::timeout(SILENCE, read_message(&mut waiting)).await.is_err(), "served beyond the limit");
        // ...and is served once another one ends.
        drop(served.pop());
        let answer = tokio::time::timeout(PATIENCE, read_message(&mut waiting)).await.expect("served in the end");
        assert_eq!(Message::from_vec(&answer.unwrap().unwrap()).unwrap().id, 6);
    }

    /// Waits until `done` holds, for [`PATIENCE`] at most.
    async fn eventually(what: &str, mut done: impl FnMut() -> bool) {
        let deadline = Instant::now() + PATIENCE;
        while !done() {
            assert!(Instant::now() < deadline, "{what}: not in time");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    #[tokio::test]
    async fn a_dropped_server_stops_answering() {
        // With a forward that would last a minute.
        let quiet = Upstream::start(silent).await;
        let (server, udp, tcp) =
            serve(view(vec![quiet.address]), Timeouts { forward: Duration::from_secs(60), ..QUICK });
        let asked = query(4, "web", RecordType::A);
        assert!(ask_udp(udp, &asked, PATIENCE).await.is_some());
        let mut open = TcpStream::connect(tcp).await.unwrap();
        ask_tcp(&mut open, &asked).await;
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(&query(5, "example.com.", RecordType::A), udp).await.unwrap();
        eventually("the forward", || !quiet.seen().is_empty()).await;

        drop(server);
        // The connection in progress ends...
        let mut byte = [0; 1];
        let read = tokio::time::timeout(PATIENCE, open.read(&mut byte)).await.expect("closed in time");
        assert!(matches!(read, Ok(0) | Err(_)), "{read:?}");
        // ...new ones are refused...
        let deadline = Instant::now() + PATIENCE;
        while TcpStream::connect(tcp).await.is_ok() {
            assert!(Instant::now() < deadline, "still accepting");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        // ...queries over UDP go unanswered...
        assert_eq!(ask_udp(udp, &asked, SILENCE).await, None);
        // ...as the socket is closed, along with the forward that shared it:
        // its port is free again.
        eventually("a free port", || std::net::UdpSocket::bind(udp).is_ok()).await;
    }
}

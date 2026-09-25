//! A minimal rtnetlink encoder/decoder: enough to create a bridge and veth
//! pairs, move a link into another network namespace, assign addresses,
//! add routes and bring links up. This is what `ip link`/`ip addr`/`ip route`
//! do under the hood.
//!
//! ## Wire format
//!
//! A netlink message is a 16-byte `nlmsghdr` followed by a family header
//! (`ifinfomsg` for links, `ifaddrmsg` for addresses, `rtmsg` for routes) and
//! then a list of **attributes** (`rtattr`): `{u16 len, u16 type, payload}`,
//! each padded to 4 bytes. Attributes nest: `IFLA_LINKINFO` contains
//! `IFLA_INFO_KIND = "veth"` and `IFLA_INFO_DATA`, which contains
//! `VETH_INFO_PEER`, which contains a whole `ifinfomsg` plus attributes for
//! the peer. Integers are host-endian (little-endian here), except IP
//! addresses, which are just their network-order bytes.
//!
//! Everything here is safe code; the socket itself comes from `nix`.

use std::os::fd::{AsFd, OwnedFd};

use nix::sys::socket::{
    AddressFamily, MsgFlags, NetlinkAddr, SockFlag, SockProtocol, SockType, bind, recv, send, socket,
};

use crate::{Errno, Result};

/// rtnetlink message types and flags.
pub mod consts {
    pub const RTM_NEWLINK: u16 = 16;
    pub const RTM_DELLINK: u16 = 17;
    pub const RTM_GETLINK: u16 = 18;
    pub const RTM_NEWADDR: u16 = 20;
    pub const RTM_DELADDR: u16 = 21;
    pub const RTM_GETADDR: u16 = 22;
    pub const RTM_NEWROUTE: u16 = 24;
    pub const RTM_DELROUTE: u16 = 25;

    pub const NLMSG_NOOP: u16 = 1;
    pub const NLMSG_ERROR: u16 = 2;
    pub const NLMSG_DONE: u16 = 3;

    pub const NLM_F_REQUEST: u16 = 0x01;
    pub const NLM_F_MULTI: u16 = 0x02;
    pub const NLM_F_ACK: u16 = 0x04;
    pub const NLM_F_DUMP: u16 = 0x300;
    pub const NLM_F_REPLACE: u16 = 0x100;
    pub const NLM_F_EXCL: u16 = 0x200;
    pub const NLM_F_CREATE: u16 = 0x400;

    pub const IFLA_ADDRESS: u16 = 1;
    pub const IFLA_IFNAME: u16 = 3;
    pub const IFLA_MTU: u16 = 4;
    pub const IFLA_MASTER: u16 = 10;
    pub const IFLA_OPERSTATE: u16 = 16;
    pub const IFLA_LINKINFO: u16 = 18;
    pub const IFLA_NET_NS_PID: u16 = 19;
    pub const IFLA_STATS64: u16 = 23;
    pub const IFLA_NET_NS_FD: u16 = 28;

    pub const IFLA_INFO_KIND: u16 = 1;
    pub const IFLA_INFO_DATA: u16 = 2;
    pub const VETH_INFO_PEER: u16 = 1;

    pub const IFA_ADDRESS: u16 = 1;
    pub const IFA_LOCAL: u16 = 2;
    pub const IFA_BROADCAST: u16 = 4;

    pub const RTA_DST: u16 = 1;
    pub const RTA_OIF: u16 = 4;
    pub const RTA_GATEWAY: u16 = 5;

    pub const RT_TABLE_MAIN: u8 = 254;
    pub const RTPROT_BOOT: u8 = 3;
    pub const RT_SCOPE_UNIVERSE: u8 = 0;
    pub const RT_SCOPE_LINK: u8 = 253;
    pub const RTN_UNICAST: u8 = 1;

    pub const IFF_UP: u32 = 0x1;
    pub const IFF_LOOPBACK: u32 = 0x8;
    pub const IFF_RUNNING: u32 = 0x40;

    pub const AF_UNSPEC: u8 = 0;
    pub const AF_INET: u8 = 2;
    pub const AF_INET6: u8 = 10;

    /// A nested attribute sets this bit in its type (`NLA_F_NESTED`).
    pub const NLA_F_NESTED: u16 = 1 << 15;
    pub const NLA_TYPE_MASK: u16 = !(1 << 15 | 1 << 14);
}
use consts::*;

const NLMSG_HDRLEN: usize = 16;

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// `struct ifinfomsg` (16 bytes).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IfInfoMsg {
    pub family: u8,
    pub ifi_type: u16,
    pub index: i32,
    pub flags: u32,
    pub change: u32,
}

impl IfInfoMsg {
    pub fn to_bytes(&self) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[0] = self.family;
        b[2..4].copy_from_slice(&self.ifi_type.to_ne_bytes());
        b[4..8].copy_from_slice(&self.index.to_ne_bytes());
        b[8..12].copy_from_slice(&self.flags.to_ne_bytes());
        b[12..16].copy_from_slice(&self.change.to_ne_bytes());
        b
    }
    pub fn parse(b: &[u8]) -> Option<IfInfoMsg> {
        if b.len() < 16 {
            return None;
        }
        Some(IfInfoMsg {
            family: b[0],
            ifi_type: u16::from_ne_bytes([b[2], b[3]]),
            index: i32::from_ne_bytes(b[4..8].try_into().ok()?),
            flags: u32::from_ne_bytes(b[8..12].try_into().ok()?),
            change: u32::from_ne_bytes(b[12..16].try_into().ok()?),
        })
    }
}

/// `struct ifaddrmsg` (8 bytes).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IfAddrMsg {
    pub family: u8,
    pub prefixlen: u8,
    pub flags: u8,
    pub scope: u8,
    pub index: u32,
}

impl IfAddrMsg {
    pub fn to_bytes(&self) -> [u8; 8] {
        let mut b = [0u8; 8];
        b[0] = self.family;
        b[1] = self.prefixlen;
        b[2] = self.flags;
        b[3] = self.scope;
        b[4..8].copy_from_slice(&self.index.to_ne_bytes());
        b
    }
}

/// `struct rtmsg` (12 bytes).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RtMsg {
    pub family: u8,
    pub dst_len: u8,
    pub src_len: u8,
    pub tos: u8,
    pub table: u8,
    pub protocol: u8,
    pub scope: u8,
    pub rtm_type: u8,
    pub flags: u32,
}

impl RtMsg {
    pub fn to_bytes(&self) -> [u8; 12] {
        let mut b = [0u8; 12];
        b[..8].copy_from_slice(&[
            self.family,
            self.dst_len,
            self.src_len,
            self.tos,
            self.table,
            self.protocol,
            self.scope,
            self.rtm_type,
        ]);
        b[8..12].copy_from_slice(&self.flags.to_ne_bytes());
        b
    }
}

/// Builds one netlink message.
#[derive(Debug)]
pub struct MsgBuilder {
    buf: Vec<u8>,
    nests: Vec<usize>,
}

impl MsgBuilder {
    /// Starts a message of type `ty`; `NLM_F_REQUEST | NLM_F_ACK` are added.
    pub fn new(ty: u16, flags: u16) -> Self {
        let mut buf = vec![0u8; NLMSG_HDRLEN];
        buf[4..6].copy_from_slice(&ty.to_ne_bytes());
        buf[6..8].copy_from_slice(&(flags | NLM_F_REQUEST | NLM_F_ACK).to_ne_bytes());
        MsgBuilder { buf, nests: Vec::new() }
    }

    /// Appends the family header (or any raw, 4-byte padded bytes).
    pub fn header(mut self, bytes: &[u8]) -> Self {
        self.buf.extend_from_slice(bytes);
        self.pad();
        self
    }

    fn pad(&mut self) {
        let n = align4(self.buf.len());
        self.buf.resize(n, 0);
    }

    /// Appends an attribute with a raw payload.
    pub fn attr(mut self, ty: u16, data: &[u8]) -> Self {
        let len = 4 + data.len();
        self.buf.extend_from_slice(&(len as u16).to_ne_bytes());
        self.buf.extend_from_slice(&ty.to_ne_bytes());
        self.buf.extend_from_slice(data);
        self.pad();
        self
    }
    pub fn attr_u32(self, ty: u16, v: u32) -> Self {
        self.attr(ty, &v.to_ne_bytes())
    }
    /// A NUL-terminated string attribute (e.g. `IFLA_IFNAME`).
    pub fn attr_str(self, ty: u16, s: &str) -> Self {
        let mut v = s.as_bytes().to_vec();
        v.push(0);
        self.attr(ty, &v)
    }

    /// Opens a nested attribute; close it with [`MsgBuilder::end_nest`].
    pub fn begin_nest(mut self, ty: u16) -> Self {
        self.nests.push(self.buf.len());
        self.buf.extend_from_slice(&[0, 0]);
        self.buf.extend_from_slice(&(ty | NLA_F_NESTED).to_ne_bytes());
        self
    }
    pub fn end_nest(mut self) -> Self {
        let start = self.nests.pop().expect("end_nest without begin_nest");
        let len = (self.buf.len() - start) as u16;
        self.buf[start..start + 2].copy_from_slice(&len.to_ne_bytes());
        self
    }

    /// Finishes the message: fills in length and sequence number.
    pub fn finish(mut self, seq: u32) -> Vec<u8> {
        assert!(self.nests.is_empty(), "unclosed nested attribute");
        let len = self.buf.len() as u32;
        self.buf[0..4].copy_from_slice(&len.to_ne_bytes());
        self.buf[8..12].copy_from_slice(&seq.to_ne_bytes());
        self.buf
    }
}

/// One received message.
#[derive(Debug, Clone)]
pub struct NlMsg {
    pub ty: u16,
    pub flags: u16,
    pub seq: u32,
    pub payload: Vec<u8>,
}

/// Splits a receive buffer into messages.
pub fn parse_messages(mut buf: &[u8]) -> Vec<NlMsg> {
    let mut out = Vec::new();
    while buf.len() >= NLMSG_HDRLEN {
        let len = u32::from_ne_bytes(buf[0..4].try_into().unwrap()) as usize;
        if len < NLMSG_HDRLEN || len > buf.len() {
            break;
        }
        out.push(NlMsg {
            ty: u16::from_ne_bytes([buf[4], buf[5]]),
            flags: u16::from_ne_bytes([buf[6], buf[7]]),
            seq: u32::from_ne_bytes(buf[8..12].try_into().unwrap()),
            payload: buf[NLMSG_HDRLEN..len].to_vec(),
        });
        buf = &buf[align4(len).min(buf.len())..];
    }
    out
}

/// Iterates `(type, payload)` attributes in `buf` (type has the nested bit
/// stripped).
pub fn attrs(mut buf: &[u8]) -> impl Iterator<Item = (u16, &[u8])> {
    std::iter::from_fn(move || {
        if buf.len() < 4 {
            return None;
        }
        let len = u16::from_ne_bytes([buf[0], buf[1]]) as usize;
        let ty = u16::from_ne_bytes([buf[2], buf[3]]) & NLA_TYPE_MASK;
        if len < 4 || len > buf.len() {
            return None;
        }
        let data = &buf[4..len];
        buf = &buf[align4(len).min(buf.len())..];
        Some((ty, data))
    })
}

/// A decoded `RTM_NEWLINK` (from a GETLINK dump).
#[derive(Debug, Clone, Default)]
pub struct LinkInfo {
    pub index: i32,
    pub name: String,
    pub flags: u32,
    pub mtu: u32,
    pub mac: Vec<u8>,
    pub master: Option<u32>,
    pub kind: Option<String>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
}

impl LinkInfo {
    pub fn parse(payload: &[u8]) -> Option<LinkInfo> {
        let hdr = IfInfoMsg::parse(payload)?;
        let mut li = LinkInfo { index: hdr.index, flags: hdr.flags, ..Default::default() };
        for (ty, data) in attrs(&payload[16..]) {
            match ty {
                IFLA_IFNAME => li.name = cstr_attr(data),
                IFLA_MTU if data.len() >= 4 => li.mtu = u32::from_ne_bytes(data[..4].try_into().ok()?),
                IFLA_ADDRESS => li.mac = data.to_vec(),
                IFLA_MASTER if data.len() >= 4 => li.master = Some(u32::from_ne_bytes(data[..4].try_into().ok()?)),
                IFLA_LINKINFO => {
                    for (t, d) in attrs(data) {
                        if t == IFLA_INFO_KIND {
                            li.kind = Some(cstr_attr(d));
                        }
                    }
                }
                IFLA_STATS64 if data.len() >= 32 => {
                    let u = |i: usize| u64::from_ne_bytes(data[i * 8..i * 8 + 8].try_into().unwrap());
                    li.rx_packets = u(0);
                    li.tx_packets = u(1);
                    li.rx_bytes = u(2);
                    li.tx_bytes = u(3);
                }
                _ => {}
            }
        }
        Some(li)
    }
}

fn cstr_attr(d: &[u8]) -> String {
    let end = d.iter().position(|&b| b == 0).unwrap_or(d.len());
    String::from_utf8_lossy(&d[..end]).into_owned()
}

/// A `NETLINK_ROUTE` socket bound in the calling thread's network namespace.
///
/// A netlink socket talks to the netns it was *created* in, even if the
/// thread later moves elsewhere; create it on the thread that is in the
/// target namespace.
#[derive(Debug)]
pub struct RtNetlink {
    fd: OwnedFd,
    seq: u32,
}

impl RtNetlink {
    pub fn open() -> Result<RtNetlink> {
        let fd = socket(AddressFamily::Netlink, SockType::Raw, SockFlag::SOCK_CLOEXEC, SockProtocol::NetlinkRoute)?;
        bind(std::os::fd::AsRawFd::as_raw_fd(&fd), &NetlinkAddr::new(0, 0))?;
        Ok(RtNetlink { fd, seq: 1 })
    }

    /// Sends a request built with [`MsgBuilder`] and collects replies until
    /// the ACK (or `NLMSG_DONE` for dumps). A negative error in the ACK is
    /// returned as `Err`.
    pub fn request(&mut self, msg: MsgBuilder) -> Result<Vec<NlMsg>> {
        self.seq = self.seq.wrapping_add(1);
        let seq = self.seq;
        let bytes = msg.finish(seq);
        send(std::os::fd::AsRawFd::as_raw_fd(&self.fd), &bytes, MsgFlags::empty())?;
        let mut replies = Vec::new();
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = recv(std::os::fd::AsRawFd::as_raw_fd(&self.fd.as_fd()), &mut buf, MsgFlags::empty())?;
            for m in parse_messages(&buf[..n]) {
                if m.seq != seq {
                    continue;
                }
                match m.ty {
                    NLMSG_ERROR => {
                        let code = i32::from_ne_bytes(m.payload.get(..4).ok_or(Errno::EIO)?.try_into().unwrap());
                        return if code == 0 { Ok(replies) } else { Err(Errno::from_raw(-code)) };
                    }
                    NLMSG_DONE => return Ok(replies),
                    NLMSG_NOOP => {}
                    _ => replies.push(m),
                }
            }
        }
    }

    /// Dumps all links.
    pub fn links(&mut self) -> Result<Vec<LinkInfo>> {
        let msg = MsgBuilder::new(RTM_GETLINK, NLM_F_DUMP).header(&IfInfoMsg::default().to_bytes());
        Ok(self.request(msg)?.iter().filter_map(|m| LinkInfo::parse(&m.payload)).collect())
    }

    /// Sets `IFF_UP` on the link with index `index` (`ip link set … up`).
    pub fn set_link_up(&mut self, index: i32) -> Result<()> {
        const IFF_UP: u32 = libc::IFF_UP as u32;
        let hdr = IfInfoMsg { index, flags: IFF_UP, change: IFF_UP, ..Default::default() };
        self.request(MsgBuilder::new(RTM_NEWLINK, NLM_F_ACK).header(&hdr.to_bytes())).map(drop)
    }

    /// Looks up a link by name.
    pub fn link_by_name(&mut self, name: &str) -> Result<Option<LinkInfo>> {
        let msg = MsgBuilder::new(RTM_GETLINK, 0).header(&IfInfoMsg::default().to_bytes()).attr_str(IFLA_IFNAME, name);
        match self.request(msg) {
            Ok(r) => Ok(r.iter().find_map(|m| LinkInfo::parse(&m.payload))),
            Err(Errno::ENODEV) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_nested_veth_request() {
        let peer = IfInfoMsg::default().to_bytes();
        let msg = MsgBuilder::new(RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL)
            .header(&IfInfoMsg::default().to_bytes())
            .attr_str(IFLA_IFNAME, "rlv0")
            .begin_nest(IFLA_LINKINFO)
            .attr_str(IFLA_INFO_KIND, "veth")
            .begin_nest(IFLA_INFO_DATA)
            .begin_nest(VETH_INFO_PEER)
            .header(&peer)
            .attr_str(IFLA_IFNAME, "rlv0p")
            .end_nest()
            .end_nest()
            .end_nest()
            .finish(7);
        assert_eq!(msg.len() % 4, 0);
        assert_eq!(u32::from_ne_bytes(msg[0..4].try_into().unwrap()) as usize, msg.len());
        // Walk back through the attributes we just wrote.
        let body = &msg[NLMSG_HDRLEN + 16..];
        let top: Vec<_> = attrs(body).collect();
        assert_eq!(top[0].0, IFLA_IFNAME);
        assert_eq!(top[1].0, IFLA_LINKINFO);
        let kinds: Vec<_> = attrs(top[1].1).map(|a| a.0).collect();
        assert_eq!(kinds, vec![IFLA_INFO_KIND, IFLA_INFO_DATA]);
    }

    #[test]
    fn can_dump_links_unprivileged() {
        let mut nl = RtNetlink::open().unwrap();
        let links = nl.links().unwrap();
        assert!(links.iter().any(|l| l.name == "lo"));
    }
}

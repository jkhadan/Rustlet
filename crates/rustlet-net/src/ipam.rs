//! IP address management: which subnet a network gets, which address a
//! container gets.
//!
//! Every network is an IPv4 subnet on a bridge. The default one is
//! `10.89.0.0/24`; a network created without `--subnet` gets the next
//! `/24` of the daemon's pool (`10.89.0.0/16`) that overlaps no other
//! network and no route the host already has (a VPN's, the LAN's). The
//! subnet's first address is the gateway, the bridge's own; containers get
//! the others, except the network and broadcast addresses.
//!
//! This module only decides; it keeps nothing. Which addresses are in use
//! is the daemon's to know (it records each container's address with the
//! container), and it asks [`Allocator::allocate`] with that knowledge.

use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// An IPv4 subnet, `10.89.0.0/24`: a network address with no host bits set,
/// and a prefix length from 8 to 30 (a bridge needs a gateway and room for
/// containers; a /31 or /32 has none).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(into = "String", try_from = "String")]
pub struct Subnet {
    network: Ipv4Addr,
    prefix_len: u8,
}

impl Subnet {
    /// The subnet `network/prefix_len`; host bits must be zero.
    pub fn new(network: Ipv4Addr, prefix_len: u8) -> Result<Subnet> {
        if !(8..=30).contains(&prefix_len) {
            return Err(Error::invalid(format!("{network}/{prefix_len}: the prefix length must be 8 to 30")));
        }
        let s = Subnet { network, prefix_len };
        if u32::from(network) & !s.mask() != 0 {
            let base = Ipv4Addr::from(u32::from(network) & s.mask());
            return Err(Error::invalid(format!(
                "{network}/{prefix_len} has host bits set: did you mean {base}/{prefix_len}?"
            )));
        }
        Ok(s)
    }

    /// Parses `10.89.0.0/24`.
    pub fn parse(s: &str) -> Result<Subnet> {
        let (addr, len) =
            s.split_once('/').ok_or_else(|| Error::invalid(format!("{s:?} is not a subnet (10.89.5.0/24)")))?;
        let addr =
            addr.parse::<Ipv4Addr>().map_err(|_| Error::invalid(format!("{s:?}: {addr:?} is not an IPv4 address")))?;
        let len = len.parse::<u8>().map_err(|_| Error::invalid(format!("{s:?}: {len:?} is not a prefix length")))?;
        Subnet::new(addr, len)
    }

    pub fn network(&self) -> Ipv4Addr {
        self.network
    }

    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    fn mask(&self) -> u32 {
        u32::MAX << (32 - u32::from(self.prefix_len))
    }

    pub fn broadcast(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.network) | !self.mask())
    }

    /// The first address after the network's: the default gateway.
    pub fn first_host(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.network) + 1)
    }

    pub fn last_host(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.broadcast()) - 1)
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        u32::from(ip) & self.mask() == u32::from(self.network)
    }

    /// Does `other` share an address with this subnet? (One contains the
    /// other: CIDR blocks never overlap partially.)
    pub fn overlaps(&self, other: &Subnet) -> bool {
        self.contains(other.network) || other.contains(self.network)
    }

    /// Does this subnet share an address with the block `addr/prefix_len`
    /// (a route's destination, any prefix length, `/0` included)?
    pub fn overlaps_block(&self, addr: Ipv4Addr, prefix_len: u8) -> bool {
        let len = prefix_len.min(self.prefix_len);
        let mask = if len == 0 { 0 } else { u32::MAX << (32 - u32::from(len)) };
        u32::from(addr) & mask == u32::from(self.network) & mask
    }

    /// An address of the subnet that a container (or the gateway) may have:
    /// not the network's or the broadcast address.
    pub fn is_host(&self, ip: Ipv4Addr) -> bool {
        self.contains(ip) && ip != self.network && ip != self.broadcast()
    }
}

impl fmt::Display for Subnet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix_len)
    }
}

impl FromStr for Subnet {
    type Err = Error;
    fn from_str(s: &str) -> Result<Subnet> {
        Subnet::parse(s)
    }
}

impl From<Subnet> for String {
    fn from(s: Subnet) -> String {
        s.to_string()
    }
}

impl TryFrom<String> for Subnet {
    type Error = Error;
    fn try_from(s: String) -> Result<Subnet> {
        Subnet::parse(&s)
    }
}

/// The first `/prefix_len` block of `pool` that overlaps nothing `taken`
/// says is taken (other networks' subnets, the host's routes).
pub fn free_subnet(pool: Subnet, prefix_len: u8, taken: impl Fn(&Subnet) -> bool) -> Option<Subnet> {
    if prefix_len < pool.prefix_len {
        return None;
    }
    let step = 1u64 << (32 - u32::from(prefix_len));
    let start = u64::from(u32::from(pool.network));
    let end = u64::from(u32::from(pool.broadcast()));
    (0..)
        .map(|i| start + i * step)
        .take_while(|&addr| addr <= end)
        .filter_map(|addr| Subnet::new(Ipv4Addr::from(addr as u32), prefix_len).ok())
        .find(|s| !taken(s))
}

/// Hands out container addresses in one subnet: the next free one after the
/// last it gave, wrapping around at the end, so a just-released address is
/// the last to be reused (a neighbour's stale ARP entry, a DNS answer cached
/// somewhere, have time to expire). After a daemon restart it starts from
/// the beginning again; only addresses in use matter.
#[derive(Debug, Clone)]
pub struct Allocator {
    subnet: Subnet,
    gateway: Ipv4Addr,
    last: Option<Ipv4Addr>,
}

impl Allocator {
    pub fn new(subnet: Subnet, gateway: Ipv4Addr) -> Allocator {
        Allocator { subnet, gateway, last: None }
    }

    /// A free address: not the gateway, the network or the broadcast
    /// address, and not one `in_use` says is taken. `None` when the subnet
    /// is full.
    pub fn allocate(&mut self, in_use: impl Fn(Ipv4Addr) -> bool) -> Option<Ipv4Addr> {
        let first = u32::from(self.subnet.first_host());
        let last = u32::from(self.subnet.last_host());
        let count = last - first + 1;
        let after = self.last.map(u32::from).filter(|&a| (first..=last).contains(&a)).map_or(first, |a| a + 1);
        for i in 0..count {
            let candidate = first + (after - first + i) % count;
            let ip = Ipv4Addr::from(candidate);
            if ip != self.gateway && !in_use(ip) {
                self.last = Some(ip);
                return Some(ip);
            }
        }
        None
    }
}

/// The MAC address a container's `eth0` gets for `ip`: `02:52:` and the
/// address's four bytes (locally administered, unicast), as Docker derives
/// `02:42:…`. An address that is reused comes back with the same MAC, so
/// the neighbours' ARP caches stay right.
pub fn mac_for(ip: Ipv4Addr) -> [u8; 6] {
    let [a, b, c, d] = ip.octets();
    [0x02, 0x52, a, b, c, d]
}

/// `02:52:0a:59:00:02`.
pub fn format_mac(mac: &[u8; 6]) -> String {
    mac.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(s: &str) -> Subnet {
        Subnet::parse(s).unwrap()
    }

    #[test]
    fn subnets_parse_and_measure() {
        let s = net("10.89.0.0/24");
        assert_eq!(s.to_string(), "10.89.0.0/24");
        assert_eq!(s.first_host(), Ipv4Addr::new(10, 89, 0, 1));
        assert_eq!(s.last_host(), Ipv4Addr::new(10, 89, 0, 254));
        assert_eq!(s.broadcast(), Ipv4Addr::new(10, 89, 0, 255));
        assert!(s.contains(Ipv4Addr::new(10, 89, 0, 200)) && !s.contains(Ipv4Addr::new(10, 89, 1, 1)));
        assert!(s.is_host(Ipv4Addr::new(10, 89, 0, 1)) && !s.is_host(Ipv4Addr::new(10, 89, 0, 255)));
        assert_eq!(net("10.89.0.0/16").broadcast(), Ipv4Addr::new(10, 89, 255, 255));
        for bad in ["10.89.0.0", "10.89.0.5/24", "10.89.0.0/31", "10.0.0.0/7", "10.89.0/24", "x/24", "10.89.0.0/x"] {
            assert!(Subnet::parse(bad).is_err(), "{bad}");
        }
        let e = Subnet::parse("10.89.0.5/24").unwrap_err().to_string();
        assert!(e.contains("did you mean 10.89.0.0/24"), "{e}");
        // A string in JSON.
        assert_eq!(serde_json::to_string(&s).unwrap(), r#""10.89.0.0/24""#);
        assert_eq!(serde_json::from_str::<Subnet>(r#""10.89.3.0/24""#).unwrap(), net("10.89.3.0/24"));
    }

    #[test]
    fn overlaps() {
        let pool = net("10.89.0.0/16");
        assert!(pool.overlaps(&net("10.89.7.0/24")) && net("10.89.7.0/24").overlaps(&pool));
        assert!(!net("10.89.0.0/24").overlaps(&net("10.89.1.0/24")));
        let lan = net("192.168.50.0/24");
        assert!(lan.overlaps_block(Ipv4Addr::new(192, 168, 0, 0), 16));
        assert!(lan.overlaps_block(Ipv4Addr::new(192, 168, 50, 128), 25));
        assert!(!lan.overlaps_block(Ipv4Addr::new(10, 0, 0, 0), 8));
        assert!(lan.overlaps_block(Ipv4Addr::UNSPECIFIED, 0), "a default route covers everything");
    }

    #[test]
    fn free_subnets_skip_whats_taken() {
        let pool = net("10.89.0.0/16");
        let taken = [net("10.89.0.0/24"), net("10.89.1.0/24"), net("10.89.3.0/24")];
        let next = free_subnet(pool, 24, |s| taken.iter().any(|t| t.overlaps(s)));
        assert_eq!(next, Some(net("10.89.2.0/24")));
        // A host route covering 10.89.2.0/23 takes 2 and 3 as well.
        let next = free_subnet(pool, 24, |s| {
            taken.iter().any(|t| t.overlaps(s)) || s.overlaps_block(Ipv4Addr::new(10, 89, 2, 0), 23)
        });
        assert_eq!(next, Some(net("10.89.4.0/24")));
        assert_eq!(free_subnet(pool, 24, |_| true), None);
        assert_eq!(free_subnet(net("10.89.0.0/24"), 16, |_| false), None, "bigger than the pool");
        assert_eq!(free_subnet(net("10.89.255.0/24"), 24, |_| false), Some(net("10.89.255.0/24")));
    }

    #[test]
    fn addresses_come_in_turn_and_wrap() {
        let s = net("10.89.0.0/29"); // hosts .1-.6; .1 is the gateway
        let mut a = Allocator::new(s, s.first_host());
        let mut used = std::collections::BTreeSet::new();
        let ip = |d| Ipv4Addr::new(10, 89, 0, d);
        for d in 2..=6 {
            let got = a.allocate(|x| used.contains(&x)).unwrap();
            assert_eq!(got, ip(d));
            used.insert(got);
        }
        assert_eq!(a.allocate(|x| used.contains(&x)), None, "full");
        // .3 is released: it comes back (it is the only one free).
        used.remove(&ip(3));
        assert_eq!(a.allocate(|x| used.contains(&x)), Some(ip(3)));
        // Release .2 and .5: the next is after the last given (.3), so .5.
        used.remove(&ip(2));
        used.remove(&ip(5));
        assert_eq!(a.allocate(|x| used.contains(&x)), Some(ip(5)));
        assert_eq!(a.allocate(|x| x == ip(5) || used.contains(&x)), Some(ip(2)), "wraps around");
        // A gateway that isn't the first address is skipped too.
        let mut b = Allocator::new(s, ip(2));
        assert_eq!(b.allocate(|_| false), Some(ip(1)));
        assert_eq!(b.allocate(|x| x == ip(1)), Some(ip(3)));
    }

    #[test]
    fn macs_follow_addresses() {
        let mac = mac_for(Ipv4Addr::new(10, 89, 0, 2));
        assert_eq!(format_mac(&mac), "02:52:0a:59:00:02");
        assert_eq!(mac[0] & 0b11, 0b10, "locally administered, unicast");
    }
}

//! IP address management: which subnets a network gets, which addresses a
//! container gets.
//!
//! Every network is an IPv4 subnet on a bridge. The default one is
//! `10.89.0.0/24`; a network created without `--subnet` gets the next
//! `/24` of the daemon's pool (`10.89.0.0/16`) that overlaps no other
//! network and no route the host already has (a VPN's, the LAN's). The
//! subnet's first address is the gateway, the bridge's own; containers get
//! the others, except the network and broadcast addresses.
//!
//! A network created with `--ipv6` has an IPv6 subnet as well ([`Subnet6`]):
//! the next free `/64` of the daemon's IPv6 pool unless one is given. The
//! pool is a block of **unique local addresses** (`fd00::/8`, RFC 4193):
//! private, like 10/8, and routed nowhere beyond the host, which NATs them
//! as it does the IPv4 ones. RFC 4193 wants the 40 bits after `fd` random,
//! so that two sites' blocks almost never collide; [`Subnet6::ula`] derives
//! them from a seed (the daemon uses the host's machine id), which keeps
//! them the same across restarts without being written down. An IPv6
//! subnet has no broadcast address; its first address (all host bits zero)
//! is the subnet-router anycast address, which no host may have, so the
//! gateway is the one after it again.
//!
//! This module only decides; it keeps nothing. Which addresses are in use
//! is the daemon's to know (it records each container's addresses with the
//! container), and it asks [`Allocator::allocate`] and
//! [`Allocator6::allocate`] with that knowledge.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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

/// An IPv6 subnet, `fd00:89:0:1::/64`: a network address with no host bits
/// set, and a prefix length from 8 to 126 (room for the gateway and a
/// container besides the subnet-router anycast address).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(into = "String", try_from = "String")]
pub struct Subnet6 {
    network: Ipv6Addr,
    prefix_len: u8,
}

impl Subnet6 {
    /// The subnet `network/prefix_len`; host bits must be zero.
    pub fn new(network: Ipv6Addr, prefix_len: u8) -> Result<Subnet6> {
        if !(8..=126).contains(&prefix_len) {
            return Err(Error::invalid(format!("{network}/{prefix_len}: the prefix length must be 8 to 126")));
        }
        let s = Subnet6 { network, prefix_len };
        if u128::from(network) & !s.mask() != 0 {
            let base = Ipv6Addr::from(u128::from(network) & s.mask());
            return Err(Error::invalid(format!(
                "{network}/{prefix_len} has host bits set: did you mean {base}/{prefix_len}?"
            )));
        }
        Ok(s)
    }

    /// Parses `fd00:89:0:1::/64`.
    pub fn parse(s: &str) -> Result<Subnet6> {
        let (addr, len) = s
            .split_once('/')
            .ok_or_else(|| Error::invalid(format!("{s:?} is not an IPv6 subnet (fd00:89:0:5::/64)")))?;
        let addr =
            addr.parse::<Ipv6Addr>().map_err(|_| Error::invalid(format!("{s:?}: {addr:?} is not an IPv6 address")))?;
        let len = len.parse::<u8>().map_err(|_| Error::invalid(format!("{s:?}: {len:?} is not a prefix length")))?;
        Subnet6::new(addr, len)
    }

    /// A `/48` of unique local addresses: `fd` and 40 bits of the seed's
    /// SHA-256 (RFC 4193's "pseudo-random Global ID"; the seed makes it
    /// the same on every start).
    pub fn ula(seed: &[u8]) -> Subnet6 {
        let digest = Sha256::digest(seed);
        let mut octets = [0u8; 16];
        octets[0] = 0xfd;
        octets[1..6].copy_from_slice(&digest[..5]);
        Subnet6 { network: Ipv6Addr::from(octets), prefix_len: 48 }
    }

    pub fn network(&self) -> Ipv6Addr {
        self.network
    }

    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    fn mask(&self) -> u128 {
        u128::MAX << (128 - u32::from(self.prefix_len))
    }

    /// The first address after the subnet-router anycast one: the default
    /// gateway.
    pub fn first_host(&self) -> Ipv6Addr {
        Ipv6Addr::from(u128::from(self.network) + 1)
    }

    /// The subnet's last address (IPv6 has no broadcast address).
    pub fn last_host(&self) -> Ipv6Addr {
        Ipv6Addr::from(u128::from(self.network) | !self.mask())
    }

    pub fn contains(&self, ip: Ipv6Addr) -> bool {
        u128::from(ip) & self.mask() == u128::from(self.network)
    }

    /// Does `other` share an address with this subnet?
    pub fn overlaps(&self, other: &Subnet6) -> bool {
        self.contains(other.network) || other.contains(self.network)
    }

    /// Does this subnet share an address with the block `addr/prefix_len`
    /// (a route's destination, `/0` included)?
    pub fn overlaps_block(&self, addr: Ipv6Addr, prefix_len: u8) -> bool {
        let len = prefix_len.min(self.prefix_len);
        let mask = if len == 0 { 0 } else { u128::MAX << (128 - u32::from(len)) };
        u128::from(addr) & mask == u128::from(self.network) & mask
    }

    /// An address of the subnet that a container (or the gateway) may have:
    /// not the subnet-router anycast address.
    pub fn is_host(&self, ip: Ipv6Addr) -> bool {
        self.contains(ip) && ip != self.network
    }
}

impl fmt::Display for Subnet6 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix_len)
    }
}

impl FromStr for Subnet6 {
    type Err = Error;
    fn from_str(s: &str) -> Result<Subnet6> {
        Subnet6::parse(s)
    }
}

impl From<Subnet6> for String {
    fn from(s: Subnet6) -> String {
        s.to_string()
    }
}

impl TryFrom<String> for Subnet6 {
    type Error = Error;
    fn try_from(s: String) -> Result<Subnet6> {
        Subnet6::parse(&s)
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

/// [`free_subnet`] for IPv6: the first free `/prefix_len` (`/64`) of
/// `pool`, among its first [`MAX_STEPS`] blocks.
pub fn free_subnet6(pool: Subnet6, prefix_len: u8, taken: impl Fn(&Subnet6) -> bool) -> Option<Subnet6> {
    if prefix_len < pool.prefix_len || prefix_len > 126 {
        return None;
    }
    let step = 1u128 << (128 - u32::from(prefix_len));
    let blocks = 1u128.checked_shl(u32::from(prefix_len - pool.prefix_len)).unwrap_or(u128::MAX);
    let start = u128::from(pool.network);
    (0..blocks.min(u128::from(MAX_STEPS)))
        .filter_map(|i| Subnet6::new(Ipv6Addr::from(start + i * step), prefix_len).ok())
        .find(|s| !taken(s))
}

/// The most candidates one search looks at: every address of a `/8`, every
/// `/64` of a `/40`. Allocations stop well before this in practice (the
/// first free one is at most one past the addresses in use), but a search
/// in a subnet with 2^64 addresses must end even if a bug says that every
/// one is taken.
pub const MAX_STEPS: u32 = 1 << 24;

/// The next address of `first..=last` after `after` (from `first` if none,
/// wrapping around at `last`) that `usable` accepts, among at most
/// [`MAX_STEPS`] candidates.
fn next_usable(first: u128, last: u128, after: Option<u128>, usable: impl Fn(u128) -> bool) -> Option<u128> {
    let count = (last - first).saturating_add(1);
    let start = match after.filter(|a| (first..=last).contains(a)) {
        Some(a) if a < last => a + 1,
        _ => first,
    };
    (0..count.min(u128::from(MAX_STEPS)))
        .map(|i| first + (start - first + i) % count)
        .find(|&candidate| usable(candidate))
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
        let (first, last) = (u32::from(self.subnet.first_host()), u32::from(self.subnet.last_host()));
        let ip = next_usable(first.into(), last.into(), self.last.map(|a| u32::from(a).into()), |c| {
            let ip = Ipv4Addr::from(c as u32);
            ip != self.gateway && !in_use(ip)
        })
        .map(|c| Ipv4Addr::from(c as u32))?;
        self.last = Some(ip);
        Some(ip)
    }
}

/// [`Allocator`] for an IPv6 subnet: the next free address after the last
/// one given, never the subnet-router anycast address or the gateway.
#[derive(Debug, Clone)]
pub struct Allocator6 {
    subnet: Subnet6,
    gateway: Ipv6Addr,
    last: Option<Ipv6Addr>,
}

impl Allocator6 {
    pub fn new(subnet: Subnet6, gateway: Ipv6Addr) -> Allocator6 {
        Allocator6 { subnet, gateway, last: None }
    }

    /// A free address, or `None` when the subnet is full.
    pub fn allocate(&mut self, in_use: impl Fn(Ipv6Addr) -> bool) -> Option<Ipv6Addr> {
        let (first, last) = (u128::from(self.subnet.first_host()), u128::from(self.subnet.last_host()));
        let ip = next_usable(first, last, self.last.map(u128::from), |c| {
            let ip = Ipv6Addr::from(c);
            ip != self.gateway && !in_use(ip)
        })
        .map(Ipv6Addr::from)?;
        self.last = Some(ip);
        Some(ip)
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

    fn net6(s: &str) -> Subnet6 {
        Subnet6::parse(s).unwrap()
    }

    #[test]
    fn ipv6_subnets_parse_and_measure() {
        let s = net6("fd00:89:0:1::/64");
        assert_eq!(s.to_string(), "fd00:89:0:1::/64");
        assert_eq!(s.first_host(), "fd00:89:0:1::1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(s.last_host(), "fd00:89:0:1:ffff:ffff:ffff:ffff".parse::<Ipv6Addr>().unwrap());
        assert!(s.contains("fd00:89:0:1::abcd".parse().unwrap()) && !s.contains("fd00:89:0:2::1".parse().unwrap()));
        assert!(!s.is_host(s.network()), "the subnet-router anycast address");
        assert!(s.is_host(s.first_host()));
        for bad in ["fd00::", "fd00::1/64", "fd00::/127", "fd00::/7", "x/64", "10.0.0.0/8", "fd00::/x"] {
            assert!(Subnet6::parse(bad).is_err(), "{bad}");
        }
        let e = Subnet6::parse("fd00:89::5/64").unwrap_err().to_string();
        assert!(e.contains("did you mean fd00:89::/64"), "{e}");
        assert_eq!(serde_json::to_string(&s).unwrap(), r#""fd00:89:0:1::/64""#);
        assert_eq!(serde_json::from_str::<Subnet6>(r#""fd00::/48""#).unwrap(), net6("fd00::/48"));
        let lan = net6("fd4b:a90d:1d5c:63::/64");
        assert!(lan.overlaps_block("fd4b:a90d:1d5c::".parse().unwrap(), 48));
        assert!(!lan.overlaps_block("fd33:3b76:8cb2:1::".parse().unwrap(), 64));
        assert!(lan.overlaps_block(Ipv6Addr::UNSPECIFIED, 0), "a default route covers everything");
        assert!(net6("fd00::/48").overlaps(&net6("fd00:0:0:7::/64")));
    }

    #[test]
    fn ula_pools_are_stable_unique_local_48s() {
        let a = Subnet6::ula(b"machine-a");
        assert_eq!(a, Subnet6::ula(b"machine-a"), "the same seed, the same pool");
        assert_ne!(a, Subnet6::ula(b"machine-b"));
        assert_eq!(a.prefix_len(), 48);
        assert_eq!(a.network().octets()[0], 0xfd, "fd00::/8, locally assigned");
        assert_eq!(&a.network().octets()[6..], &[0; 10], "a /48");
    }

    #[test]
    fn free_ipv6_subnets_skip_whats_taken() {
        let pool = net6("fd00:89::/48");
        let taken = [net6("fd00:89::/64"), net6("fd00:89:0:1::/64")];
        let next = free_subnet6(pool, 64, |s| taken.iter().any(|t| t.overlaps(s)));
        assert_eq!(next, Some(net6("fd00:89:0:2::/64")));
        // A host route to fd00:89:0:2::/63 takes 2 and 3.
        let next = free_subnet6(pool, 64, |s| {
            taken.iter().any(|t| t.overlaps(s)) || s.overlaps_block("fd00:89:0:2::".parse().unwrap(), 63)
        });
        assert_eq!(next, Some(net6("fd00:89:0:4::/64")));
        assert_eq!(free_subnet6(net6("fd00:89::/62"), 64, |_| true), None, "four blocks, all taken");
        assert_eq!(free_subnet6(net6("fd00:89::/64"), 48, |_| false), None, "bigger than the pool");
        // A huge pool is searched only so far, and still ends.
        assert_eq!(free_subnet6(net6("fd00::/8"), 64, |_| true), None);
    }

    #[test]
    fn ipv6_addresses_come_in_turn_skipping_the_gateway() {
        let s = net6("fd00:89::/125"); // ::1-::7; ::1 is the gateway
        let mut a = Allocator6::new(s, s.first_host());
        let ip = |n: u16| Ipv6Addr::new(0xfd00, 0x89, 0, 0, 0, 0, 0, n);
        let mut used = std::collections::BTreeSet::new();
        for n in 2..=7 {
            let got = a.allocate(|x| used.contains(&x)).unwrap();
            assert_eq!(got, ip(n));
            used.insert(got);
        }
        assert_eq!(a.allocate(|x| used.contains(&x)), None, "full");
        used.remove(&ip(4));
        assert_eq!(a.allocate(|x| used.contains(&x)), Some(ip(4)));
        // In a /64, the next after the last.
        let big = net6("fd00:89:0:1::/64");
        let mut b = Allocator6::new(big, big.first_host());
        assert_eq!(b.allocate(|_| false), Some("fd00:89:0:1::2".parse().unwrap()));
        assert_eq!(b.allocate(|_| false), Some("fd00:89:0:1::3".parse().unwrap()));
        // Everything "taken" still ends, with nothing.
        assert_eq!(b.allocate(|_| true), None);
    }
}

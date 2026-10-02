//! Bridges and veth pairs, over the hand-written rtnetlink codec in
//! `rustlet_sys::netlink`.
//!
//! ```text
//!  host netns                                   container netns
//!   rustlet0 (bridge, 10.89.0.1/24, up)
//!     └── rlv<hash> (veth, up) ═══ veth ═══════ eth0 (10.89.0.2/24, 02:52:0a:59:00:02, up)
//!   rlb… (bridge, 10.89.1.1/24, fd…:1::1/64)                default via 10.89.0.1
//!     └── rlv<hash> (veth, up) ═══ veth ═══════ eth1 (10.89.1.2/24, fd…:1::2/64)
//!                                                default via fd…:1::1 (IPv6)
//! ```
//!
//! A veth pair is two network interfaces joined back to back: what one end
//! sends, the other receives. One end stays on the host, attached to the
//! bridge (a software switch); the other is created directly *inside* the
//! container's namespace, already named `eth0` (or `eth1`, … for its
//! further networks; one `RTM_NEWLINK` with `IFLA_NET_NS_FD` in the peer's
//! attributes), so no stray `eth0` ever appears on the host. Deleting
//! either end deletes both, and destroying a namespace destroys the ends
//! inside it.
//!
//! The host's end is tagged with an alias (`IFLA_IFALIAS`, `ip link show`
//! prints it) naming the container and the network. An end left by an
//! earlier run of the same container on the same network is recognised by
//! it and replaced; a link that merely has the same name is never touched.
//!
//! Default routes are set apart from the interfaces
//! ([`set_default_routes`]): a container on several networks has one
//! default route per family, through the network the daemon picks, and it
//! moves when that network is disconnected.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::BorrowedFd;

use rustlet_sys::Errno;
use rustlet_sys::netlink::{RtNetlink, VethPeer};

use crate::error::{Context, Error, Result};
use crate::{netns, sysctl};

/// The name of a container's `n`th interface (`eth0`, `eth1`, …).
pub fn container_ifname(n: usize) -> String {
    format!("eth{n}")
}

/// The host's end of a container's veth pair on a network: `rlv` and 12
/// hex digits of SHA-256 of the two ids, 15 characters (the most an
/// interface name has). The same container on the same network always gets
/// the same name, so it can be found again; [`endpoint_alias`] says whose
/// it is.
pub fn host_ifname(container_id: &str, network_id: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(format!("{container_id}/{network_id}"));
    let hex: String = digest.iter().take(6).map(|b| format!("{b:02x}")).collect();
    format!("rlv{hex}")
}

/// The alias that tags the host's end of a container's veth pair on a
/// network: `rustlet <container id> <network id>`. [`container_tag`] is
/// its start, shared by all of a container's.
pub fn endpoint_alias(container_id: &str, network_id: &str) -> String {
    format!("{} {network_id}", container_tag(container_id))
}

/// What every alias of a container's veths starts with.
pub fn container_tag(container_id: &str) -> String {
    format!("rustlet {container_id}")
}

/// A container's place on a bridge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Endpoint<'a> {
    /// The host's end of the veth pair (`rlv…`).
    pub host_ifname: &'a str,
    /// The host end's alias: who it belongs to. A link named `host_ifname`
    /// with this alias is a leftover of the same container on the same
    /// network, and is replaced; without it, it isn't ours.
    pub alias: &'a str,
    /// The container's end (`eth0`, `eth1`, …).
    pub ifname: &'a str,
    pub bridge: &'a str,
    pub address: Ipv4Addr,
    pub prefix_len: u8,
    /// Its IPv6 address and prefix length, on a network with IPv6.
    pub address6: Option<(Ipv6Addr, u8)>,
    pub mac: [u8; 6],
}

fn netlink() -> Result<RtNetlink> {
    RtNetlink::open().context("open an rtnetlink socket")
}

/// Makes sure the bridge `name` exists in the caller's network namespace,
/// with `gateway/prefix_len` (and `gateway6`, on a network with IPv6) and
/// up (`ip link add NAME type bridge`, `ip addr add`, `ip link set up`):
/// creates whatever is missing, so it is safe to call at every daemon
/// start. IPv6 is turned off on it before the link-local address would
/// appear, unless the network has IPv6; then router advertisements arriving
/// on it are ignored (a container could send one), and its address is
/// usable at once (no duplicate address detection: the bridge is ours).
pub fn ensure_bridge(name: &str, gateway: Ipv4Addr, prefix_len: u8, gateway6: Option<(Ipv6Addr, u8)>) -> Result<i32> {
    let mut nl = netlink()?;
    let link = match nl.link_by_name(name).with_context(|| format!("look up {name}"))? {
        Some(l) => l,
        None => {
            match nl.create_bridge(name) {
                Ok(()) | Err(Errno::EEXIST) => {}
                Err(e) => return Err(e).with_context(|| format!("create the bridge {name}")),
            }
            nl.link_by_name(name)
                .with_context(|| format!("look up {name}"))?
                .ok_or_else(|| Error::invalid(format!("the bridge {name} vanished as it was created")))?
        }
    };
    if link.kind.as_deref() != Some("bridge") {
        return Err(Error::invalid(format!(
            "{name} exists and is not a bridge ({}): remove it, or configure another bridge name",
            link.kind.as_deref().unwrap_or("no kind")
        )));
    }
    let addresses = nl.addresses().context("list addresses")?;
    let has = |ip: IpAddr, len: u8| {
        addresses.iter().any(|a| a.index == link.index as u32 && a.address == ip && a.prefix_len == len)
    };
    match gateway6 {
        Some((gw6, len6)) => {
            if !sysctl::ipv6_available() {
                return Err(Error::invalid(format!("{name}: the kernel has no IPv6 (ipv6.disable=1?)")));
            }
            sysctl::enable_ipv6(name)?;
            if !has(gw6.into(), len6) {
                match nl.add_address6(link.index, gw6, len6, true) {
                    Ok(()) | Err(Errno::EEXIST) => {}
                    Err(e) => return Err(e).with_context(|| format!("add {gw6}/{len6} to {name}")),
                }
            }
        }
        None => sysctl::disable_ipv6(name)?,
    }
    if !has(gateway.into(), prefix_len) {
        match nl.add_address(link.index, gateway, prefix_len) {
            Ok(()) | Err(Errno::EEXIST) => {}
            Err(e) => return Err(e).with_context(|| format!("add {gateway}/{prefix_len} to {name}")),
        }
    }
    nl.set_link_up(link.index).with_context(|| format!("bring {name} up"))?;
    Ok(link.index)
}

/// Deletes the link `name` in the caller's network namespace; `false` if
/// there was none.
pub fn delete_link(name: &str) -> Result<bool> {
    let mut nl = netlink()?;
    let Some(link) = nl.link_by_name(name).with_context(|| format!("look up {name}"))? else {
        return Ok(false);
    };
    match nl.delete_link(link.index) {
        Ok(()) => Ok(true),
        // Gone meanwhile (its namespace went away).
        Err(Errno::ENODEV) => Ok(false),
        Err(e) => Err(e).with_context(|| format!("delete {name}")),
    }
}

/// The links of the caller's namespace whose alias is `alias` or starts
/// with `alias` and a space: what a container left, by its tag.
pub fn links_tagged(alias: &str) -> Result<Vec<String>> {
    let mut nl = netlink()?;
    Ok(nl
        .links()
        .context("list links")?
        .into_iter()
        .filter(|l| {
            l.alias.as_deref().is_some_and(|a| a == alias || a.strip_prefix(alias).is_some_and(|r| r.starts_with(' ')))
        })
        .map(|l| l.name)
        .collect())
}

/// Connects the network namespace `ns` to a bridge of the caller's: a veth
/// pair with the host's end on the bridge, and `ep.ifname` inside with its
/// addresses and MAC (no routes but the subnets' own: see
/// [`set_default_routes`]). A host end of the same name and alias, left by
/// an earlier run, is deleted first. If anything fails after the pair
/// exists, it is deleted again.
pub fn attach(ns: BorrowedFd<'_>, ep: &Endpoint<'_>) -> Result<()> {
    let mut nl = netlink()?;
    let bridge = nl
        .link_by_name(ep.bridge)
        .with_context(|| format!("look up {}", ep.bridge))?
        .ok_or_else(|| Error::invalid(format!("the bridge {} doesn't exist", ep.bridge)))?;
    if let Some(old) = nl.link_by_name(ep.host_ifname).with_context(|| format!("look up {}", ep.host_ifname))? {
        if old.alias.as_deref() != Some(ep.alias) {
            return Err(Error::invalid(format!(
                "a link named {} exists and isn't this container's ({}): not touching it",
                ep.host_ifname,
                old.alias.as_deref().map_or("no alias".to_owned(), |a| format!("alias {a:?}"))
            )));
        }
        delete_link(ep.host_ifname)?;
        tracing::info!("deleted a leftover {}", ep.host_ifname);
    }
    let peer = VethPeer { name: ep.ifname, netns: Some(ns), mac: Some(ep.mac) };
    nl.create_veth(ep.host_ifname, &peer).with_context(|| format!("create the veth pair {}", ep.host_ifname))?;
    let configured = (|| {
        let host = nl
            .link_by_name(ep.host_ifname)
            .with_context(|| format!("look up {}", ep.host_ifname))?
            .ok_or_else(|| Error::invalid(format!("{} vanished as it was created", ep.host_ifname)))?;
        nl.set_alias(host.index, ep.alias).with_context(|| format!("tag {}", ep.host_ifname))?;
        sysctl::disable_ipv6(ep.host_ifname)?;
        nl.set_master(host.index, bridge.index)
            .with_context(|| format!("attach {} to {}", ep.host_ifname, ep.bridge))?;
        nl.set_link_up(host.index).with_context(|| format!("bring {} up", ep.host_ifname))?;
        netns::run_in(ns, || configure_inside(ep))
    })();
    if configured.is_err() {
        let _ = delete_link(ep.host_ifname);
    }
    configured
}

/// Inside the container's namespace: the interface's addresses (IPv6 first,
/// so that it is on before the link comes up), then up.
fn configure_inside(ep: &Endpoint<'_>) -> Result<()> {
    let mut nl = netlink()?;
    let link = nl
        .link_by_name(ep.ifname)
        .with_context(|| format!("look up {}", ep.ifname))?
        .ok_or_else(|| Error::invalid(format!("{} didn't appear in the container's network namespace", ep.ifname)))?;
    match ep.address6 {
        Some((ip, len)) => {
            sysctl::enable_ipv6(ep.ifname)?;
            nl.add_address6(link.index, ip, len, true).with_context(|| format!("add {ip}/{len} to {}", ep.ifname))?;
        }
        None => sysctl::disable_ipv6(ep.ifname)?,
    }
    nl.add_address(link.index, ep.address, ep.prefix_len)
        .with_context(|| format!("add {}/{} to {}", ep.address, ep.prefix_len, ep.ifname))?;
    nl.set_link_up(link.index).with_context(|| format!("bring {} up", ep.ifname))?;
    Ok(())
}

/// Sets the namespace `ns`'s default routes: IPv4 through `v4` (a gateway
/// and the interface it is on), IPv6 through `v6`; `None` removes that
/// family's default route (no network with a way out). A route already
/// there is replaced, so this is what follows every change to the
/// container's networks.
pub fn set_default_routes(
    ns: BorrowedFd<'_>,
    v4: Option<(Ipv4Addr, &str)>,
    v6: Option<(Ipv6Addr, &str)>,
) -> Result<()> {
    netns::run_in(ns, || {
        let mut nl = netlink()?;
        set_default(&mut nl, Ipv4Addr::UNSPECIFIED.into(), v4.map(|(gw, i)| (gw.into(), i)))?;
        if sysctl::ipv6_available() {
            set_default(&mut nl, Ipv6Addr::UNSPECIFIED.into(), v6.map(|(gw, i)| (gw.into(), i)))?;
        }
        Ok(())
    })
}

fn set_default(nl: &mut RtNetlink, any: IpAddr, via: Option<(IpAddr, &str)>) -> Result<()> {
    match via {
        Some((gw, ifname)) => {
            let link = nl
                .link_by_name(ifname)
                .with_context(|| format!("look up {ifname}"))?
                .ok_or_else(|| Error::invalid(format!("no {ifname} for the default route via {gw}")))?;
            nl.replace_route(any, 0, Some(gw), Some(link.index))
                .with_context(|| format!("route by default via {gw} on {ifname}"))
        }
        // None there: ESRCH for IPv4, ENOENT for IPv6.
        None => match nl.delete_route(any, 0) {
            Ok(()) | Err(Errno::ESRCH | Errno::ENOENT) => Ok(()),
            Err(e) => Err(e).with_context(|| format!("remove the default route ({any}/0)")),
        },
    }
}

/// Brings `lo` up in the caller's network namespace (a new namespace's
/// loopback starts down).
pub fn loopback_up() -> Result<()> {
    let mut nl = netlink()?;
    let lo = nl.link_by_name("lo").context("look up lo")?.ok_or_else(|| Error::invalid("no lo"))?;
    nl.set_link_up(lo.index).context("bring lo up")
}

/// The routes of the caller's namespace's main table, as `(destination,
/// prefix length)`, IPv4 and IPv6: what a new network's subnets must not
/// overlap. Default routes are left out (they overlap everything).
pub fn routed_blocks() -> Result<Vec<(IpAddr, u8)>> {
    let mut nl = netlink()?;
    Ok(nl
        .routes()
        .context("list routes")?
        .into_iter()
        .filter(|r| r.table == u32::from(rustlet_sys::netlink::consts::RT_TABLE_MAIN) && r.dst_len > 0)
        .map(|r| (r.dst, r.dst_len))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interface_names() {
        assert_eq!(container_ifname(0), "eth0");
        assert_eq!(container_ifname(12), "eth12");
        let (c, n) = ("c".repeat(64), "n".repeat(64));
        let name = host_ifname(&c, &n);
        assert_eq!(name.len(), 15, "IFNAMSIZ - 1");
        assert!(name.starts_with("rlv") && name[3..].chars().all(|ch| ch.is_ascii_hexdigit()), "{name}");
        assert_eq!(name, host_ifname(&c, &n), "the same pair, the same name");
        assert_ne!(name, host_ifname(&c, &"m".repeat(64)), "another network, another name");
        assert_eq!(endpoint_alias("abc", "def"), "rustlet abc def");
        assert!(endpoint_alias("abc", "def").starts_with(&format!("{} ", container_tag("abc"))));
    }

    #[test]
    fn routed_blocks_have_no_default_route() {
        // Readable by anyone: the host's own routes.
        let blocks = routed_blocks().unwrap();
        assert!(blocks.iter().all(|(_, len)| *len > 0), "{blocks:?}");
    }
}

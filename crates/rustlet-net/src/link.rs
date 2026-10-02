//! Bridges and veth pairs, over the hand-written rtnetlink codec in
//! `rustlet_sys::netlink`.
//!
//! ```text
//!  host netns                                   container netns
//!   rustlet0 (bridge, 10.89.0.1/24, up)
//!     └── rlv<short id> (veth, up) ═══ veth ═══ eth0 (10.89.0.2/24, 02:52:0a:59:00:02, up)
//!                                                default via 10.89.0.1
//! ```
//!
//! A veth pair is two network interfaces joined back to back: what one end
//! sends, the other receives. One end stays on the host, attached to the
//! bridge (a software switch); the other is created directly *inside* the
//! container's namespace, already named `eth0` (one `RTM_NEWLINK` with
//! `IFLA_NET_NS_FD` in the peer's attributes), so no stray `eth0` ever
//! appears on the host. Deleting either end deletes both, and destroying a
//! namespace destroys the ends inside it.

use std::net::Ipv4Addr;
use std::os::fd::BorrowedFd;

use rustlet_sys::Errno;
use rustlet_sys::netlink::{RtNetlink, VethPeer};

use crate::error::{Context, Error, Result};
use crate::{netns, sysctl};

/// The container's end of its veth pair.
pub const CONTAINER_IFNAME: &str = "eth0";

/// A container's place on a bridge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Endpoint<'a> {
    /// The host's end of the veth pair (`rlv<short id>`).
    pub host_ifname: &'a str,
    pub bridge: &'a str,
    pub address: Ipv4Addr,
    pub prefix_len: u8,
    /// The default route; `None` on an internal network (no way out).
    pub gateway: Option<Ipv4Addr>,
    pub mac: [u8; 6],
}

fn netlink() -> Result<RtNetlink> {
    RtNetlink::open().context("open an rtnetlink socket")
}

/// Makes sure the bridge `name` exists in the caller's network namespace,
/// with `gateway/prefix_len` and up (`ip link add NAME type bridge`, `ip
/// addr add`, `ip link set up`): creates whatever is missing, so it is safe
/// to call at every daemon start. IPv6 is turned off on it first, before
/// the link-local address would appear.
pub fn ensure_bridge(name: &str, gateway: Ipv4Addr, prefix_len: u8) -> Result<i32> {
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
    sysctl::disable_ipv6(name)?;
    let has = nl
        .addresses()
        .context("list addresses")?
        .iter()
        .any(|a| a.index == link.index as u32 && a.address == gateway && a.prefix_len == prefix_len);
    if !has {
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

/// Connects the network namespace `ns` to a bridge of the caller's: a veth
/// pair with the host's end on the bridge, and `eth0` inside with its
/// address, MAC and default route. A host end of the same name left by an
/// earlier run is deleted first. If anything fails after the pair exists,
/// it is deleted again.
pub fn attach(ns: BorrowedFd<'_>, ep: &Endpoint<'_>) -> Result<()> {
    let mut nl = netlink()?;
    let bridge = nl
        .link_by_name(ep.bridge)
        .with_context(|| format!("look up {}", ep.bridge))?
        .ok_or_else(|| Error::invalid(format!("the bridge {} doesn't exist", ep.bridge)))?;
    if delete_link(ep.host_ifname)? {
        tracing::info!("deleted a leftover {}", ep.host_ifname);
    }
    let peer = VethPeer { name: CONTAINER_IFNAME, netns: Some(ns), mac: Some(ep.mac) };
    nl.create_veth(ep.host_ifname, &peer).with_context(|| format!("create the veth pair {}", ep.host_ifname))?;
    let configured = (|| {
        let host = nl
            .link_by_name(ep.host_ifname)
            .with_context(|| format!("look up {}", ep.host_ifname))?
            .ok_or_else(|| Error::invalid(format!("{} vanished as it was created", ep.host_ifname)))?;
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

/// Inside the container's namespace: `eth0`'s address, up, the default
/// route.
fn configure_inside(ep: &Endpoint<'_>) -> Result<()> {
    let mut nl = netlink()?;
    let eth0 = nl
        .link_by_name(CONTAINER_IFNAME)
        .context("look up eth0")?
        .ok_or_else(|| Error::invalid("eth0 didn't appear in the container's network namespace"))?;
    sysctl::disable_ipv6(CONTAINER_IFNAME)?;
    nl.add_address(eth0.index, ep.address, ep.prefix_len)
        .with_context(|| format!("add {}/{} to eth0", ep.address, ep.prefix_len))?;
    nl.set_link_up(eth0.index).context("bring eth0 up")?;
    if let Some(gw) = ep.gateway {
        nl.add_route(Ipv4Addr::UNSPECIFIED, 0, Some(gw), Some(eth0.index))
            .with_context(|| format!("add the default route via {gw}"))?;
    }
    Ok(())
}

/// Brings `lo` up in the caller's network namespace (a new namespace's
/// loopback starts down).
pub fn loopback_up() -> Result<()> {
    let mut nl = netlink()?;
    let lo = nl.link_by_name("lo").context("look up lo")?.ok_or_else(|| Error::invalid("no lo"))?;
    nl.set_link_up(lo.index).context("bring lo up")
}

/// The IPv4 routes of the caller's namespace's main table, as
/// `(destination, prefix length)`: what a new network's subnet must not
/// overlap. The default route is left out (it overlaps everything).
pub fn routed_blocks() -> Result<Vec<(Ipv4Addr, u8)>> {
    let mut nl = netlink()?;
    Ok(nl
        .routes()
        .context("list routes")?
        .into_iter()
        .filter(|r| r.table == u32::from(rustlet_sys::netlink::consts::RT_TABLE_MAIN) && r.dst_len > 0)
        .map(|r| (r.dst, r.dst_len))
        .collect())
}

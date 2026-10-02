//! The seam between the daemon and the host's network: what it takes to
//! give a container namespace a place on a network, and to publish ports.
//!
//! [`Bridge`] is the rootful way (docs/architecture.md §2.5): Linux bridges,
//! veth pairs, nftables. Rootless mode (Phase 8) can't create interfaces on
//! the host at all, and will plug in `pasta` instead, which forwards a
//! namespace's traffic through sockets of an unprivileged process; the
//! daemon only ever talks to a [`NetworkBackend`].

use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::BorrowedFd;

use crate::error::Result;
use crate::firewall::Ruleset;
use crate::link::{self, Endpoint};

/// The host's side of networking, in the caller's network namespace. Every
/// method blocks (netlink, `nft`): call it off the async threads.
pub trait NetworkBackend: Send + Sync {
    /// Makes sure a network's host side exists (for [`Bridge`], the bridge
    /// with its gateway addresses, IPv4 and, on a network with IPv6, IPv6;
    /// up). Idempotent.
    fn ensure_network(
        &self,
        bridge: &str,
        gateway: Ipv4Addr,
        prefix_len: u8,
        gateway6: Option<(Ipv6Addr, u8)>,
    ) -> Result<()>;
    /// Removes a network's host side; nothing to do is fine.
    fn remove_network(&self, bridge: &str) -> Result<()>;
    /// Gives the namespace `ns` its place on a network.
    fn connect(&self, ns: BorrowedFd<'_>, endpoint: &Endpoint<'_>) -> Result<()>;
    /// Undoes [`NetworkBackend::connect`] (by the host end's name); nothing
    /// to do is fine.
    fn disconnect(&self, host_ifname: &str) -> Result<()>;
    /// Undoes every [`NetworkBackend::connect`] whose endpoint alias starts
    /// with `tag` (all of one container's, [`link::container_tag`]): what a
    /// run cut short left without a record.
    fn disconnect_tagged(&self, tag: &str) -> Result<()>;
    /// Points the namespace `ns`'s default routes (IPv4, IPv6) at a gateway
    /// on one of its interfaces, or removes them (`None`).
    fn set_default_routes(
        &self,
        ns: BorrowedFd<'_>,
        v4: Option<(Ipv4Addr, &str)>,
        v6: Option<(Ipv6Addr, &str)>,
    ) -> Result<()>;
    /// Puts the firewall (NAT, published ports, guards) in the state
    /// `rules` describes, replacing whatever was there.
    fn apply(&self, rules: &Ruleset) -> Result<()>;
}

/// Bridges, veth pairs and nftables.
#[derive(Debug, Default, Clone, Copy)]
pub struct Bridge;

impl NetworkBackend for Bridge {
    fn ensure_network(
        &self,
        bridge: &str,
        gateway: Ipv4Addr,
        prefix_len: u8,
        gateway6: Option<(Ipv6Addr, u8)>,
    ) -> Result<()> {
        link::ensure_bridge(bridge, gateway, prefix_len, gateway6).map(drop)
    }

    fn remove_network(&self, bridge: &str) -> Result<()> {
        link::delete_link(bridge).map(drop)
    }

    fn connect(&self, ns: BorrowedFd<'_>, endpoint: &Endpoint<'_>) -> Result<()> {
        link::attach(ns, endpoint)
    }

    fn disconnect(&self, host_ifname: &str) -> Result<()> {
        link::delete_link(host_ifname).map(drop)
    }

    fn disconnect_tagged(&self, tag: &str) -> Result<()> {
        for name in link::links_tagged(tag)? {
            link::delete_link(&name)?;
        }
        Ok(())
    }

    fn set_default_routes(
        &self,
        ns: BorrowedFd<'_>,
        v4: Option<(Ipv4Addr, &str)>,
        v6: Option<(Ipv6Addr, &str)>,
    ) -> Result<()> {
        link::set_default_routes(ns, v4, v6)
    }

    fn apply(&self, rules: &Ruleset) -> Result<()> {
        rules.apply()
    }
}

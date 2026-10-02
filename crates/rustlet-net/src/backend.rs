//! The seam between the daemon and the host's network: what it takes to
//! give a container namespace a place on a network, and to publish ports.
//!
//! [`Bridge`] is the rootful way (docs/architecture.md §2.5): Linux bridges,
//! veth pairs, nftables. Rootless mode (Phase 8) can't create interfaces on
//! the host at all, and will plug in `pasta` instead, which forwards a
//! namespace's traffic through sockets of an unprivileged process; the
//! daemon only ever talks to a [`NetworkBackend`].

use std::net::Ipv4Addr;
use std::os::fd::BorrowedFd;

use crate::error::Result;
use crate::firewall::Ruleset;
use crate::link::{self, Endpoint};

/// The host's side of networking, in the caller's network namespace. Every
/// method blocks (netlink, `nft`): call it off the async threads.
pub trait NetworkBackend: Send + Sync {
    /// Makes sure a network's host side exists (for [`Bridge`], the bridge
    /// with its gateway address, up). Idempotent.
    fn ensure_network(&self, bridge: &str, gateway: Ipv4Addr, prefix_len: u8) -> Result<()>;
    /// Removes a network's host side; nothing to do is fine.
    fn remove_network(&self, bridge: &str) -> Result<()>;
    /// Gives the namespace `ns` its place on a network.
    fn connect(&self, ns: BorrowedFd<'_>, endpoint: &Endpoint<'_>) -> Result<()>;
    /// Undoes [`NetworkBackend::connect`] (by the host end's name); nothing
    /// to do is fine.
    fn disconnect(&self, host_ifname: &str) -> Result<()>;
    /// Puts the firewall (NAT, published ports, guards) in the state
    /// `rules` describes, replacing whatever was there.
    fn apply(&self, rules: &Ruleset) -> Result<()>;
}

/// Bridges, veth pairs and nftables.
#[derive(Debug, Default, Clone, Copy)]
pub struct Bridge;

impl NetworkBackend for Bridge {
    fn ensure_network(&self, bridge: &str, gateway: Ipv4Addr, prefix_len: u8) -> Result<()> {
        link::ensure_bridge(bridge, gateway, prefix_len).map(drop)
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

    fn apply(&self, rules: &Ruleset) -> Result<()> {
        rules.apply()
    }
}

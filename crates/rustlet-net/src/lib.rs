//! # rustlet-net: a container's network, from the host's side
//!
//! ```text
//!   host netns                                     container netns (pinned: <run>/netns/<id>)
//!   ┌────────────────────────────────────────┐     ┌──────────────────────────────┐
//!   │ ens18 192.168.50.143                   │     │ lo 127.0.0.1                 │
//!   │   ▲ nft table inet rustlet:            │     │ eth0 10.89.0.2/24 ─┐         │
//!   │   │  masquerade out, DNAT -p, guards   │     │ default via 10.89.0.1        │
//!   │ rustlet0 10.89.0.1/24 (bridge)         │     │ 127.0.0.11: DNS (user nets)  │
//!   │   └─ rlv<short id> ◄── veth pair ──────┼─────┼────────────────────┘         │
//!   │ the daemon: proxy for -p, DNS server   │     └──────────────────────────────┘
//!   └────────────────────────────────────────┘
//! ```
//!
//! The runtime never configures a network: the daemon pins a network
//! namespace for each container and sets it up before the container
//! exists, and the OCI spec only says "join this path". Everything that
//! has to happen *inside* a namespace (an address on `eth0`, a route,
//! a socket at `127.0.0.11`) is done by a dedicated thread that `setns`es
//! into it: network namespaces belong to threads, so a pooled thread must
//! never be left in one.
//!
//! | module | what |
//! |---|---|
//! | [`dns`] | the embedded DNS server at `127.0.0.11` |
//! | [`proxy`] | the userland proxy for published ports |

#![forbid(unsafe_code)]

pub mod dns;
pub mod error;
pub mod proxy;

pub use error::{Context, Error, Result};

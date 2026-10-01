//! # rustlet-image: from an image name to a root filesystem
//!
//! ```text
//!  "nginx"                                                   [reference]
//!     │ normalize → docker.io/library/nginx:latest
//!     ▼
//!  registry ── index ── manifest ── config + layer blobs    [pull, manifest]
//!     │ every byte checked against the digest that named it
//!     ▼
//!  content/   (OCI image layout: blobs/sha256/…, index.json)  [content]
//!     │ decompress, check diff IDs, confine every write
//!     ▼
//!  snapshots/<chain ID>/fs   one directory per layer          [unpack, snapshot]
//!     │ overlayfs: lowerdir+ = layers (idmapped for --userns), upper = the container's
//!     ▼
//!  containers/<id>/rootfs                                     [rootfs]
//!     │ + image config (Entrypoint, Cmd, Env, User, …)
//!     ▼
//!  config.json  ──►  rustlet-runc                             [runspec, user]
//! ```
//!
//! The registry protocol itself (tokens, HTTP) is `oci-client`'s; this
//! crate decides what to fetch, verifies and stores it, and does the
//! filesystem work by hand: unpacking through `openat2` so that no archive
//! entry can write outside its layer, overlay whiteouts and opaque
//! directories, and the overlay mount through the new mount API.
//!
//! Pulling needs no privileges beyond write access to the store. Unpacking
//! and mounting need root (owners, whiteout device nodes, `trusted.*`
//! attributes, mounts).

#![forbid(unsafe_code)]

pub mod config;
pub mod content;
pub mod digest;
pub mod error;
pub mod image;
pub mod import;
pub mod manifest;
pub mod media;
pub mod pull;
pub mod reference;
pub mod rootfs;
pub mod runspec;
pub mod snapshot;
pub mod store;
pub mod unpack;
pub mod user;

pub use digest::Digest;
pub use error::{Error, Result};
pub use image::{Image, Layer};
pub use reference::ImageRef;
pub use store::Store;

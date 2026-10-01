//! Image references: what you type, and what it means.
//!
//! ```text
//!   alpine                      →  docker.io/library/alpine:latest
//!   nginx:1.27                  →  docker.io/library/nginx:1.27
//!   bitnami/redis               →  docker.io/bitnami/redis:latest
//!   ghcr.io/owner/tool@sha256:… →  ghcr.io/owner/tool@sha256:…
//! ```
//!
//! The rules are Docker's: a first component without a `.` or `:` (and not
//! `localhost`) isn't a registry, so the image is on Docker Hub; a
//! single-component Docker Hub name lives under `library/` (the "official
//! images"); no tag and no digest means `:latest`. `oci-spec`'s
//! [`Reference`] implements them; this type keeps it normalized and is what
//! the store records an image under.
//!
//! A tag is a *mutable* pointer: `alpine:latest` today is a different image
//! than a year ago. A digest is immutable. The store keeps both views: the
//! name the image was pulled by, and the digest the registry returned for it
//! at that moment (Docker's "repo digest").

use std::fmt;

use oci_spec::distribution::Reference;

use crate::digest::Digest;
use crate::error::{Error, Result};

/// A normalized image reference.
#[derive(Clone, PartialEq, Eq)]
pub struct ImageRef {
    inner: Reference,
}

impl ImageRef {
    /// Parses and normalizes `s` (see the module docs).
    pub fn parse(s: &str) -> Result<ImageRef> {
        let inner = Reference::try_from(s).map_err(|e| Error::invalid(format!("image reference {s:?}: {e}")))?;
        if let Some(d) = inner.digest() {
            // Only sha256 content is accepted anywhere else, so refuse others
            // here, where the message can still name the reference.
            Digest::parse(d).map_err(|e| Error::invalid(format!("image reference {s:?}: {e}")))?;
        }
        Ok(ImageRef { inner })
    }

    /// The full normalized name, e.g. `docker.io/library/alpine:latest`.
    /// This is the name the store files the image under.
    pub fn name(&self) -> String {
        self.inner.whole()
    }

    /// The registry as written (`docker.io`), not the host actually
    /// contacted (for Docker Hub, `index.docker.io`).
    pub fn registry(&self) -> &str {
        self.inner.registry()
    }

    /// The repository, e.g. `library/alpine`.
    pub fn repository(&self) -> &str {
        self.inner.repository()
    }

    /// The tag, if any (`latest` when neither tag nor digest was given).
    pub fn tag(&self) -> Option<&str> {
        self.inner.tag()
    }

    /// The digest, if the reference pins one.
    pub fn digest(&self) -> Option<Digest> {
        self.inner.digest().map(|d| Digest::parse(d).expect("checked in parse"))
    }

    /// The same repository, pinned to `digest` (keeping the tag, if any).
    pub fn with_digest(&self, digest: &Digest) -> ImageRef {
        ImageRef { inner: self.inner.clone_with_digest(digest.to_string()) }
    }

    /// For `oci-client`.
    pub fn oci(&self) -> &Reference {
        &self.inner
    }
}

impl fmt::Display for ImageRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name())
    }
}

impl fmt::Debug for ImageRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ImageRef({})", self.name())
    }
}

impl std::str::FromStr for ImageRef {
    type Err = Error;
    fn from_str(s: &str) -> Result<ImageRef> {
        ImageRef::parse(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_like_docker() {
        let cases = [
            ("alpine", "docker.io/library/alpine:latest"),
            ("nginx:1.27", "docker.io/library/nginx:1.27"),
            ("bitnami/redis", "docker.io/bitnami/redis:latest"),
            ("docker.io/library/python:3-slim", "docker.io/library/python:3-slim"),
            ("ghcr.io/owner/tool:v1", "ghcr.io/owner/tool:v1"),
            ("localhost:5000/x", "localhost:5000/x:latest"),
        ];
        for (input, want) in cases {
            assert_eq!(ImageRef::parse(input).unwrap().name(), want, "{input}");
        }
        let r = ImageRef::parse("alpine").unwrap();
        assert_eq!((r.registry(), r.repository(), r.tag()), ("docker.io", "library/alpine", Some("latest")));
    }

    #[test]
    fn digests_pin_and_must_be_sha256() {
        let hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let r = ImageRef::parse(&format!("alpine@sha256:{hex}")).unwrap();
        assert_eq!(r.digest().unwrap().hex(), hex);
        assert_eq!(r.name(), format!("docker.io/library/alpine@sha256:{hex}"));
        assert!(ImageRef::parse(&format!("alpine@sha512:{hex}{hex}")).is_err());
        let pinned = ImageRef::parse("alpine").unwrap().with_digest(&Digest::of(b""));
        assert_eq!(pinned.digest(), Some(Digest::of(b"")));
    }

    #[test]
    fn refuses_malformed_references() {
        for bad in ["", "library/Alpine", "a b", "alpine:", ":tag", "alpine@sha256:abc"] {
            assert!(ImageRef::parse(bad).is_err(), "{bad:?} parsed");
        }
    }
}

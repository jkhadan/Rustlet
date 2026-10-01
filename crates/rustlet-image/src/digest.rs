//! Content addresses (`sha256:<64 hex digits>`) and the chain IDs built
//! from them.
//!
//! Everything in an OCI image is named by the SHA-256 of its bytes: the
//! manifest, the config, every layer. That makes the whole image
//! tamper-evident from a single digest. A manifest names its config and
//! layers by digest, so if you trust the manifest's digest you can check
//! everything else as it arrives.
//!
//! A layer has *two* digests:
//!
//! * the **blob digest**, of the compressed bytes the registry sends (the
//!   manifest lists it), and
//! * the **diff ID**, of the uncompressed tar stream (the image config lists
//!   it under `rootfs.diff_ids`).
//!
//! Unpacking checks both. The blob digest proves the download is what the
//! manifest named; the diff ID proves the decompressor produced what the
//! config named. Only the diff ID says what ends up on disk.
//!
//! ## Chain IDs
//!
//! A layer's contents only make sense on top of the layers below it: a
//! whiteout deletes a file *from a lower layer*. So an unpacked layer is
//! keyed by its **chain ID**, which identifies it together with all its
//! parents (image-spec `config.md`):
//!
//! ```text
//! ChainID(L₀) = DiffID(L₀)
//! ChainID(Lₙ) = sha256(ChainID(Lₙ₋₁) + " " + DiffID(Lₙ))
//! ```
//!
//! Two images that share their first three layers share the first three
//! chain IDs, and so the first three unpacked snapshots.

use std::fmt;
use std::io::Read;
use std::str::FromStr;

use sha2::{Digest as _, Sha256};

use crate::error::{Error, Result};

/// A `sha256:` content digest. Other algorithms (OCI also allows sha512)
/// are refused when parsed: no registry we pull from uses them.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Digest {
    /// 64 lowercase hex digits.
    hex: String,
}

impl Digest {
    /// Parses `sha256:<64 lowercase hex digits>`.
    pub fn parse(s: &str) -> Result<Digest> {
        let (algorithm, hex) = s.split_once(':').ok_or_else(|| Error::invalid(format!("digest {s:?}: no ':'")))?;
        if algorithm != "sha256" {
            return Err(Error::unsupported(format!("digest {s:?}: only sha256 is supported")));
        }
        Digest::from_hex(hex).map_err(|_| Error::invalid(format!("digest {s:?}: not 64 lowercase hex digits")))
    }

    /// From the 64 hex digits alone (as in `blobs/sha256/<hex>`).
    pub fn from_hex(hex: &str) -> Result<Digest> {
        if hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            Ok(Digest { hex: hex.to_owned() })
        } else {
            Err(Error::invalid(format!("{hex:?} is not 64 lowercase hex digits")))
        }
    }

    /// The digest of `bytes`.
    pub fn of(bytes: &[u8]) -> Digest {
        Digest { hex: hex::encode(Sha256::digest(bytes)) }
    }

    /// The 64 hex digits.
    pub fn hex(&self) -> &str {
        &self.hex
    }

    /// The first 12 hex digits, as `docker images` shows them.
    pub fn short(&self) -> &str {
        &self.hex[..12]
    }

    /// From `oci-spec`'s digest type (which allows other algorithms).
    pub fn from_oci(d: &oci_spec::image::Digest) -> Result<Digest> {
        Digest::parse(d.as_ref())
    }

    /// To `oci-spec`'s digest type.
    pub fn to_oci(&self) -> oci_spec::image::Digest {
        oci_spec::image::Digest::from_str(&self.to_string()).expect("a sha256 digest is a valid OCI digest")
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sha256:{}", self.hex)
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl FromStr for Digest {
    type Err = Error;
    fn from_str(s: &str) -> Result<Digest> {
        Digest::parse(s)
    }
}

impl TryFrom<String> for Digest {
    type Error = Error;
    fn try_from(s: String) -> Result<Digest> {
        Digest::parse(&s)
    }
}

impl From<Digest> for String {
    fn from(d: Digest) -> String {
        d.to_string()
    }
}

/// An incremental SHA-256.
#[derive(Clone, Default)]
pub struct Hasher(Sha256);

impl fmt::Debug for Hasher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hasher({})", self.digest())
    }
}

impl Hasher {
    pub fn new() -> Hasher {
        Hasher::default()
    }

    pub fn update(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }

    /// The digest of everything passed to [`update`](Self::update) so far.
    pub fn digest(&self) -> Digest {
        Digest { hex: hex::encode(self.0.clone().finalize()) }
    }
}

/// A reader that hashes and counts every byte read through it.
///
/// Unpacking stacks two of them: one on the compressed blob (its digest must
/// be the manifest's), one on the decompressed stream (the config's diff ID).
pub struct HashingReader<R> {
    inner: R,
    hasher: Hasher,
    count: u64,
}

impl<R> HashingReader<R> {
    pub fn new(inner: R) -> HashingReader<R> {
        HashingReader { inner, hasher: Hasher::new(), count: 0 }
    }

    /// Bytes read so far.
    pub fn count(&self) -> u64 {
        self.count
    }

    /// Digest of the bytes read so far.
    pub fn digest(&self) -> Digest {
        self.hasher.digest()
    }

    pub fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }

    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.hasher.update(&buf[..n]);
        self.count += n as u64;
        Ok(n)
    }
}

/// The chain IDs of a stack of layers, bottom first (see the module docs).
pub fn chain_ids(diff_ids: &[Digest]) -> Vec<Digest> {
    let mut out: Vec<Digest> = Vec::with_capacity(diff_ids.len());
    for diff_id in diff_ids {
        let next = match out.last() {
            None => diff_id.clone(),
            Some(parent) => Digest::of(format!("{parent} {diff_id}").as_bytes()),
        };
        out.push(next);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    #[test]
    fn parses_and_prints() {
        let d = Digest::parse(&format!("sha256:{EMPTY}")).unwrap();
        assert_eq!(d, Digest::of(b""));
        assert_eq!(d.to_string(), format!("sha256:{EMPTY}"));
        assert_eq!(d.short(), "e3b0c44298fc");
        assert_eq!(Digest::from_oci(&d.to_oci()).unwrap(), d);
        let json = serde_json::to_string(&d).unwrap();
        assert_eq!(serde_json::from_str::<Digest>(&json).unwrap(), d);
    }

    #[test]
    fn refuses_malformed_digests() {
        for bad in [
            "",
            "sha256",
            "sha256:",
            &format!("sha256:{}", &EMPTY[..63]),
            &format!("sha256:{EMPTY}0"),
            &format!("sha256:{}", EMPTY.to_uppercase()),
            &format!("sha256:../../{}", &EMPTY[6..]),
        ] {
            assert!(Digest::parse(bad).is_err(), "{bad:?} parsed");
        }
        assert!(matches!(Digest::parse(&format!("sha512:{EMPTY}")), Err(Error::Unsupported(_))));
    }

    #[test]
    fn hashing_reader_hashes_what_passes_through() {
        let mut r = HashingReader::new(&b"hello world"[..]);
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        assert_eq!(r.count(), 11);
        assert_eq!(r.digest(), Digest::of(b"hello world"));
    }

    #[test]
    fn chain_ids_follow_the_spec() {
        let a = Digest::of(b"a");
        let b = Digest::of(b"b");
        let c = Digest::of(b"c");
        let ids = chain_ids(&[a.clone(), b.clone(), c.clone()]);
        assert_eq!(ids[0], a);
        assert_eq!(ids[1], Digest::of(format!("{a} {b}").as_bytes()));
        assert_eq!(ids[2], Digest::of(format!("{} {c}", ids[1]).as_bytes()));
        assert!(chain_ids(&[]).is_empty());
    }
}

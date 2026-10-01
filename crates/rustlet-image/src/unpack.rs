//! Unpacking one layer: a tar stream from an untrusted image, written into
//! an empty directory without ever writing outside it.

use std::io::Read;
use std::os::fd::BorrowedFd;

use crate::digest::Digest;
use crate::error::Result;
use crate::media::Compression;

/// What unpacking a layer did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UnpackReport {
    /// Archive entries processed (including skipped ones).
    pub entries: u64,
    /// Bytes of regular-file data written.
    pub bytes: u64,
    /// `.wh.<name>` entries turned into overlay whiteouts.
    pub whiteouts: u64,
    /// Directories marked opaque.
    pub opaque_dirs: u64,
    /// Device nodes not created (paths inside the layer).
    pub skipped_devices: Vec<String>,
    /// Extended attributes not set: overlay's own, or unsupported here
    /// (`path: name`).
    pub dropped_xattrs: Vec<String>,
    /// Digest and size of the compressed input.
    pub blob_digest: Option<Digest>,
    pub blob_size: u64,
    /// Digest of the uncompressed tar stream: the diff ID.
    pub diff_id: Option<Digest>,
}

/// Unpacks the layer blob `blob` (compressed with `compression`) into the
/// empty directory `dest`, and reports both digests for the caller to check.
pub fn unpack(blob: impl Read, compression: Compression, dest: BorrowedFd<'_>) -> Result<UnpackReport> {
    let _ = (blob, compression, dest);
    unimplemented!("unpack::unpack")
}

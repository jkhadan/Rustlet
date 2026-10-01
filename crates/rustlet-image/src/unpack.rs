//! Unpacking one layer: a tar stream from an untrusted image, written into
//! an empty directory without ever writing outside it.
//!
//! A layer is a tar archive of the files one build step added or changed,
//! plus markers for what it *removed* (OCI image-spec `layer.md`):
//!
//! ```text
//!  etc/nginx/nginx.conf        a file this layer adds or replaces
//!  var/cache/apt/.wh.archives  "archives" is deleted from the layers below
//!  usr/share/doc/.wh..wh..opq  everything below hid in usr/share/doc is gone;
//!                              only this layer's entries of it remain
//! ```
//!
//! Each layer gets its own directory (a snapshot), and overlayfs stacks them
//! (`rootfs`). Overlay has its own way to say "deleted": a **whiteout** is a
//! character device 0:0, an **opaque** directory carries the attribute
//! `trusted.overlay.opaque=y`. Unpacking converts the tar markers into those.
//!
//! ## Never writing outside the layer
//!
//! Every name in the archive is chosen by the image's author. The rules:
//!
//! 1. **Names are checked as text first.** `..` anywhere is refused; a
//!    leading `/` and `.` components are dropped (`/etc/x` is `etc/x`, as
//!    Docker treats it).
//! 2. **The parent directory is resolved with `openat2(RESOLVE_IN_ROOT)`**
//!    relative to the layer directory: if an earlier entry made `lib` a
//!    symlink to `/usr/lib` (or to `../../..`), `lib/x` resolves to
//!    `<layer>/usr/lib/x`, never to the host's. This is what Docker gets by
//!    unpacking inside a `chroot`. `RESOLVE_NO_XDEV` keeps the walk off any
//!    mount, `RESOLVE_NO_MAGICLINKS` away from `/proc`-style links.
//! 3. **The last component is never followed.** Each entry is created
//!    relative to its parent's fd, with `O_NOFOLLOW`/`AT_SYMLINK_NOFOLLOW`
//!    or calls that don't follow (`mkdirat`, `symlinkat`, `mknodat`). An
//!    existing entry of the same name is removed first (a directory only if
//!    the new entry isn't one: tar merges directories), with
//!    `remove_tree_at`, which doesn't follow symlinks either.
//! 4. **Hard links must point inside this layer**, resolved the same way
//!    and linked by fd (`linkat(AT_EMPTY_PATH)`), never to a directory or a
//!    whiteout. A link to a lower layer's file has no meaning in a per-layer
//!    directory (Docker's overlay2 refuses such layers too).
//! 5. **Device nodes are skipped** (reported in [`UnpackReport`]): the
//!    rootfs is mounted `nodev` anyway, and `/dev` is a tmpfs.
//!
//! ## Metadata, in this order
//!
//! owner (`fchown`), then mode (`fchmod`; a chown clears setuid/setgid, so
//! the mode must come after), then extended attributes (a chown also clears
//! `security.capability`, the file capabilities of `ping` and friends), then
//! times. Directory times are set last of all, since creating entries in a
//! directory changes its mtime. Attributes come from PAX `SCHILY.xattr.*`
//! records, except overlay's own (`trusted.overlay.*`, `user.overlay.*`):
//! from an image they could forge an opaque directory or a redirect.
//!
//! Unprivileged callers (the unit tests, rootless mode one day) keep their
//! own uid as owner and mark opaque directories with `user.overlay.opaque`,
//! the attribute an overlay mounted with `userxattr` reads.
//!
//! ## Digests
//!
//! The input passes through two [`HashingReader`]s, before and after
//! decompression. The archive ends with zero blocks and padding that the tar
//! parser stops short of; both streams are read to their end, because the
//! digests cover every byte. The caller compares them with the manifest's
//! blob digest and the config's diff ID before using the directory.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{self, BufReader, Read};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use nix::fcntl::{AtFlags, OFlag};
use nix::sys::stat::{FchmodatFlags, Mode, SFlag, UtimensatFlags};
use nix::sys::time::TimeSpec;
use nix::unistd::{Gid, Uid, UnlinkatFlags};
use rustlet_sys::Errno;
use rustlet_sys::fs::{ResolveFlags, Statx, fstatx, openat2, statx};
use rustlet_sys::{tree, xattr};
use tar::EntryType;

use crate::digest::{Digest, HashingReader};
use crate::error::{Context, Error, Result};
use crate::media::Compression;

/// Marks an overlay directory opaque (rootful overlay).
pub const OPAQUE_XATTR: &str = "trusted.overlay.opaque";
/// The same for an overlay mounted with `userxattr` (unprivileged unpacks).
pub const USER_OPAQUE_XATTR: &str = "user.overlay.opaque";

const WHITEOUT_PREFIX: &[u8] = b".wh.";
const OPAQUE_MARKER: &[u8] = b".wh..wh..opq";
/// `.wh..wh.*` other than the opaque marker: AUFS bookkeeping (`.wh..wh.plnk`).
const META_PREFIX: &[u8] = b".wh..wh.";
/// Attribute namespaces overlayfs keeps for itself.
const OVERLAY_XATTRS: [&str; 2] = ["trusted.overlay.", "user.overlay."];

/// How every path inside the layer is resolved (see the module docs).
const RESOLVE: ResolveFlags = ResolveFlags::IN_ROOT.union(ResolveFlags::NO_MAGICLINKS).union(ResolveFlags::NO_XDEV);

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
    /// Other entries not acted on: AUFS metadata, PAX global headers, …
    pub skipped_other: Vec<String>,
    /// Extended attributes not set: overlay's own, or unsupported here
    /// (`path: name`).
    pub dropped_xattrs: Vec<String>,
    /// Digest and size of the compressed input.
    pub blob_digest: Option<Digest>,
    pub blob_size: u64,
    /// Digest and size of the uncompressed tar stream: the diff ID.
    pub diff_id: Option<Digest>,
    pub tar_size: u64,
}

/// Unpacks the layer blob `blob` (compressed with `compression`) into the
/// empty directory `dest`, and reports both digests for the caller to check.
pub fn unpack(blob: impl Read, compression: Compression, dest: BorrowedFd<'_>) -> Result<UnpackReport> {
    let mut compressed = HashingReader::new(BufReader::with_capacity(1 << 16, blob));
    let mut report = {
        let decompressed: Box<dyn Read + '_> = match compression {
            Compression::None => Box::new(&mut compressed),
            Compression::Gzip => Box::new(flate2::read::MultiGzDecoder::new(&mut compressed)),
            Compression::Zstd => {
                Box::new(zstd::stream::read::Decoder::new(&mut compressed).context("start zstd decompression")?)
            }
        };
        let mut tar_stream = HashingReader::new(decompressed);
        let mut unpacker = Unpacker::new(dest)?;
        {
            let mut archive = tar::Archive::new(&mut tar_stream);
            for entry in archive.entries().context("read the layer archive")? {
                unpacker.entry(entry.context("read the layer archive")?)?;
            }
        }
        io::copy(&mut tar_stream, &mut io::sink()).context("read to the end of the layer archive")?;
        unpacker.finish()?;
        let mut report = unpacker.report;
        report.diff_id = Some(tar_stream.digest());
        report.tar_size = tar_stream.count();
        report
    };
    io::copy(&mut compressed, &mut io::sink()).context("read to the end of the layer blob")?;
    report.blob_digest = Some(compressed.digest());
    report.blob_size = compressed.count();
    Ok(report)
}

/// The cleaned, relative form of an archive name: `None` for the layer's
/// root (`./`), an error for `..` or NUL.
fn clean(raw: &[u8]) -> std::result::Result<Option<PathBuf>, &'static str> {
    if raw.contains(&0) {
        return Err("the name contains a NUL byte");
    }
    let mut out = PathBuf::new();
    for component in raw.split(|&b| b == b'/') {
        match component {
            b"" | b"." => continue,
            b".." => return Err("the name contains `..`"),
            c => out.push(OsStr::from_bytes(c)),
        }
    }
    Ok(if out.as_os_str().is_empty() { None } else { Some(out) })
}

fn is_whiteout(st: &Statx) -> bool {
    st.is_char_device() && st.rdev == (0, 0)
}

/// An entry's owner, mode, times and attributes.
struct Meta {
    uid: u32,
    gid: u32,
    mode: u32,
    atime: TimeSpec,
    mtime: TimeSpec,
    xattrs: Vec<(String, Vec<u8>)>,
}

impl Meta {
    /// From the header, overridden by PAX records (which carry ids too large
    /// for the header's octal fields, sub-second times, and attributes).
    fn read<R: Read>(entry: &mut tar::Entry<'_, R>, shown: &str) -> Result<Meta> {
        let header = entry.header();
        let bad = |field: &str, e: io::Error| Error::invalid(format!("layer entry {shown:?}: {field}: {e}"));
        // An empty numeric field (all NULs or spaces) reads as 0, as Go's
        // archive/tar (Docker's, containerd's) reads it; the tar crate
        // refuses it. Anything else that doesn't parse is an error.
        let old = header.as_old();
        let field = |raw: &[u8], parsed: io::Result<u64>, name: &str| match parsed {
            Ok(v) => Ok(v),
            Err(_) if raw.iter().all(|&b| b == 0 || b == b' ') => Ok(0),
            Err(e) => Err(bad(name, e)),
        };
        let mut uid = field(&old.uid, header.uid(), "uid")?;
        let mut gid = field(&old.gid, header.gid(), "gid")?;
        let mode = field(&old.mode, header.mode().map(u64::from), "mode")? as u32;
        let secs = field(&old.mtime, header.mtime(), "mtime")?;
        let mut mtime = TimeSpec::new(i64::try_from(secs).unwrap_or(i64::MAX), 0);
        let mut atime = None;
        let mut xattrs = Vec::new();
        if let Some(extensions) = entry.pax_extensions().map_err(|e| bad("PAX header", e))? {
            for ext in extensions {
                let ext = ext.map_err(|e| bad("PAX record", e))?;
                let Ok(key) = ext.key() else { continue };
                let value = || std::str::from_utf8(ext.value_bytes()).unwrap_or("");
                match key {
                    "uid" => {
                        uid = value().parse().map_err(|_| Error::invalid(format!("layer entry {shown:?}: PAX uid")))?
                    }
                    "gid" => {
                        gid = value().parse().map_err(|_| Error::invalid(format!("layer entry {shown:?}: PAX gid")))?
                    }
                    "mtime" => mtime = pax_time(value()).unwrap_or(mtime),
                    "atime" => atime = pax_time(value()),
                    k => {
                        if let Some(name) = k.strip_prefix("SCHILY.xattr.") {
                            xattrs.push((name.to_owned(), ext.value_bytes().to_vec()));
                        }
                    }
                }
            }
        }
        // uid_t/gid_t -1 means "don't change" to chown(2); larger can't exist.
        let id = |v: u64, what: &str| {
            u32::try_from(v)
                .ok()
                .filter(|&v| v != u32::MAX)
                .ok_or_else(|| Error::invalid(format!("layer entry {shown:?}: {what} {v} is out of range")))
        };
        Ok(Meta { uid: id(uid, "uid")?, gid: id(gid, "gid")?, mode, atime: atime.unwrap_or(mtime), mtime, xattrs })
    }
}

/// A PAX time: decimal seconds, optionally negative, optionally with a
/// fraction (`1700000000.123456789`).
fn pax_time(s: &str) -> Option<TimeSpec> {
    let (neg, s) = match s.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, s),
    };
    let (secs, frac) = s.split_once('.').unwrap_or((s, ""));
    let secs: i64 = secs.parse().ok()?;
    if !frac.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let digits = &frac[..frac.len().min(9)];
    let nanos: i64 =
        if digits.is_empty() { 0 } else { digits.parse::<i64>().ok()? * 10i64.pow(9 - digits.len() as u32) };
    Some(if neg {
        if nanos == 0 { TimeSpec::new(-secs, 0) } else { TimeSpec::new(-secs - 1, 1_000_000_000 - nanos) }
    } else {
        TimeSpec::new(secs, nanos)
    })
}

struct Unpacker<'a> {
    root: BorrowedFd<'a>,
    /// Running as root: owners are preserved, opaque directories use
    /// `trusted.overlay.opaque`.
    privileged: bool,
    report: UnpackReport,
    /// Directory times, applied by [`finish`](Self::finish).
    dir_times: Vec<(PathBuf, TimeSpec, TimeSpec)>,
}

impl<'a> Unpacker<'a> {
    fn new(root: BorrowedFd<'a>) -> Result<Unpacker<'a>> {
        let st = fstatx(root).context("stat the layer directory")?;
        if !st.is_dir() {
            return Err(Error::invalid("the layer directory is not a directory"));
        }
        Ok(Unpacker {
            root,
            privileged: nix::unistd::geteuid().is_root(),
            report: UnpackReport::default(),
            dir_times: Vec::new(),
        })
    }

    fn opaque_xattr(&self) -> &'static str {
        if self.privileged { OPAQUE_XATTR } else { USER_OPAQUE_XATTR }
    }

    fn entry<R: Read>(&mut self, mut entry: tar::Entry<'_, R>) -> Result<()> {
        self.report.entries += 1;
        let raw = entry.path_bytes().into_owned();
        let shown = String::from_utf8_lossy(&raw).into_owned();
        let kind = entry.header().entry_type();
        if matches!(kind, EntryType::XGlobalHeader) {
            self.report.skipped_other.push(shown);
            return Ok(());
        }
        let path = clean(&raw).map_err(|why| Error::invalid(format!("layer entry {shown:?}: {why}")))?;
        let meta = Meta::read(&mut entry, &shown)?;
        let Some(path) = path else {
            // `./`: the layer's own root directory.
            if kind != EntryType::Directory {
                return Err(Error::invalid(format!("layer entry {shown:?}: the root must be a directory")));
            }
            let fd = self.open_dir_rw(Path::new("")).context("open the layer directory")?;
            self.apply(fd.as_fd(), &meta, &shown)?;
            self.dir_times.push((PathBuf::new(), meta.atime, meta.mtime));
            return Ok(());
        };
        let parent = path.parent().unwrap_or(Path::new("")).to_owned();
        let name: OsString = path.file_name().expect("a cleaned path ends in a name").to_owned();
        let name_bytes = name.as_bytes();

        if name_bytes == OPAQUE_MARKER {
            self.dir(&parent, &shown)?;
            let fd = self.open_dir_rw(&parent).with_context(|| format!("layer entry {shown:?}: open its directory"))?;
            return self.mark_opaque(fd.as_fd(), &shown);
        }
        if name_bytes.starts_with(META_PREFIX) {
            self.report.skipped_other.push(shown);
            return Ok(());
        }
        if let Some(target) = name_bytes.strip_prefix(WHITEOUT_PREFIX) {
            let target = OsStr::from_bytes(target);
            if target.is_empty() || target == "." || target == ".." {
                return Err(Error::invalid(format!("layer entry {shown:?}: a whiteout must name an entry")));
            }
            let dir = self.dir(&parent, &shown)?;
            return self.whiteout(dir.as_fd(), target, &shown);
        }
        match kind {
            EntryType::Directory => self.directory(&parent, &name, &meta, &shown),
            EntryType::Regular | EntryType::Continuous | EntryType::GNUSparse => {
                self.file(&parent, &name, &meta, &mut entry, &shown)
            }
            EntryType::Symlink => {
                let target = entry.link_name_bytes().map(|t| t.into_owned()).unwrap_or_default();
                if target.is_empty() || target.contains(&0) {
                    return Err(Error::invalid(format!("layer entry {shown:?}: a symlink needs a target")));
                }
                self.symlink(&parent, &name, OsStr::from_bytes(&target), &meta, &shown)
            }
            EntryType::Link => {
                let target = entry.link_name_bytes().map(|t| t.into_owned()).unwrap_or_default();
                self.hardlink(&parent, &name, &target, &shown)
            }
            EntryType::Fifo => self.fifo(&parent, &name, &meta, &shown),
            EntryType::Char | EntryType::Block => {
                self.report.skipped_devices.push(shown);
                Ok(())
            }
            _ => {
                self.report.skipped_other.push(shown);
                Ok(())
            }
        }
    }

    /// An `O_PATH` fd for the directory `rel` inside the layer.
    fn open_dir(&self, rel: &Path) -> rustlet_sys::Result<OwnedFd> {
        let p = if rel.as_os_str().is_empty() { Path::new(".") } else { rel };
        openat2(Some(self.root), p, OFlag::O_PATH | OFlag::O_DIRECTORY, Mode::empty(), RESOLVE)
    }

    /// The same, opened for I/O (`fchown`/`fchmod`/`fsetxattr` need that).
    fn open_dir_rw(&self, rel: &Path) -> rustlet_sys::Result<OwnedFd> {
        let p = if rel.as_os_str().is_empty() { Path::new(".") } else { rel };
        openat2(Some(self.root), p, OFlag::O_RDONLY | OFlag::O_DIRECTORY, Mode::empty(), RESOLVE)
    }

    /// The parent directory `rel` of an entry, created (`0755`, like
    /// Docker) where the archive didn't list it. Returns an `O_PATH` fd.
    fn dir(&mut self, rel: &Path, shown: &str) -> Result<OwnedFd> {
        match self.open_dir(rel) {
            Ok(fd) => return Ok(fd),
            Err(Errno::ENOENT | Errno::ENOTDIR) => {}
            Err(e) => return Err(e).with_context(|| format!("layer entry {shown:?}: open {}", rel.display())),
        }
        // One component at a time, so that what is missing is created right
        // where the walk so far ended (inside the layer, by construction).
        let mut so_far = PathBuf::new();
        let mut cur = self.open_dir(Path::new("")).context("open the layer directory")?;
        for component in rel.components() {
            let name = component.as_os_str();
            so_far.push(name);
            let ctx = || format!("layer entry {shown:?}: {}", so_far.display());
            cur = match self.open_dir(&so_far) {
                Ok(fd) => fd,
                Err(Errno::ENOENT) => {
                    match self.mkdir_implicit(cur.as_fd(), name, false) {
                        Ok(()) => {}
                        // ENOENT through a name that exists: a symlink to a
                        // directory the layer doesn't have. `mkdir -p`
                        // fails here too, and so does Docker.
                        Err(Errno::EEXIST) => {
                            return Err(Error::invalid(format!(
                                "{}: a symlink to a directory this layer doesn't contain",
                                ctx()
                            )));
                        }
                        Err(e) => return Err(e).with_context(ctx),
                    }
                    self.open_dir(&so_far).with_context(ctx)?
                }
                Err(Errno::ENOTDIR) => {
                    let st = statx(Some(cur.as_fd()), name, libc::AT_SYMLINK_NOFOLLOW).with_context(ctx)?;
                    if !is_whiteout(&st) {
                        return Err(Error::invalid(format!("{}: not a directory", ctx())));
                    }
                    // This layer deleted the lower `name` and now puts
                    // something below it: in the merged view `name` is a
                    // new directory holding only this layer's entries, an
                    // opaque directory.
                    nix::unistd::unlinkat(cur.as_fd(), name, UnlinkatFlags::NoRemoveDir).with_context(ctx)?;
                    self.mkdir_implicit(cur.as_fd(), name, true).with_context(ctx)?;
                    self.open_dir(&so_far).with_context(ctx)?
                }
                Err(e) => return Err(e).with_context(ctx),
            };
        }
        Ok(cur)
    }

    fn mkdir_implicit(&mut self, parent: BorrowedFd<'_>, name: &OsStr, opaque: bool) -> rustlet_sys::Result<()> {
        nix::sys::stat::mkdirat(parent, name, Mode::from_bits_truncate(0o755))?;
        let fd = nix::fcntl::openat(
            parent,
            name,
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )?;
        if self.privileged {
            nix::unistd::fchown(&fd, Some(Uid::from_raw(0)), Some(Gid::from_raw(0)))?;
        }
        // Explicitly: mkdirat's mode is subject to the umask.
        nix::sys::stat::fchmod(&fd, Mode::from_bits_truncate(0o755))?;
        if opaque {
            xattr::fset(fd.as_fd(), self.opaque_xattr(), b"y")?;
            self.report.opaque_dirs += 1;
        }
        Ok(())
    }

    fn mark_opaque(&mut self, dir: BorrowedFd<'_>, shown: &str) -> Result<()> {
        xattr::fset(dir, self.opaque_xattr(), b"y")
            .with_context(|| format!("layer entry {shown:?}: set {}", self.opaque_xattr()))?;
        self.report.opaque_dirs += 1;
        Ok(())
    }

    /// `.wh.<target>`: hide the lower layers' `target`.
    fn whiteout(&mut self, dir: BorrowedFd<'_>, target: &OsStr, shown: &str) -> Result<()> {
        let ctx = || format!("layer entry {shown:?}: whiteout");
        match statx(Some(dir), target, libc::AT_SYMLINK_NOFOLLOW) {
            // A directory of this layer with the same name: it stays (only
            // lower layers are whited out), but none of the lower entries
            // of it may show through: opaque.
            Ok(st) if st.is_dir() => {
                let fd = nix::fcntl::openat(
                    dir,
                    target,
                    OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                    Mode::empty(),
                )
                .with_context(ctx)?;
                self.mark_opaque(fd.as_fd(), shown)
            }
            // This layer's own entry already hides the lower one.
            Ok(_) => Ok(()),
            Err(Errno::ENOENT) => {
                nix::sys::stat::mknodat(dir, target, SFlag::S_IFCHR, Mode::empty(), nix::sys::stat::makedev(0, 0))
                    .with_context(ctx)?;
                if self.privileged {
                    nix::unistd::fchownat(
                        dir,
                        target,
                        Some(Uid::from_raw(0)),
                        Some(Gid::from_raw(0)),
                        AtFlags::AT_SYMLINK_NOFOLLOW,
                    )
                    .with_context(ctx)?;
                }
                self.report.whiteouts += 1;
                Ok(())
            }
            Err(e) => Err(e).with_context(ctx),
        }
    }

    /// Makes room for a new entry `name`: a directory stays if the new entry
    /// is one too; anything else is removed (recursively, for a directory).
    /// Returns what was there.
    fn make_room(&mut self, dir: BorrowedFd<'_>, name: &OsStr, new_is_dir: bool, shown: &str) -> Result<Option<Statx>> {
        let st = match statx(Some(dir), name, libc::AT_SYMLINK_NOFOLLOW) {
            Ok(st) => st,
            Err(Errno::ENOENT) => return Ok(None),
            Err(e) => return Err(e).with_context(|| format!("layer entry {shown:?}: stat")),
        };
        if !(new_is_dir && st.is_dir()) {
            tree::remove_tree_at(dir, name).with_context(|| format!("layer entry {shown:?}: replace what is there"))?;
        }
        Ok(Some(st))
    }

    fn directory(&mut self, parent: &Path, name: &OsStr, meta: &Meta, shown: &str) -> Result<()> {
        let dir = self.dir(parent, shown)?;
        let old = self.make_room(dir.as_fd(), name, true, shown)?;
        let ctx = || format!("layer entry {shown:?}");
        if old.as_ref().is_none_or(|st| !st.is_dir()) {
            nix::sys::stat::mkdirat(dir.as_fd(), name, Mode::from_bits_truncate(0o700)).with_context(ctx)?;
        }
        let fd = nix::fcntl::openat(
            dir.as_fd(),
            name,
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .with_context(ctx)?;
        if old.as_ref().is_some_and(is_whiteout) {
            // A directory replacing this layer's own whiteout: opaque, as in
            // `dir`'s implicit case.
            self.mark_opaque(fd.as_fd(), shown)?;
        }
        self.apply(fd.as_fd(), meta, shown)?;
        self.dir_times.push((parent.join(name), meta.atime, meta.mtime));
        Ok(())
    }

    fn file(&mut self, parent: &Path, name: &OsStr, meta: &Meta, data: &mut impl Read, shown: &str) -> Result<()> {
        let dir = self.dir(parent, shown)?;
        self.make_room(dir.as_fd(), name, false, shown)?;
        let ctx = || format!("layer entry {shown:?}");
        let fd = nix::fcntl::openat(
            dir.as_fd(),
            name,
            OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::from_bits_truncate(0o600),
        )
        .with_context(ctx)?;
        let mut file = File::from(fd);
        self.report.bytes += io::copy(data, &mut file).with_context(ctx)?;
        self.apply(file.as_fd(), meta, shown)?;
        nix::sys::stat::futimens(&file, &meta.atime, &meta.mtime).with_context(ctx)?;
        Ok(())
    }

    fn symlink(&mut self, parent: &Path, name: &OsStr, target: &OsStr, meta: &Meta, shown: &str) -> Result<()> {
        let dir = self.dir(parent, shown)?;
        self.make_room(dir.as_fd(), name, false, shown)?;
        let ctx = || format!("layer entry {shown:?}");
        nix::unistd::symlinkat(target, dir.as_fd(), name).with_context(ctx)?;
        self.chown_at(dir.as_fd(), name, meta).with_context(ctx)?;
        self.set_xattrs(meta, shown, |attr, value| xattr::lset_at(dir.as_fd(), name, attr, value))?;
        nix::sys::stat::utimensat(dir.as_fd(), name, &meta.atime, &meta.mtime, UtimensatFlags::NoFollowSymlink)
            .with_context(ctx)?;
        Ok(())
    }

    fn hardlink(&mut self, parent: &Path, name: &OsStr, target: &[u8], shown: &str) -> Result<()> {
        let bad = |why: &str| Error::invalid(format!("layer entry {shown:?}: hard link: {why}"));
        let rel = clean(target).map_err(bad)?.ok_or_else(|| bad("to the layer's root"))?;
        let src = match openat2(Some(self.root), &rel, OFlag::O_PATH | OFlag::O_NOFOLLOW, Mode::empty(), RESOLVE) {
            Ok(fd) => fd,
            Err(Errno::ENOENT | Errno::ENOTDIR) => {
                return Err(bad(&format!("{} is not in this layer", rel.display())));
            }
            Err(e) => return Err(e).with_context(|| format!("layer entry {shown:?}: open link target")),
        };
        let st = fstatx(src.as_fd()).with_context(|| format!("layer entry {shown:?}: stat link target"))?;
        if st.is_dir() {
            return Err(bad("to a directory"));
        }
        if is_whiteout(&st) {
            return Err(bad("to a whiteout"));
        }
        let dir = self.dir(parent, shown)?;
        if let Ok(old) = statx(Some(dir.as_fd()), name, libc::AT_SYMLINK_NOFOLLOW)
            && (old.dev, old.ino) == (st.dev, st.ino)
        {
            return Ok(()); // the same link, listed twice
        }
        self.make_room(dir.as_fd(), name, false, shown)?;
        self.link_fd(src.as_fd(), dir.as_fd(), name).with_context(|| format!("layer entry {shown:?}: link"))
    }

    /// `linkat(fd, "", dir, name, AT_EMPTY_PATH)`: link the inode we hold.
    /// That needs `CAP_DAC_READ_SEARCH`; without it (unprivileged tests) the
    /// fd's magic link names the same inode.
    fn link_fd(&self, src: BorrowedFd<'_>, dir: BorrowedFd<'_>, name: &OsStr) -> rustlet_sys::Result<()> {
        match nix::unistd::linkat(src, "", dir, name, AtFlags::AT_EMPTY_PATH) {
            Err(Errno::ENOENT) if !self.privileged => {
                let magic = format!("/proc/self/fd/{}", src.as_raw_fd());
                nix::unistd::linkat(self.root, magic.as_str(), dir, name, AtFlags::AT_SYMLINK_FOLLOW)
            }
            r => r,
        }
    }

    fn fifo(&mut self, parent: &Path, name: &OsStr, meta: &Meta, shown: &str) -> Result<()> {
        let dir = self.dir(parent, shown)?;
        self.make_room(dir.as_fd(), name, false, shown)?;
        let ctx = || format!("layer entry {shown:?}");
        nix::unistd::mkfifoat(dir.as_fd(), name, Mode::from_bits_truncate(0o600)).with_context(ctx)?;
        self.chown_at(dir.as_fd(), name, meta).with_context(ctx)?;
        // Following is harmless here: `name` is the FIFO just created.
        nix::sys::stat::fchmodat(
            dir.as_fd(),
            name,
            Mode::from_bits_truncate(meta.mode & 0o7777),
            FchmodatFlags::FollowSymlink,
        )
        .with_context(ctx)?;
        self.set_xattrs(meta, shown, |attr, value| xattr::lset_at(dir.as_fd(), name, attr, value))?;
        nix::sys::stat::utimensat(dir.as_fd(), name, &meta.atime, &meta.mtime, UtimensatFlags::NoFollowSymlink)
            .with_context(ctx)?;
        Ok(())
    }

    fn chown_at(&self, dir: BorrowedFd<'_>, name: &OsStr, meta: &Meta) -> rustlet_sys::Result<()> {
        if !self.privileged {
            return Ok(());
        }
        let (uid, gid) = (Some(Uid::from_raw(meta.uid)), Some(Gid::from_raw(meta.gid)));
        nix::unistd::fchownat(dir, name, uid, gid, AtFlags::AT_SYMLINK_NOFOLLOW)
    }

    /// Owner, mode, attributes, in that order (see the module docs).
    fn apply(&mut self, fd: BorrowedFd<'_>, meta: &Meta, shown: &str) -> Result<()> {
        let ctx = || format!("layer entry {shown:?}");
        if self.privileged {
            nix::unistd::fchown(fd, Some(Uid::from_raw(meta.uid)), Some(Gid::from_raw(meta.gid))).with_context(ctx)?;
        }
        nix::sys::stat::fchmod(fd, Mode::from_bits_truncate(meta.mode & 0o7777)).with_context(ctx)?;
        self.set_xattrs(meta, shown, |attr, value| xattr::fset(fd, attr, value))
    }

    fn set_xattrs(
        &mut self,
        meta: &Meta,
        shown: &str,
        mut set: impl FnMut(&str, &[u8]) -> rustlet_sys::Result<()>,
    ) -> Result<()> {
        for (name, value) in &meta.xattrs {
            if OVERLAY_XATTRS.iter().any(|p| name.starts_with(p)) {
                self.report.dropped_xattrs.push(format!("{shown}: {name}"));
                continue;
            }
            match set(name, value) {
                Ok(()) => {}
                // The filesystem doesn't support that namespace; or `user.*`
                // on a symlink or FIFO, or an unprivileged unpack setting
                // `trusted.*`/`security.*`.
                Err(Errno::ENOTSUP) => self.report.dropped_xattrs.push(format!("{shown}: {name}")),
                Err(Errno::EPERM) if !self.privileged || name.starts_with("user.") => {
                    self.report.dropped_xattrs.push(format!("{shown}: {name}"))
                }
                Err(e) => return Err(e).with_context(|| format!("layer entry {shown:?}: set attribute {name}")),
            }
        }
        Ok(())
    }

    /// Directory times, last.
    fn finish(&mut self) -> Result<()> {
        for (rel, atime, mtime) in self.dir_times.iter().rev() {
            let p = if rel.as_os_str().is_empty() { Path::new(".") } else { rel.as_path() };
            match openat2(
                Some(self.root),
                p,
                OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW,
                Mode::empty(),
                RESOLVE,
            ) {
                Ok(fd) => nix::sys::stat::futimens(&fd, atime, mtime)
                    .with_context(|| format!("set the times of {}", rel.display()))?,
                // A later entry replaced it.
                Err(Errno::ENOENT | Errno::ENOTDIR | Errno::ELOOP) => {}
                Err(e) => return Err(e).with_context(|| format!("open {}", rel.display())),
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;

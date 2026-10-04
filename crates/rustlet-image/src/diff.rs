//! Commit: what a container changed, as a layer.
//!
//! A container's changes are all in its overlay's upper directory
//! (`containers/<id>/upper`, see `rootfs`): files it created or modified
//! (whole, overlay copies a file up before the first write), directories
//! it created or that hold changed entries, a **whiteout** (a character
//! device 0:0) for each entry of a lower layer it deleted, and the
//! attribute `trusted.overlay.opaque=y` on a directory it deleted and made
//! again (the lower layers' entries of it are gone). A layer says the same
//! in a tar archive, the other way round from unpacking (`unpack`):
//!
//! ```text
//!  upper/                                 layer.tar
//!  ├─ etc/hostname     (file)        ──►  etc/  etc/hostname
//!  ├─ tmp/old          (char 0:0)    ──►  tmp/  tmp/.wh.old
//!  └─ var/cache/       (opaque=y)    ──►  var/  var/cache/  var/cache/.wh..wh..opq
//! ```
//!
//! `rustlet commit` and every `RUN`, `COPY` and `ADD` of a build go through
//! [`commit_layer`]: the archive, gzipped, becomes a blob of the store,
//! whose uncompressed digest is the layer's diff ID.
//!
//! ## Rules
//!
//! - **Deterministic**: depth first, each directory's entries in byte order
//!   of their names, parents before children (a directory's entry, then its
//!   opaque marker if it has one, then its entries), as Docker's own walk
//!   goes; names relative, without `./`, directories ending in `/`; no user
//!   or group names; header times in whole seconds; PAX records sorted by
//!   key. The same upper directory always makes the same bytes.
//! - **Never followed**: a symlink is stored as one; every entry is
//!   examined relative to its parent's fd (`AT_SYMLINK_NOFOLLOW`), and a
//!   file is opened `O_NOFOLLOW | O_NONBLOCK` and checked to be the inode
//!   that was examined; FIFOs are never opened. A file must still have its
//!   size when read (a paused or stopped container's upper doesn't change);
//!   otherwise the commit fails rather than write a wrong header.
//! - **Whiteouts** become empty regular files `.wh.<name>`. Overlay makes
//!   them as hard links to one inode in `work/work`, so they are *never*
//!   tar hard links of each other. **Opaque** directories (the `y` value;
//!   `x` means something else) get a `.wh..wh..opq` entry. Neither marker
//!   has metadata of its own: an empty file, mode `0600`, owned by `0:0`,
//!   from the epoch.
//! - **Hard links** between other files of the upper directory stay hard
//!   links: the first name (in the archive's order) is the file, later ones
//!   are link entries to it.
//! - **Attributes**: every extended attribute except overlay's own
//!   (`trusted.overlay.*`, `user.overlay.*`: opaque markers, `origin`,
//!   `impure`, `uuid`…), as PAX `SCHILY.xattr.<name>` records. Owners are
//!   translated by [`DiffOptions::map_owner`] (an upper directory of a
//!   `--userns=remap` container holds host ids: [`unmap_remap`]), and so
//!   are the ids inside a version 3 `security.capability` and POSIX ACLs,
//!   as `copyup` does.
//! - **Left out** (listed in [`DiffReport::skipped`]): device nodes other
//!   than whiteouts, sockets, and [`DiffOptions::skip`]'s paths with
//!   everything below them: a container's mount points (`/proc`, `/dev`,
//!   `/etc/resolv.conf`, its volumes' targets) are made by the runtime when
//!   the image lacks them, and are no change of the container's; what is
//!   below one was hidden by the mount. A directory that held nothing but
//!   such paths (`/etc` copied up for `/etc/resolv.conf`, the parents made
//!   for a volume's target) goes with them; an empty directory of the
//!   container's own stays. The skipped paths are matched as
//!   written (`.`, `..` and repeated `/` aside), not through the image's
//!   symlinks. So is an entry the container itself named `.wh.<something>`:
//!   in a layer, that name means a whiteout.
//! - PAX records for what ustar headers can't hold: names over 100 bytes,
//!   link targets over 100, ids over 2097151, sizes over 8 GiB (and times
//!   before 1970).
//! - The walk uses its own stack (depth capped, as `copyup`'s), not
//!   recursion.

use std::collections::{HashMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{self, BufWriter, Read, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use nix::fcntl::{AtFlags, OFlag};
use nix::sys::stat::{FileStat, Mode};
use oci_spec::image::Descriptor;
use rustlet_sys::{Errno, xattr};
use tar::EntryType;

use crate::content::{ContentStore, descriptor};
use crate::copyup::map_ids;
use crate::digest::{Digest, Hasher};
use crate::error::{Context, Error, Result};
use crate::media;
use crate::unpack::{OPAQUE_XATTR, USER_OPAQUE_XATTR};

/// How many levels below the upper directory the tree may go (as in
/// `copyup`: each level holds an fd).
const MAX_DEPTH: usize = 4096;
/// Attribute namespaces overlayfs keeps for itself.
const OVERLAY_XATTRS: [&str; 2] = ["trusted.overlay.", "user.overlay."];
const WHITEOUT_PREFIX: &[u8] = b".wh.";
const OPAQUE_MARKER: &[u8] = b".wh..wh..opq";

/// What a ustar header's fields hold: ids of 7 octal digits, sizes and
/// times of 11 (names and link targets: 100 bytes, the fields' size).
const MAX_ID: u32 = 0o7_777_777;
const MAX_SIZE: u64 = 0o77_777_777_777;
const MAX_TIME: i64 = 0o77_777_777_777;
const BLOCK: usize = 512;

/// How [`diff`] reads an upper directory.
pub struct DiffOptions<'a> {
    /// Absolute paths in the container that were mount points while it
    /// ran: left out, with everything below them.
    pub skip: &'a [PathBuf],
    /// Owners as stored in the upper directory → owners in the layer.
    pub map_owner: &'a dyn Fn(u32, u32) -> (u32, u32),
}

impl Default for DiffOptions<'_> {
    fn default() -> Self {
        DiffOptions { skip: &[], map_owner: &|uid, gid| (uid, gid) }
    }
}

/// What [`diff`] wrote.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DiffReport {
    /// Archive entries written (whiteout and opaque markers included).
    pub entries: u64,
    /// Bytes of file content.
    pub bytes: u64,
    pub whiteouts: u64,
    pub opaque_dirs: u64,
    /// Entries left out, as absolute paths in the container.
    pub skipped: Vec<String>,
    /// The digest and size of the archive: the layer's diff ID.
    pub diff_id: Option<Digest>,
    pub tar_size: u64,
}

/// A layer [`commit_layer`] stored.
#[derive(Debug, Clone)]
pub struct CommittedLayer {
    /// The blob (`application/vnd.oci.image.layer.v1.tar+gzip`).
    pub descriptor: Descriptor,
    pub diff_id: Digest,
    pub report: DiffReport,
}

/// Writes the changes recorded in the overlay upper directory `upper` as an
/// uncompressed layer archive to `out` (see the module docs).
pub fn diff(upper: &Path, out: &mut dyn Write, options: &DiffOptions<'_>) -> Result<DiffReport> {
    let root = nix::fcntl::open(upper, OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC, Mode::empty())
        .with_context(|| format!("open {}", upper.display()))?;
    let mut differ = Differ {
        tar: TarWriter::new(out),
        map_owner: options.map_owner,
        skip: options.skip.iter().map(|p| relative(p)).collect(),
        links: HashMap::new(),
        report: DiffReport::default(),
    };
    if differ.skip.contains(&Vec::new()) {
        // A mount on `/` itself: everything is below it.
        differ.report.skipped.push("/".to_owned());
    } else {
        differ.walk(root)?;
    }
    let Differ { tar, mut report, .. } = differ;
    let (diff_id, size) = tar.finish()?;
    report.diff_id = Some(diff_id);
    report.tar_size = size;
    Ok(report)
}

/// [`diff`], gzipped into the store as a layer blob.
pub fn commit_layer(content: &ContentStore, upper: &Path, options: &DiffOptions<'_>) -> Result<CommittedLayer> {
    // Compressed output comes in small pieces; the file gets them in large
    // ones. An error drops the writer, which deletes what it wrote.
    let blob = BufWriter::with_capacity(1 << 20, content.blob_writer()?);
    let mut gzip = flate2::write::GzEncoder::new(blob, flate2::Compression::default());
    let report = diff(upper, &mut gzip, options)?;
    let blob = gzip.finish().context("compress the layer")?;
    let blob = blob.into_inner().map_err(io::IntoInnerError::into_error).context("write the layer")?;
    let (digest, size) = blob.finish()?;
    let diff_id = report.diff_id.clone().expect("diff reports the diff ID");
    Ok(CommittedLayer { descriptor: descriptor(media::OCI_LAYER_GZIP, &digest, size), diff_id, report })
}

/// The owners of a `--userns=remap` container's upper directory, as its
/// image would have them: host ids 1000000–1065535 are container ids
/// 0–65535; anything else is an id the container saw as unmapped, 65534
/// (`nobody`).
pub fn unmap_remap(uid: u32, gid: u32) -> (u32, u32) {
    let back = |id: u32| {
        id.checked_sub(rustlet_runtime::spec::REMAP_HOST_ID)
            .filter(|&c| c < rustlet_runtime::spec::REMAP_SIZE)
            .unwrap_or(65534)
    };
    (back(uid), back(gid))
}

/// A directory being walked.
struct Frame {
    dir: OwnedFd,
    /// Its path below the upper directory (empty for the upper directory).
    rel: Vec<u8>,
    /// The entries still to write.
    names: std::vec::IntoIter<OsString>,
    /// Its own entry, until something in it is written (see
    /// [`Differ::finish_dir`]).
    pending: Option<PendingDir>,
    /// Something below it was left out as a mount point, or was a directory
    /// that held only such.
    held_mounts: bool,
}

/// A directory's entry, not written yet.
struct PendingDir {
    /// Its archive name, with the trailing `/`.
    entry: Vec<u8>,
    st: FileStat,
    xattrs: Vec<(String, Vec<u8>)>,
}

struct Differ<'w, 'a> {
    tar: TarWriter<'w>,
    map_owner: &'a dyn Fn(u32, u32) -> (u32, u32),
    /// [`DiffOptions::skip`], relative to the upper directory.
    skip: HashSet<Vec<u8>>,
    /// The archive name of each inode with more than one name, by
    /// `(st_dev, st_ino)`: the first one written.
    links: HashMap<(u64, u64), Vec<u8>>,
    report: DiffReport,
}

impl Differ<'_, '_> {
    /// The walk, depth first, from the upper directory `root`.
    fn walk(&mut self, root: OwnedFd) -> Result<()> {
        let names = entries(root.as_fd()).context("list the upper directory")?;
        let mut stack =
            vec![Frame { dir: root, rel: Vec::new(), names: names.into_iter(), pending: None, held_mounts: false }];
        while let Some(dir) = stack.last_mut() {
            let Some(name) = dir.names.next() else {
                let done = stack.pop().expect("the loop just looked at it");
                self.finish_dir(&mut stack, done)?;
                continue;
            };
            if let Some(sub) = self.entry(&mut stack, &name)? {
                if stack.len() > MAX_DEPTH {
                    return Err(Error::unsupported(format!(
                        "{:?}: more than {MAX_DEPTH} levels deep",
                        in_container(&sub.rel)
                    )));
                }
                stack.push(sub);
            }
        }
        Ok(())
    }

    /// Writes the entry `name` of the directory atop `stack`, or leaves it
    /// out. A directory is returned for the walk to enter.
    fn entry(&mut self, stack: &mut [Frame], name: &OsStr) -> Result<Option<Frame>> {
        let dir = stack.last_mut().expect("the walk is in a directory");
        let rel = child(&dir.rel, name.as_bytes());
        let path = in_container(&rel);
        if self.skip.contains(&rel) {
            self.report.skipped.push(path.to_string_lossy().into_owned());
            dir.held_mounts = true;
            return Ok(None);
        }
        if name.as_bytes().starts_with(WHITEOUT_PREFIX) {
            self.report.skipped.push(path.to_string_lossy().into_owned());
            return Ok(None);
        }
        let shown = format!("{path:?}");
        let st = nix::sys::stat::fstatat(&dir.dir, name, AtFlags::AT_SYMLINK_NOFOLLOW)
            .with_context(|| format!("{shown}: stat"))?;
        match st.st_mode & libc::S_IFMT {
            libc::S_IFDIR => return self.directory(stack, name, rel, &st, &shown).map(Some),
            libc::S_IFCHR if st.st_rdev == 0 => {
                self.flush(stack)?;
                let dir = stack.last().expect("the walk is in a directory");
                self.whiteout(&dir.rel, name)?
            }
            libc::S_IFREG | libc::S_IFLNK | libc::S_IFIFO => {
                self.flush(stack)?;
                let dir = stack.last().expect("the walk is in a directory");
                self.leaf(dir, name, rel, &st, &shown)?
            }
            // Device nodes and sockets.
            _ => self.report.skipped.push(path.to_string_lossy().into_owned()),
        }
        Ok(None)
    }

    /// A directory, returned to be walked. Its entry waits until something
    /// in it is written ([`flush`](Self::flush)) or its walk ends
    /// ([`finish_dir`](Self::finish_dir)); an opaque one is written at once,
    /// with its marker: hiding the lower layers' entries is a change in
    /// itself.
    fn directory(
        &mut self,
        stack: &mut [Frame],
        name: &OsStr,
        rel: Vec<u8>,
        st: &FileStat,
        shown: &str,
    ) -> Result<Frame> {
        let parent = stack.last().expect("the walk is in a directory");
        let dir = open_checked(parent.dir.as_fd(), name, st, shown)?;
        let attrs = self.xattrs(&Attrs::Fd(dir.as_fd()), shown)?;
        let mut entry = rel.clone();
        entry.push(b'/');
        let names = entries(dir.as_fd()).with_context(|| format!("{shown}: list it"))?;
        let pending = PendingDir { entry, st: *st, xattrs: attrs.kept };
        if attrs.opaque {
            self.flush(stack)?;
            self.write_dir(&pending)?;
            let mut marker = pending.entry;
            marker.extend_from_slice(OPAQUE_MARKER);
            self.marker(&marker)?;
            self.report.opaque_dirs += 1;
            return Ok(Frame { dir, rel, names: names.into_iter(), pending: None, held_mounts: false });
        }
        Ok(Frame { dir, rel, names: names.into_iter(), pending: Some(pending), held_mounts: false })
    }

    /// The directories being walked whose entries aren't written yet,
    /// outermost first: something below them is about to be.
    fn flush(&mut self, stack: &mut [Frame]) -> Result<()> {
        for frame in stack.iter_mut() {
            if let Some(pending) = frame.pending.take() {
                self.write_dir(&pending)?;
            }
        }
        Ok(())
    }

    /// A directory whose entries are all done, nothing of them written: an
    /// empty directory of the container's own (a `mkdir`), written now;
    /// unless all it held was mount points (and directories of nothing
    /// else), which the runtime makes where the image lacks them (`/etc`
    /// for `/etc/resolv.conf`, a volume's target and its parents) and are no
    /// change of the container's: then it is left out too, as Docker's
    /// init layer keeps such paths out of a container's diff.
    fn finish_dir(&mut self, stack: &mut [Frame], done: Frame) -> Result<()> {
        let Some(pending) = done.pending else { return Ok(()) };
        if done.held_mounts {
            self.report.skipped.push(in_container(&done.rel).to_string_lossy().into_owned());
            if let Some(parent) = stack.last_mut() {
                parent.held_mounts = true;
            }
            return Ok(());
        }
        self.flush(stack)?;
        self.write_dir(&pending)
    }

    fn write_dir(&mut self, pending: &PendingDir) -> Result<()> {
        let header = self.header(&pending.entry, EntryType::Directory, &pending.st);
        self.put(&EntryHeader { xattrs: &pending.xattrs, ..header })
    }

    /// A file, symlink or FIFO; or a later name of one already written, as
    /// a hard link to its first.
    fn leaf(&mut self, dir: &Frame, name: &OsStr, rel: Vec<u8>, st: &FileStat, shown: &str) -> Result<()> {
        let inode = (st.st_dev, st.st_ino);
        if st.st_nlink > 1
            && let Some(first) = self.links.get(&inode)
        {
            let link = EntryHeader { link: first, ..self.header(&rel, EntryType::Link, st) };
            self.tar.header(&link)?;
            self.report.entries += 1;
            return Ok(());
        }
        match st.st_mode & libc::S_IFMT {
            libc::S_IFREG => {
                let file = open_checked(dir.dir.as_fd(), name, st, shown)?;
                let attrs = self.xattrs(&Attrs::Fd(file.as_fd()), shown)?;
                let size = u64::try_from(st.st_size).unwrap_or_default();
                self.put(&EntryHeader { size, xattrs: &attrs.kept, ..self.header(&rel, EntryType::Regular, st) })?;
                self.tar.data(&mut File::from(file), size, shown)?;
                self.report.bytes += size;
            }
            libc::S_IFLNK => {
                let target =
                    nix::fcntl::readlinkat(&dir.dir, name).with_context(|| format!("{shown}: read the link"))?;
                let attrs = self.xattrs(&Attrs::at(dir.dir.as_fd(), name), shown)?;
                let header = self.header(&rel, EntryType::Symlink, st);
                self.put(&EntryHeader { link: target.as_bytes(), xattrs: &attrs.kept, ..header })?;
            }
            _ => {
                // A FIFO is never opened: a reader waits for a writer. Its
                // attributes are read by name, as a symlink's.
                let attrs = self.xattrs(&Attrs::at(dir.dir.as_fd(), name), shown)?;
                self.put(&EntryHeader { xattrs: &attrs.kept, ..self.header(&rel, EntryType::Fifo, st) })?;
            }
        }
        if st.st_nlink > 1 {
            self.links.insert(inode, rel);
        }
        Ok(())
    }

    /// `.wh.<name>`: the container deleted `name` from a lower layer.
    fn whiteout(&mut self, dir: &[u8], name: &OsStr) -> Result<()> {
        self.marker(&child(dir, &[WHITEOUT_PREFIX, name.as_bytes()].concat()))?;
        self.report.whiteouts += 1;
        Ok(())
    }

    /// A whiteout or opaque marker: an empty file with no metadata of its
    /// own (see the module docs).
    fn marker(&mut self, name: &[u8]) -> Result<()> {
        let header = EntryHeader {
            name,
            kind: EntryType::Regular,
            mode: 0o600,
            uid: 0,
            gid: 0,
            mtime: 0,
            size: 0,
            link: b"",
            xattrs: &[],
        };
        self.put(&header)
    }

    fn put(&mut self, header: &EntryHeader<'_>) -> Result<()> {
        self.tar.header(header)?;
        self.report.entries += 1;
        Ok(())
    }

    /// The header fields an entry takes from its inode: mode (with setuid,
    /// setgid, sticky), owner (mapped), modification time.
    fn header<'h>(&self, name: &'h [u8], kind: EntryType, st: &FileStat) -> EntryHeader<'h> {
        let (uid, gid) = (self.map_owner)(st.st_uid, st.st_gid);
        EntryHeader {
            name,
            kind,
            mode: st.st_mode & 0o7777,
            uid,
            gid,
            mtime: st.st_mtime,
            size: 0,
            link: b"",
            xattrs: &[],
        }
    }

    /// The attributes `from` has, as the layer keeps them (see the module
    /// docs), and whether overlay's own mark it opaque.
    fn xattrs(&self, from: &Attrs<'_>, shown: &str) -> Result<Xattrs> {
        let mut out = Xattrs { kept: Vec::new(), opaque: false };
        let names = match from.list() {
            Ok(names) => names,
            // A filesystem without attributes has none to keep.
            Err(Errno::ENOTSUP) => return Ok(out),
            Err(e) => return Err(e).with_context(|| format!("{shown}: list the attributes")),
        };
        for name in names {
            let value = || from.get(&name).with_context(|| format!("{shown}: read attribute {name}"));
            if OVERLAY_XATTRS.iter().any(|p| name.starts_with(p)) {
                if name == OPAQUE_XATTR || name == USER_OPAQUE_XATTR {
                    out.opaque |= value()? == b"y";
                }
                continue;
            }
            if name.contains('=') {
                // A PAX record's key ends at its first `=`.
                return Err(Error::unsupported(format!("{shown}: attribute {name:?}: a tar archive can't hold it")));
            }
            let value = map_ids(&name, value()?, self.map_owner);
            out.kept.push((name, value));
        }
        out.kept.sort();
        Ok(out)
    }
}

/// An entry's attributes, as [`Differ::xattrs`] found them.
struct Xattrs {
    /// Name and value of each attribute the layer keeps, sorted by name.
    kept: Vec<(String, Vec<u8>)>,
    /// Overlay's opaque attribute says `y`.
    opaque: bool,
}

/// Where an entry's attributes are read: its fd, or, for a symlink or FIFO,
/// which isn't opened, its name in its directory's magic link
/// (`/proc/self/fd/<dir>/<name>`, as in `copyup`): the `l*xattr` calls
/// follow the magic link, a middle component, to exactly the directory
/// held, and don't follow the name.
enum Attrs<'a> {
    Fd(BorrowedFd<'a>),
    At(PathBuf),
}

impl Attrs<'_> {
    fn at(dir: BorrowedFd<'_>, name: &OsStr) -> Self {
        Attrs::At(Path::new(&format!("/proc/self/fd/{}", dir.as_raw_fd())).join(name))
    }

    fn list(&self) -> rustlet_sys::Result<Vec<String>> {
        match self {
            Attrs::Fd(fd) => xattr::flist(*fd),
            Attrs::At(path) => xattr::llist(path),
        }
    }

    fn get(&self, name: &str) -> rustlet_sys::Result<Vec<u8>> {
        match self {
            Attrs::Fd(fd) => xattr::fget(*fd, name),
            Attrs::At(path) => xattr::lget(path, name),
        }
    }
}

/// Opens the entry `name` of `dir`, which `st` says is a regular file or a
/// directory, for reading, and checks it is still that inode. The flags are
/// GNU tar's (and `copyup`'s): `O_NOFOLLOW`, and `O_NONBLOCK` and
/// `O_NOCTTY`, so that a FIFO or a terminal put in its place could neither
/// block the open nor become the daemon's terminal before the check
/// refuses it.
fn open_checked(dir: BorrowedFd<'_>, name: &OsStr, st: &FileStat, shown: &str) -> Result<OwnedFd> {
    let flags = OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_NOCTTY | OFlag::O_CLOEXEC;
    let fd = nix::fcntl::openat(dir, name, flags, Mode::empty()).with_context(|| format!("{shown}: open"))?;
    let now = nix::sys::stat::fstat(&fd).with_context(|| format!("{shown}: stat"))?;
    let inode = |st: &FileStat| (st.st_dev, st.st_ino, st.st_mode & libc::S_IFMT);
    if inode(&now) != inode(st) {
        return Err(Error::invalid(format!("{shown}: replaced while it was being read")));
    }
    Ok(fd)
}

/// The names in `dir` other than `.` and `..`, in byte order. (A directory
/// stream of its own, so that `dir`'s offset doesn't move.)
fn entries(dir: BorrowedFd<'_>) -> rustlet_sys::Result<Vec<OsString>> {
    let fd = nix::fcntl::openat(dir, ".", OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC, Mode::empty())?;
    let mut listing = nix::dir::Dir::from_fd(fd)?;
    let mut names = Vec::new();
    for entry in listing.iter() {
        let entry = entry?;
        let name = entry.file_name().to_bytes();
        if !matches!(name, b"." | b"..") {
            names.push(OsStr::from_bytes(name).to_owned());
        }
    }
    names.sort_unstable();
    Ok(names)
}

/// `dir/name`, as archive names are joined (`dir` empty: the top).
fn child(dir: &[u8], name: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(dir.len() + 1 + name.len());
    if !dir.is_empty() {
        out.extend_from_slice(dir);
        out.push(b'/');
    }
    out.extend_from_slice(name);
    out
}

/// An entry's path in the container.
fn in_container(rel: &[u8]) -> PathBuf {
    Path::new("/").join(OsStr::from_bytes(rel))
}

/// A path in the container relative to its root, as the walk names
/// entries: empty and `.` components dropped, `..` taking one back.
fn relative(path: &Path) -> Vec<u8> {
    let mut parts: Vec<&[u8]> = Vec::new();
    for part in path.as_os_str().as_bytes().split(|&b| b == b'/') {
        match part {
            b"" | b"." => {}
            b".." => {
                parts.pop();
            }
            part => parts.push(part),
        }
    }
    parts.join(&b'/')
}

/// One entry's header, for [`TarWriter::header`].
pub(crate) struct EntryHeader<'a> {
    pub(crate) name: &'a [u8],
    pub(crate) kind: EntryType,
    /// Permission bits, setuid, setgid and sticky included.
    pub(crate) mode: u32,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    /// Seconds since the epoch.
    pub(crate) mtime: i64,
    pub(crate) size: u64,
    /// A symlink's target, or a hard link's first name.
    pub(crate) link: &'a [u8],
    /// Extended attributes (name, value), for PAX `SCHILY.xattr.` records.
    pub(crate) xattrs: &'a [(String, Vec<u8>)],
}

/// A tar archive being written: ustar headers, with PAX records for what
/// they can't hold (see the module docs), every byte hashed and counted.
/// [`diff`] writes layers with it, and `archive::save` whole images.
pub(crate) struct TarWriter<'a> {
    out: Hashed<'a>,
    buf: Vec<u8>,
}

/// The archive's bytes on their way out.
struct Hashed<'a> {
    out: &'a mut dyn Write,
    hasher: Hasher,
    count: u64,
}

impl Hashed<'_> {
    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        self.out.write_all(bytes).context("write the archive")?;
        self.hasher.update(bytes);
        self.count += bytes.len() as u64;
        Ok(())
    }

    /// Zeros to the end of the block that `len` bytes of data end in.
    fn pad(&mut self, len: u64) -> Result<()> {
        match (len % BLOCK as u64) as usize {
            0 => Ok(()),
            partial => self.write(&[0; BLOCK][partial..]),
        }
    }
}

impl<'a> TarWriter<'a> {
    pub(crate) fn new(out: &'a mut dyn Write) -> TarWriter<'a> {
        TarWriter { out: Hashed { out, hasher: Hasher::new(), count: 0 }, buf: vec![0; 1 << 17] }
    }

    /// Writes an entry's header, after a PAX header if it needs one. Its
    /// data, if it has any, follows with [`data`](Self::data).
    pub(crate) fn header(&mut self, entry: &EntryHeader<'_>) -> Result<()> {
        let mut pax: Vec<(String, Vec<u8>)> = Vec::new();
        let mut header = tar::Header::new_ustar();
        header.set_entry_type(entry.kind);
        header.set_mode(entry.mode & 0o7777);
        if !put_name(&mut header.as_old_mut().name, entry.name) {
            pax.push(("path".to_owned(), entry.name.to_vec()));
        }
        if !put_name(&mut header.as_old_mut().linkname, entry.link) {
            pax.push(("linkpath".to_owned(), entry.link.to_vec()));
        }
        let mut id = |key: &str, value: u32| {
            if value <= MAX_ID {
                u64::from(value)
            } else {
                pax.push((key.to_owned(), value.to_string().into_bytes()));
                0
            }
        };
        header.set_uid(id("uid", entry.uid));
        header.set_gid(id("gid", entry.gid));
        if entry.size <= MAX_SIZE {
            header.set_size(entry.size);
        } else {
            pax.push(("size".to_owned(), entry.size.to_string().into_bytes()));
            header.set_size(0);
        }
        match u64::try_from(entry.mtime) {
            Ok(mtime) if entry.mtime <= MAX_TIME => header.set_mtime(mtime),
            _ => {
                pax.push(("mtime".to_owned(), entry.mtime.to_string().into_bytes()));
                header.set_mtime(0);
            }
        }
        // Zeros, as Go's archive/tar (Docker's) writes them.
        header.set_device_major(0).context("make a tar header")?;
        header.set_device_minor(0).context("make a tar header")?;
        for (name, value) in entry.xattrs {
            pax.push((format!("SCHILY.xattr.{name}"), value.clone()));
        }
        if !pax.is_empty() {
            pax.sort();
            self.pax(entry.name, &pax)?;
        }
        header.set_cksum();
        self.out.write(header.as_bytes())
    }

    /// A PAX extended header (`x`) with `records`, for the entry `name`.
    /// It is named as Go's archive/tar names them (`dir/PaxHeaders.0/name`);
    /// readers that know PAX never see the name.
    fn pax(&mut self, name: &[u8], records: &[(String, Vec<u8>)]) -> Result<()> {
        let mut data = Vec::new();
        for (key, value) in records {
            // "<length> <key>=<value>\n", the length counting its own digits.
            let rest = key.len() + value.len() + 3;
            let mut len = rest + 1;
            while rest + len.to_string().len() != len {
                len = rest + len.to_string().len();
            }
            data.extend_from_slice(format!("{len} {key}=").as_bytes());
            data.extend_from_slice(value);
            data.push(b'\n');
        }
        let mut header = tar::Header::new_ustar();
        header.set_entry_type(EntryType::XHeader);
        put_name(&mut header.as_old_mut().name, &pax_name(name));
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_size(data.len() as u64);
        header.set_device_major(0).context("make a tar header")?;
        header.set_device_minor(0).context("make a tar header")?;
        header.set_cksum();
        self.out.write(header.as_bytes())?;
        self.out.write(&data)?;
        self.out.pad(data.len() as u64)
    }

    /// Copies `src` as the data of the entry whose header was just written,
    /// and pads it to a whole block. `src` (`what`, in errors) must have
    /// exactly `size` bytes: the header said so already.
    pub(crate) fn data(&mut self, src: &mut dyn Read, size: u64, what: &str) -> Result<()> {
        let changed =
            || Error::invalid(format!("{what}: its size changed while it was being read (from {size} bytes)"));
        let mut left = size;
        while left > 0 {
            let want = self.buf.len().min(usize::try_from(left).unwrap_or(usize::MAX));
            let n = read_some(src, &mut self.buf[..want]).with_context(|| format!("{what}: read"))?;
            if n == 0 {
                return Err(changed());
            }
            self.out.write(&self.buf[..n])?;
            left -= n as u64;
        }
        if read_some(src, &mut self.buf[..1]).with_context(|| format!("{what}: read"))? != 0 {
            return Err(changed());
        }
        self.out.pad(size)
    }

    /// Ends the archive (two zero blocks); returns the digest and size of
    /// everything written.
    pub(crate) fn finish(mut self) -> Result<(Digest, u64)> {
        self.out.write(&[0; 2 * BLOCK])?;
        self.out.out.flush().context("write the archive")?;
        Ok((self.out.hasher.digest(), self.out.count))
    }
}

/// Copies `value` into a header's name field. False if it doesn't fit: the
/// field then holds what does, without a trailing `/` (a reader that
/// ignores the PAX record could take a cut name for a directory's).
fn put_name(field: &mut [u8], value: &[u8]) -> bool {
    if value.len() <= field.len() {
        field[..value.len()].copy_from_slice(value);
        return true;
    }
    let cut = &value[..field.len()];
    let kept = cut.iter().rposition(|&b| b != b'/').map_or(0, |i| i + 1);
    field[..kept].copy_from_slice(&cut[..kept]);
    false
}

/// The name of an entry's PAX header, as Go's archive/tar makes it:
/// `dir/PaxHeaders.0/base`, ASCII only.
fn pax_name(name: &[u8]) -> Vec<u8> {
    let trimmed = &name[..name.iter().rposition(|&b| b != b'/').map_or(0, |i| i + 1)];
    let (dir, base) = match trimmed.iter().rposition(|&b| b == b'/') {
        Some(i) => trimmed.split_at(i + 1),
        None => (&b""[..], trimmed),
    };
    [dir, b"PaxHeaders.0/", base].concat().into_iter().filter(u8::is_ascii).collect()
}

/// `read`, again if interrupted.
fn read_some(src: &mut dyn Read, buf: &mut [u8]) -> io::Result<usize> {
    loop {
        match src.read(buf) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            r => return r,
        }
    }
}

#[cfg(test)]
mod tests {
    //! Unprivileged tests: everything belongs to the user running them, and
    //! opaque directories are marked `user.overlay.opaque` (the attribute
    //! the unprivileged unpack writes). `trusted.overlay.*` and other owners
    //! need root.

    use std::collections::BTreeMap;
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
    use std::os::unix::net::UnixListener;
    use std::sync::mpsc;
    use std::time::Duration;

    use nix::sys::stat::{SFlag, UtimensatFlags};
    use nix::sys::time::TimeSpec;
    use nix::unistd::{getegid, geteuid};

    use super::*;
    use crate::media::Compression;

    const MTIME: i64 = 1_600_000_000;

    /// An upper directory being made, in a temporary directory.
    struct Upper {
        tmp: tempfile::TempDir,
    }

    impl Upper {
        fn new() -> Upper {
            let tmp = tempfile::tempdir().unwrap();
            std::fs::create_dir(tmp.path().join("upper")).unwrap();
            Upper { tmp }
        }

        fn path(&self, p: &str) -> PathBuf {
            self.tmp.path().join("upper").join(p)
        }

        fn dir(&self, p: &str, mode: u32) -> &Self {
            std::fs::create_dir(self.path(p)).unwrap();
            std::fs::set_permissions(self.path(p), std::fs::Permissions::from_mode(mode)).unwrap();
            self
        }

        fn file(&self, p: &str, data: &str, mode: u32) -> &Self {
            std::fs::write(self.path(p), data).unwrap();
            std::fs::set_permissions(self.path(p), std::fs::Permissions::from_mode(mode)).unwrap();
            self
        }

        fn symlink(&self, target: &str, p: &str) -> &Self {
            std::os::unix::fs::symlink(target, self.path(p)).unwrap();
            self
        }

        fn fifo(&self, p: &str, mode: u32) -> &Self {
            nix::unistd::mkfifo(&self.path(p), Mode::from_bits_truncate(mode)).unwrap();
            std::fs::set_permissions(self.path(p), std::fs::Permissions::from_mode(mode)).unwrap();
            self
        }

        /// What overlay leaves for a deleted lower entry: a character
        /// device 0:0, mode 0 (unprivileged since Linux 5.8).
        fn whiteout(&self, p: &str) -> &Self {
            nix::sys::stat::mknod(&self.path(p), SFlag::S_IFCHR, Mode::empty(), 0).unwrap();
            self
        }

        fn hard_link(&self, from: &str, to: &str) -> &Self {
            std::fs::hard_link(self.path(from), self.path(to)).unwrap();
            self
        }

        fn xattr(&self, p: &str, name: &str, value: &[u8]) -> &Self {
            xattr::lset(&self.path(p), name, value).unwrap();
            self
        }

        /// Sets the modification time of `p` (not following a symlink).
        fn mtime(&self, p: &str, secs: i64) -> &Self {
            let t = TimeSpec::new(secs, 123_456_789);
            nix::sys::stat::utimensat(nix::fcntl::AT_FDCWD, &self.path(p), &t, &t, UtimensatFlags::NoFollowSymlink)
                .unwrap();
            self
        }

        fn diff_with(&self, options: &DiffOptions<'_>) -> Result<(Vec<u8>, DiffReport)> {
            let mut out = Vec::new();
            let report = diff(&self.path(""), &mut out, options)?;
            Ok((out, report))
        }

        fn diff(&self) -> (Vec<u8>, DiffReport) {
            self.diff_with(&DiffOptions::default()).unwrap()
        }

        /// [`diff`](Self::diff) on a thread of its own, so that a test
        /// fails rather than hangs if the diff opens a FIFO.
        fn diff_unblocked(&self) -> (Vec<u8>, DiffReport) {
            let upper = self.path("");
            let (tx, rx) = mpsc::channel();
            std::thread::spawn(move || {
                let mut out = Vec::new();
                let report = diff(&upper, &mut out, &DiffOptions::default()).map_err(|e| e.to_string());
                let _ = tx.send(report.map(|r| (out, r)));
            });
            rx.recv_timeout(Duration::from_secs(30)).expect("blocked (opening a FIFO?)").unwrap()
        }
    }

    /// An archive entry, as a reader sees it (PAX records applied).
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Entry {
        name: String,
        kind: EntryType,
        mode: u32,
        uid: u64,
        gid: u64,
        mtime: u64,
        link: Option<String>,
        data: Vec<u8>,
        /// Every PAX record of the entry.
        pax: BTreeMap<String, Vec<u8>>,
        /// The name in the ustar header itself.
        header_name: Vec<u8>,
        /// The header's user and group names.
        owner_names: (Vec<u8>, Vec<u8>),
    }

    impl Entry {
        fn xattrs(&self) -> BTreeMap<&str, &[u8]> {
            self.pax.iter().filter_map(|(k, v)| Some((k.strip_prefix("SCHILY.xattr.")?, v.as_slice()))).collect()
        }
    }

    fn read(tar: &[u8]) -> Vec<Entry> {
        let mut archive = tar::Archive::new(tar);
        let mut out = Vec::new();
        for entry in archive.entries().unwrap() {
            let mut entry = entry.unwrap();
            let pax = match entry.pax_extensions().unwrap() {
                Some(records) => records
                    .map(|r| r.unwrap())
                    .map(|r| (r.key().unwrap().to_owned(), r.value_bytes().to_vec()))
                    .collect(),
                None => BTreeMap::new(),
            };
            let pax_id = |key: &str, header: u64| {
                pax.get(key).map_or(header, |v: &Vec<u8>| std::str::from_utf8(v).unwrap().parse().unwrap())
            };
            let header = entry.header().clone();
            let mut data = Vec::new();
            entry.read_to_end(&mut data).unwrap();
            out.push(Entry {
                name: String::from_utf8(entry.path_bytes().into_owned()).unwrap(),
                kind: header.entry_type(),
                mode: header.mode().unwrap(),
                uid: pax_id("uid", header.uid().unwrap()),
                gid: pax_id("gid", header.gid().unwrap()),
                mtime: header.mtime().unwrap(),
                link: entry.link_name_bytes().map(|l| String::from_utf8(l.into_owned()).unwrap()),
                data,
                header_name: header.as_old().name.iter().copied().take_while(|&b| b != 0).collect(),
                owner_names: (
                    header.username_bytes().unwrap_or_default().to_vec(),
                    header.groupname_bytes().unwrap_or_default().to_vec(),
                ),
                pax,
            });
        }
        out
    }

    /// PAX records parsed by their lengths, as Go's archive/tar reads them
    /// (the tar crate splits them at newlines, which a value may hold).
    fn pax_records(mut data: &[u8]) -> BTreeMap<String, Vec<u8>> {
        let mut out = BTreeMap::new();
        while !data.is_empty() {
            let space = data.iter().position(|&b| b == b' ').unwrap();
            let len: usize = std::str::from_utf8(&data[..space]).unwrap().parse().unwrap();
            assert_eq!(data[len - 1], b'\n', "a record ends where its length says");
            let record = &data[space + 1..len - 1];
            let equals = record.iter().position(|&b| b == b'=').unwrap();
            out.insert(String::from_utf8(record[..equals].to_vec()).unwrap(), record[equals + 1..].to_vec());
            data = &data[len..];
        }
        out
    }

    fn names(entries: &[Entry]) -> Vec<&str> {
        entries.iter().map(|e| e.name.as_str()).collect()
    }

    fn find<'e>(entries: &'e [Entry], name: &str) -> &'e Entry {
        entries.iter().find(|e| e.name == name).unwrap_or_else(|| panic!("no {name} in {:?}", names(entries)))
    }

    #[test]
    fn writes_files_directories_links_and_fifos_depth_first_in_byte_order() {
        let u = Upper::new();
        u.dir("etc", 0o755)
            .file("etc/hostname", "box\n", 0o644)
            .dir("bin", 0o755)
            .file("bin/tool", "#!/bin/sh\n", 0o4755)
            .file("bin/group-tool", "g", 0o2711)
            .symlink("tool", "bin/link")
            .symlink("/etc/hostname", "bin/absolute")
            .symlink("/nowhere/at/all", "bin/dangling")
            .dir("tmp", 0o1777)
            .fifo("tmp/pipe", 0o640)
            // `a/`'s entries come before `a-1`: depth first, as Docker's walk.
            .dir("a", 0o750)
            .dir("a/b", 0o700)
            .file("a/b/deep", "deep down", 0o600)
            .file("a-1", "", 0o444);
        let all = [
            "a",
            "a/b",
            "a/b/deep",
            "a-1",
            "bin",
            "bin/absolute",
            "bin/dangling",
            "bin/group-tool",
            "bin/link",
            "bin/tool",
            "etc",
            "etc/hostname",
            "tmp",
            "tmp/pipe",
        ];
        for (i, p) in all.iter().enumerate() {
            u.mtime(p, MTIME + i as i64);
        }

        let (tar, report) = u.diff_unblocked();
        let entries = read(&tar);
        assert_eq!(
            names(&entries),
            [
                "a/",
                "a/b/",
                "a/b/deep",
                "a-1",
                "bin/",
                "bin/absolute",
                "bin/dangling",
                "bin/group-tool",
                "bin/link",
                "bin/tool",
                "etc/",
                "etc/hostname",
                "tmp/",
                "tmp/pipe",
            ]
        );
        let kind = |name: &str| find(&entries, name).kind;
        for dir in ["a/", "a/b/", "bin/", "etc/", "tmp/"] {
            assert_eq!(kind(dir), EntryType::Directory, "{dir}");
        }
        for file in ["a/b/deep", "a-1", "bin/group-tool", "bin/tool", "etc/hostname"] {
            assert_eq!(kind(file), EntryType::Regular, "{file}");
        }
        assert_eq!(kind("tmp/pipe"), EntryType::Fifo);
        for (link, target) in
            [("bin/link", "tool"), ("bin/absolute", "/etc/hostname"), ("bin/dangling", "/nowhere/at/all")]
        {
            let e = find(&entries, link);
            assert_eq!((e.kind, e.link.as_deref(), e.mode), (EntryType::Symlink, Some(target), 0o777), "{link}");
        }
        let mode = |name: &str| find(&entries, name).mode;
        assert_eq!(
            [mode("bin/tool"), mode("bin/group-tool"), mode("tmp/"), mode("a/"), mode("a-1"), mode("tmp/pipe")],
            [0o4755, 0o2711, 0o1777, 0o750, 0o444, 0o640]
        );
        assert_eq!(find(&entries, "etc/hostname").data, b"box\n");
        assert_eq!(find(&entries, "a/b/deep").data, b"deep down");
        let (uid, gid) = (u64::from(geteuid().as_raw()), u64::from(getegid().as_raw()));
        for (i, p) in all.iter().enumerate() {
            let e = entries.iter().find(|e| e.name.trim_end_matches('/') == *p).unwrap();
            assert_eq!(e.mtime, (MTIME + i as i64) as u64, "{p}: whole seconds");
            assert_eq!((e.uid, e.gid), (uid, gid), "{p}");
            assert_eq!(e.owner_names, (vec![], vec![]), "{p}: no user or group names");
            assert!(e.pax.is_empty(), "{p}: {:?}", e.pax);
        }
        assert_eq!(
            report,
            DiffReport {
                entries: all.len() as u64,
                bytes: (4 + 10 + 1 + 9) as u64,
                whiteouts: 0,
                opaque_dirs: 0,
                skipped: vec![],
                diff_id: Some(Digest::of(&tar)),
                tar_size: tar.len() as u64,
            }
        );
        // ustar headers; the archive ends with two zero blocks.
        assert_eq!(&tar[257..265], b"ustar\x0000");
        assert!(tar.ends_with(&[0; 1024]));
        assert_eq!(tar.len() % 512, 0);
    }

    #[test]
    fn whiteouts_and_opaque_directories_become_markers() {
        let u = Upper::new();
        u.dir("tmp", 0o1777)
            .whiteout("tmp/old")
            .dir("var", 0o755)
            .dir("var/cache", 0o700)
            .xattr("var/cache", USER_OPAQUE_XATTR, b"y")
            .file("var/cache/new", "n", 0o644)
            .file("var/cache/-first", "f", 0o644)
            // `x` isn't opaque (overlay: "has whiteouts below"), and the
            // attribute itself is overlay's, never stored.
            .dir("var/log", 0o755)
            .xattr("var/log", USER_OPAQUE_XATTR, b"x");
        let (tar, report) = u.diff();
        let entries = read(&tar);
        assert_eq!(
            names(&entries),
            [
                "tmp/",
                "tmp/.wh.old",
                "var/",
                "var/cache/",
                "var/cache/.wh..wh..opq",
                "var/cache/-first",
                "var/cache/new",
                "var/log/",
            ],
            "the opaque marker comes right after its directory"
        );
        for marker in ["tmp/.wh.old", "var/cache/.wh..wh..opq"] {
            let e = find(&entries, marker);
            assert_eq!(
                (e.kind, e.mode, e.uid, e.gid, e.mtime, e.data.len()),
                (EntryType::Regular, 0o600, 0, 0, 0, 0),
                "{marker}"
            );
        }
        for dir in ["var/cache/", "var/log/"] {
            assert!(find(&entries, dir).xattrs().is_empty(), "{dir}: overlay's attributes stay out");
        }
        assert_eq!((report.whiteouts, report.opaque_dirs, report.entries), (1, 1, 8));
    }

    #[test]
    fn a_whiteout_with_several_names_stays_a_whiteout_under_each() {
        // Overlay makes every whiteout a hard link to one inode.
        let u = Upper::new();
        u.whiteout("gone")
            .hard_link("gone", "also-gone")
            .dir("sub", 0o755)
            .hard_link("gone", "sub/gone-too")
            .file("file", "x", 0o644)
            .hard_link("file", "sub/file-too");
        let (tar, report) = u.diff();
        let entries = read(&tar);
        assert_eq!(names(&entries), [".wh.also-gone", "file", ".wh.gone", "sub/", "sub/file-too", "sub/.wh.gone-too"]);
        for marker in [".wh.also-gone", ".wh.gone", "sub/.wh.gone-too"] {
            assert_eq!(
                (find(&entries, marker).kind, find(&entries, marker).link.as_deref()),
                (EntryType::Regular, None)
            );
        }
        // Other files with several names are links to the first.
        let link = find(&entries, "sub/file-too");
        assert_eq!((link.kind, link.link.as_deref(), link.data.len()), (EntryType::Link, Some("file"), 0));
        assert_eq!(report.whiteouts, 3);
    }

    #[test]
    fn hard_links_point_at_the_first_name_written() {
        let u = Upper::new();
        u.dir("b", 0o755)
            .dir("a", 0o755)
            .file("b/one", "three names", 0o640)
            .hard_link("b/one", "a/two")
            .hard_link("b/one", "c")
            .symlink("target", "s1")
            .hard_link("s1", "s2")
            .fifo("p1", 0o600)
            .hard_link("p1", "p2");
        let (tar, report) = u.diff_unblocked();
        let entries = read(&tar);
        assert_eq!(names(&entries), ["a/", "a/two", "b/", "b/one", "c", "p1", "p2", "s1", "s2"]);
        let first = find(&entries, "a/two");
        assert_eq!((first.kind, first.data.as_slice(), first.mode), (EntryType::Regular, &b"three names"[..], 0o640));
        for (name, target) in [("b/one", "a/two"), ("c", "a/two"), ("p2", "p1"), ("s2", "s1")] {
            let e = find(&entries, name);
            assert_eq!((e.kind, e.link.as_deref(), e.data.len()), (EntryType::Link, Some(target), 0), "{name}");
        }
        assert_eq!(find(&entries, "s1").link.as_deref(), Some("target"));
        assert_eq!(report.bytes, 11, "the content once");
    }

    #[test]
    fn extended_attributes_are_kept_but_not_overlays_own() {
        let u = Upper::new();
        u.file("file", "x", 0o644)
            .xattr("file", "user.foo", b"bar")
            .xattr("file", "user.binary", b"\0=\xff")
            .xattr("file", "user.overlay.origin", b"o")
            .dir("dir", 0o755)
            .xattr("dir", "user.dir", b"d")
            .xattr("dir", "user.overlay.impure", b"y");
        let (tar, _) = u.diff();
        let entries = read(&tar);
        let file = find(&entries, "file");
        assert_eq!(
            file.xattrs(),
            BTreeMap::from([("user.binary", &b"\0=\xff"[..]), ("user.foo", &b"bar"[..])]),
            "values are binary-safe"
        );
        assert_eq!(find(&entries, "dir/").xattrs(), BTreeMap::from([("user.dir", &b"d"[..])]));
        assert_eq!(file.data, b"x");
    }

    #[test]
    fn owners_and_the_ids_in_acls_go_through_map_owner() {
        let u = Upper::new();
        u.dir("dir", 0o755).file("dir/file", "x", 0o640).symlink("file", "dir/link");
        // A POSIX ACL naming user 4242 and group 4343.
        let acl = |user: u32, group: u32| {
            let mut v = 2u32.to_le_bytes().to_vec();
            for (tag, perm, id) in [
                (1u16, 6u16, u32::MAX),
                (2, 4, user),
                (4, 4, u32::MAX),
                (8, 4, group),
                (0x10, 4, u32::MAX),
                (0x20, 0, u32::MAX),
            ] {
                v.extend_from_slice(&tag.to_le_bytes());
                v.extend_from_slice(&perm.to_le_bytes());
                v.extend_from_slice(&id.to_le_bytes());
            }
            v
        };
        let acls = xattr::lset(&u.path("dir/file"), "system.posix_acl_access", &acl(4242, 4343)).is_ok();
        let (me, my_group) = (geteuid().as_raw(), getegid().as_raw());
        // Our own ids go far up (past what a ustar header holds); others by one.
        let map = |uid: u32, gid: u32| {
            (if uid == me { 3_000_000 } else { uid + 1 }, if gid == my_group { 7 } else { gid + 1 })
        };
        let (tar, _) = u.diff_with(&DiffOptions { skip: &[], map_owner: &map }).unwrap();
        let entries = read(&tar);
        for name in ["dir/", "dir/file", "dir/link"] {
            let e = find(&entries, name);
            assert_eq!((e.uid, e.gid), (3_000_000, 7), "{name}");
            assert_eq!(e.pax.get("uid").map(Vec::as_slice), Some(&b"3000000"[..]), "{name}: a PAX record");
            assert!(!e.pax.contains_key("gid"), "{name}: 7 fits the header");
        }
        if acls {
            assert_eq!(find(&entries, "dir/file").xattrs()["system.posix_acl_access"], acl(4243, 4344));
        }
        assert_eq!(unmap_remap(1_000_000, 1_000_101), (0, 101));
        assert_eq!(unmap_remap(0, 1_065_536), (65534, 65534));
    }

    #[test]
    fn long_names_and_link_targets_go_in_pax_records() {
        let u = Upper::new();
        let long_dir = "d".repeat(99); // with its `/`, exactly 100 bytes: fits
        let longer = "e".repeat(120);
        let target = format!("/{}", "t/".repeat(80));
        u.dir(&long_dir, 0o755)
            .dir(&format!("{long_dir}/{longer}"), 0o755)
            .file(&format!("{long_dir}/{longer}/file"), "x", 0o644)
            .symlink(&target, "link");
        let (tar, _) = u.diff();
        let entries = read(&tar);
        let dir = find(&entries, &format!("{long_dir}/"));
        assert!(dir.pax.is_empty());
        let nested = find(&entries, &format!("{long_dir}/{longer}/"));
        assert_eq!(nested.pax["path"], format!("{long_dir}/{longer}/").as_bytes());
        assert_eq!(nested.header_name, long_dir.as_bytes(), "cut at 100 bytes, without the `/`");
        let file = find(&entries, &format!("{long_dir}/{longer}/file"));
        assert_eq!(file.data, b"x");
        let link = find(&entries, "link");
        assert_eq!(link.link.as_deref(), Some(target.as_str()));
        assert_eq!(link.pax.keys().collect::<Vec<_>>(), ["linkpath"]);
        // A cut name never ends in `/`.
        let mut field = [0u8; 10];
        assert!(!put_name(&mut field, b"abcdefghi//jk"));
        assert_eq!(&field, b"abcdefghi\0");
        assert_eq!(pax_name(b"a/b/c/"), b"a/b/PaxHeaders.0/c");
        assert_eq!(pax_name("é".as_bytes()), b"PaxHeaders.0/");
    }

    #[test]
    fn pax_records_carry_what_the_header_cannot() {
        let mut out = Vec::new();
        let mut tar = TarWriter::new(&mut out);
        let xattrs = [("user.a".to_owned(), vec![b'v'; 300]), ("user.nl".to_owned(), b"a\nb=c".to_vec())];
        let header = EntryHeader {
            name: b"f",
            kind: EntryType::Regular,
            mode: 0o644,
            uid: MAX_ID,
            gid: MAX_ID + 1,
            mtime: -5,
            size: MAX_SIZE + 1,
            link: b"",
            xattrs: &xattrs,
        };
        tar.header(&header).unwrap();
        drop(tar);
        // Only the headers: 8 GiB of data won't do for a test.
        let extended = tar::Header::from_byte_slice(&out[..512]);
        assert_eq!(extended.entry_type(), EntryType::XHeader);
        let data_len = extended.size().unwrap() as usize;
        let pax = pax_records(&out[512..512 + data_len]);
        assert_eq!(pax["gid"], format!("{}", MAX_ID + 1).as_bytes());
        assert_eq!(pax["size"], format!("{}", MAX_SIZE + 1).as_bytes());
        assert_eq!(pax["mtime"], b"-5");
        assert_eq!(pax["SCHILY.xattr.user.a"], vec![b'v'; 300]);
        assert_eq!(pax["SCHILY.xattr.user.nl"], b"a\nb=c", "a value is binary, newlines included");
        assert!(!pax.contains_key("uid"), "{MAX_ID} fits");
        let main = tar::Header::from_byte_slice(&out[512 + data_len.div_ceil(512) * 512..][..512]);
        assert_eq!((main.uid().unwrap(), main.gid().unwrap(), main.size().unwrap()), (u64::from(MAX_ID), 0, 0));
        assert_eq!(main.mtime().unwrap(), 0);
    }

    #[test]
    fn the_same_upper_makes_the_same_bytes() {
        let u = Upper::new();
        u.dir("z", 0o755).file("z/a", "a", 0o644).file("b", "b", 0o600).whiteout("c").symlink("b", "d");
        u.xattr("b", "user.two", b"2").xattr("b", "user.one", b"1");
        let (first, _) = u.diff();
        // Reading moved the access times, which no header holds.
        std::fs::read(u.path("z/a")).unwrap();
        let (second, _) = u.diff();
        assert_eq!(first, second);
        assert_eq!(
            find(&read(&first), "b").pax.keys().collect::<Vec<_>>(),
            ["SCHILY.xattr.user.one", "SCHILY.xattr.user.two"],
            "records sorted"
        );
    }

    /// Everything below `root`, as unpacking should recreate it: per path,
    /// its type, mode, size, content or target, time, attributes and which
    /// earlier path it is a hard link of.
    fn tree(root: &Path) -> BTreeMap<String, String> {
        let mut out = BTreeMap::new();
        let mut seen: HashMap<u64, String> = HashMap::new();
        let mut todo = vec![root.to_owned()];
        while let Some(dir) = todo.pop() {
            let mut names: Vec<_> = std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().path()).collect();
            names.sort();
            for path in names {
                let rel = path.strip_prefix(root).unwrap().to_string_lossy().into_owned();
                let m = std::fs::symlink_metadata(&path).unwrap();
                let t = m.file_type();
                let what = if t.is_dir() {
                    todo.push(path.clone());
                    "dir".to_owned()
                } else if t.is_symlink() {
                    format!("symlink {:?}", std::fs::read_link(&path).unwrap())
                } else if t.is_fifo() {
                    "fifo".to_owned()
                } else if t.is_char_device() {
                    format!("char {}", m.rdev())
                } else {
                    format!("file {:?}", String::from_utf8_lossy(&std::fs::read(&path).unwrap()))
                };
                let link = match seen.get(&m.ino()) {
                    Some(first) if !t.is_dir() && !t.is_char_device() => format!(" = {first}"),
                    _ => {
                        seen.insert(m.ino(), rel.clone());
                        String::new()
                    }
                };
                let mut attrs: Vec<_> = xattr::llist(&path)
                    .unwrap_or_default()
                    .into_iter()
                    .map(|n| format!("{n}={:?}", xattr::lget(&path, &n).unwrap()))
                    .collect();
                attrs.sort();
                // A symlink's mode is always 0777, its time is kept.
                let mode = m.permissions().mode() & 0o7777;
                let time = if t.is_char_device() { 0 } else { m.mtime() };
                out.insert(rel, format!("{what} {mode:o} t={time} {attrs:?}{link}"));
            }
        }
        out
    }

    #[test]
    fn a_layer_unpacks_back_into_the_same_tree() {
        let u = Upper::new();
        let long = "l".repeat(150);
        u.dir("etc", 0o755)
            .file("etc/passwd", "root:x:0:0::/root:/bin/sh\n", 0o644)
            .dir("bin", 0o755)
            .file("bin/su", "setuid", 0o4755)
            .file("bin/x", "xx", 0o700)
            .hard_link("bin/x", "etc/x-link")
            .symlink("/bin/su", "bin/sudo")
            .symlink(&long, "bin/far")
            .dir("tmp", 0o1777)
            .fifo("tmp/pipe", 0o620)
            .whiteout("tmp/deleted")
            .dir("var", 0o755)
            .dir("var/lib", 0o755)
            .xattr("var/lib", USER_OPAQUE_XATTR, b"y")
            .file("var/lib/state", "s", 0o600)
            .xattr("var/lib/state", "user.note", b"hello")
            .dir(&long, 0o755)
            .file(&format!("{long}/{long}"), "deep and long", 0o644);
        for p in [
            "etc/passwd",
            "bin/su",
            "bin/x",
            "bin/sudo",
            "tmp/pipe",
            "var/lib/state",
            "etc",
            "bin",
            "tmp",
            "var/lib",
            "var",
            long.as_str(),
        ] {
            u.mtime(p, MTIME);
        }
        let (tar, report) = u.diff_unblocked();
        assert_eq!((report.whiteouts, report.opaque_dirs), (1, 1));

        let dest = tempfile::tempdir().unwrap();
        let fd = nix::fcntl::open(dest.path(), OFlag::O_RDONLY | OFlag::O_DIRECTORY, Mode::empty()).unwrap();
        let unpacked = crate::unpack::unpack(&tar[..], Compression::None, fd.as_fd()).unwrap();
        assert_eq!(unpacked.diff_id, report.diff_id);
        assert_eq!((unpacked.whiteouts, unpacked.opaque_dirs), (1, 1));
        assert!(unpacked.dropped_xattrs.is_empty(), "{:?}", unpacked.dropped_xattrs);
        assert_eq!(tree(dest.path()), tree(&u.path("")));
    }

    #[test]
    fn skipped_paths_devices_and_sockets_are_left_out() {
        let u = Upper::new();
        u.dir("proc", 0o755)
            .file("proc/cpuinfo", "fake", 0o444)
            .dir("etc", 0o755)
            .file("etc/hosts", "127.0.0.1 localhost\n", 0o644)
            .file("etc/resolv.conf", "", 0o644)
            .dir("data", 0o755)
            .dir("data/sub", 0o755)
            .file("data/sub/x", "x", 0o644)
            .dir("run", 0o755)
            // A container's own `.wh.` name: in a layer, it would delete `x`.
            .file(".wh.x", "", 0o644)
            .dir("dir", 0o755)
            .file("dir/.wh..wh..opq", "", 0o644);
        let _socket = UnixListener::bind(u.path("run/sock")).unwrap();
        let skip = [
            PathBuf::from("/proc"),
            PathBuf::from("/etc/resolv.conf"),
            PathBuf::from("//data/./sub/"),
            PathBuf::from("/missing"),
            PathBuf::from("/etc/../dir/nothing"),
        ];
        let (tar, report) = u.diff_with(&DiffOptions { skip: &skip, ..DiffOptions::default() }).unwrap();
        // `data/` held only a skipped path: left out with it.
        assert_eq!(names(&read(&tar)), ["dir/", "etc/", "etc/hosts", "run/"]);
        assert_eq!(
            report.skipped,
            ["/.wh.x", "/data/sub", "/data", "/dir/.wh..wh..opq", "/etc/resolv.conf", "/proc", "/run/sock"]
        );
        assert_eq!(report.entries, 4);

        // A mount on `/`: nothing is the container's.
        let (tar, report) =
            u.diff_with(&DiffOptions { skip: &[PathBuf::from("/")], ..DiffOptions::default() }).unwrap();
        assert!(read(&tar).is_empty());
        assert_eq!(report.skipped, ["/"]);
    }

    #[test]
    fn directories_made_only_for_mount_points_are_left_out() {
        let u = Upper::new();
        // /etc copied up for the runtime's /etc/resolv.conf; a volume's
        // target and the parents the runtime made for it; an empty
        // directory of the container's own; an opaque one whose only entry
        // is a mount point.
        u.dir("etc", 0o755)
            .file("etc/resolv.conf", "", 0o644)
            .dir("a", 0o755)
            .dir("a/b", 0o755)
            .dir("a/b/target", 0o755)
            .dir("empty", 0o755)
            .dir("opaque", 0o755)
            .xattr("opaque", USER_OPAQUE_XATTR, b"y")
            .file("opaque/hosts", "", 0o644);
        let skip = [PathBuf::from("/etc/resolv.conf"), PathBuf::from("/a/b/target"), PathBuf::from("/opaque/hosts")];
        let (tar, report) = u.diff_with(&DiffOptions { skip: &skip, ..DiffOptions::default() }).unwrap();
        assert_eq!(names(&read(&tar)), ["empty/", "opaque/", "opaque/.wh..wh..opq"]);
        for gone in ["/etc", "/a/b", "/a"] {
            assert!(report.skipped.iter().any(|s| s == gone), "{gone}: {:?}", report.skipped);
        }
        // Nothing else: an empty layer, as a RUN that changes nothing.
        let (tar, _) = Upper::new()
            .dir("etc", 0o755)
            .file("etc/resolv.conf", "", 0o644)
            .diff_with(&DiffOptions { skip: &skip, ..DiffOptions::default() })
            .unwrap();
        assert!(read(&tar).is_empty());
    }

    #[test]
    fn symlinks_are_stored_never_followed() {
        let u = Upper::new();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret"), "host file").unwrap();
        u.symlink(outside.path().to_str().unwrap(), "escape").symlink("../../../..", "up");
        let (tar, _) = u.diff();
        let entries = read(&tar);
        assert_eq!(names(&entries), ["escape", "up"]);
        assert!(entries.iter().all(|e| e.kind == EntryType::Symlink && e.data.is_empty()));
    }

    #[test]
    fn an_entry_replaced_during_the_walk_is_refused_never_followed() {
        let u = Upper::new();
        let victim = u.tmp.path().join("victim");
        std::fs::write(&victim, "host file").unwrap();
        u.file("file", "mine", 0o644).file("other", "other", 0o644).dir("dir", 0o755);
        let root = nix::fcntl::open(&u.path(""), OFlag::O_RDONLY | OFlag::O_DIRECTORY, Mode::empty()).unwrap();
        let stat = |name: &str| nix::sys::stat::fstatat(&root, name, AtFlags::AT_SYMLINK_NOFOLLOW).unwrap();
        let (file, dir) = (stat("file"), stat("dir"));
        // Between the stat and the open, a symlink takes the file's place…
        std::fs::remove_file(u.path("file")).unwrap();
        u.symlink(victim.to_str().unwrap(), "file");
        let err = open_checked(root.as_fd(), OsStr::new("file"), &file, "\"/file\"").unwrap_err();
        assert_eq!(err.errno(), Some(Errno::ELOOP), "{err}");
        // …or another file, or a symlink to a directory.
        std::fs::rename(u.path("other"), u.path("file")).unwrap();
        let err = open_checked(root.as_fd(), OsStr::new("file"), &file, "\"/file\"").unwrap_err();
        assert!(err.to_string().contains("replaced"), "{err}");
        std::fs::remove_dir(u.path("dir")).unwrap();
        u.symlink(u.tmp.path().to_str().unwrap(), "dir");
        assert!(open_checked(root.as_fd(), OsStr::new("dir"), &dir, "\"/dir\"").is_err());
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "host file");
    }

    #[test]
    fn a_file_whose_size_changes_while_read_is_an_error() {
        for (data, size) in [(&b"abc"[..], 5), (&b"abcdef"[..], 5)] {
            let mut out = Vec::new();
            let mut tar = TarWriter::new(&mut out);
            let err = tar.data(&mut &data[..], size, "\"/f\"").unwrap_err().to_string();
            assert!(err.contains("size changed"), "{err}");
        }
    }

    #[test]
    fn a_deep_tree_is_written() {
        const DEPTH: usize = 300;
        let u = Upper::new();
        let deep: PathBuf = std::iter::repeat_n("d", DEPTH).collect();
        std::fs::create_dir_all(u.path("").join(&deep)).unwrap();
        std::fs::write(u.path("").join(&deep).join("leaf"), "at the bottom").unwrap();
        let (tar, report) = u.diff();
        assert_eq!(report.entries, DEPTH as u64 + 1);
        let entries = read(&tar);
        assert_eq!(entries.last().unwrap().name, format!("{}/leaf", deep.display()));
    }

    #[test]
    fn commit_layer_stores_the_gzipped_archive() {
        let u = Upper::new();
        u.dir("app", 0o755).file("app/main", "print('hi')\n", 0o644).whiteout("gone");
        let dir = tempfile::tempdir().unwrap();
        let content =
            ContentStore::open(dir.path().join("content"), dir.path().join("ingest"), dir.path().join("lock")).unwrap();
        let layer = commit_layer(&content, &u.path(""), &DiffOptions::default()).unwrap();
        let digest = Digest::from_oci(layer.descriptor.digest()).unwrap();
        assert_eq!(layer.descriptor.media_type().to_string(), media::OCI_LAYER_GZIP);
        let blob = std::fs::read(content.blob_path(&digest)).unwrap();
        assert_eq!((Digest::of(&blob), blob.len() as u64), (digest, layer.descriptor.size()));
        let mut tar = Vec::new();
        flate2::read::GzDecoder::new(&blob[..]).read_to_end(&mut tar).unwrap();
        assert_eq!(Digest::of(&tar), layer.diff_id);
        assert_eq!(layer.report.diff_id.as_ref(), Some(&layer.diff_id));
        assert_eq!(tar, u.diff().0, "the same archive as diff writes");
        assert_eq!(names(&read(&tar)), ["app/", "app/main", ".wh.gone"]);
        assert_eq!(std::fs::read_dir(dir.path().join("ingest")).unwrap().count(), 0, "nothing left behind");

        // Twice: the same blob.
        let again = commit_layer(&content, &u.path(""), &DiffOptions::default()).unwrap();
        assert_eq!(again.descriptor, layer.descriptor);
    }
}

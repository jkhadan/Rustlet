//! Copy-up: an empty volume gets the image's files.
//!
//! When a container mounts a volume that is empty over a path where its
//! image has files (`-v data:/var/lib/postgresql/data`, or the image's own
//! `VOLUME`), Docker first copies those files into the volume, so the
//! program finds what its image put there, and from then on it lives in the
//! volume. The daemon does the same at each start, while the container's
//! root filesystem is mounted but no container process exists yet.
//!
//! The source is image content (and the container's own changes): it is
//! untrusted, and the daemon is root. So the copy is made the way unpacking
//! is (`unpack`):
//!
//! - **the source directory** is resolved inside the root filesystem
//!   (`openat2(RESOLVE_IN_ROOT)`: a symlink such as `/var/run → /run`
//!   leads to the container's `/run`, never the host's);
//! - **below it, nothing is followed**: every entry is examined with
//!   `AT_SYMLINK_NOFOLLOW` and opened with `O_NOFOLLOW` relative to its
//!   parent's fd, so a symlink is copied as a symlink, whatever it points
//!   to;
//! - **the destination** is written only through fds below the volume's
//!   own directory, each entry created exclusively (`O_EXCL`, `mkdirat`,
//!   `symlinkat`, `mknodat`), never through a path;
//! - **kept**: contents, owner (translated by `map_owner`), mode (after
//!   the owner: `chown` clears setuid bits), extended attributes (after the
//!   owner: `chown` clears `security.capability`; overlay's own
//!   `trusted.overlay.*`/`user.overlay.*` are skipped), access and
//!   modification times (directories' last, after their contents), hard
//!   links between files of the copied tree, FIFOs;
//! - **skipped** (and listed): device nodes and sockets;
//! - the volume's directory itself takes the source directory's owner and
//!   mode (Docker's `copyOwnership`).
//!
//! The walk uses its own stack, not recursion, so a deep tree can't
//! exhaust the daemon's thread stack.
//!
//! ## In detail
//!
//! A directory's names are read when the walk enters it, and copied in
//! sorted order, so a tree is always copied the same way. Each level of the
//! stack holds two fds, the directory and its copy, which is why the depth
//! is capped (4096 levels). A directory's copy is made `0700`, and gets its
//! owner, mode, attributes and times once everything in it is done: a
//! default ACL set any earlier would give the copies made in it ACLs their
//! sources don't have.
//!
//! A source entry is opened only when `fstatat` has said it is a regular
//! file or a directory, and the fd must then be that same inode. The flags
//! are GNU tar's: `O_NOFOLLOW`, and `O_NONBLOCK` and `O_NOCTTY`, so that a
//! FIFO or a terminal put in its place could neither block the open nor
//! become the daemon's terminal before the check refuses it. A FIFO is
//! never opened (a reader waits for a writer): its attributes, like a
//! symlink's, are read by name. Its copy is opened, without blocking, so
//! that its owner and mode are set through an fd rather than a name that
//! another container sharing the volume could swap for something else.
//! Only a symlink's metadata has to be set by name (without following it):
//! a symlink can't be opened for I/O.
//!
//! The copy of an inode with more than one name stays open until all its
//! names are seen, and the later names are links to that fd
//! (`linkat(AT_EMPTY_PATH)`): to exactly the inode made for the first one,
//! whatever has happened to that name since.
//!
//! Owners aren't the only ids an idmapped root filesystem shows shifted.
//! So are the root a file capability belongs to (revision 3 of
//! `security.capability` names it) and the users and groups an ACL names.
//! `map_owner` translates those too: copied as they read, they would name
//! ids that the volume's idmapped mount in the container doesn't map, and
//! the capabilities and ACL entries would apply to no one.

use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use nix::fcntl::{AtFlags, OFlag};
use nix::sys::stat::{FileStat, Mode, UtimensatFlags};
use nix::sys::time::TimeSpec;
use nix::unistd::{Gid, Uid};
use rustlet_sys::Errno;
use rustlet_sys::fs::{ResolveFlags, openat2};
use rustlet_sys::xattr;

use crate::error::{Context, Error, Result};

/// How `path` is resolved: inside the root filesystem, as `open_in_root` does.
const RESOLVE: ResolveFlags = ResolveFlags::IN_ROOT.union(ResolveFlags::NO_MAGICLINKS);
/// How many levels below the copied directory the tree may go.
const MAX_DEPTH: usize = 4096;
/// Attribute namespaces overlayfs keeps for itself.
const OVERLAY_XATTRS: [&str; 2] = ["trusted.overlay.", "user.overlay."];

/// File capabilities. Revision 3 (`struct vfs_ns_cap_data`, 24 bytes) ends
/// with the id of the root they apply under; revision 2 means the initial
/// user namespace's.
const CAPS_XATTR: &str = "security.capability";
const CAPS_REVISION_MASK: u32 = 0xff00_0000;
const CAPS_REVISION_3: u32 = 0x0300_0000;
const CAPS_V3_LEN: usize = 24;
/// POSIX ACLs as attributes: a version, then entries of a tag (`u16`),
/// permissions (`u16`) and an id (`u32`), which only named users and
/// groups use.
const ACL_XATTRS: [&str; 2] = ["system.posix_acl_access", "system.posix_acl_default"];
const ACL_VERSION: u32 = 2;
const ACL_USER: u16 = 0x02;
const ACL_GROUP: u16 = 0x08;

/// What a copy-up did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CopyUp {
    /// False: the root filesystem has no directory at that path, so there
    /// was nothing to copy.
    pub copied: bool,
    /// Entries created below the volume's directory.
    pub entries: u64,
    /// Bytes of file content copied.
    pub bytes: u64,
    /// Device nodes and sockets left out, relative to the copied directory.
    pub skipped: Vec<PathBuf>,
}

/// Copies the directory at `path` (absolute, in the container) of the root
/// filesystem `root` into `dest`, the volume's directory, which should be
/// empty ([`is_empty`]; an entry that already exists there is an error).
/// `map_owner` turns owners as seen through `root` into those to write
/// (the identity, except under `--userns=remap`, whose idmapped root
/// filesystem shows the image's owners shifted by 1000000 while volumes
/// hold them unshifted). An error takes back what the copy made at the
/// top of `dest`, and only that: another container sharing the volume may
/// have written there meanwhile (an entry it made first is the usual
/// error), and its files stay.
pub fn copy_up(
    root: BorrowedFd<'_>,
    path: &Path,
    dest: BorrowedFd<'_>,
    map_owner: &dyn Fn(u32, u32) -> (u32, u32),
) -> Result<CopyUp> {
    // Otherwise every path would fail with ENOTDIR, which reads as nothing
    // to copy.
    let st = nix::sys::stat::fstat(root).context("stat the root filesystem")?;
    if st.st_mode & libc::S_IFMT != libc::S_IFDIR {
        return Err(Error::invalid("the root filesystem is not a directory"));
    }
    let src = match openat2(Some(root), path, OFlag::O_RDONLY | OFlag::O_DIRECTORY, Mode::empty(), RESOLVE) {
        Ok(fd) => fd,
        // Nothing to copy. (Whether a volume can be mounted there is for
        // the mount to say.)
        Err(Errno::ENOENT | Errno::ENOTDIR) => return Ok(CopyUp::default()),
        Err(e) => return Err(e).with_context(|| format!("open {path:?} in the root filesystem")),
    };
    let st = nix::sys::stat::fstat(&src).with_context(|| format!("stat {path:?}"))?;
    let dst = nix::fcntl::openat(dest, ".", OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC, Mode::empty())
        .context("open the volume's directory")?;
    let mut copier = Copier {
        path,
        map_owner,
        report: CopyUp { copied: true, ..CopyUp::default() },
        links: HashMap::new(),
        made: Vec::new(),
    };
    let copied = copier.tree(src, dst, st);
    if copied.is_err() {
        for name in &copier.made {
            if let Err(e) = rustlet_sys::tree::remove_tree_at(dest, name) {
                tracing::warn!("copy-up into a volume failed, and its {name:?} could not be removed: {e}");
            }
        }
    }
    copied.map(|()| copier.report)
}

impl Copier<'_> {
    /// The walk: `src` copied into `dst`, then `dst` given `st`'s owner and
    /// mode.
    fn tree(&mut self, src: OwnedFd, dst: OwnedFd, st: FileStat) -> Result<()> {
        let mut stack = vec![self.frame(src, dst, PathBuf::new(), st)?];
        while let Some(dir) = stack.last_mut() {
            let Some(name) = dir.names.next() else {
                let done = stack.pop().expect("the loop just looked at it");
                if stack.is_empty() {
                    self.volume(&done)?
                } else {
                    self.finish(&done)?
                }
                continue;
            };
            if let Some(sub) = self.entry(dir, &name)? {
                if stack.len() > MAX_DEPTH {
                    return Err(Error::unsupported(format!("{:?}: more than {MAX_DEPTH} levels deep", self.path)));
                }
                stack.push(sub);
            }
        }
        Ok(())
    }
}

/// Has the directory `dir` no entries (other than `.` and `..`)?
pub fn is_empty(dir: BorrowedFd<'_>) -> Result<bool> {
    let mut listing = listing(dir).context("open the directory")?;
    for entry in listing.iter() {
        let entry = entry.context("list the directory")?;
        if !matches!(entry.file_name().to_bytes(), b"." | b"..") {
            return Ok(false);
        }
    }
    Ok(true)
}

/// A directory being copied: its entries are copied in turn, then its own
/// metadata is set.
struct Frame {
    /// The source directory and its copy, both open for reading.
    src: OwnedFd,
    dst: OwnedFd,
    /// The entries still to copy.
    names: std::vec::IntoIter<OsString>,
    /// Its path below the copied directory.
    rel: PathBuf,
    st: FileStat,
}

/// The copy of an inode with more than one name, for its later names.
struct Linked {
    copy: OwnedFd,
    rel: PathBuf,
    /// Names of the source inode not seen yet. Names outside the copied
    /// directory are never seen: such an entry stays to the end.
    remaining: u64,
}

struct Copier<'a> {
    /// The copied directory's path in the container, which messages name
    /// entries by.
    path: &'a Path,
    map_owner: &'a dyn Fn(u32, u32) -> (u32, u32),
    report: CopyUp,
    /// Inodes with more than one name, by the source's `(st_dev, st_ino)`.
    links: HashMap<(u64, u64), Linked>,
    /// The entries made at the top of the volume, which a failed copy
    /// removes.
    made: Vec<OsString>,
}

impl Copier<'_> {
    /// `name` was just made in `dir`: if that is the volume's own directory,
    /// it is the copy's to take back.
    fn made(&mut self, dir: &Frame, name: &OsStr) {
        if dir.rel.as_os_str().is_empty() {
            self.made.push(name.to_owned());
        }
    }

    /// An entry as messages name it: its path in the container.
    fn shown(&self, rel: &Path) -> String {
        // (`join("")` would add a trailing slash.)
        if rel.as_os_str().is_empty() { format!("{:?}", self.path) } else { format!("{:?}", self.path.join(rel)) }
    }

    /// A directory and its copy, with its names read.
    fn frame(&self, src: OwnedFd, dst: OwnedFd, rel: PathBuf, st: FileStat) -> Result<Frame> {
        let names = entries(src.as_fd()).with_context(|| format!("{}: list it", self.shown(&rel)))?;
        Ok(Frame { src, dst, names: names.into_iter(), rel, st })
    }

    /// Copies the entry `name` of `dir`. A directory is only made, and
    /// returned for the walk to enter.
    fn entry(&mut self, dir: &Frame, name: &OsStr) -> Result<Option<Frame>> {
        let rel = dir.rel.join(name);
        let shown = self.shown(&rel);
        let st = nix::sys::stat::fstatat(&dir.src, name, AtFlags::AT_SYMLINK_NOFOLLOW)
            .with_context(|| format!("{shown}: stat"))?;
        let kind = st.st_mode & libc::S_IFMT;
        if kind == libc::S_IFDIR {
            return self.directory(dir, name, rel, st, &shown).map(Some);
        }
        if st.st_nlink > 1 && self.link(dir, name, &st, &shown)? {
            return Ok(None);
        }
        let copy = match kind {
            libc::S_IFREG => Some(self.file(dir, name, &st, &shown)?),
            libc::S_IFIFO => Some(self.fifo(dir, name, &st, &shown)?),
            libc::S_IFLNK => {
                self.symlink(dir, name, &st, &shown)?;
                None
            }
            // Device nodes and sockets.
            _ => {
                self.report.skipped.push(rel);
                return Ok(None);
            }
        };
        self.report.entries += 1;
        if st.st_nlink > 1 {
            // A symlink can only be held `O_PATH`, by the name just made.
            let copy = match copy {
                Some(fd) => fd,
                None => nix::fcntl::openat(
                    &dir.dst,
                    name,
                    OFlag::O_PATH | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                    Mode::empty(),
                )
                .with_context(|| format!("{shown}: open the copy"))?,
            };
            self.links.insert((st.st_dev, st.st_ino), Linked { copy, rel, remaining: st.st_nlink - 1 });
        }
        Ok(None)
    }

    /// A later name of an inode already copied becomes a link to the copy.
    /// False for the inode's first name.
    fn link(&mut self, dir: &Frame, name: &OsStr, st: &FileStat, shown: &str) -> Result<bool> {
        let key = (st.st_dev, st.st_ino);
        let Some(linked) = self.links.get_mut(&key) else { return Ok(false) };
        link_fd(linked.copy.as_fd(), dir.dst.as_fd(), name)
            .with_context(|| format!("{shown}: link it to {:?}", self.path.join(&linked.rel)))?;
        linked.remaining -= 1;
        let done = linked.remaining == 0;
        self.made(dir, name);
        if done {
            self.links.remove(&key);
        }
        self.report.entries += 1;
        Ok(true)
    }

    /// A directory: its copy is made, private until [`finish`](Self::finish).
    fn directory(&mut self, parent: &Frame, name: &OsStr, rel: PathBuf, st: FileStat, shown: &str) -> Result<Frame> {
        let src = open_source(parent.src.as_fd(), name, &st, shown)?;
        nix::sys::stat::mkdirat(&parent.dst, name, Mode::from_bits_truncate(0o700))
            .with_context(|| format!("{shown}: create the copy"))?;
        self.made(parent, name);
        self.report.entries += 1;
        let dst = nix::fcntl::openat(
            &parent.dst,
            name,
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .with_context(|| format!("{shown}: open the copy"))?;
        self.frame(src, dst, rel, st)
    }

    /// A regular file: contents first (a write clears file capabilities),
    /// then the metadata.
    fn file(&mut self, dir: &Frame, name: &OsStr, st: &FileStat, shown: &str) -> Result<OwnedFd> {
        let mut from = File::from(open_source(dir.src.as_fd(), name, st, shown)?);
        let fd = nix::fcntl::openat(
            &dir.dst,
            name,
            OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::from_bits_truncate(0o600),
        )
        .with_context(|| format!("{shown}: create the copy"))?;
        self.made(dir, name);
        let mut to = File::from(fd);
        self.report.bytes += io::copy(&mut from, &mut to).with_context(|| format!("{shown}: copy the contents"))?;
        self.apply(&Attrs::Fd(from.as_fd()), to.as_fd(), st, shown)?;
        Ok(to.into())
    }

    /// A symlink with the same target. Its metadata is set by name, never
    /// following it.
    fn symlink(&mut self, dir: &Frame, name: &OsStr, st: &FileStat, shown: &str) -> Result<()> {
        let target = nix::fcntl::readlinkat(&dir.src, name).with_context(|| format!("{shown}: read the link"))?;
        nix::unistd::symlinkat(target.as_os_str(), &dir.dst, name)
            .with_context(|| format!("{shown}: create the copy"))?;
        self.made(dir, name);
        let (uid, gid) = (self.map_owner)(st.st_uid, st.st_gid);
        let (uid, gid) = (Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid)));
        nix::unistd::fchownat(&dir.dst, name, uid, gid, AtFlags::AT_SYMLINK_NOFOLLOW)
            .with_context(|| format!("{shown}: set the owner"))?;
        let set = |attr: &str, value: &[u8]| xattr::lset_at(dir.dst.as_fd(), name, attr, value);
        self.xattrs(&Attrs::at(dir.src.as_fd(), name), set, shown)?;
        let (atime, mtime) = times(st);
        nix::sys::stat::utimensat(&dir.dst, name, &atime, &mtime, UtimensatFlags::NoFollowSymlink)
            .with_context(|| format!("{shown}: set the times"))
    }

    /// A FIFO: a new one, whose metadata is set through an fd.
    fn fifo(&mut self, dir: &Frame, name: &OsStr, st: &FileStat, shown: &str) -> Result<OwnedFd> {
        nix::unistd::mkfifoat(&dir.dst, name, Mode::from_bits_truncate(0o600))
            .with_context(|| format!("{shown}: create the copy"))?;
        self.made(dir, name);
        // Opening a FIFO for reading with O_NONBLOCK returns at once. What
        // it opens must be a FIFO: nothing else may get the source's owner
        // and mode (a setuid bit means nothing to a FIFO).
        let fd = nix::fcntl::openat(
            &dir.dst,
            name,
            OFlag::O_RDONLY | OFlag::O_NONBLOCK | OFlag::O_NOFOLLOW | OFlag::O_NOCTTY | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .with_context(|| format!("{shown}: open the copy"))?;
        let now = nix::sys::stat::fstat(&fd).with_context(|| format!("{shown}: stat the copy"))?;
        if now.st_mode & libc::S_IFMT != libc::S_IFIFO {
            return Err(Error::invalid(format!("{shown}: the copy was replaced while it was being made")));
        }
        self.apply(&Attrs::at(dir.src.as_fd(), name), fd.as_fd(), st, shown)?;
        Ok(fd)
    }

    /// A directory whose entries are all copied gets its own metadata.
    fn finish(&self, dir: &Frame) -> Result<()> {
        self.apply(&Attrs::Fd(dir.src.as_fd()), dir.dst.as_fd(), &dir.st, &self.shown(&dir.rel))
    }

    /// The volume's directory: the source directory's owner and mode.
    fn volume(&self, top: &Frame) -> Result<()> {
        self.owner_and_mode(top.dst.as_fd(), &top.st, "the volume's directory")
    }

    /// Owner, mode, attributes, times, in that order (see the module docs),
    /// through the copy's fd.
    fn apply(&self, from: &Attrs<'_>, to: BorrowedFd<'_>, st: &FileStat, shown: &str) -> Result<()> {
        self.owner_and_mode(to, st, shown)?;
        self.xattrs(from, |name, value| xattr::fset(to, name, value), shown)?;
        let (atime, mtime) = times(st);
        nix::sys::stat::futimens(to, &atime, &mtime).with_context(|| format!("{shown}: set the times"))
    }

    fn owner_and_mode(&self, fd: BorrowedFd<'_>, st: &FileStat, shown: &str) -> Result<()> {
        let (uid, gid) = (self.map_owner)(st.st_uid, st.st_gid);
        nix::unistd::fchown(fd, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid)))
            .with_context(|| format!("{shown}: set the owner"))?;
        nix::sys::stat::fchmod(fd, Mode::from_bits_truncate(st.st_mode & 0o7777))
            .with_context(|| format!("{shown}: set the mode"))
    }

    /// Copies the attributes `from` has, except overlay's own, with `set`.
    fn xattrs(
        &self,
        from: &Attrs<'_>,
        set: impl Fn(&str, &[u8]) -> rustlet_sys::Result<()>,
        shown: &str,
    ) -> Result<()> {
        let names = match from.list() {
            Ok(names) => names,
            // A filesystem without attributes has none to copy.
            Err(Errno::ENOTSUP) => return Ok(()),
            Err(e) => return Err(e).with_context(|| format!("{shown}: list the attributes")),
        };
        for name in names.iter().filter(|name| !OVERLAY_XATTRS.iter().any(|p| name.starts_with(p))) {
            let value = from.get(name).with_context(|| format!("{shown}: read attribute {name}"))?;
            set(name, &map_ids(name, value, self.map_owner))
                .with_context(|| format!("{shown}: set attribute {name}"))?;
        }
        Ok(())
    }
}

/// Opens the entry `name` of `dir`, which `st` says is a regular file or a
/// directory, for reading, and checks it is still that inode (see the
/// module docs for the flags).
pub(crate) fn open_source(dir: BorrowedFd<'_>, name: &OsStr, st: &FileStat, shown: &str) -> Result<OwnedFd> {
    let flags = OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_NOCTTY | OFlag::O_CLOEXEC;
    let fd = nix::fcntl::openat(dir, name, flags, Mode::empty()).with_context(|| format!("{shown}: open"))?;
    let now = nix::sys::stat::fstat(&fd).with_context(|| format!("{shown}: stat"))?;
    let inode = |st: &FileStat| (st.st_dev, st.st_ino, st.st_mode & libc::S_IFMT);
    if inode(&now) != inode(st) {
        return Err(Error::invalid(format!("{shown}: replaced while it was being copied")));
    }
    Ok(fd)
}

/// Where an entry's attributes are read: its fd, or, for a symlink or FIFO,
/// which isn't opened, its name in its directory's magic link
/// (`/proc/self/fd/<dir>/<name>`). The `l*xattr` calls follow the magic
/// link, a middle component, to exactly the directory held, and don't
/// follow the name.
pub(crate) enum Attrs<'a> {
    Fd(BorrowedFd<'a>),
    At(PathBuf),
}

impl Attrs<'_> {
    pub(crate) fn at(dir: BorrowedFd<'_>, name: &OsStr) -> Self {
        Attrs::At(Path::new(&format!("/proc/self/fd/{}", dir.as_raw_fd())).join(name))
    }

    pub(crate) fn list(&self) -> rustlet_sys::Result<Vec<String>> {
        match self {
            Attrs::Fd(fd) => xattr::flist(*fd),
            Attrs::At(path) => xattr::llist(path),
        }
    }

    pub(crate) fn get(&self, name: &str) -> rustlet_sys::Result<Vec<u8>> {
        match self {
            Attrs::Fd(fd) => xattr::fget(*fd, name),
            Attrs::At(path) => xattr::lget(path, name),
        }
    }
}

/// The ids inside an attribute's value, translated like owners (see the
/// module docs). An idmapping maps uids and gids each on its own, so a
/// lone id is passed to `map_owner` as both halves of the pair. Other
/// values, and ones not well formed (the kernel judges those), stay as
/// they are.
fn map_ids(name: &str, mut value: Vec<u8>, map_owner: &dyn Fn(u32, u32) -> (u32, u32)) -> Vec<u8> {
    fn le32(b: &[u8]) -> u32 {
        u32::from_le_bytes([b[0], b[1], b[2], b[3]])
    }
    if name == CAPS_XATTR && value.len() == CAPS_V3_LEN && le32(&value) & CAPS_REVISION_MASK == CAPS_REVISION_3 {
        let root = le32(&value[20..]);
        value[20..].copy_from_slice(&map_owner(root, root).0.to_le_bytes());
    } else if ACL_XATTRS.contains(&name) && value.len() % 8 == 4 && le32(&value) == ACL_VERSION {
        for entry in value[4..].as_chunks_mut::<8>().0 {
            let id = le32(&entry[4..]);
            let mapped = match u16::from_le_bytes([entry[0], entry[1]]) {
                ACL_USER => map_owner(id, id).0,
                ACL_GROUP => map_owner(id, id).1,
                _ => continue,
            };
            entry[4..].copy_from_slice(&mapped.to_le_bytes());
        }
    }
    value
}

/// `linkat(fd, "", dir, name, AT_EMPTY_PATH)`: a new name for exactly the
/// inode `fd` holds. The kernel allows that with `CAP_DAC_READ_SEARCH` and,
/// in recent kernels, for an fd the caller opened itself; where an
/// unprivileged caller (the unit tests) gets `ENOENT`, the fd's magic link
/// names the same inode.
pub(crate) fn link_fd(fd: BorrowedFd<'_>, dir: BorrowedFd<'_>, name: &OsStr) -> rustlet_sys::Result<()> {
    match nix::unistd::linkat(fd, "", dir, name, AtFlags::AT_EMPTY_PATH) {
        Err(Errno::ENOENT) => {
            let magic = format!("/proc/self/fd/{}", fd.as_raw_fd());
            nix::unistd::linkat(nix::fcntl::AT_FDCWD, magic.as_str(), dir, name, AtFlags::AT_SYMLINK_FOLLOW)
        }
        r => r,
    }
}

pub(crate) fn times(st: &FileStat) -> (TimeSpec, TimeSpec) {
    (TimeSpec::new(st.st_atime, st.st_atime_nsec), TimeSpec::new(st.st_mtime, st.st_mtime_nsec))
}

/// The names in `dir` other than `.` and `..`, sorted.
pub(crate) fn entries(dir: BorrowedFd<'_>) -> rustlet_sys::Result<Vec<OsString>> {
    let mut listing = listing(dir)?;
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

/// A directory stream of `dir`'s own, so that `dir` may be an `O_PATH` fd
/// and its offset doesn't move.
fn listing(dir: BorrowedFd<'_>) -> rustlet_sys::Result<nix::dir::Dir> {
    let fd = nix::fcntl::openat(dir, ".", OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC, Mode::empty())?;
    nix::dir::Dir::from_fd(fd)
}

#[cfg(test)]
mod tests {
    //! Unprivileged tests: everything belongs to the user running them.
    //! Other owners, file capabilities, device nodes and the translation
    //! under `--userns=remap` need root.

    use std::cell::RefCell;
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
    use std::os::unix::net::UnixListener;
    use std::sync::mpsc;
    use std::time::Duration;

    use nix::unistd::{getegid, geteuid};

    use super::*;

    const ATIME: i64 = 1_500_000_000;
    const MTIME: i64 = 1_600_000_000;
    /// `ACL_UNDEFINED_ID`: the id of an ACL entry that names no one.
    const NO_ID: u32 = u32::MAX;

    fn identity(uid: u32, gid: u32) -> (u32, u32) {
        (uid, gid)
    }

    fn open(p: &Path) -> OwnedFd {
        nix::fcntl::open(p, OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC, Mode::empty()).unwrap()
    }

    fn meta(p: &Path) -> std::fs::Metadata {
        std::fs::symlink_metadata(p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
    }

    fn mode(p: &Path) -> u32 {
        meta(p).permissions().mode() & 0o7777
    }

    /// `((atime, nsec), (mtime, nsec))`, of a symlink itself.
    fn times_of(p: &Path) -> ((i64, i64), (i64, i64)) {
        let m = meta(p);
        ((m.atime(), m.atime_nsec()), (m.mtime(), m.mtime_nsec()))
    }

    fn set_times(p: &Path, atime: (i64, i64), mtime: (i64, i64)) {
        let (atime, mtime) = (TimeSpec::new(atime.0, atime.1), TimeSpec::new(mtime.0, mtime.1));
        nix::sys::stat::utimensat(nix::fcntl::AT_FDCWD, p, &atime, &mtime, UtimensatFlags::NoFollowSymlink).unwrap();
    }

    /// One of the user's other groups, which files may be given without
    /// privileges.
    fn other_group() -> Option<u32> {
        let mine = getegid();
        nix::unistd::getgroups().unwrap().into_iter().find(|&g| g != mine).map(Gid::as_raw)
    }

    /// Runs `f` on a thread of its own, so that a test fails rather than
    /// hangs if it blocks (a FIFO opened for reading waits for a writer).
    fn unblocked<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(f());
        });
        rx.recv_timeout(Duration::from_secs(30)).expect("blocked (opening a FIFO?)")
    }

    /// A root filesystem `root/` and an empty volume `vol/`, side by side
    /// in a temporary directory.
    struct Fixture {
        tmp: tempfile::TempDir,
    }

    impl Fixture {
        fn new() -> Fixture {
            let tmp = tempfile::tempdir().unwrap();
            for dir in ["root", "vol"] {
                std::fs::create_dir(tmp.path().join(dir)).unwrap();
            }
            Fixture { tmp }
        }

        /// `p` in the root filesystem.
        fn root(&self, p: &str) -> PathBuf {
            self.tmp.path().join("root").join(p)
        }

        /// `p` in the volume.
        fn vol(&self, p: &str) -> PathBuf {
            self.tmp.path().join("vol").join(p)
        }

        /// Another empty volume.
        fn volume(&self, name: &str) -> PathBuf {
            let p = self.tmp.path().join(name);
            std::fs::create_dir(&p).unwrap();
            p
        }

        fn dir(&self, p: &str, mode: u32) {
            std::fs::create_dir(self.root(p)).unwrap();
            std::fs::set_permissions(self.root(p), std::fs::Permissions::from_mode(mode)).unwrap();
        }

        fn file(&self, p: &str, data: &str, mode: u32) {
            std::fs::write(self.root(p), data).unwrap();
            std::fs::set_permissions(self.root(p), std::fs::Permissions::from_mode(mode)).unwrap();
        }

        fn symlink(&self, target: &str, p: &str) {
            std::os::unix::fs::symlink(target, self.root(p)).unwrap();
        }

        fn copy_into(&self, path: &str, vol: &Path, map: &dyn Fn(u32, u32) -> (u32, u32)) -> Result<CopyUp> {
            copy_up(open(&self.root("")).as_fd(), Path::new(path), open(vol).as_fd(), map)
        }

        fn copy(&self, path: &str) -> Result<CopyUp> {
            self.copy_into(path, &self.vol(""), &identity)
        }

        /// [`copy`](Self::copy) through [`unblocked`], with `map`.
        fn copy_unblocked(
            &self,
            path: &'static str,
            map: fn(u32, u32) -> (u32, u32),
        ) -> std::result::Result<CopyUp, String> {
            let (root, vol) = (self.root(""), self.vol(""));
            unblocked(move || {
                copy_up(open(&root).as_fd(), Path::new(path), open(&vol).as_fd(), &map).map_err(|e| e.to_string())
            })
        }
    }

    /// The bytes of an ACL attribute with `(tag, permissions, id)` entries.
    fn acl(entries: &[(u16, u16, u32)]) -> Vec<u8> {
        let mut value = ACL_VERSION.to_le_bytes().to_vec();
        for &(tag, perm, id) in entries {
            value.extend_from_slice(&tag.to_le_bytes());
            value.extend_from_slice(&perm.to_le_bytes());
            value.extend_from_slice(&id.to_le_bytes());
        }
        value
    }

    #[test]
    fn copies_a_tree_with_its_contents_modes_and_times() {
        let f = Fixture::new();
        f.dir("data", 0o750);
        f.file("data/motd", "hello\n", 0o644);
        f.file("data/empty", "", 0o444);
        f.dir("data/bin", 0o755);
        f.file("data/bin/tool", "#!/bin/sh\necho hi\n", 0o755);
        // Any chown clears these bits, even an unprivileged one that
        // changes nothing: they show that the mode comes after the owner.
        f.file("data/bin/setuid", "u", 0o4755);
        f.file("data/bin/setgid", "g", 0o2755);
        f.dir("data/shared", 0o2775);
        f.file("data/shared/note", "for the group", 0o664);
        f.dir("data/a", 0o700);
        f.dir("data/a/b", 0o711);
        f.dir("data/a/b/c", 0o755);
        f.file("data/a/b/c/deep", "deep down", 0o600);
        let entries = [
            "motd",
            "empty",
            "bin",
            "bin/tool",
            "bin/setuid",
            "bin/setgid",
            "shared",
            "shared/note",
            "a",
            "a/b",
            "a/b/c",
            "a/b/c/deep",
        ];
        // Times differ per entry, and are set once everything exists:
        // making an entry changes its directory's mtime.
        let stamp = |i: usize| ((ATIME + i as i64, 1_000 + i as i64), (MTIME + i as i64, 123_456_789 + i as i64));
        for (i, p) in entries.iter().enumerate() {
            set_times(&f.root("data").join(p), stamp(i).0, stamp(i).1);
        }

        let r = f.copy("/data").unwrap();
        let bytes = ["hello\n", "#!/bin/sh\necho hi\n", "u", "g", "for the group", "deep down"]
            .map(str::len)
            .iter()
            .sum::<usize>();
        assert_eq!(r, CopyUp { copied: true, entries: entries.len() as u64, bytes: bytes as u64, skipped: vec![] });
        // Times first: reading a copy here would move its atime (relatime).
        for (i, p) in entries.iter().enumerate() {
            let copy = f.vol(p);
            // Directories included: their times were set after their contents.
            assert_eq!(times_of(&copy), stamp(i), "{p}");
            assert_eq!(mode(&copy), mode(&f.root("data").join(p)), "{p}");
            assert_eq!((meta(&copy).uid(), meta(&copy).gid()), (geteuid().as_raw(), getegid().as_raw()), "{p}");
        }
        for p in ["motd", "empty", "bin/tool", "shared/note", "a/b/c/deep"] {
            assert_eq!(std::fs::read(f.vol(p)).unwrap(), std::fs::read(f.root("data").join(p)).unwrap(), "{p}");
        }
        assert_eq!(mode(&f.vol("shared")), 0o2775, "a setgid directory");
        assert_eq!(mode(&f.vol("bin/tool")), 0o755);
        assert_eq!(mode(&f.vol("bin/setuid")), 0o4755, "setuid survives the chown");
        assert_eq!(mode(&f.vol("bin/setgid")), 0o2755, "setgid survives the chown");
        assert_eq!(mode(&f.vol("")), 0o750, "the volume's directory takes the source directory's mode");
    }

    #[test]
    fn symlinks_are_copied_as_symlinks_and_never_followed() {
        let f = Fixture::new();
        // Outside the root: nothing may be read or written through a link.
        let victim = f.tmp.path().join("victim");
        std::fs::write(&victim, "keep").unwrap();
        let victim_dir = f.tmp.path().join("victim-dir");
        std::fs::create_dir(&victim_dir).unwrap();
        f.dir("data", 0o755);
        f.file("data/motd", "hi", 0o644);
        let links = [
            ("relative", "motd"),
            ("absolute", "/etc/passwd"),
            ("climbing", "../../../../../.."),
            ("dangling", "nowhere/at/all"),
            ("to-a-file", victim.to_str().unwrap()),
            ("to-a-dir", victim_dir.to_str().unwrap()),
        ];
        for (i, (name, target)) in links.iter().enumerate() {
            f.symlink(target, &format!("data/{name}"));
            set_times(&f.root("data").join(name), (ATIME, 0), (MTIME + i as i64, 0));
        }

        let r = f.copy("/data").unwrap();
        assert_eq!((r.entries, r.bytes), (1 + links.len() as u64, 2));
        for (i, (name, target)) in links.iter().enumerate() {
            let copy = f.vol(name);
            assert!(meta(&copy).file_type().is_symlink(), "{name}");
            assert_eq!(std::fs::read_link(&copy).unwrap(), Path::new(target), "{name}");
            assert_eq!(times_of(&copy).1, (MTIME + i as i64, 0), "{name}");
        }
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep");
        assert_eq!(std::fs::read_dir(&victim_dir).unwrap().count(), 0);
    }

    #[test]
    fn hard_links_are_copied_as_links() {
        let f = Fixture::new();
        for dir in ["data", "data/sub", "data/sub/deeper"] {
            f.dir(dir, 0o755);
        }
        f.file("data/a", "three names", 0o644);
        std::fs::hard_link(f.root("data/a"), f.root("data/sub/b")).unwrap();
        std::fs::hard_link(f.root("data/a"), f.root("data/sub/deeper/c")).unwrap();
        f.file("data/x", "two", 0o600);
        std::fs::hard_link(f.root("data/x"), f.root("data/y")).unwrap();
        // Its other name is outside the copied directory.
        f.file("data/lonely", "one here", 0o644);
        std::fs::hard_link(f.root("data/lonely"), f.root("elsewhere")).unwrap();
        // A symlink can have more than one name too (`hard_link` doesn't
        // follow it).
        f.symlink("a", "data/s");
        std::fs::hard_link(f.root("data/s"), f.root("data/s2")).unwrap();

        let r = f.copy("/data").unwrap();
        assert_eq!(r.bytes, ["three names", "two", "one here"].map(str::len).iter().sum::<usize>() as u64);
        // sub, sub/deeper, a, sub/b, sub/deeper/c, x, y, lonely, s, s2
        assert_eq!(r.entries, 10);
        let inode = |p: &str| meta(&f.vol(p)).ino();
        let links = |p: &str| meta(&f.vol(p)).nlink();
        assert_eq!([inode("sub/b"), inode("sub/deeper/c")], [inode("a"); 2]);
        assert_eq!(links("a"), 3);
        assert_eq!(std::fs::read_to_string(f.vol("sub/deeper/c")).unwrap(), "three names");
        assert_eq!((inode("y"), links("x")), (inode("x"), 2));
        assert_eq!(links("lonely"), 1);
        assert_eq!((inode("s2"), links("s")), (inode("s"), 2));
        assert_eq!(std::fs::read_link(f.vol("s2")).unwrap(), Path::new("a"));
    }

    #[test]
    fn fifos_are_made_anew_and_sockets_skipped() {
        let f = Fixture::new();
        f.dir("data", 0o755);
        nix::unistd::mkfifo(&f.root("data/pipe"), Mode::from_bits_truncate(0o600)).unwrap();
        std::fs::set_permissions(f.root("data/pipe"), std::fs::Permissions::from_mode(0o640)).unwrap();
        std::fs::hard_link(f.root("data/pipe"), f.root("data/pipe2")).unwrap();
        set_times(&f.root("data/pipe"), (ATIME, 1), (MTIME, 2));
        f.dir("data/sub", 0o755);
        let _sockets = [f.root("data/sock"), f.root("data/sub/sock")].map(|p| UnixListener::bind(p).unwrap());

        // The source FIFO must not be opened: run the copy where blocking
        // shows. Its owner is set through the copy's fd: map the group to
        // another of the user's, if there is one.
        let map = |uid: u32, gid: u32| (uid, other_group().unwrap_or(gid));
        let r = f.copy_unblocked("/data", map).unwrap();
        assert_eq!(r.skipped, [PathBuf::from("sock"), PathBuf::from("sub/sock")]);
        assert_eq!(r.entries, 3, "pipe, pipe2, sub");
        let pipe = meta(&f.vol("pipe"));
        assert!(pipe.file_type().is_fifo());
        assert_eq!(pipe.permissions().mode() & 0o7777, 0o640);
        assert_eq!(times_of(&f.vol("pipe")), ((ATIME, 1), (MTIME, 2)));
        assert_eq!(pipe.gid(), other_group().unwrap_or(getegid().as_raw()));
        assert_eq!((meta(&f.vol("pipe2")).ino(), pipe.nlink()), (pipe.ino(), 2));
        for p in ["sock", "sub/sock"] {
            assert!(std::fs::symlink_metadata(f.vol(p)).is_err(), "{p}");
        }
    }

    #[test]
    fn extended_attributes_are_copied_but_not_overlays_own() {
        let f = Fixture::new();
        f.dir("data", 0o755);
        f.file("data/file", "x", 0o644);
        f.dir("data/dir", 0o755);
        for (p, name, value) in [
            ("data/file", "user.note", "hello"),
            ("data/file", "user.overlay.redirect", "/etc"),
            ("data/dir", "user.dir", "d"),
            ("data/dir", "user.overlay.opaque", "y"),
        ] {
            xattr::lset(&f.root(p), name, value.as_bytes()).unwrap();
        }

        f.copy("/data").unwrap();
        assert_eq!(xattr::lget(&f.vol("file"), "user.note").unwrap(), b"hello");
        assert_eq!(xattr::lget(&f.vol("dir"), "user.dir").unwrap(), b"d");
        for (p, name) in [("file", "user.overlay.redirect"), ("dir", "user.overlay.opaque")] {
            assert_eq!(xattr::lget(&f.vol(p), name), Err(Errno::ENODATA), "{p}: {name}");
        }
    }

    #[test]
    fn ids_inside_an_acl_go_through_the_mapping() {
        let f = Fixture::new();
        f.dir("data", 0o755);
        f.file("data/file", "x", 0o640);
        let with = |user, group| {
            acl(&[
                (0x01, 6, NO_ID),
                (ACL_USER, 4, user),
                (0x04, 4, NO_ID),
                (ACL_GROUP, 4, group),
                (0x10, 4, NO_ID),
                (0x20, 0, NO_ID),
            ])
        };
        match xattr::lset(&f.root("data/file"), ACL_XATTRS[0], &with(4242, 4343)) {
            Ok(()) => {}
            Err(Errno::ENOTSUP) => return, // no ACLs on this filesystem
            Err(e) => panic!("set an ACL: {e}"),
        }
        // Every id but the user's own moves up by one.
        let (me, my_group) = (geteuid().as_raw(), getegid().as_raw());
        let map =
            |uid: u32, gid: u32| (if uid == me { uid } else { uid + 1 }, if gid == my_group { gid } else { gid + 1 });

        f.copy_into("/data", &f.vol(""), &map).unwrap();
        assert_eq!(xattr::lget(&f.vol("file"), ACL_XATTRS[0]).unwrap(), with(4243, 4344));
        assert_eq!(mode(&f.vol("file")), 0o640);
    }

    #[test]
    fn ids_inside_capabilities_and_acls_are_mapped() {
        let unshift = |uid: u32, gid: u32| (uid.wrapping_sub(1_000_000), gid.wrapping_sub(1_000_000));
        // cap_net_raw, permitted and effective; revision 3 adds the root.
        let caps = |magic: u32, root: Option<u32>| {
            let mut value = magic.to_le_bytes().to_vec();
            for word in [1u32 << 13, 0, 0, 0].into_iter().chain(root) {
                value.extend_from_slice(&word.to_le_bytes());
            }
            value
        };
        let v3 = |root| caps(0x0300_0001, Some(root));
        assert_eq!(map_ids(CAPS_XATTR, v3(1_000_000), &unshift), v3(0));
        let v2 = caps(0x0200_0001, None);
        assert_eq!(map_ids(CAPS_XATTR, v2.clone(), &unshift), v2, "revision 2 names no root");
        assert_eq!(map_ids("user.caps", v3(1_000_000), &unshift), v3(1_000_000), "only file capabilities");
        let short = v3(1_000_000)[..23].to_vec();
        assert_eq!(map_ids(CAPS_XATTR, short.clone(), &unshift), short);

        let with = |user, group| {
            acl(&[
                (0x01, 7, NO_ID),
                (ACL_USER, 5, user),
                (0x04, 5, NO_ID),
                (ACL_GROUP, 5, group),
                (0x10, 5, NO_ID),
                (0x20, 0, NO_ID),
            ])
        };
        for name in ACL_XATTRS {
            assert_eq!(map_ids(name, with(1_000_101, 1_000_102), &unshift), with(101, 102), "{name}");
        }
        let mut other_version = with(1_000_101, 1_000_102);
        other_version[0] = 3;
        assert_eq!(map_ids(ACL_XATTRS[0], other_version.clone(), &unshift), other_version);
        let mut torn = with(1_000_101, 1_000_102);
        torn.pop();
        assert_eq!(map_ids(ACL_XATTRS[0], torn.clone(), &unshift), torn);
    }

    #[test]
    fn owners_go_through_the_mapping() {
        let f = Fixture::new();
        let (uid, gid) = (geteuid().as_raw(), getegid().as_raw());
        let group = other_group();
        f.dir("data", 0o755);
        f.file("data/file", "x", 0o644);
        f.dir("data/dir", 0o755);
        f.symlink("file", "data/link");
        if let Some(group) = group {
            nix::unistd::chown(&f.root("data/file"), None, Some(Gid::from_raw(group))).unwrap();
        }

        // Once for each inode copied and the volume's directory, with the
        // owner it has in the root.
        let seen = RefCell::new(Vec::new());
        f.copy_into("/data", &f.vol(""), &|u, g| {
            seen.borrow_mut().push((u, g));
            (u, g)
        })
        .unwrap();
        let mut seen = seen.into_inner();
        seen.sort();
        let mut expected = vec![(uid, gid), (uid, group.unwrap_or(gid)), (uid, gid), (uid, gid)];
        expected.sort();
        assert_eq!(seen, expected);
        assert_eq!(meta(&f.vol("file")).gid(), group.unwrap_or(gid));

        // What the mapping returns is what is written.
        let Some(group) = group else { return };
        let vol = f.volume("vol2");
        f.copy_into("/data", &vol, &|u, _| (u, group)).unwrap();
        for p in ["", "file", "dir", "link"] {
            let m = meta(&vol.join(p));
            assert_eq!((m.uid(), m.gid()), (uid, group), "{p:?}");
        }
    }

    #[test]
    fn the_path_resolves_inside_the_root_filesystem() {
        let f = Fixture::new();
        f.dir("data", 0o755);
        f.file("data/marker", "the root's /data", 0o644);
        f.symlink("data", "link");
        f.symlink("/data", "abs");
        f.symlink("../../../../../../data", "climbing");
        // The host has an /etc too, with much more in it.
        f.dir("etc", 0o755);
        f.file("etc/marker", "the root's /etc", 0o644);
        f.symlink("/etc", "etc-link");
        for (i, (path, marker)) in [
            ("/link", "the root's /data"),
            ("/abs", "the root's /data"),
            ("/climbing", "the root's /data"),
            ("/etc/../../link", "the root's /data"),
            ("/etc-link", "the root's /etc"),
        ]
        .into_iter()
        .enumerate()
        {
            let vol = f.volume(&format!("vol{i}"));
            assert!(f.copy_into(path, &vol, &identity).unwrap().copied, "{path}");
            let names: Vec<_> = std::fs::read_dir(&vol).unwrap().map(|e| e.unwrap().file_name()).collect();
            assert_eq!(names, ["marker"], "{path}: the root's directory, nothing else");
            assert_eq!(std::fs::read_to_string(vol.join("marker")).unwrap(), marker, "{path}");
        }
    }

    #[test]
    fn a_missing_path_or_one_that_is_not_a_directory_copies_nothing() {
        let f = Fixture::new();
        f.dir("data", 0o755);
        f.file("data/file", "x", 0o644);
        f.symlink("/nowhere", "dangling");
        f.symlink("/data/file", "to-a-file");
        nix::unistd::mkfifo(&f.root("fifo"), Mode::from_bits_truncate(0o644)).unwrap();
        let before = mode(&f.vol(""));
        for path in
            ["/missing", "/data/missing/below", "/data/file", "/data/file/below", "/dangling", "/to-a-file", "/fifo"]
        {
            assert_eq!(f.copy_unblocked(path, identity).unwrap(), CopyUp::default(), "{path}");
        }
        assert!(is_empty(open(&f.vol("")).as_fd()).unwrap());
        assert_eq!(mode(&f.vol("")), before, "the volume's directory is left alone");
    }

    #[test]
    fn an_entry_already_in_the_volume_is_an_error() {
        let f = Fixture::new();
        f.dir("data", 0o755);
        f.file("data/a", "new", 0o644);
        f.file("data/b", "new", 0o644);
        f.dir("data/c", 0o755);
        std::fs::write(f.vol("b"), "old").unwrap();
        let err = f.copy("/data").unwrap_err().to_string();
        assert!(err.contains("\"/data/b\"") && err.contains("EEXIST"), "{err}");
        assert_eq!(std::fs::read_to_string(f.vol("b")).unwrap(), "old");

        // A symlink there isn't followed.
        let vol = f.volume("vol2");
        let victim = f.tmp.path().join("victim");
        std::fs::write(&victim, "keep").unwrap();
        std::os::unix::fs::symlink(&victim, vol.join("b")).unwrap();
        let err = f.copy_into("/data", &vol, &identity).unwrap_err().to_string();
        assert!(err.contains("\"/data/b\"") && err.contains("EEXIST"), "{err}");
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep");

        // Nor is a directory merged.
        let vol = f.volume("vol3");
        std::fs::create_dir(vol.join("c")).unwrap();
        let err = f.copy_into("/data", &vol, &identity).unwrap_err().to_string();
        assert!(err.contains("\"/data/c\"") && err.contains("EEXIST"), "{err}");
    }

    #[test]
    fn a_failed_copy_takes_back_only_what_it_made() {
        let f = Fixture::new();
        f.dir("data", 0o755);
        f.file("data/a", "new", 0o644);
        std::fs::hard_link(f.root("data/a"), f.root("data/a-link")).unwrap();
        f.dir("data/a-dir", 0o755);
        f.file("data/a-dir/x", "new", 0o644);
        f.symlink("a", "data/a-sym");
        f.file("data/b", "new", 0o644);
        // Written by a container sharing the volume after the emptiness
        // check, which is what makes the copy fail.
        std::fs::write(f.vol("b"), "theirs").unwrap();
        std::fs::create_dir(f.vol("c")).unwrap();
        assert!(f.copy("/data").is_err());
        let mut names: Vec<_> = std::fs::read_dir(f.vol("")).unwrap().map(|e| e.unwrap().file_name()).collect();
        names.sort();
        assert_eq!(names, ["b", "c"], "the copy's own entries go, nothing else");
        assert_eq!(std::fs::read_to_string(f.vol("b")).unwrap(), "theirs");
    }

    #[test]
    fn is_empty_looks_for_any_entry() {
        let dir = tempfile::tempdir().unwrap();
        let fd = open(dir.path());
        assert!(is_empty(fd.as_fd()).unwrap());
        assert!(is_empty(fd.as_fd()).unwrap(), "asked twice");
        std::fs::write(dir.path().join(".hidden"), "").unwrap();
        assert!(!is_empty(fd.as_fd()).unwrap());
        let path_fd =
            nix::fcntl::open(dir.path(), OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC, Mode::empty()).unwrap();
        assert!(!is_empty(path_fd.as_fd()).unwrap(), "an O_PATH fd will do");
        let file = File::open(dir.path().join(".hidden")).unwrap();
        assert!(is_empty(file.as_fd()).is_err());
    }

    #[test]
    fn a_deep_tree_is_copied() {
        const DEPTH: usize = 300;
        let f = Fixture::new();
        f.dir("data", 0o755);
        let deep: PathBuf = std::iter::repeat_n("d", DEPTH).collect();
        std::fs::create_dir_all(f.root("data").join(&deep)).unwrap();
        std::fs::write(f.root("data").join(&deep).join("leaf"), "at the bottom").unwrap();

        let r = f.copy("/data").unwrap();
        assert_eq!(r.entries, DEPTH as u64 + 1);
        assert_eq!(std::fs::read_to_string(f.vol("").join(&deep).join("leaf")).unwrap(), "at the bottom");
    }

    #[test]
    fn a_root_that_is_not_a_directory_is_an_error() {
        let f = Fixture::new();
        f.file("file", "x", 0o644);
        let file = File::open(f.root("file")).unwrap();
        let err = copy_up(file.as_fd(), Path::new("/data"), open(&f.vol("")).as_fd(), &identity).unwrap_err();
        assert!(err.to_string().contains("not a directory"), "{err}");
    }
}

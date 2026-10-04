//! `COPY` and `ADD`: files from a build context, or from another stage's
//! filesystem, into the root filesystem a build step is making.
//!
//! The builder mounts the step's root filesystem (an overlay of the image
//! so far, with an empty upper directory), and this module writes into it;
//! the upper directory then becomes the step's layer (`diff`). Both sides
//! are untrusted in their own way: the destination is an image's tree,
//! whose symlinks its author chose (`/app → /etc`), and the source is a
//! user's directory, whose symlinks may point anywhere on the host. The
//! daemon is root. So, as in `unpack` and `copyup`:
//!
//! - **destination paths** are resolved inside the root filesystem
//!   (`openat2(RESOLVE_IN_ROOT)`): `/app/x` through `/app → /etc` is the
//!   *image's* `/etc/x`; missing directories are made one component at a
//!   time, relative to the fd of the last one;
//! - **source paths** are resolved inside their root the same way (a
//!   symlink in the context to `/etc` leads to the context's `etc`, if it
//!   has one, never the host's); the named source itself is followed (within
//!   its root), what is below it never is: a symlink in a copied directory is
//!   copied as a symlink;
//! - every entry is created relative to its parent's fd, an existing one of
//!   the same name replaced (a directory merges with a directory; anything
//!   else is removed first, with `remove_tree_at`);
//! - files are opened `O_NOFOLLOW | O_NONBLOCK` and checked to be the inode
//!   examined; FIFOs aren't opened; device nodes and sockets are skipped.
//!
//! ## Docker's rules
//!
//! - Each source is a path relative to the source root (a leading `/` is
//!   the root too: the build context can't be left), and may hold wildcards
//!   (`*`, `?`, `[…]`, Go's `filepath.Match`, per component). A source that
//!   matches nothing is an error, naming it.
//! - The destination is absolute, or relative to the working directory; a
//!   trailing `/` makes it a directory. With more than one source (or a
//!   wildcard matching more than one), it must be one.
//! - A source **directory** is copied by its *contents* into the
//!   destination directory, which is created if missing; directories merge.
//! - A source **file** goes to `<dest>/<its name>` when the destination ends
//!   in `/` or is an existing directory (in the root filesystem, after
//!   resolving it), else to the destination path itself.
//! - Copies keep their source's mode (`spec.mode`, `--chmod`, replaces it
//!   for every file and directory copied), modification time and extended
//!   attributes (overlay's own excepted); their owner is `spec.owner`
//!   (`0:0` unless `--chown`). Directories the copy has to create, the
//!   destination's missing parents included, are `0755` and also
//!   `spec.owner`'s. Hard links between copied files stay links.
//! - `ADD` (`spec.extract_archives`): a source that is a tar archive
//!   (plain, gzip or zstd, told by its content, not its name) is extracted
//!   into the destination directory instead of copied, as `tar -x` would
//!   (`unpack::unpack_with` without whiteouts, confined to that directory),
//!   keeping the archive's owners and modes. Anything else is copied as by
//!   `COPY`. (URLs are refused before this module is reached.)
//!
//! Unprivileged (the unit tests), owners can't be set: the copies keep the
//! caller's, as `unpack` does.
//!
//! ## The cache key
//!
//! [`digest`] hashes what [`copy`] would copy, with the same matching:
//! every entry's path relative to its source, type, mode, size and content
//! (a SHA-256 of a file's bytes), a symlink's target; plus the
//! destination, owner and `--chmod`. Not modification times and not the
//! source's owners (the copy sets its own): touching a file doesn't make a
//! cached `COPY` run again, changing its content does.
//!
//! ## In detail
//!
//! **Matching.** A source is cleaned as Docker cleans it (Go's
//! `path.Join("/", src)`: empty and `.` components dropped, `..` never
//! above the root), then split as BuildKit splits it: the components before
//! the first with an unescaped `*`, `?` or `[` (Docker's
//! `containsWildcards`) are names, as written (a `\` in them stays); from
//! that one on, each is a pattern, matched against the sorted names of
//! each directory matched so far. A pattern never matches `/`, and `*`
//! matches a leading `.`. Every match is a source of its own, copied in
//! order (a later one replaces what an earlier one copied), and followed:
//! `COPY dir/* /d/` copies a directory among `dir`'s entries by its
//! contents, as Docker does, so `dir/sub/x` lands in `/d/x`.
//!
//! **The destination** names a directory when it ends in `/` (or `.` or
//! `..`), or when it resolves to one before anything is copied. Otherwise
//! a file replaces whatever non-directory has the destination's path, a
//! symlink included: its last component is never followed to write a file
//! (Docker would follow it, inside the root, and replace its target). A
//! component that is a file, or a symlink to nothing, is an error, as for
//! Docker's `mkdir -p`; so is a destination directory that exists as
//! something else. The destination directory keeps its own owner and mode
//! (or is made `0755`); the directories below it, made or merged into, take
//! their source's metadata, as `tar -x` gives it.
//!
//! **Named sources** are resolved to `O_PATH` fds and examined (`fstat`)
//! before a regular file is opened, through its magic link
//! (`/proc/self/fd/N`: exactly the inode held, so `O_NOFOLLOW` has nothing
//! to refuse), which is why a device node behind a symlink is never
//! opened. A named FIFO is made anew without its attributes: an `O_PATH`
//! fd can't read them, and a FIFO is never opened. Hard links are kept
//! across all the sources of one copy.
//!
//! **Attributes** the destination can't hold (`ENOTSUP`), or an
//! unprivileged copy may not set (`EPERM`: `trusted.*`, `security.*`), are
//! left out; any other failure is an error.
//!
//! **An archive** is a regular file whose first 512 bytes, decompressed if
//! a gzip or zstd magic number starts it, are a tar header: `ustar` at
//! offset 257 (POSIX's `ustar\0`, GNU's `ustar `) and a checksum that adds
//! up as the `tar` crate counts it. A compressed file that doesn't
//! decompress, or holds anything else, is copied as it is; bzip2 and xz
//! aren't recognised. Device nodes in an archive are skipped, and listed as
//! `<archive>/<entry>`. An entry for the archive's own root (`./`) gives
//! the destination directory its metadata, as `tar -x` does (Docker skips
//! it).
//!
//! A copy that fails leaves what it made: the builder throws the step's
//! root filesystem away.
//!
//! **The digest** is a SHA-256 of length-prefixed fields: a version; the
//! destination (absolute, cleaned, ending in `/` if it names a directory),
//! the owner, `--chmod` and `ADD`; then, for each source matched, its path,
//! and for each entry it copies, in the walk's order (names sorted, depth
//! first): its kind, its path below the source, the mode its copy gets,
//! and its size and content digest, its target, or, for a later name of an
//! inode with several, the first name.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::File;
use std::io::{self, Read, Seek};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use nix::fcntl::{AtFlags, OFlag};
use nix::sys::stat::{FileStat, Mode, UtimensatFlags};
use nix::unistd::{Gid, Uid};
use rustlet_sys::Errno;
use rustlet_sys::fs::{ResolveFlags, openat2};
use rustlet_sys::xattr;

use crate::copyup::{Attrs, entries, link_fd, open_source, times};
use crate::digest::{Digest, Hasher, HashingReader};
use crate::error::{Context, Error, Result};
use crate::media::{Compression, detect_compression};
use crate::unpack::{UnpackOptions, unpack_with};

/// How paths are resolved, on both sides: inside their root.
const RESOLVE: ResolveFlags = ResolveFlags::IN_ROOT.union(ResolveFlags::NO_MAGICLINKS);
/// How many levels below a copied directory the tree may go.
const MAX_DEPTH: usize = 4096;
/// Attribute namespaces overlayfs keeps for itself.
const OVERLAY_XATTRS: [&str; 2] = ["trusted.overlay.", "user.overlay."];
/// A tar header, and where in it the magic and the checksum are.
const BLOCK: usize = 512;
const MAGIC: std::ops::Range<usize> = 257..262;
const CHECKSUM: std::ops::Range<usize> = 148..156;

/// One `COPY` or `ADD`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopySpec {
    /// The sources, as the instruction gives them (variables expanded).
    pub sources: Vec<String>,
    /// The destination, as given: absolute, or relative to `workdir`.
    pub dest: String,
    /// The image's working directory, absolute.
    pub workdir: String,
    /// The owner of every copy and of the directories made (`--chown`).
    pub owner: (u32, u32),
    /// `--chmod`: the mode of every file and directory copied.
    pub mode: Option<u32>,
    /// `ADD`: extract tar archives instead of copying them.
    pub extract_archives: bool,
}

/// What [`copy`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CopyReport {
    /// Entries created or replaced (directories merged into count too).
    pub entries: u64,
    /// Bytes of file content copied or extracted.
    pub bytes: u64,
    /// Archives extracted (`ADD`).
    pub extracted: u64,
    /// Device nodes and sockets left out, as source paths.
    pub skipped: Vec<PathBuf>,
}

/// Copies `spec.sources` from the source root `src` (the build context's
/// directory, or another stage's mounted root filesystem) into the root
/// filesystem `dest` (see the module docs).
pub fn copy(src: BorrowedFd<'_>, dest: BorrowedFd<'_>, spec: &CopySpec) -> Result<CopyReport> {
    check_directory(src, "the source")?;
    check_directory(dest, "the root filesystem")?;
    let target = Target::new(spec);
    let sources = expand(src, &spec.sources)?;
    // Docker's rule, checked before anything is written.
    let into = target.dir || existing_dir(dest, &target)?;
    if sources.len() > 1 && !into {
        return Err(Error::invalid(format!(
            "{} sources need a directory to copy into, and {target} is not one (a trailing / makes one)",
            sources.len()
        )));
    }
    let mut copier = Copier {
        spec,
        privileged: nix::unistd::geteuid().is_root(),
        report: CopyReport::default(),
        links: HashMap::new(),
    };
    for named in &sources {
        copier.named(src, dest, named, &target, into)?;
    }
    Ok(copier.report)
}

/// A digest of what [`copy`] would copy from `src` (see the module docs):
/// the build cache's key for the step.
pub fn digest(src: BorrowedFd<'_>, spec: &CopySpec) -> Result<Digest> {
    check_directory(src, "the source")?;
    let target = Target::new(spec);
    let sources = expand(src, &spec.sources)?;
    let mut digester = Digester { hasher: Hasher::new(), mode: spec.mode, links: HashMap::new() };
    digester.field(b"rustlet copy 1");
    digester.field(target.absolute().as_bytes());
    digester.number(spec.owner.0.into());
    digester.number(spec.owner.1.into());
    digester.number(spec.mode.map_or(u64::MAX, u64::from));
    digester.number(spec.extract_archives.into());
    for named in &sources {
        digester.named(src, named)?;
    }
    Ok(digester.hasher.digest())
}

/// Refuses a root that isn't a directory: every path in it would fail with
/// `ENOTDIR`, which reads as nothing there.
fn check_directory(fd: BorrowedFd<'_>, what: &str) -> Result<()> {
    let st = nix::sys::stat::fstat(fd).with_context(|| format!("stat {what}"))?;
    if !is_dir(&st) {
        return Err(Error::invalid(format!("{what} is not a directory")));
    }
    Ok(())
}

fn is_dir(st: &FileStat) -> bool {
    st.st_mode & libc::S_IFMT == libc::S_IFDIR
}

/// An entry as messages name it: its path in the source root.
fn shown(rel: &Path) -> String {
    if rel.as_os_str().is_empty() { "\".\"".to_owned() } else { format!("{rel:?}") }
}

/// The components of `path` as Docker cleans it (Go's `path.Join("/", p)`):
/// empty ones and `.` dropped, `..` taking back the one before it, and
/// nothing at the root.
fn clean(path: &str) -> Vec<&str> {
    let mut out = Vec::new();
    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            component => out.push(component),
        }
    }
    out
}

/// Where [`copy`] writes.
struct Target {
    /// Below the root filesystem's root: `spec.dest`, against the working
    /// directory if relative, [`clean`]ed.
    path: PathBuf,
    /// It names a directory: it ends in `/`, `.` or `..`.
    dir: bool,
}

impl Target {
    fn new(spec: &CopySpec) -> Target {
        let full =
            if spec.dest.starts_with('/') { spec.dest.clone() } else { format!("{}/{}", spec.workdir, spec.dest) };
        let last = spec.dest.rsplit('/').next().unwrap_or_default();
        Target { path: clean(&full).into_iter().collect(), dir: matches!(last, "" | "." | "..") }
    }

    /// The path as the image sees it (`/srv/app/`).
    fn absolute(&self) -> String {
        let slash = if self.dir && !self.path.as_os_str().is_empty() { "/" } else { "" };
        format!("/{}{slash}", self.path.display())
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "destination {:?}", self.absolute())
    }
}

/// A source, its wildcards matched.
struct Named<'a> {
    /// As the instruction gives it.
    given: &'a str,
    /// Its path below the source root.
    rel: PathBuf,
    /// `given` has wildcards.
    pattern: bool,
}

impl fmt::Display for Named<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.pattern {
            write!(f, "source {} (matching {:?})", shown(&self.rel), self.given)
        } else {
            write!(f, "source {:?}", self.given)
        }
    }
}

/// `sources` with their wildcards matched, in order (see the module docs).
fn expand<'a>(src: BorrowedFd<'_>, sources: &'a [String]) -> Result<Vec<Named<'a>>> {
    if sources.is_empty() {
        return Err(Error::invalid("no source files were specified"));
    }
    let mut out = Vec::new();
    for given in sources {
        let components = clean(given);
        // Names up to the first pattern, patterns from there on, as
        // BuildKit splits a source: a name after a pattern must be in the
        // listing too (`d*/x` matches `d1/x`, not a `dir/x` that isn't).
        let first = components.iter().position(|c| glob::is_pattern(c.as_bytes()));
        let (names_part, patterns) = components.split_at(first.unwrap_or(components.len()));
        let pattern = first.is_some();
        let mut matched = vec![names_part.iter().collect::<PathBuf>()];
        for component in patterns {
            // Checked here, whatever the directories hold: matching an
            // empty name goes through the whole pattern.
            if glob::matches(component.as_bytes(), b"").is_err() {
                return Err(Error::invalid(format!("source {given:?}: {component:?} is not a valid wildcard pattern")));
            }
            let mut next = Vec::new();
            for dir in &matched {
                for name in names(src, dir, given)? {
                    if glob::matches(component.as_bytes(), name.as_bytes()) == Ok(true) {
                        next.push(dir.join(name));
                    }
                }
            }
            matched = next;
        }
        if matched.is_empty() {
            return Err(Error::NotFound(format!("source {given:?}: no file or directory matches it")));
        }
        out.extend(matched.into_iter().map(|rel| Named { given, rel, pattern }));
    }
    Ok(out)
}

/// The names in the directory `dir` of the source root, sorted; none if it
/// has no such directory.
fn names(src: BorrowedFd<'_>, dir: &Path, given: &str) -> Result<Vec<OsString>> {
    let p = if dir.as_os_str().is_empty() { Path::new(".") } else { dir };
    let fd = match openat2(Some(src), p, OFlag::O_PATH | OFlag::O_DIRECTORY, Mode::empty(), RESOLVE) {
        Ok(fd) => fd,
        Err(Errno::ENOENT | Errno::ENOTDIR) => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("source {given:?}: open {}", shown(dir))),
    };
    entries(fd.as_fd()).with_context(|| format!("source {given:?}: list {}", shown(dir)))
}

/// The source `named`, followed inside the source root: an `O_PATH` fd for
/// it, and what it is.
fn open_named(src: BorrowedFd<'_>, named: &Named<'_>) -> Result<(OwnedFd, FileStat)> {
    let p = if named.rel.as_os_str().is_empty() { Path::new(".") } else { named.rel.as_path() };
    let fd = match openat2(Some(src), p, OFlag::O_PATH, Mode::empty(), RESOLVE) {
        Ok(fd) => fd,
        // Nothing there, a symlink to nothing, or a path through a file.
        Err(Errno::ENOENT | Errno::ENOTDIR) => {
            return Err(Error::NotFound(format!("{named}: no such file or directory")));
        }
        Err(e) => return Err(e).with_context(|| format!("{named}: open")),
    };
    let st = nix::sys::stat::fstat(&fd).with_context(|| format!("{named}: stat"))?;
    Ok((fd, st))
}

/// Opens `fd`, an `O_PATH` fd that `st` says is a regular file or a
/// directory, for reading, and checks it is still that inode. A file is
/// opened through its magic link, with `open_source`'s other flags (see the
/// module docs).
fn open_checked(fd: BorrowedFd<'_>, st: &FileStat, shown: &str) -> Result<OwnedFd> {
    let opened = if is_dir(st) {
        nix::fcntl::openat(fd, ".", OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC, Mode::empty())
    } else {
        rustlet_sys::fs::reopen(fd, OFlag::O_RDONLY | OFlag::O_NONBLOCK | OFlag::O_NOCTTY)
    }
    .with_context(|| format!("{shown}: open"))?;
    let now = nix::sys::stat::fstat(&opened).with_context(|| format!("{shown}: stat"))?;
    let inode = |st: &FileStat| (st.st_dev, st.st_ino, st.st_mode & libc::S_IFMT);
    if inode(&now) != inode(st) {
        return Err(Error::invalid(format!("{shown}: replaced while it was being copied")));
    }
    Ok(opened)
}

/// The directory `path` below `root`, resolved inside it, open for reading.
fn open_dir_in(root: BorrowedFd<'_>, path: &Path) -> rustlet_sys::Result<OwnedFd> {
    let p = if path.as_os_str().is_empty() { Path::new(".") } else { path };
    openat2(Some(root), p, OFlag::O_RDONLY | OFlag::O_DIRECTORY, Mode::empty(), RESOLVE)
}

/// Does the destination resolve, inside the root filesystem, to a
/// directory?
fn existing_dir(root: BorrowedFd<'_>, target: &Target) -> Result<bool> {
    match open_dir_in(root, &target.path) {
        Ok(_) => Ok(true),
        // Nothing, a non-directory, or a symlink loop: what a file replaces.
        Err(Errno::ENOENT | Errno::ENOTDIR | Errno::ELOOP) => Ok(false),
        Err(e) => Err(e).with_context(|| format!("{target}: open it")),
    }
}

/// Makes room for a new entry `name` in `dir`: a directory there stays if
/// the new entry is one too (true: it is merged into); anything else is
/// removed, a directory with everything in it.
fn make_room(dir: BorrowedFd<'_>, name: &OsStr, new_is_dir: bool, shown: &str) -> Result<bool> {
    let st = match nix::sys::stat::fstatat(dir, name, AtFlags::AT_SYMLINK_NOFOLLOW) {
        Ok(st) => st,
        Err(Errno::ENOENT) => return Ok(false),
        Err(e) => return Err(e).with_context(|| format!("{shown}: stat what the destination has there")),
    };
    if new_is_dir && is_dir(&st) {
        return Ok(true);
    }
    rustlet_sys::tree::remove_tree_at(dir, name)
        .with_context(|| format!("{shown}: replace what the destination has there"))?;
    Ok(false)
}

/// How `file` is compressed, if it is a tar archive (see the module docs).
/// `file` is left at its start.
fn archive(file: &mut File) -> io::Result<Option<Compression>> {
    let mut magic = Vec::with_capacity(4);
    (&mut *file).take(4).read_to_end(&mut magic)?;
    file.rewind()?;
    let compression = detect_compression(&magic);
    let mut block = Vec::with_capacity(BLOCK);
    let read = match compression {
        Compression::None => (&mut *file).take(BLOCK as u64).read_to_end(&mut block),
        Compression::Gzip => flate2::read::MultiGzDecoder::new(&mut *file).take(BLOCK as u64).read_to_end(&mut block),
        Compression::Zstd => zstd::stream::read::Decoder::new(&mut *file)
            .and_then(|decoder| decoder.take(BLOCK as u64).read_to_end(&mut block)),
    };
    file.rewind()?;
    match read {
        Ok(_) => Ok(is_tar_header(&block).then_some(compression)),
        // Not what its magic number says: a file like any other.
        Err(_) if compression != Compression::None => Ok(None),
        Err(e) => Err(e),
    }
}

/// Is `block` a tar header: the magic, and a checksum that adds up as the
/// `tar` crate counts it (bytes unsigned, the checksum field as spaces)?
fn is_tar_header(block: &[u8]) -> bool {
    if block.len() != BLOCK || &block[MAGIC] != b"ustar" {
        return false;
    }
    let mut header = tar::Header::new_old();
    header.as_mut_bytes().copy_from_slice(block);
    let sum = block
        .iter()
        .enumerate()
        .map(|(i, &b)| if CHECKSUM.contains(&i) { u32::from(b' ') } else { u32::from(b) })
        .sum::<u32>();
    header.cksum().is_ok_and(|cksum| cksum == sum)
}

/// A directory being copied: its entries are copied in turn, then its own
/// metadata is set.
struct Frame {
    /// The source directory and its copy, both open for reading.
    src: OwnedFd,
    dst: OwnedFd,
    /// The entries still to copy.
    names: std::vec::IntoIter<OsString>,
    /// Its path below the source root.
    rel: PathBuf,
    st: FileStat,
    /// The destination directory itself, which keeps its own metadata.
    top: bool,
}

/// The copy of an inode with more than one name, for its later names.
struct Linked {
    copy: OwnedFd,
    /// Its first name, as messages show it.
    shown: String,
    /// Names of the source inode not seen yet. Names outside what is
    /// copied are never seen: such an entry stays to the end.
    remaining: u64,
}

struct Copier<'a> {
    spec: &'a CopySpec,
    /// Running as root: what is made gets `spec.owner`.
    privileged: bool,
    report: CopyReport,
    /// Inodes with more than one name, by the source's `(st_dev, st_ino)`.
    links: HashMap<(u64, u64), Linked>,
}

impl Copier<'_> {
    /// Copies one source, followed: a directory's contents into the
    /// destination directory, anything else to its place (see the module
    /// docs).
    fn named(
        &mut self,
        src: BorrowedFd<'_>,
        root: BorrowedFd<'_>,
        named: &Named<'_>,
        target: &Target,
        into: bool,
    ) -> Result<()> {
        let (fd, st) = open_named(src, named)?;
        let shown = named.to_string();
        match st.st_mode & libc::S_IFMT {
            libc::S_IFDIR => {
                let from = open_checked(fd.as_fd(), &st, &shown)?;
                let to = self.dest_dir(root, &target.path, target)?;
                self.tree(from, to, named.rel.clone(), st)
            }
            libc::S_IFREG => {
                let mut from = File::from(open_checked(fd.as_fd(), &st, &shown)?);
                if self.spec.extract_archives
                    && let Some(compression) = archive(&mut from).with_context(|| format!("{shown}: read"))?
                {
                    let to = self.dest_dir(root, &target.path, target)?;
                    return self.extract(from, compression, to.as_fd(), &named.rel, &shown);
                }
                let (dir, name) = self.place(root, named, target, into)?;
                if st.st_nlink > 1 && self.link(&st, dir.as_fd(), &name, &shown)? {
                    return Ok(());
                }
                let copy = self.file(from, dir.as_fd(), &name, &st, &shown)?;
                self.made(Some(copy), dir.as_fd(), &name, &st, &shown)
            }
            libc::S_IFIFO => {
                let (dir, name) = self.place(root, named, target, into)?;
                if st.st_nlink > 1 && self.link(&st, dir.as_fd(), &name, &shown)? {
                    return Ok(());
                }
                // Without attributes: its `O_PATH` fd can't read them.
                let copy = self.fifo(None, dir.as_fd(), &name, &st, &shown)?;
                self.made(Some(copy), dir.as_fd(), &name, &st, &shown)
            }
            // Device nodes and sockets. (A symlink was followed.)
            _ => {
                self.report.skipped.push(named.rel.clone());
                Ok(())
            }
        }
    }

    /// Where a source that isn't a directory goes: the destination
    /// directory and the source's name, or the destination's parent and its
    /// name.
    fn place(
        &mut self,
        root: BorrowedFd<'_>,
        named: &Named<'_>,
        target: &Target,
        into: bool,
    ) -> Result<(OwnedFd, OsString)> {
        match (into, target.path.file_name(), named.rel.file_name()) {
            (false, Some(name), _) => {
                let parent = target.path.parent().unwrap_or(Path::new(""));
                Ok((self.dest_dir(root, parent, target)?, name.to_owned()))
            }
            (_, _, Some(name)) => Ok((self.dest_dir(root, &target.path, target)?, name.to_owned())),
            // Only the source root has no name, and it is a directory.
            (_, _, None) => Err(Error::invalid(format!("{named}: not a file"))),
        }
    }

    /// The directory `path` (the destination, or its parent) below the root
    /// filesystem's root, resolved inside it, with what is missing made one
    /// component at a time, relative to the last directory reached.
    fn dest_dir(&self, root: BorrowedFd<'_>, path: &Path, target: &Target) -> Result<OwnedFd> {
        match open_dir_in(root, path) {
            Ok(fd) => return Ok(fd),
            Err(Errno::ENOENT | Errno::ENOTDIR) => {}
            Err(e) => return Err(e).with_context(|| format!("{target}: open /{}", path.display())),
        }
        let mut so_far = PathBuf::new();
        let mut cur = open_dir_in(root, &so_far).context("open the root filesystem")?;
        for component in path.components() {
            let name = component.as_os_str();
            so_far.push(name);
            let at = || format!("{target}: /{}", so_far.display());
            cur = match open_dir_in(root, &so_far) {
                Ok(fd) => fd,
                Err(Errno::ENOENT) => match self.mkdir(cur.as_fd(), name) {
                    Ok(fd) => fd,
                    // ENOENT through a name that exists: a symlink to a
                    // directory the image doesn't have. (`mkdir -p` fails
                    // here too, and so does Docker.)
                    Err(Errno::EEXIST) => {
                        return Err(Error::invalid(format!("{}: a symlink to a directory that doesn't exist", at())));
                    }
                    Err(e) => return Err(e).with_context(at),
                },
                Err(Errno::ENOTDIR) => return Err(Error::invalid(format!("{}: not a directory", at()))),
                Err(e) => return Err(e).with_context(at),
            };
        }
        Ok(cur)
    }

    /// A directory the copy has to make: `0755`, and `spec.owner`'s.
    fn mkdir(&self, parent: BorrowedFd<'_>, name: &OsStr) -> rustlet_sys::Result<OwnedFd> {
        nix::sys::stat::mkdirat(parent, name, Mode::from_bits_truncate(0o755))?;
        let fd = nix::fcntl::openat(
            parent,
            name,
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )?;
        self.chown(fd.as_fd())?;
        // Explicitly: mkdirat's mode is subject to the umask.
        nix::sys::stat::fchmod(&fd, Mode::from_bits_truncate(0o755))?;
        Ok(fd)
    }

    /// Gives `fd` the copy's owner, if the copy can.
    fn chown(&self, fd: BorrowedFd<'_>) -> rustlet_sys::Result<()> {
        if !self.privileged {
            return Ok(());
        }
        let (uid, gid) = self.spec.owner;
        nix::unistd::fchown(fd, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid)))
    }

    /// The walk: the entries of `src` copied into `dst`, the destination
    /// directory. It uses its own stack, not recursion, as `copyup` does.
    fn tree(&mut self, src: OwnedFd, dst: OwnedFd, rel: PathBuf, st: FileStat) -> Result<()> {
        let mut stack = vec![self.frame(src, dst, rel, st, true)?];
        while let Some(dir) = stack.last_mut() {
            let Some(name) = dir.names.next() else {
                let done = stack.pop().expect("the loop just looked at it");
                if !done.top {
                    self.finish(&done)?;
                }
                continue;
            };
            if let Some(sub) = self.entry(dir, &name)? {
                if stack.len() > MAX_DEPTH {
                    return Err(Error::unsupported(format!("{}: more than {MAX_DEPTH} levels deep", shown(&sub.rel))));
                }
                stack.push(sub);
            }
        }
        Ok(())
    }

    /// A directory and its copy, with its names read.
    fn frame(&self, src: OwnedFd, dst: OwnedFd, rel: PathBuf, st: FileStat, top: bool) -> Result<Frame> {
        let names = entries(src.as_fd()).with_context(|| format!("{}: list it", shown(&rel)))?;
        Ok(Frame { src, dst, names: names.into_iter(), rel, st, top })
    }

    /// Copies the entry `name` of `dir`, never following it. A directory is
    /// only made (or found), and returned for the walk to enter.
    fn entry(&mut self, dir: &Frame, name: &OsStr) -> Result<Option<Frame>> {
        let rel = dir.rel.join(name);
        let shown = shown(&rel);
        let st = nix::sys::stat::fstatat(&dir.src, name, AtFlags::AT_SYMLINK_NOFOLLOW)
            .with_context(|| format!("{shown}: stat"))?;
        let kind = st.st_mode & libc::S_IFMT;
        if kind == libc::S_IFDIR {
            return self.directory(dir, name, rel, st, &shown).map(Some);
        }
        if !matches!(kind, libc::S_IFREG | libc::S_IFLNK | libc::S_IFIFO) {
            // Device nodes and sockets.
            self.report.skipped.push(rel);
            return Ok(None);
        }
        let (src, dst) = (dir.src.as_fd(), dir.dst.as_fd());
        if st.st_nlink > 1 && self.link(&st, dst, name, &shown)? {
            return Ok(None);
        }
        let copy = match kind {
            libc::S_IFREG => {
                let from = File::from(open_source(src, name, &st, &shown)?);
                Some(self.file(from, dst, name, &st, &shown)?)
            }
            libc::S_IFIFO => Some(self.fifo(Some(&Attrs::at(src, name)), dst, name, &st, &shown)?),
            _ => {
                self.symlink(src, dst, name, &st, &shown)?;
                None
            }
        };
        self.made(copy, dst, name, &st, &shown)?;
        Ok(None)
    }

    /// A directory below the destination directory: made, private until
    /// [`finish`](Self::finish), or merged into if the destination has one.
    fn directory(&mut self, parent: &Frame, name: &OsStr, rel: PathBuf, st: FileStat, shown: &str) -> Result<Frame> {
        let src = open_source(parent.src.as_fd(), name, &st, shown)?;
        if !make_room(parent.dst.as_fd(), name, true, shown)? {
            nix::sys::stat::mkdirat(&parent.dst, name, Mode::from_bits_truncate(0o700))
                .with_context(|| format!("{shown}: create the copy"))?;
        }
        self.report.entries += 1;
        let dst = nix::fcntl::openat(
            &parent.dst,
            name,
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .with_context(|| format!("{shown}: open the copy"))?;
        self.frame(src, dst, rel, st, false)
    }

    /// A later name of an inode already copied becomes a link to the copy.
    /// False for the inode's first name.
    fn link(&mut self, st: &FileStat, dst: BorrowedFd<'_>, name: &OsStr, shown: &str) -> Result<bool> {
        let key = (st.st_dev, st.st_ino);
        let Some(linked) = self.links.get_mut(&key) else { return Ok(false) };
        make_room(dst, name, false, shown)?;
        link_fd(linked.copy.as_fd(), dst, name).with_context(|| format!("{shown}: link it to {}", linked.shown))?;
        linked.remaining -= 1;
        if linked.remaining == 0 {
            self.links.remove(&key);
        }
        self.report.entries += 1;
        Ok(true)
    }

    /// Counts a non-directory just copied, and keeps its copy for the later
    /// names of an inode with several.
    fn made(
        &mut self,
        copy: Option<OwnedFd>,
        dst: BorrowedFd<'_>,
        name: &OsStr,
        st: &FileStat,
        shown: &str,
    ) -> Result<()> {
        self.report.entries += 1;
        if st.st_nlink > 1 {
            // A symlink can only be held `O_PATH`, by the name just made.
            let copy = match copy {
                Some(fd) => fd,
                None => {
                    nix::fcntl::openat(dst, name, OFlag::O_PATH | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC, Mode::empty())
                        .with_context(|| format!("{shown}: open the copy"))?
                }
            };
            let linked = Linked { copy, shown: shown.to_owned(), remaining: st.st_nlink - 1 };
            self.links.insert((st.st_dev, st.st_ino), linked);
        }
        Ok(())
    }

    /// A regular file: contents first (a write clears file capabilities),
    /// then the metadata.
    fn file(
        &mut self,
        mut from: File,
        dst: BorrowedFd<'_>,
        name: &OsStr,
        st: &FileStat,
        shown: &str,
    ) -> Result<OwnedFd> {
        make_room(dst, name, false, shown)?;
        let fd = nix::fcntl::openat(
            dst,
            name,
            OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::from_bits_truncate(0o600),
        )
        .with_context(|| format!("{shown}: create the copy"))?;
        let mut to = File::from(fd);
        self.report.bytes += io::copy(&mut from, &mut to).with_context(|| format!("{shown}: copy the contents"))?;
        self.apply(Some(&Attrs::Fd(from.as_fd())), to.as_fd(), st, shown)?;
        Ok(to.into())
    }

    /// A FIFO: a new one, whose metadata is set through an fd.
    fn fifo(
        &self,
        from: Option<&Attrs<'_>>,
        dst: BorrowedFd<'_>,
        name: &OsStr,
        st: &FileStat,
        shown: &str,
    ) -> Result<OwnedFd> {
        make_room(dst, name, false, shown)?;
        nix::unistd::mkfifoat(dst, name, Mode::from_bits_truncate(0o600))
            .with_context(|| format!("{shown}: create the copy"))?;
        // Opening a FIFO for reading with O_NONBLOCK returns at once. What
        // it opens must be the FIFO just made.
        let fd = nix::fcntl::openat(
            dst,
            name,
            OFlag::O_RDONLY | OFlag::O_NONBLOCK | OFlag::O_NOFOLLOW | OFlag::O_NOCTTY | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .with_context(|| format!("{shown}: open the copy"))?;
        let now = nix::sys::stat::fstat(&fd).with_context(|| format!("{shown}: stat the copy"))?;
        if now.st_mode & libc::S_IFMT != libc::S_IFIFO {
            return Err(Error::invalid(format!("{shown}: the copy was replaced while it was being made")));
        }
        self.apply(from, fd.as_fd(), st, shown)?;
        Ok(fd)
    }

    /// A symlink with the same target. Its metadata is set by name, never
    /// following it.
    fn symlink(
        &self,
        src: BorrowedFd<'_>,
        dst: BorrowedFd<'_>,
        name: &OsStr,
        st: &FileStat,
        shown: &str,
    ) -> Result<()> {
        let target = nix::fcntl::readlinkat(src, name).with_context(|| format!("{shown}: read the link"))?;
        make_room(dst, name, false, shown)?;
        nix::unistd::symlinkat(target.as_os_str(), dst, name).with_context(|| format!("{shown}: create the copy"))?;
        if self.privileged {
            let (uid, gid) = self.spec.owner;
            let (uid, gid) = (Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid)));
            nix::unistd::fchownat(dst, name, uid, gid, AtFlags::AT_SYMLINK_NOFOLLOW)
                .with_context(|| format!("{shown}: set the owner"))?;
        }
        self.xattrs(&Attrs::at(src, name), |attr, value| xattr::lset_at(dst, name, attr, value), shown)?;
        let (atime, mtime) = times(st);
        nix::sys::stat::utimensat(dst, name, &atime, &mtime, UtimensatFlags::NoFollowSymlink)
            .with_context(|| format!("{shown}: set the times"))
    }

    /// A directory whose entries are all copied gets its source's metadata.
    fn finish(&self, dir: &Frame) -> Result<()> {
        self.apply(Some(&Attrs::Fd(dir.src.as_fd())), dir.dst.as_fd(), &dir.st, &shown(&dir.rel))
    }

    /// Owner, mode, attributes, times, in that order (`copyup` says why),
    /// through the copy's fd.
    fn apply(&self, from: Option<&Attrs<'_>>, to: BorrowedFd<'_>, st: &FileStat, shown: &str) -> Result<()> {
        self.chown(to).with_context(|| format!("{shown}: set the owner"))?;
        let mode = self.spec.mode.unwrap_or(st.st_mode) & 0o7777;
        nix::sys::stat::fchmod(to, Mode::from_bits_truncate(mode)).with_context(|| format!("{shown}: set the mode"))?;
        if let Some(from) = from {
            self.xattrs(from, |name, value| xattr::fset(to, name, value), shown)?;
        }
        let (atime, mtime) = times(st);
        nix::sys::stat::futimens(to, &atime, &mtime).with_context(|| format!("{shown}: set the times"))
    }

    /// Copies the attributes `from` has, except overlay's own, with `set`
    /// (see the module docs for those left out).
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
            match set(name, &value) {
                Ok(()) | Err(Errno::ENOTSUP) => {}
                Err(Errno::EPERM) if !self.privileged => {}
                Err(e) => return Err(e).with_context(|| format!("{shown}: set attribute {name}")),
            }
        }
        Ok(())
    }

    /// `ADD`: the archive `from` extracted into the directory `to`.
    fn extract(
        &mut self,
        from: File,
        compression: Compression,
        to: BorrowedFd<'_>,
        rel: &Path,
        shown: &str,
    ) -> Result<()> {
        let r = unpack_with(from, compression, to, &UnpackOptions { whiteouts: false })
            .map_err(|e| Error::invalid(format!("{shown}: extract the archive: {e}")))?;
        let skipped = (r.skipped_devices.len() + r.skipped_other.len()) as u64;
        self.report.entries += r.entries.saturating_sub(skipped);
        self.report.bytes += r.bytes;
        self.report.extracted += 1;
        let inside = |entry: &String| rel.join(clean(entry).into_iter().collect::<PathBuf>());
        self.report.skipped.extend(r.skipped_devices.iter().map(inside));
        Ok(())
    }
}

/// What [`digest`] hashes, as it goes.
struct Digester {
    hasher: Hasher,
    /// `--chmod`: the mode every file and directory gets.
    mode: Option<u32>,
    /// Inodes with more than one name, as [`Copier`] keeps them: the first
    /// name's path below the source root, and the names not seen yet.
    links: HashMap<(u64, u64), (PathBuf, u64)>,
}

/// A directory being hashed.
struct Level {
    fd: OwnedFd,
    names: std::vec::IntoIter<OsString>,
    /// Its path below the source.
    rel: PathBuf,
}

impl Digester {
    /// A field, its length first, so that no two lists of fields hash
    /// alike.
    fn field(&mut self, bytes: &[u8]) {
        self.hasher.update(&(bytes.len() as u64).to_le_bytes());
        self.hasher.update(bytes);
    }

    fn number(&mut self, n: u64) {
        self.hasher.update(&n.to_le_bytes());
    }

    /// An entry: what it is, its path below its source, and the mode its
    /// copy gets (`None`: a symlink's, which has none).
    fn entry(&mut self, kind: &[u8], rel: &Path, mode: Option<u32>) {
        self.field(kind);
        self.field(rel.as_os_str().as_bytes());
        self.number(mode.map_or(u64::MAX, u64::from));
    }

    /// The mode the copy of a file or directory gets.
    fn mode(&self, st: &FileStat) -> u32 {
        self.mode.unwrap_or(st.st_mode & 0o7777)
    }

    /// One source, followed, as [`Copier::named`] copies it.
    fn named(&mut self, src: BorrowedFd<'_>, named: &Named<'_>) -> Result<()> {
        let (fd, st) = open_named(src, named)?;
        let shown = named.to_string();
        self.field(b"source");
        self.field(named.rel.as_os_str().as_bytes());
        match st.st_mode & libc::S_IFMT {
            // Its contents: the directory itself is no copy's.
            libc::S_IFDIR => {
                self.field(b"directory");
                self.tree(open_checked(fd.as_fd(), &st, &shown)?, &named.rel)
            }
            kind @ (libc::S_IFREG | libc::S_IFIFO) => {
                let here = Path::new("");
                if self.linked(&st, here, &named.rel) {
                    return Ok(());
                }
                if kind == libc::S_IFIFO {
                    self.entry(b"fifo", here, Some(self.mode(&st)));
                    return Ok(());
                }
                self.file(here, File::from(open_checked(fd.as_fd(), &st, &shown)?), &st, &shown)
            }
            // Device nodes and sockets aren't copied.
            _ => Ok(()),
        }
    }

    /// The entries below the directory `dir` (the source `top`), in the
    /// order [`Copier::tree`] copies them.
    fn tree(&mut self, dir: OwnedFd, top: &Path) -> Result<()> {
        let names = entries(dir.as_fd()).with_context(|| format!("{}: list it", shown(top)))?;
        let mut stack = vec![Level { fd: dir, names: names.into_iter(), rel: PathBuf::new() }];
        while let Some(level) = stack.last_mut() {
            let Some(name) = level.names.next() else {
                stack.pop();
                continue;
            };
            if let Some(sub) = self.tree_entry(level, &name, top)? {
                if stack.len() > MAX_DEPTH {
                    let deep = shown(&top.join(&sub.rel));
                    return Err(Error::unsupported(format!("{deep}: more than {MAX_DEPTH} levels deep")));
                }
                stack.push(sub);
            }
        }
        Ok(())
    }

    /// The entry `name` of `level`, never followed. A directory is returned
    /// for the walk to enter.
    fn tree_entry(&mut self, level: &Level, name: &OsStr, top: &Path) -> Result<Option<Level>> {
        let rel = level.rel.join(name);
        let full = top.join(&rel);
        let shown = shown(&full);
        let st = nix::sys::stat::fstatat(&level.fd, name, AtFlags::AT_SYMLINK_NOFOLLOW)
            .with_context(|| format!("{shown}: stat"))?;
        let kind = st.st_mode & libc::S_IFMT;
        match kind {
            libc::S_IFDIR => {
                self.entry(b"directory", &rel, Some(self.mode(&st)));
                let fd = open_source(level.fd.as_fd(), name, &st, &shown)?;
                let names = entries(fd.as_fd()).with_context(|| format!("{shown}: list it"))?;
                return Ok(Some(Level { fd, names: names.into_iter(), rel }));
            }
            libc::S_IFREG | libc::S_IFLNK | libc::S_IFIFO => {}
            // Device nodes and sockets aren't copied.
            _ => return Ok(None),
        }
        if self.linked(&st, &rel, &full) {
            return Ok(None);
        }
        match kind {
            libc::S_IFREG => {
                let file = File::from(open_source(level.fd.as_fd(), name, &st, &shown)?);
                self.file(&rel, file, &st, &shown)?;
            }
            libc::S_IFLNK => {
                let target =
                    nix::fcntl::readlinkat(&level.fd, name).with_context(|| format!("{shown}: read the link"))?;
                self.entry(b"symlink", &rel, None);
                self.field(target.as_bytes());
            }
            _ => self.entry(b"fifo", &rel, Some(self.mode(&st))),
        }
        Ok(None)
    }

    /// A later name of an inode with several, hashed as a link to its first
    /// name (as [`Copier::link`] makes it). False for the first name.
    fn linked(&mut self, st: &FileStat, rel: &Path, full: &Path) -> bool {
        if st.st_nlink <= 1 {
            return false;
        }
        let first = match self.links.entry((st.st_dev, st.st_ino)) {
            Entry::Vacant(entry) => {
                entry.insert((full.to_owned(), st.st_nlink - 1));
                return false;
            }
            Entry::Occupied(mut entry) => {
                entry.get_mut().1 -= 1;
                if entry.get().1 == 0 { entry.remove().0 } else { entry.get().0.clone() }
            }
        };
        self.field(b"link");
        self.field(rel.as_os_str().as_bytes());
        self.field(first.as_os_str().as_bytes());
        true
    }

    /// A regular file: its size and the digest of its contents.
    fn file(&mut self, rel: &Path, file: File, st: &FileStat, shown: &str) -> Result<()> {
        let mut contents = HashingReader::new(file);
        io::copy(&mut contents, &mut io::sink()).with_context(|| format!("{shown}: read it"))?;
        self.entry(b"file", rel, Some(self.mode(st)));
        self.number(contents.count());
        self.field(contents.digest().hex().as_bytes());
        Ok(())
    }
}

/// Go's `filepath.Match` (on Unix, where `\` escapes), which Docker matches
/// sources with, on bytes: a name needn't be UTF-8. Here it only ever sees
/// one component and one name, but it is the whole of Go's function, `/`
/// rules included.
mod glob {
    /// A pattern that isn't well formed (Go's `ErrBadPattern`).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) struct BadPattern;

    const SEPARATOR: u8 = b'/';
    /// What Go's `utf8.DecodeRune` returns for a byte that starts no
    /// character.
    const RUNE_ERROR: u32 = 0xfffd;

    /// Is `component` a pattern? Docker's `containsWildcards`: an unescaped
    /// `*`, `?` or `[`.
    pub(super) fn is_pattern(component: &[u8]) -> bool {
        let mut i = 0;
        while i < component.len() {
            match component[i] {
                b'\\' => i += 1,
                b'*' | b'?' | b'[' => return true,
                _ => {}
            }
            i += 1;
        }
        false
    }

    /// Does `name` match `pattern`, all of it?
    pub(super) fn matches(mut pattern: &[u8], mut name: &[u8]) -> Result<bool, BadPattern> {
        'pattern: while !pattern.is_empty() {
            let (star, chunk, rest) = scan_chunk(pattern);
            pattern = rest;
            if star && chunk.is_empty() {
                // A trailing `*` matches the rest of the name, without a `/`.
                return Ok(!name.contains(&SEPARATOR));
            }
            // A match at the current position. The last chunk must use up
            // the name; otherwise a `*` may still find a later match.
            let here = match_chunk(chunk, name);
            if let Ok(Some(rest)) = here
                && (rest.is_empty() || !pattern.is_empty())
            {
                name = rest;
                continue;
            }
            here?;
            if star {
                // A match after skipping i + 1 bytes; a `*` can't skip a `/`.
                let mut i = 0;
                while i < name.len() && name[i] != SEPARATOR {
                    if let Some(rest) = match_chunk(chunk, &name[i + 1..])? {
                        if pattern.is_empty() && !rest.is_empty() {
                            i += 1;
                            continue;
                        }
                        name = rest;
                        continue 'pattern;
                    }
                    i += 1;
                }
            }
            // No match, but the rest of the pattern must still be well
            // formed.
            while !pattern.is_empty() {
                let (_, chunk, rest) = scan_chunk(pattern);
                pattern = rest;
                match_chunk(chunk, b"")?;
            }
            return Ok(false);
        }
        Ok(name.is_empty())
    }

    /// The next chunk of `pattern`: whether `*`s come before it, the chunk
    /// (up to the next `*` outside brackets), and the rest.
    fn scan_chunk(mut pattern: &[u8]) -> (bool, &[u8], &[u8]) {
        let mut star = false;
        while let [b'*', rest @ ..] = pattern {
            pattern = rest;
            star = true;
        }
        let mut in_range = false;
        let mut i = 0;
        while i < pattern.len() {
            match pattern[i] {
                // A `\` at the end is for `match_chunk` to refuse.
                b'\\' if i + 1 < pattern.len() => i += 1,
                b'[' => in_range = true,
                b']' => in_range = false,
                b'*' if !in_range => break,
                _ => {}
            }
            i += 1;
        }
        (star, &pattern[..i], &pattern[i..])
    }

    /// Does `chunk` (no `*` in it) match the start of `s`? What follows the
    /// match, if so.
    fn match_chunk<'a>(mut chunk: &[u8], mut s: &'a [u8]) -> Result<Option<&'a [u8]>, BadPattern> {
        // After a mismatch the chunk is still read through, to check it is
        // well formed, but `s` no longer is.
        let mut failed = false;
        while let Some(&c) = chunk.first() {
            if !failed && s.is_empty() {
                failed = true;
            }
            match c {
                b'[' => {
                    let mut r = 0;
                    if !failed {
                        let (rune, n) = decode(s);
                        r = rune;
                        s = &s[n..];
                    }
                    chunk = &chunk[1..];
                    let negated = chunk.first() == Some(&b'^');
                    if negated {
                        chunk = &chunk[1..];
                    }
                    let mut matched = false;
                    let mut ranges = 0;
                    loop {
                        if chunk.first() == Some(&b']') && ranges > 0 {
                            chunk = &chunk[1..];
                            break;
                        }
                        let (lo, rest) = class_char(chunk)?;
                        chunk = rest;
                        let mut hi = lo;
                        if chunk.first() == Some(&b'-') {
                            (hi, chunk) = class_char(&chunk[1..])?;
                        }
                        if lo <= r && r <= hi {
                            matched = true;
                        }
                        ranges += 1;
                    }
                    if matched == negated {
                        failed = true;
                    }
                }
                b'?' => {
                    if !failed {
                        if s[0] == SEPARATOR {
                            failed = true;
                        }
                        s = &s[decode(s).1..];
                    }
                    chunk = &chunk[1..];
                }
                _ => {
                    if c == b'\\' {
                        chunk = &chunk[1..];
                        if chunk.is_empty() {
                            return Err(BadPattern);
                        }
                    }
                    if !failed {
                        if chunk[0] != s[0] {
                            failed = true;
                        }
                        s = &s[1..];
                    }
                    chunk = &chunk[1..];
                }
            }
        }
        Ok(if failed { None } else { Some(s) })
    }

    /// A character of a class, escaped or not, and the rest of the chunk,
    /// which can't be empty: the class has yet to end (Go's `getEsc`).
    fn class_char(mut chunk: &[u8]) -> Result<(u32, &[u8]), BadPattern> {
        match chunk.first() {
            None | Some(b'-' | b']') => return Err(BadPattern),
            Some(b'\\') => {
                chunk = &chunk[1..];
                if chunk.is_empty() {
                    return Err(BadPattern);
                }
            }
            Some(_) => {}
        }
        let (r, n) = decode(chunk);
        let rest = &chunk[n..];
        if (r == RUNE_ERROR && n == 1) || rest.is_empty() {
            return Err(BadPattern);
        }
        Ok((r, rest))
    }

    /// Go's `utf8.DecodeRune`: the character `b` starts with and its length
    /// in bytes, `(U+FFFD, 1)` for a byte that starts none.
    fn decode(b: &[u8]) -> (u32, usize) {
        let len = match b.first() {
            None => return (RUNE_ERROR, 0),
            Some(0x00..=0x7f) => 1,
            Some(0xc2..=0xdf) => 2,
            Some(0xe0..=0xef) => 3,
            Some(0xf0..=0xf4) => 4,
            Some(_) => return (RUNE_ERROR, 1),
        };
        match b.get(..len).map(std::str::from_utf8) {
            Some(Ok(c)) => (c.chars().next().map_or(RUNE_ERROR, u32::from), len),
            _ => (RUNE_ERROR, 1),
        }
    }
}

#[cfg(test)]
mod tests;

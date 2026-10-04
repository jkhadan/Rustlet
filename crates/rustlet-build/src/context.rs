//! Packing a build context: the client's half of a build.
//!
//! `rustlet build DIR` sends DIR as a tar archive, less what the ignore
//! file excludes (`ignore`). Like Docker's CLI, the client does this, so
//! that what is excluded (a `target/` of gigabytes, `.git`, secrets) never
//! leaves it:
//!
//! - entries in byte order of their names, each directory before what it
//!   holds (a depth-first walk); directories, regular files, symlinks (as
//!   symlinks, their targets as they are, never followed); hard links as
//!   separate files; FIFOs, sockets and devices left out;
//! - owners 0:0 and no user or group names (`COPY` sets its own owners;
//!   the client's ids mean nothing in an image); modes and modification
//!   times kept;
//! - the Containerfile and the ignore file are always included, even if a
//!   pattern excludes them (the daemon needs the first; Docker does the
//!   same);
//! - a Containerfile outside the context (`-f ../Containerfile`) is added
//!   as `.rustlet-containerfile` ([`dockerfile_name`] says which name the
//!   build's options should give);
//! - a symlink or a path that can't be read is an error naming it, except
//!   what is excluded (never looked at, unless an exception needs the walk
//!   to enter it: then a directory that can't be read is left out);
//! - an excluded directory the walk enters for an exception is in the
//!   archive only if something below it is.
//!
//! [`pack`] writes to any `std::io::Write`: `rustlet_client::RequestBody::
//! pipe` sends it as it is written.

use std::ffi::OsString;
use std::fs::{self, File, Metadata};
use std::io::{self, Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};

use crate::ignore::{IgnoreRules, ignore_file};

/// What a Containerfile from outside the context is called inside it.
const OUTSIDE_NAME: &str = ".rustlet-containerfile";

/// The default Containerfile of `context`: `Containerfile`, else
/// `Dockerfile`, if one is there.
pub fn default_containerfile(context: &Path) -> Option<PathBuf> {
    ["Containerfile", "Dockerfile"].into_iter().map(|name| context.join(name)).find(|path| path.is_file())
}

/// The name the Containerfile `containerfile` has inside the packed
/// context (its path relative to `context`, `/`-separated, or
/// `.rustlet-containerfile` when it is outside): what
/// `BuildOptions::dockerfile` should say.
pub fn dockerfile_name(context: &Path, containerfile: &Path) -> Result<String, ContextError> {
    let root = context.canonicalize().map_err(|source| io_error(context, source))?;
    Ok(match locate(&root, containerfile)? {
        Location::Inside(name) => name,
        Location::Outside(_) => OUTSIDE_NAME.to_owned(),
    })
}

/// Where the Containerfile is, for the archive.
enum Location {
    /// In the context, at this path (symlinks resolved).
    Inside(String),
    /// Elsewhere (or at a path that isn't UTF-8): added as
    /// `.rustlet-containerfile`, from this file.
    Outside(PathBuf),
}

/// `containerfile` against the canonical context directory `root`.
fn locate(root: &Path, containerfile: &Path) -> Result<Location, ContextError> {
    let file = containerfile.canonicalize().map_err(|source| io_error(containerfile, source))?;
    let metadata = fs::metadata(&file).map_err(|source| io_error(&file, source))?;
    if !metadata.is_file() {
        return Err(ContextError::Invalid(format!("{}: the Containerfile isn't a file", containerfile.display())));
    }
    match file.strip_prefix(root).ok().and_then(Path::to_str) {
        Some(name) if !name.is_empty() => Ok(Location::Inside(name.to_owned())),
        _ => Ok(Location::Outside(file)),
    }
}

fn io_error(path: &Path, source: io::Error) -> ContextError {
    ContextError::Io { path: path.to_owned(), source }
}

/// What [`pack`] put in the archive.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Packed {
    /// [`dockerfile_name`]'s answer.
    pub dockerfile: String,
    /// Entries (directories included).
    pub entries: u64,
    /// Bytes of file content.
    pub bytes: u64,
    /// Paths excluded by the ignore file (directories counted once).
    pub excluded: u64,
}

/// Why a context couldn't be packed.
#[derive(Debug, thiserror::Error)]
pub enum ContextError {
    #[error("{path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("{0}")]
    Invalid(String),
}

/// Packs `context` (a directory) with `containerfile` (as given, relative
/// to the current directory or absolute) into `out`.
pub fn pack(context: &Path, containerfile: &Path, out: &mut dyn Write) -> Result<Packed, ContextError> {
    let metadata = fs::metadata(context).map_err(|source| io_error(context, source))?;
    if !metadata.is_dir() {
        return Err(ContextError::Invalid(format!("{}: the build context isn't a directory", context.display())));
    }
    let root = context.canonicalize().map_err(|source| io_error(context, source))?;
    let location = locate(&root, containerfile)?;
    let ignore = ignore_file(context, containerfile);
    let rules = match &ignore {
        Some(path) => {
            let text = fs::read_to_string(path).map_err(|source| io_error(path, source))?;
            IgnoreRules::parse(&text).map_err(|e| ContextError::Invalid(format!("{}: {e}", path.display())))?
        }
        None => IgnoreRules::default(),
    };
    // What the daemon needs whatever the patterns say.
    let mut always = Vec::new();
    let (dockerfile, outside) = match location {
        Location::Inside(name) => {
            always.push(name.clone());
            (name, None)
        }
        Location::Outside(file) => (OUTSIDE_NAME.to_owned(), Some(file)),
    };
    if let Some(path) = &ignore
        && let Ok(path) = path.canonicalize()
        && let Some(name) = path.strip_prefix(&root).ok().and_then(Path::to_str)
    {
        always.push(name.to_owned());
    }
    let mut packer = Packer {
        out: tar::Builder::new(out),
        rules,
        always,
        outside,
        pending: Vec::new(),
        packed: Packed { dockerfile, ..Packed::default() },
    };
    packer.walk(&root, Path::new(""))?;
    packer.out.finish().map_err(|source| io_error(context, source))?;
    Ok(packer.packed)
}

/// The walk's state.
struct Packer<'w> {
    out: tar::Builder<&'w mut dyn Write>,
    rules: IgnoreRules,
    /// Context paths included whatever the patterns say: the Containerfile
    /// and the ignore file.
    always: Vec<String>,
    /// A Containerfile from outside the context, for [`OUTSIDE_NAME`].
    outside: Option<PathBuf>,
    /// Excluded directories the walk is in for an exception (path, context
    /// path, what it is), outermost first: written once something below
    /// them is.
    pending: Vec<(PathBuf, PathBuf, Metadata)>,
    packed: Packed,
}

impl Packer<'_> {
    /// Packs what `dir` (at `rel` in the context) holds.
    fn walk(&mut self, dir: &Path, rel: &Path) -> Result<(), ContextError> {
        let mut names = fs::read_dir(dir)
            .and_then(|entries| entries.map(|entry| entry.map(|e| e.file_name())).collect::<io::Result<Vec<_>>>())
            .map_err(|source| io_error(dir, source))?;
        if rel.as_os_str().is_empty() && self.outside.is_some() {
            // The Containerfile from outside takes the name, and its place.
            names.retain(|name| name != OUTSIDE_NAME);
            names.push(OsString::from(OUTSIDE_NAME));
        }
        names.sort();
        for name in names {
            let path = dir.join(&name);
            let child = rel.join(&name);
            if let Some(file) = self.outside.as_ref().filter(|_| rel.as_os_str().is_empty() && name == OUTSIDE_NAME) {
                let file = file.clone();
                self.flush_pending()?;
                self.file(&file, &child, None)?;
                continue;
            }
            self.entry(&path, &child)?;
        }
        Ok(())
    }

    fn entry(&mut self, path: &Path, rel: &Path) -> Result<(), ContextError> {
        let name = rel.to_string_lossy();
        let always = self.always.iter().any(|a| *a == name);
        let excluded = !always && self.rules.excludes(&name);
        if excluded {
            let prefix = format!("{name}/");
            let enter = self.rules.may_include_below(&name) || self.always.iter().any(|a| a.starts_with(&prefix));
            // Never looked at, unless an exception may need what is below.
            let directory = if enter { fs::symlink_metadata(path).ok().filter(Metadata::is_dir) } else { None };
            match directory {
                Some(metadata) => {
                    self.pending.push((path.to_owned(), rel.to_owned(), metadata));
                    let depth = self.pending.len();
                    match self.walk(path, rel) {
                        Ok(()) => {}
                        // An excluded directory it can't read: left out.
                        Err(ContextError::Io { path: failed, .. }) if failed == path => {}
                        Err(e) => return Err(e),
                    }
                    // Still pending: nothing below it was included.
                    if self.pending.len() == depth {
                        self.pending.pop();
                        self.packed.excluded += 1;
                    }
                }
                None => self.packed.excluded += 1,
            }
            return Ok(());
        }
        let metadata = fs::symlink_metadata(path).map_err(|source| io_error(path, source))?;
        let kind = metadata.file_type();
        if kind.is_fifo() || kind.is_socket() || kind.is_block_device() || kind.is_char_device() {
            return Ok(());
        }
        self.flush_pending()?;
        if kind.is_dir() {
            self.directory(path, rel, &metadata)?;
            self.walk(path, rel)
        } else if kind.is_symlink() {
            let target = fs::read_link(path).map_err(|source| io_error(path, source))?;
            let mut header = header(tar::EntryType::Symlink, &metadata, 0);
            self.out.append_link(&mut header, rel, &target).map_err(|source| io_error(path, source))?;
            self.packed.entries += 1;
            Ok(())
        } else {
            self.file(path, rel, Some(&metadata))
        }
    }

    /// Writes the excluded directories the walk is in, now that something
    /// below them is in the archive.
    fn flush_pending(&mut self) -> Result<(), ContextError> {
        for (path, rel, metadata) in std::mem::take(&mut self.pending) {
            self.directory(&path, &rel, &metadata)?;
        }
        Ok(())
    }

    fn directory(&mut self, path: &Path, rel: &Path, metadata: &Metadata) -> Result<(), ContextError> {
        let mut name = rel.as_os_str().to_owned();
        name.push("/");
        let mut header = header(tar::EntryType::Directory, metadata, 0);
        self.out.append_data(&mut header, Path::new(&name), io::empty()).map_err(|source| io_error(path, source))?;
        self.packed.entries += 1;
        Ok(())
    }

    /// A regular file. `seen`: what the walk saw at `path` (the file opened
    /// must be that one: no symlink put there since); `None` for the
    /// Containerfile from outside, which is followed as `-f` named it.
    fn file(&mut self, path: &Path, rel: &Path, seen: Option<&Metadata>) -> Result<(), ContextError> {
        let file = File::open(path).map_err(|source| io_error(path, source))?;
        let metadata = file.metadata().map_err(|source| io_error(path, source))?;
        let same = seen.is_none_or(|seen| seen.dev() == metadata.dev() && seen.ino() == metadata.ino());
        if !metadata.is_file() || !same {
            return Err(ContextError::Invalid(format!("{}: changed while the context was packed", path.display())));
        }
        let size = metadata.len();
        let mut header = header(tar::EntryType::Regular, &metadata, size);
        let data = Exact { file, left: size };
        self.out.append_data(&mut header, rel, data).map_err(|source| io_error(path, source))?;
        self.packed.entries += 1;
        self.packed.bytes += size;
        Ok(())
    }
}

/// An entry's header: owners 0:0 without names, the mode and the
/// modification time (whole seconds) as they are.
fn header(kind: tar::EntryType, metadata: &Metadata, size: u64) -> tar::Header {
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(kind);
    header.set_size(size);
    header.set_mode(metadata.mode() & 0o7777);
    header.set_mtime(u64::try_from(metadata.mtime()).unwrap_or(0));
    header.set_uid(0);
    header.set_gid(0);
    header
}

/// A file's first `left` bytes, exactly: the size its header announced. A
/// file that grows is cut there; one that shrinks is an error, since the
/// archive can't be written right any more.
struct Exact {
    file: File,
    left: u64,
}

impl Read for Exact {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.left == 0 {
            return Ok(0);
        }
        let want = usize::try_from(self.left).unwrap_or(usize::MAX).min(buf.len());
        let n = self.file.read(&mut buf[..want])?;
        if n == 0 && want > 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "the file shrank while the context was packed"));
        }
        self.left -= n as u64;
        Ok(n)
    }
}

#[cfg(test)]
mod tests;

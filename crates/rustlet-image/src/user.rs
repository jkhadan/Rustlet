//! Who a container runs as: resolving `USER` against the image's own
//! `/etc/passwd` and `/etc/group`.
//!
//! CONTRACT (to be implemented; delete this paragraph when done). Semantics
//! are runc's `user.GetExecUser`, which Docker uses:
//!
//! * the spec is `user[:group]`, each part a name or a number; empty or
//!   `None` means uid 0 (looked up in passwd for its gid and home);
//! * user: a name must be in passwd (first match wins) → its uid, primary
//!   gid and home; a number is used as is, and if passwd has it, its gid and
//!   home are taken from there; otherwise gid 0, home `/`;
//! * group given: a name must be in group → its gid; a number is used as is;
//!   no supplementary groups then;
//! * no group given and the user was found in passwd by name or number:
//!   supplementary groups are every group whose member list names that user,
//!   in file order, duplicates removed (Docker: `id` in alpine shows root in
//!   `bin`, `daemon`, `sys`, … this way);
//! * ids must fit `0..=u32::MAX - 1` (`-1` means "unchanged" to the kernel);
//! * malformed lines are skipped, as glibc does; lines starting with `#`
//!   too. Fields: passwd `name:pw:uid:gid:gecos:home:shell`, group
//!   `name:pw:gid:member,member`.
//!
//! The files belong to the image, so they are read through the mounted
//! rootfs with `openat2(RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS)` (an
//! absolute symlink stays inside the image), `O_NONBLOCK | O_NOCTTY` (a FIFO
//! must not hang the read), and only if they are regular files, at most
//! 1 MiB each. A missing file is the same as an empty one; one that exists
//! but isn't a regular file, or is larger, is an `Error::Invalid` naming it.

use std::os::fd::BorrowedFd;

use crate::error::Result;

/// A line of `/etc/passwd`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswdEntry {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub home: String,
    pub shell: String,
}

/// A line of `/etc/group`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupEntry {
    pub name: String,
    pub gid: u32,
    pub members: Vec<String>,
}

/// The process identity a `USER` spec resolves to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedUser {
    pub uid: u32,
    pub gid: u32,
    /// Supplementary groups (`process.user.additionalGids`).
    pub additional_gids: Vec<u32>,
    /// The passwd name, if the user was found there.
    pub name: Option<String>,
    /// From passwd, else `/`.
    pub home: String,
}

/// Parses `/etc/passwd` text.
pub fn parse_passwd(text: &str) -> Vec<PasswdEntry> {
    let _ = text;
    unimplemented!("user::parse_passwd")
}

/// Parses `/etc/group` text.
pub fn parse_group(text: &str) -> Vec<GroupEntry> {
    let _ = text;
    unimplemented!("user::parse_group")
}

/// Resolves `spec` (`USER`, or `-u`) against parsed files.
pub fn resolve_in(passwd: &[PasswdEntry], group: &[GroupEntry], spec: Option<&str>) -> Result<ResolvedUser> {
    let _ = (passwd, group, spec);
    unimplemented!("user::resolve_in")
}

/// Resolves `spec` against the files in the mounted rootfs `rootfs` (an fd
/// for its root directory).
pub fn resolve(rootfs: BorrowedFd<'_>, spec: Option<&str>) -> Result<ResolvedUser> {
    let _ = (rootfs, spec);
    unimplemented!("user::resolve")
}

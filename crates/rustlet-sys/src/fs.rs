//! Files and file descriptors: `openat2`, `statx`, `close_range`, sealed memfds.

use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::path::Path;

use bitflags::bitflags;
use nix::fcntl::OFlag;
use nix::sys::stat::Mode;

use crate::{Errno, Result, check, check_int, cstr, owned_fd};

bitflags! {
    /// `RESOLVE_*` flags for `openat2(2)`.
    ///
    /// * `IN_ROOT`: treat `dirfd` as `/`. Absolute symlinks and `..` stay
    ///   inside it, as if the process had `chroot`ed there. This is how we
    ///   resolve paths *inside a container rootfs* from the host.
    /// * `BENEATH`: fail (`EXDEV`) instead of escaping `dirfd`; used for
    ///   untrusted tar entries where an escape attempt is itself an error.
    /// * `NO_MAGICLINKS`: refuse `/proc/<pid>/fd/*`-style magic links.
    /// * `NO_SYMLINKS`, `NO_XDEV`: no symlinks at all / no mount crossings.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct ResolveFlags: u64 {
        const NO_XDEV = 0x01;
        const NO_MAGICLINKS = 0x02;
        const NO_SYMLINKS = 0x04;
        const BENEATH = 0x08;
        const IN_ROOT = 0x10;
        const CACHED = 0x20;
    }
}

/// `struct open_how` from `<linux/openat2.h>`.
#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

/// `openat2(dirfd, path, how)`. `O_CLOEXEC` is always added.
///
/// The kernel may return `EAGAIN` for `IN_ROOT`/`BENEATH` lookups when it sees
/// a concurrent rename; we retry a bounded number of times.
pub fn openat2(
    dirfd: Option<BorrowedFd<'_>>,
    path: impl AsRef<Path>,
    flags: OFlag,
    mode: Mode,
    resolve: ResolveFlags,
) -> Result<OwnedFd> {
    let p = cstr(path.as_ref())?;
    let dfd = dirfd.map_or(libc::AT_FDCWD, |f| f.as_raw_fd());
    let mut how = OpenHow {
        flags: (flags | OFlag::O_CLOEXEC).bits() as u64,
        // The kernel rejects a non-zero mode unless O_CREAT/O_TMPFILE is set.
        mode: if flags.intersects(OFlag::O_CREAT | OFlag::O_TMPFILE) { mode.bits() as u64 } else { 0 },
        resolve: resolve.bits(),
    };
    for _ in 0..32 {
        // SAFETY: `p` is a valid C string and `how` a correctly laid out
        // `struct open_how` whose size we pass; both outlive the call.
        let ret =
            unsafe { libc::syscall(libc::SYS_openat2, dfd, p.as_ptr(), &raw mut how, std::mem::size_of::<OpenHow>()) };
        match check(ret) {
            Ok(fd) => return Ok(owned_fd(fd)),
            Err(Errno::EAGAIN) => continue,
            Err(e) => return Err(e),
        }
    }
    Err(Errno::EAGAIN)
}

/// Opens `path` *inside* the root `root` (`RESOLVE_IN_ROOT |
/// RESOLVE_NO_MAGICLINKS`) as an `O_PATH` handle. Symlinks are followed, but
/// they cannot leave `root`: an absolute link target is re-rooted at `root`.
pub fn open_in_root(root: BorrowedFd<'_>, path: impl AsRef<Path>, extra: OFlag) -> Result<OwnedFd> {
    openat2(Some(root), path, OFlag::O_PATH | extra, Mode::empty(), ResolveFlags::IN_ROOT | ResolveFlags::NO_MAGICLINKS)
}

/// Re-opens an `O_PATH` fd with real access flags via `/proc/self/fd/N`.
///
/// This goes through a magic link on purpose: the fd was resolved safely
/// already, so re-opening it cannot be redirected.
pub fn reopen(fd: BorrowedFd<'_>, flags: OFlag) -> Result<OwnedFd> {
    let path = format!("/proc/self/fd/{}", fd.as_raw_fd());
    nix::fcntl::open(path.as_str(), flags | OFlag::O_CLOEXEC, Mode::empty())
}

/// The fields of `statx(2)` that Rustlets uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Statx {
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub ino: u64,
    pub size: u64,
    /// Device the inode lives on (`st_dev`), as `(major, minor)`.
    pub dev: (u32, u32),
    /// Device number for device files (`st_rdev`), as `(major, minor)`.
    pub rdev: (u32, u32),
    /// Unique ID of the mount the file lives on (`STATX_MNT_ID`, 5.8).
    /// Unlike `st_dev`, this differs for two bind mounts of the same
    /// filesystem, which is why `safe_remove_tree` compares it.
    pub mnt_id: u64,
    pub nlink: u32,
}

impl Statx {
    /// File type bits (`S_IFMT`).
    pub fn file_type(&self) -> u32 {
        self.mode & libc::S_IFMT
    }
    pub fn is_dir(&self) -> bool {
        self.file_type() == libc::S_IFDIR
    }
    pub fn is_symlink(&self) -> bool {
        self.file_type() == libc::S_IFLNK
    }
    pub fn is_char_device(&self) -> bool {
        self.file_type() == libc::S_IFCHR
    }
}

/// `statx(dirfd, path, flags)`. Pass an empty path plus `AT_EMPTY_PATH` in
/// `at_flags` to stat the fd itself.
pub fn statx(dirfd: Option<BorrowedFd<'_>>, path: impl AsRef<Path>, at_flags: libc::c_int) -> Result<Statx> {
    let p = cstr(path.as_ref())?;
    let dfd = dirfd.map_or(libc::AT_FDCWD, |f| f.as_raw_fd());
    // SAFETY: an all-zero `struct statx` is a valid value.
    let mut sx: libc::statx = unsafe { std::mem::zeroed() };
    let mask = libc::STATX_BASIC_STATS | libc::STATX_MNT_ID;
    // SAFETY: `p` is a valid C string and `sx` a writable `struct statx`.
    let ret = unsafe { libc::statx(dfd, p.as_ptr(), at_flags, mask, &raw mut sx) };
    check_int(ret)?;
    Ok(Statx {
        mode: sx.stx_mode as u32,
        uid: sx.stx_uid,
        gid: sx.stx_gid,
        ino: sx.stx_ino,
        size: sx.stx_size,
        dev: (sx.stx_dev_major, sx.stx_dev_minor),
        rdev: (sx.stx_rdev_major, sx.stx_rdev_minor),
        mnt_id: sx.stx_mnt_id,
        nlink: sx.stx_nlink,
    })
}

/// `statx` of an fd itself.
pub fn fstatx(fd: BorrowedFd<'_>) -> Result<Statx> {
    statx(Some(fd), "", libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW)
}

/// Flag for [`close_range`]: mark close-on-exec instead of closing.
pub const CLOSE_RANGE_CLOEXEC: u32 = 1 << 2;

/// `close_range(first, last, flags)` (5.9; `CLOEXEC` flag 5.11).
///
/// With `CLOSE_RANGE_CLOEXEC` nothing is closed *now*, so it cannot pull an fd
/// out from under code that still owns an `OwnedFd` for it; everything in the
/// range is simply closed by the kernel at the next `execve`. That is the only
/// mode we expose, which keeps this function sound.
pub fn close_range_cloexec(first: u32) -> Result<()> {
    // SAFETY: with CLOSE_RANGE_CLOEXEC no descriptor is closed, so no
    // `OwnedFd` in the process is invalidated.
    let ret = unsafe { libc::syscall(libc::SYS_close_range, first, u32::MAX, CLOSE_RANGE_CLOEXEC) };
    check(ret).map(drop)
}

bitflags! {
    /// File seals (`F_SEAL_*`) for memfds.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Seals: libc::c_int {
        /// No further seals may be added.
        const SEAL = libc::F_SEAL_SEAL;
        const SHRINK = libc::F_SEAL_SHRINK;
        const GROW = libc::F_SEAL_GROW;
        const WRITE = libc::F_SEAL_WRITE;
        const FUTURE_WRITE = libc::F_SEAL_FUTURE_WRITE;
        const EXEC = 0x0020; // F_SEAL_EXEC (6.3)
    }
}

/// `memfd_create(name, MFD_CLOEXEC | MFD_ALLOW_SEALING)`.
pub fn memfd_create(name: &str) -> Result<OwnedFd> {
    let n = cstr(name)?;
    // SAFETY: `n` is a valid C string for the duration of the call.
    let ret = unsafe { libc::memfd_create(n.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) };
    check_int(ret).map(|fd| owned_fd(fd.into()))
}

/// `MFD_EXEC` (6.3): the memfd may be executed even when the
/// `vm.memfd_noexec` sysctl makes new memfds non-executable by default.
const MFD_EXEC: libc::c_uint = 0x0010;

/// `memfd_create(name, MFD_CLOEXEC | MFD_ALLOW_SEALING | MFD_EXEC)`: a
/// memfd meant to be `fexecve`d (the runtime's sealed self-copy).
/// `EACCES` if `vm.memfd_noexec = 2` forbids executable memfds.
pub fn memfd_create_exec(name: &str) -> Result<OwnedFd> {
    let n = cstr(name)?;
    let flags = libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING | MFD_EXEC;
    // SAFETY: `n` is a valid C string for the duration of the call.
    let ret = unsafe { libc::memfd_create(n.as_ptr(), flags) };
    check_int(ret).map(|fd| owned_fd(fd.into()))
}

/// `fcntl(F_ADD_SEALS)`.
pub fn add_seals(fd: BorrowedFd<'_>, seals: Seals) -> Result<()> {
    // SAFETY: plain fcntl on a borrowed fd with an integer argument.
    let ret = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_ADD_SEALS, seals.bits()) };
    check_int(ret).map(drop)
}

/// `fcntl(F_GET_SEALS)`. `EINVAL` for files that are not memfds.
pub fn get_seals(fd: BorrowedFd<'_>) -> Result<Seals> {
    // SAFETY: plain fcntl on a borrowed fd.
    let ret = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GET_SEALS) };
    check_int(ret).map(Seals::from_bits_retain)
}

/// `fstatfs(fd).f_type`: the filesystem magic number.
pub fn fs_magic(fd: impl AsFd) -> Result<i64> {
    let st = nix::sys::statfs::fstatfs(fd)?;
    Ok(st.filesystem_type().0 as i64)
}

/// Filesystem magic numbers we check for.
pub mod magic {
    pub const PROC_SUPER_MAGIC: i64 = 0x9fa0;
    pub const SYSFS_MAGIC: i64 = 0x6265_6572;
    pub const CGROUP2_SUPER_MAGIC: i64 = 0x6367_7270;
    pub const TMPFS_MAGIC: i64 = 0x0102_1994;
    pub const OVERLAYFS_SUPER_MAGIC: i64 = 0x794c_7630;
    pub const NSFS_MAGIC: i64 = 0x6e73_6673;
    pub const DEVPTS_SUPER_MAGIC: i64 = 0x1cd1;
}

/// `mkfifoat` via nix, exposed so callers don't need the `fs` feature.
pub fn mkfifo(path: &Path, mode: Mode) -> Result<()> {
    nix::unistd::mkfifo(path, mode)
}

/// Returns the canonical path of an fd from `/proc/self/fd` (diagnostics
/// only; never trust it for security decisions).
pub fn fd_path(fd: BorrowedFd<'_>) -> Option<std::path::PathBuf> {
    std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd())).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;

    #[test]
    fn open_how_size() {
        assert_eq!(std::mem::size_of::<OpenHow>(), 24);
    }

    #[test]
    fn in_root_resolves_absolute_symlinks_inside_root() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("etc")).unwrap();
        std::fs::write(dir.path().join("etc/passwd"), "inside").unwrap();
        // A symlink that points at the *host* /etc/passwd…
        std::os::unix::fs::symlink("/etc/passwd", dir.path().join("link")).unwrap();
        let root = nix::fcntl::open(dir.path(), OFlag::O_PATH | OFlag::O_DIRECTORY, Mode::empty()).unwrap();
        let fd = openat2(Some(root.as_fd()), "link", OFlag::O_RDONLY, Mode::empty(), ResolveFlags::IN_ROOT).unwrap();
        // …resolves to <root>/etc/passwd instead.
        let s = std::fs::read_to_string(format!("/proc/self/fd/{}", fd.as_raw_fd())).unwrap();
        assert_eq!(s, "inside");
    }

    #[test]
    fn beneath_rejects_dotdot_escape() {
        let dir = tempfile::tempdir().unwrap();
        let root = nix::fcntl::open(dir.path(), OFlag::O_PATH | OFlag::O_DIRECTORY, Mode::empty()).unwrap();
        let r = openat2(Some(root.as_fd()), "../../etc/passwd", OFlag::O_RDONLY, Mode::empty(), ResolveFlags::BENEATH);
        assert_eq!(r.unwrap_err(), Errno::EXDEV);
    }

    #[test]
    fn memfd_seals_block_writes() {
        use std::io::Write;
        let fd = memfd_create("t").unwrap();
        let mut f = std::fs::File::from(fd);
        f.write_all(b"hello").unwrap();
        add_seals(f.as_fd(), Seals::SEAL | Seals::SHRINK | Seals::GROW | Seals::WRITE).unwrap();
        assert!(f.write_all(b"x").is_err());
        assert!(get_seals(f.as_fd()).unwrap().contains(Seals::WRITE));
    }

    #[test]
    fn statx_reports_mount_id() {
        let s = statx(None, "/", 0).unwrap();
        assert!(s.is_dir());
        assert!(s.mnt_id > 0);
    }
}

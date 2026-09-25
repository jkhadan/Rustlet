//! Pseudo-terminals: open a PTY master, get its peer, make it the
//! controlling terminal, resize it.

use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd};
use std::path::Path;

use nix::fcntl::OFlag;
use nix::sys::stat::Mode;

use crate::{Result, check_int, owned_fd};

const TIOCGPTN: libc::c_ulong = 0x8004_5430;
const TIOCSPTLCK: libc::c_ulong = 0x4004_5431;
const TIOCGPTPEER: libc::c_ulong = 0x5441;

/// Opens the PTY multiplexer at `ptmx` (normally `/dev/ptmx`, which inside a
/// container is a symlink to the private devpts instance's `pts/ptmx`) and
/// unlocks the new pair. Returns the master.
pub fn open_ptmx(ptmx: &Path) -> Result<OwnedFd> {
    let fd = nix::fcntl::open(ptmx, OFlag::O_RDWR | OFlag::O_NOCTTY | OFlag::O_CLOEXEC, Mode::empty())?;
    let unlock: libc::c_int = 0;
    // SAFETY: TIOCSPTLCK reads one `int` from the pointer, which is live.
    let ret = unsafe { libc::ioctl(fd.as_raw_fd(), TIOCSPTLCK, &raw const unlock) };
    check_int(ret)?;
    Ok(fd)
}

/// Unlocks a PTY master opened some other way (e.g. with `openat2`).
pub fn unlock_pty(master: BorrowedFd<'_>) -> Result<()> {
    let unlock: libc::c_int = 0;
    // SAFETY: TIOCSPTLCK reads one `int` from the pointer, which is live.
    let ret = unsafe { libc::ioctl(master.as_raw_fd(), TIOCSPTLCK, &raw const unlock) };
    check_int(ret).map(drop)
}

/// `TIOCGPTN`: the slave's number, i.e. `/dev/pts/<n>`.
pub fn pty_number(master: BorrowedFd<'_>) -> Result<u32> {
    let mut n: libc::c_uint = 0;
    // SAFETY: TIOCGPTN writes one `unsigned int` to the live pointer.
    let ret = unsafe { libc::ioctl(master.as_raw_fd(), TIOCGPTN, &raw mut n) };
    check_int(ret)?;
    Ok(n)
}

/// `TIOCGPTPEER` (4.13): opens the slave *through the master fd*, so no
/// path lookup (and no race on `/dev/pts/<n>`) is involved.
pub fn open_peer(master: BorrowedFd<'_>) -> Result<OwnedFd> {
    let flags = libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC;
    // SAFETY: TIOCGPTPEER takes open flags by value and returns a new fd.
    let ret = unsafe { libc::ioctl(master.as_raw_fd(), TIOCGPTPEER, flags) };
    check_int(ret).map(|fd| owned_fd(fd.into()))
}

/// `TIOCSCTTY`: make `tty` our controlling terminal (after `setsid`).
pub fn set_controlling_tty(tty: BorrowedFd<'_>) -> Result<()> {
    // SAFETY: TIOCSCTTY takes an int by value (0 = don't steal).
    let ret = unsafe { libc::ioctl(tty.as_raw_fd(), libc::TIOCSCTTY, 0) };
    check_int(ret).map(drop)
}

/// Terminal size in character cells.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WinSize {
    pub rows: u16,
    pub cols: u16,
}

/// `TIOCSWINSZ`. Sent to the master, it raises `SIGWINCH` in the
/// foreground process group on the slave side.
pub fn set_winsize(fd: BorrowedFd<'_>, size: WinSize) -> Result<()> {
    let ws = libc::winsize { ws_row: size.rows, ws_col: size.cols, ws_xpixel: 0, ws_ypixel: 0 };
    // SAFETY: TIOCSWINSZ reads one `struct winsize` from the live pointer.
    let ret = unsafe { libc::ioctl(fd.as_raw_fd(), libc::TIOCSWINSZ, &raw const ws) };
    check_int(ret).map(drop)
}

/// `TIOCGWINSZ`.
pub fn get_winsize(fd: BorrowedFd<'_>) -> Result<WinSize> {
    let mut ws = libc::winsize { ws_row: 0, ws_col: 0, ws_xpixel: 0, ws_ypixel: 0 };
    // SAFETY: TIOCGWINSZ writes one `struct winsize` to the live pointer.
    let ret = unsafe { libc::ioctl(fd.as_raw_fd(), libc::TIOCGWINSZ, &raw mut ws) };
    check_int(ret)?;
    Ok(WinSize { rows: ws.ws_row, cols: ws.ws_col })
}

/// `dup2(old, new)` onto one of the standard streams (0, 1 or 2).
///
/// Duplicating onto an arbitrary number could silently close an fd that an
/// `OwnedFd` elsewhere believes it owns; restricting the target to stdio
/// keeps this safe, since std never hands out `OwnedFd`s for 0–2.
pub fn dup2_stdio(old: BorrowedFd<'_>, stdio: libc::c_int) -> Result<()> {
    if !(0..=2).contains(&stdio) {
        return Err(crate::Errno::EINVAL);
    }
    // SAFETY: the target is one of 0/1/2, which no `OwnedFd` in this
    // process owns; `old` is borrowed and therefore open.
    let ret = unsafe { libc::dup2(old.as_raw_fd(), stdio) };
    check_int(ret).map(drop)
}

/// `isatty(fd)`.
pub fn isatty(fd: BorrowedFd<'_>) -> bool {
    nix::unistd::isatty(fd).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;

    #[test]
    fn open_pty_pair() {
        let m = match open_ptmx(Path::new("/dev/ptmx")) {
            Ok(m) => m,
            Err(_) => return, // no devpts in some CI sandboxes
        };
        let _n = pty_number(m.as_fd()).unwrap();
        let s = open_peer(m.as_fd()).unwrap();
        assert!(isatty(s.as_fd()));
        set_winsize(m.as_fd(), WinSize { rows: 40, cols: 120 }).unwrap();
        assert_eq!(get_winsize(s.as_fd()).unwrap(), WinSize { rows: 40, cols: 120 });
    }
}

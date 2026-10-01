//! Extended attributes on fds (`f*xattr`) and on paths without following
//! the final symlink (`l*xattr`).
//!
//! Layer unpacking uses these to preserve `security.capability` (file caps)
//! and friends, and to set overlayfs' `trusted.overlay.opaque`.

use std::os::fd::{AsRawFd, BorrowedFd};
use std::path::Path;

use crate::{Errno, Result, check, cstr};

fn isize_res(ret: libc::ssize_t) -> Result<usize> {
    check(ret as libc::c_long).map(|v| v as usize)
}

/// `fsetxattr(fd, name, value, 0)`.
pub fn fset(fd: BorrowedFd<'_>, name: &str, value: &[u8]) -> Result<()> {
    let n = cstr(name)?;
    // SAFETY: `n` is a C string and `value` is valid for `len` bytes.
    let ret = unsafe { libc::fsetxattr(fd.as_raw_fd(), n.as_ptr(), value.as_ptr().cast(), value.len(), 0) };
    crate::check_int(ret).map(drop)
}

/// `lsetxattr(path, name, value, 0)`: sets on a symlink itself.
pub fn lset(path: &Path, name: &str, value: &[u8]) -> Result<()> {
    let p = cstr(path)?;
    let n = cstr(name)?;
    // SAFETY: both strings are valid C strings; `value` is valid for `len`.
    let ret = unsafe { libc::lsetxattr(p.as_ptr(), n.as_ptr(), value.as_ptr().cast(), value.len(), 0) };
    crate::check_int(ret).map(drop)
}

/// Sets an attribute on the entry `name` of the directory `dir` *without
/// following it*, the one way to reach a symlink itself by fd: `fsetxattr`
/// needs an fd opened for I/O, and a symlink can only be opened `O_PATH`.
///
/// It calls `lsetxattr("/proc/self/fd/<dir>/<name>")`: the magic link for
/// `dir` is a non-final component, so it is followed to exactly the
/// directory we hold; `name` is final, so `l*` doesn't follow it. `name` must
/// be a single component. Only `trusted.*` and `security.*` attributes exist
/// on symlinks (`user.*` gets `EPERM`).
pub fn lset_at(dir: BorrowedFd<'_>, name: &std::ffi::OsStr, attr: &str, value: &[u8]) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;
    if name.is_empty() || name == "." || name == ".." || name.as_bytes().contains(&b'/') {
        return Err(Errno::EINVAL);
    }
    let path = Path::new(&format!("/proc/self/fd/{}", dir.as_raw_fd())).join(name);
    lset(&path, attr, value)
}

/// `fgetxattr` into a freshly sized buffer. `ENODATA` if absent.
pub fn fget(fd: BorrowedFd<'_>, name: &str) -> Result<Vec<u8>> {
    let n = cstr(name)?;
    let mut buf = vec![0u8; 256];
    loop {
        // SAFETY: `buf` is writable for `len` bytes, `n` is a C string.
        let ret = unsafe { libc::fgetxattr(fd.as_raw_fd(), n.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
        match isize_res(ret) {
            Ok(len) => {
                buf.truncate(len);
                return Ok(buf);
            }
            Err(Errno::ERANGE) if buf.len() < 1 << 20 => buf.resize(buf.len() * 4, 0),
            Err(e) => return Err(e),
        }
    }
}

/// `lgetxattr` (does not follow a final symlink).
pub fn lget(path: &Path, name: &str) -> Result<Vec<u8>> {
    let p = cstr(path)?;
    let n = cstr(name)?;
    let mut buf = vec![0u8; 256];
    loop {
        // SAFETY: `buf` is writable for `len` bytes; both strings are C strings.
        let ret = unsafe { libc::lgetxattr(p.as_ptr(), n.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
        match isize_res(ret) {
            Ok(len) => {
                buf.truncate(len);
                return Ok(buf);
            }
            Err(Errno::ERANGE) if buf.len() < 1 << 20 => buf.resize(buf.len() * 4, 0),
            Err(e) => return Err(e),
        }
    }
}

fn split_names(buf: &[u8]) -> Vec<String> {
    buf.split(|&b| b == 0).filter(|s| !s.is_empty()).map(|s| String::from_utf8_lossy(s).into_owned()).collect()
}

/// `flistxattr`.
pub fn flist(fd: BorrowedFd<'_>) -> Result<Vec<String>> {
    let mut buf = vec![0u8; 1024];
    loop {
        // SAFETY: `buf` is writable for `len` bytes.
        let ret = unsafe { libc::flistxattr(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
        match isize_res(ret) {
            Ok(len) => return Ok(split_names(&buf[..len])),
            Err(Errno::ERANGE) if buf.len() < 1 << 20 => buf.resize(buf.len() * 4, 0),
            Err(e) => return Err(e),
        }
    }
}

/// `llistxattr`.
pub fn llist(path: &Path) -> Result<Vec<String>> {
    let p = cstr(path)?;
    let mut buf = vec![0u8; 1024];
    loop {
        // SAFETY: `buf` is writable for `len` bytes; `p` is a C string.
        let ret = unsafe { libc::llistxattr(p.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
        match isize_res(ret) {
            Ok(len) => return Ok(split_names(&buf[..len])),
            Err(Errno::ERANGE) if buf.len() < 1 << 20 => buf.resize(buf.len() * 4, 0),
            Err(e) => return Err(e),
        }
    }
}

/// `fremovexattr`.
pub fn fremove(fd: BorrowedFd<'_>, name: &str) -> Result<()> {
    let n = cstr(name)?;
    // SAFETY: `n` is a valid C string.
    let ret = unsafe { libc::fremovexattr(fd.as_raw_fd(), n.as_ptr()) };
    crate::check_int(ret).map(drop)
}

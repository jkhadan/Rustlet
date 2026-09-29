//! The kernel keyring (`keyctl(2)`): just enough to give each container a
//! session keyring of its own.
//!
//! Keyrings hold secrets (Kerberos tickets, fscrypt and dm-crypt keys, …)
//! and are **not namespaced**. Every process has a *session* keyring,
//! inherited across `fork` and `execve`; without a new one, a container would
//! share `rustlet-runc`'s, i.e. its caller's. So init joins a fresh, named
//! session keyring first thing, as runc does.

use crate::{Errno, Result, check, cstr};

/// A key or keyring serial number.
pub type KeySerial = i32;

const KEYCTL_GET_KEYRING_ID: libc::c_int = 0;
const KEYCTL_JOIN_SESSION_KEYRING: libc::c_int = 1;
const KEYCTL_SETPERM: libc::c_int = 5;
const KEYCTL_DESCRIBE: libc::c_int = 6;

/// Permission bit: the key's owner may *search* it (`KEY_USR_SEARCH`).
/// Permissions are four bytes: possessor, user, group, other; each has
/// VIEW 0x01, READ 0x02, WRITE 0x04, SEARCH 0x08, LINK 0x10, SETATTR 0x20.
pub const KEY_USR_SEARCH: u32 = 0x08 << 16;

/// `KEYCTL_JOIN_SESSION_KEYRING`: joins the session keyring called `name`,
/// creating it if no keyring of that name is searchable by us, and returns
/// its serial number. `ENOSYS` if the kernel has no keyring support.
pub fn join_session_keyring(name: &str) -> Result<KeySerial> {
    let n = cstr(name)?;
    // SAFETY: KEYCTL_JOIN_SESSION_KEYRING reads one NUL-terminated string,
    // which `n` provides for the duration of the call.
    let ret = unsafe { libc::syscall(libc::SYS_keyctl, KEYCTL_JOIN_SESSION_KEYRING, n.as_ptr()) };
    check(ret).map(|v| v as KeySerial)
}

/// `KEY_SPEC_SESSION_KEYRING`: "the caller's session keyring", for calls
/// that take a key serial.
pub const SESSION_KEYRING: KeySerial = -3;

/// `KEYCTL_GET_KEYRING_ID` (without creating anything): the real serial
/// number behind a special id such as [`SESSION_KEYRING`].
pub fn keyring_id(key: KeySerial) -> Result<KeySerial> {
    // SAFETY: integer arguments only.
    let ret = unsafe { libc::syscall(libc::SYS_keyctl, KEYCTL_GET_KEYRING_ID, key, 0) };
    check(ret).map(|v| v as KeySerial)
}

/// `KEYCTL_DESCRIBE`: `type;uid;gid;perm;description`, with `perm` in hex.
pub fn describe(key: KeySerial) -> Result<String> {
    let mut buf = vec![0u8; 512];
    // SAFETY: the kernel writes at most `buf.len()` bytes into `buf`, which
    // is valid and exclusively borrowed for the call.
    let ret = unsafe { libc::syscall(libc::SYS_keyctl, KEYCTL_DESCRIBE, key, buf.as_mut_ptr(), buf.len()) };
    let n = check(ret)? as usize;
    // The return value is the full length including the NUL, even if it
    // didn't fit (then we'd see a truncated description, fine for our use).
    buf.truncate(n.min(buf.len()).saturating_sub(1));
    String::from_utf8(buf).map_err(|_| Errno::EINVAL)
}

/// `KEYCTL_SETPERM`.
pub fn set_perm(key: KeySerial, perm: u32) -> Result<()> {
    // SAFETY: integer-only keyctl operation.
    let ret = unsafe { libc::syscall(libc::SYS_keyctl, KEYCTL_SETPERM, key, perm) };
    check(ret).map(drop)
}

/// The permission mask of `key`, parsed from [`describe`].
pub fn perm(key: KeySerial) -> Result<u32> {
    let d = describe(key)?;
    let hex = d.split(';').nth(3).ok_or(Errno::EINVAL)?;
    u32::from_str_radix(hex, 16).map_err(|_| Errno::EINVAL)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_describe_and_set_perm() {
        // Joining changes the session keyring of the calling *thread* only
        // (credentials are per thread), so this doesn't leak into other
        // tests; the keyring goes away with the test process.
        let name = format!("rustlet-test-{}", std::process::id());
        let key = join_session_keyring(&name).unwrap();
        let d = describe(key).unwrap();
        assert!(d.starts_with("keyring;"), "{d}");
        assert!(d.ends_with(&format!(";{name}")), "{d}");
        let p = perm(key).unwrap();
        set_perm(key, p | KEY_USR_SEARCH).unwrap();
        assert_eq!(perm(key).unwrap(), p | KEY_USR_SEARCH);
    }
}

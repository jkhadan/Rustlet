//! Running from a sealed copy of ourselves (CVE-2019-5736).
//!
//! ## The attack
//!
//! Whatever `rustlet-runc` runs inside a container starts life as a copy of
//! `rustlet-runc` (container init, `exec`'s child), and for that process
//! `/proc/self/exe` is the runtime binary **on the host**. In 2019, a
//! malicious image exploited exactly that against runc: it replaced a binary
//! in the container with `#!/proc/self/exe`, so that `runc exec` ended up
//! executing *runc itself* inside the container. A process in the container
//! then opened `/proc/<that pid>/exe` (the host's runc) and, once runc had
//! exited, reopened it for writing and overwrote it. The next `runc` anyone
//! ran on the host was the attacker's program, as root.
//!
//! ## The fix
//!
//! Before doing anything that puts a process into a container, copy the
//! binary into a **memfd** (an anonymous in-memory file), **seal** it
//! against every kind of change (`F_SEAL_WRITE | F_SEAL_GROW |
//! F_SEAL_SHRINK`, and `F_SEAL_SEAL` so the seals can't be removed), and
//! re-execute from that copy with `fexecve`. From then on `/proc/self/exe`
//! is the sealed memfd: nothing can write to it, and it isn't the host file.
//! (`PR_SET_DUMPABLE=0` alone was runc's first attempt, and wasn't enough:
//! once the program in the container runs, it is dumpable again.)
//!
//! The cost is a copy of the binary in memory for as long as a process runs
//! from it: `rustlet-runc run` in the foreground, and container init until
//! it `execve`s. That's why a release build (a few MB) is the one to deploy;
//! the debug build is about 70 MB.
//!
//! Detecting "already sealed" asks the kernel (`F_GET_SEALS` on
//! `/proc/self/exe`), not an environment variable: a variable could be set
//! by whoever runs us, to skip the protection.

use std::ffi::CString;
use std::os::fd::AsFd;
use std::os::unix::ffi::OsStringExt;

use rustlet_sys::Errno;
use rustlet_sys::fs::{self, Seals};

use crate::error::{Context, Error, Result};

/// The seals that make the copy immutable.
const SEALS: Seals = Seals::SEAL.union(Seals::SHRINK).union(Seals::GROW).union(Seals::WRITE);

/// Returns if we already run from a sealed memfd; otherwise copies
/// `/proc/self/exe` into one and re-executes it with the same arguments and
/// environment (and so never returns, unless that fails).
///
/// Call it first thing, before creating threads or opening anything that
/// shouldn't be inherited: non-close-on-exec fds survive the re-exec (which
/// is what `--preserve-fds` relies on).
pub fn ensure_sealed_binary() -> Result<()> {
    if is_sealed()? {
        return Ok(());
    }
    let mut exe = std::fs::File::open("/proc/self/exe").context("open /proc/self/exe")?;
    let memfd = fs::memfd_create_exec("rustlet-runc").context("memfd_create")?;
    let mut copy = std::fs::File::from(memfd);
    // std uses copy_file_range here: an in-kernel copy, no userspace buffer.
    std::io::copy(&mut exe, &mut copy).context("copy the runtime binary into a memfd")?;
    fs::add_seals(copy.as_fd(), SEALS).context("seal the memfd")?;

    let args: Vec<CString> = std::env::args_os().map(to_cstring).collect::<Result<_>>()?;
    let env: Vec<CString> = std::env::vars_os()
        .map(|(k, v)| {
            let mut kv = k.into_vec();
            kv.push(b'=');
            kv.extend(v.into_vec());
            CString::new(kv).map_err(|_| Error::invalid("environment variable with a NUL byte"))
        })
        .collect::<Result<_>>()?;
    let errno = rustlet_sys::process::fexecve(copy.as_fd(), &args, &env);
    Err(Error::Sys { context: "re-execute from the sealed memfd".into(), errno })
}

/// Is `/proc/self/exe` a memfd carrying all of [`SEALS`]?
fn is_sealed() -> Result<bool> {
    let exe = std::fs::File::open("/proc/self/exe").context("open /proc/self/exe")?;
    match fs::get_seals(exe.as_fd()) {
        Ok(s) => Ok(s.contains(SEALS)),
        // Not a memfd (a regular file on disk): not sealed.
        Err(Errno::EINVAL) => Ok(false),
        Err(e) => Err(e).context("F_GET_SEALS /proc/self/exe"),
    }
}

fn to_cstring(s: std::ffi::OsString) -> Result<CString> {
    CString::new(s.into_vec()).map_err(|_| Error::invalid("argument with a NUL byte"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_test_binary_is_not_sealed() {
        assert!(!is_sealed().unwrap());
    }
}

//! Network namespaces the daemon pins, and running code inside one.
//!
//! A network namespace lives as long as something refers to it: a process
//! in it, an open fd of its `ns/net` file, or a **bind mount** of that file.
//! The daemon creates each container's namespace before the container
//! exists, so nothing would hold it; it pins it at `<run>/netns/<id>` the
//! way `ip netns add` does, and the runtime joins it by path (the OCI spec
//! says `{"type": "network", "path": …}`). Unmounting the pin lets the
//! namespace go once the container's processes have exited.
//!
//! **Threads.** A network namespace is an attribute of a *thread*:
//! `unshare(CLONE_NEWNET)` and `setns` change only the caller's. Work in a
//! namespace therefore happens on a thread of its own, made for it and
//! ended after it ([`create`], [`run_in`]); a pooled thread (tokio's, or
//! `spawn_blocking`'s) left in a container's namespace would carry the next
//! task there. What such a thread creates belongs to that namespace for
//! good: a netlink socket configures it, a listening socket listens there,
//! a child process (`nft`) starts there, wherever they are used afterwards.

use std::fs::File;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use rustlet_sys::Errno;
use rustlet_sys::mount::{MntFlags, MsFlags, mount};
use rustlet_sys::process::{CloneFlags, open_ns, setns, unshare};

use crate::error::{Context, Result};

/// Creates a network namespace, runs `setup` in it (bring `lo` up, write
/// its sysctls), then pins it at `pin`, which must not exist. If `setup`
/// fails, the namespace is simply dropped: nothing is left behind.
pub fn create(pin: &Path, setup: impl FnOnce() -> Result<()> + Send) -> Result<()> {
    on_own_thread(|| {
        unshare(CloneFlags::NEWNET).context("unshare a network namespace")?;
        setup()?;
        File::options()
            .write(true)
            .create_new(true)
            .mode(0o444)
            .open(pin)
            .with_context(|| format!("create {}", pin.display()))?;
        let pinned = mount(Some("/proc/thread-self/ns/net"), pin, None::<&str>, MsFlags::MS_BIND, None::<&str>)
            .with_context(|| format!("pin the network namespace at {}", pin.display()));
        if pinned.is_err() {
            let _ = std::fs::remove_file(pin);
        }
        pinned
    })
}

/// Unpins: unmounts `pin` and deletes it. Fine if it is gone already, or
/// was never mounted.
pub fn remove(pin: &Path) -> Result<()> {
    match nix::mount::umount2(pin, MntFlags::MNT_DETACH) {
        Ok(()) | Err(Errno::EINVAL | Errno::ENOENT) => {}
        Err(e) => return Err(e).with_context(|| format!("unmount {}", pin.display())),
    }
    match std::fs::remove_file(pin) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            Err(e).with_context(|| format!("remove {}", pin.display()))
        }
        _ => Ok(()),
    }
}

/// Opens a network namespace by its pin (or any `/proc/…/ns/net`).
pub fn open(path: &Path) -> Result<OwnedFd> {
    open_ns(path).with_context(|| format!("open the network namespace {}", path.display()))
}

/// Runs `f` on a new thread that has joined the network namespace `ns`.
pub fn run_in<T: Send>(ns: BorrowedFd<'_>, f: impl FnOnce() -> Result<T> + Send) -> Result<T> {
    on_own_thread(|| {
        setns(ns, CloneFlags::NEWNET).context("join the network namespace")?;
        f()
    })
}

/// [`run_in`] the namespace pinned at `pin`.
pub fn run_in_pinned<T: Send>(pin: &Path, f: impl FnOnce() -> Result<T> + Send) -> Result<T> {
    let ns = open(pin)?;
    run_in(ns.as_fd(), f)
}

/// Makes `dir` (created if missing) the place for pins, as `ip netns` does
/// for `/run/netns`: a mount point with shared propagation. Another mount
/// namespace that copied the host's (a service with `PrivateTmp=`, say)
/// then holds its copies of the pins as slaves of these, and unpinning
/// here unmounts them there too, instead of keeping the namespaces alive
/// in a copy nobody will ever unmount.
pub fn prepare_dir(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    let shared = || mount(None::<&str>, dir, None::<&str>, MsFlags::MS_SHARED | MsFlags::MS_REC, None::<&str>);
    match shared() {
        Ok(()) => Ok(()),
        // Not a mount point yet: make it one, a bind mount of itself.
        Err(Errno::EINVAL) => {
            mount(Some(dir), dir, None::<&str>, MsFlags::MS_BIND | MsFlags::MS_REC, None::<&str>)
                .with_context(|| format!("bind {} onto itself", dir.display()))?;
            shared().with_context(|| format!("make {} shared", dir.display()))
        }
        Err(e) => Err(e).with_context(|| format!("make {} shared", dir.display())),
    }
}

/// The inode of a network namespace file: two namespaces are the same one
/// if their inodes (on nsfs) are.
pub fn inode(path: &Path) -> Result<u64> {
    use std::os::unix::fs::MetadataExt;
    Ok(std::fs::metadata(path).with_context(|| format!("stat {}", path.display()))?.ino())
}

/// Runs `f` on a thread of its own and waits for it; a panic there goes on
/// in the caller.
fn on_own_thread<T: Send>(f: impl FnOnce() -> Result<T> + Send) -> Result<T> {
    std::thread::scope(|s| match s.spawn(f).join() {
        Ok(r) => r,
        Err(panic) => std::panic::resume_unwind(panic),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn threads_leave_the_callers_namespace_alone() {
        let before = inode(Path::new("/proc/thread-self/ns/net")).unwrap();
        // Joining even our own namespace takes CAP_SYS_ADMIN, which an
        // ordinary user lacks; either way the caller's thread is untouched.
        let own = open(Path::new("/proc/self/ns/net")).unwrap();
        let r = run_in(own.as_fd(), || inode(Path::new("/proc/thread-self/ns/net")));
        if let Ok(inside) = r {
            assert_eq!(inside, before);
        }
        assert_eq!(inode(Path::new("/proc/thread-self/ns/net")).unwrap(), before);
    }

    #[test]
    fn panics_come_back_to_the_caller() {
        let r = std::panic::catch_unwind(|| on_own_thread::<()>(|| panic!("inside")));
        assert!(r.is_err());
    }
}

//! `linux.maskedPaths` and `linux.readonlyPaths`.
//!
//! The container's `/proc` and `/sys` are real kernel interfaces, and not all
//! of them are namespaced. Some would leak host information (`/proc/kcore`
//! is the kernel's memory, `/proc/keys` the host's keyrings,
//! `/proc/timer_list` what every CPU is doing), others would let root in the
//! container reconfigure the host (`/proc/sys/kernel/*`,
//! `/proc/sysrq-trigger`, `/proc/irq/*/smp_affinity`). Two tools, both mounts
//! stacked on top:
//!
//! * **read-only paths** get a read-only bind of themselves: still readable
//!   (programs read `/proc/sys/kernel/ostype`), no longer writable, even for
//!   root, because a read-only *mount* refuses writes before the file is
//!   asked;
//! * **masked paths** disappear behind something empty: a directory behind a
//!   read-only, empty tmpfs; a file behind `/dev/null` (reads give nothing,
//!   and the program sees a file where it expects one).
//!
//! Both run in container init after `pivot_root`, so `/` is the container's
//! root. As everywhere else, targets are resolved once, with `openat2`
//! (confined to the root, no magic links), and mounts attach to that fd.
//! A path that doesn't exist on this kernel (`/proc/acpi` without ACPI) is
//! skipped, like runc does; any other failure stops the container.

use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::{Component, Path, PathBuf};

use nix::fcntl::OFlag;
use nix::sys::stat::Mode;
use rustlet_sys::Errno;
use rustlet_sys::fs::{ResolveFlags, fstatx, open_in_root, openat2};
use rustlet_sys::mount::{
    FsContext, MountAttr, OpenTreeFlags, Propagation, SetAttr, mount_setattr, move_mount_fd, open_tree,
};

use crate::error::{Context, Error, Result};

/// Validated path rules, in `config.json` order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PathRules {
    pub masked: Vec<PathBuf>,
    pub readonly: Vec<PathBuf>,
}

/// Parent side, at plan time: every entry must be absolute and clean.
pub fn plan(masked: &[String], readonly: &[String]) -> Result<PathRules> {
    let clean_all = |list: &[String], field: &str| list.iter().map(|p| clean(p, field)).collect::<Result<Vec<_>>>();
    Ok(PathRules { masked: clean_all(masked, "maskedPaths")?, readonly: clean_all(readonly, "readonlyPaths")? })
}

/// `/proc//sys/./` -> `/proc/sys`. Refuses relative paths and `..`: these
/// are paths *inside the container*, and `..` would make it hard to say
/// which one is meant. Refuses `/` too: a mount on top of the root is
/// invisible to a process whose root is the mount underneath (the process
/// keeps referring to the lower one), so it would silently do nothing. For a
/// read-only root there is `root.readonly`.
fn clean(p: &str, field: &str) -> Result<PathBuf> {
    let bad = |why: &str| Error::invalid(format!("linux.{field}: {p:?} {why}"));
    if p.contains('\0') {
        return Err(bad("contains a NUL byte"));
    }
    let path = Path::new(p);
    if !path.is_absolute() {
        return Err(bad("must be an absolute path"));
    }
    let mut out = PathBuf::from("/");
    for c in path.components() {
        match c {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(n) => out.push(n),
            Component::ParentDir => return Err(bad("must not contain `..`")),
            Component::Prefix(_) => unreachable!("no path prefixes on Linux"),
        }
    }
    if out == Path::new("/") {
        return Err(bad("is the container's root (use root.readonly for a read-only root)"));
    }
    Ok(out)
}

/// Container init, after `pivot_root` (and after sysctls were written):
/// read-only paths first, then masked paths.
///
/// The order is runc's: masks last, so each one is the topmost mount at its
/// path. (Default specs list `/proc/asound` in both; it ends up masked.)
pub(crate) fn apply(rules: &PathRules) -> Result<()> {
    let root = nix::fcntl::open("/", OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC, Mode::empty())
        .context("open / for masked and read-only paths")?;
    for p in &rules.readonly {
        make_readonly(root.as_fd(), p)?;
    }
    // Opened (and verified) only when the first masked *file* needs it.
    let mut dev_null = None;
    for p in &rules.masked {
        mask(root.as_fd(), p, &mut dev_null)?;
    }
    Ok(())
}

/// Resolves `path` inside `root` to an `O_PATH` fd; `None` if it doesn't
/// exist. Symlinks are followed but stay inside the root.
fn open_target(root: BorrowedFd<'_>, path: &Path) -> Result<Option<OwnedFd>, Errno> {
    match open_in_root(root, path.strip_prefix("/").unwrap_or(path), OFlag::empty()) {
        Ok(fd) => Ok(Some(fd)),
        Err(Errno::ENOENT) => Ok(None),
        Err(e) => Err(e),
    }
}

/// A read-only bind of `path` onto itself.
///
/// `open_tree(CLONE | RECURSIVE)` copies the mount (and anything mounted
/// below it) as a detached tree, `mount_setattr(RDONLY, recursive)` flips
/// only the read-only bit on every mount of the copy (so `nosuid`, `nodev`
/// and `noexec` stay as they were), and `move_mount` stacks it on the
/// original.
fn make_readonly(root: BorrowedFd<'_>, path: &Path) -> Result<()> {
    let ctx = || format!("make {} read-only", path.display());
    let Some(target) = open_target(root, path).with_context(ctx)? else {
        return Ok(());
    };
    let tree = open_tree(
        Some(target.as_fd()),
        Path::new(""),
        OpenTreeFlags::CLONE | OpenTreeFlags::RECURSIVE | OpenTreeFlags::EMPTY_PATH,
    )
    .with_context(ctx)?;
    // Everything in our mount namespace is private already (rootfs step 1);
    // saying so for the copy costs nothing and means we don't rely on it.
    mount_setattr(
        tree.as_fd(),
        true,
        &SetAttr { set: MountAttr::RDONLY, propagation: Some(Propagation::Private), ..Default::default() },
    )
    .with_context(ctx)?;
    move_mount_fd(tree.as_fd(), target.as_fd()).with_context(ctx)
}

/// Hides `path`: a read-only empty tmpfs over a directory, `/dev/null` over
/// anything else. `dev_null` caches the verified `/dev/null` fd.
fn mask(root: BorrowedFd<'_>, path: &Path, dev_null: &mut Option<OwnedFd>) -> Result<()> {
    let ctx = || format!("mask {}", path.display());
    let Some(target) = open_target(root, path).with_context(ctx)? else {
        return Ok(());
    };
    let mnt = if fstatx(target.as_fd()).with_context(ctx)?.is_dir() {
        let fs = FsContext::open("tmpfs").with_context(ctx)?;
        fs.mount(MountAttr::RDONLY | MountAttr::NOSUID | MountAttr::NODEV | MountAttr::NOEXEC).with_context(ctx)?
    } else {
        let null = match dev_null {
            Some(fd) => fd,
            None => dev_null.insert(open_dev_null(root)?),
        };
        // A bind of exactly the inode we checked: `open_tree` on the fd,
        // with an empty path, looks nothing up.
        open_tree(Some(null.as_fd()), Path::new(""), OpenTreeFlags::CLONE | OpenTreeFlags::EMPTY_PATH)
            .with_context(ctx)?
    };
    move_mount_fd(mnt.as_fd(), target.as_fd()).with_context(ctx)
}

/// Opens the container's `/dev/null` and proves it is the null device
/// (character device 1:3) before anything is bind-mounted from it.
///
/// This is the fix for **CVE-2025-31133**. runc masked files with
/// `mount("/dev/null", path, MS_BIND)`, trusting whatever the path
/// `/dev/null` resolved to. A container that could replace it (a shared
/// volume on `/dev`, a racing process) made it a symlink to
/// `/proc/sys/kernel/core_pattern`, and runc dutifully bind-mounted *that*,
/// read-write, over `/proc/timer_list`. Writing `|/evil` there set the
/// host's `core_pattern`, and the next crash anywhere ran `/evil` as root on
/// the host.
///
/// Here:
/// * the lookup allows no symlinks at all (`RESOLVE_NO_SYMLINKS`, which also
///   covers `/dev` itself being one), and with `O_PATH | O_NOFOLLOW` a
///   symlink at `/dev/null` is returned *as* a symlink and fails the check
///   below rather than being followed;
/// * `fstatx` on the fd must say "character device 1:3". A regular file, a
///   procfs file, a directory: all refused;
/// * the bind is made from this fd, so what we checked is what gets mounted.
fn open_dev_null(root: BorrowedFd<'_>) -> Result<OwnedFd> {
    let fd = openat2(
        Some(root),
        "dev/null",
        OFlag::O_PATH | OFlag::O_NOFOLLOW,
        Mode::empty(),
        ResolveFlags::IN_ROOT | ResolveFlags::NO_SYMLINKS,
    )
    .context("open /dev/null (for masked paths)")?;
    let st = fstatx(fd.as_fd()).context("statx /dev/null")?;
    if !st.is_char_device() || st.rdev != (1, 3) {
        return Err(Error::Init {
            message: format!(
                "/dev/null is not the null device (file type {:#o}, device {}:{}); refusing to bind it over \
                 masked paths",
                st.file_type(),
                st.rdev.0,
                st.rdev.1
            ),
            errno: None,
        });
    }
    Ok(fd)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn plan_cleans_and_keeps_order() {
        let r =
            plan(&strings(&["/proc/kcore", "/sys//firmware/", "/proc/./keys"]), &strings(&["/proc/sys", "/proc/bus"]))
                .unwrap();
        assert_eq!(r.masked, [Path::new("/proc/kcore"), Path::new("/sys/firmware"), Path::new("/proc/keys")]);
        assert_eq!(r.readonly, [Path::new("/proc/sys"), Path::new("/proc/bus")]);
    }

    #[test]
    fn plan_accepts_the_oci_defaults() {
        use oci_spec::runtime::{get_default_maskedpaths, get_default_readonly_paths};
        let r = plan(&get_default_maskedpaths(), &get_default_readonly_paths()).unwrap();
        assert_eq!(r.masked.len(), get_default_maskedpaths().len());
    }

    #[test]
    fn plan_rejects_unclean_paths() {
        for bad in ["proc/kcore", "", "/proc/../etc/shadow", "/", "//.", "/proc/k\0core"] {
            let e = plan(&strings(&[bad]), &[]).unwrap_err().to_string();
            assert!(e.contains("maskedPaths"), "{bad:?}: {e}");
            let e = plan(&[], &strings(&[bad])).unwrap_err().to_string();
            assert!(e.contains("readonlyPaths"), "{bad:?}: {e}");
        }
    }

    #[test]
    fn missing_targets_are_skipped_and_symlinks_stay_inside() {
        let dir = tempfile::tempdir().unwrap();
        let root = nix::fcntl::open(dir.path(), OFlag::O_PATH | OFlag::O_DIRECTORY, Mode::empty()).unwrap();
        assert!(open_target(root.as_fd(), Path::new("/proc/acpi")).unwrap().is_none());
        // An absolute symlink resolves inside the root, not on the host.
        std::fs::write(dir.path().join("inside"), "").unwrap();
        std::os::unix::fs::symlink("/inside", dir.path().join("link")).unwrap();
        let fd = open_target(root.as_fd(), Path::new("/link")).unwrap().unwrap();
        let want = std::fs::metadata(dir.path().join("inside")).unwrap();
        let got = fstatx(fd.as_fd()).unwrap();
        assert_eq!(got.ino, std::os::unix::fs::MetadataExt::ino(&want));
    }

    #[test]
    fn dev_null_must_be_the_null_device() {
        let dir = tempfile::tempdir().unwrap();
        let root = nix::fcntl::open(dir.path(), OFlag::O_PATH | OFlag::O_DIRECTORY, Mode::empty()).unwrap();
        std::fs::create_dir(dir.path().join("dev")).unwrap();
        // CVE-2025-31133: a symlink to a procfs file where /dev/null should be.
        std::os::unix::fs::symlink("/proc/sys/kernel/core_pattern", dir.path().join("dev/null")).unwrap();
        let e = open_dev_null(root.as_fd()).unwrap_err().to_string();
        assert!(e.contains("not the null device"), "{e}");
        // A regular file is refused as well.
        std::fs::remove_file(dir.path().join("dev/null")).unwrap();
        std::fs::write(dir.path().join("dev/null"), "").unwrap();
        assert!(open_dev_null(root.as_fd()).unwrap_err().to_string().contains("not the null device"));
        // So is a symlinked /dev (the lookup refuses any symlink: ELOOP).
        std::fs::remove_dir_all(dir.path().join("dev")).unwrap();
        std::os::unix::fs::symlink("/", dir.path().join("dev")).unwrap();
        assert_eq!(open_dev_null(root.as_fd()).unwrap_err().errno(), Some(Errno::ELOOP));
    }

    #[test]
    fn the_real_dev_null_passes() {
        // The host's /dev is a devtmpfs with a real null device; no privilege needed.
        let root = nix::fcntl::open("/", OFlag::O_PATH | OFlag::O_DIRECTORY, Mode::empty()).unwrap();
        open_dev_null(root.as_fd()).unwrap();
    }
}

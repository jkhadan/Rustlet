//! Building the container's filesystem view and switching into it.
//!
//! Runs inside container init, in its brand-new mount namespace, which
//! starts as a *copy* of the host's mount table. The steps, in order:
//!
//! 1. **Cut propagation** ([`make_private`]). The copied mounts keep their
//!    propagation type, and on a systemd host `/` is `shared`: a mount
//!    (or unmount!) under a shared mount is replayed in every peer, including
//!    the host's namespace. `mount("/", MS_REC|MS_PRIVATE)` turns every mount
//!    into a private one, and we re-read mountinfo to *prove* no shared mount
//!    is left before going further.
//! 2. **Bind the rootfs onto itself** ([`bind_rootfs`]). `pivot_root`
//!    requires the new root to be a mount point; a plain directory isn't
//!    one. `open_tree(OPEN_TREE_CLONE)` + `move_mount` makes it one, and the
//!    fd we keep refers to the root of that new mount.
//! 3. **Mount everything in `config.json`** ([`mount_entry`]), fd-based:
//!    build the mount detached (`fsopen`/`fsmount` or `open_tree`), resolve
//!    the target with `openat2(RESOLVE_IN_ROOT)`, attach with `move_mount`
//!    onto that fd. See `inroot` for why.
//! 4. **Populate `/dev`** ([`populate_dev`]): device nodes and the standard
//!    symlinks, only ever inside a tmpfs.
//! 5. **Switch root** ([`pivot`]): `pivot_root(".", ".")`, then detach the
//!    old root, which is now stacked on top of the new one.
//! 6. **Read-only root** ([`make_root_readonly`]), if asked for.

use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::Path;

use nix::fcntl::OFlag;
use nix::sys::stat::{Mode, SFlag};
use rustlet_sys::fs::{fs_magic, fstatx, magic};
use rustlet_sys::mount::{
    self, FsContext, MntFlags, MountAttr, MsFlags, OpenTreeFlags, Propagation, SetAttr, mount_setattr, move_mount_fd,
    open_tree,
};
use rustlet_sys::{Errno, mountinfo};

use crate::error::{Context, Error, Result};
use crate::inroot;
use crate::mounts::{self, FsOption, MountEntry, MountKind};
use crate::plan::Plan;

/// Steps 1–5 (and 6 if requested), in order. On return the process's root
/// and working directory are the container's `/`.
pub fn setup(plan: &Plan) -> Result<()> {
    make_private()?;
    let root = bind_rootfs(&plan.root)?;
    for m in &plan.mounts {
        mount_entry(root.as_fd(), m)?;
    }
    populate_dev(root.as_fd())?;
    // The working directory is created (if missing) while we still hold the
    // rootfs fd; `process` chdir()s into it after the identity switch.
    inroot::mkdir_all(root.as_fd(), &plan.process.cwd, Mode::from_bits_truncate(0o755))
        .with_context(|| format!("create cwd {}", plan.process.cwd.display()))?;
    pivot(root)?;
    if plan.root_readonly {
        make_root_readonly()?;
    }
    Ok(())
}

/// Step 1: `mount("/", MS_REC|MS_PRIVATE)`, then verify via mountinfo.
pub fn make_private() -> Result<()> {
    mount::mount(None::<&str>, "/", None::<&str>, MsFlags::MS_REC | MsFlags::MS_PRIVATE, None::<&str>)
        .context("make / rprivate")?;
    let mounts = mountinfo::read_self().context("read /proc/self/mountinfo")?;
    // `shared:N` = we would send events to peer group N; `master:N` = we
    // would receive them. After MS_PRIVATE there must be neither.
    let leaky: Vec<_> = mounts
        .iter()
        .filter(|m| m.optional.iter().any(|o| o.starts_with("shared:") || o.starts_with("master:")))
        .map(|m| m.mount_point.display().to_string())
        .collect();
    if !leaky.is_empty() {
        return Err(Error::Init {
            message: format!("mounts still propagate to/from the host after MS_PRIVATE: {leaky:?}"),
            errno: None,
        });
    }
    Ok(())
}

/// Step 2: turns `root` into a mount point by bind-mounting it onto itself,
/// recursively (a rootfs may contain mounts of its own), with `nodev`: device
/// nodes that come with an image never work. Returns an `O_PATH` fd for the
/// root of the new mount.
pub fn bind_rootfs(root: &Path) -> Result<OwnedFd> {
    let ctx = || format!("bind rootfs {}", root.display());
    let tree = open_tree(None, root, OpenTreeFlags::CLONE | OpenTreeFlags::RECURSIVE).with_context(ctx)?;
    mount_setattr(
        tree.as_fd(),
        true,
        &SetAttr { set: MountAttr::NODEV, propagation: Some(Propagation::Private), ..Default::default() },
    )
    .with_context(ctx)?;
    let target = nix::fcntl::open(
        root,
        OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .with_context(ctx)?;
    move_mount_fd(tree.as_fd(), target.as_fd()).with_context(ctx)?;
    // After move_mount, `tree` refers to the root of the attached mount;
    // `target` still refers to the directory *underneath* it.
    Ok(tree)
}

/// Step 3: creates one mount detached, then attaches it at its destination.
pub fn mount_entry(root: BorrowedFd<'_>, m: &MountEntry) -> Result<()> {
    let ctx = || format!("mount {}", m.describe());
    let (mnt, is_dir) = match &m.kind {
        MountKind::Fs { fstype, source, options } => {
            let fs = FsContext::open(fstype).with_context(ctx)?;
            if let Some(src) = source {
                fs.set_string("source", src).with_context(ctx)?;
            }
            for o in options {
                match o {
                    FsOption::Flag(k) => fs.set_flag(k),
                    FsOption::Value(k, v) => fs.set_string(k, v),
                }
                .with_context(|| format!("{}: option {o:?}", ctx()))?;
            }
            // For a new filesystem the attributes are simply part of fsmount.
            (fs.mount(m.set).with_context(ctx)?, true)
        }
        MountKind::Bind { source, recursive } => {
            let is_dir = std::fs::metadata(source).with_context(ctx)?.is_dir();
            let mut flags = OpenTreeFlags::CLONE;
            if *recursive {
                flags |= OpenTreeFlags::RECURSIVE;
            }
            let tree = open_tree(None, source, flags).with_context(ctx)?;
            // The clone inherits the source mount's attributes; `set`/`clear`
            // adjust them. Like mount(8), `ro` on an rbind applies to the top
            // mount only; submounts keep their own flags.
            mount_setattr(
                tree.as_fd(),
                false,
                &SetAttr { set: m.set, clear: m.clear, propagation: Some(Propagation::Private), userns: None },
            )
            .with_context(ctx)?;
            (tree, is_dir)
        }
    };
    if let MountKind::Fs { fstype, .. } = &m.kind
        && matches!(fstype.as_str(), "proc" | "sysfs")
    {
        refuse_symlinked_destination(root, m, fstype)?;
    }
    if !m.rec_set.is_empty() || !m.rec_clear.is_empty() {
        mount_setattr(
            mnt.as_fd(),
            true,
            &SetAttr { set: m.rec_set, clear: m.rec_clear, propagation: None, userns: None },
        )
        .with_context(|| format!("{}: recursive mount options", ctx()))?;
    }
    let target =
        inroot::ensure_mount_target(root, &m.destination, is_dir).with_context(|| format!("{}: mount point", ctx()))?;
    check_resolved_target(m, target.as_fd())?;
    move_mount_fd(mnt.as_fd(), target.as_fd()).with_context(ctx)
}

/// procfs and sysfs go exactly where the spec says, onto a real directory:
/// if the image made `/proc` a symlink (to `/tmp/p`, say), following it
/// would put the kernel's files somewhere else and leave the image's own
/// `proc/` in place, and every later check on "/proc/…" would be looking at
/// the wrong thing. runc refuses this too, with the same words.
fn refuse_symlinked_destination(root: BorrowedFd<'_>, m: &MountEntry, fstype: &str) -> Result<()> {
    let rel = m.destination.strip_prefix("/").unwrap_or(&m.destination);
    match rustlet_sys::fs::open_in_root(root, rel, OFlag::O_NOFOLLOW) {
        Ok(fd) if fstatx(fd.as_fd()).with_context(|| format!("mount {}", m.describe()))?.is_symlink() => {
            Err(Error::invalid(format!(
                "{fstype} must be mounted on ordinary directory: {} is a symlink in the rootfs",
                m.destination.display()
            )))
        }
        // Missing is fine: the mount point is created.
        Ok(_) | Err(Errno::ENOENT) => Ok(()),
        Err(e) => Err(e).with_context(|| format!("mount {}: look up the mount point", m.describe())),
    }
}

/// The plan checked each destination *as written*. But the rootfs belongs to
/// the image, and a symlink in it can send a harmless-looking destination
/// into `/proc` (Alpine ships `/etc/mtab -> ../proc/mounts`: a volume on
/// `/etc/mtab` would cover `/proc/1/mounts`). What counts is where the path
/// *resolved*: unless the plan vetted the destination as one on the
/// kernel's filesystems, the target must not be on procfs, sysfs or
/// cgroupfs. (runc's `checkProcMount` runs on the resolved path for the same
/// reason; CVE-2019-19921 was a symlink race into `/proc`.)
fn check_resolved_target(m: &MountEntry, target: BorrowedFd<'_>) -> Result<()> {
    if mounts::vetted_kernel_fs_destination(&m.destination) {
        return Ok(());
    }
    let f_type = fs_magic(target).with_context(|| format!("mount {}: fstatfs the mount point", m.describe()))?;
    let fs = match f_type {
        magic::PROC_SUPER_MAGIC => "procfs",
        magic::SYSFS_MAGIC => "sysfs",
        magic::CGROUP2_SUPER_MAGIC => "cgroupfs",
        _ => return Ok(()),
    };
    Err(Error::invalid(format!(
        "mount {}: the destination resolves (through a symlink in the rootfs) to a file on {fs}; \
         mounts may not cover the kernel's files",
        m.describe()
    )))
}

/// The device nodes every container gets (OCI "default devices").
/// `(name, major, minor)`; all are world read/write character devices.
const DEFAULT_DEVICES: [(&str, u64, u64); 6] =
    [("null", 1, 3), ("zero", 1, 5), ("full", 1, 7), ("random", 1, 8), ("urandom", 1, 9), ("tty", 5, 0)];

/// `/dev` symlinks: `(name, target)`. runc also adds `core -> /proc/kcore`;
/// we don't: kcore is kernel memory, and the default `maskedPaths` hide it anyway.
const DEV_SYMLINKS: [(&str, &str); 5] = [
    // The devpts instance mounted at /dev/pts has its own ptmx; programs
    // open /dev/ptmx, so point it there instead of at the host's.
    ("ptmx", "pts/ptmx"),
    ("fd", "/proc/self/fd"),
    ("stdin", "/proc/self/fd/0"),
    ("stdout", "/proc/self/fd/1"),
    ("stderr", "/proc/self/fd/2"),
];

/// Step 4: device nodes and symlinks in the container's `/dev`.
///
/// Refuses unless `/dev` is a tmpfs: the nodes must never be written into
/// the image's own `dev/` directory (which is shared and, being on a `nodev`
/// mount, couldn't use them anyway).
pub fn populate_dev(root: BorrowedFd<'_>) -> Result<()> {
    let dev = inroot::open_dir(root, Path::new("/dev")).context("open /dev in rootfs")?;
    if fs_magic(dev.as_fd()).context("fstatfs /dev")? != magic::TMPFS_MAGIC {
        return Err(Error::invalid(
            "the spec must mount a tmpfs on /dev (device nodes are never created in the image)",
        ));
    }
    for (name, major, minor) in DEFAULT_DEVICES {
        // umask is 0 during init, so 0o666 is exactly what gets created.
        match nix::sys::stat::mknodat(
            &dev,
            name,
            SFlag::S_IFCHR,
            Mode::from_bits_truncate(0o666),
            nix::sys::stat::makedev(major, minor),
        ) {
            Ok(()) => {}
            // Already there (e.g. the spec bind-mounted one): keep it.
            Err(Errno::EEXIST) => {}
            Err(e) => return Err(e).with_context(|| format!("mknod /dev/{name}")),
        }
    }
    for (name, target) in DEV_SYMLINKS {
        match nix::unistd::symlinkat(target, &dev, name) {
            Ok(()) | Err(Errno::EEXIST) => {}
            Err(e) => return Err(e).with_context(|| format!("symlink /dev/{name}")),
        }
    }
    Ok(())
}

/// Step 5: makes `root` the process's `/` and throws the host's view away.
///
/// `pivot_root(new_root, put_old)` moves the current root mount to `put_old`
/// and makes `new_root` the root. The classic recipe needs a `put_old`
/// directory inside the rootfs. The trick from `pivot_root(2)` avoids that:
/// with the new root as working directory, `pivot_root(".", ".")` stacks the
/// old root *on top of* the new one, at the same place, and
/// `umount2(".", MNT_DETACH)` peels it off again. Detaching the old root is
/// only safe because step 1 made every mount private: on a shared mount the
/// unmount would propagate to the host.
pub fn pivot(root: OwnedFd) -> Result<()> {
    let want = fstatx(root.as_fd()).context("statx rootfs")?;
    mount::fchdir(root.as_fd()).context("fchdir rootfs")?;
    mount::pivot_root(Path::new("."), Path::new(".")).context("pivot_root")?;
    mount::umount2(Path::new("."), MntFlags::MNT_DETACH).context("detach old root")?;
    nix::unistd::chdir("/").context("chdir /")?;
    drop(root);
    // Sanity check: `/` is now exactly the mount we built.
    let now = rustlet_sys::fs::statx(None, "/", 0).context("statx /")?;
    if (now.dev, now.ino, now.mnt_id) != (want.dev, want.ino, want.mnt_id) {
        return Err(Error::Init { message: "after pivot_root, / is not the container rootfs".into(), errno: None });
    }
    Ok(())
}

/// Step 6: `root.readonly`. Only the root mount itself becomes read-only;
/// `/proc`, `/dev`, `/dev/shm`, … keep their own flags.
pub fn make_root_readonly() -> Result<()> {
    let root = nix::fcntl::open("/", OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC, Mode::empty())
        .context("open /")?;
    mount_setattr(root.as_fd(), false, &SetAttr { set: MountAttr::RDONLY, ..Default::default() })
        .context("make rootfs read-only")
}

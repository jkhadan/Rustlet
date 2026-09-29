//! Building the container's filesystem view and switching into it.
//!
//! Runs inside container init, in its brand-new mount namespace, which
//! starts as a *copy* of the host's mount table. Before that, still in
//! `rustlet-runc`, the host-side trees are opened ([`HostTrees`]). The steps,
//! in order:
//!
//! 0. **Open the host's trees** (parent, before `clone3`): the rootfs and
//!    every bind-mount source, as detached copies (`open_tree(CLONE)`), see
//!    [`HostTrees`] for why the parent does this.
//! 1. **Cut propagation** ([`make_private`]). The copied mounts keep their
//!    propagation type, and on a systemd host `/` is `shared`: a mount
//!    (or unmount!) under a shared mount is replayed in every peer, including
//!    the host's namespace. `mount("/", MS_REC|MS_PRIVATE)` turns every mount
//!    into a private one, and we re-read mountinfo to *prove* no shared mount
//!    is left before going further.
//! 2. **Attach the rootfs on top of `/`** ([`attach_rootfs`]). `pivot_root`
//!    needs the new root to be a mount point, and this makes it one without
//!    ever looking up the rootfs's path in here. It doesn't change what init
//!    sees as `/` yet: a process's root is a (mount, directory) pair that
//!    stays the *lower* mount, so host paths such as `/dev/null` still
//!    resolve on the host until step 5.
//! 3. **Mount everything in `config.json`** ([`mount_entry`]), fd-based:
//!    build the mount detached (`fsopen`/`fsmount`, or the parent's tree),
//!    resolve the target with `openat2(RESOLVE_IN_ROOT)`, attach with
//!    `move_mount` onto that fd. See `inroot` for why.
//! 4. **Populate `/dev`** ([`populate_dev`]): device nodes (or, in a user
//!    namespace, bind mounts of the host's) and the standard symlinks, only
//!    ever inside a tmpfs.
//! 5. **Switch root** ([`pivot`]): `pivot_root(".", ".")`, then detach the
//!    old root, which is now stacked on top of the new one.
//! 6. **Read-only root** ([`make_root_readonly`]), if asked for.

use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::Path;

use nix::fcntl::OFlag;
use nix::sys::stat::{Mode, SFlag};
use rustlet_sys::fs::{fs_magic, fstatx, magic};
use rustlet_sys::mount::{
    self, FsContext, MntFlags, MountAttr, MoveMountFlags, MsFlags, OpenTreeFlags, Propagation, SetAttr, mount_setattr,
    move_mount_fd, open_tree,
};
use rustlet_sys::{Errno, mountinfo};

use crate::error::{Context, Error, Result};
use crate::inroot;
use crate::mounts::{self, FsOption, MountEntry, MountKind};
use crate::plan::Plan;

/// The host side of a container's mounts, opened by `rustlet-runc` itself
/// before `clone3`: the rootfs and the source of every bind mount.
///
/// Why the parent, and not init:
///
/// * **Init may not be able to reach them.** With a user namespace, init is
///   host uid 1000000, and a bundle in a `0750` home directory is out of its
///   reach (every path lookup checks search permission on each directory).
///   The parent is host root.
/// * **Idmapped mounts need it.** Only a mount that isn't attached anywhere
///   yet may be idmapped, and only by someone privileged over the
///   filesystem's own user namespace (the host's): the parent does it while
///   init waits ([`HostTrees::idmap`]).
/// * **Each host path is resolved exactly once**, by the privileged side,
///   before any process of the container exists to race with it.
///
/// Every tree is a *detached* copy (`open_tree(OPEN_TREE_CLONE)`): a mount
/// that is attached nowhere, so nothing can be mounted onto or below it and
/// the fd is the only way to it. Init inherits the fds through `clone3` and
/// attaches them; they are close-on-exec, so none reaches the container's
/// program.
pub(crate) struct HostTrees {
    rootfs: OwnedFd,
    /// One per `plan.mounts` entry: `Some` for bind mounts.
    binds: Vec<Option<OwnedFd>>,
}

impl HostTrees {
    /// Parent side, before `clone3`.
    pub(crate) fn open(plan: &Plan) -> Result<HostTrees> {
        let rootfs = open_rootfs(&plan.root)?;
        let binds = plan
            .mounts
            .iter()
            .map(|m| match &m.kind {
                MountKind::Bind { source, recursive } => open_bind(m, source, *recursive).map(Some),
                MountKind::Fs { .. } | MountKind::HostSysfs => Ok(None),
            })
            .collect::<Result<_>>()?;
        Ok(HostTrees { rootfs, binds })
    }

    /// Parent side, once the user namespace's maps are written: idmaps the
    /// bind mounts that asked for it (`idmap`, `ridmap`) with `userns`, an fd
    /// for init's user namespace. File owners on those mounts are then
    /// translated through the container's maps: a file of host root's
    /// belongs to container root, and what container root creates is stored
    /// as host root's.
    pub(crate) fn idmap(&self, plan: &Plan, userns: BorrowedFd<'_>) -> Result<()> {
        for (m, tree) in plan.mounts.iter().zip(&self.binds) {
            let (Some(idmap), Some(tree)) = (&m.idmap, tree) else { continue };
            mount_setattr(
                tree.as_fd(),
                idmap.recursive,
                &SetAttr { set: MountAttr::IDMAP, userns: Some(userns), ..Default::default() },
            )
            .with_context(|| format!("mount {}: idmap it with the container's user namespace", m.describe()))?;
        }
        Ok(())
    }
}

/// Steps 1–5 (and 6 if requested), in order, with the trees the parent
/// opened. On return the process's root and working directory are the
/// container's `/`.
pub(crate) fn setup(plan: &Plan, trees: HostTrees) -> Result<()> {
    make_private()?;
    let root = attach_rootfs(trees.rootfs)?;
    for (m, tree) in plan.mounts.iter().zip(trees.binds) {
        mount_entry(root.as_fd(), m, tree)?;
    }
    populate_dev(root.as_fd(), plan.namespaces.new_user())?;
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

/// Step 0 (parent): a detached, recursive copy of the rootfs (it may contain
/// mounts of its own), with `nodev` on every mount of it: device nodes that
/// come with an image never work.
fn open_rootfs(root: &Path) -> Result<OwnedFd> {
    let ctx = || format!("open rootfs {}", root.display());
    let tree = open_tree(None, root, OpenTreeFlags::CLONE | OpenTreeFlags::RECURSIVE).with_context(ctx)?;
    mount_setattr(
        tree.as_fd(),
        true,
        &SetAttr { set: MountAttr::NODEV, propagation: Some(Propagation::Private), ..Default::default() },
    )
    .with_context(ctx)?;
    Ok(tree)
}

/// Step 0 (parent): a detached copy of a bind mount's source, `rbind`
/// copying the mounts below it too. The clone inherits the source mount's
/// attributes; `set`/`clear` adjust them. Like mount(8), `ro` on an rbind
/// applies to the top mount only; submounts keep their own flags (the
/// recursive `rro` & co. are applied in [`mount_entry`]).
fn open_bind(m: &MountEntry, source: &Path, recursive: bool) -> Result<OwnedFd> {
    let ctx = || format!("mount {}", m.describe());
    let mut flags = OpenTreeFlags::CLONE;
    if recursive {
        flags |= OpenTreeFlags::RECURSIVE;
    }
    let tree = open_tree(None, source, flags).with_context(ctx)?;
    mount_setattr(
        tree.as_fd(),
        false,
        &SetAttr { set: m.set, clear: m.clear, propagation: Some(Propagation::Private), userns: None },
    )
    .with_context(ctx)?;
    Ok(tree)
}

/// Step 2: mounts the rootfs tree (from [`HostTrees`]) on top of `/`, and
/// returns the tree's fd, which now refers to the root of the attached
/// mount.
///
/// `/` because it is the one place init can always name: it never has to
/// look up the rootfs's host path, which (see [`HostTrees`]) it might not be
/// allowed to. Being mounted *on* `/`, the tree is a child of the old root,
/// exactly what `pivot_root` needs (step 5). Until then, init's root stays
/// the old root underneath (a process's root doesn't move when something is
/// mounted over it), so its absolute paths still lead to the host's files.
pub fn attach_rootfs(tree: OwnedFd) -> Result<OwnedFd> {
    mount::move_mount(Some(tree.as_fd()), Path::new(""), None, Path::new("/"), MoveMountFlags::F_EMPTY_PATH)
        .context("attach the rootfs on top of /")?;
    Ok(tree)
}

/// Step 3: attaches one mount at its destination: a new filesystem, the
/// parent's tree for a bind mount (`tree`), or init's copy of the host's
/// `/sys`.
pub(crate) fn mount_entry(root: BorrowedFd<'_>, m: &MountEntry, tree: Option<OwnedFd>) -> Result<()> {
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
        MountKind::Bind { .. } => {
            let tree = tree.ok_or_else(|| Error::Init {
                message: format!("{}: rustlet-runc didn't open the source", ctx()),
                errno: None,
            })?;
            let is_dir = fstatx(tree.as_fd()).with_context(ctx)?.is_dir();
            (tree, is_dir)
        }
        MountKind::HostSysfs => (host_sysfs(m).with_context(ctx)?, true),
    };
    match &m.kind {
        MountKind::Fs { fstype, .. } if matches!(fstype.as_str(), "proc" | "sysfs") => {
            refuse_symlinked_destination(root, m, fstype)?;
        }
        MountKind::HostSysfs => refuse_symlinked_destination(root, m, "sysfs")?,
        _ => {}
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

/// [`MountKind::HostSysfs`]: a recursive copy of `/sys` from init's copy of
/// the host's mount table (before `pivot_root`, `/sys` is still the
/// host's), with the entry's attributes on every mount of the copy, so that
/// `ro` also covers what is mounted below `/sys`. Made here rather than by the
/// parent because the kernel keeps what it copies into a less privileged
/// mount namespace *locked*: those submounts can't be taken off to look
/// underneath, or have their flags cleared.
fn host_sysfs(m: &MountEntry) -> rustlet_sys::Result<OwnedFd> {
    let tree = open_tree(None, Path::new("/sys"), OpenTreeFlags::CLONE | OpenTreeFlags::RECURSIVE)?;
    if fs_magic(tree.as_fd())? != magic::SYSFS_MAGIC {
        return Err(Errno::EXDEV);
    }
    mount_setattr(
        tree.as_fd(),
        true,
        &SetAttr { set: m.set, clear: m.clear, propagation: Some(Propagation::Private), userns: None },
    )?;
    Ok(tree)
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
///
/// In a user namespace (`userns`), `mknod` of a device is always `EPERM`
/// (it needs `CAP_MKNOD` in the initial user namespace), and a node on a
/// filesystem mounted from inside one could never be opened anyway (the
/// kernel marks such superblocks "no devices"). So each node is a bind mount
/// of the host's own instead ([`bind_host_device`]).
pub fn populate_dev(root: BorrowedFd<'_>, userns: bool) -> Result<()> {
    let dev = inroot::open_dir(root, Path::new("/dev")).context("open /dev in rootfs")?;
    if fs_magic(dev.as_fd()).context("fstatfs /dev")? != magic::TMPFS_MAGIC {
        return Err(Error::invalid(
            "the spec must mount a tmpfs on /dev (device nodes are never created in the image)",
        ));
    }
    for (name, major, minor) in DEFAULT_DEVICES {
        if userns {
            bind_host_device(dev.as_fd(), name, (major, minor))?;
            continue;
        }
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

/// A bind of the host's `/dev/<name>` onto a new, empty file in the
/// container's `/dev`.
///
/// The host's node comes from init's copy of the host's mount table (step 4
/// runs before `pivot_root`, so `/dev` is still the host's devtmpfs, which
/// belongs to the initial user namespace: its nodes can be opened). The copy
/// is checked to be the character device it should be before it is attached,
/// and it inherits the host mount's `nosuid`/`noexec`, locked.
fn bind_host_device(dev: BorrowedFd<'_>, name: &str, (major, minor): (u64, u64)) -> Result<()> {
    let ctx = || format!("bind the host's /dev/{name}");
    let host = Path::new("/dev").join(name);
    let tree = open_tree(None, &host, OpenTreeFlags::CLONE | OpenTreeFlags::SYMLINK_NOFOLLOW).with_context(ctx)?;
    let st = fstatx(tree.as_fd()).with_context(ctx)?;
    if !st.is_char_device() || (u64::from(st.rdev.0), u64::from(st.rdev.1)) != (major, minor) {
        return Err(Error::Init {
            message: format!(
                "the host's /dev/{name} is not character device {major}:{minor} (file type {:#o}, device {}:{})",
                st.file_type(),
                st.rdev.0,
                st.rdev.1
            ),
            errno: None,
        });
    }
    let create = OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
    let target = match nix::fcntl::openat(dev, name, create, Mode::from_bits_truncate(0o666)) {
        Ok(fd) => fd,
        // Already there (e.g. the spec bind-mounted one): keep it.
        Err(Errno::EEXIST) => return Ok(()),
        Err(e) => return Err(e).with_context(|| format!("create /dev/{name}")),
    };
    move_mount_fd(tree.as_fd(), target.as_fd()).with_context(ctx)
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

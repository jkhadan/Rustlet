//! The container's /dev: defaults, validated OCI nodes, and host binds in
//! user namespaces. Device access is controlled separately by the cgroup
//! filter; a node alone never grants read or write access.

use std::os::fd::{AsFd, BorrowedFd};
use std::path::{Path, PathBuf};

use nix::fcntl::{AtFlags, OFlag};
use nix::sys::stat::{FchmodatFlags, Mode, SFlag, fchmodat, makedev, mknodat};
use nix::unistd::{Gid, Uid, fchownat};
use oci_spec::runtime::{Linux, LinuxDeviceType};
use rustlet_sys::Errno;
use rustlet_sys::fs::{fs_magic, fstatx, magic};
use rustlet_sys::mount::{OpenTreeFlags, move_mount_fd, open_tree};

use crate::cgroups::devices::{DevType, MAX_MAJOR, MAX_MINOR};
use crate::error::{Context, Error, Result};
use crate::inroot;
use crate::mounts::{MountEntry, MountKind};
use crate::namespaces::NamespacePlan;

/// `(name, major, minor)`; all default nodes are character devices.
pub const DEFAULT_DEVICES: [(&str, u32, u32); 6] =
    [("null", 1, 3), ("zero", 1, 5), ("full", 1, 7), ("random", 1, 8), ("urandom", 1, 9), ("tty", 5, 0)];

/// Standard symlinks; deliberately no `core -> /proc/kcore`.
pub const DEV_SYMLINKS: [(&str, &str); 5] = [
    ("ptmx", "pts/ptmx"),
    ("fd", "/proc/self/fd"),
    ("stdin", "/proc/self/fd/0"),
    ("stdout", "/proc/self/fd/1"),
    ("stderr", "/proc/self/fd/2"),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeType {
    Char,
    Block,
    Fifo,
}

impl NodeType {
    fn flag(self) -> SFlag {
        match self {
            Self::Char => SFlag::S_IFCHR,
            Self::Block => SFlag::S_IFBLK,
            Self::Fifo => SFlag::S_IFIFO,
        }
    }
    pub fn device_type(self) -> Option<DevType> {
        match self {
            Self::Char => Some(DevType::Char),
            Self::Block => Some(DevType::Block),
            Self::Fifo => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceNode {
    pub index: usize,
    pub path: PathBuf,
    pub typ: NodeType,
    pub major: u32,
    pub minor: u32,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DevPlan {
    pub nodes: Vec<DeviceNode>,
    pub userns: bool,
}

impl DevPlan {
    /// Init mknods rootful char/block nodes inside the already-filtered
    /// cgroup. FIFOs and host binds need no device mknod rule.
    pub fn mknod_rules(&self) -> Vec<(usize, DevType, u32, u32)> {
        if self.userns {
            return Vec::new();
        }
        self.nodes.iter().filter_map(|n| Some((n.index, n.typ.device_type()?, n.major, n.minor))).collect()
    }
}

/// Check the node paths against the mount plan before touching the cgroup.
pub fn plan(linux: &Linux, ns: &NamespacePlan, mounts: &[MountEntry]) -> Result<DevPlan> {
    let entries = linux.devices().as_deref().unwrap_or_default();
    if !entries.is_empty() && linux.cgroups_path().is_none() {
        return Err(Error::invalid("linux.devices needs a device filter: set linux.cgroupsPath"));
    }
    let dev_mount = mounts.iter().rev().find(|m| m.destination == Path::new("/dev"));
    if !matches!(dev_mount.map(|m| &m.kind), Some(MountKind::Fs { fstype, .. }) if fstype == "tmpfs") {
        return Err(Error::invalid(
            "the spec must mount a tmpfs on /dev (device nodes are never created in the image)",
        ));
    }
    let mut nodes: Vec<DeviceNode> = Vec::new();
    for (index, d) in entries.iter().enumerate() {
        let bad = |why: &str| Error::invalid(format!("linux.devices[{index}] ({}): {why}", d.path().display()));
        let path = d.path();
        let text = path.to_str().ok_or_else(|| bad("path must be UTF-8"))?;
        if !text.starts_with("/dev/") || text[1..].split('/').any(|p| matches!(p, "" | "." | "..")) {
            return Err(bad("path must be absolute and clean, strictly under /dev"));
        }
        let first = text[5..].split('/').next().unwrap();
        if first == "console" || DEV_SYMLINKS.iter().any(|(name, _)| *name == first) {
            return Err(bad("path conflicts with /dev/console or a standard /dev symlink"));
        }
        if text[5..].contains('/') && DEFAULT_DEVICES.iter().any(|(name, _, _)| *name == first) {
            return Err(bad("path is below a default device node"));
        }
        if nodes.iter().any(|n| n.path == *path) {
            return Err(bad("duplicate device path"));
        }
        if nodes.iter().any(|n| n.path.starts_with(path) || path.starts_with(&n.path)) {
            return Err(bad("a device path cannot be a parent of another device"));
        }
        if mounts.iter().any(|m| {
            m.destination != Path::new("/dev") && (m.destination.starts_with(path) || path.starts_with(&m.destination))
        }) {
            return Err(bad("path conflicts with a mount at, above or below the device"));
        }
        let typ = match d.typ() {
            LinuxDeviceType::C | LinuxDeviceType::U => NodeType::Char,
            LinuxDeviceType::B => NodeType::Block,
            LinuxDeviceType::P => NodeType::Fifo,
            _ => return Err(bad("type must be b, c, u (char), or p (FIFO)")),
        };
        let number = |n: i64, max: u32| {
            u32::try_from(n).ok().filter(|n| *n <= max).ok_or_else(|| bad("major/minor is out of range"))
        };
        let major = number(d.major(), MAX_MAJOR)?;
        let minor = number(d.minor(), MAX_MINOR)?;
        if let Some((_, maj, min)) = DEFAULT_DEVICES.iter().find(|(name, _, _)| text == format!("/dev/{name}"))
            && (typ != NodeType::Char || (major, minor) != (*maj, *min))
        {
            return Err(bad("a default device path must keep its character type and device numbers"));
        }
        if d.uid() == Some(u32::MAX) || d.gid() == Some(u32::MAX) {
            return Err(bad("uid/gid cannot be the kernel's -1 (unchanged) sentinel"));
        }
        nodes.push(DeviceNode {
            index,
            path: path.clone(),
            typ,
            major,
            minor,
            mode: d.file_mode().unwrap_or(0o666) & 0o7777,
            uid: d.uid().unwrap_or(0),
            gid: d.gid().unwrap_or(0),
        });
    }
    Ok(DevPlan { nodes, userns: ns.new_user() })
}

/// Populate only the freshly mounted /dev tmpfs, through `dev`, the fd of
/// that very mount, once every mount of the spec is in place. No container
/// process can run yet, and conflicting mounts were refused at plan time.
///
/// The filesystem type of whatever `/dev` resolves to proves nothing: a
/// symlink in the image (`/mnt -> /dev`) can send a later bind mount on top
/// of the fresh tmpfs, and a host directory on tmpfs passes a type check.
/// So `/dev` in the rootfs must still lead to the root of this mount, or
/// `create` fails before anything is written.
pub fn populate(root: BorrowedFd<'_>, dev: BorrowedFd<'_>, plan: &DevPlan) -> Result<()> {
    if fs_magic(dev).context("fstatfs /dev")? != magic::TMPFS_MAGIC {
        return Err(Error::invalid("the spec must mount a tmpfs on /dev"));
    }
    let made = fstatx(dev).context("statx /dev")?;
    let seen = inroot::open_dir(root, Path::new("/dev")).context("open /dev in rootfs")?;
    let seen = fstatx(seen.as_fd()).context("statx /dev")?;
    if (seen.mnt_id, seen.dev, seen.ino) != (made.mnt_id, made.dev, made.ino) {
        return Err(Error::invalid(
            "/dev is no longer the tmpfs mounted there: a later mount covers it \
             (through a symlink to /dev in the rootfs?)",
        ));
    }
    for (index, (name, major, minor)) in DEFAULT_DEVICES.into_iter().enumerate() {
        let path = PathBuf::from(format!("/dev/{name}"));
        if plan.nodes.iter().any(|n| n.path == path) {
            continue;
        }
        let n = DeviceNode { index, path, typ: NodeType::Char, major, minor, mode: 0o666, uid: 0, gid: 0 };
        populate_node(dev, &n, plan.userns, true)?;
    }
    for n in &plan.nodes {
        populate_node(dev, n, plan.userns, false)?;
    }
    for (name, target) in DEV_SYMLINKS {
        match nix::unistd::symlinkat(target, dev, name) {
            Ok(()) | Err(Errno::EEXIST) => {}
            Err(e) => return Err(e).with_context(|| format!("symlink /dev/{name}")),
        }
    }
    Ok(())
}

fn populate_node(dev: BorrowedFd<'_>, n: &DeviceNode, userns: bool, default: bool) -> Result<()> {
    let relative = n.path.strip_prefix("/dev").expect("validated /dev path");
    let parent = inroot::mkdir_all(dev, relative.parent().unwrap(), Mode::from_bits_truncate(0o755))
        .with_context(|| format!("create parent of {}", n.path.display()))?;
    let name = relative.file_name().unwrap();
    if userns && n.typ != NodeType::Fifo {
        return bind_host_device(parent.as_fd(), name, n, default);
    }
    let ctx = || format!("create device {}", n.path.display());
    match mknodat(
        &parent,
        name,
        n.typ.flag(),
        Mode::from_bits_truncate(n.mode),
        makedev(n.major.into(), n.minor.into()),
    ) {
        Ok(()) => {}
        Err(Errno::EEXIST) if default => return Ok(()),
        Err(e) => return Err(e).with_context(ctx),
    }
    fchownat(&parent, name, Some(Uid::from_raw(n.uid)), Some(Gid::from_raw(n.gid)), AtFlags::AT_SYMLINK_NOFOLLOW)
        .with_context(|| format!("chown {}", n.path.display()))?;
    // chown clears set-id bits, so chmod comes last.
    fchmodat(&parent, name, Mode::from_bits_truncate(n.mode), FchmodatFlags::NoFollowSymlink)
        .with_context(|| format!("chmod {}", n.path.display()))
}

fn bind_host_device(parent: BorrowedFd<'_>, name: &std::ffi::OsStr, n: &DeviceNode, default: bool) -> Result<()> {
    let ctx = || format!("bind the host's {}", n.path.display());
    let tree = open_tree(None, &n.path, OpenTreeFlags::CLONE | OpenTreeFlags::SYMLINK_NOFOLLOW).with_context(ctx)?;
    let st = fstatx(tree.as_fd()).with_context(ctx)?;
    let right_type = match n.typ {
        NodeType::Char => st.is_char_device(),
        NodeType::Block => st.is_block_device(),
        NodeType::Fifo => false,
    };
    if !right_type || st.rdev != (n.major, n.minor) {
        return Err(Error::invalid(format!(
            "the host's {} is not {:?} device {}:{} (file type {:#o}, device {}:{})",
            n.path.display(),
            n.typ,
            n.major,
            n.minor,
            st.file_type(),
            st.rdev.0,
            st.rdev.1
        )));
    }
    let flags = OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
    let target = match nix::fcntl::openat(parent, name, flags, Mode::from_bits_truncate(0o666)) {
        Ok(fd) => fd,
        Err(Errno::EEXIST) if default => return Ok(()),
        Err(e) => return Err(e).with_context(ctx),
    };
    // The host's mode/owner are preserved, including in a user namespace.
    move_mount_fd(tree.as_fd(), target.as_fd()).with_context(ctx)
}

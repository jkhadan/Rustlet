//! A container's root filesystem: an overlay of an image's snapshots plus a
//! writable layer of its own.
//!
//! ```text
//! containers/<id>/
//! ├─ upper/    the container's own changes (overlay's upperdir)
//! ├─ work/     overlay's scratch space (must be on upper's filesystem)
//! └─ rootfs/   the mount point: the merged view, what root.path names
//!
//!            rootfs/  =  upper/  over  layer N  over … over  layer 0
//! ```
//!
//! **Lookups go top-down**: the first layer that has a name wins, so an
//! upper layer's file hides a lower one's. A **whiteout** (a 0:0 character
//! device) in a layer hides the name below it; an **opaque** directory
//! (`trusted.overlay.opaque=y`) hides the lower layers' contents of that
//! directory. **Writes go to upper only**: modifying a lower file first
//! copies it up; deleting one leaves a whiteout in upper. The snapshots are
//! never written, so every container of an image shares them.
//!
//! The overlay is built with the new mount API. `lowerdir+` (kernel 6.8)
//! adds one lower layer per `fsconfig` call, top layer first. The old
//! `lowerdir=a:b:c` string needed `:` (and, for `mount(2)`, `,`) escaped,
//! and doesn't even fit: `fsconfig` takes string values of at most 255
//! bytes, and three snapshot paths are longer than that. `metacopy` and
//! `index` are set off and `redirect_dir` to `nofollow`, whatever the
//! kernel's defaults: with them, upper could hold references into the lower
//! layers instead of whole entries, and a container's changes would no
//! longer be a self-contained diff (which `commit` and the builder need,
//! Phase 7). `nofollow` rather than `off`: `off` creates no redirects but
//! follows one it finds (with the usual `redirect_always_follow=Y`), and no
//! layer should ever have one; unpacking drops `trusted.overlay.*` from
//! images too. The mount is `nodev`, and its source reads `rustlet` in
//! mountinfo.
//!
//! ## With a user namespace (`--userns=remap`)
//!
//! Layers are unpacked with the image's ids: `/bin/sh` belongs to uid 0. In
//! a remapped container, uid 0 is host uid 1000000, so those files would
//! show up as owned by `nobody`. Instead of a chowned copy of every layer,
//! each layer is used through an **idmapped mount**: `open_tree(CLONE)` of
//! the snapshot, then `mount_setattr(MOUNT_ATTR_IDMAP)` with a user namespace
//! that has the container's mappings, so on-disk uid 0 reads as host uid
//! 1000000 (container root), on-disk 101 as 1000101, and so on. Overlay
//! (5.19+) accepts idmapped lower layers.
//!
//! Two details. The user namespace has to exist before the container does:
//! a parked helper process provides it (`rustlet_sys::process::UsernsHolder`),
//! and its maps are written through the runtime's `IdMapper`. And before
//! kernel 6.15 overlay can only take layers that are *attached* in the
//! mounter's namespace (`clone_private_mount` checks), so the idmapped trees
//! are attached under `lower/` (mode 0700) just long enough to create the
//! overlay, which keeps its own private clones, then detached. Upper is
//! simply owned by the container's root (host uid 1000000): what container
//! root creates there is stored as 1000000, and copy-up keeps the idmapped
//! owner.

use std::os::fd::AsFd;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};

use rustlet_runtime::spec::{REMAP_HOST_ID, REMAP_SIZE};
use rustlet_runtime::userns::{DirectIdMapper, IdMap, IdMapper, UsernsPlan};
use rustlet_sys::Errno;
use rustlet_sys::mount::{
    FsContext, MntFlags, MountAttr, MoveMountFlags, OpenTreeFlags, SetAttr, mount_setattr, move_mount, open_tree,
    umount2,
};
use rustlet_sys::process::UsernsHolder;

use crate::error::{Context, Error, Result};
use crate::snapshot::Snapshot;

/// Overlay's limit on lower layers (`OVL_MAX_STACK`).
pub const MAX_LAYERS: usize = 500;

/// The mappings of `--userns=remap`: container ids `0..65536` are host ids
/// `1000000..` (docs/architecture.md §2.2.1).
pub fn remap() -> UsernsPlan {
    let map = IdMap { container: 0, host: REMAP_HOST_ID, size: REMAP_SIZE };
    UsernsPlan { uids: vec![map], gids: vec![map] }
}

/// A mounted container rootfs in `containers/<id>/`.
#[derive(Debug)]
pub struct ContainerRootfs {
    dir: PathBuf,
    mounted: bool,
}

impl ContainerRootfs {
    /// Creates `dir/{upper,work,rootfs}` and mounts the overlay of `layers`
    /// (bottom first) with `upper` on top at `dir/rootfs`. With `idmap`, the
    /// layers are idmapped with the container's mappings first, so files the
    /// image owns as root appear as the container's root. `dir` must not
    /// exist yet; on failure nothing of it is left.
    pub fn mount(dir: &Path, layers: &[Snapshot], idmap: Option<&UsernsPlan>) -> Result<ContainerRootfs> {
        if layers.is_empty() {
            return Err(Error::invalid("the image has no layers, so no filesystem to run"));
        }
        if layers.len() > MAX_LAYERS {
            return Err(Error::unsupported(format!("{} layers; overlay stacks at most {MAX_LAYERS}", layers.len())));
        }
        let dir = canonical_new(dir)?;
        std::fs::DirBuilder::new().mode(0o700).create(&dir).with_context(|| format!("create {}", dir.display()))?;
        let mut rootfs = ContainerRootfs { dir, mounted: false };
        match rootfs.mount_layers(layers, idmap) {
            Ok(()) => Ok(rootfs),
            Err(e) => {
                if let Err(cleanup) = rootfs.remove_files() {
                    tracing::warn!("cleaning up after a failed rootfs mount: {cleanup}");
                }
                Err(e)
            }
        }
    }

    fn mount_layers(&mut self, layers: &[Snapshot], idmap: Option<&UsernsPlan>) -> Result<()> {
        let upper = self.dir.join("upper");
        let work = self.dir.join("work");
        let target = self.rootfs();
        for (path, mode) in [(&upper, 0o755), (&work, 0o700), (&target, 0o755)] {
            std::fs::DirBuilder::new().mode(mode).create(path).with_context(|| format!("create {}", path.display()))?;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
                .with_context(|| format!("chmod {}", path.display()))?;
        }
        let staged = match idmap {
            None => None,
            Some(maps) => {
                let (uid, gid) = maps
                    .uid_to_host(0)
                    .zip(maps.gid_to_host(0))
                    .ok_or_else(|| Error::invalid("the user namespace must map uid and gid 0"))?;
                // The merged root directory's owner is upper's.
                std::os::unix::fs::chown(&upper, Some(uid), Some(gid))
                    .with_context(|| format!("chown {} to {uid}:{gid}", upper.display()))?;
                Some(self.stage_idmapped(layers, maps)?)
            }
        };
        let lowers: Vec<PathBuf> = match &staged {
            Some(s) => s.paths.clone(),
            None => layers.iter().map(Snapshot::fs).collect(),
        };
        let result = mount_overlay(&lowers, &upper, &work, &target);
        // The overlay holds private clones of its layers: the staged
        // mounts can go either way.
        drop(staged);
        result?;
        self.mounted = true;
        Ok(())
    }

    /// Attaches an idmapped clone of every layer under `lower/<n>`.
    fn stage_idmapped(&self, layers: &[Snapshot], maps: &UsernsPlan) -> Result<Staged> {
        let holder = UsernsHolder::spawn().context("create a user namespace for the idmapped layers")?;
        DirectIdMapper.write(holder.pid(), maps)?;
        let ns = holder.open_ns().context("open the idmap's user namespace")?;
        drop(holder);
        let dir = self.dir.join("lower");
        std::fs::DirBuilder::new().mode(0o700).create(&dir).with_context(|| format!("create {}", dir.display()))?;
        let mut staged = Staged { dir, paths: Vec::new() };
        for (i, layer) in layers.iter().enumerate() {
            let fs = layer.fs();
            let ctx = || format!("idmap layer {}", layer.info.chain_id.short());
            let tree = open_tree(None, &fs, OpenTreeFlags::CLONE).with_context(ctx)?;
            mount_setattr(
                tree.as_fd(),
                false,
                &SetAttr { set: MountAttr::IDMAP, userns: Some(ns.as_fd()), ..Default::default() },
            )
            .with_context(ctx)?;
            let at = staged.dir.join(i.to_string());
            std::fs::DirBuilder::new().mode(0o700).create(&at).with_context(|| format!("create {}", at.display()))?;
            move_mount(Some(tree.as_fd()), Path::new(""), None, &at, MoveMountFlags::F_EMPTY_PATH).with_context(ctx)?;
            staged.paths.push(at);
        }
        Ok(staged)
    }

    /// The container directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The mount point: what goes into `config.json` as `root.path`.
    pub fn rootfs(&self) -> PathBuf {
        self.dir.join("rootfs")
    }

    /// The container's writable layer.
    pub fn upper(&self) -> PathBuf {
        self.dir.join("upper")
    }

    /// Unmounts the overlay (idempotent). A plain unmount first; if something
    /// still uses it, a lazy one, so it goes once that something does.
    pub fn unmount(&mut self) -> Result<()> {
        if self.mounted {
            let target = self.rootfs();
            match umount2(&target, MntFlags::empty()) {
                Ok(()) | Err(Errno::EINVAL | Errno::ENOENT) => {}
                Err(Errno::EBUSY) => {
                    umount2(&target, MntFlags::MNT_DETACH).with_context(|| format!("unmount {}", target.display()))?
                }
                Err(e) => return Err(e).with_context(|| format!("unmount {}", target.display())),
            }
            self.mounted = false;
        }
        Ok(())
    }

    /// Unmounts and deletes the container directory, writable layer included.
    pub fn remove(mut self) -> Result<()> {
        self.unmount()?;
        self.remove_files()
    }

    fn remove_files(&mut self) -> Result<()> {
        // Whatever is still mounted below (staged layers after a crash, the
        // overlay itself) goes first: safe_remove_tree refuses otherwise.
        rustlet_sys::tree::unmount_under(&self.dir).with_context(|| format!("unmount under {}", self.dir.display()))?;
        self.mounted = false;
        rustlet_sys::tree::safe_remove_tree(&self.dir).with_context(|| format!("remove {}", self.dir.display()))
    }
}

/// The idmapped layers, attached under `lower/`; detached and removed on drop.
struct Staged {
    dir: PathBuf,
    paths: Vec<PathBuf>,
}

impl Drop for Staged {
    fn drop(&mut self) {
        for p in &self.paths {
            if let Err(e) = umount2(p, MntFlags::MNT_DETACH) {
                tracing::warn!("detach staged layer {}: {e}", p.display());
            }
            let _ = std::fs::remove_dir(p);
        }
        let _ = std::fs::remove_dir(&self.dir);
    }
}

/// `fsopen("overlay")`, one `lowerdir+` per layer (top first), upper, work,
/// the fixed options and a source name, `fsmount(nodev)`, attached at
/// `target`.
fn mount_overlay(lowers: &[PathBuf], upper: &Path, work: &Path, target: &Path) -> Result<()> {
    let utf8 =
        |p: &Path| p.to_str().map(str::to_owned).ok_or_else(|| Error::invalid(format!("{} is not UTF-8", p.display())));
    let ctx = FsContext::open("overlay").context("fsopen(\"overlay\")")?;
    let config = |key: &str, value: &str| {
        ctx.set_string(key, value)
            .map_err(|errno| Error::Sys { context: format!("overlay {key}={value}{}", kernel_says(&ctx)), errno })
    };
    // Each `lowerdir+` goes below the ones before it.
    for lower in lowers.iter().rev() {
        config("lowerdir+", &utf8(lower)?)?;
    }
    config("upperdir", &utf8(upper)?)?;
    config("workdir", &utf8(work)?)?;
    for (key, value) in [("redirect_dir", "nofollow"), ("metacopy", "off"), ("index", "off"), ("source", "rustlet")] {
        config(key, value)?;
    }
    let mnt = ctx
        .mount(MountAttr::NODEV)
        .map_err(|errno| Error::Sys { context: format!("create the overlay{}", kernel_says(&ctx)), errno })?;
    move_mount(Some(mnt.as_fd()), Path::new(""), None, target, MoveMountFlags::F_EMPTY_PATH)
        .with_context(|| format!("attach the overlay at {}", target.display()))
}

/// The filesystem context's own explanation, if it left one.
fn kernel_says(ctx: &FsContext) -> String {
    let log = ctx.log();
    if log.is_empty() { String::new() } else { format!(" (kernel: {})", log.join("; ")) }
}

/// `dir` with its parent canonicalized (the removal code insists on paths
/// without symlinks); `dir` itself must not exist.
fn canonical_new(dir: &Path) -> Result<PathBuf> {
    let (Some(parent), Some(name)) = (dir.parent(), dir.file_name()) else {
        return Err(Error::invalid(format!("{} can't be a container directory", dir.display())));
    };
    if !dir.is_absolute() {
        return Err(Error::invalid(format!("container directory {} must be absolute", dir.display())));
    }
    let parent = parent.canonicalize().with_context(|| format!("resolve {}", parent.display()))?;
    let dir = parent.join(name);
    if dir.symlink_metadata().is_ok() {
        return Err(Error::invalid(format!("{} already exists", dir.display())));
    }
    Ok(dir)
}

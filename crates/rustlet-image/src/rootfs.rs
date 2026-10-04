//! A container's root filesystem: an overlay of an image's snapshots plus a
//! writable layer of its own.
//!
//! ```text
//! containers/<id>/
//! ├─ upper/    the container's own changes (overlay's upperdir)
//! ├─ work/     overlay's scratch space (must be on upper's filesystem)
//! ├─ rootfs/   the mount point: the merged view, what root.path names
//! └─ empty/    the one lower layer of an image without layers (made when needed)
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
//! An image may have no layers at all: one built `FROM scratch` with only
//! metadata, or the image a build step's container starts from on
//! `scratch`. Overlay needs at least one lower layer, so such a rootfs gets
//! an empty directory, `empty/` (`0755`), as its only one: the merged root
//! directory takes its owner and mode from upper anyway, and nothing else
//! is below.
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

/// A container's directory, `containers/<id>/`, and the overlay mounted on
/// its `rootfs/` (while it is).
///
/// The directory outlives the mount: the daemon mounts the overlay when the
/// container starts and unmounts it when it stops, and `upper/` (the
/// container's changes) stays until the container is removed.
#[derive(Debug)]
pub struct ContainerRootfs {
    dir: PathBuf,
    mounted: bool,
}

impl ContainerRootfs {
    /// [`create`](Self::create) and [`mount_layers`](Self::mount_layers) in
    /// one: `dir` must not exist yet; on failure nothing of it is left.
    pub fn mount(dir: &Path, layers: &[Snapshot], idmap: Option<&UsernsPlan>) -> Result<ContainerRootfs> {
        check_layers(layers)?;
        let mut rootfs = ContainerRootfs::create(dir)?;
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

    /// Creates `dir` (which must not exist yet) with an empty `upper/`,
    /// `work/` and `rootfs/`. Nothing is mounted.
    pub fn create(dir: &Path) -> Result<ContainerRootfs> {
        let dir = canonical_new(dir)?;
        std::fs::DirBuilder::new().mode(0o700).create(&dir).with_context(|| format!("create {}", dir.display()))?;
        let rootfs = ContainerRootfs { dir, mounted: false };
        for (path, mode) in [(rootfs.upper(), 0o755), (rootfs.dir.join("work"), 0o700), (rootfs.rootfs(), 0o755)] {
            let made = std::fs::DirBuilder::new()
                .mode(mode)
                .create(&path)
                .and_then(|()| std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)));
            if let Err(e) = made {
                let _ = rustlet_sys::tree::safe_remove_tree(&rootfs.dir);
                return Err(e).with_context(|| format!("create {}", path.display()));
            }
        }
        Ok(rootfs)
    }

    /// An existing container directory, made by [`create`](Self::create),
    /// mounted or not (a daemon that restarted finds it either way).
    pub fn open(dir: &Path) -> Result<ContainerRootfs> {
        let dir = dir.canonicalize().with_context(|| format!("open {}", dir.display()))?;
        for sub in ["upper", "work", "rootfs"] {
            let p = dir.join(sub);
            if !std::fs::symlink_metadata(&p).with_context(|| format!("open {}", p.display()))?.is_dir() {
                return Err(Error::invalid(format!("{} is not a directory", p.display())));
            }
        }
        let mut rootfs = ContainerRootfs { dir, mounted: false };
        rootfs.mounted = rootfs.is_mounted()?;
        Ok(rootfs)
    }

    /// Is something mounted on `rootfs/`? (Its mount differs from the
    /// directory's.)
    pub fn is_mounted(&self) -> Result<bool> {
        let id = |p: &Path| {
            rustlet_sys::fs::statx(None, p, libc::AT_SYMLINK_NOFOLLOW)
                .map(|s| s.mnt_id)
                .with_context(|| format!("statx {}", p.display()))
        };
        Ok(id(&self.rootfs())? != id(&self.dir)?)
    }

    /// Mounts the overlay of `layers` (bottom first; none: `empty/`, see
    /// the module docs) with `upper/` on top at `rootfs/`. With `idmap`, the
    /// layers are idmapped with the container's mappings first, so files the
    /// image owns as root appear as the container's root, and `upper/` is
    /// given to the mapped root.
    pub fn mount_layers(&mut self, layers: &[Snapshot], idmap: Option<&UsernsPlan>) -> Result<()> {
        check_layers(layers)?;
        if self.mounted || self.is_mounted()? {
            return Err(Error::invalid(format!("{} is mounted already", self.rootfs().display())));
        }
        let upper = self.upper();
        let work = self.dir.join("work");
        let target = self.rootfs();
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
                // `empty/` has nothing whose owner could show.
                if layers.is_empty() { None } else { Some(self.stage_idmapped(layers, maps)?) }
            }
        };
        let lowers: Vec<PathBuf> = match &staged {
            Some(s) => s.paths.clone(),
            None if layers.is_empty() => vec![self.empty_lower()?],
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

    /// `empty/`, made if it isn't there yet: the lower layer of an image
    /// without layers. (Overlay never writes to a lower layer, so a remount
    /// finds it as empty as it was made.)
    fn empty_lower(&self) -> Result<PathBuf> {
        let dir = self.dir.join("empty");
        match std::fs::DirBuilder::new().mode(0o755).create(&dir) {
            // Explicitly: mkdir's mode is subject to the umask.
            Ok(()) => std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755))
                .with_context(|| format!("chmod {}", dir.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e).with_context(|| format!("create {}", dir.display())),
        }
        if !std::fs::symlink_metadata(&dir).with_context(|| format!("stat {}", dir.display()))?.is_dir() {
            return Err(Error::invalid(format!("{} is not a directory", dir.display())));
        }
        Ok(dir)
    }

    /// Attaches an idmapped clone of every layer under `lower/<n>`.
    fn stage_idmapped(&self, layers: &[Snapshot], maps: &UsernsPlan) -> Result<Staged> {
        let holder = UsernsHolder::spawn().context("create a user namespace for the idmapped layers")?;
        DirectIdMapper.write(holder.pid(), maps)?;
        let ns = holder.open_ns().context("open the idmap's user namespace")?;
        drop(holder);
        let dir = self.dir.join("lower");
        if dir.symlink_metadata().is_ok() {
            // Left by a crash between staging and detaching.
            rustlet_sys::tree::unmount_under(&dir).with_context(|| format!("unmount under {}", dir.display()))?;
            rustlet_sys::tree::safe_remove_tree(&dir).with_context(|| format!("remove {}", dir.display()))?;
        }
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

    /// Deletes a container directory in whatever state it is: a removal
    /// that failed half-way may have left it without `upper/`, `work/` or
    /// `rootfs/`, and [`open`](Self::open) refuses it then. Nothing to
    /// delete is fine.
    pub fn remove_dir(dir: &Path) -> Result<()> {
        if dir.symlink_metadata().is_err() {
            return Ok(());
        }
        match ContainerRootfs::open(dir) {
            Ok(rootfs) => rootfs.remove(),
            Err(_) => {
                let dir = dir.canonicalize().with_context(|| format!("open {}", dir.display()))?;
                ContainerRootfs { dir, mounted: false }.remove_files()
            }
        }
    }

    fn remove_files(&mut self) -> Result<()> {
        // Whatever is still mounted below (staged layers after a crash, the
        // overlay itself) goes first: safe_remove_tree refuses otherwise.
        rustlet_sys::tree::unmount_under(&self.dir).with_context(|| format!("unmount under {}", self.dir.display()))?;
        self.mounted = false;
        rustlet_sys::tree::safe_remove_tree(&self.dir).with_context(|| format!("remove {}", self.dir.display()))
    }
}

/// Overlay's limit; none is fine (`empty/`).
fn check_layers(layers: &[Snapshot]) -> Result<()> {
    if layers.len() > MAX_LAYERS {
        return Err(Error::unsupported(format!("{} layers; overlay stacks at most {MAX_LAYERS}", layers.len())));
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(n: usize) -> Snapshot {
        let digest = crate::Digest::of(n.to_string().as_bytes());
        Snapshot {
            info: crate::snapshot::SnapshotInfo {
                chain_id: digest.clone(),
                diff_id: digest.clone(),
                parent: None,
                blob: digest,
                size: 0,
                entries: 0,
                created: String::new(),
            },
            dir: PathBuf::from(format!("/nonexistent/{n}")),
        }
    }

    #[test]
    fn an_image_may_have_no_layers_but_not_more_than_overlay_stacks() {
        check_layers(&[]).unwrap();
        let layers: Vec<Snapshot> = (0..=MAX_LAYERS).map(snapshot).collect();
        check_layers(&layers[..MAX_LAYERS]).unwrap();
        let err = check_layers(&layers).unwrap_err();
        assert!(matches!(err, Error::Unsupported(_)), "{err}");
    }

    #[test]
    fn the_empty_lower_layer_is_made_once_and_left_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().canonicalize().unwrap().join("c");
        let rootfs = ContainerRootfs::create(&dir).unwrap();
        let empty = rootfs.empty_lower().unwrap();
        assert_eq!(empty, dir.join("empty"));
        let mode = std::fs::metadata(&empty).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o755);
        assert_eq!(rootfs.empty_lower().unwrap(), empty, "a remount finds it");
        assert_eq!(std::fs::read_dir(&empty).unwrap().count(), 0);
        // `open` doesn't need it, and removal takes it along.
        ContainerRootfs::open(&dir).unwrap();
        ContainerRootfs::remove_dir(&dir).unwrap();
        assert!(dir.symlink_metadata().is_err());
    }

    #[test]
    fn a_half_removed_container_directory_can_still_be_removed() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().canonicalize().unwrap().join("c");
        ContainerRootfs::create(&dir).unwrap();
        std::fs::write(dir.join("upper/file"), "x").unwrap();
        // What a removal that failed half-way leaves: `open` refuses it.
        std::fs::remove_dir(dir.join("work")).unwrap();
        assert!(ContainerRootfs::open(&dir).is_err());
        ContainerRootfs::remove_dir(&dir).unwrap();
        assert!(dir.symlink_metadata().is_err());
        // Already gone: nothing to do.
        ContainerRootfs::remove_dir(&dir).unwrap();
    }
}

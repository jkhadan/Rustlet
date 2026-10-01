//! A container's root filesystem: an overlay of an image's snapshots plus a
//! writable layer of its own.

use std::path::{Path, PathBuf};

use rustlet_runtime::userns::UsernsPlan;

use crate::error::Result;
use crate::snapshot::Snapshot;

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
    /// image owns as root appear as the container's root.
    pub fn mount(dir: &Path, layers: &[Snapshot], idmap: Option<&UsernsPlan>) -> Result<ContainerRootfs> {
        let _ = (dir, layers, idmap);
        unimplemented!("rootfs::mount")
    }

    /// The container directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The mount point: what goes into `config.json` as `root.path`.
    pub fn rootfs(&self) -> PathBuf {
        self.dir.join("rootfs")
    }

    /// Unmounts the overlay (idempotent).
    pub fn unmount(&mut self) -> Result<()> {
        let _ = self.mounted;
        unimplemented!("rootfs::unmount")
    }

    /// Unmounts and deletes the container directory, writable layer included.
    pub fn remove(self) -> Result<()> {
        unimplemented!("rootfs::remove")
    }
}

//! Volumes, and the rest of a container's mounts.
//!
//! ```text
//!  <data>/volumes/          0700
//!     <name>/               0700
//!        _data/             the volume: bind-mounted into containers
//! ```
//!
//! **At create** a container's mounts are resolved once and recorded: a
//! `-v /path` (no name) and each `VOLUME` of the image that no mount covers
//! become new *anonymous* volumes (64 hex digits for a name, as Docker's);
//! a named volume that doesn't exist yet is created; a bind mount's host
//! directory is created if `-v` asked for it, and must exist otherwise.
//!
//! **At each start**, an empty volume gets a copy of what the image has at
//! its mount point (`rustlet_image::copyup`), unless the mount says
//! `nocopy`, before the container exists; one copy at a time per volume.
//!
//! **In use** means named in any container's record, running or not, as in
//! Docker: such a volume can't be removed. Anonymous volumes go with their
//! container when it is removed with `--rm` or `rm -v`.
//!
//! **User namespaces.** A container with `--userns=remap` gets its volumes
//! as *idmapped* mounts, so files the volume holds as owned by uid 0 are
//! its root's, and what its root writes lands as uid 0: one volume works
//! the same for remapped containers and others. Host directories (`-v
//! /host:/c`) keep their owners as the host sees them (container root is
//! host uid 1000000 there) unless the mount says `idmap`.

use std::os::fd::AsFd;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use nix::fcntl::OFlag;
use nix::sys::stat::Mode;
use rustlet_spec::container::{ContainerConfig, UsernsMode};
use rustlet_spec::event::EventKind;
use rustlet_spec::network::PruneResponse;
use rustlet_spec::volume::{MountPoint, MountSpec, MountType, TMPFS_FLAGS, Volume, valid_volume_name};

use crate::container::Container;
use crate::daemon::Daemon;
use crate::db::VolumeRecord;
use crate::error::{ApiError, ApiResult};
use crate::lifecycle::blocking;

/// Mount points that are the runtime's own.
const RESERVED_TARGETS: [&str; 6] = ["/proc", "/sys", "/sys/fs/cgroup", "/dev", "/dev/pts", "/dev/mqueue"];

impl Daemon {
    /// `<data>/volumes/<name>/_data`.
    pub fn volume_data(&self, name: &str) -> PathBuf {
        self.paths.volumes.join(name).join("_data")
    }

    pub fn find_volume(&self, name: &str) -> ApiResult<VolumeRecord> {
        self.db.volumes()?.into_iter().find(|v| v.name == name).ok_or_else(|| ApiError::no_such_volume(name))
    }

    /// Creates the volume `name` (a new anonymous one for `None`); an
    /// existing volume of that name is simply returned, as by Docker.
    /// Returns whether it was created.
    pub fn create_volume(
        &self,
        name: Option<String>,
        labels: std::collections::BTreeMap<String, String>,
    ) -> ApiResult<(VolumeRecord, bool)> {
        let anonymous = name.is_none();
        let name = match name {
            Some(n) if !valid_volume_name(&n) => {
                return Err(ApiError::invalid(format!(
                    "invalid volume name {n:?}: use [a-zA-Z0-9][a-zA-Z0-9_.-]+, at most 128 characters"
                )));
            }
            Some(n) => n,
            None => crate::names::new_id(|_| false),
        };
        if let Ok(v) = self.find_volume(&name) {
            return Ok((v, false));
        }
        let record = VolumeRecord { name: name.clone(), created: rustlet_shim::logfile::now(), labels, anonymous };
        let dir = self.paths.volumes.join(&name);
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .map_err(|e| ApiError::internal(format!("create {}: {e}", dir.display())))?;
        let made = std::fs::DirBuilder::new().mode(0o755).create(dir.join("_data"));
        let inserted = made
            .map_err(|e| ApiError::internal(format!("create {}/_data: {e}", dir.display())))
            .and_then(|()| self.db.insert_volume(&record));
        if let Err(e) = inserted {
            let _ = std::fs::remove_dir_all(&dir);
            // Created by someone else meanwhile: theirs it is.
            if let Ok(v) = self.find_volume(&name) {
                return Ok((v, false));
            }
            return Err(e);
        }
        self.events.emit(EventKind::Volume, "create", &name, Default::default());
        Ok((record, true))
    }

    /// Volume name → the names of the containers that have it among their
    /// mounts.
    pub fn volume_users(&self) -> std::collections::BTreeMap<String, Vec<String>> {
        let mut m: std::collections::BTreeMap<String, Vec<String>> = Default::default();
        for c in self.all_containers() {
            for mount in c.record.mounts.iter().filter(|m| m.kind == MountType::Volume) {
                if let Some(name) = &mount.source {
                    m.entry(name.clone()).or_default().push(c.record.name.clone());
                }
            }
        }
        m
    }

    pub fn describe_volume(&self, v: &VolumeRecord, containers: Vec<String>) -> Volume {
        Volume {
            name: v.name.clone(),
            driver: "local".into(),
            mountpoint: self.volume_data(&v.name).display().to_string(),
            created: v.created.clone(),
            labels: v.labels.clone(),
            anonymous: v.anonymous,
            containers,
        }
    }

    /// Removes a volume no container uses. `force`: a missing one is fine.
    pub async fn remove_volume(&self, name: &str, force: bool) -> ApiResult<u64> {
        let v = match self.find_volume(name) {
            Ok(v) => v,
            Err(_) if force => return Ok(0),
            Err(e) => return Err(e),
        };
        if let Some(users) = self.volume_users().get(&v.name) {
            return Err(ApiError::conflict(format!("volume {} is in use by {}", v.name, users.join(", "))));
        }
        let dir = self.paths.volumes.join(&v.name);
        let size = {
            let data = dir.join("_data");
            blocking(move || Ok::<_, ApiError>(tree_size(&data))).await?
        };
        blocking(move || {
            rustlet_sys::tree::safe_remove_tree(&dir)
                .map_err(|e| ApiError::internal(format!("remove {}: {e}", dir.display())))
        })
        .await?;
        self.db.remove_volume(&v.name)?;
        self.events.emit(EventKind::Volume, "destroy", &v.name, Default::default());
        Ok(size)
    }

    /// Removes the volumes no container uses: anonymous ones, or all with
    /// `all`.
    pub async fn prune_volumes(&self, all: bool) -> ApiResult<PruneResponse> {
        let users = self.volume_users();
        let mut r = PruneResponse::default();
        for v in self.db.volumes()? {
            if users.contains_key(&v.name) || !(all || v.anonymous) {
                continue;
            }
            r.space_reclaimed += self.remove_volume(&v.name, true).await?;
            r.deleted.push(v.name);
        }
        Ok(r)
    }

    /// A container's mounts as `create` records them (see the module docs).
    /// On failure, the anonymous volumes made for it are removed again.
    pub async fn resolve_mounts(
        &self,
        config: &ContainerConfig,
        image_volumes: &[String],
    ) -> ApiResult<Vec<MountSpec>> {
        let mut made = Vec::new();
        let result = self.resolve_mounts_into(config, image_volumes, &mut made);
        if result.is_err() {
            for name in made {
                let _ = self.remove_volume(&name, true).await;
            }
        }
        result
    }

    fn resolve_mounts_into(
        &self,
        config: &ContainerConfig,
        image_volumes: &[String],
        made: &mut Vec<String>,
    ) -> ApiResult<Vec<MountSpec>> {
        let remap = config.userns == UsernsMode::Remap;
        let mut out: Vec<MountSpec> = Vec::new();
        for m in &config.mounts {
            // `/data/` and `/data` are the same mount point (as for Docker).
            let mut m = m.clone();
            if let Some(clean) = clean_target(&m.target) {
                m.target = clean;
            }
            check_mount(&m, remap)?;
            if out.iter().any(|o| o.target == m.target) {
                return Err(ApiError::invalid(format!("duplicate mount point: {}", m.target)));
            }
            match m.kind {
                MountType::Volume => {
                    let (v, created) = self.create_volume(m.source.clone(), Default::default())?;
                    if created {
                        made.push(v.name.clone());
                    }
                    m.source = Some(v.name);
                }
                MountType::Bind => {
                    let src = PathBuf::from(m.source.as_deref().unwrap_or_default());
                    match std::fs::symlink_metadata(&src) {
                        Ok(_) => {}
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound && m.create_host_path => {
                            std::fs::DirBuilder::new()
                                .recursive(true)
                                .mode(0o755)
                                .create(&src)
                                .map_err(|e| ApiError::internal(format!("create {}: {e}", src.display())))?;
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                            return Err(ApiError::invalid(format!(
                                "bind source path does not exist: {}",
                                src.display()
                            )));
                        }
                        Err(e) => return Err(ApiError::internal(format!("{}: {e}", src.display()))),
                    }
                }
                MountType::Tmpfs => {}
            }
            out.push(m);
        }
        let mut wanted: Vec<String> = image_volumes
            .iter()
            .filter_map(|v| {
                let target = clean_target(v);
                if target.is_none() {
                    tracing::warn!("the image's VOLUME {v:?} is not an absolute path: left out");
                }
                target
            })
            .collect();
        wanted.sort();
        wanted.dedup();
        for target in wanted {
            if out.iter().any(|o| o.target == target) {
                continue;
            }
            let mut m = MountSpec { kind: MountType::Volume, target, ..MountSpec::default() };
            // The image is untrusted: its VOLUME / or /proc gets the same
            // answer as a -v would, now rather than as a runtime error at
            // every start.
            check_mount(&m, remap).map_err(|e| e.context(format!("the image's VOLUME {}", m.target)))?;
            let (v, _) = self.create_volume(None, Default::default())?;
            made.push(v.name.clone());
            m.source = Some(v.name);
            out.push(m);
        }
        Ok(out)
    }

    /// At a start, with the root filesystem mounted at `rootfs`: each empty
    /// volume (not `nocopy`) gets the image's files at its mount point.
    pub async fn prepare_volumes(&self, c: &Container, rootfs: &Path) -> ApiResult<()> {
        let remap = c.record.config.userns == UsernsMode::Remap;
        for m in c.record.mounts.iter().filter(|m| m.kind == MountType::Volume && !m.no_copy) {
            let Some(name) = m.source.clone() else { continue };
            let lock = self.volume_lock(&name);
            let _turn = lock.lock().await;
            let (data, rootfs, target) = (self.volume_data(&name), rootfs.to_owned(), m.target.clone());
            let copied = blocking(move || {
                let r = copy_into_volume(&rootfs, &target, &data, remap);
                if r.is_err() {
                    // Half a copy would count as content: empty the volume,
                    // so the next start copies again.
                    let _ = empty_dir(&data);
                }
                r
            })
            .await
            .map_err(|e| e.context(format!("copy the image's {} into the volume {name}", m.target)))?;
            if let Some(r) = copied
                && !r.skipped.is_empty()
            {
                tracing::warn!(id = %c.id(), volume = %name, "copy-up left out {} device nodes and sockets", r.skipped.len());
            }
        }
        Ok(())
    }

    fn volume_lock(&self, name: &str) -> Arc<tokio::sync::Mutex<()>> {
        let mut locks = self.volume_locks.lock().unwrap_or_else(|e| e.into_inner());
        locks.entry(name.to_owned()).or_default().clone()
    }

    /// The anonymous volumes of a removed container, removed too (`rm -v`,
    /// `--rm`), unless another container uses them as well.
    pub async fn remove_anonymous_volumes(&self, c: &Container) {
        for m in c.record.mounts.iter().filter(|m| m.kind == MountType::Volume) {
            let Some(name) = &m.source else { continue };
            if self.find_volume(name).is_ok_and(|v| v.anonymous)
                && let Err(e) = self.remove_volume(name, true).await
            {
                tracing::warn!(id = %c.id(), "remove its volume {name}: {e}");
            }
        }
    }

    /// A container's mounts as `inspect` shows them.
    pub fn mount_points(&self, c: &Container) -> Vec<MountPoint> {
        c.record
            .mounts
            .iter()
            .map(|m| MountPoint {
                kind: m.kind,
                name: (m.kind == MountType::Volume).then(|| m.source.clone()).flatten(),
                source: match m.kind {
                    MountType::Volume => {
                        self.volume_data(m.source.as_deref().unwrap_or_default()).display().to_string()
                    }
                    MountType::Bind => m.source.clone().unwrap_or_default(),
                    MountType::Tmpfs => String::new(),
                },
                destination: m.target.clone(),
                read_only: m.read_only
                    || m.tmpfs_options.iter().rev().find(|o| *o == "ro" || *o == "rw").is_some_and(|o| o == "ro"),
            })
            .collect()
    }
}

/// What the daemon checks of a mount, whoever sent it (the CLI's parsers
/// check the same).
fn check_mount(m: &MountSpec, remap: bool) -> ApiResult<()> {
    let bad = |why: String| Err(ApiError::invalid(format!("mount on {:?}: {why}", m.target)));
    if clean_target(&m.target).as_deref() != Some(m.target.as_str()) {
        return bad("the target must be a clean absolute path".into());
    }
    if m.target == "/" || RESERVED_TARGETS.contains(&m.target.as_str()) {
        return bad("that path is the runtime's own".into());
    }
    match m.kind {
        MountType::Volume => {
            if let Some(n) = &m.source
                && !valid_volume_name(n)
            {
                return bad(format!("{n:?} is not a volume name"));
            }
        }
        MountType::Bind => match &m.source {
            Some(s) if s.starts_with('/') => {}
            _ => return bad("a bind mount needs an absolute host path".into()),
        },
        MountType::Tmpfs => {
            if m.source.is_some() {
                return bad("a tmpfs mount has no source".into());
            }
            if let Some(o) = m.tmpfs_options.iter().find(|o| !TMPFS_FLAGS.contains(&o.as_str())) {
                return bad(format!("unsupported tmpfs option {o:?}"));
            }
            if m.tmpfs_mode.is_some_and(|mode| mode > 0o7777) {
                return bad("the tmpfs mode has more than permission bits".into());
            }
        }
    }
    if m.idmap && !remap {
        return bad("idmap needs a user namespace (--userns=remap)".into());
    }
    if m.idmap && m.kind == MountType::Tmpfs {
        return bad("a tmpfs mount can't be idmapped".into());
    }
    Ok(())
}

/// A mount target cleaned lexically (`/data/` is `/data`), if it is an
/// absolute path without `..`.
fn clean_target(t: &str) -> Option<String> {
    if !t.starts_with('/') || t.split('/').any(|c| c == "..") {
        return None;
    }
    let parts: Vec<&str> = t.split('/').filter(|c| !c.is_empty() && *c != ".").collect();
    Some(format!("/{}", parts.join("/")))
}

/// Copy-up into the volume directory `data`, if it is empty. With
/// `--userns=remap` the root filesystem shows the image's owners shifted by
/// [`REMAP_HOST_ID`](rustlet_runtime::spec::REMAP_HOST_ID); the volume gets
/// them unshifted (it is mounted idmapped).
fn copy_into_volume(
    rootfs: &Path,
    target: &str,
    data: &Path,
    remap: bool,
) -> ApiResult<Option<rustlet_image::copyup::CopyUp>> {
    let open = |p: &Path, extra: OFlag| {
        nix::fcntl::open(p, OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | extra, Mode::empty())
            .map_err(|e| ApiError::internal(format!("open {}: {e}", p.display())))
    };
    let dest = open(data, OFlag::O_RDONLY)?;
    if !rustlet_image::copyup::is_empty(dest.as_fd())? {
        return Ok(None);
    }
    let root = open(rootfs, OFlag::O_PATH)?;
    let unshift = |id: u32| {
        let base = rustlet_runtime::spec::REMAP_HOST_ID;
        if remap && (base..base + rustlet_runtime::spec::REMAP_SIZE).contains(&id) { id - base } else { id }
    };
    let map = |uid: u32, gid: u32| (unshift(uid), unshift(gid));
    Ok(Some(rustlet_image::copyup::copy_up(root.as_fd(), Path::new(target), dest.as_fd(), &map)?))
}

/// Removes everything in `dir`, which stays (on its filesystem only, not
/// following symlinks: `rustlet_sys::tree`).
fn empty_dir(dir: &Path) -> ApiResult<()> {
    let fd = nix::fcntl::open(
        dir,
        OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_RDONLY,
        Mode::empty(),
    )
    .map_err(|e| ApiError::internal(format!("open {}: {e}", dir.display())))?;
    for entry in std::fs::read_dir(dir).map_err(|e| ApiError::internal(format!("read {}: {e}", dir.display())))? {
        let entry = entry.map_err(|e| ApiError::internal(e.to_string()))?;
        rustlet_sys::tree::remove_tree_at(fd.as_fd(), &entry.file_name())
            .map_err(|e| ApiError::internal(format!("remove {}: {e}", entry.path().display())))?;
    }
    Ok(())
}

/// The bytes the files below `dir` hold (not following symlinks, staying
/// on its filesystem).
fn tree_size(dir: &Path) -> u64 {
    use std::os::unix::fs::MetadataExt;
    let Ok(top) = std::fs::symlink_metadata(dir) else { return 0 };
    let mut total = 0;
    let mut stack = vec![dir.to_owned()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else { continue };
        for e in entries.flatten() {
            let Ok(m) = e.metadata() else { continue };
            if m.dev() != top.dev() {
                continue;
            }
            if m.is_dir() {
                stack.push(e.path());
            } else if m.is_file() {
                total += m.len();
            }
        }
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets_are_cleaned_and_checked() {
        assert_eq!(clean_target("/data/").as_deref(), Some("/data"));
        assert_eq!(clean_target("/var//lib/./x").as_deref(), Some("/var/lib/x"));
        assert_eq!(clean_target("rel"), None);
        assert_eq!(clean_target("/a/../b"), None);
        let m = |t: &str| MountSpec { kind: MountType::Tmpfs, target: t.into(), ..MountSpec::default() };
        assert!(check_mount(&m("/run"), false).is_ok());
        for bad in ["/", "/proc", "/dev", "/data/", "data"] {
            assert!(check_mount(&m(bad), false).is_err(), "{bad}");
        }
        let odd = MountSpec { tmpfs_options: vec!["uid=0".into()], ..m("/run") };
        assert!(check_mount(&odd, false).is_err());
        let idmapped = MountSpec {
            kind: MountType::Bind,
            source: Some("/srv".into()),
            target: "/srv".into(),
            idmap: true,
            ..MountSpec::default()
        };
        assert!(check_mount(&idmapped, false).is_err(), "idmap without a user namespace");
        assert!(check_mount(&idmapped, true).is_ok());
    }

    #[test]
    fn emptied_directories_stay() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("a/b")).unwrap();
        std::fs::write(dir.path().join("a/b/f"), "x").unwrap();
        std::os::unix::fs::symlink("/etc", dir.path().join("link")).unwrap();
        empty_dir(dir.path()).unwrap();
        assert!(dir.path().is_dir() && std::fs::read_dir(dir.path()).unwrap().next().is_none());
        assert!(Path::new("/etc/passwd").exists(), "a symlink is removed, not followed");
    }

    #[test]
    fn sizes_add_up() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a"), [0u8; 100]).unwrap();
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        std::fs::write(dir.path().join("sub/b"), [0u8; 23]).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", dir.path().join("link")).unwrap();
        assert_eq!(tree_size(dir.path()), 123);
    }
}

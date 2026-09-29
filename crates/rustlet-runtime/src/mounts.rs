//! Turning OCI `mounts` entries into something the new mount API can execute.
//!
//! An OCI mount looks like the arguments of `mount(8)`:
//!
//! ```json
//! { "destination": "/dev", "type": "tmpfs", "source": "tmpfs",
//!   "options": ["nosuid", "strictatime", "mode=755", "size=65536k"] }
//! ```
//!
//! The `options` list mixes three different things, which the classic
//! `mount(2)` also mixes into one call:
//!
//! | kind                  | examples                         | new mount API              |
//! |-----------------------|----------------------------------|----------------------------|
//! | per-mount attributes  | `ro`, `nosuid`, `nodev`, `noexec`, `relatime` | `fsmount(attr)` / `mount_setattr` |
//! | the operation itself  | `bind`, `rbind`                  | `open_tree(OPEN_TREE_CLONE)` |
//! | filesystem options    | `mode=755`, `size=65536k`, `newinstance` | `fsconfig(key, value)` |
//!
//! [`parse`] sorts them apart *before* the container is created, so a typo in
//! `config.json` is reported by `rustlet-runc` itself rather than as an
//! obscure `EINVAL` from deep inside container init.

use std::path::{Component, Path, PathBuf};

use oci_spec::runtime::Mount;
use rustlet_sys::mount::MountAttr;

use crate::bundle::Bundle;
use crate::error::{Context, Error, Result, Unsupported};
use crate::userns::IdMap;

/// A filesystem option passed to `fsconfig`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FsOption {
    /// A bare word, e.g. `newinstance` (`FSCONFIG_SET_FLAG`).
    Flag(String),
    /// `key=value`, e.g. `mode=755` (`FSCONFIG_SET_STRING`).
    Value(String, String),
}

/// How the mount is created.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MountKind {
    /// A new filesystem instance: `fsopen(fstype)`, `fsconfig(...)`, `fsmount`.
    Fs {
        /// Kernel filesystem type, e.g. `proc`, `tmpfs`, `cgroup2`.
        fstype: String,
        /// Shown in the "source" column of mountinfo (`tmpfs`, `shm`, …).
        source: Option<String>,
        options: Vec<FsOption>,
    },
    /// A bind mount of a host path: `open_tree(source, OPEN_TREE_CLONE)`,
    /// plus `AT_RECURSIVE` for `rbind`. `rustlet-runc` opens the source
    /// itself, before the container exists (see `rootfs::HostTrees`).
    Bind { source: PathBuf, recursive: bool },
    /// Instead of sysfs, a recursive bind of the host's `/sys` made by init
    /// itself, from its copy of the host's mount table: what a container with
    /// a user namespace but no network namespace of its own gets, since only
    /// the network namespace's owner may mount sysfs (see `userns`). Made in
    /// init, so the kernel keeps the host's submounts under it locked (they
    /// can't be unmounted to see what's underneath). `set`/`clear` apply to
    /// every mount of the copy.
    HostSysfs,
}

/// One validated mount, in the order `config.json` lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountEntry {
    /// Absolute, lexically clean path inside the container (no `..`).
    pub destination: PathBuf,
    pub kind: MountKind,
    /// Mount attributes to set / clear (`ro` sets RDONLY, `rw` clears it).
    pub set: MountAttr,
    pub clear: MountAttr,
    /// The recursive variants (`rro`, `rnosuid`, …, runc's extension):
    /// applied with `AT_RECURSIVE` to the mount *and every mount below it*,
    /// after `set`/`clear`.
    pub rec_set: MountAttr,
    pub rec_clear: MountAttr,
    /// `idmap`/`ridmap`: an idmapped bind mount (see [`Idmap`]).
    pub idmap: Option<Idmap>,
}

/// An idmapped mount: file owners are translated through the container's
/// user namespace on the way in and out, so files that belong to host root
/// belong to container root, without anything being chowned on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Idmap {
    /// `ridmap`: every mount of an `rbind`, not only the top one.
    pub recursive: bool,
    /// The mount's own `uidMappings`/`gidMappings`, if it has any. Only the
    /// container's own are supported (`userns::check_mounts`); empty means
    /// "the container's".
    pub uids: Vec<IdMap>,
    pub gids: Vec<IdMap>,
}

impl MountEntry {
    /// Filesystem type name for messages.
    pub fn describe(&self) -> String {
        match &self.kind {
            MountKind::Fs { fstype, .. } => format!("{fstype} on {}", self.destination.display()),
            MountKind::Bind { source, recursive } => format!(
                "{} {} on {}",
                if *recursive { "rbind" } else { "bind" },
                source.display(),
                self.destination.display()
            ),
            MountKind::HostSysfs => format!("rbind of the host's /sys on {}", self.destination.display()),
        }
    }
}

/// Filesystem types this runtime knows how to create. `cgroup` is mapped to
/// `cgroup2`: this host (like every modern distro) runs the unified hierarchy
/// only, and runc's default spec still says `cgroup`.
fn kernel_fstype(t: &str) -> Option<&'static str> {
    Some(match t {
        "proc" => "proc",
        "sysfs" => "sysfs",
        "tmpfs" => "tmpfs",
        "devpts" => "devpts",
        "mqueue" => "mqueue",
        "cgroup" | "cgroup2" => "cgroup2",
        _ => return None,
    })
}

/// What one option word means.
enum Opt {
    Set(MountAttr),
    Clear(MountAttr),
    /// One of the atime modes (a 2-bit field, so it replaces the others).
    Atime(MountAttr),
    /// A recursive attribute (`rro`, `rnosuid`, …): `(set, clear)`.
    Rec(MountAttr, MountAttr),
    Bind {
        recursive: bool,
    },
    /// `idmap` / `ridmap`.
    Idmap {
        recursive: bool,
    },
    /// Accepted and implied: propagation is always private here.
    Private,
    Ignore,
    /// Anything else: handed to the filesystem via `fsconfig`.
    Fs(FsOption),
}

/// `MOUNT_ATTR_RELATIME` is 0: "relatime" means "clear the atime field".
const RELATIME: MountAttr = MountAttr::empty();

fn classify(word: &str) -> Result<Opt> {
    use MountAttr as A;
    Ok(match word {
        "ro" => Opt::Set(A::RDONLY),
        "rw" => Opt::Clear(A::RDONLY),
        "nosuid" => Opt::Set(A::NOSUID),
        "suid" => Opt::Clear(A::NOSUID),
        "nodev" => Opt::Set(A::NODEV),
        "dev" => Opt::Clear(A::NODEV),
        "noexec" => Opt::Set(A::NOEXEC),
        "exec" => Opt::Clear(A::NOEXEC),
        "nosymfollow" => Opt::Set(A::NOSYMFOLLOW),
        "symfollow" => Opt::Clear(A::NOSYMFOLLOW),
        "nodiratime" => Opt::Set(A::NODIRATIME),
        "diratime" => Opt::Clear(A::NODIRATIME),
        "relatime" => Opt::Atime(RELATIME),
        "noatime" => Opt::Atime(A::NOATIME),
        "strictatime" => Opt::Atime(A::STRICTATIME),
        // The recursive family. The atime mode is a 2-bit field, and the
        // kernel only lets mount_setattr replace it as a whole (clearing
        // part of it is EINVAL): so `rnoatime` means "clear the field, set
        // NOATIME", and the "not that mode" words (`ratime`, `rnorelatime`,
        // `rnostrictatime`) clear it back to the default, relatime. That is
        // what runc does too.
        "rro" => Opt::Rec(A::RDONLY, A::empty()),
        "rrw" => Opt::Rec(A::empty(), A::RDONLY),
        "rnosuid" => Opt::Rec(A::NOSUID, A::empty()),
        "rsuid" => Opt::Rec(A::empty(), A::NOSUID),
        "rnodev" => Opt::Rec(A::NODEV, A::empty()),
        "rdev" => Opt::Rec(A::empty(), A::NODEV),
        "rnoexec" => Opt::Rec(A::NOEXEC, A::empty()),
        "rexec" => Opt::Rec(A::empty(), A::NOEXEC),
        "rnodiratime" => Opt::Rec(A::NODIRATIME, A::empty()),
        "rdiratime" => Opt::Rec(A::empty(), A::NODIRATIME),
        "rnosymfollow" => Opt::Rec(A::NOSYMFOLLOW, A::empty()),
        "rsymfollow" => Opt::Rec(A::empty(), A::NOSYMFOLLOW),
        "rrelatime" | "ratime" | "rnorelatime" | "rnostrictatime" => Opt::Rec(RELATIME, A::ATIME_MASK),
        "rnoatime" => Opt::Rec(A::NOATIME, A::ATIME_MASK),
        "rstrictatime" => Opt::Rec(A::STRICTATIME, A::ATIME_MASK),
        "bind" => Opt::Bind { recursive: false },
        "rbind" => Opt::Bind { recursive: true },
        "private" | "rprivate" => Opt::Private,
        "defaults" => Opt::Ignore,
        "shared" | "rshared" | "slave" | "rslave" | "unbindable" | "runbindable" => {
            return Err(Error::invalid(format!(
                "mount option `{word}`: container mounts are always private (propagation to or from the host is not supported)"
            )));
        }
        "remount" => return Err(Error::invalid("mount option `remount` makes no sense in config.json")),
        "idmap" => Opt::Idmap { recursive: false },
        "ridmap" => Opt::Idmap { recursive: true },
        "tmpcopyup" => {
            return Err(Error::Unsupported(vec![Unsupported {
                field: "mount option `tmpcopyup`".into(),
                when: "Phase 5, as daemon-side volume copy-up",
            }]));
        }
        other => Opt::Fs(match other.split_once('=') {
            Some((k, v)) => FsOption::Value(k.to_owned(), v.to_owned()),
            None => FsOption::Flag(other.to_owned()),
        }),
    })
}

/// Makes `dest` absolute and rejects `..`: mount destinations are classified
/// by prefix below (e.g. "under /proc"), which is only sound on clean paths.
pub fn clean_destination(dest: &Path) -> Result<PathBuf> {
    let mut out = PathBuf::from("/");
    for c in dest.components() {
        match c {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(n) => out.push(n),
            Component::ParentDir => {
                return Err(Error::invalid(format!("mount destination {} contains `..`", dest.display())));
            }
            Component::Prefix(_) => unreachable!("no path prefixes on Linux"),
        }
    }
    Ok(out)
}

/// Parses and validates one OCI mount.
pub fn parse(m: &Mount, bundle: &Bundle) -> Result<MountEntry> {
    let destination = clean_destination(m.destination())?;
    let what = || format!("mount on {}", destination.display());
    if destination == Path::new("/") {
        return Err(Error::invalid("a mount on `/` would hide the rootfs; use root.path instead"));
    }

    let mut set = MountAttr::empty();
    let mut clear = MountAttr::empty();
    let (mut rec_set, mut rec_clear) = (MountAttr::empty(), MountAttr::empty());
    let mut bind = None;
    let mut idmap: Option<bool> = None;
    let mut fs_opts = Vec::new();
    for word in m.options().iter().flatten() {
        match classify(word)? {
            Opt::Set(a) => {
                set |= a;
                clear -= a;
            }
            Opt::Clear(a) => {
                clear |= a;
                set -= a;
            }
            Opt::Atime(a) => {
                set = (set - MountAttr::ATIME_MASK) | a;
                clear |= MountAttr::ATIME_MASK;
            }
            Opt::Rec(a, c) => {
                // A later atime word replaces an earlier one.
                if c.contains(MountAttr::ATIME_MASK) {
                    rec_set -= MountAttr::ATIME_MASK;
                }
                rec_set = (rec_set - c) | a;
                rec_clear = (rec_clear - a) | c;
            }
            Opt::Bind { recursive } => bind = Some(recursive || bind == Some(true)),
            Opt::Idmap { recursive } => idmap = Some(recursive || idmap == Some(true)),
            Opt::Private | Opt::Ignore => {}
            Opt::Fs(o) => fs_opts.push(o),
        }
    }

    let typ = m.typ().as_deref().unwrap_or("");
    let kind = if bind.is_some() || typ == "bind" {
        if !fs_opts.is_empty() {
            return Err(Error::invalid(format!(
                "{}: unknown bind-mount options {:?} (filesystem options are not allowed on bind mounts)",
                what(),
                fs_opts
            )));
        }
        let source =
            m.source().as_deref().ok_or_else(|| Error::invalid(format!("{}: bind mount without source", what())))?;
        MountKind::Bind { source: bundle.resolve(source), recursive: bind.unwrap_or(false) }
    } else {
        let fstype = kernel_fstype(typ).ok_or_else(|| {
            Error::invalid(format!(
                "{}: mount type `{typ}` is not supported (known: proc, sysfs, tmpfs, devpts, mqueue, cgroup, bind)",
                what()
            ))
        })?;
        let source = m.source().as_ref().map(|s| s.to_string_lossy().into_owned());
        MountKind::Fs { fstype: fstype.to_owned(), source, options: fs_opts }
    };

    let idmap = parse_idmap(m, idmap, &kind).map_err(|why| Error::invalid(format!("{}: {why}", what())))?;
    let entry = MountEntry { destination, kind, set, clear, rec_set, rec_clear, idmap };
    check_pseudo_fs_targets(&entry)?;
    Ok(entry)
}

/// The `idmap`/`ridmap` options and the mount's own `uidMappings` and
/// `gidMappings`, which OCI only allows together. Whether the container has
/// a user namespace to idmap with is the plan's business
/// (`userns::check_mounts`).
fn parse_idmap(m: &Mount, option: Option<bool>, kind: &MountKind) -> std::result::Result<Option<Idmap>, String> {
    let (uids, gids) = (m.uid_mappings().as_deref(), m.gid_mappings().as_deref());
    let Some(recursive) = option else {
        if uids.is_some() || gids.is_some() {
            return Err("uidMappings/gidMappings on a mount need the `idmap` or `ridmap` option".into());
        }
        return Ok(None);
    };
    if !matches!(kind, MountKind::Bind { .. }) {
        return Err("`idmap`/`ridmap` are only supported on bind mounts".into());
    }
    if uids.is_some() != gids.is_some() {
        return Err("a mount's uidMappings and gidMappings go together: give both or neither".into());
    }
    let convert =
        |maps: Option<&[oci_spec::runtime::LinuxIdMapping]>| crate::userns::from_spec(maps.unwrap_or_default());
    Ok(Some(Idmap { recursive, uids: convert(uids), gids: convert(gids) }))
}

/// The files under `/proc` that a bind mount may replace: the ones lxcfs
/// emulates (a FUSE filesystem that shows a container its own cgroup limits
/// as "the machine": `free` reads `/proc/meminfo`, `nproc` reads
/// `/proc/cpuinfo`, …). The list is runc's.
const PROC_BIND_FILES: [&str; 10] = [
    "/proc/cpuinfo",
    "/proc/diskstats",
    "/proc/meminfo",
    "/proc/stat",
    "/proc/swaps",
    "/proc/uptime",
    "/proc/loadavg",
    "/proc/slabinfo",
    "/proc/net/dev",
    "/proc/sys/kernel/ns_last_pid",
];

/// `/proc` and `/sys` are kernel interfaces, and mounting *over* parts of them
/// is how several container escapes worked: CVE-2019-16884 mounted over
/// `/proc/self/attr` to switch off AppArmor, and a bind onto `/proc/sys/…` or
/// `/sys/…` can hand the container a writable kernel knob. User mounts there
/// would also defeat `maskedPaths`/`readonlyPaths`, which are applied to the
/// kernel's files, not to whatever was mounted on top. So only these are
/// allowed:
///
/// * `/proc`: a new procfs instance, nothing else;
/// * below `/proc`: a bind mount of a regular *file* onto one of
///   [`PROC_BIND_FILES`] (lxcfs). A file can't carry submounts, and only
///   these few names can be replaced;
/// * `/sys`: sysfs, or a bind mount (of the host's `/sys`, for user
///   namespaces that may not mount sysfs);
/// * `/sys/fs/cgroup`: cgroup2 (the spec's `cgroup` became `cgroup2` above);
/// * nothing else below `/sys`.
///
/// Elsewhere, procfs and sysfs are refused: a second instance at `/mnt/proc`
/// would show everything `maskedPaths` hides at `/proc`.
fn check_pseudo_fs_targets(e: &MountEntry) -> Result<()> {
    let d = e.destination.as_path();
    let fstype = match &e.kind {
        MountKind::Fs { fstype, .. } => Some(fstype.as_str()),
        MountKind::Bind { .. } | MountKind::HostSysfs => None,
    };
    let refuse = |why: String| Err(Error::invalid(format!("mount {} is not allowed: {why}", e.describe())));
    if d == Path::new("/proc") {
        if fstype != Some("proc") {
            return refuse("/proc must be a new procfs instance (type `proc`)".into());
        }
    } else if d.starts_with("/proc") {
        if !PROC_BIND_FILES.iter().any(|f| d == Path::new(f)) {
            return refuse(format!(
                "user mounts inside /proc could replace kernel files (a writable /proc/sys, a fake /proc/self/attr) \
                 and would defeat maskedPaths/readonlyPaths; the only exceptions are bind mounts of regular files \
                 onto {}",
                PROC_BIND_FILES.join(", ")
            ));
        }
        let MountKind::Bind { source, .. } = &e.kind else {
            return refuse(format!(
                "{} may only be replaced by a bind mount of a regular file (as lxcfs does)",
                d.display()
            ));
        };
        // Checked here in the parent, like every other spec error. The source
        // is a host path chosen by whoever wrote config.json; `metadata`
        // follows symlinks, as the bind itself will.
        let meta = std::fs::metadata(source).with_context(|| format!("mount {}: stat source", e.describe()))?;
        if !meta.is_file() {
            return refuse(format!("the source of a bind mount onto {} must be a regular file", d.display()));
        }
    } else if d == Path::new("/sys") {
        if !matches!(fstype, Some("sysfs") | None) {
            return refuse("/sys must be sysfs or a bind mount".into());
        }
    } else if d == Path::new("/sys/fs/cgroup") {
        if fstype != Some("cgroup2") {
            return refuse("/sys/fs/cgroup must be a cgroup2 mount (type `cgroup` or `cgroup2`)".into());
        }
    } else if d.starts_with("/sys") {
        return refuse(
            "user mounts inside /sys could replace kernel knobs and would defeat maskedPaths/readonlyPaths; only \
             sysfs on /sys and cgroup2 on /sys/fs/cgroup are allowed there"
                .into(),
        );
    } else if let Some(fs @ ("proc" | "sysfs")) = fstype {
        let home = if fs == "proc" { "/proc" } else { "/sys" };
        return refuse(format!(
            "{fs} may only be mounted on {home} (a second instance elsewhere would not be covered by \
             maskedPaths/readonlyPaths)"
        ));
    }
    Ok(())
}

/// Whether the plan vetted `dest` as a mount point on the kernel's own
/// filesystems (`/proc`, `/sys` and below: see [`check_pseudo_fs_targets`]).
/// Any *other* destination must not end up on procfs, sysfs or cgroupfs once
/// symlinks are followed; `rootfs::mount_entry` checks that on the resolved
/// target.
pub(crate) fn vetted_kernel_fs_destination(dest: &Path) -> bool {
    dest.starts_with("/proc") || dest.starts_with("/sys")
}

#[cfg(test)]
mod tests {
    use super::*;
    use oci_spec::runtime::{MountBuilder, get_default_mounts};

    fn bundle() -> Bundle {
        Bundle::from_spec(PathBuf::from("/bundles/b"), Default::default())
    }

    fn mount(dest: &str, typ: &str, source: &str, opts: &[&str]) -> Mount {
        MountBuilder::default()
            .destination(dest)
            .typ(typ)
            .source(source)
            .options(opts.iter().map(|s| s.to_string()).collect::<Vec<_>>())
            .build()
            .unwrap()
    }

    #[test]
    fn runc_default_mounts_all_parse() {
        let b = bundle();
        for m in get_default_mounts() {
            parse(&m, &b).unwrap_or_else(|e| panic!("{:?}: {e}", m.destination()));
        }
    }

    #[test]
    fn recursive_attributes() {
        let b = bundle();
        let e = parse(&mount("/mnt", "bind", "/tmp", &["rbind", "rro", "rnosuid", "rexec"]), &b).unwrap();
        assert_eq!(e.rec_set, MountAttr::RDONLY | MountAttr::NOSUID);
        assert_eq!(e.rec_clear, MountAttr::NOEXEC);
        assert_eq!((e.set, e.clear), (MountAttr::empty(), MountAttr::empty()));
        // The atime field is replaced as a whole; the last word wins, and
        // "not that mode" means relatime.
        let e = parse(&mount("/mnt", "bind", "/tmp", &["rbind", "rnoatime", "ratime"]), &b).unwrap();
        assert_eq!((e.rec_set, e.rec_clear), (MountAttr::empty(), MountAttr::ATIME_MASK));
        let e = parse(&mount("/mnt", "bind", "/tmp", &["rbind", "rstrictatime"]), &b).unwrap();
        assert_eq!((e.rec_set, e.rec_clear), (MountAttr::STRICTATIME, MountAttr::ATIME_MASK));
    }

    #[test]
    fn splits_attributes_from_fs_options() {
        let m = mount("/dev", "tmpfs", "tmpfs", &["nosuid", "strictatime", "mode=755", "size=65536k"]);
        let e = parse(&m, &bundle()).unwrap();
        assert_eq!(e.set, MountAttr::NOSUID | MountAttr::STRICTATIME);
        assert!(e.clear.contains(MountAttr::ATIME_MASK));
        assert_eq!(
            e.kind,
            MountKind::Fs {
                fstype: "tmpfs".into(),
                source: Some("tmpfs".into()),
                options: vec![
                    FsOption::Value("mode".into(), "755".into()),
                    FsOption::Value("size".into(), "65536k".into())
                ],
            }
        );
    }

    #[test]
    fn later_options_win() {
        let e = parse(&mount("/data", "tmpfs", "tmpfs", &["ro", "rw"]), &bundle()).unwrap();
        assert!(!e.set.contains(MountAttr::RDONLY));
        assert!(e.clear.contains(MountAttr::RDONLY));
    }

    #[test]
    fn cgroup_means_cgroup2() {
        let e = parse(&mount("/sys/fs/cgroup", "cgroup", "cgroup", &["ro"]), &bundle()).unwrap();
        assert!(matches!(e.kind, MountKind::Fs { ref fstype, .. } if fstype == "cgroup2"));
    }

    #[test]
    fn bind_sources_are_relative_to_the_bundle() {
        let e = parse(&mount("/data", "none", "data", &["rbind", "ro"]), &bundle()).unwrap();
        assert_eq!(e.kind, MountKind::Bind { source: "/bundles/b/data".into(), recursive: true });
        assert_eq!(e.set, MountAttr::RDONLY);
    }

    #[test]
    fn rejects_dangerous_or_unknown_mounts() {
        let b = bundle();
        let bad = [
            mount("/", "tmpfs", "tmpfs", &[]),
            mount("/proc/sys", "tmpfs", "tmpfs", &[]),
            mount("/proc", "tmpfs", "tmpfs", &[]),
            mount("/sys/kernel", "bind", "/tmp", &["bind"]),
            mount("/mnt/proc", "proc", "proc", &[]),
            mount("/data/../etc", "tmpfs", "tmpfs", &[]),
            mount("/data", "tmpfs", "tmpfs", &["rshared"]),
            mount("/data", "ext4", "/dev/sda3", &[]),
            mount("/data", "bind", "/tmp", &["bind", "mode=755"]),
        ];
        for m in bad {
            assert!(parse(&m, &b).is_err(), "should reject {m:?}");
        }
    }

    #[test]
    fn idmap_options_and_mappings() {
        let b = bundle();
        let e = parse(&mount("/data", "bind", "/tmp", &["rbind", "ridmap"]), &b).unwrap();
        assert_eq!(e.idmap, Some(Idmap { recursive: true, uids: vec![], gids: vec![] }));
        assert_eq!(parse(&mount("/data", "bind", "/tmp", &["bind"]), &b).unwrap().idmap, None);
        // Only bind mounts can be idmapped.
        let msg = parse(&mount("/data", "tmpfs", "tmpfs", &["idmap"]), &b).unwrap_err().to_string();
        assert!(msg.contains("only supported on bind mounts"), "{msg}");
        // Mappings need the option, and come in pairs.
        let map = oci_spec::runtime::LinuxIdMappingBuilder::default().host_id(1u32).size(1u32).build().unwrap();
        let mut m = mount("/data", "bind", "/tmp", &["bind"]);
        m.set_uid_mappings(Some(vec![map]));
        m.set_gid_mappings(Some(vec![map]));
        assert!(parse(&m, &b).unwrap_err().to_string().contains("need the `idmap`"));
        m.set_options(Some(vec!["bind".into(), "idmap".into()]));
        let e = parse(&m, &b).unwrap();
        assert_eq!(e.idmap.unwrap().uids, vec![IdMap { container: 0, host: 1, size: 1 }]);
        m.set_gid_mappings(None);
        assert!(parse(&m, &b).unwrap_err().to_string().contains("go together"));
    }

    #[test]
    fn lxcfs_files_may_be_bind_mounted_into_proc() {
        let b = bundle();
        let file = tempfile::NamedTempFile::new().unwrap();
        let src = file.path().to_str().unwrap();
        for dest in ["/proc/meminfo", "/proc/cpuinfo", "/proc/net/dev", "/proc/sys/kernel/ns_last_pid"] {
            parse(&mount(dest, "bind", src, &["bind", "ro"]), &b).unwrap_or_else(|e| panic!("{dest}: {e}"));
        }
        let dir = tempfile::tempdir().unwrap();
        let bad = [
            // Not a file.
            (mount("/proc/meminfo", "bind", dir.path().to_str().unwrap(), &["rbind"]), "regular file"),
            // Not a bind.
            (mount("/proc/meminfo", "tmpfs", "tmpfs", &[]), "bind mount of a regular file"),
            // Not on the list, even as a file bind.
            (mount("/proc/kcore", "bind", src, &["bind"]), "inside /proc"),
            (mount("/proc/sys/kernel/core_pattern", "bind", src, &["bind"]), "inside /proc"),
            (mount("/proc/self/attr/exec", "bind", src, &["bind"]), "inside /proc"),
        ];
        for (m, why) in bad {
            let msg = parse(&m, &b).unwrap_err().to_string();
            assert!(msg.contains(why), "{:?}: {msg}", m.destination());
        }
        // A missing source is an error too (not "not a file" by accident).
        let e = parse(&mount("/proc/meminfo", "bind", "/nonexistent/meminfo", &["bind"]), &b).unwrap_err();
        assert_eq!(e.errno(), Some(rustlet_sys::Errno::ENOENT));
    }

    #[test]
    fn pseudo_filesystems_stay_in_their_place() {
        let b = bundle();
        let bad = [
            mount("/sys", "tmpfs", "tmpfs", &[]),
            mount("/sys/fs/cgroup", "tmpfs", "tmpfs", &[]),
            mount("/sys/fs/cgroup", "bind", "/sys/fs/cgroup", &["rbind"]),
            mount("/sys/firmware", "tmpfs", "tmpfs", &[]),
            mount("/mnt/sys", "sysfs", "sysfs", &[]),
        ];
        for m in bad {
            assert!(parse(&m, &b).is_err(), "should reject {m:?}");
        }
        // Allowed: a bind of the host's /sys (user namespaces), and paths
        // that merely *start* with the same letters.
        parse(&mount("/sys", "bind", "/sys", &["rbind", "ro"]), &b).unwrap();
        parse(&mount("/proc2", "tmpfs", "tmpfs", &[]), &b).unwrap();
        parse(&mount("/system", "tmpfs", "tmpfs", &[]), &b).unwrap();
    }
}

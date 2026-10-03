//! Volumes and mounts: storage that lives outside a container's own layer.
//!
//! | kind | what is mounted | lives |
//! |---|---|---|
//! | volume | `<data root>/volumes/<name>/_data`, managed by the daemon | until `volume rm` (anonymous ones: until their container is removed with `--rm`/`rm -v`) |
//! | bind | a host directory or file | it is the host's |
//! | tmpfs | a new tmpfs | until the container stops |
//!
//! A volume that is empty when it is first mounted gets a copy of what the
//! image has at that path (unless `nocopy`), as Docker does.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use ts_rs::TS;

/// What a mount is.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, TS)]
#[serde(rename_all = "lowercase")]
pub enum MountType {
    #[default]
    Volume,
    Bind,
    Tmpfs,
}

impl std::fmt::Display for MountType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            MountType::Volume => "volume",
            MountType::Bind => "bind",
            MountType::Tmpfs => "tmpfs",
        })
    }
}

/// One mount of `-v`, `--mount` or `--tmpfs`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize, TS)]
#[serde(default)]
pub struct MountSpec {
    #[serde(rename = "type")]
    pub kind: MountType,
    /// A volume's name (`None`: a new anonymous volume), or a bind mount's
    /// absolute host path. Unused for tmpfs.
    pub source: Option<String>,
    /// The absolute path in the container.
    pub target: String,
    pub read_only: bool,
    /// Volume: don't copy the image's files into it when it is empty.
    pub no_copy: bool,
    /// Bind: create the host directory if it is missing (the `-v` syntax
    /// does, as Docker's; `--mount` doesn't).
    pub create_host_path: bool,
    /// Bind, in a container with `--userns=remap`: an idmapped mount, so
    /// the host's owners appear as the container's (host root as container
    /// root). Volumes always are; host directories only when asked.
    pub idmap: bool,
    /// Tmpfs: `size=`, in bytes (default: half the RAM, the kernel's).
    pub tmpfs_size: Option<u64>,
    /// Tmpfs: `mode=` (default 1777).
    pub tmpfs_mode: Option<u32>,
    /// Tmpfs: mount flags over the defaults `nosuid,nodev,noexec`
    /// (`exec`, `suid`, `dev`, `ro`, …).
    pub tmpfs_options: Vec<String>,
}

impl MountSpec {
    /// `-v`/`--volume`: `[SOURCE:]TARGET[:OPTIONS]`, Docker's short
    /// syntax. An absolute `SOURCE` is a host path (bind mount, created if
    /// missing), anything else a volume's name; without a source, an
    /// anonymous volume. Options, comma-separated: `ro`, `rw`, `nocopy`,
    /// `idmap`, `private`/`rprivate` (the only propagation there is).
    ///
    /// ```
    /// # use rustlet_spec::volume::{MountSpec, MountType};
    /// let m = MountSpec::parse_volume("data:/var/lib/data:ro").unwrap();
    /// assert_eq!((m.kind, m.source.as_deref(), m.read_only), (MountType::Volume, Some("data"), true));
    /// assert_eq!(MountSpec::parse_volume("/srv/www:/usr/share/nginx/html").unwrap().kind, MountType::Bind);
    /// ```
    pub fn parse_volume(s: &str) -> Result<MountSpec, String> {
        let bad = |why: &str| format!("-v {s:?}: {why}");
        let parts: Vec<&str> = s.split(':').collect();
        let (source, target, options) = match parts.as_slice() {
            [t] => (None, *t, ""),
            [_, o] if is_option_list(o) => {
                return Err(bad("a volume without a source can't have options (give NAME:TARGET:OPTIONS)"));
            }
            [src, t] => (Some(*src), *t, ""),
            [src, t, o] => (Some(*src), *t, *o),
            _ => return Err(bad("expected [SOURCE:]TARGET[:OPTIONS]")),
        };
        let mut m = MountSpec { target: target.to_owned(), ..MountSpec::default() };
        match source {
            None => m.kind = MountType::Volume,
            Some("") => return Err(bad("the source is empty")),
            Some(p) if p.starts_with('/') => {
                m.kind = MountType::Bind;
                m.source = Some(p.to_owned());
                m.create_host_path = true;
            }
            Some(name) if valid_volume_name(name) => {
                m.kind = MountType::Volume;
                m.source = Some(name.to_owned());
            }
            Some(name) => {
                return Err(bad(&format!(
                    "{name:?} is neither an absolute host path nor a volume name ([a-zA-Z0-9][a-zA-Z0-9_.-]+)"
                )));
            }
        }
        for opt in options.split(',').filter(|o| !o.is_empty()) {
            match opt {
                "ro" => m.read_only = true,
                "rw" => m.read_only = false,
                "nocopy" if m.kind == MountType::Volume => m.no_copy = true,
                "idmap" => m.idmap = true,
                "private" | "rprivate" => {}
                "z" | "Z" => return Err(bad("SELinux relabelling (z, Z) isn't supported")),
                "shared" | "rshared" | "slave" | "rslave" => {
                    return Err(bad(&format!("{opt}: container mounts are always private")));
                }
                other => return Err(bad(&format!("unknown option {other:?}"))),
            }
        }
        m.check().map_err(|e| bad(&e))?;
        Ok(m)
    }

    /// `--mount`: Docker's long syntax, `key=value` pairs separated by
    /// commas: `type=volume|bind|tmpfs` (default volume),
    /// `source`/`src`, `target`/`destination`/`dst`, `readonly`/`ro`,
    /// `volume-nocopy`, `bind-propagation=rprivate`, `tmpfs-size`,
    /// `tmpfs-mode`. A bind mount's source must exist.
    pub fn parse_mount(s: &str) -> Result<MountSpec, String> {
        let bad = |why: &str| format!("--mount {s:?}: {why}");
        let mut m = MountSpec::default();
        let mut kind = None;
        for field in s.split(',').filter(|f| !f.is_empty()) {
            let (key, value) = match field.split_once('=') {
                Some((k, v)) => (k.trim(), Some(v.trim())),
                None => (field.trim(), None),
            };
            let flag = |v: Option<&str>| match v {
                None | Some("true" | "1") => Ok(true),
                Some("false" | "0") => Ok(false),
                Some(other) => Err(bad(&format!("{key}={other}: expected true or false"))),
            };
            let value_of = |v| nonempty(v).ok_or_else(|| bad(&format!("{key} needs a value")));
            match key {
                "type" => {
                    kind = Some(match value_of(value)? {
                        "volume" => MountType::Volume,
                        "bind" => MountType::Bind,
                        "tmpfs" => MountType::Tmpfs,
                        other => return Err(bad(&format!("unsupported type {other:?} (volume, bind, tmpfs)"))),
                    })
                }
                "source" | "src" => m.source = Some(value_of(value)?.to_owned()),
                "target" | "destination" | "dst" => m.target = value_of(value)?.to_owned(),
                "readonly" | "ro" => m.read_only = flag(value)?,
                "volume-nocopy" => m.no_copy = flag(value)?,
                "bind-propagation" => match value_of(value)? {
                    "private" | "rprivate" => {}
                    other => {
                        return Err(bad(&format!("bind-propagation={other}: container mounts are always private")));
                    }
                },
                "tmpfs-size" => m.tmpfs_size = Some(parse_bytes(value_of(value)?).map_err(|e| bad(&e))?),
                "tmpfs-mode" => {
                    let v = value_of(value)?;
                    m.tmpfs_mode =
                        Some(u32::from_str_radix(v, 8).map_err(|_| bad(&format!("tmpfs-mode={v}: not octal")))?);
                }
                "consistency" => {}
                "volume-driver" if value == Some("local") => {}
                other => return Err(bad(&format!("unsupported key {other:?}"))),
            }
        }
        m.kind = kind.unwrap_or_default();
        match m.kind {
            MountType::Volume => {
                if let Some(name) = &m.source
                    && !valid_volume_name(name)
                {
                    return Err(bad(&format!("{name:?} is not a volume name ([a-zA-Z0-9][a-zA-Z0-9_.-]+)")));
                }
            }
            MountType::Bind if m.source.is_none() => return Err(bad("a bind mount needs a source")),
            MountType::Tmpfs if m.source.is_some() => return Err(bad("a tmpfs mount has no source")),
            _ => {}
        }
        if m.kind != MountType::Tmpfs && (m.tmpfs_size.is_some() || m.tmpfs_mode.is_some()) {
            return Err(bad("tmpfs-size and tmpfs-mode are for type=tmpfs"));
        }
        if m.kind != MountType::Volume && m.no_copy {
            return Err(bad("volume-nocopy is for type=volume"));
        }
        m.check().map_err(|e| bad(&e))?;
        Ok(m)
    }

    /// `--tmpfs TARGET[:OPTIONS]`: options as `mount -o` takes them,
    /// `size=` (with a k/m/g suffix) and `mode=` (octal) among them.
    pub fn parse_tmpfs(s: &str) -> Result<MountSpec, String> {
        let bad = |why: &str| format!("--tmpfs {s:?}: {why}");
        let (target, options) = s.split_once(':').unwrap_or((s, ""));
        let mut m = MountSpec { kind: MountType::Tmpfs, target: target.to_owned(), ..MountSpec::default() };
        for opt in options.split(',').filter(|o| !o.is_empty()) {
            match opt.split_once('=') {
                Some(("size", v)) => m.tmpfs_size = Some(parse_bytes(v).map_err(|e| bad(&e))?),
                Some(("mode", v)) => {
                    m.tmpfs_mode = Some(u32::from_str_radix(v, 8).map_err(|_| bad(&format!("mode={v}: not octal")))?)
                }
                Some((k, _)) => return Err(bad(&format!("unsupported option {k:?}"))),
                None if TMPFS_FLAGS.contains(&opt) => m.tmpfs_options.push(opt.to_owned()),
                None => return Err(bad(&format!("unsupported option {opt:?}"))),
            }
        }
        m.check().map_err(|e| bad(&e))?;
        Ok(m)
    }

    /// What every syntax shares: the target is a clean absolute path, a
    /// bind source absolute.
    fn check(&self) -> Result<(), String> {
        if !self.target.starts_with('/') {
            return Err(format!("the target {:?} must be an absolute path", self.target));
        }
        if self.target == "/" {
            return Err("can't mount over the container's root".into());
        }
        if self.target.split('/').any(|c| c == "..") {
            return Err(format!("the target {:?} may not contain ..", self.target));
        }
        if self.kind == MountType::Bind
            && let Some(src) = &self.source
            && !src.starts_with('/')
        {
            return Err(format!("the host path {src:?} must be absolute"));
        }
        if let Some(mode) = self.tmpfs_mode
            && mode > 0o7777
        {
            return Err(format!("mode {mode:o} has more than permission bits"));
        }
        Ok(())
    }
}

/// `Some` non-empty value.
fn nonempty(v: Option<&str>) -> Option<&str> {
    v.filter(|v| !v.is_empty())
}

/// The mount flags `--tmpfs` takes.
pub const TMPFS_FLAGS: [&str; 8] = ["ro", "rw", "exec", "noexec", "suid", "nosuid", "dev", "nodev"];

/// `-v`'s third part, or a second part that can only be options.
fn is_option_list(s: &str) -> bool {
    !s.starts_with('/')
        && s.split(',').all(|o| {
            matches!(
                o,
                "ro" | "rw"
                    | "nocopy"
                    | "idmap"
                    | "z"
                    | "Z"
                    | "private"
                    | "rprivate"
                    | "shared"
                    | "rshared"
                    | "slave"
                    | "rslave"
            )
        })
}

/// `64m`, `1g`, `512k`, `1048576`: bytes.
fn parse_bytes(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let (digits, unit) = s.find(|c: char| !c.is_ascii_digit()).map_or((s, ""), |i| s.split_at(i));
    let n: u64 = digits.parse().map_err(|_| format!("{s:?} is not a size"))?;
    let shift = match unit.to_ascii_lowercase().as_str() {
        "" | "b" => 0,
        "k" | "kb" | "kib" => 10,
        "m" | "mb" | "mib" => 20,
        "g" | "gb" | "gib" => 30,
        _ => return Err(format!("{s:?}: unknown unit {unit:?} (k, m, g)")),
    };
    n.checked_mul(1 << shift).ok_or_else(|| format!("{s:?} is too large"))
}

/// Is `name` a valid volume name? Docker's rule: `[a-zA-Z0-9][a-zA-Z0-9_.-]+`
/// (at least two characters), at most 128 here.
pub fn valid_volume_name(name: &str) -> bool {
    name.len() >= 2 && crate::valid_container_name(name)
}

/// `POST /v1/volumes`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(default)]
pub struct VolumeCreate {
    /// Default: a random 64-hex-digit name (an anonymous volume).
    pub name: Option<String>,
    pub labels: BTreeMap<String, String>,
}

/// A volume: `GET /v1/volumes` lists them, `GET /v1/volumes/{name}` shows
/// one.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(default)]
pub struct Volume {
    pub name: String,
    /// Always `local`.
    pub driver: String,
    /// Its directory on the host (`/var/lib/rustlet/volumes/<name>/_data`).
    pub mountpoint: String,
    /// RFC 3339, UTC.
    pub created: String,
    pub labels: BTreeMap<String, String>,
    /// Made for a container's `-v /path` or the image's `VOLUME`, with a
    /// generated name.
    pub anonymous: bool,
    /// The containers (by name) that have it among their mounts.
    pub containers: Vec<String>,
}

/// Query of `DELETE /v1/volumes/{name}`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(default)]
pub struct VolumeRemoveQuery {
    /// No error if it doesn't exist.
    pub force: bool,
}

/// Query of `POST /v1/volumes/prune`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(default)]
pub struct VolumePruneQuery {
    /// Named volumes too, not only anonymous ones (Docker's `--all`).
    pub all: bool,
}

/// A container's mount, as `inspect` shows it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(default)]
pub struct MountPoint {
    #[serde(rename = "type")]
    pub kind: MountType,
    /// A volume's name.
    pub name: Option<String>,
    /// On the host: the volume's directory or the bind source.
    pub source: String,
    pub destination: String,
    pub read_only: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_syntax() {
        let v = |s| MountSpec::parse_volume(s).unwrap();
        let anon = v("/data");
        assert_eq!((anon.kind, anon.source.as_deref(), anon.target.as_str()), (MountType::Volume, None, "/data"));
        let named = v("cache:/var/cache:ro,nocopy");
        assert_eq!(named.source.as_deref(), Some("cache"));
        assert!(named.read_only && named.no_copy && !named.create_host_path);
        let bind = v("/srv/www:/www:rw,idmap");
        assert_eq!((bind.kind, bind.source.as_deref()), (MountType::Bind, Some("/srv/www")));
        assert!(bind.create_host_path && bind.idmap && !bind.read_only);
        assert_eq!(v("/a:/b:rprivate").kind, MountType::Bind);
        for bad in [
            "",
            "data",
            "/data:ro",
            "x:/data",
            "../x:/data",
            "data:rel",
            "data:/",
            "data:/a/../b",
            "/h:/c:nocopy",
            "/h:/c:shared",
            "/h:/c:z",
            "/h:/c:wat",
            "a:b:c:d",
            ":/data",
        ] {
            assert!(MountSpec::parse_volume(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn long_syntax() {
        let m = |s| MountSpec::parse_mount(s).unwrap();
        let vol = m("source=data,target=/data,readonly,volume-nocopy=true");
        assert_eq!((vol.kind, vol.source.as_deref()), (MountType::Volume, Some("data")));
        assert!(vol.read_only && vol.no_copy);
        let anon = m("dst=/data");
        assert_eq!((anon.kind, anon.source), (MountType::Volume, None));
        let bind = m("type=bind,src=/etc/hosts,dst=/h,ro=false,bind-propagation=rprivate");
        assert_eq!(bind.kind, MountType::Bind);
        assert!(!bind.create_host_path && !bind.read_only, "--mount binds need their source");
        let tmp = m("type=tmpfs,dst=/run,tmpfs-size=64m,tmpfs-mode=1770");
        assert_eq!((tmp.tmpfs_size, tmp.tmpfs_mode), (Some(64 << 20), Some(0o1770)));
        for bad in [
            "type=nfs,dst=/x",
            "type=bind,dst=/x",
            "type=tmpfs,src=x,dst=/x",
            "type=volume,src=/abs,dst=/x",
            "type=bind,src=rel,dst=/x",
            "dst=/x,tmpfs-size=1m",
            "type=bind,src=/h,dst=/x,volume-nocopy",
            "src=data",
            "dst=/x,readonly=maybe",
            "dst=/x,bind-propagation=shared",
            "dst=/x,what=1",
            "dst=",
        ] {
            assert!(MountSpec::parse_mount(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn tmpfs_syntax() {
        let t = MountSpec::parse_tmpfs("/run:rw,exec,size=1g,mode=700").unwrap();
        assert_eq!((t.kind, t.target.as_str()), (MountType::Tmpfs, "/run"));
        assert_eq!((t.tmpfs_size, t.tmpfs_mode), (Some(1 << 30), Some(0o700)));
        assert_eq!(t.tmpfs_options, ["rw", "exec"]);
        assert_eq!(MountSpec::parse_tmpfs("/tmp").unwrap().tmpfs_options, Vec::<String>::new());
        for bad in ["tmp", "/x:size=lots", "/x:mode=9", "/x:uid=0", "/x:bogus", "/x:mode=17777"] {
            assert!(MountSpec::parse_tmpfs(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn sizes_and_names() {
        assert_eq!(parse_bytes("512k").unwrap(), 512 << 10);
        assert_eq!(parse_bytes("2G").unwrap(), 2 << 30);
        assert_eq!(parse_bytes("100").unwrap(), 100);
        assert!(parse_bytes("1t").is_err() && parse_bytes("m").is_err());
        assert!(valid_volume_name("db") && valid_volume_name("my_vol.1-a"));
        assert!(!valid_volume_name("d") && !valid_volume_name("-db") && !valid_volume_name("a/b"));
    }
}

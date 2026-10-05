//! From an image to a runtime spec: the `config.json` that `rustlet-runc`
//! runs.
//!
//! The image config says how its author meant the image to run, `rustlet
//! run`'s options override parts of that, and the runtime understands
//! neither: it takes an OCI runtime spec. OCI image-spec
//! [`conversion.md`] says how config fields become spec fields, Docker's
//! `run` says what the options override, and everything else is
//! [`default_spec`]'s, unchanged. Capabilities, the seccomp profile, masked
//! and read-only paths, `noNewPrivileges`, rlimits and mounts are the
//! engine's decisions, never the image's.
//!
//! ```text
//!  image config             rustlet run             config.json
//!  Entrypoint, Cmd          --entrypoint, ARGS…     process.args
//!  Env                      -e KEY=VALUE            process.env
//!  WorkingDir               -w DIR                  process.cwd
//!  User + its /etc files    -u USER[:GROUP]         process.user
//!                           -t                      process.terminal
//!                           --hostname              hostname
//!                           --read-only             root.readonly
//!                           --userns=remap          linux.namespaces, uid/gid maps
//!  os, architecture, Labels…                        annotations
//! ```
//!
//! **Command.** `process.args` is the entrypoint followed by the command
//! (conversion.md: `Cmd` is appended to `Entrypoint`). Arguments after the
//! image name replace `Cmd`. `--entrypoint` replaces `Entrypoint` *and*
//! drops the image's `Cmd`, which was written as arguments for the image's
//! own entrypoint (Docker documents the same); `--entrypoint ''` clears it,
//! leaving the arguments alone. Nothing to run is an error here, where the
//! message can say why, rather than at `create`.
//!
//! **Environment.** The image's `Env`, in order. Each `-e KEY=VALUE`
//! replaces the entry named `KEY` where it stands (and drops any later
//! duplicate, which a program reading the environment last-wins would see
//! instead) or, if there is none, is appended in the order given. Then,
//! only if still missing, the variables Docker adds: `PATH` (runc's and
//! Docker's default), `HOSTNAME`, and with `-t` `TERM=xterm`. conversion.md
//! asks a converter not to add a name the image's `Env` already has, and
//! these are only added when nothing has them. `HOME` isn't set here: the
//! runtime adds it at exec from the container's `/etc/passwd`, as runc
//! does. A bare `-e KEY` is refused: Docker's CLI fills in the value from
//! the shell it runs in, a request to the engine carries no such
//! environment, and quietly setting nothing would hide the mistake. Any
//! entry that isn't `KEY=value` would fail `create`, so it fails here,
//! saying where it came from.
//!
//! **Working directory.** `-w`, else `WorkingDir`, else `/`. The runtime
//! wants an absolute `process.cwd`, so a relative path is taken from `/`
//! (older builders wrote such `WorkingDir`s; Docker refuses a relative `-w`,
//! here it gets the same treatment), and the result is cleaned lexically:
//! `app/./x/..` is `/app`. That is tidiness, not confinement: the runtime
//! `chdir`s after `pivot_root`, as the container user, and then checks that
//! it is still inside.
//!
//! **User.** [`user::resolve`] against the image's own files, read through
//! the mounted rootfs. `process.user` gets the uid, the gid and the
//! supplementary gids, **the primary gid first** (`additionalGids`); `umask`
//! stays unset, so the runtime's 0022 applies. Putting the primary gid in
//! the supplementary list is what a login does (`initgroups(3)`), and what
//! Docker, Podman and containerd do since CVE-2022-36109: a process that
//! runs a setgid program would otherwise leave its primary group behind,
//! and with it whatever a group-deny permission (`rw----r--`: anyone but
//! the group may read) kept from it. The default spec's `noNewPrivileges`
//! already stops `execve` from changing ids; this keeps the list right
//! whatever the spec's NNP setting.
//!
//! **Root.** `root.path` is the mounted overlay, as an absolute path (the
//! runtime would read a relative one against the bundle directory, not the
//! caller's). It is writable unless `--read-only`: the overlay's upper layer
//! is this container's own, and Docker's default is writable too. (The dev
//! bundle's rootfs is read-only because it is shared.)
//!
//! **Annotations.** conversion.md's implicit ones, each when the config has
//! a value: `org.opencontainers.image.os`, `.architecture`, `.variant`,
//! `.os.version`, `.os.features` (comma separated), `.author`, `.created`,
//! `.stopSignal`, and `.exposedPorts` (the `ExposedPorts` keys, sorted,
//! comma separated). Then the config's `Labels`, which conversion.md says
//! MUST take precedence over the implicit values: a label is the image's
//! explicit annotation. Last, two keys that are this engine's alone:
//! [`IMAGE_NAME`] (the name the image was loaded by, if it was) and
//! [`IMAGE_MANIFEST`] (its manifest digest). They record what the engine
//! knows and the image can't vouch for (a config can't contain the digest
//! of the manifest that names it), so a label can neither set nor change
//! them.
//!
//! **Not yet:** `Volumes`, `Healthcheck`, `StopSignal` and `ExposedPorts`
//! are for the daemon to act on (Phases 4 and 5); until then the
//! annotations record the stop signal and the ports.
//!
//! **`--userns=remap`** gives the container a user namespace with
//! [`with_user_namespace`]: container ids 0–65535 are host ids
//! 1000000–1065535 ([`REMAP_HOST_ID`], [`REMAP_SIZE`]), and the runtime
//! refuses a user or group outside that range. The caller sets
//! `linux.cgroupsPath` and `linux.resources`.
//!
//! [`conversion.md`]: https://github.com/opencontainers/image-spec/blob/main/conversion.md

use std::collections::BTreeMap;
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};

use nix::fcntl::OFlag;
use nix::sys::stat::Mode;
use rustlet_runtime::oci_spec::runtime::{Root, Spec, User};
use rustlet_runtime::process::DEFAULT_PATH;
use rustlet_runtime::spec::{REMAP_HOST_ID, REMAP_SIZE, default_spec, with_user_namespace};

use crate::error::{Context, Error, Result};
use crate::image::Image;
use crate::user::{self, ResolvedUser};

/// The annotation recording the name the image was loaded by.
pub const IMAGE_NAME: &str = "io.rustlet.image.name";
/// The annotation recording the image's manifest digest.
pub const IMAGE_MANIFEST: &str = "io.rustlet.image.manifest";

/// The prefix of conversion.md's implicit annotations.
const OCI_IMAGE: &str = "org.opencontainers.image.";

/// `rustlet run`-style choices that override the image config. As with
/// Docker's flags, an empty `user`, `workdir` or `hostname` counts as not
/// given.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunOptions {
    /// Command arguments (`IMAGE ARGS…`), replacing the image's `Cmd`.
    pub args: Vec<String>,
    /// Explicitly discard the image's `Cmd`, including with no arguments
    /// and an inherited entrypoint (Compose's empty `command`).
    pub clear_cmd: bool,
    /// `--entrypoint`; `Some(vec![])` clears the image's.
    pub entrypoint: Option<Vec<String>>,
    /// `-e KEY=VALUE`, in order.
    pub env: Vec<String>,
    /// Names explicitly removed from the inherited image environment.
    /// Values supplied in `env` take precedence over these removals.
    pub unset_env: Vec<String>,
    /// `-u user[:group]`.
    pub user: Option<String>,
    /// `-w DIR`.
    pub workdir: Option<String>,
    /// `-t`.
    pub tty: bool,
    pub hostname: Option<String>,
    /// `--read-only`.
    pub readonly_rootfs: bool,
    /// `--userns=remap`.
    pub userns_remap: bool,
}

/// The spec for running `image` on the mounted rootfs at `rootfs` (an
/// absolute path). Reads the image's passwd/group files through it to
/// resolve the user.
pub fn build(image: &Image, rootfs: &Path, options: &RunOptions) -> Result<Spec> {
    check_rootfs(rootfs)?;
    let root = nix::fcntl::open(rootfs, OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC, Mode::empty())
        .with_context(|| format!("open the rootfs {}", rootfs.display()))?;
    let user_spec = given(&options.user).or_else(|| image.config.config()?.user().as_deref());
    let user = user::resolve(root.as_fd(), user_spec)?;
    build_with_user(image, rootfs, &user, options)
}

/// [`build`] with the user already resolved (no file access; what the unit
/// tests exercise).
pub fn build_with_user(image: &Image, rootfs: &Path, user: &ResolvedUser, options: &RunOptions) -> Result<Spec> {
    check_rootfs(rootfs)?;
    let config = image.config.config();
    let mut spec = default_spec();
    if let Some(hostname) = given(&options.hostname) {
        spec.set_hostname(Some(hostname.into()));
    }
    let hostname = spec.hostname().clone().unwrap_or_default();

    let process = spec.process_mut().get_or_insert_with(Default::default);
    process.set_args(Some(process_args(
        config.and_then(|c| c.entrypoint().as_deref()),
        config.and_then(|c| c.cmd().as_deref()),
        options,
    )?));
    process.set_env(Some(process_env(
        config.and_then(|c| c.env().as_deref()).unwrap_or_default(),
        options,
        &hostname,
    )?));
    let workdir = given(&options.workdir).or_else(|| config?.working_dir().as_deref()).unwrap_or("/");
    process.set_cwd(PathBuf::from(clean_absolute(workdir)));
    process.set_terminal(Some(options.tty));
    let mut process_user = User::default();
    process_user.set_uid(user.uid);
    process_user.set_gid(user.gid);
    let mut gids = vec![user.gid];
    gids.extend(user.additional_gids.iter().copied().filter(|&g| g != user.gid));
    process_user.set_additional_gids(Some(gids));
    process.set_user(process_user);

    let mut root = Root::default();
    root.set_path(rootfs.into());
    root.set_readonly(Some(options.readonly_rootfs));
    spec.set_root(Some(root));
    spec.set_annotations(Some(annotations(image).into_iter().collect()));
    if options.userns_remap {
        with_user_namespace(&mut spec, REMAP_HOST_ID, REMAP_SIZE);
    }
    Ok(spec)
}

/// `process.args` from the image's entrypoint/cmd and the options.
pub fn process_args(
    entrypoint: Option<&[String]>,
    cmd: Option<&[String]>,
    options: &RunOptions,
) -> Result<Vec<String>> {
    let (entrypoint, cmd) = match &options.entrypoint {
        // The image's Cmd goes with the image's entrypoint.
        Some(ours) => (ours.as_slice(), &[][..]),
        None => (entrypoint.unwrap_or_default(), cmd.unwrap_or_default()),
    };
    let command = if !options.args.is_empty() {
        options.args.as_slice()
    } else if options.clear_cmd {
        &[][..]
    } else {
        cmd
    };
    let args: Vec<String> = entrypoint.iter().chain(command).cloned().collect();
    match args.first() {
        Some(program) if !program.is_empty() => Ok(args),
        Some(_) => Err(Error::invalid("no command: the program name (the first of Entrypoint and Cmd) is empty")),
        None if options.entrypoint.is_some() => {
            Err(Error::invalid("no command: the entrypoint was cleared and no arguments were given"))
        }
        None => Err(Error::invalid("no command: the image has no Entrypoint or Cmd, and no arguments were given")),
    }
}

/// `process.env` from the image's `Env` and the options; `hostname` is the
/// container's, for `HOSTNAME`.
pub fn process_env(image_env: &[String], options: &RunOptions, hostname: &str) -> Result<Vec<String>> {
    for name in &options.unset_env {
        if name.is_empty() || name.contains(['=', '\0']) {
            return Err(Error::invalid(format!(
                "unset environment name {name:?}: expected a nonempty name without '=' or NUL"
            )));
        }
    }
    let mut env = Vec::with_capacity(image_env.len() + options.env.len() + 3);
    for entry in image_env {
        if env_name(entry).is_none() {
            return Err(Error::invalid(format!("the image's Env entry {entry:?} is not KEY=value")));
        }
        if !options.unset_env.iter().any(|name| env_name(entry) == Some(name.as_str())) {
            env.push(entry.clone());
        }
    }
    for entry in &options.env {
        let Some(name) = env_name(entry) else {
            return Err(Error::invalid(if entry.contains('=') {
                format!("-e {entry:?}: the variable name is empty")
            } else {
                format!("-e {entry:?}: give a value ({entry}=…); there is no client environment to copy it from")
            }));
        };
        set_env(&mut env, name, entry);
    }
    let missing = |env: &[String], name: &str| !env.iter().any(|e| env_name(e) == Some(name));
    if missing(&env, "PATH") {
        env.push(format!("PATH={DEFAULT_PATH}"));
    }
    if missing(&env, "HOSTNAME") {
        env.push(format!("HOSTNAME={hostname}"));
    }
    if options.tty && missing(&env, "TERM") {
        env.push("TERM=xterm".into());
    }
    Ok(env)
}

/// The name in `NAME=value`, if `entry` is one (the name may not be empty).
fn env_name(entry: &str) -> Option<&str> {
    entry.split_once('=').map(|(name, _)| name).filter(|name| !name.is_empty())
}

/// Puts `entry` in place of the first entry named `name`, dropping any later
/// ones, or appends it if there is none.
fn set_env(env: &mut Vec<String>, name: &str, entry: &str) {
    let mut replaced = false;
    env.retain_mut(|e| {
        if env_name(e) != Some(name) {
            return true;
        }
        if replaced {
            return false;
        }
        *e = entry.to_owned();
        replaced = true;
        true
    });
    if !replaced {
        env.push(entry.to_owned());
    }
}

/// The runtime annotations for `image` (sorted map).
pub fn annotations(image: &Image) -> BTreeMap<String, String> {
    let oci = &image.config.oci;
    let config = image.config.config();
    let exposed_ports = config.and_then(|c| c.exposed_ports().clone()).map(|mut ports| {
        ports.sort();
        ports.join(",")
    });
    let implicit = [
        ("os", Some(oci.os().to_string())),
        ("architecture", Some(oci.architecture().to_string())),
        ("variant", oci.variant().clone()),
        ("os.version", oci.os_version().clone()),
        ("os.features", oci.os_features().as_ref().map(|f| f.join(","))),
        ("author", oci.author().clone()),
        ("created", oci.created().clone()),
        ("stopSignal", config.and_then(|c| c.stop_signal().clone())),
        ("exposedPorts", exposed_ports),
    ];
    let mut out: BTreeMap<String, String> = implicit
        .into_iter()
        .filter_map(|(key, value)| Some((format!("{OCI_IMAGE}{key}"), value.filter(|v| !v.is_empty())?)))
        .collect();
    // Labels win over the implicit values (conversion.md). The runtime spec
    // allows no empty annotation key.
    for (key, value) in config.and_then(|c| c.labels().as_ref()).into_iter().flatten() {
        if !key.is_empty() {
            out.insert(key.clone(), value.clone());
        }
    }
    // Ours win over everything: set by the engine or not at all.
    match &image.name {
        Some(name) => out.insert(IMAGE_NAME.into(), name.clone()),
        None => out.remove(IMAGE_NAME),
    };
    out.insert(IMAGE_MANIFEST.into(), image.manifest_digest.to_string());
    out
}

/// An option that was given: as with Docker's flags, an empty string counts
/// as not given.
fn given(option: &Option<String>) -> Option<&str> {
    option.as_deref().filter(|s| !s.is_empty())
}

fn check_rootfs(rootfs: &Path) -> Result<()> {
    if rootfs.is_absolute() {
        Ok(())
    } else {
        Err(Error::invalid(format!("rootfs {} must be an absolute path", rootfs.display())))
    }
}

/// `path` taken from `/` and cleaned lexically, like Go's `path.Clean("/" +
/// path)`: no empty or `.` components, and `..` removes the component
/// before it (at `/`, there is none to remove).
fn clean_absolute(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            part => parts.push(part),
        }
    }
    format!("/{}", parts.join("/"))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use oci_spec::image::ImageManifest;
    use rustlet_runtime::oci_spec::runtime::LinuxNamespaceType;

    use super::*;
    use crate::config::ImageConfig;
    use crate::digest::Digest;
    use crate::media;

    const ROOTFS: &str = "/var/lib/rustlet/containers/3f9a2c41d7e8/rootfs";

    /// Like `nginx:1.27`: an entrypoint script, a stop signal, a port, no
    /// `User` (the master process starts as root).
    const NGINX: &str = r#"{
        "architecture": "amd64",
        "os": "linux",
        "created": "2025-04-16T20:06:31Z",
        "config": {
            "ExposedPorts": {"80/tcp": {}},
            "Env": [
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "NGINX_VERSION=1.27.5",
                "NJS_VERSION=0.8.10",
                "NJS_RELEASE=1~bookworm",
                "PKG_RELEASE=1~bookworm",
                "DYNPKG_RELEASE=1~bookworm"
            ],
            "Entrypoint": ["/docker-entrypoint.sh"],
            "Cmd": ["nginx", "-g", "daemon off;"],
            "Labels": {"maintainer": "NGINX Docker Maintainers <docker-maint@nginx.com>"},
            "StopSignal": "SIGQUIT"
        },
        "rootfs": {"type": "layers", "diff_ids": [
            "sha256:7fb72a7d1a8e984ccd01277432de660162a547a00de77151518dc9033cfb8cb4",
            "sha256:ee0d4fd5f2a4bb5f1d2d6e3d4ec0e0b58f0ac4ad8b46c95c0d69a3f41a5bfd33"
        ]}
    }"#;

    /// Like `python:3.13-slim`: just a `Cmd`, and a longer `Env`.
    const PYTHON: &str = r#"{
        "architecture": "amd64",
        "os": "linux",
        "created": "2025-04-08T19:45:12Z",
        "config": {
            "Env": [
                "PATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "LANG=C.UTF-8",
                "GPG_KEY=7169605F62C751356D054A26A821E680E5FA6305",
                "PYTHON_VERSION=3.13.3",
                "PYTHON_SHA256=40f868bcbdeb8149a3149580bb9bfd407b3321cd48f0be631af955ac92c0e041"
            ],
            "Cmd": ["python3"]
        },
        "rootfs": {"type": "layers", "diff_ids": [
            "sha256:1287fbecdfcce6ee8cf2436e5b9e9d86a4648db2d91080377d499737f1b307f3"
        ]}
    }"#;

    /// Like `alpine:3.24`.
    const ALPINE: &str = r#"{
        "architecture": "amd64",
        "os": "linux",
        "created": "2026-05-28T17:51:09Z",
        "config": {
            "Env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
            "Cmd": ["/bin/sh"],
            "WorkingDir": "/"
        },
        "rootfs": {"type": "layers", "diff_ids": [
            "sha256:08000c18d16dadf9553d747a58cf44023423a9ab010aab96cf263d2216b8b350"
        ]}
    }"#;

    /// An app from some older builder: a numeric `User`, a relative
    /// `WorkingDir`, no `PATH`, and labels that collide with annotations:
    /// one of conversion.md's, and both of ours.
    const APP: &str = r#"{
        "architecture": "amd64",
        "os": "linux",
        "author": "Example Ops <ops@example.com>",
        "created": "2019-03-01T12:00:00Z",
        "config": {
            "User": "1000:1000",
            "WorkingDir": "app",
            "Env": ["APP_ENV=production", "APP_PORT=8080"],
            "Entrypoint": ["./server"],
            "Cmd": ["--listen", ":8080"],
            "ExposedPorts": {"9090/tcp": {}, "8080/tcp": {}, "8125/udp": {}},
            "Volumes": {"/app/data": {}},
            "StopSignal": "SIGTERM",
            "Labels": {
                "org.opencontainers.image.stopSignal": "SIGINT",
                "org.opencontainers.image.source": "https://git.example.com/app",
                "io.rustlet.image.name": "docker.io/library/trusted:latest",
                "io.rustlet.image.manifest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            }
        },
        "rootfs": {"type": "layers", "diff_ids": [
            "sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef"
        ]}
    }"#;

    /// An image as `Image::load` returns it, made from config JSON. The
    /// layers are left out: nothing here looks at them.
    fn image(name: Option<&str>, config: &str) -> Image {
        let config_digest = Digest::of(config.as_bytes());
        let manifest = format!(
            r#"{{"schemaVersion": 2, "mediaType": "{}",
                "config": {{"mediaType": "{}", "digest": "{config_digest}", "size": {}}},
                "layers": [{{"mediaType": "{}",
                    "digest": "sha256:9824c27679d3b27c5e1cb00a73adb6f4f8d556994111c12db3c5d61a0c843df8",
                    "size": 3642247}}]}}"#,
            media::OCI_MANIFEST,
            media::OCI_CONFIG,
            config.len(),
            media::OCI_LAYER_GZIP,
        );
        Image {
            name: name.map(String::from),
            repo_digest: None,
            manifest_digest: Digest::of(manifest.as_bytes()),
            manifest: serde_json::from_str::<ImageManifest>(&manifest).unwrap(),
            config_digest,
            config: ImageConfig::parse(config.as_bytes()).unwrap(),
            layers: Vec::new(),
        }
    }

    fn strings(s: &[&str]) -> Vec<String> {
        s.iter().map(|s| s.to_string()).collect()
    }

    fn root_user(additional_gids: &[u32]) -> ResolvedUser {
        ResolvedUser {
            uid: 0,
            gid: 0,
            additional_gids: additional_gids.to_vec(),
            name: Some("root".into()),
            home: "/root".into(),
        }
    }

    /// What this module decides, as JSON with a stable key order, for the
    /// snapshots. It first checks that everything else is exactly
    /// [`default_spec`]'s: capabilities, seccomp, masked and read-only
    /// paths, NNP, rlimits, mounts. (The whole spec makes a poor snapshot:
    /// its capability sets serialize in hash order, and the seccomp profile
    /// runs to thousands of lines.)
    fn decided(spec: &Spec) -> serde_json::Value {
        let default = default_spec();
        let mut rest = spec.clone();
        rest.set_hostname(default.hostname().clone());
        rest.set_root(default.root().clone());
        rest.set_annotations(default.annotations().clone());
        let (p, dp) = (rest.process_mut().as_mut().unwrap(), default.process().as_ref().unwrap());
        assert_eq!(p.capabilities(), dp.capabilities());
        p.set_terminal(dp.terminal());
        p.set_user(dp.user().clone());
        p.set_args(dp.args().clone());
        p.set_env(dp.env().clone());
        p.set_cwd(dp.cwd().clone());
        let (l, dl) = (rest.linux_mut().as_mut().unwrap(), default.linux().as_ref().unwrap());
        assert_eq!(l.seccomp(), dl.seccomp());
        assert_eq!(l.masked_paths(), dl.masked_paths());
        l.set_namespaces(dl.namespaces().clone());
        l.set_uid_mappings(dl.uid_mappings().clone());
        l.set_gid_mappings(dl.gid_mappings().clone());
        assert_eq!(rest, default, "the spec differs from default_spec() in a field this module doesn't own");

        let process = spec.process().as_ref().unwrap();
        let linux = spec.linux().as_ref().unwrap();
        serde_json::json!({
            "process": {
                "terminal": process.terminal(),
                "user": process.user(),
                "args": process.args(),
                "env": process.env(),
                "cwd": process.cwd(),
            },
            "hostname": spec.hostname(),
            "root": spec.root(),
            "annotations": spec.annotations().as_ref().map(|a| a.iter().collect::<BTreeMap<_, _>>()),
            "linux": {
                "namespaces": linux.namespaces(),
                "uidMappings": linux.uid_mappings(),
                "gidMappings": linux.gid_mappings(),
            },
        })
    }

    #[test]
    fn nginx() {
        // rustlet run nginx
        let image = image(Some("docker.io/library/nginx:latest"), NGINX);
        let spec = build_with_user(&image, Path::new(ROOTFS), &root_user(&[]), &RunOptions::default()).unwrap();
        insta::assert_json_snapshot!("nginx", decided(&spec));
    }

    #[test]
    fn python_interactive() {
        // rustlet run -t --hostname py -e LANG=en_US.UTF-8 -e PYTHONDONTWRITEBYTECODE=1 python:3.13-slim python3 -q
        let options = RunOptions {
            args: strings(&["python3", "-q"]),
            env: strings(&["LANG=en_US.UTF-8", "PYTHONDONTWRITEBYTECODE=1"]),
            tty: true,
            hostname: Some("py".into()),
            ..RunOptions::default()
        };
        let image = image(Some("docker.io/library/python:3.13-slim"), PYTHON);
        let spec = build_with_user(&image, Path::new(ROOTFS), &root_user(&[]), &options).unwrap();
        insta::assert_json_snapshot!("python_interactive", decided(&spec));
    }

    #[test]
    fn alpine_remapped_and_read_only() {
        // rustlet run --userns=remap --read-only alpine:3.24, root in its
        // usual groups (see `user`).
        let options = RunOptions { userns_remap: true, readonly_rootfs: true, ..RunOptions::default() };
        let image = image(Some("docker.io/library/alpine:3.24"), ALPINE);
        let root = root_user(&[0, 1, 2, 3, 4, 6, 10, 11, 20, 26, 27]);
        let spec = build_with_user(&image, Path::new(ROOTFS), &root, &options).unwrap();
        insta::assert_json_snapshot!("alpine_remapped_and_read_only", decided(&spec));
    }

    #[test]
    fn app_loaded_by_digest() {
        // rustlet run sha256:…, as 1000:1000, which the image has no entries for.
        let user = ResolvedUser { uid: 1000, gid: 1000, additional_gids: vec![], name: None, home: "/".into() };
        let spec = build_with_user(&image(None, APP), Path::new(ROOTFS), &user, &RunOptions::default()).unwrap();
        insta::assert_json_snapshot!("app_loaded_by_digest", decided(&spec));
    }

    #[test]
    fn args_follow_docker() {
        let ep = strings(&["/docker-entrypoint.sh"]);
        let cmd = strings(&["nginx", "-g", "daemon off;"]);
        let run = |args: &[&str], entrypoint: Option<&[&str]>| RunOptions {
            args: strings(args),
            entrypoint: entrypoint.map(strings),
            ..RunOptions::default()
        };
        let args = |options: &RunOptions| process_args(Some(&ep), Some(&cmd), options);
        assert_eq!(args(&run(&[], None)).unwrap(), ["/docker-entrypoint.sh", "nginx", "-g", "daemon off;"]);
        assert_eq!(args(&run(&["nginx", "-T"], None)).unwrap(), ["/docker-entrypoint.sh", "nginx", "-T"]);
        // --entrypoint drops the image's Cmd.
        assert_eq!(args(&run(&[], Some(&["/bin/sh"]))).unwrap(), ["/bin/sh"]);
        assert_eq!(args(&run(&["-c", "nginx -T"], Some(&["/bin/sh"]))).unwrap(), ["/bin/sh", "-c", "nginx -T"]);
        // --entrypoint '' leaves the arguments alone…
        assert_eq!(args(&run(&["nginx", "-T"], Some(&[]))).unwrap(), ["nginx", "-T"]);
        // …and without any, nothing to run.
        assert!(matches!(args(&run(&[], Some(&[]))), Err(Error::Invalid(m)) if m.contains("entrypoint was cleared")));

        let python = strings(&["python3"]);
        assert_eq!(process_args(None, Some(&python), &run(&[], None)).unwrap(), ["python3"]);
        assert_eq!(process_args(None, Some(&python), &run(&["python3", "-q"], None)).unwrap(), ["python3", "-q"]);
        assert_eq!(process_args(Some(&ep), None, &run(&[], None)).unwrap(), ["/docker-entrypoint.sh"]);
        assert_eq!(process_args(None, None, &run(&["/bin/true"], None)).unwrap(), ["/bin/true"]);
        for (entrypoint, cmd) in [(None, None), (Some(&[][..]), Some(&[][..]))] {
            let err = process_args(entrypoint, cmd, &run(&[], None));
            assert!(matches!(err, Err(Error::Invalid(m)) if m.contains("no Entrypoint or Cmd")));
        }
        let empty = strings(&[""]);
        assert!(
            matches!(process_args(Some(&empty), Some(&cmd), &run(&[], None)), Err(Error::Invalid(m)) if m.contains("empty"))
        );
    }

    #[test]
    fn an_explicit_empty_command_keeps_only_the_entrypoint() {
        let ep = strings(&["/entrypoint"]);
        let cmd = strings(&["default", "argument"]);
        let clear = RunOptions { clear_cmd: true, ..RunOptions::default() };
        assert_eq!(process_args(Some(&ep), Some(&cmd), &clear).unwrap(), ep);
        assert!(process_args(None, Some(&cmd), &clear).is_err());
        let explicit = RunOptions { args: strings(&["replacement"]), ..clear };
        assert_eq!(process_args(Some(&ep), Some(&cmd), &explicit).unwrap(), ["/entrypoint", "replacement"]);
    }

    #[test]
    fn environment_removals_apply_before_explicit_values() {
        let inherited = strings(&["A=first", "A=last", "B=base", "C=keep"]);
        let options =
            RunOptions { unset_env: strings(&["A", "B"]), env: strings(&["B=override"]), ..RunOptions::default() };
        let env = process_env(&inherited, &options, "box").unwrap();
        assert!(!env.iter().any(|e| e.starts_with("A=")));
        assert!(env.contains(&"B=override".to_owned()));
        assert!(env.contains(&"C=keep".to_owned()));
        for name in ["", "A=B", "A\0B"] {
            let invalid = RunOptions { unset_env: vec![name.to_owned()], ..RunOptions::default() };
            assert!(matches!(process_env(&[], &invalid, "box"), Err(Error::Invalid(_))), "{name:?}");
        }
    }

    #[test]
    fn env_merges_in_place_then_adds_defaults() {
        let image_env = strings(&["PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C.UTF-8", "PYTHON_VERSION=3.13.3"]);
        let env = |image_env: &[String], options: &RunOptions| process_env(image_env, options, "box").unwrap();
        assert_eq!(
            env(&image_env, &RunOptions::default()),
            ["PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C.UTF-8", "PYTHON_VERSION=3.13.3", "HOSTNAME=box"]
        );
        // Overrides in place, new names in option order (the last of two
        // wins), then the defaults.
        let options = RunOptions {
            env: strings(&["DEBUG=1", "LANG=en_US.UTF-8", "EMPTY=", "DEBUG=2"]),
            tty: true,
            ..RunOptions::default()
        };
        assert_eq!(
            env(&image_env, &options),
            [
                "PATH=/usr/local/bin:/usr/bin:/bin",
                "LANG=en_US.UTF-8",
                "PYTHON_VERSION=3.13.3",
                "DEBUG=2",
                "EMPTY=",
                "HOSTNAME=box",
                "TERM=xterm"
            ]
        );
        // A default never replaces what the image or -e set.
        let path = format!("PATH={DEFAULT_PATH}");
        let options = RunOptions { env: strings(&["TERM=dumb", "HOSTNAME=mine"]), tty: true, ..RunOptions::default() };
        assert_eq!(env(&strings(&["A=1"]), &options), ["A=1", "TERM=dumb", "HOSTNAME=mine", path.as_str()]);
        assert_eq!(
            env(&strings(&["PATH="]), &RunOptions::default()),
            ["PATH=", "HOSTNAME=box"],
            "an empty PATH is set"
        );
        assert_eq!(env(&strings(&["PATHS=x"]), &RunOptions::default()), ["PATHS=x", path.as_str(), "HOSTNAME=box"]);
        // An override also replaces the image's duplicates.
        let options = RunOptions { env: strings(&["X=9"]), ..RunOptions::default() };
        assert_eq!(env(&strings(&["X=1", "Y=2", "X=3"]), &options), ["X=9", "Y=2", path.as_str(), "HOSTNAME=box"]);
    }

    #[test]
    fn env_refuses_what_it_cannot_honour() {
        let with = |env: &[&str]| process_env(&[], &RunOptions { env: strings(env), ..RunOptions::default() }, "h");
        assert!(
            matches!(with(&["HOME"]), Err(Error::Invalid(m)) if m.contains("\"HOME\"") && m.contains("client environment"))
        );
        assert!(matches!(with(&["=x"]), Err(Error::Invalid(m)) if m.contains("name is empty")));
        let bad_image = process_env(&strings(&["JUSTANAME"]), &RunOptions::default(), "h");
        assert!(matches!(bad_image, Err(Error::Invalid(m)) if m.contains("image's Env") && m.contains("JUSTANAME")));
    }

    #[test]
    fn workdir_is_absolute_and_clean() {
        for (path, clean) in [
            ("/", "/"),
            ("", "/"),
            ("app", "/app"),
            ("/usr//src/./app/", "/usr/src/app"),
            ("/a/b/../c", "/a/c"),
            ("../../etc", "/etc"),
            ("/..", "/"),
        ] {
            assert_eq!(clean_absolute(path), clean, "{path:?}");
        }
        let cwd = |config: &str, workdir: Option<&str>| {
            let options = RunOptions { workdir: workdir.map(String::from), ..RunOptions::default() };
            let spec = build_with_user(&image(None, config), Path::new(ROOTFS), &root_user(&[]), &options).unwrap();
            spec.process().as_ref().unwrap().cwd().clone()
        };
        assert_eq!(cwd(NGINX, None), Path::new("/"));
        assert_eq!(cwd(APP, None), Path::new("/app"));
        assert_eq!(cwd(APP, Some("/srv")), Path::new("/srv"));
        assert_eq!(cwd(APP, Some("data/../logs")), Path::new("/logs"));
        assert_eq!(cwd(APP, Some("")), Path::new("/app"), "an empty -w is no -w");
    }

    #[test]
    fn labels_win_over_implicit_annotations_but_not_over_ours() {
        let by_digest = image(None, APP);
        let a = annotations(&by_digest);
        assert_eq!(a["org.opencontainers.image.stopSignal"], "SIGINT", "the label, not StopSignal");
        assert_eq!(a["org.opencontainers.image.source"], "https://git.example.com/app");
        assert_eq!(a["org.opencontainers.image.exposedPorts"], "8080/tcp,8125/udp,9090/tcp");
        assert_eq!(a[IMAGE_MANIFEST], by_digest.manifest_digest.to_string());
        assert!(!a.contains_key(IMAGE_NAME), "a label can't name an image loaded by digest");
        let by_name = image(Some("registry.example.com/app:2.1"), APP);
        assert_eq!(annotations(&by_name)[IMAGE_NAME], "registry.example.com/app:2.1");
    }

    #[test]
    fn annotations_only_for_what_the_config_has() {
        let bare = image(
            Some("docker.io/library/scratchy:latest"),
            r#"{"architecture": "amd64", "os": "linux", "author": "",
                "rootfs": {"type": "layers", "diff_ids": []}}"#,
        );
        assert_eq!(
            annotations(&bare).into_iter().collect::<Vec<_>>(),
            [
                (IMAGE_MANIFEST.to_string(), bare.manifest_digest.to_string()),
                (IMAGE_NAME.into(), "docker.io/library/scratchy:latest".into()),
                ("org.opencontainers.image.architecture".into(), "amd64".into()),
                ("org.opencontainers.image.os".into(), "linux".into()),
            ]
        );
        // The platform fields Windows images use, and an ARM variant.
        let windows = image(
            None,
            r#"{"architecture": "amd64", "os": "windows", "os.version": "10.0.20348.2340", "os.features": ["win32k"],
                "rootfs": {"type": "layers", "diff_ids": []}}"#,
        );
        let a = annotations(&windows);
        assert_eq!(a["org.opencontainers.image.os.version"], "10.0.20348.2340");
        assert_eq!(a["org.opencontainers.image.os.features"], "win32k");
        let arm = image(
            None,
            r#"{"architecture": "arm64", "variant": "v8", "os": "linux",
                "rootfs": {"type": "layers", "diff_ids": []}}"#,
        );
        assert_eq!(annotations(&arm)["org.opencontainers.image.variant"], "v8");
    }

    #[test]
    fn empty_options_count_as_not_given() {
        let options = RunOptions { hostname: Some(String::new()), ..RunOptions::default() };
        let spec = build_with_user(&image(None, ALPINE), Path::new(ROOTFS), &root_user(&[]), &options).unwrap();
        assert_eq!(spec.hostname(), default_spec().hostname());
        assert!(spec.process().as_ref().unwrap().env().as_ref().unwrap().contains(&"HOSTNAME=rustlet".to_string()));
    }

    #[test]
    fn rootfs_must_be_absolute() {
        let image = image(None, ALPINE);
        let relative = Path::new("containers/x/rootfs");
        for result in [
            build_with_user(&image, relative, &root_user(&[]), &RunOptions::default()),
            build(&image, relative, &RunOptions::default()),
        ] {
            assert!(matches!(result, Err(Error::Invalid(m)) if m.contains("absolute")));
        }
    }

    #[test]
    fn build_resolves_the_user_in_the_rootfs() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("etc")).unwrap();
        fs::write(
            dir.path().join("etc/passwd"),
            "root:x:0:0:root:/root:/bin/sh\nweb:x:101:101::/var/www:/sbin/nologin\n",
        )
        .unwrap();
        fs::write(dir.path().join("etc/group"), "root:x:0:\nadm:x:4:web\nweb:x:101:\n").unwrap();
        let config = ALPINE.replace(r#""WorkingDir": "/""#, r#""WorkingDir": "/", "User": "web""#);
        let image = image(None, &config);
        let user_for = |options: &RunOptions| {
            let spec = build(&image, dir.path(), options).unwrap();
            spec.process().as_ref().unwrap().user().clone()
        };
        let web = user_for(&RunOptions::default());
        assert_eq!((web.uid(), web.gid(), web.additional_gids().clone()), (101, 101, Some(vec![101, 4])));
        let empty = RunOptions { user: Some(String::new()), ..RunOptions::default() };
        assert_eq!(user_for(&empty), web, "an empty -u is no -u");
        let root = user_for(&RunOptions { user: Some("root".into()), ..RunOptions::default() });
        assert_eq!((root.uid(), root.gid(), root.additional_gids().clone()), (0, 0, Some(vec![0])));
        let ghost = build(&image, dir.path(), &RunOptions { user: Some("ghost".into()), ..RunOptions::default() });
        assert!(matches!(ghost, Err(Error::Invalid(m)) if m.contains("\"ghost\"")));
        // And the namespaces of a remapped run include a user namespace.
        let remapped = build(&image, dir.path(), &RunOptions { userns_remap: true, ..RunOptions::default() }).unwrap();
        let namespaces = remapped.linux().as_ref().unwrap().namespaces().clone().unwrap();
        assert!(namespaces.iter().any(|n| n.typ() == LinuxNamespaceType::User));
    }
}

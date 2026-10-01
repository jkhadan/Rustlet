//! From an image to a runtime spec: the `config.json` that `rustlet-runc`
//! runs.
//!
//! CONTRACT (to be implemented; delete this paragraph when done). Follows
//! OCI image-spec `conversion.md` and Docker's behaviour, starting from
//! `rustlet_runtime::spec::default_spec()` (capabilities, seccomp, masked
//! paths, NNP and mounts stay as the runtime's defaults):
//!
//! * `process.args` = entrypoint + command, where entrypoint is
//!   `options.entrypoint` if set (an empty vector clears it) else the
//!   image's `Entrypoint`, and command is `options.args` if non-empty, else
//!   the image's `Cmd`, **except** that overriding the entrypoint drops the
//!   image's `Cmd` (Docker). Empty result → `Error::Invalid("no command…")`.
//! * `process.env`: the image's `Env`, then each `options.env` entry
//!   replacing the same key. A bare `KEY` (no `=`) in `options.env` is
//!   refused as invalid: Docker would copy it from the *client's*
//!   environment, and there is no client environment here. `PATH` =
//!   `rustlet_runtime::process::DEFAULT_PATH` if the result has none;
//!   `HOSTNAME=<hostname>` unless set; `TERM=xterm` with a terminal unless
//!   set. Order: image entries in order (overrides in place), then new ones
//!   in option order, then the added defaults.
//! * `process.cwd`: `options.workdir`, else `WorkingDir`, else `/`; a
//!   relative path is joined to `/` (old images have them); then
//!   lexically cleaned. `process.terminal` = `options.tty`.
//! * `process.user`: [`crate::user::resolve`] of `options.user` else `User`,
//!   read through the mounted rootfs: uid, gid, additionalGids (omitted when
//!   empty). `umask` stays unset (runtime default 0022).
//! * `hostname`: `options.hostname`, else unchanged from the default.
//! * `root.path` = `rootfs` (absolute), `root.readonly` =
//!   `options.readonly_rootfs` (Docker's default is a writable rootfs; the
//!   writable layer is the container's own).
//! * `annotations` (conversion.md): `org.opencontainers.image.os`,
//!   `.architecture`, `.variant`, `.os.version`, `.os.features` (comma
//!   joined), `.author`, `.created`, `.stopSignal`, `.exposedPorts` (sorted,
//!   comma joined), from the config when present; the config's `Labels` too,
//!   except a label never overrides one of those keys. Plus
//!   `io.rustlet.image.name` (if loaded by name) and
//!   `io.rustlet.image.manifest` (the manifest digest).
//! * `Volumes`, `Healthcheck` and `ExposedPorts` are not acted on until
//!   Phases 4–5 (the annotation records the ports).
//! * `options.userns_remap`: `rustlet_runtime::spec::with_user_namespace`
//!   with `REMAP_HOST_ID`/`REMAP_SIZE`. The caller sets `linux.cgroupsPath`
//!   and resources.

use std::collections::BTreeMap;
use std::path::Path;

use rustlet_runtime::oci_spec::runtime::Spec;

use crate::error::Result;
use crate::image::Image;
use crate::user::ResolvedUser;

/// `rustlet run`-style choices that override the image config.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunOptions {
    /// Command arguments (`IMAGE ARGS…`), replacing the image's `Cmd`.
    pub args: Vec<String>,
    /// `--entrypoint`; `Some(vec![])` clears the image's.
    pub entrypoint: Option<Vec<String>>,
    /// `-e KEY=VALUE`, in order.
    pub env: Vec<String>,
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

/// The spec for running `image` on the mounted rootfs at `rootfs`. Reads
/// the image's passwd/group files to resolve the user.
pub fn build(image: &Image, rootfs: &Path, options: &RunOptions) -> Result<Spec> {
    let _ = (image, rootfs, options);
    unimplemented!("runspec::build")
}

/// [`build`] with the user already resolved (no file access; what the unit
/// tests exercise).
pub fn build_with_user(image: &Image, rootfs: &Path, user: &ResolvedUser, options: &RunOptions) -> Result<Spec> {
    let _ = (image, rootfs, user, options);
    unimplemented!("runspec::build_with_user")
}

/// `process.args` from the image's entrypoint/cmd and the options.
pub fn process_args(
    entrypoint: Option<&[String]>,
    cmd: Option<&[String]>,
    options: &RunOptions,
) -> Result<Vec<String>> {
    let _ = (entrypoint, cmd, options);
    unimplemented!("runspec::process_args")
}

/// `process.env` from the image's `Env` and the options.
pub fn process_env(image_env: &[String], options: &RunOptions, hostname: &str) -> Result<Vec<String>> {
    let _ = (image_env, options, hostname);
    unimplemented!("runspec::process_env")
}

/// The runtime annotations for `image` (sorted map).
pub fn annotations(image: &Image) -> BTreeMap<String, String> {
    let _ = image;
    unimplemented!("runspec::annotations")
}

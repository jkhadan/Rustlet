//! The last steps before `execve`, shared by container init and `exec`:
//! process attributes, identity, seccomp.
//!
//! Order matters, because each step can take away what a later one needs:
//!
//! 1. rlimits and `oom_score_adj` first: *raising* a hard limit or lowering
//!    the OOM score needs `CAP_SYS_RESOURCE`, which is gone once the
//!    capabilities are dropped.
//! 2. [`switch_identity`]:
//!    1. seccomp, if `noNewPrivileges` is false: without no_new_privs,
//!       loading a filter needs `CAP_SYS_ADMIN`, so it must happen while we
//!       still have it (and the filter then also applies to the steps below);
//!    2. drop the bounding set (needs `CAP_SETPCAP`);
//!    3. `PR_SET_KEEPCAPS`, then `setgroups` → `setresgid` → `setresuid`
//!       (groups first: both group calls need `CAP_SETGID`);
//!    4. `capset` and the ambient set (`caps::CapsPlan::apply`).
//! 3. `chdir(cwd)` *as the container user*, then prove the new working
//!    directory is inside the container (CVE-2024-21626).
//! 4. [`exec`]: `PR_SET_NO_NEW_PRIVS`, umask, seccomp if no_new_privs is set
//!    (as late as possible, so the filter only has to allow `execve`), and
//!    finally `execve`.

use std::ffi::CString;
use std::path::{Path, PathBuf};

use nix::sys::stat::Mode;
use nix::unistd::{AccessFlags, Gid, Uid};
use rustlet_sys::Errno;
use rustlet_sys::keyring;

use crate::error::{Context, Error, Result};
use crate::plan::ProcessPlan;
use crate::proc_handle::ProcHandle;
use crate::seccomp::Filter;

/// `$PATH` used when the container's environment doesn't set one (the same
/// default runc and Docker use).
pub const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// Joins a new session keyring named `_ses.<id>` (see `rustlet_sys::keyring`
/// for why). `exec` calls this too and, finding the container's keyring by
/// name, joins that one: that's why the owner may *search* it (runc does the
/// same).
pub(crate) fn join_session_keyring(id: &str) -> Result<()> {
    match keyring::join_session_keyring(&format!("_ses.{id}")) {
        Ok(key) => {
            let perm = keyring::perm(key).context("describe the session keyring")?;
            keyring::set_perm(key, perm | keyring::KEY_USR_SEARCH).context("set the session keyring's permissions")
        }
        // A kernel without keyrings: nothing to isolate.
        Err(Errno::ENOSYS) => Ok(()),
        Err(e) => Err(e).context("join a new session keyring"),
    }
}

/// Step 1. `oom_score_adj` goes through our private procfs handle, not
/// whatever is mounted at `/proc`.
pub(crate) fn set_limits(p: &ProcessPlan, proc: &ProcHandle) -> Result<()> {
    for r in &p.rlimits {
        nix::sys::resource::setrlimit(r.resource, r.soft, r.hard)
            .with_context(|| format!("setrlimit {:?}", r.resource))?;
    }
    if let Some(adj) = p.oom_score_adj {
        proc.write(Path::new("self/oom_score_adj"), &adj.to_string())?;
    }
    Ok(())
}

/// Step 2: from root with every capability to the container's user with
/// the container's capabilities (and, without no_new_privs, the seccomp
/// filter already in place).
pub(crate) fn switch_identity(p: &ProcessPlan, seccomp: Option<&Filter>) -> Result<()> {
    if let Some(filter) = seccomp
        && !p.no_new_privileges
    {
        filter.load()?;
    }
    p.caps.drop_bounding()?;
    // Keep the permitted set across the uid switch; `apply` turns it off
    // again. (For uid 0 it makes no difference.)
    rustlet_sys::prctl::set_keepcaps(true).context("PR_SET_KEEPCAPS")?;
    switch_user(p)?;
    p.caps.apply()
}

/// Step 2.3.
fn switch_user(p: &ProcessPlan) -> Result<()> {
    if p.terminal && p.uid != 0 {
        // Our PTY slave belongs to root. Give it to the container user (as
        // runc does), or a non-root process couldn't reopen its own
        // terminal by path (`sudo`, `ssh`, `script` all do that). Only for
        // our own PTY: inherited stdio could be the *host's* terminal.
        // fds 0-2 are all the same slave, so one fchown covers them.
        let stdin = std::io::stdin();
        nix::unistd::fchown(std::os::fd::AsFd::as_fd(&stdin), Some(Uid::from_raw(p.uid)), None)
            .context("fchown the terminal to the container user")?;
    }
    // Always call setgroups, even for root: otherwise the container would
    // inherit rustlet-runc's supplementary groups.
    let groups: Vec<Gid> = p.additional_gids.iter().copied().map(Gid::from_raw).collect();
    nix::unistd::setgroups(&groups).context("setgroups")?;
    let gid = Gid::from_raw(p.gid);
    nix::unistd::setresgid(gid, gid, gid).with_context(|| format!("setresgid {gid}"))?;
    let uid = Uid::from_raw(p.uid);
    nix::unistd::setresuid(uid, uid, uid).with_context(|| format!("setresuid {uid}"))?;
    Ok(())
}

/// Step 3. `chdir` into `cwd`, then check that the result is reachable from
/// our root. If a directory fd from the host had leaked into the container
/// (the runc bug behind CVE-2024-21626), a cwd could sit *outside* the
/// root; the kernel then reports it as "(unreachable)/…", which glibc's
/// `getcwd` turns into `ENOENT`.
pub(crate) fn enter_cwd(p: &ProcessPlan) -> Result<()> {
    nix::unistd::chdir(&p.cwd).with_context(|| format!("chdir {}", p.cwd.display()))?;
    match nix::unistd::getcwd() {
        Ok(cwd) if cwd.is_absolute() => Ok(()),
        Ok(cwd) => Err(Error::Init { message: format!("cwd {} is outside the container", cwd.display()), errno: None }),
        Err(e) => Err(e).context("working directory is not inside the container root"),
    }
}

/// The program to run, resolved and converted to C strings *before* init
/// reports `Ready`, so that "executable not found" fails `create` (as with
/// runc) instead of surfacing only after `start`.
#[derive(Debug)]
pub(crate) struct Prepared {
    path: CString,
    shown: PathBuf,
    args: Vec<CString>,
    env: Vec<CString>,
}

/// Step 4a: `$PATH` lookup, as the container user, in the container's root.
pub(crate) fn prepare_exec(p: &ProcessPlan) -> Result<Prepared> {
    let path_var = p.env.iter().find_map(|e| e.strip_prefix("PATH=")).unwrap_or(DEFAULT_PATH);
    if p.args[0].contains('/') {
        // Explicit paths skip the $PATH search, but not the check: like
        // runc, fail `create` for a program that's missing (127) or can't be
        // executed (126), instead of only after `start`.
        let path = Path::new(&p.args[0]);
        if std::fs::symlink_metadata(path).is_err() && std::fs::metadata(path).is_err() {
            return Err(Error::Exec { message: format!("{}: no such file", p.args[0]), errno: Errno::ENOENT });
        }
        if !is_executable(path) {
            return Err(Error::Exec {
                message: format!("{}: not an executable file", p.args[0]),
                errno: Errno::EACCES,
            });
        }
    }
    let Some(program) = find_program(&p.args[0], path_var, is_executable) else {
        return Err(Error::Exec {
            message: format!("executable file not found in $PATH: {:?} (PATH={path_var})", p.args[0]),
            errno: Errno::ENOENT,
        });
    };
    let mut env = p.env.clone();
    if !env.iter().any(|e| e.starts_with("HOME=")) {
        // runc does the same: most programs expect a HOME.
        env.push(format!("HOME={}", home_dir(p.uid)));
    }
    let to_c = |v: &[String]| v.iter().map(|s| CString::new(s.as_bytes())).collect::<Result<Vec<_>, _>>();
    let (Ok(args), Ok(env), Ok(path)) =
        (to_c(&p.args), to_c(&env), CString::new(program.as_os_str().as_encoded_bytes()))
    else {
        return Err(Error::invalid("process.args/env contain a NUL byte"));
    };
    Ok(Prepared { path, shown: program, args, env })
}

/// Step 4b: `PR_SET_NO_NEW_PRIVS` if asked, the final umask, the seccomp
/// filter if it wasn't loaded in step 2, then `execve`. Only returns on
/// failure.
pub(crate) fn exec(p: &ProcessPlan, prepared: &Prepared, seccomp: Option<&Filter>) -> Error {
    if p.no_new_privileges {
        if let Err(e) = rustlet_sys::prctl::set_no_new_privs() {
            return Error::Sys { context: "PR_SET_NO_NEW_PRIVS".into(), errno: e };
        }
        nix::sys::stat::umask(Mode::from_bits_truncate(p.umask));
        // The very last thing before execve: from here on, only execve
        // itself has to get past the filter.
        if let Some(filter) = seccomp
            && let Err(e) = filter.load()
        {
            return e;
        }
    } else {
        nix::sys::stat::umask(Mode::from_bits_truncate(p.umask));
    }
    let errno = rustlet_sys::process::execve(&prepared.path, &prepared.args, &prepared.env);
    Error::Exec { message: format!("execve {}: {errno}", prepared.shown.display()), errno }
}

/// The home directory of `uid` from the container's `/etc/passwd`, or `/`.
///
/// The file belongs to the image, so it is read defensively: only if it is a
/// regular file (not, say, a symlink to `/dev/zero`), and at most 1 MiB.
fn home_dir(uid: u32) -> String {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let mut text = String::new();
    // O_NONBLOCK: if the image made it a FIFO, the open must not wait for a
    // writer (the regular-file check then turns it down).
    let readable = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY)
        .open("/etc/passwd")
        .ok()
        .filter(|f| f.metadata().is_ok_and(|m| m.is_file()))
        .is_some_and(|f| f.take(1 << 20).read_to_string(&mut text).is_ok());
    if readable { passwd_home(&text, uid) } else { None }.unwrap_or_else(|| "/".into())
}

/// `name:x:uid:gid:gecos:home:shell` → the `home` of the first line with `uid`.
fn passwd_home(passwd: &str, uid: u32) -> Option<String> {
    passwd.lines().find_map(|line| {
        let f: Vec<&str> = line.split(':').collect();
        (f.len() >= 7 && f[2].parse() == Ok(uid) && !f[5].is_empty()).then(|| f[5].to_owned())
    })
}

/// Is `path` a file we may execute? (`access(X_OK)` alone also says yes for
/// directories.)
fn is_executable(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|m| m.is_file()) && nix::unistd::access(path, AccessFlags::X_OK).is_ok()
}

/// `execvp`-style lookup: names containing `/` are used as they are; bare
/// names are searched in each `$PATH` entry in order (an empty entry means
/// the current directory, as POSIX says).
pub fn find_program(name: &str, path_var: &str, is_exec: impl Fn(&Path) -> bool) -> Option<PathBuf> {
    if name.contains('/') {
        return Some(PathBuf::from(name));
    }
    path_var
        .split(':')
        .map(|dir| if dir.is_empty() { Path::new(".") } else { Path::new(dir) }.join(name))
        .find(|candidate| is_exec(candidate))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn home_from_passwd() {
        let passwd = "root:x:0:0:root:/root:/bin/sh\nbroken line\nweb:x:1000:1000::/srv/web:/bin/false\n";
        assert_eq!(passwd_home(passwd, 0).as_deref(), Some("/root"));
        assert_eq!(passwd_home(passwd, 1000).as_deref(), Some("/srv/web"));
        assert_eq!(passwd_home(passwd, 5), None);
    }

    #[test]
    fn path_lookup_order_and_slashes() {
        let exists = |p: &Path| p == Path::new("/usr/bin/sh") || p == Path::new("/bin/sh");
        assert_eq!(find_program("sh", "/usr/local/bin:/usr/bin:/bin", exists), Some("/usr/bin/sh".into()));
        assert_eq!(find_program("./tool", "", exists), Some("./tool".into()));
        assert_eq!(find_program("/bin/sh", "", |_| false), Some("/bin/sh".into()));
        assert_eq!(find_program("missing", DEFAULT_PATH, exists), None);
        assert_eq!(find_program("sh", ":/x", |p| p == Path::new("./sh")), Some("./sh".into()));
    }
}

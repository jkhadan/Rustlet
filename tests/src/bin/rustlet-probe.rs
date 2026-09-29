//! `rustlet-probe`: makes the syscalls that busybox can't, for the seccomp
//! tests in `tests/tests/hardening.rs`, the user-namespace tests and the
//! device-filter tests.
//!
//! Each argument names one probe. For each one it prints a line
//! `<probe> ok` or `<probe> <ERRNO>`, e.g. `clone3 ENOSYS`; the
//! `session-keyring` probe prints the keyring's serial number and
//! description instead of `ok` (`<serial> keyring;<uid>;<gid>;<perm>;<name>`).
//!
//! Two probes take arguments, for the device filter:
//! * `access:PATH:f|r|w|rw`: `access(2)` with `F_OK`, `R_OK`, `W_OK` or both.
//!   On a device node that runs the device-cgroup check without opening
//!   anything (`F_OK` asks for no access bits at all).
//! * `mknod:PATH:b|c:MAJOR:MINOR`: `mknod(2)` of a node, mode 0600.
//!
//! This is a glibc binary and the test rootfs is Alpine (musl), so the tests
//! bind-mount it together with the host's library directory and start it
//! through the host's dynamic loader.
#![forbid(unsafe_code)]

use nix::errno::Errno;
use nix::sys::personality::{self, Persona};
use nix::sys::socket::{AddressFamily, SockFlag, SockType, socket};
use nix::sys::stat::{Mode, SFlag, makedev, mknod};
use nix::unistd::{AccessFlags, access};
use rustlet_sys::process::{Clone3, CloneFlags, Forked, WaitTarget, exit_now, fork, unshare, waitid};

/// A child that exits at once; waits for it.
fn reap(forked: rustlet_sys::Result<Forked>) -> Result<(), Errno> {
    match forked? {
        Forked::Child => exit_now(0),
        Forked::Parent { pid, .. } => waitid(WaitTarget::Pid(pid), false).map(drop),
    }
}

fn open_socket(family: AddressFamily, ty: SockType) -> Result<(), Errno> {
    socket(family, ty, SockFlag::SOCK_CLOEXEC, None).map(drop)
}

fn probe(name: &str) -> Option<Result<(), Errno>> {
    Some(match name {
        // The raw syscall. Docker's profile answers ENOSYS without
        // CAP_SYS_ADMIN, so that libcs fall back to clone(2).
        "clone3" => reap(Clone3::new().spawn()),
        "clone3-newuser" => reap(Clone3::new().flags(CloneFlags::NEWUSER).spawn()),
        // glibc's fork(): clone(2) without namespace flags.
        "fork" => reap(fork()),
        // std's spawn: glibc's posix_spawn tries clone3 first and only falls
        // back to clone(CLONE_VM|CLONE_VFORK) on ENOSYS, not on EPERM.
        "spawn" => match std::process::Command::new("/bin/true").status() {
            Ok(s) if s.success() => Ok(()),
            Ok(_) => Err(Errno::ECHILD),
            Err(e) => Err(Errno::from_raw(e.raw_os_error().unwrap_or(0))),
        },
        "unshare-user" => unshare(CloneFlags::NEWUSER),
        "unshare-net" => unshare(CloneFlags::NEWNET),
        "vsock" => open_socket(AddressFamily::Vsock, SockType::Stream),
        "alg" => open_socket(AddressFamily::Alg, SockType::SeqPacket),
        // personality(2) is allowed for a handful of exact argument values
        // only: 0xffffffff (query), PER_LINUX (0), PER_LINUX32 (8), …
        "personality-query" => personality::get().map(drop),
        "personality-linux" => personality::set(Persona::empty()).map(drop),
        "personality-no-randomize" => personality::set(Persona::ADDR_NO_RANDOMIZE).map(drop),
        "unix" => open_socket(AddressFamily::Unix, SockType::Stream),
        "inet" => open_socket(AddressFamily::Inet, SockType::Stream),
        _ => return device_probe(name),
    })
}

/// `access:PATH:MODE` and `mknod:PATH:TYPE:MAJOR:MINOR`.
fn device_probe(name: &str) -> Option<Result<(), Errno>> {
    if let Some(rest) = name.strip_prefix("access:") {
        let (path, mode) = rest.rsplit_once(':')?;
        let mode = match mode {
            "f" => AccessFlags::F_OK,
            "r" => AccessFlags::R_OK,
            "w" => AccessFlags::W_OK,
            "rw" => AccessFlags::R_OK | AccessFlags::W_OK,
            _ => return None,
        };
        return Some(access(path, mode));
    }
    let rest = name.strip_prefix("mknod:")?;
    let mut parts = rest.rsplitn(4, ':');
    let (minor, major, kind, path) = (parts.next()?, parts.next()?, parts.next()?, parts.next()?);
    let kind = match kind {
        "b" => SFlag::S_IFBLK,
        "c" => SFlag::S_IFCHR,
        _ => return None,
    };
    let dev = makedev(major.parse().ok()?, minor.parse().ok()?);
    Some(mknod(path, kind, Mode::from_bits_truncate(0o600), dev))
}

fn main() -> std::process::ExitCode {
    for name in std::env::args().skip(1) {
        if name == "session-keyring" {
            use rustlet_sys::keyring::{SESSION_KEYRING, describe, keyring_id};
            match keyring_id(SESSION_KEYRING).and_then(|id| Ok((id, describe(id)?))) {
                Ok((id, d)) => println!("{name} {id} {d}"),
                Err(e) => println!("{name} {e:?}"),
            }
            continue;
        }
        match probe(&name) {
            Some(Ok(())) => println!("{name} ok"),
            Some(Err(e)) => println!("{name} {e:?}"),
            None => {
                eprintln!("rustlet-probe: unknown probe {name:?}");
                return std::process::ExitCode::from(2);
            }
        }
    }
    std::process::ExitCode::SUCCESS
}

//! `rustlet-probe`: makes the syscalls that busybox can't, for the seccomp
//! tests in `tests/tests/hardening.rs`.
//!
//! Each argument names one probe. For each one it prints a line
//! `<probe> ok` or `<probe> <ERRNO>`, e.g. `clone3 ENOSYS`.
//!
//! This is a glibc binary and the test rootfs is Alpine (musl), so the tests
//! bind-mount it together with the host's library directory and start it
//! through the host's dynamic loader.
#![forbid(unsafe_code)]

use nix::errno::Errno;
use nix::sys::personality::{self, Persona};
use nix::sys::socket::{AddressFamily, SockFlag, SockType, socket};
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
        _ => return None,
    })
}

fn main() -> std::process::ExitCode {
    for name in std::env::args().skip(1) {
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

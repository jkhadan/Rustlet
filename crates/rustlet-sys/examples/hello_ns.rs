//! `hello-ns`: the Phase 0 namespace experiment.
//!
//! ```sh
//! cargo build -p rustlet-sys --example hello_ns
//! sudo ./target/debug/examples/hello_ns            # clone3 variant
//! sudo ./target/debug/examples/hello_ns --unshare  # unshare + fork variant
//! ```
//!
//! What it shows:
//!
//! * **PID namespace**: the child sees itself as PID 1, while the parent
//!   sees an ordinary PID for it.
//! * **UTS namespace**: the child changes its hostname; the host's is untouched.
//! * **Mount namespace**: the child mounts a *fresh* procfs over `/proc`
//!   (so `/proc` lists only the child's processes) without the host
//!   noticing, because it first switches every mount to private propagation.
//! * **Why `unshare(CLONE_NEWPID)` needs a fork**: after `unshare`, the
//!   *caller* keeps its PID and stays in the old namespace; only children
//!   it creates afterwards are born into the new one (the first becomes PID 1).
//!
//! This file contains no `unsafe`: everything goes through `rustlet-sys`.

#![forbid(unsafe_code)]

use std::path::Path;

use nix::mount::MsFlags;
use nix::unistd::{gethostname, getpid};
use rustlet_sys::mount::{FsContext, MountAttr, MoveMountFlags, move_mount};
use rustlet_sys::process::{self, Clone3, CloneFlags, Forked, WaitTarget};
use rustlet_sys::procfs;

fn main() {
    if !nix::unistd::geteuid().is_root() {
        eprintln!("hello-ns creates namespaces and needs root: sudo {}", std::env::args().next().unwrap());
        std::process::exit(1);
    }
    let unshare_mode = std::env::args().any(|a| a == "--unshare");
    let host_mnt = procfs::ns_id(None, "mnt").expect("read /proc/self/ns/mnt");

    println!("parent: pid {} hostname {:?}", getpid(), hostname());
    for kind in ["pid", "uts", "mnt"] {
        println!("parent: {kind:>4} ns inode {}", procfs::ns_id(None, kind).unwrap().1);
    }

    let flags = CloneFlags::NEWPID | CloneFlags::NEWUTS | CloneFlags::NEWNS;
    let forked = if unshare_mode {
        // Variant B: unshare, then fork.
        process::unshare(flags).expect("unshare");
        println!("parent: after unshare my pid is still {} (the new PID ns is for my children)", getpid());
        println!(
            "parent: but I am already in the new uts ns {} and mnt ns {}",
            procfs::ns_id(None, "uts").unwrap().1,
            procfs::ns_id(None, "mnt").unwrap().1
        );
        process::fork().expect("fork")
    } else {
        // Variant A: one clone3 call creates the child inside all three
        // namespaces and hands us a pidfd for it.
        Clone3::new().flags(flags | CloneFlags::PIDFD).spawn().expect("clone3")
    };

    match forked {
        Forked::Child => process::exit_now(child(host_mnt)),
        Forked::Parent { pid, pidfd } => {
            println!("parent: child has pid {pid} in *my* PID namespace");
            let res = match &pidfd {
                Some(fd) => process::waitid(WaitTarget::PidFd(std::os::fd::AsFd::as_fd(fd)), false),
                None => process::waitid(WaitTarget::Pid(pid), false),
            }
            .expect("waitid");
            println!("parent: child finished: {res:?}");
            if unshare_mode {
                // unshare(2) moved *this* process into the new UTS and mount
                // namespaces right away; only CLONE_NEWPID is deferred to
                // children. So we now share the child's hostname and its
                // /proc mount (whose PID namespace is empty now).
                println!("parent: my hostname is now {:?} too: unshare moved me into the new UTS ns", hostname());
                println!(
                    "parent: and I see the child's /proc ({} processes left in that PID ns)",
                    count_pids(Path::new("/proc"))
                );
            } else {
                println!("parent: my hostname is still {:?}", hostname());
                let proc_entries = count_pids(Path::new("/proc"));
                println!(
                    "parent: host /proc still lists {proc_entries} processes (the child's /proc mount never reached us)"
                );
            }
        }
    }
}

fn child(host_mnt: (u64, u64)) -> i32 {
    println!("  child: getpid() = {}", getpid());
    for kind in ["pid", "uts", "mnt"] {
        println!("  child: {kind:>4} ns inode {}", procfs::ns_id(None, kind).unwrap().1);
    }

    // Guardrail: never touch mounts unless we really are in a new mount ns.
    if procfs::ns_id(None, "mnt").unwrap() == host_mnt {
        eprintln!("  child: still in the host mount namespace, refusing to mount");
        return 1;
    }
    // Mounts copied into the new namespace keep their *propagation*: a
    // mount marked `shared` on the host would still forward our mounts back
    // to the host. MS_REC|MS_PRIVATE on `/` cuts every peer group first.
    nix::mount::mount(None::<&str>, "/", None::<&str>, MsFlags::MS_REC | MsFlags::MS_PRIVATE, None::<&str>)
        .expect("make / rprivate");

    nix::unistd::sethostname("hello-ns").expect("sethostname");
    println!("  child: hostname is now {:?}", hostname());

    // A fresh procfs instance, mounted with the new mount API. It belongs to
    // our PID namespace, so it lists only our processes.
    let proc = FsContext::open("proc").expect("fsopen proc");
    let mnt = proc.mount(MountAttr::NOSUID | MountAttr::NODEV | MountAttr::NOEXEC).expect("fsmount");
    move_mount(
        Some(std::os::fd::AsFd::as_fd(&mnt)),
        Path::new(""),
        None,
        Path::new("/proc"),
        MoveMountFlags::F_EMPTY_PATH,
    )
    .expect("move_mount /proc");
    println!("  child: my /proc lists {} process(es): {:?}", count_pids(Path::new("/proc")), pids(Path::new("/proc")));
    println!("  child: /proc/self/status NSpid: {}", procfs::status_field(None, "NSpid").unwrap_or_default());
    0
}

fn hostname() -> String {
    gethostname().map(|h| h.to_string_lossy().into_owned()).unwrap_or_default()
}

fn pids(proc: &Path) -> Vec<u32> {
    let mut v: Vec<u32> = std::fs::read_dir(proc)
        .map(|rd| rd.filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok()).collect())
        .unwrap_or_default();
    v.sort_unstable();
    v
}

fn count_pids(proc: &Path) -> usize {
    pids(proc).len()
}

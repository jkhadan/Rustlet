use std::ffi::CString;
use caps::{CapSet, Capability, CapsHashSet};
use nix::
{
    pty::{openpty, PtyMaster}, 
    sched::{CloneFlags, clone}, 
    unistd::Pid, sys::signal::Signal
};
use std::fs::write;

fn create_pid() -> isize {
    println!("New process created with PID: {}", std::process::id());

    // Deploys a new shell environment with cstring
    let cmd = CString::new("/bin/bash").unwrap();
    nix::unistd::execv(&cmd, &[cmd.clone()]).unwrap();

    0
}

fn drop_dangerous_capabilities() -> Result<(), caps::errors::CapsError> {
    let keep_caps = vec![
        Capability::CAP_CHOWN,
        Capability::CAP_DAC_OVERRIDE,
        Capability::CAP_FOWNER,
        Capability::CAP_SETGID,
        Capability::CAP_SETUID,
    ];

    // clear all capabilities
    caps::clear(None, CapSet::Effective)?;
    caps::clear(None, CapSet::Permitted)?;
    caps::clear(None, CapSet::Inheritable)?;

    /*
        CapsHashSet is a type alias: 
            - `pub type CapsHashSet = std::collections::HashSet<Capability>`
        
        The Capability enum is defined by caps and contains privileges that a process
        can possess (which we can add to our CapsHashSet).

        Examples:
            - CAP_SYS_ADMIN: Used for a wide range of administrative operations.
            - CAP_NET_BIND_SERVICE: Allows a process to bind to privileged TCP/UDP ports (those below 1024).
            - CAP_KILL: Allows a process to send signals to any other process. 
    */
    let caps: CapsHashSet = CapsHashSet::new(); 

    // Add back essential capabilities
    for cap in keep_caps {
        caps::set(None, CapSet::Effective, &caps)?;
    }

    Ok(())
}

fn create_container() -> Result<Pid, nix::Error> {
    const STACK_SIZE: usize = 1024 * 1024; // 1MB
    let mut stack: [u8; STACK_SIZE] = [0; STACK_SIZE];

    let flags = CloneFlags::CLONE_NEWNS 
    | CloneFlags::CLONE_NEWPID 
    | CloneFlags::CLONE_NEWUTS 
    | CloneFlags::CLONE_NEWUSER 
    | CloneFlags::CLONE_NEWIPC 
    | CloneFlags::CLONE_NEWNET 
    | CloneFlags::CLONE_NEWCGROUP;

    let pid = unsafe {
        clone(
            Box::new(create_pid), // Using a box to allocate to heap instead of stack
            &mut stack,
            flags,
            Some(Signal::SIGCHLD as i32) // to notify the parent of the child's termination (prevent zombies)
        )
    };

    println!("Created new PID namespace with PID: {}", pid.unwrap());

    Ok(pid?)
}

fn main() {
    create_container().unwrap();
}
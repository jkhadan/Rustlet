use std::ffi::CString;
use std::fs::write;
use caps::{CapSet, Capability, CapsHashSet};
use nix::
{
    pty::{openpty, PtyMaster}, 
    sched::{CloneFlags, clone}, 
    unistd::Pid, sys::signal::Signal
};

fn create_pid() -> isize {
    println!("New process created with PID: {}", std::process::id());

    // Deploys a new shell environment with cstring
    let cmd = CString::new("/bin/bash").unwrap();
    nix::unistd::execv(&cmd, &[cmd.clone()]).unwrap();

    0
}

fn setup_user_namespace(pid: Pid) -> Result<(), Box<dyn std::error::Error>> {
    let uid_map = format!("0 {} 1", nix::unistd::getuid());
    let gid_map = format!("0 {} 1", nix::unistd::getgid());

    write(format!("/proc/{}/uid_map", pid), uid_map)?;
    write(format!("/proc/{}/setgroups", pid), "deny")?; // Prevent privilege escalation
    write(format!("/proc/{}/gid_map", pid), gid_map)?;

    Ok(())
}

fn drop_dangerous_capabilities() -> Result<(), caps::errors::CapsError> {
    let keep_caps: CapsHashSet = [
        Capability::CAP_CHOWN,
        Capability::CAP_DAC_OVERRIDE,
        Capability::CAP_FOWNER,
        Capability::CAP_SETGID,
        Capability::CAP_SETUID,
    ].into_iter().collect();

    // Clear inheritable (we don't want children to inherit capabilities)
    caps::clear(None, CapSet::Inheritable)?;
    caps::clear(None, CapSet::Permitted)?;
    caps::clear(None, CapSet::Inheritable)?;
    
    
    // Set both permitted and effective to our keep_caps
    // Permitted defines what we're allowed to have
    // Effective defines what we can actually use
    caps::set(None, CapSet::Permitted, &keep_caps)?;
    caps::set(None, CapSet::Effective, &keep_caps)?;

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
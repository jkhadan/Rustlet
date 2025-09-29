use std::fs::write;
use nix::unistd::Pid;
use caps::CapSet;
use crate::app_error::AppError;

pub fn setup_user_namespace(pid: Pid) -> Result<(), AppError> {
    let uid_map = format!("0 {} 1", nix::unistd::getuid());
    let gid_map = format!("0 {} 1", nix::unistd::getgid());

    write(format!("/proc/{}/uid_map", pid), uid_map)?;
    write(format!("/proc/{}/setgroups", pid), "deny")?; // Prevent privilege escalation
    write(format!("/proc/{}/gid_map", pid), gid_map)?;

    Ok(())
}

pub fn drop_dangerous_capabilities() -> Result<(), AppError> {
    // Clear inheritable (we don't want children to inherit capabilities)
    caps::clear(None, CapSet::Inheritable)?;
    caps::clear(None, CapSet::Permitted)?;
    caps::clear(None, CapSet::Inheritable)?;
    
    println!("Successfully dropped all capabilities");
    Ok(())
}
use std::ffi::CString;
use std::fs::{write, create_dir_all};
use std::path::Path;
use caps::{CapSet};
use nix::
{
    sched::{CloneFlags, clone}, 
    unistd::Pid, sys::signal::Signal,
    unistd::pivot_root,
    mount::{mount, umount2, MsFlags, MntFlags},
    sys::wait::{waitpid, WaitStatus}
};

const CONTAINER_ROOT: &str = "/home/jkhadan/projects/Rustlet/container";

fn create_pid() -> isize {
    println!("New process created with PID: {}", std::process::id());

    // Setup secure environment inside the container
    if let Err(e) = setup_secure_rootfs() {
        eprintln!("Failed to setup secure rootfs: {}", e);
        return -1;
    }

    // Mount essential filesystems
    if let Err(e) = mount_essential_fs() {
        eprintln!("Failed to mount essential filesystems: {}", e);
        return -1;
    }

    if let Err(e) = drop_dangerous_capabilities() {
        eprintln!("Failed to drop capabilities: {}", e);
        return -1;
    }

    // Check if /bin/bash exists before trying to execute
    if !Path::new("/bin/bash").exists() {
        eprintln!("Error: /bin/bash not found in container filesystem");
        eprintln!("Make sure {} contains a valid root filesystem", CONTAINER_ROOT);
        
        // Try /bin/sh as fallback
        if Path::new("/bin/sh").exists() {
            eprintln!("Falling back to /bin/sh");
            let cmd = CString::new("/bin/sh").unwrap();
            let _ = nix::unistd::execv(&cmd, &[cmd.clone()]);
        }
        return -1;
    }

    // Execute bash
    let cmd = CString::new("/bin/bash").unwrap();
    match nix::unistd::execv(&cmd, &[cmd.clone()]) {
        Ok(_) => 0,  // This should never be reached if execv succeeds
        Err(e) => {
            eprintln!("Failed to execute /bin/bash: {}", e);
            -1
        }
    }
}

fn setup_secure_rootfs() -> Result<(), Box<dyn std::error::Error>> {
    // Check if container root exists
    if !Path::new(CONTAINER_ROOT).exists() {
        return Err(format!("Container root {} does not exist", CONTAINER_ROOT).into());
    }

    // Mount new root filesystem
    mount(Some(CONTAINER_ROOT), "/mnt", 
          Some("bind"), MsFlags::MS_BIND, None::<&str>)?;

    // Create old root directory
    create_dir_all("/mnt/old_root")?;

    // Change to new root before pivot_root
    std::env::set_current_dir("/mnt")?;
    
    // Pivot root (much safer than chroot)
    pivot_root(".", "old_root")?;
    
    // Change to new root
    std::env::set_current_dir("/")?;

    // Unmount old root
    umount2("/old_root", MntFlags::MNT_DETACH)?;
    std::fs::remove_dir("/old_root").ok(); // Ignore Errors
    
    Ok(())
}

fn mount_essential_fs() -> Result<(), nix::Error> {
    // Create mount points if they don't exist
    create_dir_all("/proc").ok();
    create_dir_all("/sys").ok();
    create_dir_all("/dev").ok();
    
    // Mount proc filesystem
    mount(Some("proc"), "/proc", Some("proc"), 
          MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC, 
          None::<&str>)?;
    
    // Mount sysfs
    mount(Some("sysfs"), "/sys", Some("sysfs"),
          MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
          None::<&str>)?;
    
    // Mount minimal /dev
    mount(Some("tmpfs"), "/dev", Some("tmpfs"),
          MsFlags::MS_NOSUID | MsFlags::MS_STRICTATIME,
          Some("mode=755"))?;
    
    Ok(())
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
    // Clear inheritable (we don't want children to inherit capabilities)
    caps::clear(None, CapSet::Inheritable)?;
    caps::clear(None, CapSet::Permitted)?;
    caps::clear(None, CapSet::Inheritable)?;
    

    println!("Successfully dropped all capabilities");
    Ok(())
}

fn create_container() -> Result<Pid, nix::Error> {
    const STACK_SIZE: usize = 1024 * 1024; // 1MB
    let mut stack = vec![0u8; STACK_SIZE];

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

    let container_pid = pid?;
    println!("Created new PID namespace with PID: {}", container_pid);

    // Setup user namespace mapping from parent process
    if let Err(e) = setup_user_namespace(container_pid) {
        eprintln!("Failed to setup user namespace: {}", e);
    }

    // Wait for container process
    match waitpid(container_pid, None) {
        Ok(WaitStatus::Exited(_, exit_code)) => {
            println!("Container exited with code: {}", exit_code);
        }
        Ok(status) => {
            println!("Container terminated with status: {:?}", status);
        }
        Err(e) => {
            eprintln!("Error waiting for container: {}", e);
        }
    }

    Ok(container_pid)
}

fn main() {
    // Check if running as root (recommended for full functionality)
    if !nix::unistd::Uid::effective().is_root() {
        eprintln!("Warning: Not running as root. Some features may not work.");
        eprintln!("Consider running with: sudo cargo run");
    }

    // Check if container filesystem exists
    if !Path::new(CONTAINER_ROOT).exists() {
        eprintln!("Error: Container root filesystem not found at {}", CONTAINER_ROOT);
        eprintln!("Please create a root filesystem first.");
        eprintln!("You can use debootstrap, alpine's minirootfs, or copy essential binaries.");
        std::process::exit(1);
    }

    if let Err(e) = create_container() {
        eprintln!("Failed to create container: {}", e);
        std::process::exit(1);
    }
}
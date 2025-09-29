use std::ffi::CString;
use std::path::Path;
use std::os::unix::fs::PermissionsExt;
use nix::{
    sched::{CloneFlags, clone},
    unistd::Pid,
    sys::signal::Signal,
    sys::wait::{waitpid, WaitStatus}
};
use crate::app_error::AppError;
use crate::{isolate_filesystem, security, cgroups};

pub fn create_pid(container_root: &str) -> isize {
    println!("New process created with PID: {}", std::process::id());

    // Setup secure environment inside the container
    if let Err(e) = isolate_filesystem::setup_secure_rootfs(container_root) {
        eprintln!("Failed to setup secure rootfs: {}", e);
        return -1;
    }

    // Mount essential filesystems
    if let Err(e) = isolate_filesystem::mount_essential_fs() {
        eprintln!("Failed to mount essential filesystems: {}", e);
        return -1;
    }

    // Drop Dangerous Capabilities
    if let Err(e) = security::drop_dangerous_capabilities() {
        eprintln!("Failed to drop capabilities: {}", e);
        return -1;
    }

    // Debug: List contents of key directories
    println!("Debug: Checking filesystem after pivot_root...");
    println!("Contents of /:");
    if let Ok(entries) = std::fs::read_dir("/") {
        for entry in entries.flatten() {
            println!("  {}", entry.file_name().to_string_lossy());
        }
    }
    
    println!("Contents of /bin:");
    if let Ok(entries) = std::fs::read_dir("/bin") {
        for entry in entries.flatten() {
            println!("  {}", entry.file_name().to_string_lossy());
        }
    } else {
        println!("  /bin directory not accessible");
    }
    
    println!("Contents of /lib:");
    if let Ok(entries) = std::fs::read_dir("/lib") {
        for entry in entries.flatten() {
            println!("  {}", entry.file_name().to_string_lossy());
        }
    } else {
        println!("  /lib directory not accessible");
    }

    // Check if /bin/bash exists and is executable
    let bash_path = Path::new("/bin/bash");
    println!("Debug: /bin/bash exists: {}", bash_path.exists());
    if bash_path.exists() {
        if let Ok(metadata) = bash_path.metadata() {
            println!("Debug: /bin/bash permissions: {:o}", metadata.permissions().mode());
            println!("Debug: /bin/bash size: {} bytes", metadata.len());
        }
    }

    // Check if /bin/bash exists before trying to execute
    if !Path::new("/bin/bash").exists() {
        eprintln!("Error: /bin/bash not found in container filesystem");
        eprintln!("Make sure {} contains a valid root filesystem", container_root);
        
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
    println!("Debug: Attempting to execute /bin/bash...");
    match nix::unistd::execv(&cmd, &[cmd.clone()]) {
        Ok(_) => 0,  // This should never be reached if execv succeeds
        Err(e) => {
            eprintln!("Failed to execute /bin/bash: {}", e);
            -1
        }
    }
}

pub fn create_container(container_root: &str) -> Result<Pid, AppError> {
    const STACK_SIZE: usize = 1024 * 1024; // 1MB
    let mut stack = vec![0u8; STACK_SIZE];

    let flags = CloneFlags::CLONE_NEWNS 
    | CloneFlags::CLONE_NEWPID 
    | CloneFlags::CLONE_NEWUTS 
    | CloneFlags::CLONE_NEWUSER 
    | CloneFlags::CLONE_NEWIPC 
    | CloneFlags::CLONE_NEWNET 
    | CloneFlags::CLONE_NEWCGROUP;

    // Generate a unique container ID
    let container_id = format!("{}", std::process::id());

    // Capture container_root for the closure
    let container_root = container_root.to_string();
    
    let pid = unsafe {
        clone(
            Box::new(move || create_pid(&container_root)), // Using move to capture container_root
            &mut stack,
            flags,
            Some(Signal::SIGCHLD as i32) // to notify the parent of the child's termination (prevent zombies)
        )
    };

    let container_pid = pid?;
    println!("Created new PID namespace with PID: {}", container_pid);

    // Setup user namespace mapping from parent process
    if let Err(e) = security::setup_user_namespace(container_pid) {
        eprintln!("Failed to setup user namespace: {}", e);
    }

    // Setup cgroups for resource limits
    let cgroup_manager = match cgroups::setup_container_cgroup(&container_id, container_pid) {
        Ok(manager) => {
            println!("Successfully configured cgroup resource limits");
            Some(manager)
        }
        Err(e) => {
            eprintln!("Failed to setup cgroups: {}. Container will run without resource limits.", e);
            None
        }
    };

    // Monitor resources periodically
    if let Some(ref cgroup) = cgroup_manager {
        cgroups::monitor_resources(cgroup).ok();
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

    // Cleanup will happen automatically when cgroup_manager is dropped
    if let Some(cgroup) = cgroup_manager {
        println!("Cleaning up container resources...");
        cgroup.cleanup().ok();
    }

    Ok(container_pid)
}
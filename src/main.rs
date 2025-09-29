use std::ffi::CString;
use std::fs::{write, create_dir_all, copy};
use std::path::{Path};
use std::process::{Command, Stdio};
use std::os::unix::fs::PermissionsExt;
use caps::CapSet;
use nix::{
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

    // Drop Dangerous Capabilities
    if let Err(e) = drop_dangerous_capabilities() {
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
    println!("Debug: Attempting to execute /bin/bash...");
    match nix::unistd::execv(&cmd, &[cmd.clone()]) {
        Ok(_) => 0,  // This should never be reached if execv succeeds
        Err(e) => {
            eprintln!("Failed to execute /bin/bash: {}", e);
            -1
        }
    }
}

fn setup_container_filesystem() -> Result<(), Box<dyn std::error::Error>> {
    println!("Setting up container filesystem at {}", CONTAINER_ROOT);
    
    // Create directory structure
    let dirs = [
        "bin", "lib", "lib64", "proc", "sys", "dev", "etc", "tmp", "usr/bin"
    ];
    
    for dir in &dirs {
        let path = Path::new(CONTAINER_ROOT).join(dir);
        create_dir_all(&path)?;
        println!("Created directory: {}", path.display());
    }

    // List of essential binaries to copy
    let binaries = ["/bin/bash", "/bin/sh", "/bin/ls", "/bin/cat", "/bin/echo"];
    
    for binary in &binaries {
        if Path::new(binary).exists() {
            let dest = Path::new(CONTAINER_ROOT).join(&binary[1..]); // Remove leading '/'
            
            // Create parent directory if it doesn't exist
            if let Some(parent) = dest.parent() {
                create_dir_all(parent)?;
            }
            
            copy(binary, &dest)?;
            println!("Copied binary: {} -> {}", binary, dest.display());
        } else {
            eprintln!("Warning: Binary {} not found on host system", binary);
        }
    }

    // Copy shared library dependencies
    copy_shared_libraries("/bin/bash")?;

    // Create basic /etc files
    create_etc_files()?;

    println!("Container filesystem setup completed successfully");
    Ok(())
}

fn copy_shared_libraries(binary: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("Finding and copying shared libraries for {}", binary);
    
    let output = Command::new("ldd")
        .arg(binary)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?
        .wait_with_output()?;

    if !output.status.success() {
        eprintln!("Warning: ldd command failed for {}", binary);
        return Ok(()); // Continue without libraries
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut libraries = std::collections::HashSet::new();

    println!("ldd output for {}:", binary);
    for line in stdout.lines() {
        println!("  {}", line);
    }

    // Parse ldd output to extract library paths
    for line in stdout.lines() {
        // Look for lines like: "libreadline.so.8 => /lib/x86_64-linux-gnu/libreadline.so.8 (0x...)"
        // or: "/lib64/ld-linux-x86-64.so.2 (0x...)"
        if let Some(path) = extract_library_path(line) {
            if Path::new(&path).exists() {
                libraries.insert(path);
            }
        }
    }

    // Copy each library maintaining directory structure
    for lib_path in libraries {
        let dest_path = Path::new(CONTAINER_ROOT).join(&lib_path[1..]); // Remove leading '/'
        
        // Create parent directories
        if let Some(parent) = dest_path.parent() {
            create_dir_all(parent)?;
        }

        copy(&lib_path, &dest_path)?;
        println!("Copied library: {} -> {}", lib_path, dest_path.display());
    }

    Ok(())
}

fn extract_library_path(line: &str) -> Option<String> {
    let line = line.trim();
    
    // Handle direct absolute paths like "/lib64/ld-linux-x86-64.so.2 (0x...)"
    if line.starts_with('/') {
        if let Some(space_pos) = line.find(' ') {
            let path = line[..space_pos].trim();
            return Some(path.to_string());
        }
        // Handle lines that might not have spaces (shouldn't happen with ldd, but just in case)
        if line.starts_with('/') && !line.contains('(') {
            return Some(line.to_string());
        }
    }
    
    // Handle mapped libraries like "libreadline.so.8 => /lib/x86_64-linux-gnu/libreadline.so.8 (0x...)"
    if let Some(arrow_pos) = line.find(" => ") {
        let after_arrow = &line[arrow_pos + 4..];
        if let Some(space_pos) = after_arrow.find(' ') {
            let path = after_arrow[..space_pos].trim();
            if path.starts_with('/') && path != "(0x" {
                return Some(path.to_string());
            }
        } else if after_arrow.starts_with('/') {
            // Handle case where there might not be a space after the path
            return Some(after_arrow.to_string());
        }
    }
    
    // Handle VDSO and other special cases by ignoring them
    if line.contains("linux-vdso.so") || line.contains("(0x") && !line.contains(" => ") {
        return None;
    }
    
    None
}

fn create_etc_files() -> Result<(), Box<dyn std::error::Error>> {
    let etc_path = Path::new(CONTAINER_ROOT).join("etc");
    create_dir_all(&etc_path)?;

    // Create /etc/passwd
    let passwd_content = "root:x:0:0:root:/root:/bin/bash\n";
    let passwd_path = etc_path.join("passwd");
    write(&passwd_path, passwd_content)?;
    println!("Created {}", passwd_path.display());

    // Create /etc/group
    let group_content = "root:x:0:\n";
    let group_path = etc_path.join("group");
    write(&group_path, group_content)?;
    println!("Created {}", group_path.display());

    Ok(())
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

    // Setup container filesystem if it doesn't exist or if forced
    let container_exists = Path::new(CONTAINER_ROOT).exists() 
        && Path::new(&format!("{}/bin/bash", CONTAINER_ROOT)).exists();
    
    if !container_exists {
        println!("Container filesystem not found or incomplete, setting up...");
        if let Err(e) = setup_container_filesystem() {
            eprintln!("Failed to setup container filesystem: {}", e);
            std::process::exit(1);
        }
    } else {
        println!("Using existing container filesystem at {}", CONTAINER_ROOT);
    }

    if let Err(e) = create_container() {
        eprintln!("Failed to create container: {}", e);
        std::process::exit(1);
    }
}
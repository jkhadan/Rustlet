use std::fs::{write, create_dir_all, copy};
use std::path::Path;
use std::process::{Command, Stdio};
use crate::app_error::AppError;

pub fn setup_container_filesystem(container_root: &str) -> Result<(), AppError> {
    println!("Setting up container filesystem at {}", container_root);
    
    // Create directory structure
    let dirs = [
        "bin", "lib", "lib64", "proc", "sys", "dev", "etc", "tmp", "usr/bin"
    ];
    
    for dir in &dirs {
        let path = Path::new(container_root).join(dir);
        create_dir_all(&path)?;
        println!("Created directory: {}", path.display());
    }

    // List of essential binaries to copy
    let binaries = ["/bin/bash", "/bin/sh", "/bin/ls", "/bin/cat", "/bin/echo"];
    
    for binary in &binaries {
        if Path::new(binary).exists() {
            let dest = Path::new(container_root).join(&binary[1..]); // Remove leading '/'
            
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
    copy_shared_libraries("/bin/bash", container_root)?;

    // Create basic /etc files
    create_etc_files(container_root)?;

    println!("Container filesystem setup completed successfully");
    Ok(())
}

pub fn copy_shared_libraries(binary: &str, container_root: &str) -> Result<(), AppError> {
    println!("Finding and copying shared libraries for {}", binary);
    
    let output = Command::new("ldd")
        .arg(binary)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?
        .wait_with_output()?;

    if !output.status.success() {
        eprintln!("Warning: ldd command failed for {}", binary);
        return Ok(());
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
        let dest_path = Path::new(container_root).join(&lib_path[1..]); // Remove leading '/'
        
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

pub fn create_etc_files(container_root: &str) -> Result<(), AppError> {
    let etc_path = Path::new(container_root).join("etc");
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

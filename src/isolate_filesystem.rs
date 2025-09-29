use std::fs::create_dir_all;
use std::path::Path;
use nix::{
    unistd::pivot_root,
    mount::{mount, umount2, MsFlags, MntFlags}
};
use crate::app_error::AppError;

pub fn setup_secure_rootfs(container_root: &str) -> Result<(), AppError> {
    // Check if container root exists
    if !Path::new(container_root).exists() {
        return Err(AppError::ContainerDNE(container_root.to_string()))
    }

    // Mount new root filesystem
    mount(Some(container_root), "/mnt", 
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

pub fn mount_essential_fs() -> Result<(), AppError> {
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
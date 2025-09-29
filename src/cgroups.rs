use std::fs::{create_dir_all, write, read_to_string, remove_dir};
use std::path::{Path, PathBuf};
use nix::unistd::Pid;
use crate::app_error::AppError;

const CGROUP_ROOT: &str = "/sys/fs/cgroup";

pub struct CgroupManager {
    cgroup_path: PathBuf,
    container_id: String,
}

impl CgroupManager {
    /// Create a new cgroup manager for a container
    pub fn new(container_id: &str) -> Result<Self, AppError> {
        // Check if cgroup v2 is available
        if !is_cgroup_v2_available()? {
            eprintln!("Warning: Cgroup v2 not available, resource limits will not be enforced");
            // Return a manager anyway, but operations will be no-ops
        }
        
        let cgroup_name = format!("rustlet_{}", container_id);
        let cgroup_path = Path::new(CGROUP_ROOT).join("rustlet").join(&cgroup_name);
        
        Ok(CgroupManager {
            cgroup_path,
            container_id: container_id.to_string(),
        })
    }
    
    /// Setup the cgroup for the container
    pub fn setup(&self) -> Result<(), AppError> {
        if !is_cgroup_v2_available()? {
            return Ok(());
        }
        
        println!("Setting up cgroup at: {}", self.cgroup_path.display());
        
        // Create the cgroup directory
        create_dir_all(&self.cgroup_path)?;
        
        // Enable controllers we want to use (memory and cpu)
        self.enable_controllers()?;
        
        Ok(())
    }
    
    /// Add a process to this cgroup
    pub fn add_process(&self, pid: Pid) -> Result<(), AppError> {
        if !is_cgroup_v2_available()? {
            return Ok(());
        }
        
        let cgroup_procs = self.cgroup_path.join("cgroup.procs");
        write(&cgroup_procs, pid.to_string())?;
        
        println!("Added process {} to cgroup", pid);
        Ok(())
    }
    
    /// Set memory limit for the container
    pub fn set_memory_limit(&self, limit_mb: u64) -> Result<(), AppError> {
        if !is_cgroup_v2_available()? {
            return Ok(());
        }
        
        let memory_max = self.cgroup_path.join("memory.max");
        let limit_bytes = limit_mb * 1024 * 1024;
        
        write(&memory_max, limit_bytes.to_string())?;
        println!("Set memory limit to {} MB", limit_mb);
        
        // Also set swap limit to 0 to prevent swap usage
        let memory_swap_max = self.cgroup_path.join("memory.swap.max");
        if memory_swap_max.exists() {
            write(&memory_swap_max, "0")?;
            println!("Disabled swap for container");
        }
        
        Ok(())
    }
    
    /// Set CPU limit for the container (as a percentage of one CPU)
    pub fn set_cpu_limit(&self, cpu_percentage: u32) -> Result<(), AppError> {
        if !is_cgroup_v2_available()? {
            return Ok(());
        }
        
        // CPU limit in cgroup v2 uses cpu.max file
        // Format: "$quota $period" or "max $period"
        // We'll use a period of 100000 microseconds (100ms)
        let period = 100000;
        let quota = (period as u32 * cpu_percentage) / 100;
        
        let cpu_max = self.cgroup_path.join("cpu.max");
        let cpu_config = format!("{} {}", quota, period);
        
        write(&cpu_max, cpu_config)?;
        println!("Set CPU limit to {}% of one core", cpu_percentage);
        
        Ok(())
    }
    
    /// Set maximum number of processes/threads
    pub fn set_pids_limit(&self, max_pids: u32) -> Result<(), AppError> {
        if !is_cgroup_v2_available()? {
            return Ok(());
        }
        
        let pids_max = self.cgroup_path.join("pids.max");
        write(&pids_max, max_pids.to_string())?;
        
        println!("Set maximum PIDs to {}", max_pids);
        Ok(())
    }
    
    /// Get current memory usage
    pub fn get_memory_usage(&self) -> Result<u64, AppError> {
        if !is_cgroup_v2_available()? {
            return Ok(0);
        }
        
        let memory_current = self.cgroup_path.join("memory.current");
        if memory_current.exists() {
            let usage = read_to_string(&memory_current)?
                .trim()
                .parse::<u64>()
                .unwrap_or(0);
            Ok(usage)
        } else {
            Ok(0)
        }
    }
    
    /// Enable necessary controllers for the cgroup
    fn enable_controllers(&self) -> Result<(), AppError> {
        // For cgroup v2, we need to enable controllers in the parent cgroup
        if let Some(parent) = self.cgroup_path.parent() {
            let subtree_control = parent.join("cgroup.subtree_control");
            
            if subtree_control.exists() {
                // Try to enable memory, cpu, and pids controllers
                // Use append mode to avoid overwriting existing controllers
                let controllers = "+memory +cpu +pids";
                
                // Read current controllers to avoid duplicates
                let current = read_to_string(&subtree_control).unwrap_or_default();
                
                if !current.contains("memory") {
                    write(&subtree_control, "+memory").ok();
                }
                if !current.contains("cpu") {
                    write(&subtree_control, "+cpu").ok();
                }
                if !current.contains("pids") {
                    write(&subtree_control, "+pids").ok();
                }
            }
        }
        
        Ok(())
    }
    
    /// Cleanup the cgroup (remove it)
    pub fn cleanup(&self) -> Result<(), AppError> {
        if !is_cgroup_v2_available()? {
            return Ok(());
        }
        
        if self.cgroup_path.exists() {
            // First, make sure no processes are in the cgroup
            let procs_file = self.cgroup_path.join("cgroup.procs");
            if procs_file.exists() {
                let procs = read_to_string(&procs_file)?;
                if !procs.trim().is_empty() {
                    eprintln!("Warning: Cgroup still has processes, skipping cleanup");
                    return Ok(());
                }
            }
            
            // Remove the cgroup directory
            remove_dir(&self.cgroup_path)?;
            println!("Cleaned up cgroup: {}", self.cgroup_path.display());
        }
        
        Ok(())
    }
}

impl Drop for CgroupManager {
    fn drop(&mut self) {
        // Attempt cleanup when the manager is dropped
        self.cleanup().ok();
    }
}

/// Check if cgroup v2 is available on the system
fn is_cgroup_v2_available() -> Result<bool, AppError> {
    let cgroup_path = Path::new(CGROUP_ROOT);
    
    // Check if the cgroup mount exists
    if !cgroup_path.exists() {
        return Ok(false);
    }
    
    // Check for cgroup v2 by looking for cgroup.controllers file
    let controllers_file = cgroup_path.join("cgroup.controllers");
    Ok(controllers_file.exists())
}

/// Apply default resource limits for a container
pub fn apply_default_limits(cgroup: &CgroupManager) -> Result<(), AppError> {
    // Set reasonable defaults
    cgroup.set_memory_limit(512)?;  // 512 MB
    cgroup.set_cpu_limit(50)?;       // 50% of one CPU core
    cgroup.set_pids_limit(128)?;     // Max 128 processes
    
    Ok(())
}

/// Create and setup a cgroup for a container process
pub fn setup_container_cgroup(container_id: &str, pid: Pid) -> Result<CgroupManager, AppError> {
    let cgroup = CgroupManager::new(container_id)?;
    
    // Setup the cgroup
    cgroup.setup()?;
    
    // Apply default limits (can be made configurable later)
    apply_default_limits(&cgroup)?;
    
    // Add the process to the cgroup
    cgroup.add_process(pid)?;
    
    Ok(cgroup)
}

/// Monitor resource usage (can be called periodically)
pub fn monitor_resources(cgroup: &CgroupManager) -> Result<(), AppError> {
    let memory_usage = cgroup.get_memory_usage()?;
    let memory_mb = memory_usage / (1024 * 1024);
    
    println!("Container {} - Memory usage: {} MB", cgroup.container_id, memory_mb);
    
    Ok(())
}
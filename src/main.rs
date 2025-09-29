use std::path::Path;

mod app_error;
mod build_env;
mod isolate_filesystem;
mod security;
mod process;

const CONTAINER_ROOT: &str = "/home/jkhadan/projects/Rustlet/container";

fn main() {
    // Setup container filesystem if it doesn't exist
    let container_exists = Path::new(CONTAINER_ROOT).exists() 
        && Path::new(&format!("{}/bin/bash", CONTAINER_ROOT)).exists();
    
    if !container_exists {
        println!("Container filesystem not found or incomplete, setting up...");
        if let Err(e) = build_env::setup_container_filesystem(CONTAINER_ROOT) {
            eprintln!("Failed to setup container filesystem: {}", e);
            std::process::exit(1);
        }
    } else {
        println!("Using existing container filesystem at {}", CONTAINER_ROOT);
    } 

    if let Err(e) = process::create_container(CONTAINER_ROOT) {
        eprintln!("Failed to create container: {}", e);
        std::process::exit(1);
    }
}
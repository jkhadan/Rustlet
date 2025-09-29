use std::io;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("Io error: {0}")]
    IoError(#[from] io::Error),

    #[error("Nix error: {0}")]
    NixError(#[from] nix::Error),

    #[error("Caps error: {0}")]
    CapsError(#[from] caps::errors::CapsError),

    #[error("Container doesn't exist {0}")]
    ContainerDNE(String),

}
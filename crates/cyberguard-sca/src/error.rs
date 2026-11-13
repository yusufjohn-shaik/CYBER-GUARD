use std::path::PathBuf;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ScaError {
    #[error("I/O error reading lockfile: {0}")]
    Io(#[from] std::io::Error),

    #[error("Failed to parse lockfile at {0}: {1}")]
    ParseError(PathBuf, String),

    #[error("Unsupported lockfile format at {0}")]
    UnsupportedFormat(PathBuf),

    #[error("Invalid SemVer specification for package {0}: {1}")]
    InvalidVersion(String, String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

use std::path::PathBuf;
use thiserror::Error;

/// Root error type for all CyberGuard operations.
#[derive(Error, Debug)]
pub enum CyberguardError {
    #[error("Configuration error: {0}")]
    Config(#[from] ConfigError),

    #[error("Subprocess execution error: {0}")]
    Process(#[from] ProcessError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Internal engine error: {0}")]
    Internal(String),
}

/// Errors originating from configuration loading and validation.
#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Configuration file not found at: {0}")]
    FileNotFound(PathBuf),

    #[error("Configuration parsing failure: {0}")]
    ParseError(String),

    #[error("Invalid configuration value for key '{key}': {message}")]
    InvalidValue { key: String, message: String },
}

/// Errors originating from external scanner and process management.
#[derive(Error, Debug)]
pub enum ProcessError {
    #[error("Process '{command}' timed out after {duration_secs} seconds")]
    Timeout { command: String, duration_secs: u64 },

    #[error("Failed to execute process '{command}': {source}")]
    ExecutionFailed {
        command: String,
        #[source]
        source: std::io::Error,
    },

    #[error("Process '{command}' was terminated by OS signal {signal}")]
    TerminatedBySignal { command: String, signal: i32 },

    #[error("Process '{command}' exceeded maximum allowed output buffer of {limit} bytes")]
    BufferExhausted { command: String, limit: usize },

    #[error("Process group error for '{command}': {source}")]
    ProcessGroupError {
        command: String,
        source: std::io::Error,
    },
}

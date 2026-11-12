use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

/// Configuration options for launching an isolated subprocess.
#[derive(Debug, Clone)]
pub struct ProcessOptions {
    pub command: String,
    pub args: Vec<String>,
    pub current_dir: Option<PathBuf>,
    pub envs: HashMap<String, String>,
    pub timeout_duration: Duration,
    pub max_output_bytes: usize,
}

impl ProcessOptions {
    /// Create new options with sensible production defaults.
    pub fn new(command: impl Into<String>, args: Vec<String>) -> Self {
        Self {
            command: command.into(),
            args,
            current_dir: None,
            envs: HashMap::new(),
            timeout_duration: Duration::from_secs(30),
            max_output_bytes: 10 * 1024 * 1024, // 10 MB default limit
        }
    }

    /// Set working directory.
    pub fn with_current_dir(mut self, dir: PathBuf) -> Self {
        self.current_dir = Some(dir);
        self
    }

    /// Set timeout duration.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout_duration = timeout;
        self
    }

    /// Set maximum output buffer bytes before graceful truncation.
    pub fn with_max_output(mut self, max_bytes: usize) -> Self {
        self.max_output_bytes = max_bytes;
        self
    }

    /// Insert an environment variable.
    pub fn with_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.envs.insert(key.into(), value.into());
        self
    }
}

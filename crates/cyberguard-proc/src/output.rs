use std::time::Duration;

/// Result of an executed subprocess.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessOutput {
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub duration: Duration,
    pub truncated: bool,
}

impl ProcessOutput {
    /// Helper to verify whether the command finished successfully (exit code 0).
    pub fn is_success(&self) -> bool {
        self.exit_code == Some(0)
    }
}

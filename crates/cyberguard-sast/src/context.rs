// Copyright 2026 CyberGuard Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Scan context and configuration model for static analysis jobs.

use std::path::PathBuf;

/// Execution context for a static analysis scan job.
#[derive(Debug, Clone)]
pub struct ScanContext {
    /// Target path (directory or single file) to scan.
    pub target_path: PathBuf,
    /// Maximum directory traversal recursion depth (default: 32).
    pub max_depth: usize,
    /// Maximum file size in bytes to inspect (default: 5 MB).
    pub max_file_size_bytes: u64,
    /// Directory/file path substrings to exclude from traversal.
    pub excluded_paths: Vec<String>,
    /// Whitelist of supported source file extensions.
    pub allowed_extensions: Vec<String>,
    /// Minimum severity filter (e.g., Some("error") or Some("warning")).
    pub min_severity: Option<String>,
}

impl Default for ScanContext {
    fn default() -> Self {
        Self {
            target_path: PathBuf::from("."),
            max_depth: 32,
            max_file_size_bytes: 5 * 1024 * 1024, // 5 MB
            excluded_paths: vec![
                "node_modules".into(),
                "target".into(),
                "vendor".into(),
                ".git".into(),
                ".venv".into(),
                "dist".into(),
                "build".into(),
                ".idea".into(),
                ".vscode".into(),
            ],
            allowed_extensions: vec![
                "rs".into(),
                "py".into(),
                "js".into(),
                "ts".into(),
                "jsx".into(),
                "tsx".into(),
                "go".into(),
                "java".into(),
                "c".into(),
                "cpp".into(),
                "h".into(),
                "hpp".into(),
                "php".into(),
                "rb".into(),
                "sh".into(),
                "bash".into(),
            ],
            min_severity: None,
        }
    }
}

impl ScanContext {
    /// Create a new ScanContext pointing to a specific target path.
    pub fn new(target_path: impl Into<PathBuf>) -> Self {
        Self {
            target_path: target_path.into(),
            ..Default::default()
        }
    }

    /// Set custom recursion depth.
    pub fn with_max_depth(mut self, max_depth: usize) -> Self {
        self.max_depth = max_depth;
        self
    }

    /// Set minimum severity threshold.
    pub fn with_min_severity(mut self, min_severity: Option<String>) -> Self {
        self.min_severity = min_severity;
        self
    }
}

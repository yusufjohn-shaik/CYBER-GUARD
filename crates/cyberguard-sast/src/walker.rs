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

//! Directory crawler and source file discovery with cycle detection and vendor exclusions.

use std::path::{Path, PathBuf};
use walkdir::{DirEntry, WalkDir};

use crate::context::ScanContext;

/// Determines if a directory or file entry should be excluded based on configured exclusion patterns.
fn is_excluded(entry: &DirEntry, excluded_patterns: &[String]) -> bool {
    let path_str = entry.path().to_string_lossy();
    let file_name = entry.file_name().to_string_lossy();

    for pattern in excluded_patterns {
        if file_name == pattern.as_str()
            || path_str.contains(&format!("/{}/", pattern))
            || path_str.ends_with(&format!("/{}", pattern))
        {
            return true;
        }
    }
    false
}

/// Checks if a file path matches allowed source code extensions.
fn is_supported_source(path: &Path, allowed_extensions: &[String]) -> bool {
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        let ext_lower = ext.to_ascii_lowercase();
        allowed_extensions
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(&ext_lower))
    } else {
        false
    }
}

/// Traverses the filesystem starting from `ctx.target_path` and collects valid source files.
/// Respects recursion limits, maximum file size, vendor exclusions, and symlink boundaries.
pub fn collect_source_files(ctx: &ScanContext) -> Vec<PathBuf> {
    if ctx.target_path.is_file() {
        return vec![ctx.target_path.clone()];
    }

    if !ctx.target_path.exists() {
        return Vec::new();
    }

    let mut files = Vec::new();
    let walker = WalkDir::new(&ctx.target_path)
        .max_depth(ctx.max_depth)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| !is_excluded(entry, &ctx.excluded_paths));

    for entry in walker.filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_file() && is_supported_source(path, &ctx.allowed_extensions) {
            if let Ok(metadata) = entry.metadata() {
                if metadata.len() <= ctx.max_file_size_bytes {
                    files.push(path.to_path_buf());
                }
            }
        }
    }

    files.sort();
    files
}

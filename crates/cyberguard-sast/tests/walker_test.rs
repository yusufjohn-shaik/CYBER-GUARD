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

use cyberguard_sast::{collect_source_files, ScanContext};
use std::fs;

#[test]
fn test_single_file_target() {
    let temp_dir = std::env::temp_dir().join(format!("cg_walker_single_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    let single_file = temp_dir.join("main.rs");
    fs::write(&single_file, "fn main() {}").unwrap();

    let ctx = ScanContext::new(single_file.clone());
    let collected = collect_source_files(&ctx);
    assert_eq!(collected.len(), 1);
    assert_eq!(collected[0], single_file);

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_walker_exclusions_and_extensions() {
    let test_root = std::env::temp_dir().join(format!("cg_walker_tree_{}", std::process::id()));
    let _ = fs::create_dir_all(test_root.join("src"));
    let _ = fs::create_dir_all(test_root.join("node_modules/dep"));
    let _ = fs::create_dir_all(test_root.join("target/debug"));
    let _ = fs::create_dir_all(test_root.join(".git/objects"));

    // Source files that should be included
    fs::write(test_root.join("src/lib.rs"), "pub fn add() {}").unwrap();
    fs::write(test_root.join("src/app.py"), "def run(): pass").unwrap();

    // Files that should be excluded by directory filter
    fs::write(test_root.join("node_modules/dep/index.js"), "console.log()").unwrap();
    fs::write(test_root.join("target/debug/build.rs"), "fn build() {}").unwrap();
    fs::write(test_root.join(".git/objects/commit.py"), "commit").unwrap();

    // Files that should be excluded by extension whitelist
    fs::write(test_root.join("src/data.json"), "{}").unwrap();
    fs::write(test_root.join("src/image.png"), "binary").unwrap();

    let ctx = ScanContext::new(&test_root);
    let files = collect_source_files(&ctx);

    assert_eq!(files.len(), 2);
    assert!(files.iter().any(|f| f.ends_with("src/lib.rs")));
    assert!(files.iter().any(|f| f.ends_with("src/app.py")));

    // Ensure none of the excluded paths leaked through
    for f in &files {
        let s = f.to_string_lossy();
        assert!(!s.contains("node_modules"));
        assert!(!s.contains("target"));
        assert!(!s.contains(".git"));
        assert!(!s.ends_with(".json"));
        assert!(!s.ends_with(".png"));
    }

    let _ = fs::remove_dir_all(&test_root);
}

#[test]
fn test_walker_depth_limiting() {
    let test_root = std::env::temp_dir().join(format!("cg_walker_depth_{}", std::process::id()));
    let deep_dir = test_root.join("level1/level2/level3/level4");
    let _ = fs::create_dir_all(&deep_dir);

    fs::write(test_root.join("root.rs"), "// root").unwrap();
    fs::write(deep_dir.join("deep.rs"), "// deep").unwrap();

    // Max depth 1: only root.rs should be visited
    let ctx = ScanContext::new(&test_root).with_max_depth(1);
    let files = collect_source_files(&ctx);

    assert_eq!(files.len(), 1);
    assert!(files[0].ends_with("root.rs"));

    let _ = fs::remove_dir_all(&test_root);
}

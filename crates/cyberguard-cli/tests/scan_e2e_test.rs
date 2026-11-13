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

use cyberguard_core::SarifLog;
use cyberguard_sast::{NativeRuleEngine, SastAnalyzer, ScanContext};
use std::fs;

#[tokio::test]
async fn test_end_to_end_sast_scan_flow() {
    let test_dir = std::env::temp_dir().join(format!("cg_e2e_scan_{}", std::process::id()));
    let _ = fs::create_dir_all(&test_dir);

    // 1. Write vulnerable source files
    let py_file = test_dir.join("vulnerable_app.py");
    let py_content = r#"
        def authenticate(username, password):
            query = "SELECT * FROM users WHERE user = '" + username + "'"
            return db.query(query)
    "#;
    fs::write(&py_file, py_content).unwrap();

    let js_file = test_dir.join("handler.js");
    let js_content = r#"
        function runBackup(dest) {
            exec("tar -czf backup.tar.gz " + dest);
        }
    "#;
    fs::write(&js_file, js_content).unwrap();

    // 2. Execute ScanContext and NativeRuleEngine
    let ctx = ScanContext::new(&test_dir);
    let engine = NativeRuleEngine::default();
    let findings = engine.analyze(&ctx).await.unwrap();

    assert_eq!(findings.len(), 2);
    assert!(findings.iter().any(|f| f.rule_id == "CG-SQLI-001"));
    assert!(findings.iter().any(|f| f.rule_id == "CG-CMDI-001"));

    // 3. Assemble full SARIF v2.1.0 log
    let mut sarif_log = SarifLog::new("CyberGuard SAST", env!("CARGO_PKG_VERSION"));
    for f in findings {
        sarif_log.add_result(f);
    }

    // Verify valid serialization
    let serialized_json = serde_json::to_string_pretty(&sarif_log).unwrap();
    assert!(serialized_json.contains("CyberGuard SAST"));
    assert!(serialized_json.contains("CG-SQLI-001"));
    assert!(serialized_json.contains("CG-CMDI-001"));
    assert!(serialized_json.contains("logicalLocationTokenHash/v1"));

    // 4. Cleanup
    let _ = fs::remove_dir_all(&test_dir);
}

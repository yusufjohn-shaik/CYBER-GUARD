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

use cyberguard_core::SarifLevel;
use cyberguard_sast::{NativeRuleEngine, SastAnalyzer, ScanContext};

#[test]
fn test_sqli_detection_true_positive() {
    let engine = NativeRuleEngine::default();
    let vulnerable_code = r#"
        def get_user(user_id):
            query = "SELECT * FROM users WHERE id = '" + user_id + "'"
            cursor.execute(query)
    "#;

    let findings = engine.scan_file_content("test.py", vulnerable_code);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "CG-SQLI-001");
    assert_eq!(findings[0].level, SarifLevel::Error);

    // Verify deterministic fingerprint was computed
    let fps = findings[0].partial_fingerprints.as_ref().unwrap();
    assert!(fps.contains_key("logicalLocationTokenHash/v1"));
}

#[test]
fn test_sqli_detection_true_negative_parameterized() {
    let engine = NativeRuleEngine::default();
    let safe_code = r#"
        def get_user(user_id):
            cursor.execute("SELECT * FROM users WHERE id = :id", {"id": user_id})
    "#;

    let findings = engine.scan_file_content("test.py", safe_code);
    let sqli_findings: Vec<_> = findings
        .into_iter()
        .filter(|f| f.rule_id == "CG-SQLI-001")
        .collect();
    assert_eq!(sqli_findings.len(), 0);
}

#[test]
fn test_cmdi_detection_true_positive() {
    let engine = NativeRuleEngine::default();
    let vulnerable_code = r#"
        const filename = req.query.file;
        exec("cat " + filename);
    "#;

    let findings = engine.scan_file_content("app.js", vulnerable_code);
    let cmdi = findings.iter().find(|f| f.rule_id == "CG-CMDI-001");
    assert!(cmdi.is_some());
    assert_eq!(cmdi.unwrap().level, SarifLevel::Error);
}

#[test]
fn test_hardcoded_secrets_detection() {
    let engine = NativeRuleEngine::default();

    // AWS Secret Key
    let aws_code = r#"
        let aws_key = "AKIAIOSFODNN7EXAMPLE";
    "#;
    let findings = engine.scan_file_content("aws.rs", aws_code);
    assert!(findings.iter().any(|f| f.rule_id == "CG-SECR-001"));

    // GitHub Personal Access Token
    let gh_code = r#"
        export GITHUB_TOKEN="ghp_123456789012345678901234567890123456"
    "#;
    let findings = engine.scan_file_content("env.sh", gh_code);
    assert!(findings.iter().any(|f| f.rule_id == "CG-SECR-001"));

    // PEM Private Key Block
    let pem_code = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...";
    let findings = engine.scan_file_content("cert.pem", pem_code);
    assert!(findings.iter().any(|f| f.rule_id == "CG-SECR-001"));
}

#[test]
fn test_path_traversal_detection() {
    let engine = NativeRuleEngine::default();
    let vulnerable_code = r#"
        let file_path = format!("../../etc/passwd");
    "#;

    let findings = engine.scan_file_content("main.rs", vulnerable_code);
    let path_finding = findings.iter().find(|f| f.rule_id == "CG-PATH-001");
    assert!(path_finding.is_some());
    assert_eq!(path_finding.unwrap().level, SarifLevel::Warning);
}

#[test]
fn test_broken_crypto_detection() {
    let engine = NativeRuleEngine::default();
    let vulnerable_code = r#"
        import hashlib
        h = hashlib.md5(password.encode()).hexdigest()
    "#;

    let findings = engine.scan_file_content("crypto.py", vulnerable_code);
    let crypto_finding = findings.iter().find(|f| f.rule_id == "CG-CRYP-001");
    assert!(crypto_finding.is_some());
    assert_eq!(crypto_finding.unwrap().level, SarifLevel::Warning);
}

#[tokio::test]
async fn test_analyzer_trait_severity_filter() {
    let engine = NativeRuleEngine::default();
    let temp_dir = std::env::temp_dir().join(format!("cg_sast_test_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let file_path = temp_dir.join("sample.py");

    let mixed_code = r#"
        query = "SELECT * FROM users WHERE id = '" + user_id + "'" # Error
        hasher = hashlib.md5() # Warning
    "#;
    std::fs::write(&file_path, mixed_code).unwrap();

    // Scan with no filter -> both Error and Warning returned
    let ctx_all = ScanContext::new(file_path.clone());
    let results_all = engine.analyze(&ctx_all).await.unwrap();
    assert_eq!(results_all.len(), 2);

    // Scan with min_severity = "error" -> only Error returned
    let ctx_error = ScanContext::new(file_path).with_min_severity(Some("error".into()));
    let results_error = engine.analyze(&ctx_error).await.unwrap();
    assert_eq!(results_error.len(), 1);
    assert_eq!(results_error[0].rule_id, "CG-SQLI-001");

    let _ = std::fs::remove_dir_all(&temp_dir);
}

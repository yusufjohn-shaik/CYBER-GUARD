use cyberguard_sca::engine::ScaEngine;
use cyberguard_sca::traits::ScaAnalyzer;
use std::fs;

#[tokio::test]
async fn test_sca_engine_end_to_end_scan_and_sarif_export() {
    let test_dir = std::env::temp_dir().join(format!("cyberguard-sca-test-{}", std::process::id()));
    let _ = fs::remove_dir_all(&test_dir);
    fs::create_dir_all(&test_dir).unwrap();

    let cargo_lock = test_dir.join("Cargo.lock");

    let lock_content = r#"
version = 3

[[package]]
name = "chrono"
version = "0.4.19"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "deadbeef"

[[package]]
name = "safe-pkg"
version = "1.0.0"
"#;

    fs::write(&cargo_lock, lock_content).unwrap();

    let engine = ScaEngine::new();
    let report = engine.scan(&test_dir).await.unwrap();

    assert_eq!(report.total_packages, 2);
    assert_eq!(report.findings.len(), 1);

    let finding = &report.findings[0];
    assert_eq!(finding.package.name, "chrono");
    assert_eq!(finding.vulnerability.id, "RUSTSEC-2020-0071");
    assert!(finding.tri_factor_score > 0.0);

    // Test SARIF serialization
    let sarif = engine.to_sarif_log(&report);
    assert_eq!(sarif.runs.len(), 1);
    assert_eq!(sarif.runs[0].results.len(), 1);
    assert_eq!(sarif.runs[0].results[0].rule_id, "RUSTSEC-2020-0071");

    let sarif_json = serde_json::to_string_pretty(&sarif).unwrap();
    assert!(sarif_json.contains("CyberGuard SCA"));
    assert!(sarif_json.contains("RUSTSEC-2020-0071"));

    let _ = fs::remove_dir_all(&test_dir);
}

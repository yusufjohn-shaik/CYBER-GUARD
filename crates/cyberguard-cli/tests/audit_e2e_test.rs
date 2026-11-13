use cyberguard_sca::engine::ScaEngine;
use cyberguard_sca::sbom::generate_cyclonedx_json;
use cyberguard_sca::traits::ScaAnalyzer;
use std::fs;

#[tokio::test]
async fn test_cli_audit_e2e_lockfile_discovery_and_sbom() {
    let test_dir =
        std::env::temp_dir().join(format!("cyberguard-audit-test-{}", std::process::id()));
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
name = "serde"
version = "1.0.210"
"#;
    fs::write(&cargo_lock, lock_content).unwrap();

    let engine = ScaEngine::new();
    let report = engine.scan(&test_dir).await.unwrap();

    assert_eq!(report.total_packages, 2);
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.findings[0].vulnerability.id, "RUSTSEC-2020-0071");

    // Test CycloneDX SBOM generation
    let sbom = generate_cyclonedx_json("test-app", &report.packages).unwrap();
    assert!(sbom.contains("CycloneDX"));
    assert!(sbom.contains("pkg:cargo/chrono@0.4.19"));
    assert!(sbom.contains("pkg:cargo/serde@1.0.210"));

    let _ = fs::remove_dir_all(&test_dir);
}

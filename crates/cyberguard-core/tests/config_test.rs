use cyberguard_core::config::CyberguardConfig;
use std::fs;
use std::path::PathBuf;

#[test]
fn test_default_configuration() {
    let config = CyberguardConfig::default();
    assert_eq!(config.general.workspace_dir, PathBuf::from("."));
    assert_eq!(config.general.log_level, "info");
    assert_eq!(config.process.timeout_seconds, 30);
    assert_eq!(config.process.max_output_bytes, 10 * 1024 * 1024);
    assert!(config.reporting.sarif_enabled);
}

#[test]
fn test_yaml_config_loading() {
    let tmp_dir = std::env::temp_dir().join(format!("cg_test_{}", std::process::id()));
    fs::create_dir_all(&tmp_dir).expect("Failed to create temp directory");
    let config_path = tmp_dir.join("cyberguard.yaml");

    let yaml_content = r#"
general:
  workspace_dir: "/tmp/custom_scan"
  log_level: "debug"
process:
  timeout_seconds: 60
  max_output_bytes: 5242880
reporting:
  sarif_enabled: true
  output_file: "/tmp/results.sarif"
"#;

    fs::write(&config_path, yaml_content).expect("Failed to write yaml config");

    let config =
        CyberguardConfig::load_from_path(&config_path).expect("Failed to load valid yaml config");

    assert_eq!(
        config.general.workspace_dir,
        PathBuf::from("/tmp/custom_scan")
    );
    assert_eq!(config.general.log_level, "debug");
    assert_eq!(config.process.timeout_seconds, 60);
    assert_eq!(config.process.max_output_bytes, 5242880);
    assert_eq!(
        config.reporting.output_file,
        Some(PathBuf::from("/tmp/results.sarif"))
    );

    let _ = fs::remove_dir_all(&tmp_dir);
}

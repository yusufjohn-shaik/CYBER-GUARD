use cyberguard_core::config::CyberguardConfig;
use cyberguard_core::error::ConfigError;
use std::fs;
use std::path::{Path, PathBuf};

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

#[test]
fn test_nonexistent_config_file_returns_error() {
    let nonexistent = Path::new("/path/does/not/exist/cyberguard.yaml");
    let result = CyberguardConfig::load_from_path(nonexistent);
    assert!(result.is_err());
    match result {
        Err(ConfigError::FileNotFound(path)) => {
            assert_eq!(path, nonexistent.to_path_buf());
        }
        _ => panic!("Expected ConfigError::FileNotFound"),
    }
}

#[test]
fn test_invalid_yaml_syntax_returns_parse_error() {
    let tmp_dir = std::env::temp_dir().join(format!("cg_test_invalid_{}", std::process::id()));
    fs::create_dir_all(&tmp_dir).expect("Failed to create temp directory");
    let config_path = tmp_dir.join("invalid.yaml");

    fs::write(&config_path, "general: [unclosed list").expect("Failed to write broken yaml");

    let result = CyberguardConfig::load_from_path(&config_path);
    assert!(result.is_err());
    match result {
        Err(ConfigError::ParseError(_)) => {}
        _ => panic!("Expected ConfigError::ParseError"),
    }

    let _ = fs::remove_dir_all(&tmp_dir);
}

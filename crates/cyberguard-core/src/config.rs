use crate::error::ConfigError;
use figment::providers::{Env, Format, Serialized, Yaml};
use figment::Figment;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Master configuration struct for CyberGuard.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CyberguardConfig {
    #[serde(default)]
    pub general: GeneralConfig,

    #[serde(default)]
    pub process: ProcessConfig,

    #[serde(default)]
    pub reporting: ReportingConfig,
}

/// General settings (directories, logging).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeneralConfig {
    pub workspace_dir: PathBuf,
    pub log_level: String,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            workspace_dir: PathBuf::from("."),
            log_level: "info".to_string(),
        }
    }
}

/// Settings for subprocess management and timeouts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessConfig {
    pub timeout_seconds: u64,
    pub max_output_bytes: usize,
}

impl Default for ProcessConfig {
    fn default() -> Self {
        Self {
            timeout_seconds: 30,
            max_output_bytes: 10 * 1024 * 1024, // 10 MB default bounded buffer
        }
    }
}

/// Settings for output generation and SARIF formatting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportingConfig {
    pub sarif_enabled: bool,
    pub output_file: Option<PathBuf>,
}

impl Default for ReportingConfig {
    fn default() -> Self {
        Self {
            sarif_enabled: true,
            output_file: None,
        }
    }
}

impl CyberguardConfig {
    /// Load configuration strictly from a given file path.
    pub fn load_from_path(path: &Path) -> Result<Self, ConfigError> {
        if !path.exists() {
            return Err(ConfigError::FileNotFound(path.to_path_buf()));
        }

        Figment::from(Serialized::defaults(CyberguardConfig::default()))
            .merge(Yaml::file(path))
            .extract()
            .map_err(|e| ConfigError::ParseError(e.to_string()))
    }

    /// Load layered configuration: Defaults -> File (if found) -> CYBERGUARD_* Environment variables.
    pub fn load_layered(optional_path: Option<&Path>) -> Result<Self, ConfigError> {
        let mut figment = Figment::from(Serialized::defaults(CyberguardConfig::default()));

        if let Some(path) = optional_path {
            if path.exists() {
                figment = figment.merge(Yaml::file(path));
            } else {
                return Err(ConfigError::FileNotFound(path.to_path_buf()));
            }
        } else {
            let default_path = Path::new("cyberguard.yaml");
            if default_path.exists() {
                figment = figment.merge(Yaml::file(default_path));
            }
        }

        figment
            .merge(Env::prefixed("CYBERGUARD_").split("__"))
            .extract()
            .map_err(|e| ConfigError::ParseError(e.to_string()))
    }
}

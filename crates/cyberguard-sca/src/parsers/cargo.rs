use crate::error::ScaError;
use crate::models::{Ecosystem, Package};
use crate::traits::LockfileParser;
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Default, Clone)]
pub struct CargoLockParser;

impl CargoLockParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Deserialize)]
struct RawCargoLock {
    #[serde(default)]
    package: Vec<RawCargoPackage>,
}

#[derive(Deserialize)]
struct RawCargoPackage {
    name: String,
    version: String,
    source: Option<String>,
    checksum: Option<String>,
    #[serde(default)]
    dependencies: Vec<String>,
}

impl LockfileParser for CargoLockParser {
    fn can_parse(&self, path: &Path) -> bool {
        path.file_name()
            .and_then(|f| f.to_str())
            .map(|name| name == "Cargo.lock")
            .unwrap_or(false)
    }

    fn parse(&self, path: &Path, content: &str) -> Result<Vec<Package>, ScaError> {
        let raw_lock: RawCargoLock = toml::from_str(content)
            .map_err(|e| ScaError::ParseError(path.to_path_buf(), e.to_string()))?;

        let mut packages = Vec::with_capacity(raw_lock.package.len());

        for raw_pkg in raw_lock.package {
            let is_direct = raw_pkg.source.is_none();
            let mut pkg = Package::new(
                raw_pkg.name,
                raw_pkg.version,
                Ecosystem::Cargo,
                raw_pkg.checksum,
                is_direct,
            );

            // Extract dependency package names (e.g., "memchr 2.7.4" -> "memchr")
            pkg.dependencies = raw_pkg
                .dependencies
                .into_iter()
                .map(|dep| dep.split_whitespace().next().unwrap_or(&dep).to_string())
                .collect();

            packages.push(pkg);
        }

        Ok(packages)
    }
}

use crate::error::ScaError;
use crate::models::{Ecosystem, Package};
use crate::traits::LockfileParser;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Default, Clone)]
pub struct NpmLockParser;

impl NpmLockParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Deserialize)]
struct RawNpmLock {
    #[serde(default)]
    packages: Option<HashMap<String, RawNpmPackage>>,
    #[serde(default)]
    dependencies: Option<HashMap<String, RawNpmV1Dependency>>,
}

#[derive(Deserialize)]
struct RawNpmPackage {
    version: Option<String>,
    integrity: Option<String>,
    #[serde(default)]
    dependencies: HashMap<String, String>,
}

#[derive(Deserialize)]
struct RawNpmV1Dependency {
    version: String,
    integrity: Option<String>,
    #[serde(default)]
    dependencies: Option<HashMap<String, RawNpmV1Dependency>>,
}

impl LockfileParser for NpmLockParser {
    fn can_parse(&self, path: &Path) -> bool {
        path.file_name()
            .and_then(|f| f.to_str())
            .map(|name| name == "package-lock.json")
            .unwrap_or(false)
    }

    fn parse(&self, path: &Path, content: &str) -> Result<Vec<Package>, ScaError> {
        let raw_lock: RawNpmLock = serde_json::from_str(content)
            .map_err(|e| ScaError::ParseError(path.to_path_buf(), e.to_string()))?;

        let mut packages = Vec::new();

        // 1. Try modern lockfile v2/v3 (packages map)
        if let Some(packages_map) = raw_lock.packages {
            for (key, raw_pkg) in packages_map {
                if key.is_empty() {
                    continue; // Skip root project definition
                }

                let version = match raw_pkg.version {
                    Some(v) => v,
                    None => continue,
                };

                // Extract package name from node_modules path
                // e.g. "node_modules/@types/node" -> "@types/node"
                // e.g. "node_modules/express/node_modules/ms" -> "ms"
                let pkg_name = if let Some(idx) = key.rfind("node_modules/") {
                    &key[idx + "node_modules/".len()..]
                } else {
                    &key
                };

                let is_direct = key.matches("node_modules/").count() == 1;

                let mut pkg = Package::new(
                    pkg_name,
                    version,
                    Ecosystem::Npm,
                    raw_pkg.integrity,
                    is_direct,
                );

                pkg.dependencies = raw_pkg.dependencies.into_keys().collect();
                packages.push(pkg);
            }
        } else if let Some(deps_map) = raw_lock.dependencies {
            // 2. Fallback to v1 dependencies tree
            fn traverse_v1_deps(
                deps: HashMap<String, RawNpmV1Dependency>,
                is_direct: bool,
                out: &mut Vec<Package>,
            ) {
                for (name, dep) in deps {
                    let mut pkg = Package::new(
                        &name,
                        &dep.version,
                        Ecosystem::Npm,
                        dep.integrity,
                        is_direct,
                    );

                    if let Some(nested) = dep.dependencies {
                        pkg.dependencies = nested.keys().cloned().collect();
                        traverse_v1_deps(nested, false, out);
                    }

                    out.push(pkg);
                }
            }

            traverse_v1_deps(deps_map, true, &mut packages);
        }

        Ok(packages)
    }
}

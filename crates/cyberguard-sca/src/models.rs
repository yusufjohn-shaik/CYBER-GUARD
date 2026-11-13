use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Ecosystem {
    Cargo,
    Npm,
    PyPi,
}

impl Ecosystem {
    pub fn as_purl_type(&self) -> &'static str {
        match self {
            Ecosystem::Cargo => "cargo",
            Ecosystem::Npm => "npm",
            Ecosystem::PyPi => "pypi",
        }
    }
}

/// Represents an identified third-party dependency package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub ecosystem: Ecosystem,
    pub purl: String,
    pub checksum: Option<String>,
    pub is_direct: bool,
    pub dependencies: Vec<String>,
}

impl Package {
    pub fn new(
        name: impl Into<String>,
        version: impl Into<String>,
        ecosystem: Ecosystem,
        checksum: Option<String>,
        is_direct: bool,
    ) -> Self {
        let name_str = name.into();
        let version_str = version.into();

        // Standard Package URL (PURL) encoding
        // npm scoped packages (@scope/name) become pkg:npm/%40scope/name@version
        let purl_name = if ecosystem == Ecosystem::Npm && name_str.starts_with('@') {
            name_str.replace('@', "%40")
        } else {
            name_str.clone()
        };

        let purl = format!(
            "pkg:{}/{}@{}",
            ecosystem.as_purl_type(),
            purl_name,
            version_str
        );

        Self {
            name: name_str,
            version: version_str,
            ecosystem,
            purl,
            checksum,
            is_direct,
            dependencies: Vec::new(),
        }
    }
}

/// Known security advisory vulnerability.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Vulnerability {
    pub id: String,
    pub cve: Option<String>,
    pub package_name: String,
    pub ecosystem: Ecosystem,
    pub affected_range: String,
    pub fixed_version: Option<String>,
    pub summary: String,
    pub details: String,
    pub severity: String,
    pub cvss: f64,
    pub epss: f64,
}

/// Specific finding matched against a dependency.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScaFinding {
    pub package: Package,
    pub vulnerability: Vulnerability,
    pub reachability: f64,
    pub tri_factor_score: f64,
}

/// Summary report of an SCA scan across one or more lockfiles.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScaReport {
    pub target_path: PathBuf,
    pub lockfiles_scanned: Vec<PathBuf>,
    pub total_packages: usize,
    pub direct_dependencies: usize,
    pub transitive_dependencies: usize,
    pub packages: Vec<Package>,
    pub findings: Vec<ScaFinding>,
}

impl ScaReport {
    pub fn new(target_path: PathBuf) -> Self {
        Self {
            target_path,
            ..Default::default()
        }
    }
}

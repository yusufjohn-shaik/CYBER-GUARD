use crate::models::{Ecosystem, Package, Vulnerability};
use semver::{Version, VersionReq};

#[derive(Debug, Clone)]
pub struct VulnerabilityDatabase {
    advisories: Vec<Vulnerability>,
}

impl VulnerabilityDatabase {
    pub fn new(advisories: Vec<Vulnerability>) -> Self {
        Self { advisories }
    }

    /// Initializes the embedded catalog of known high-severity open-source vulnerabilities.
    pub fn embedded() -> Self {
        let advisories = vec![
            // 1. Cargo: chrono
            Vulnerability {
                id: "RUSTSEC-2020-0071".to_string(),
                cve: Some("CVE-2020-35873".to_string()),
                package_name: "chrono".to_string(),
                ecosystem: Ecosystem::Cargo,
                affected_range: "< 0.4.20".to_string(),
                fixed_version: Some("0.4.20".to_string()),
                summary: "Potential use-after-free or memory corruption via localtime_r".to_string(),
                details: "A flaw in the formatting routines of chrono could allow segmentation fault or arbitrary read.".to_string(),
                severity: "HIGH".to_string(),
                cvss: 7.5,
                epss: 0.12,
            },
            // 2. Cargo: tokio
            Vulnerability {
                id: "RUSTSEC-2021-0145".to_string(),
                cve: Some("CVE-2021-45710".to_string()),
                package_name: "tokio".to_string(),
                ecosystem: Ecosystem::Cargo,
                affected_range: ">= 0.1.13, < 1.13.1".to_string(),
                fixed_version: Some("1.13.1".to_string()),
                summary: "Data race in tokio::sync::mpsc and task join handle".to_string(),
                details: "Race condition in tokio synchronization primitives leading to potential memory unsafety.".to_string(),
                severity: "HIGH".to_string(),
                cvss: 7.0,
                epss: 0.08,
            },
            // 3. Cargo: crossbeam-channel
            Vulnerability {
                id: "RUSTSEC-2020-0159".to_string(),
                cve: Some("CVE-2020-36470".to_string()),
                package_name: "crossbeam-channel".to_string(),
                ecosystem: Ecosystem::Cargo,
                affected_range: "< 0.5.2".to_string(),
                fixed_version: Some("0.5.2".to_string()),
                summary: "Data race in crossbeam-channel bounded queue".to_string(),
                details: "A data race in the select mechanism could result in undefined behavior under high concurrency.".to_string(),
                severity: "HIGH".to_string(),
                cvss: 7.5,
                epss: 0.05,
            },
            // 4. npm: lodash
            Vulnerability {
                id: "GHSA-p6mc-m468-83gw".to_string(),
                cve: Some("CVE-2020-8203".to_string()),
                package_name: "lodash".to_string(),
                ecosystem: Ecosystem::Npm,
                affected_range: "< 4.17.21".to_string(),
                fixed_version: Some("4.17.21".to_string()),
                summary: "Prototype Pollution in lodash via zipObjectDeep".to_string(),
                details: "Prototype pollution in lodash allows unprivileged attackers to modify Object.prototype properties.".to_string(),
                severity: "HIGH".to_string(),
                cvss: 7.4,
                epss: 0.72,
            },
            // 5. npm: minimist
            Vulnerability {
                id: "GHSA-xvch-5ox4-994e".to_string(),
                cve: Some("CVE-2021-44906".to_string()),
                package_name: "minimist".to_string(),
                ecosystem: Ecosystem::Npm,
                affected_range: "< 1.2.6".to_string(),
                fixed_version: Some("1.2.6".to_string()),
                summary: "Prototype Pollution in minimist argument parsing".to_string(),
                details: "Minimist before 1.2.6 is vulnerable to Prototype Pollution via __proto__ argument keys.".to_string(),
                severity: "CRITICAL".to_string(),
                cvss: 9.8,
                epss: 0.85,
            },
            // 6. npm: express
            Vulnerability {
                id: "GHSA-qw6h-v559-w3pj".to_string(),
                cve: Some("CVE-2024-21508".to_string()),
                package_name: "express".to_string(),
                ecosystem: Ecosystem::Npm,
                affected_range: "< 4.19.2".to_string(),
                fixed_version: Some("4.19.2".to_string()),
                summary: "Regular Expression Denial of Service in express routing".to_string(),
                details: "RedoS vulnerability allows remote attackers to cause high CPU usage and denial of service.".to_string(),
                severity: "MEDIUM".to_string(),
                cvss: 5.3,
                epss: 0.15,
            },
        ];

        Self { advisories }
    }

    /// Evaluates if a given package version matches known security advisories.
    pub fn find_vulnerabilities(&self, package: &Package) -> Vec<Vulnerability> {
        let clean_version = package.version.trim_start_matches('v');
        let pkg_semver = match Version::parse(clean_version) {
            Ok(v) => v,
            Err(_) => return Vec::new(),
        };

        let mut matches = Vec::new();

        for advisory in &self.advisories {
            if advisory.ecosystem == package.ecosystem && advisory.package_name == package.name {
                if let Ok(req) = VersionReq::parse(&advisory.affected_range) {
                    if req.matches(&pkg_semver) {
                        matches.push(advisory.clone());
                    }
                }
            }
        }

        matches
    }
}

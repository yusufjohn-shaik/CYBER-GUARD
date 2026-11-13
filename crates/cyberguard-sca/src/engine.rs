use crate::db::VulnerabilityDatabase;
use crate::error::ScaError;
use crate::models::{ScaFinding, ScaReport};
use crate::parsers::{CargoLockParser, NpmLockParser};
use crate::traits::{LockfileParser, ScaAnalyzer};
use async_trait::async_trait;
use cyberguard_core::sarif::{Message, ReportingDescriptor, SarifLevel, SarifLog, SarifResult};
use std::fs;
use std::path::Path;
use walkdir::WalkDir;

/// Production SCA Engine for lockfile discovery, SBOM extraction, and vulnerability matching.
pub struct ScaEngine {
    db: VulnerabilityDatabase,
    parsers: Vec<Box<dyn LockfileParser>>,
}

impl Default for ScaEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl ScaEngine {
    pub fn new() -> Self {
        let parsers: Vec<Box<dyn LockfileParser>> = vec![
            Box::new(CargoLockParser::new()),
            Box::new(NpmLockParser::new()),
        ];

        Self {
            db: VulnerabilityDatabase::embedded(),
            parsers,
        }
    }

    pub fn with_database(db: VulnerabilityDatabase) -> Self {
        let parsers: Vec<Box<dyn LockfileParser>> = vec![
            Box::new(CargoLockParser::new()),
            Box::new(NpmLockParser::new()),
        ];

        Self { db, parsers }
    }

    /// Converts an SCA scan report into standard OASIS SARIF v2.1.0 telemetry.
    pub fn to_sarif_log(&self, report: &ScaReport) -> SarifLog {
        let mut sarif_log = SarifLog::new("CyberGuard SCA", env!("CARGO_PKG_VERSION"));

        for finding in &report.findings {
            let level = if finding.vulnerability.cvss >= 7.0 {
                SarifLevel::Error
            } else {
                SarifLevel::Warning
            };

            let message = format!(
                "Known vulnerability {} ({}) in dependency {}@{}. {}",
                finding.vulnerability.id,
                finding.vulnerability.cve.as_deref().unwrap_or("N/A"),
                finding.package.name,
                finding.package.version,
                finding.vulnerability.summary
            );

            let mut result = SarifResult::new(&finding.vulnerability.id, level, message);

            // Add location referencing the scanned lockfile
            let file_str = report
                .lockfiles_scanned
                .first()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|| "lockfile".to_string());

            result.add_location(&file_str, 1, Some(1), Some(1), Some(1));

            // Set Tri-Factor risk score properties
            result.with_tri_factor(
                finding.vulnerability.cvss,
                finding.vulnerability.epss,
                finding.reachability,
            );

            // Compute deterministic BLAKE3/SHA-256 fingerprint
            result.compute_deterministic_fingerprint();

            sarif_log.add_result(result);

            // Register rule descriptor if not already present
            let rule = ReportingDescriptor {
                id: finding.vulnerability.id.clone(),
                name: finding.vulnerability.cve.clone(),
                short_description: Message {
                    text: finding.vulnerability.summary.clone(),
                },
                full_description: Some(Message {
                    text: finding.vulnerability.details.clone(),
                }),
                help_uri: Some(format!(
                    "https://osv.dev/vulnerability/{}",
                    finding.vulnerability.id
                )),
            };

            sarif_log.add_rule(rule);
        }

        sarif_log
    }
}

#[async_trait]
impl ScaAnalyzer for ScaEngine {
    async fn scan(&self, target: &Path) -> Result<ScaReport, ScaError> {
        let mut report = ScaReport::new(target.to_path_buf());

        let mut lockfiles = Vec::new();

        if target.is_file() {
            lockfiles.push(target.to_path_buf());
        } else if target.is_dir() {
            for entry in WalkDir::new(target)
                .follow_links(false)
                .into_iter()
                .filter_entry(|e| {
                    let file_name = e.file_name().to_string_lossy();
                    !file_name.starts_with('.')
                        && file_name != "target"
                        && file_name != "node_modules"
                        && file_name != "vendor"
                        && file_name != "dist"
                })
                .flatten()
            {
                let path = entry.path();
                if path.is_file() {
                    for parser in &self.parsers {
                        if parser.can_parse(path) {
                            lockfiles.push(path.to_path_buf());
                            break;
                        }
                    }
                }
            }
        }

        report.lockfiles_scanned = lockfiles.clone();

        for lockfile in lockfiles {
            let content = fs::read_to_string(&lockfile)?;
            for parser in &self.parsers {
                if parser.can_parse(&lockfile) {
                    let packages = parser.parse(&lockfile, &content)?;
                    for pkg in packages {
                        let is_direct = pkg.is_direct;
                        let vulns = self.db.find_vulnerabilities(&pkg);

                        for v in vulns {
                            let reachability = if is_direct { 1.0 } else { 0.6 };
                            let tri_factor_raw = v.cvss * v.epss * reachability;
                            let tri_factor_score = (tri_factor_raw * 100.0).round() / 100.0;

                            report.findings.push(ScaFinding {
                                package: pkg.clone(),
                                vulnerability: v,
                                reachability,
                                tri_factor_score,
                            });
                        }

                        if is_direct {
                            report.direct_dependencies += 1;
                        } else {
                            report.transitive_dependencies += 1;
                        }

                        report.packages.push(pkg);
                    }
                    break;
                }
            }
        }

        report.total_packages = report.packages.len();

        Ok(report)
    }
}

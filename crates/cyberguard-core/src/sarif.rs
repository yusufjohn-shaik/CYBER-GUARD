use crate::ocsf::{
    OcsfFindingInfo, OcsfProduct, OcsfSeverity, OcsfVulnerability, OcsfVulnerabilityFinding,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// Root object of a SARIF v2.1.0 report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifLog {
    pub version: String,
    #[serde(rename = "$schema")]
    pub schema: String,
    pub runs: Vec<Run>,
}

impl SarifLog {
    /// Create a new SARIF log initialized with the CyberGuard tool driver.
    pub fn new(tool_name: &str, tool_version: &str) -> Self {
        Self {
            version: "2.1.0".to_string(),
            schema: "https://json.schemastore.org/sarif-2.1.0.json".to_string(),
            runs: vec![Run {
                tool: Tool {
                    driver: Driver {
                        name: tool_name.to_string(),
                        version: tool_version.to_string(),
                        information_uri: "https://github.com/yusufjohn-shaik/CYBER-GUARD"
                            .to_string(),
                        rules: Vec::new(),
                    },
                },
                results: Vec::new(),
            }],
        }
    }

    /// Register a rule definition into the primary tool driver.
    pub fn add_rule(&mut self, rule: ReportingDescriptor) {
        if let Some(run) = self.runs.first_mut() {
            run.tool.driver.rules.push(rule);
        }
    }

    /// Add a vulnerability finding result to the primary run.
    pub fn add_result(&mut self, result: SarifResult) {
        if let Some(run) = self.runs.first_mut() {
            run.results.push(result);
        }
    }

    /// Convert all SARIF findings to a sequence of OCSF v1.3.0 Vulnerability Finding events.
    pub fn to_ocsf(&self) -> Vec<OcsfVulnerabilityFinding> {
        let mut events = Vec::new();
        for run in &self.runs {
            let tool_name = &run.tool.driver.name;
            for res in &run.results {
                events.push(res.to_ocsf(tool_name));
            }
        }
        events
    }
}

/// A single execution run within the SARIF log.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Run {
    pub tool: Tool,
    pub results: Vec<SarifResult>,
}

/// Information about the tool that generated the run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Tool {
    pub driver: Driver,
}

/// Primary component (driver) descriptor.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Driver {
    pub name: String,
    pub version: String,
    pub information_uri: String,
    pub rules: Vec<ReportingDescriptor>,
}

/// Metadata descriptor for a vulnerability check rule.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportingDescriptor {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub short_description: Message,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub full_description: Option<Message>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub help_uri: Option<String>,
}

/// Standardized finding result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifResult {
    pub rule_id: String,
    pub level: SarifLevel,
    pub message: Message,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub locations: Vec<Location>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub code_flows: Vec<CodeFlow>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fixes: Vec<Fix>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partial_fingerprints: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<serde_json::Value>,
}

impl SarifResult {
    /// Create a new SarifResult with required fields.
    pub fn new(rule_id: impl Into<String>, level: SarifLevel, message: impl Into<String>) -> Self {
        Self {
            rule_id: rule_id.into(),
            level,
            message: Message {
                text: message.into(),
            },
            locations: Vec::new(),
            code_flows: Vec::new(),
            fixes: Vec::new(),
            partial_fingerprints: None,
            properties: None,
        }
    }

    /// Add a physical file location to the finding.
    pub fn add_location(
        &mut self,
        uri: impl Into<String>,
        start_line: usize,
        start_column: Option<usize>,
        end_line: Option<usize>,
        end_column: Option<usize>,
    ) {
        self.locations.push(Location {
            physical_location: Some(PhysicalLocation {
                artifact_location: ArtifactLocation { uri: uri.into() },
                region: Some(Region {
                    start_line,
                    start_column,
                    end_line,
                    end_column,
                }),
            }),
        });
    }

    /// Add a taint/call-graph code flow.
    pub fn add_code_flow(&mut self, code_flow: CodeFlow) {
        self.code_flows.push(code_flow);
    }

    /// Add a proposed surgical code fix.
    pub fn add_fix(&mut self, fix: Fix) {
        self.fixes.push(fix);
    }

    /// Attach CyberGuard Tri-Factor risk index metadata (`cvss`, `epss`, `reachability`).
    pub fn with_tri_factor(&mut self, cvss: f64, epss: f64, reachability: f64) {
        let tri_factor = (cvss * epss * reachability * 100.0).round() / 100.0;
        let mut props = match self.properties.take() {
            Some(serde_json::Value::Object(map)) => map,
            _ => serde_json::Map::new(),
        };

        props.insert("cvss".to_string(), serde_json::json!(cvss));
        props.insert("epss".to_string(), serde_json::json!(epss));
        props.insert("reachability".to_string(), serde_json::json!(reachability));
        props.insert("triFactorScore".to_string(), serde_json::json!(tri_factor));

        self.properties = Some(serde_json::Value::Object(props));
    }

    /// Compute a deterministic partial fingerprint (BLAKE3/SHA-256) based on rule and logical location.
    pub fn compute_deterministic_fingerprint(&mut self) {
        let mut hasher = Sha256::new();
        hasher.update(self.rule_id.as_bytes());

        if let Some(loc) = self.locations.first() {
            if let Some(ref phys) = loc.physical_location {
                hasher.update(phys.artifact_location.uri.as_bytes());
                if let Some(ref reg) = phys.region {
                    hasher.update(reg.start_line.to_string().as_bytes());
                }
            }
        }

        let hash_hex = format!("{:x}", hasher.finalize());
        let mut map = self.partial_fingerprints.take().unwrap_or_default();
        map.insert("logicalLocationTokenHash/v1".to_string(), hash_hex);
        self.partial_fingerprints = Some(map);
    }

    /// Convert this SARIF result into an OCSF v1.3.0 Vulnerability Finding event.
    pub fn to_ocsf(&self, product_name: &str) -> OcsfVulnerabilityFinding {
        let cvss = self
            .properties
            .as_ref()
            .and_then(|p| p.get("cvss")?.as_f64());
        let epss = self
            .properties
            .as_ref()
            .and_then(|p| p.get("epss")?.as_f64());
        let reach = self
            .properties
            .as_ref()
            .and_then(|p| p.get("reachability")?.as_f64());
        let tri_factor = self
            .properties
            .as_ref()
            .and_then(|p| p.get("triFactorScore")?.as_f64());

        let severity = match self.level {
            SarifLevel::Error => {
                if cvss.unwrap_or(0.0) >= 9.0 {
                    OcsfSeverity::Critical
                } else {
                    OcsfSeverity::High
                }
            }
            SarifLevel::Warning => OcsfSeverity::Medium,
            SarifLevel::Note => OcsfSeverity::Low,
            SarifLevel::None => OcsfSeverity::Informational,
        };

        OcsfVulnerabilityFinding {
            activity_id: 1, // Create
            activity_name: "Create".to_string(),
            category_uid: 2, // Findings
            category_name: "Findings".to_string(),
            class_uid: 2001, // Vulnerability Finding
            class_name: "Vulnerability Finding".to_string(),
            severity_id: severity as u8,
            severity: format!("{:?}", severity),
            status_id: 1, // New
            status: "New".to_string(),
            time: chrono::Utc::now().timestamp_millis(),
            metadata: OcsfProduct {
                product: product_name.to_string(),
                version: "0.3.0".to_string(),
            },
            finding_info: OcsfFindingInfo {
                title: self.rule_id.clone(),
                description: self.message.text.clone(),
            },
            vulnerabilities: vec![OcsfVulnerability {
                cve: self.rule_id.clone(),
                cvss_score: cvss,
                epss_score: epss,
                reachability: reach,
                tri_factor_score: tri_factor,
            }],
        }
    }
}

/// Severity level of a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SarifLevel {
    None,
    Note,
    Warning,
    Error,
}

/// Encapsulates human-readable message text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Message {
    pub text: String,
}

/// Physical location of an identified vulnerability.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Location {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub physical_location: Option<PhysicalLocation>,
}

/// Concrete file and region details.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PhysicalLocation {
    pub artifact_location: ArtifactLocation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<Region>,
}

/// Artifact URI pointer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactLocation {
    pub uri: String,
}

/// Text line and column boundaries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Region {
    pub start_line: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_column: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_line: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_column: Option<usize>,
}

/// Represents a multi-step taint or call-graph path.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CodeFlow {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<Message>,
    pub thread_flows: Vec<ThreadFlow>,
}

/// Execution steps within a single thread of execution.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ThreadFlow {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<Message>,
    pub locations: Vec<ThreadFlowLocation>,
}

/// A single step in a taint or execution flow.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ThreadFlowLocation {
    pub location: Location,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub step: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub importance: Option<String>,
}

/// Proposed surgical code remediation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Fix {
    pub description: Message,
    pub artifact_changes: Vec<ArtifactChange>,
}

/// File-level changes within a proposed fix.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactChange {
    pub artifact_location: ArtifactLocation,
    pub replacements: Vec<Replacement>,
}

/// Specific text substitution within an artifact.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Replacement {
    pub deleted_region: Region,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inserted_content: Option<Message>,
}

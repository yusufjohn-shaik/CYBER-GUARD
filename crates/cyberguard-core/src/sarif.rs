use serde::{Deserialize, Serialize};

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
    pub locations: Vec<Location>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<serde_json::Value>,
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

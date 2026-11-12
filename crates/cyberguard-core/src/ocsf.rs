use serde::{Deserialize, Serialize};

/// OCSF Severity numeric rankings and labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum OcsfSeverity {
    Unknown = 0,
    Informational = 1,
    Low = 2,
    Medium = 3,
    High = 4,
    Critical = 5,
    Fatal = 6,
}

/// OCSF v1.3.0 Vulnerability Finding Event (Class UID 2001, Category UID 2: Findings).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OcsfVulnerabilityFinding {
    pub activity_id: u8,
    pub activity_name: String,
    pub category_uid: u16,
    pub category_name: String,
    pub class_uid: u16,
    pub class_name: String,
    pub severity_id: u8,
    pub severity: String,
    pub status_id: u8,
    pub status: String,
    pub time: i64,
    pub metadata: OcsfProduct,
    pub finding_info: OcsfFindingInfo,
    pub vulnerabilities: Vec<OcsfVulnerability>,
}

/// Information about the scanning product/tool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OcsfProduct {
    pub product: String,
    pub version: String,
}

/// High-level finding details.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OcsfFindingInfo {
    pub title: String,
    pub description: String,
}

/// Detailed vulnerability data, including CyberGuard Tri-Factor risk score.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OcsfVulnerability {
    pub cve: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cvss_score: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epss_score: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reachability: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tri_factor_score: Option<f64>,
}

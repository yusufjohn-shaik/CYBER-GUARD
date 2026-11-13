// Copyright 2026 CyberGuard Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Rule definitions and severity thresholds for static analysis scanning.

use cyberguard_core::SarifLevel;
use regex::Regex;

/// Definition of a single static analysis security rule.
#[derive(Clone, Debug)]
pub struct SastRule {
    /// Unique rule identifier (e.g., `CG-SQLI-001`).
    pub id: String,
    /// Human-readable rule name.
    pub name: String,
    /// Default SARIF severity level.
    pub severity: SarifLevel,
    /// Linear-time regular expression pattern.
    pub pattern: Regex,
    /// Vulnerability remediation guidance message.
    pub message: String,
    /// Documentation or standard CWE reference URI.
    pub help_uri: String,
    /// Common Weakness Enumeration identifier (e.g., `CWE-89`).
    pub cwe: String,
}

impl SastRule {
    /// Create a new SAST rule definition.
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        severity: SarifLevel,
        pattern_str: &str,
        message: impl Into<String>,
        help_uri: impl Into<String>,
        cwe: impl Into<String>,
    ) -> Result<Self, regex::Error> {
        let pattern = Regex::new(pattern_str)?;
        Ok(Self {
            id: id.into(),
            name: name.into(),
            severity,
            pattern,
            message: message.into(),
            help_uri: help_uri.into(),
            cwe: cwe.into(),
        })
    }
}

/// Minimum severity threshold filter for query results.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SeverityThreshold {
    /// Informational note level.
    Note = 0,
    /// Warning level.
    Warning = 1,
    /// Critical / Error level.
    Error = 2,
}

impl SeverityThreshold {
    /// Parse from case-insensitive string slice.
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "note" | "info" => Some(Self::Note),
            "warning" | "warn" => Some(Self::Warning),
            "error" | "err" | "critical" => Some(Self::Error),
            _ => None,
        }
    }

    /// Check if a SarifLevel meets or exceeds this threshold.
    pub fn matches(&self, level: &SarifLevel) -> bool {
        let level_val = match level {
            SarifLevel::Note => 0,
            SarifLevel::Warning => 1,
            SarifLevel::Error => 2,
            SarifLevel::None => 0,
        };
        level_val >= (*self as usize)
    }
}

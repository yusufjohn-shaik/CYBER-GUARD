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

//! In-process Static Application Security Testing (SAST) rule execution engine.

use async_trait::async_trait;
use cyberguard_core::{CyberguardError, SarifResult};
use std::fs;

use crate::context::ScanContext;
use crate::rules::{default_rules, SastRule, SeverityThreshold};
use crate::traits::SastAnalyzer;
use crate::walker::collect_source_files;

/// High-performance in-process SAST rule evaluation engine.
#[derive(Clone, Debug)]
pub struct NativeRuleEngine {
    rules: Vec<SastRule>,
}

impl Default for NativeRuleEngine {
    fn default() -> Self {
        Self {
            rules: default_rules(),
        }
    }
}

impl NativeRuleEngine {
    /// Create a new engine initialized with specific rules.
    pub fn new(rules: Vec<SastRule>) -> Self {
        Self { rules }
    }

    /// Access the registered rule suite.
    pub fn rules(&self) -> &[SastRule] {
        &self.rules
    }

    /// Calculate line number and column number from byte offset in text.
    fn calculate_position(text: &str, byte_offset: usize) -> (usize, usize) {
        let prefix = &text[..byte_offset];
        let line = prefix.lines().count().max(1);
        let col = match prefix.rfind('\n') {
            Some(pos) => byte_offset - pos,
            None => byte_offset + 1,
        };
        (line, col)
    }

    /// Scan string content of a file against all registered rules.
    pub fn scan_file_content(&self, file_path: &str, content: &str) -> Vec<SarifResult> {
        let mut results = Vec::new();

        for rule in &self.rules {
            for mat in rule.pattern.find_iter(content) {
                let (start_line, start_col) = Self::calculate_position(content, mat.start());
                let (end_line, end_col) = Self::calculate_position(content, mat.end());

                let mut result = SarifResult::new(&rule.id, rule.severity, &rule.message);
                result.add_location(
                    file_path,
                    start_line,
                    Some(start_col),
                    Some(end_line),
                    Some(end_col),
                );

                let mut props = serde_json::Map::new();
                props.insert("cwe".to_string(), serde_json::json!(rule.cwe));
                props.insert("ruleName".to_string(), serde_json::json!(rule.name));
                props.insert("helpUri".to_string(), serde_json::json!(rule.help_uri));
                result.properties = Some(serde_json::Value::Object(props));

                // Compute deterministic fingerprint based on rule_id and logical location
                result.compute_deterministic_fingerprint();

                results.push(result);
            }
        }

        results
    }
}

#[async_trait]
impl SastAnalyzer for NativeRuleEngine {
    fn name(&self) -> &str {
        "cyberguard-native-sast"
    }

    async fn analyze(&self, ctx: &ScanContext) -> Result<Vec<SarifResult>, CyberguardError> {
        let source_files = collect_source_files(ctx);
        let mut all_results = Vec::new();

        for file_path in source_files {
            let path_str = file_path.to_string_lossy().to_string();
            match fs::read_to_string(&file_path) {
                Ok(content) => {
                    let mut file_findings = self.scan_file_content(&path_str, &content);
                    all_results.append(&mut file_findings);
                }
                Err(err) => {
                    tracing::debug!(
                        path = %path_str,
                        error = %err,
                        "Skipping unreadable or non-UTF8 source file"
                    );
                }
            }
        }

        // Apply minimum severity filtering if specified in context
        if let Some(ref min_sev) = ctx.min_severity {
            if let Some(threshold) = SeverityThreshold::parse(min_sev) {
                all_results.retain(|res| threshold.matches(&res.level));
            }
        }

        Ok(all_results)
    }
}

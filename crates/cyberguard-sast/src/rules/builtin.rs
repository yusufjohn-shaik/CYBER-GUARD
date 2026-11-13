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

//! Built-in static analysis security rules covering core OWASP Top 10 vulnerabilities.

use cyberguard_core::SarifLevel;

use super::rule::SastRule;

/// Compile and return the complete suite of default in-process SAST rules.
pub fn default_rules() -> Vec<SastRule> {
    vec![
        SastRule::new(
            "CG-SQLI-001",
            "SQL Injection via Unsanitized Formatting",
            SarifLevel::Error,
            r"(?i)(SELECT|INSERT|UPDATE|DELETE)\s+.*(\+|%s|\{\}|\$|#\{|\.format\()",
            "Potential SQL injection via raw string interpolation or concatenation. Use parameterized queries or prepared statements.",
            "https://cwe.mitre.org/data/definitions/89.html",
            "CWE-89",
        ).expect("Valid SQLI rule regex"),

        SastRule::new(
            "CG-CMDI-001",
            "OS Command Injection via Shell Invocation",
            SarifLevel::Error,
            r"(?i)(system|exec|spawn|popen)\s*\(\s*.*(\+|%s|\{\}|\$|\.format\()",
            "Potential OS command injection via unescaped string in command invocation. Avoid executing raw shell commands with user inputs.",
            "https://cwe.mitre.org/data/definitions/78.html",
            "CWE-78",
        ).expect("Valid CMDI rule regex"),

        SastRule::new(
            "CG-SECR-001",
            "Hardcoded Cryptographic Secret or API Token",
            SarifLevel::Error,
            r"(?i)(AKIA[0-9A-Z]{16}|ghp_[0-9a-zA-Z]{36}|-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)",
            "Hardcoded cryptographic secret or API token detected in source code. Store secrets in environment variables or a secret vault.",
            "https://cwe.mitre.org/data/definitions/798.html",
            "CWE-798",
        ).expect("Valid SECR rule regex"),

        SastRule::new(
            "CG-PATH-001",
            "Path Traversal via Unvalidated Relative Path Sequence",
            SarifLevel::Warning,
            r"(?i)\.\./|\.\.\\",
            "Potential directory traversal via unvalidated relative path sequence. Sanitize and canonicalize file paths.",
            "https://cwe.mitre.org/data/definitions/22.html",
            "CWE-22",
        ).expect("Valid PATH rule regex"),

        SastRule::new(
            "CG-CRYP-001",
            "Broken Cryptographic Primitives (MD5/SHA1)",
            SarifLevel::Warning,
            r"(?i)(md5::new|sha1::new|CryptoJS\.MD5|CryptoJS\.SHA1|hashlib\.md5|hashlib\.sha1)",
            "Broken or cryptographically weak hashing algorithm (MD5/SHA1) detected. Upgrade to SHA-256, SHA-3, or BLAKE3.",
            "https://cwe.mitre.org/data/definitions/327.html",
            "CWE-327",
        ).expect("Valid CRYP rule regex"),
    ]
}

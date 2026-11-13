use cyberguard_core::sarif::{Message, ReportingDescriptor, SarifLevel, SarifLog, SarifResult};

#[test]
fn test_sarif_log_creation_and_serialization() {
    let mut log = SarifLog::new("CyberGuard", env!("CARGO_PKG_VERSION"));

    let rule = ReportingDescriptor {
        id: "CG-SEC-001".to_string(),
        name: Some("CommandInjection".to_string()),
        short_description: Message {
            text: "Unsanitized user input in shell execution".to_string(),
        },
        full_description: Some(Message {
            text: "Detected tainted argument passed directly to subprocess Command::new without validation."
                .to_string(),
        }),
        help_uri: Some("https://cyberguard.dev/rules/CG-SEC-001".to_string()),
    };

    let mut result = SarifResult::new(
        "CG-SEC-001",
        SarifLevel::Error,
        "Potential remote code execution via tainted endpoint parameter",
    );
    result.add_location("src/server/handler.rs", 42, Some(15), Some(42), Some(38));
    result.properties = Some(serde_json::json!({
        "cvss": 9.8,
        "epss": 0.89,
        "reachability": "VERIFIED_REACHABLE",
        "tri_factor_score": 8.72
    }));

    log.add_rule(rule);
    log.add_result(result);

    let json_str = serde_json::to_string_pretty(&log).expect("Failed to serialize SARIF log");
    assert!(json_str.contains("\"version\": \"2.1.0\""));
    assert!(json_str.contains("\"CG-SEC-001\""));
    assert!(json_str.contains("\"tri_factor_score\": 8.72"));
    assert!(json_str.contains("\"VERIFIED_REACHABLE\""));

    // Verify roundtrip deserialization
    let deserialized: SarifLog =
        serde_json::from_str(&json_str).expect("Failed to deserialize SARIF log");
    assert_eq!(deserialized.version, "2.1.0");
    assert_eq!(deserialized.runs.len(), 1);
    assert_eq!(deserialized.runs[0].results.len(), 1);
    assert_eq!(deserialized.runs[0].results[0].rule_id, "CG-SEC-001");
}

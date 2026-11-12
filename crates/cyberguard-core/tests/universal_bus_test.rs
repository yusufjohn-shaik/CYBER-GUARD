use cyberguard_core::ocsf::OcsfSeverity;
use cyberguard_core::sarif::{
    ArtifactChange, ArtifactLocation, CodeFlow, Fix, Location, Message, PhysicalLocation, Region,
    Replacement, SarifLevel, SarifLog, SarifResult, ThreadFlow, ThreadFlowLocation,
};

#[test]
fn test_sarif_code_flow_and_remediation_serialization() {
    let mut log = SarifLog::new("CyberGuard", "0.3.0");

    let taint_flow = CodeFlow {
        message: Some(Message {
            text: "Taint propagation path from HTTP parameter to SQL sink".to_string(),
        }),
        thread_flows: vec![ThreadFlow {
            message: None,
            locations: vec![
                ThreadFlowLocation {
                    location: Location {
                        physical_location: Some(PhysicalLocation {
                            artifact_location: ArtifactLocation {
                                uri: "src/api/routes.rs".to_string(),
                            },
                            region: Some(Region {
                                start_line: 12,
                                start_column: Some(8),
                                end_line: Some(12),
                                end_column: Some(25),
                            }),
                        }),
                    },
                    step: Some(1),
                    importance: Some("essential".to_string()),
                },
                ThreadFlowLocation {
                    location: Location {
                        physical_location: Some(PhysicalLocation {
                            artifact_location: ArtifactLocation {
                                uri: "src/db/query.rs".to_string(),
                            },
                            region: Some(Region {
                                start_line: 45,
                                start_column: Some(12),
                                end_line: Some(45),
                                end_column: Some(60),
                            }),
                        }),
                    },
                    step: Some(2),
                    importance: Some("essential".to_string()),
                },
            ],
        }],
    };

    let fix = Fix {
        description: Message {
            text: "Use parameterized query with SQL binding".to_string(),
        },
        artifact_changes: vec![ArtifactChange {
            artifact_location: ArtifactLocation {
                uri: "src/db/query.rs".to_string(),
            },
            replacements: vec![Replacement {
                deleted_region: Region {
                    start_line: 45,
                    start_column: Some(12),
                    end_line: Some(45),
                    end_column: Some(60),
                },
                inserted_content: Some(Message {
                    text: "sqlx::query(\"SELECT * FROM users WHERE id = $1\").bind(user_id)"
                        .to_string(),
                }),
            }],
        }],
    };

    let mut result = SarifResult::new(
        "CG-SQLI-001",
        SarifLevel::Error,
        "Unsanitized user input reaches raw SQL executor",
    );
    result.add_location("src/db/query.rs", 45, Some(12), Some(45), Some(60));
    result.add_code_flow(taint_flow);
    result.add_fix(fix);
    result.with_tri_factor(9.8, 0.92, 1.0);
    result.compute_deterministic_fingerprint();

    log.add_result(result);

    let json_output = serde_json::to_string_pretty(&log).expect("Failed to serialize SARIF");
    assert!(json_output.contains("codeFlows"));
    assert!(json_output.contains("threadFlows"));
    assert!(json_output.contains("sqlx::query"));
    assert!(json_output.contains("triFactorScore"));
    assert!(json_output.contains("partialFingerprints"));

    // Verify roundtrip deserialization
    let deserialized: SarifLog =
        serde_json::from_str(&json_output).expect("Failed to deserialize SARIF");
    assert_eq!(deserialized.runs[0].results.len(), 1);
    let item = &deserialized.runs[0].results[0];
    assert_eq!(item.code_flows.len(), 1);
    assert_eq!(item.fixes.len(), 1);
    assert!(item.partial_fingerprints.is_some());
}

#[test]
fn test_sarif_to_ocsf_conversion() {
    let mut result = SarifResult::new(
        "CG-BOLA-002",
        SarifLevel::Error,
        "Broken Object Level Authorization (BOLA) detected on endpoint /api/user/{id}",
    );
    result.add_location("src/api/user.rs", 88, Some(4), Some(88), Some(30));
    result.with_tri_factor(8.5, 0.75, 1.0);

    let ocsf_event = result.to_ocsf("CyberGuard-Engine");

    assert_eq!(ocsf_event.class_uid, 2001); // Vulnerability Finding
    assert_eq!(ocsf_event.category_uid, 2); // Findings
    assert_eq!(ocsf_event.severity_id, OcsfSeverity::High as u8);
    assert_eq!(ocsf_event.finding_info.title, "CG-BOLA-002");
    assert!(ocsf_event.vulnerabilities[0].cve.contains("CG-BOLA-002"));
    assert_eq!(ocsf_event.vulnerabilities[0].cvss_score, Some(8.5));
    assert_eq!(ocsf_event.vulnerabilities[0].epss_score, Some(0.75));
    assert_eq!(ocsf_event.vulnerabilities[0].reachability, Some(1.0));
    assert_eq!(ocsf_event.vulnerabilities[0].tri_factor_score, Some(6.38)); // 8.5 * 0.75 * 1.0 = 6.375 -> rounded to 6.38
}

#[test]
fn test_deterministic_fingerprint_stability_and_uniqueness() {
    let mut res1 = SarifResult::new("CG-RCE-001", SarifLevel::Error, "Remote Code Execution");
    res1.add_location("src/handler.rs", 100, None, None, None);
    res1.compute_deterministic_fingerprint();

    let mut res2 = SarifResult::new("CG-RCE-001", SarifLevel::Error, "Remote Code Execution");
    res2.add_location("src/handler.rs", 100, None, None, None);
    res2.compute_deterministic_fingerprint();

    let mut res3 = SarifResult::new("CG-RCE-001", SarifLevel::Error, "Remote Code Execution");
    res3.add_location("src/other.rs", 100, None, None, None);
    res3.compute_deterministic_fingerprint();

    let fp1 = res1.partial_fingerprints.unwrap();
    let fp2 = res2.partial_fingerprints.unwrap();
    let fp3 = res3.partial_fingerprints.unwrap();

    // Identical rule and location produce identical fingerprint
    assert_eq!(
        fp1.get("logicalLocationTokenHash/v1"),
        fp2.get("logicalLocationTokenHash/v1")
    );

    // Different location produces different fingerprint
    assert_ne!(
        fp1.get("logicalLocationTokenHash/v1"),
        fp3.get("logicalLocationTokenHash/v1")
    );
}

#[test]
fn test_tri_factor_zero_reachability_neutralizes_risk() {
    let mut res = SarifResult::new("CG-DESER-001", SarifLevel::Error, "Vulnerable Deserializer");
    res.with_tri_factor(9.8, 0.95, 0.0); // Reachability = 0.0

    let props = res.properties.unwrap();
    let score = props.get("triFactorScore").unwrap().as_f64().unwrap();
    assert_eq!(score, 0.0); // Risk is completely neutralized!
}

#[test]
fn test_ocsf_severity_levels_mapping() {
    let mut critical_res =
        SarifResult::new("CG-AUTH-001", SarifLevel::Error, "Critical Auth Bypass");
    critical_res.with_tri_factor(9.8, 0.9, 1.0); // CVSS >= 9.0 -> Critical
    let event = critical_res.to_ocsf("CG");
    assert_eq!(event.severity_id, OcsfSeverity::Critical as u8);

    let warn_res = SarifResult::new("CG-INFO-001", SarifLevel::Warning, "Weak Cipher Suite");
    let event = warn_res.to_ocsf("CG");
    assert_eq!(event.severity_id, OcsfSeverity::Medium as u8);

    let note_res = SarifResult::new("CG-NOTE-001", SarifLevel::Note, "Verbose Headers");
    let event = note_res.to_ocsf("CG");
    assert_eq!(event.severity_id, OcsfSeverity::Low as u8);
}

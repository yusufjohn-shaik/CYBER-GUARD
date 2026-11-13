use cyberguard_sca::models::{Ecosystem, Package};
use cyberguard_sca::sbom::{generate_cyclonedx_json, generate_spdx_json};

#[test]
fn test_cyclonedx_v1_5_sbom_generation() {
    let packages = vec![
        Package::new(
            "tokio",
            "1.40.0",
            Ecosystem::Cargo,
            Some("sha256-abcdef1234567890".to_string()),
            true,
        ),
        Package::new(
            "@types/node",
            "18.11.0",
            Ecosystem::Npm,
            Some("sha512-9876543210fedcba".to_string()),
            false,
        ),
    ];

    let json_str = generate_cyclonedx_json("MyWorkspace", &packages).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json_str).unwrap();

    assert_eq!(v["bomFormat"], "CycloneDX");
    assert_eq!(v["specVersion"], "1.5");
    assert_eq!(v["components"].as_array().unwrap().len(), 2);

    let comp0 = &v["components"][0];
    assert_eq!(comp0["name"], "tokio");
    assert_eq!(comp0["version"], "1.40.0");
    assert_eq!(comp0["purl"], "pkg:cargo/tokio@1.40.0");
    assert_eq!(comp0["type"], "library");

    let comp1 = &v["components"][1];
    assert_eq!(comp1["name"], "@types/node");
    assert_eq!(comp1["purl"], "pkg:npm/%40types/node@18.11.0");
}

#[test]
fn test_spdx_v2_3_sbom_generation() {
    let packages = vec![Package::new(
        "serde",
        "1.0.210",
        Ecosystem::Cargo,
        None,
        true,
    )];

    let json_str = generate_spdx_json("MyWorkspace", &packages).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json_str).unwrap();

    assert_eq!(v["spdxVersion"], "SPDX-2.3");
    assert_eq!(v["dataLicense"], "CC0-1.0");
    assert_eq!(v["packages"].as_array().unwrap().len(), 1);

    let pkg0 = &v["packages"][0];
    assert_eq!(pkg0["name"], "serde");
    assert_eq!(pkg0["versionInfo"], "1.0.210");
    assert_eq!(
        pkg0["externalRefs"][0]["referenceLocator"],
        "pkg:cargo/serde@1.0.210"
    );
}

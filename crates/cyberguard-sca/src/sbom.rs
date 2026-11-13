use crate::error::ScaError;
use crate::models::Package;
use chrono::Utc;
use serde::Serialize;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CycloneDxBom<'a> {
    bom_format: &'static str,
    spec_version: &'static str,
    version: u32,
    metadata: CycloneDxMetadata<'a>,
    components: Vec<CycloneDxComponent<'a>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CycloneDxMetadata<'a> {
    timestamp: String,
    tools: Vec<CycloneDxTool>,
    component: CycloneDxRootComponent<'a>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CycloneDxTool {
    vendor: &'static str,
    name: &'static str,
    version: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CycloneDxRootComponent<'a> {
    #[serde(rename = "type")]
    component_type: &'static str,
    name: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CycloneDxComponent<'a> {
    #[serde(rename = "type")]
    component_type: &'static str,
    name: &'a str,
    version: &'a str,
    purl: &'a str,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    hashes: Vec<CycloneDxHash<'a>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CycloneDxHash<'a> {
    alg: &'static str,
    content: &'a str,
}

pub fn generate_cyclonedx_json(
    project_name: &str,
    packages: &[Package],
) -> Result<String, ScaError> {
    let mut components = Vec::with_capacity(packages.len());

    for pkg in packages {
        let mut hashes = Vec::new();
        if let Some(chk) = &pkg.checksum {
            let alg = if chk.starts_with("sha512-") || chk.len() == 128 {
                "SHA-512"
            } else {
                "SHA-256"
            };
            hashes.push(CycloneDxHash { alg, content: chk });
        }

        components.push(CycloneDxComponent {
            component_type: "library",
            name: &pkg.name,
            version: &pkg.version,
            purl: &pkg.purl,
            hashes,
        });
    }

    let bom = CycloneDxBom {
        bom_format: "CycloneDX",
        spec_version: "1.5",
        version: 1,
        metadata: CycloneDxMetadata {
            timestamp: Utc::now().to_rfc3339(),
            tools: vec![CycloneDxTool {
                vendor: "CyberGuard",
                name: "cyberguard-sca",
                version: env!("CARGO_PKG_VERSION"),
            }],
            component: CycloneDxRootComponent {
                component_type: "application",
                name: project_name,
            },
        },
        components,
    };

    serde_json::to_string_pretty(&bom).map_err(ScaError::from)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SpdxDocument<'a> {
    spdx_version: &'static str,
    data_license: &'static str,
    #[serde(rename = "SPDXID")]
    spdx_id: &'static str,
    name: &'a str,
    document_namespace: String,
    packages: Vec<SpdxPackage<'a>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SpdxPackage<'a> {
    #[serde(rename = "SPDXID")]
    spdx_id: String,
    name: &'a str,
    version_info: &'a str,
    download_location: &'static str,
    files_analyzed: bool,
    external_refs: Vec<SpdxExternalRef<'a>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SpdxExternalRef<'a> {
    reference_category: &'static str,
    reference_type: &'static str,
    reference_locator: &'a str,
}

pub fn generate_spdx_json(project_name: &str, packages: &[Package]) -> Result<String, ScaError> {
    let mut spdx_packages = Vec::with_capacity(packages.len());

    for (idx, pkg) in packages.iter().enumerate() {
        let clean_name = pkg.name.replace('@', "").replace('/', "-");
        let spdx_id = format!("SPDXRef-Package-{}-{}", clean_name, idx);

        spdx_packages.push(SpdxPackage {
            spdx_id,
            name: &pkg.name,
            version_info: &pkg.version,
            download_location: "NOASSERTION",
            files_analyzed: false,
            external_refs: vec![SpdxExternalRef {
                reference_category: "PACKAGE-MANAGER",
                reference_type: "purl",
                reference_locator: &pkg.purl,
            }],
        });
    }

    let doc = SpdxDocument {
        spdx_version: "SPDX-2.3",
        data_license: "CC0-1.0",
        spdx_id: "SPDXRef-DOCUMENT",
        name: project_name,
        document_namespace: format!("https://cyberguard.dev/spdx/{}", project_name),
        packages: spdx_packages,
    };

    serde_json::to_string_pretty(&doc).map_err(ScaError::from)
}

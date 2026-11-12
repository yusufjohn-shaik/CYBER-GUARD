# 📦 Module 03: Universal Data Bus (OASIS SARIF v2.1.0 & OCSF Engine)
## Sprint Execution Record (Agile-Spiral Hybrid Model)

---

## 1. Sprint Objective & User Story
**User Story:** As a security engineer, DevSecOps pipeline, or AI coding agent, I need a standardized, high-performance security data bus so that all vulnerability findings, multi-hop code flows (taint paths), and attack paths are represented in OASIS SARIF v2.1.0 and Open Cybersecurity Schema Framework (OCSF) formats with cryptographic deduplication fingerprints and Tri-Factor risk scoring.

**Module Number:** 03 of 21  
**Target Delivery Date:** November 12, 2026  
**Primary Crates:** `cyberguard-core`  
**Language:** Rust 1.85+ (2024 Edition)  

---

## 2. Step 1: Spiral Risk Gate (Quadrant II: Risk Analysis)

Before implementing code, the engineering team executed the mandatory Spiral Risk Assessment:

| Risk ID | Identified Risk | Impact | Architectural Mitigation Strategy | Gate Status |
| :--- | :--- | :--- | :--- | :--- |
| **RISK-03-01** | **Memory Exhaustion on Gigabyte SARIF Logs:** Large monorepos can produce hundreds of megabytes of SARIF logs. Parsing the entire file into a monolithic DOM tree can trigger high memory spikes. | High | Implement streaming Serde deserialization and chunked results processing; utilize typed, zero-copy string slices where applicable. | **CLEARED ✅** |
| **RISK-03-02** | **Finding Duplicate Invalidation Across Commits:** Line numbers change when code is edited, causing naive file+line duplicate checks to produce duplicate alerts for identical unfixed vulnerabilities. | Critical | Implement AST-stable **Partial Fingerprints** (`partialFingerprints`) computed via normalized code token hashing (BLAKE3) rather than raw line numbers. | **CLEARED ✅** |
| **RISK-03-03** | **Schema Divergence Between SARIF & OCSF:** Converting from code-centric SARIF (OASIS) to telemetry-centric OCSF (AWS/Splunk) can drop vital context (code flows, CWEs, reachability indices). | Medium | Design an explicit bidirectional converter with standardized CyberGuard extension attributes mapping SARIF `codeFlows` into OCSF `evidence` and `remediation` blocks. | **CLEARED ✅** |
| **RISK-03-04** | **Floating Point Drift in Tri-Factor Math:** Comparing floating point risk scores (`CVSS × EPSS × Reachability`) across platforms can cause rounding discrepancies. | Low | Enforce 2-decimal rounded precision on all exported Tri-Factor risk scores. | **CLEARED ✅** |

---

## 3. Step 2: Architecture & Component Breakdown

### 3.1 Advanced OASIS SARIF v2.1.0 Enhancements (`crates/cyberguard-core/src/sarif.rs`)
- **CodeFlow & ThreadFlow:** Strongly typed structs representing multi-step taint paths from source to sink.
- **Fix & ArtifactChange:** Machine-readable proposed code fixes with replacement ranges.
- **Fingerprinting:** Deterministic BLAKE3 hash generation for finding deduplication.
- **Tri-Factor Bag:** Custom CyberGuard properties bag (`cvss`, `epss`, `reachability_index`, `tri_factor_score`).

### 3.2 OCSF v1.3.0 Engine (`crates/cyberguard-core/src/ocsf.rs`)
- **Vulnerability Finding Class (UID `2001`):** Complete OCSF-compliant event model.
- **Metadata, Remediation, and Affected Resource objects.**
- **Converter Trait:** `From<SarifResult> for OcsfFinding`.

---

## 4. Step 3: QA Verification & Test Coverage
- Unit tests verifying SARIF code flows and thread flow location navigation.
- Conversion tests verifying SARIF to OCSF fidelity without loss of risk metrics.
- Deterministic partial fingerprint hashing tests.
- Zero warnings under `cargo clippy --workspace -- -D warnings`.

---

## 5. Step 4: Review & Sign-Off (Quadrant IV)
- **Linux Foundation DCO:** All commits signed-off (`git commit -s`).
- **Clean Git History:** Atomic commit with test coverage validation.

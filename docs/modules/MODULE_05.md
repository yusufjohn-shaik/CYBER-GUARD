# 📦 Module 05: Software Composition Analysis (SCA) & Supply Chain Security
## Sprint Execution Record (Agile-Spiral Hybrid Model)

---

## 1. Sprint Objective & User Story

**User Story:** As a DevSecOps engineer, security auditor, or autonomous AI agent, I need a blazingly fast, pure Rust Software Composition Analysis (SCA) engine that parses project lockfiles (`Cargo.lock`, `package-lock.json`), generates standardized Software Bills of Materials (CycloneDX v1.5 & SPDX v2.3 JSON), matches components against the OSV (Open Source Vulnerability) schema, and calculates Tri-Factor exploitability without external runtime dependencies or copyleft contamination.

**Module Number:** 05 of 21  
**Target Delivery Date:** November 14, 2026  
**Primary Crates:** `cyberguard-sca`, `cyberguard-core`, `cyberguard-cli`  
**Language:** Rust 1.85+ (2021 Edition)  

---

## 2. Step 1: Spiral Risk Gate (Quadrant II: Risk Analysis)

| Risk ID | Identified Risk | Impact | Architectural Mitigation Strategy | Gate Status |
| :--- | :--- | :--- | :--- | :--- |
| **RISK-05-01** | **Malicious/Cyclic Dependency Graph:** A crafted `package-lock.json` with circular dependencies could cause infinite loops or stack overflow during resolution. | Critical | Enforce acyclic dependency validation using Tarjan's algorithm / visited sets with max depth bounds (default: 64 levels). | **CLEARED ✅** |
| **RISK-05-02** | **Billion-Laughs / Exponential Parser DoS:** Enormous or maliciously crafted lockfiles could consume gigabytes of RAM during serde deserialization. | High | Enforce strict file size limits (default: 32 MB max per lockfile) and streaming/bounded parsing. | **CLEARED ✅** |
| **RISK-05-03** | **Network Dependency in Offline / Air-Gapped Environments:** Calling live APIs for every scan would fail in air-gapped CI/CD environments and violate the offline-first mandate. | High | Implement an embedded/cached offline OSV vulnerability database snapshot with local semver matching, allowing zero-network execution. | **CLEARED ✅** |
| **RISK-05-04** | **Copyleft / GPL Contamination:** Copying or linking GPL-licensed SCA parsers (e.g., from GPL tools). | Critical | Clean-room pure Rust implementation using permissive crates (`serde`, `serde_json`, `toml`, `semver`) dual-licensed MIT/Apache-2.0. | **CLEARED ✅** |
| **RISK-05-05** | **SemVer Coercion Errors:** Package registries (especially npm) contain non-standard version strings (`1.0.0-beta.1+build`, `v2.0`). | Medium | Robust version parsing with lenient normalization fallback conforming to semver specification. | **CLEARED ✅** |

---

## 3. Step 2: Architecture & Component Breakdown

### 3.1 `crates/cyberguard-sca`
- **Data Models:**
  - `Package`: Package URL (`purl`), name, version, ecosystem (`Cargo`, `Npm`, `PyPI`), direct vs transitive.
  - `DependencyGraph`: Directed dependency relations.
  - `Sbom`: CycloneDX v1.5 JSON & SPDX v2.3 JSON export formats.
  - `VulnerabilityMatch`: CVE/GHSA ID, affected range, severity, CVSS, EPSS score.
- **Parsers:**
  - `CargoLockParser`: Parses TOML-based `Cargo.lock` files (V1, V2, V3 formats).
  - `NpmLockParser`: Parses JSON-based `package-lock.json` (Lockfile v1, v2, v3 formats).
- **Vulnerability Database Engine:**
  - In-memory embedded OSV advisory catalog for fast, zero-network semver interval matching.
  - Trait `ScaAnalyzer`: Unified async interface returning `SarifResult` and OCSF vulnerability findings.

---

## 4. Step 3: QA Verification & Test Coverage
- Unit tests for `Cargo.lock` parsing (normal, checksums, multiple dependencies).
- Unit tests for `package-lock.json` parsing (v1/v2/v3, scoped packages like `@types/node`).
- Unit tests for CycloneDX v1.5 JSON and SPDX v2.3 SBOM generation.
- Semver vulnerability interval matching tests against known CVEs (e.g. `CVE-2021-44906`, `RUSTSEC-2020-0071`).
- Zero warnings under `cargo clippy --workspace --all-targets -- -D warnings`.
- Clean code formatting via `cargo fmt --all -- --check`.

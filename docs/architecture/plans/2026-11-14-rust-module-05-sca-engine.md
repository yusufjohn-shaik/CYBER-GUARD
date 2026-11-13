# Module 05: SCA & Supply Chain Security Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a high-performance, pure Rust Software Composition Analysis (SCA) engine (`cyberguard-sca`) that parses `Cargo.lock` and `package-lock.json` lockfiles, produces standard CycloneDX v1.5 and SPDX v2.3 SBOMs, and performs offline semver vulnerability matching emitting SARIF v2.1.0 telemetry.

**Architecture:** A modular crate `cyberguard-sca` inside the virtual Cargo workspace. Implements unified lockfile parsers (`CargoLockParser`, `NpmLockParser`), package models with standardized Package URLs (`purl`), an embedded OSV advisory catalog, and an asynchronous `ScaAnalyzer` that converts supply-chain findings into `SarifResult` and OCSF events.

**Tech Stack:** Rust 2021, `toml`, `serde`, `serde_json`, `semver`, `thiserror`, `cyberguard-core`.

**Spec:** [`docs/modules/MODULE_05.md`](file:///home/john/CYBER-GUARD/docs/modules/MODULE_05.md)

## Global Constraints
- Pure native Rust (zero Go, Python, or JVM runtimes).
- All dependencies must be dual-licensed MIT / Apache-2.0.
- Strict `#![deny(unsafe_code)]`.
- Zero compiler warnings under `cargo clippy --workspace --all-targets -- -D warnings`.
- Every commit signed off with `git commit -s`.

## Review Focus
1. Malformed or partial lockfiles return structured errors instead of panicking.
2. Multiple versions of the same package (e.g. transitive dependencies) are deduplicated or tracked distinctly by version and path.
3. Packages with non-standard SemVer strings are gracefully coerced without scan interruption.
4. Generated CycloneDX v1.5 SBOM adheres strictly to the official JSON schema.
5. Vulnerability matching correctly assesses upper/lower semver bounds (`>=`, `<`, `<=`).

---

### Task 1: Initialize `cyberguard-sca` Crate & Workspace Registration

**Files:**
- Modify: `Cargo.toml`
- Create: `crates/cyberguard-sca/Cargo.toml`
- Create: `crates/cyberguard-sca/src/lib.rs`

- [ ] **Step 1: Add `cyberguard-sca` to root `Cargo.toml` workspace members and dependencies**
- [ ] **Step 2: Create `crates/cyberguard-sca/Cargo.toml`**
- [ ] **Step 3: Create initial `crates/cyberguard-sca/src/lib.rs` and verify workspace compiles**

---

### Task 2: Core Data Models & Error Types (TDD)

**Files:**
- Create: `crates/cyberguard-sca/src/error.rs`
- Create: `crates/cyberguard-sca/src/models.rs`
- Create: `crates/cyberguard-sca/src/traits.rs`
- Test: `crates/cyberguard-sca/tests/models_test.rs`

- [ ] **Step 1: Write failing test in `models_test.rs` testing Package PURL generation and validation**
- [ ] **Step 2: Implement `ScaError`, `Package`, `Ecosystem`, `Dependency` in `models.rs` and `error.rs`**
- [ ] **Step 3: Implement `LockfileParser` trait in `traits.rs`**
- [ ] **Step 4: Run tests and verify GREEN**

---

### Task 3: Cargo Lockfile Parser (TDD)

**Files:**
- Create: `crates/cyberguard-sca/src/parsers/cargo.rs`
- Create: `crates/cyberguard-sca/src/parsers/mod.rs`
- Test: `crates/cyberguard-sca/tests/cargo_parser_test.rs`

- [ ] **Step 1: Write failing test in `cargo_parser_test.rs` with representative `Cargo.lock` content**
- [ ] **Step 2: Implement `CargoLockParser` using `toml` and `serde`**
- [ ] **Step 3: Run test, verify packages correctly extracted (names, versions, checksums, source)**
- [ ] **Step 4: Test invalid TOML and verify graceful `ScaError::ParseError` handling**

---

### Task 4: NPM Lockfile Parser (v1, v2, v3) (TDD)

**Files:**
- Create: `crates/cyberguard-sca/src/parsers/npm.rs`
- Test: `crates/cyberguard-sca/tests/npm_parser_test.rs`

- [ ] **Step 1: Write failing test in `npm_parser_test.rs` testing npm v2/v3 `packages` map and v1 `dependencies`**
- [ ] **Step 2: Implement `NpmLockParser` handling scoped packages (`@types/node`), integrity hashes, and dev flags**
- [ ] **Step 3: Run test, verify all packages accurately parsed**

---

### Task 5: SBOM Generation (CycloneDX v1.5 & SPDX v2.3 JSON) (TDD)

**Files:**
- Create: `crates/cyberguard-sca/src/sbom.rs`
- Test: `crates/cyberguard-sca/tests/sbom_test.rs`

- [ ] **Step 1: Write failing test in `sbom_test.rs` verifying CycloneDX v1.5 JSON output**
- [ ] **Step 2: Implement `generate_cyclonedx_json` and `generate_spdx_json`**
- [ ] **Step 3: Verify valid JSON schema serialization with correct components, hashes, and licenses**

---

### Task 6: Vulnerability Database & SemVer Matching Engine (TDD)

**Files:**
- Create: `crates/cyberguard-sca/src/db.rs`
- Create: `crates/cyberguard-sca/src/engine.rs`
- Test: `crates/cyberguard-sca/tests/vulnerability_matcher_test.rs`

- [ ] **Step 1: Write failing test in `vulnerability_matcher_test.rs` matching vulnerable package versions**
- [ ] **Step 2: Implement `VulnerabilityDatabase` with embedded OSV advisories and semver range evaluation**
- [ ] **Step 3: Implement `ScaEngine` producing `SarifResult` and OCSF vulnerability findings**
- [ ] **Step 4: Run tests and verify 100% pass rate**

---

### Task 7: CLI Integration & End-to-End Verification

**Files:**
- Modify: `crates/cyberguard-cli/Cargo.toml`
- Modify: `crates/cyberguard-cli/src/main.rs`
- Create: `tests/fixtures/vulnerable-supply-chain/`
- Test: `crates/cyberguard-cli/tests/sca_cli_test.rs`

- [ ] **Step 1: Add `cyberguard-sca` to `cyberguard-cli` dependencies**
- [ ] **Step 2: Connect SCA lockfile autodetection and audit command in `main.rs`**
- [ ] **Step 3: Create vulnerable supply-chain test fixture (`Cargo.lock` & `package-lock.json`)**
- [ ] **Step 4: Run full workspace test suite and clippy linting**
- [ ] **Step 5: Verify CLI output against fixture**

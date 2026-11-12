# Module 04: SAST Static Analysis Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a production-grade, zero-dependency Static Application Security Testing (SAST) engine in pure Rust (`cyberguard-sast`), featuring native OWASP Top 10 security rules, directory traversal with smart vendor exclusion, sandboxed external tool orchestration (`cyberguard-proc`), and unified SARIF v2.1.0 output with deterministic deduplication fingerprints.

**Architecture:** A new crate `crates/cyberguard-sast` implementing the `SastAnalyzer` trait. A `NativeRuleEngine` provides instant, local vulnerability scanning using linear-time regular expressions ($O(n)$ ReDoS-immune). An `ExternalOrchestrator` runs third-party scanners (like Semgrep) inside isolated POSIX process groups via `cyberguard-proc`. Results are unified into SARIF v2.1.0 via `cyberguard-core`.

**Tech Stack:** Rust 1.85+, `regex` (linear-time automata), `walkdir` or standard `std::fs`, `cyberguard-core`, `cyberguard-proc`.

**Spec:** [docs/modules/MODULE_04.md](file:///home/john/CYBER-GUARD/docs/modules/MODULE_04.md) and [docs/architecture/RUST_STACK_SPECIFICATION.md](file:///home/john/CYBER-GUARD/docs/architecture/RUST_STACK_SPECIFICATION.md).

## Global Constraints
- Strictly Apache-2.0 clean-room. No GPL/AGPL crates statically linked or vendored.
- Zero `unsafe` blocks.
- Minimum 80% automated unit/integration test coverage.
- Zero Clippy warnings (`cargo clippy --workspace -- -D warnings`).
- All commits signed with `git commit -s` (Linux Foundation DCO).

---

### Task 1: Create `crates/cyberguard-sast` & Core Trait Interface
**Files:**
- Create: `crates/cyberguard-sast/Cargo.toml`
- Create: `crates/cyberguard-sast/src/lib.rs`
- Create: `crates/cyberguard-sast/src/traits.rs`
- Create: `crates/cyberguard-sast/src/context.rs`
- Modify: `Cargo.toml` (root workspace)
- Test: `crates/cyberguard-sast/tests/engine_test.rs`

**Interfaces:**
- Produces:
  - `pub trait SastAnalyzer: Send + Sync { fn name(&self) -> &str; fn analyze(&self, ctx: &ScanContext) -> Result<Vec<SarifResult>, CyberguardError>; }`
  - `pub struct ScanContext { pub target_path: PathBuf, pub max_depth: usize, pub excluded_paths: Vec<String> }`

- [ ] **Step 1: Add `cyberguard-sast` to root `Cargo.toml`**
- [ ] **Step 2: Create `crates/cyberguard-sast/Cargo.toml` with dependencies**
- [ ] **Step 3: Implement `SastAnalyzer` trait and `ScanContext`**
- [ ] **Step 4: Verify clean workspace compilation**

---

### Task 2: Implement Built-In `NativeRuleEngine` (Zero-Dependency SAST)
**Files:**
- Create: `crates/cyberguard-sast/src/rules/mod.rs`
- Create: `crates/cyberguard-sast/src/rules/rule.rs`
- Create: `crates/cyberguard-sast/src/rules/builtin.rs`
- Create: `crates/cyberguard-sast/src/engine.rs`
- Test: `crates/cyberguard-sast/tests/native_rules_test.rs`

**Interfaces:**
- Produces:
  - `struct SastRule { id: String, name: String, severity: SarifLevel, pattern: Regex, message: String, help_uri: String }`
  - `struct NativeRuleEngine { rules: Vec<SastRule> }`
  - Built-in rules for:
    - `CG-SQLI-001`: Raw string formatting/concatenation in SQL query functions.
    - `CG-CMDI-001`: Unsanitized command execution via shell invocations (`sh -c`, `bash -c`, `cmd.exe /c`).
    - `CG-SECR-001`: High-entropy hardcoded API keys (AWS, GitHub, Generic private keys).
    - `CG-PATH-001`: Path traversal / directory climb patterns (`../` concatenation).
    - `CG-CRYP-001`: Broken cryptographic primitives (MD5, SHA1 for security-sensitive operations).

- [ ] **Step 1: Write failing rule tests against vulnerable and safe code snippets**
- [ ] **Step 2: Implement `SastRule` and `NativeRuleEngine`**
- [ ] **Step 3: Run tests and verify passing**

---

### Task 3: Directory Crawler with Smart Vendor & Git Exclusions
**Files:**
- Create: `crates/cyberguard-sast/src/walker.rs`
- Test: `crates/cyberguard-sast/tests/walker_test.rs`

**Interfaces:**
- Produces:
  - `pub fn collect_source_files(ctx: &ScanContext) -> Vec<PathBuf>;`
  - Automatically filters out: `node_modules/`, `target/`, `vendor/`, `.git/`, `.venv/`, `dist/`.

- [ ] **Step 1: Write directory traversal tests verifying default exclusions**
- [ ] **Step 2: Implement `collect_source_files`**
- [ ] **Step 3: Run tests and verify passing**

---

### Task 4: Integrate SAST Engine into `cyberguard-cli`
**Files:**
- Modify: `crates/cyberguard-cli/Cargo.toml`
- Modify: `crates/cyberguard-cli/src/main.rs`
- Test: `crates/cyberguard-cli/tests/scan_e2e_test.rs`

**Interfaces:**
- Produces:
  - Running `cyberguard scan <PATH>` invokes `NativeRuleEngine::scan` and outputs real findings with line numbers, code snippets, and SARIF export!

- [ ] **Step 1: Add `cyberguard-sast` dependency to `cyberguard-cli`**
- [ ] **Step 2: Wire up scan subcommand to execute SAST engine**
- [ ] **Step 3: Test end-to-end scanning against sample vulnerable file**
- [ ] **Step 4: Verify `cargo test --workspace` and `cargo clippy` pass cleanly**
- [ ] **Step 5: DCO Commit**

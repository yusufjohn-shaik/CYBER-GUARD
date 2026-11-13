# Module 04: SAST Static Analysis Engine
*Sprint Execution Record (Agile-Spiral Hybrid Model & Elephant-Goldfish Model)*

---

## 1. Problem Statement & Scope Boundaries

### Problem Statement
Modern continuous integration pipelines and developer workflows require static vulnerability detection that executes in-process without slow language runtime bootups (Python, JVM, Node.js) or network-gated cloud services. Developers need an extensible, zero-configuration Static Application Security Testing (SAST) engine that inspects source files with deterministic performance, respects ignore boundaries, and emits standardized OASIS SARIF v2.1.0 telemetry with deterministic deduplication fingerprints.

### Goals
1. Create a dedicated workspace crate `crates/cyberguard-sast` establishing the `SastAnalyzer` asynchronous trait contract.
2. Implement an in-process `NativeRuleEngine` using linear-time regular expressions ($O(n)$ search guarantees to prevent backtracking ReDoS) covering core OWASP vulnerability classes:
   - `CG-SQLI-001` (SQL Injection)
   - `CG-CMDI-001` (Command Injection)
   - `CG-SECR-001` (Hardcoded Secret Tokens)
   - `CG-PATH-001` (Path Traversal)
   - `CG-CRYP-001` (Broken Cryptographic Primitives)
3. Implement a fast directory crawler with automatic filtering of vendor, cache, and build directories (`node_modules/`, `target/`, `vendor/`, `.git/`, `.venv/`, `dist/`) and whitelist filtering for source code file extensions (`.rs`, `.py`, `.js`, `.ts`, `.go`, `.java`, `.c`, `.cpp`).
4. Connect `cyberguard scan <PATH>` in `cyberguard-cli` to execute the SAST engine and emit formatted terminal summaries and OASIS SARIF v2.1.0 logs with BLAKE3 partial fingerprints (`SarifResult::compute_deterministic_fingerprint()`).
5. Maintain zero Clippy warnings (`-D warnings`) and 100% automated test pass rate with Linux Foundation DCO sign-off.

### Non-Goals (Deferred to Subsequent Modules)
- **External Multi-Tool Adapters:** Subprocess orchestration wrappers for Semgrep, Gosec, and Bandit are scheduled for Module 05.
- **Cross-Tool Taxonomy Normalization:** Unifying disparate external scanner schemas into common CWE taxonomies is scheduled for Module 05.
- **AST Dataflow / Taint Reachability:** Deep AST call-graph tracing and interprocedural taint propagation are scheduled for Modules 07 & 08 (Deep Attack Path Tracer).
- **Automated Remediation:** Programmatic AST-level patch synthesis is scheduled for Module 09.

---

## 2. Alternatives Considered

| Dimension | Option A (Chosen) | Option B (Rejected) | Technical Decision Rationale |
| :--- | :--- | :--- | :--- |
| **Rule Engine Architecture** | **In-Process Linear-Time Regex (`regex` crate)** | **Tree-sitter / Language Grammars** | Tree-sitter requires C toolchains, heavy pre-compiled grammars per language, and high build friction. Linear-time finite automata (`regex`) guarantee $O(n)$ search performance, zero C dependencies, instant engine initialization, and sub-millisecond execution across multiple source languages. Semantic reachability is complemented in Module 07. |
| **Analyzer Trait Model** | **Asynchronous Trait (`async fn analyze`)** | **Synchronous Trait (`fn analyze`)** | A synchronous trait blocks Tokio executor threads if analyzers perform filesystem I/O, network queries, or future subprocess orchestration. An asynchronous trait maintains compatibility with the Tokio microkernel established in Module 02. |
| **Filesystem Traversal** | **Depth-Bounded Walker (`walkdir`)** | **Bespoke Hand-Coded Recursion** | Hand-rolled recursion easily fails on symlink loops, cyclic directory structures, and deep folder trees. `walkdir` provides battle-tested depth limits, symlink cycle detection, and memory-efficient directory streaming. |
| **Fingerprinting Standard** | **BLAKE3 Partial Fingerprint (`cyberguard-core`)** | **Custom SAST Hashing Engine** | Module 03 already established `SarifResult::compute_deterministic_fingerprint()` using BLAKE3. Re-implementing hashing inside `cyberguard-sast` would duplicate logic and risk hash divergence. |

---

## 3. Step 1: Spiral Risk Gate (Quadrant II: Risk Analysis)

| Risk ID | Identified Risk | Impact | Architectural Mitigation Strategy | Gate Status |
| :--- | :--- | :--- | :--- | :--- |
| **RISK-04-01** | **Infinite Symlink Traversal & Directory Bombing:** Scanning recursive directory trees or circular symlinks could trap the scanner in an infinite loop. | Critical | Enforce cycle detection and a maximum traversal depth bound (default max depth: 32) via `walkdir`. | **CLEARED ✅** |
| **RISK-04-02** | **Regular Expression Denial of Service (ReDoS):** Complex regex patterns in security rules could trigger catastrophic backtracking on malicious input. | High | Use Rust's linear-time `regex` crate, which compiles to finite automata with guaranteed $O(n)$ search time relative to input length. | **CLEARED ✅** |
| **RISK-04-03** | **Memory Exhaustion on Massive Repositories:** Reading hundreds of large or binary files into memory could trigger Out-Of-Memory (OOM) failures. | High | Enforce a maximum file size threshold (default: 5 MB). Skip files exceeding 5 MB and filter non-source file extensions. Handle non-UTF-8 files gracefully with warning logs instead of crashing. | **CLEARED ✅** |
| **RISK-04-04** | **Noise from Vendor & Test Directories:** Scanning `node_modules/`, `vendor/`, or `.git/` generates thousands of irrelevant alerts. | High | Enforce default directory exclusion filters for `node_modules/`, `vendor/`, `target/`, `.venv/`, `.git/`, and `dist/`. | **CLEARED ✅** |
| **RISK-04-05** | **Trait Incompatibility with Async Subprocesses:** Defining a synchronous analyzer trait would block Tokio worker threads when external processes are added. | Medium | Define `SastAnalyzer::analyze` as an `async` method from the start. | **CLEARED ✅** |

---

## 4. Step 2: Architecture & Component Breakdown

```text
┌────────────────────────────────────────────────────────────────────────┐
│                        crates/cyberguard-sast                          │
├────────────────────────────────────────────────────────────────────────┤
│ 1. PLUGGABLE ANALYZER TRAIT (SastAnalyzer)                             │
│    • name(&self) -> &str                                               │
│    • is_available(&self) -> bool                                       │
│    • async fn analyze(&self, ctx: &ScanContext)                        │
│        -> Result<Vec<SarifResult>, CyberguardError>                    │
├────────────────────────────────────────────────────────────────────────┤
│ 2. SCAN CONTEXT & DIRECTORY CRAWLER (ScanContext, Walker)              │
│    • Target path, max depth (32), max file size (5 MB)                 │
│    • Source extensions: .rs, .py, .js, .ts, .go, .java, .c, .cpp       │
│    • Default exclusions: node_modules, target, vendor, .git, .venv     │
├────────────────────────────────────────────────────────────────────────┤
│ 3. IN-PROCESS NATIVE RULE ENGINE (NativeRuleEngine)                    │
│    • Linear-time regex automata with line and column span extraction   │
│    • Built-in OWASP rules: SQLi, Command Injection, Secrets,           │
│      Path Traversal, Broken Crypto                                     │
│    • Populates SarifResult with BLAKE3 partial fingerprints            │
└────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                        crates/cyberguard-cli                           │
│  cyberguard scan <PATH> [--format terminal|sarif|json] [--min-severity]│
└────────────────────────────────────────────────────────────────────────┘
```

---

## 5. Detailed Implementation Plan (Zero-Decision Specification)

### Task 1: Initialize `crates/cyberguard-sast` & Define `SastAnalyzer` Trait
- **Root Workspace Updates:**
  - Add `"crates/cyberguard-sast"` to `[workspace.members]` in root `Cargo.toml`.
  - Add `cyberguard-sast = { path = "crates/cyberguard-sast" }` to `[workspace.dependencies]` in root `Cargo.toml`.
  - Add `regex = "1.11"` and `walkdir = "2.5"` to `[workspace.dependencies]` in root `Cargo.toml`.
- **Files to Create:**
  - `crates/cyberguard-sast/Cargo.toml`
  - `crates/cyberguard-sast/src/lib.rs`
  - `crates/cyberguard-sast/src/traits.rs`
  - `crates/cyberguard-sast/src/context.rs`
- **Interfaces & Types:**
  ```rust
  // crates/cyberguard-sast/src/traits.rs
  use async_trait::async_trait;
  use cyberguard_core::{CyberguardError, SarifResult};
  use crate::context::ScanContext;

  #[async_trait]
  pub trait SastAnalyzer: Send + Sync {
      fn name(&self) -> &str;
      fn is_available(&self) -> bool { true }
      async fn analyze(&self, ctx: &ScanContext) -> Result<Vec<SarifResult>, CyberguardError>;
  }

  // crates/cyberguard-sast/src/context.rs
  use std::path::PathBuf;

  #[derive(Debug, Clone)]
  pub struct ScanContext {
      pub target_path: PathBuf,
      pub max_depth: usize,
      pub max_file_size_bytes: u64,
      pub excluded_paths: Vec<String>,
      pub allowed_extensions: Vec<String>,
  }

  impl Default for ScanContext {
      fn default() -> Self {
          Self {
              target_path: PathBuf::from("."),
              max_depth: 32,
              max_file_size_bytes: 5 * 1024 * 1024, // 5 MB
              excluded_paths: vec![
                  "node_modules".into(),
                  "target".into(),
                  "vendor".into(),
                  ".git".into(),
                  ".venv".into(),
                  "dist".into(),
              ],
              allowed_extensions: vec![
                  "rs".into(), "py".into(), "js".into(), "ts".into(),
                  "go".into(), "java".into(), "c".into(), "cpp".into(),
              ],
          }
      }
  }
  ```

### Task 2: Implement Directory Crawler with Cycle Detection (`walker.rs`)
- **Files to Create:**
  - `crates/cyberguard-sast/src/walker.rs`
  - `crates/cyberguard-sast/tests/walker_test.rs`
- **Interfaces & Logic:**
  ```rust
  pub fn collect_source_files(ctx: &ScanContext) -> Vec<PathBuf> {
      if ctx.target_path.is_file() {
          return vec![ctx.target_path.clone()];
      }
      let mut files = Vec::new();
      let walker = walkdir::WalkDir::new(&ctx.target_path)
          .max_depth(ctx.max_depth)
          .follow_links(false)
          .into_iter()
          .filter_entry(|e| !is_excluded(e, &ctx.excluded_paths));

      for entry in walker.filter_map(|e| e.ok()) {
          let path = entry.path();
          if path.is_file() && is_supported_source(path, &ctx.allowed_extensions) {
              if let Ok(metadata) = entry.metadata() {
                  if metadata.len() <= ctx.max_file_size_bytes {
                      files.push(path.to_path_buf());
                  }
              }
          }
      }
      files
  }
  ```

### Task 3: Implement In-Process `NativeRuleEngine` with OWASP Top 10 Rules
- **Files to Create:**
  - `crates/cyberguard-sast/src/rules/mod.rs`
  - `crates/cyberguard-sast/src/rules/rule.rs`
  - `crates/cyberguard-sast/src/rules/builtin.rs`
  - `crates/cyberguard-sast/src/engine.rs`
  - `crates/cyberguard-sast/tests/native_rules_test.rs`
- **Rule Specifications:**
  1. `CG-SQLI-001` (SQL Injection):
     - Pattern: `(?i)(SELECT|INSERT|UPDATE|DELETE)\s+.*(\+|%s|\{\}|\$|#\{|\.format\()`
     - Severity: `SarifLevel::Error` (CWE-89)
     - Message: "Potential SQL injection via raw string interpolation or concatenation."
     - URI: "https://cwe.mitre.org/data/definitions/89.html"
  2. `CG-CMDI-001` (Command Injection):
     - Pattern: `(?i)(system|exec|spawn|popen)\s*\(\s*.*(\+|%s|\{\}|\$|\.format\()`
     - Severity: `SarifLevel::Error` (CWE-78)
     - Message: "Potential OS command injection via unescaped string in command invocation."
     - URI: "https://cwe.mitre.org/data/definitions/78.html"
  3. `CG-SECR-001` (Hardcoded Secret):
     - Pattern: `(?i)(AKIA[0-9A-Z]{16}|ghp_[0-9a-zA-Z]{36}|-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)`
     - Severity: `SarifLevel::Error` (CWE-798)
     - Message: "Hardcoded cryptographic secret or API token detected."
     - URI: "https://cwe.mitre.org/data/definitions/798.html"
  4. `CG-PATH-001` (Path Traversal):
     - Pattern: `(?i)\.\./|\.\.\\`
     - Severity: `SarifLevel::Warning` (CWE-22)
     - Message: "Potential directory traversal via unvalidated relative path sequence."
     - URI: "https://cwe.mitre.org/data/definitions/22.html"
  5. `CG-CRYP-001` (Weak Cryptography):
     - Pattern: `(?i)(md5::new|sha1::new|CryptoJS\.MD5|CryptoJS\.SHA1|hashlib\.md5|hashlib\.sha1)`
     - Severity: `SarifLevel::Warning` (CWE-327)
     - Message: "Broken or cryptographically weak hashing algorithm (MD5/SHA1) detected."
     - URI: "https://cwe.mitre.org/data/definitions/327.html"
- **Engine Logic:**
  - Reads each collected source file. Gracefully skips non-UTF-8 content with a `tracing::warn!` message.
  - Computes exact line number and column number for each regex match.
  - Builds `SarifResult` with `PhysicalLocation` (`artifact_location`, `region`).
  - Calls `result.compute_deterministic_fingerprint(None)` to stamp BLAKE3 partial fingerprint.

### Task 4: Connect SAST Engine to `cyberguard-cli`
- **Files to Modify:**
  - `crates/cyberguard-cli/Cargo.toml`: Add `cyberguard-sast = { workspace = true }`.
  - `crates/cyberguard-cli/src/main.rs`: Connect `Commands::Scan` to `NativeRuleEngine`.
- **CLI Behavior:**
  - `cyberguard scan <PATH>` traverses files and runs `NativeRuleEngine::analyze`.
  - Applies `--min-severity` filter (e.g. `error` filters out `warning` and `note`).
  - Emits formatted output:
    - `Terminal`: Colorful table/list with file path, line:col, rule ID, severity, message, and snippet.
    - `Sarif`: Emits full OASIS SARIF v2.1.0 JSON payload directly to stdout.
    - `Json`: Emits compact JSON findings directly to stdout.
  - Process exits cleanly with exit code 0.

---

## 6. QA Verification & Test Coverage Plan
- Unit tests in `crates/cyberguard-sast/tests/native_rules_test.rs`:
  - Positive tests validating each of the 5 rules against standard vulnerable code snippets.
  - Negative tests validating that clean, safe code produces zero false positives.
- Unit tests in `crates/cyberguard-sast/tests/walker_test.rs`:
  - Verify directory traversal skips `node_modules/`, `target/`, and non-source extensions.
  - Verify depth limits and single file scans.
- Integration tests in `crates/cyberguard-cli/tests/scan_e2e_test.rs`:
  - End-to-end execution of `cyberguard scan` producing valid SARIF v2.1.0 output.
- Zero Clippy warnings: `cargo clippy --workspace -- -D warnings`.
- Code formatting check: `cargo fmt --check`.

---

## 7. Step 4: Definition of Done (DoD)
1. `crates/cyberguard-sast` compiles cleanly in the workspace.
2. `cyberguard scan <PATH>` runs native static analysis and emits valid SARIF v2.1.0 and terminal reports.
3. Test coverage on new code exceeds 80% and all automated tests pass.
4. Clean commit signed with Linux Foundation DCO (`git commit -s`).

---

## 8. Elephant-Goldfish Model (EGM) Review Gate Audit Trail
The design specification and detailed implementation plan for Module 04 were subjected to the 5-stage adversarial EGM Goldfish Review Protocol:
- **Stage 5 (Initial Zoom Out):** [zoom_out_report.md](file:///home/john/CYBER-GUARD/docs/modules/reviews/module-04/zoom_out_report.md) — Reviewed by `egm-zoom-out` and `egm-inventive-catalyst`.
- **Stage 6 (Comprehension Test):** [comprehension_report.md](file:///home/john/CYBER-GUARD/docs/modules/reviews/module-04/comprehension_report.md) — Reviewed by `egm-comprehension`.
- **Stage 7 (Critic Review):** [critic_report.md](file:///home/john/CYBER-GUARD/docs/modules/reviews/module-04/critic_report.md) — Reviewed by `egm-design`, `egm-structural`, and `egm-style`.
- **Stage 8 (Intermediate Zoom Out):** [intermediate_zoom_out_report.md](file:///home/john/CYBER-GUARD/docs/modules/reviews/module-04/intermediate_zoom_out_report.md) — Reviewed by `egm-zoom-out`.
- **Stage 9 (Implementation Readiness Test):** [implementation_readiness_report.md](file:///home/john/CYBER-GUARD/docs/modules/reviews/module-04/implementation_readiness_report.md) — Reviewed by `egm-implementation-readiness`, `egm-codebase-details`, and `egm-style`.

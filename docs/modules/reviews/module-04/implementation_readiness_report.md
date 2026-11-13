# Implementation Readiness Report: Stage 9 Review

**Target:** `/home/john/CYBER-GUARD/docs/modules/MODULE_04.md` (Lines 76–140, `DetailedRange`)  
**Standard:** `resources/document_standards/implementation-readiness-standard.md`

## Reviewer Status

| Reviewer | Lens | Status |
| :--- | :--- | :--- |
| `egm-implementation-readiness` | Pragmatic Tech Lead (Zero-Decision Rule, Actionability) | completed |
| `egm-codebase-details` | Technical Quality Auditor (Codebase Alignment, APIs, Reuse) | completed |
| `egm-style` | Technical Copy Editor (Clarity, Precision, Claim Calibration) | completed |

---

## Prioritized Findings (Blockers -> Major -> Nits)

### 🔴 Finding 1: Contradictory API & Interface Definition (`SastAnalyzer::analyze` vs `NativeRuleEngine::scan`)
* **Reviewer Lens:** `egm-codebase-details`, `egm-implementation-readiness`, `egm-style`
* **Affected Scope:** Lines 87, 104, 134
* **Discrepancy Description:** Task 1 defines `pub trait SastAnalyzer { fn analyze(...) -> Result<Vec<SarifResult>, CyberguardError>; }`, but Task 2 never implements `SastAnalyzer` for `NativeRuleEngine`. Furthermore, Task 4 states that the CLI invokes an undeclared method `NativeRuleEngine::scan`.
* **Rationale & Recommendation:** Eliminate the contradiction. Specify `impl SastAnalyzer for NativeRuleEngine`, keep `async fn analyze(&self, ctx: &ScanContext) -> Result<Vec<SarifResult>, CyberguardError>`, and have the CLI invoke the analyzer through `SastAnalyzer`.

---

### 🔴 Finding 2: Synchronous Trait Blocks Async Subprocess Orchestration
* **Reviewer Lens:** `egm-codebase-details`, `egm-implementation-readiness`
* **Affected Scope:** Lines 87, 91; `crates/cyberguard-proc/src/supervisor.rs:12`
* **Discrepancy Description:** `cyberguard-proc::execute_process` is `async`, but `SastAnalyzer::analyze` is defined synchronously. Wrapping any async subprocess execution inside a sync trait forces blocking runtime threads.
* **Rationale & Recommendation:** Define the trait method as asynchronous: `async fn analyze(&self, ctx: &ScanContext) -> Result<Vec<SarifResult>, CyberguardError>`.

---

### 🔴 Finding 3: Undefined Built-in Rule Patterns and Zero-Decision Violations
* **Reviewer Lens:** `egm-implementation-readiness`, `egm-codebase-details`
* **Affected Scope:** Lines 105–110
* **Discrepancy Description:** The plan lists 5 rule IDs (`CG-SQLI-001`, `CG-CMDI-001`, `CG-SECR-001`, `CG-PATH-001`, `CG-CRYP-001`) with short abstract titles, but provides zero regex literals, target severities, rule messages, or documentation URIs. `CG-SECR-001` also mentions "High-entropy" without defining token patterns or an entropy calculation algorithm.
* **Rationale & Recommendation:** Document concrete regex patterns, exact `SarifLevel` mappings, descriptive messages, and CWE tags for each rule in the plan.

---

### 🟡 Finding 4: Incomplete Root Workspace Dependency Declarations
* **Reviewer Lens:** `egm-codebase-details`, `egm-implementation-readiness`
* **Affected Scope:** Lines 84–91, 130–136; root `Cargo.toml`
* **Discrepancy Description:** The root workspace enforces dependency inheritance via `[workspace.dependencies]`. The plan fails to specify adding `cyberguard-sast = { path = "crates/cyberguard-sast" }` and `regex = "1.11"` to root `[workspace.dependencies]`.
* **Rationale & Recommendation:** Explicitly detail additions to both `[workspace.members]` and `[workspace.dependencies]` in root `Cargo.toml`.

---

### 🟡 Finding 5: Unspecified Traversal Constraints and File Filtering (`walker.rs`)
* **Reviewer Lens:** `egm-codebase-details`, `egm-implementation-readiness`, `egm-style`
* **Affected Scope:** Lines 116–126
* **Discrepancy Description:** Task 3 plans a bespoke directory crawler without declaring `walkdir` or `ignore` in dependencies. It does not define supported file extensions (risking regex scans on binary/media files), single file scanning behavior, or cycle/symlink handling.
* **Rationale & Recommendation:** Replace custom walker logic with the standard `ignore` crate (or `walkdir`) with an explicit whitelist of supported source file extensions (`.rs`, `.py`, `.js`, `.ts`, `.go`, `.java`, `.c`, `.cpp`), max depth enforcement, and graceful skipping of unreadable/binary files.

---

### 🟡 Finding 6: Scope Discrepancy — Complete Omission of External Tool Tasks
* **Reviewer Lens:** `egm-implementation-readiness`, `egm-codebase-details`
* **Affected Scope:** Lines 76–140 vs Section 1 (Lines 6–14) and Section 3 (Lines 46–54)
* **Discrepancy Description:** Sprint objectives and architecture diagrams specify Semgrep, Gosec, Bandit orchestration and deduplication, but Tasks 1–4 contain zero tasks, structs, or tests for them. Task 1 prematurely adds `cyberguard-proc` without utilizing it.
* **Rationale & Recommendation:** Formally record external multi-tool adapters as Non-Goals for Module 04, focusing Module 04 on delivering the pluggable `SastAnalyzer` trait and `NativeRuleEngine`.

---

### 🟡 Finding 7: Missed Codebase Reuse of Deterministic Fingerprinting & Incomplete CLI Integration
* **Reviewer Lens:** `egm-codebase-details`, `egm-style`
* **Affected Scope:** Lines 128–139; `crates/cyberguard-core/src/sarif.rs#L190-L207`
* **Discrepancy Description:** Module 03 implemented `SarifResult::compute_deterministic_fingerprint()`, but Tasks 2 and 4 do not specify calling it. In addition, CLI `--min-severity` filtering and exit code behavior are unstated.
* **Rationale & Recommendation:** Specify that `NativeRuleEngine` invokes `SarifResult::compute_deterministic_fingerprint()` on each finding. Detail `--min-severity` filtering logic and exit code semantics (exit 0 on clean or findings reported, exit 1 on execution error).

---

### 🟢 Finding 8: Jargon, Promotional Buzzwords, and Redundant Phrasing
* **Reviewer Lens:** `egm-style`
* **Affected Scope:** Lines 95, 116, 121, 137, 140
* **Discrepancy Description:** Promotional buzzwords like "Zero-Dependency SAST", "Smart Vendor & Git Exclusions", informal slang like "Wire up", and uncalibrated claims like "real findings".
* **Rationale & Recommendation:** `CALIBRATE`. Clean up terminology to factual, professional engineering prose: "Implement In-Process NativeRuleEngine", "Directory Crawler with Default Directory Exclusions", "Connect scan subcommand".

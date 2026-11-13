# Comprehension Report: Stage 6 Comprehension Test

**Target:** `/home/john/CYBER-GUARD/docs/modules/MODULE_04.md` (Lines 1–140)  
**Reviewer:** `egm-comprehension` (Naive Reader Persona)

---

### What this proposes
The document proposes the implementation of Module 04 for the CyberGuard security scanner, introducing a Static Application Security Testing (SAST) engine within `crates/cyberguard-sast` and integrating it into `cyberguard-cli`. The planned engine includes a zero-dependency native rule scanner executing OWASP security checks via linear-time regular expressions, a smart directory crawler that excludes vendor and version control directories, and an architectural framework to safely orchestrate external analyzers (Semgrep, Gosec, Bandit) via isolated subprocesses with SHA-256 deduplication and OASIS SARIF v2.1.0 output formatting.

### How the existing system works, per this document
Based on this document, CyberGuard is structured as a multi-crate Rust workspace comprising `cyberguard-core`, `cyberguard-proc`, and `cyberguard-cli`. A standardized OASIS SARIF v2.1.0 data bus was established in Module 03, and `cyberguard-proc` exists to execute external command-line tools inside isolated POSIX process groups to prevent GPL copyleft contagion and resource exhaustion. The current CLI serves as the entry point but currently lacks native SAST inspection workflows.

---

### Prioritized Findings

#### 1. Severity: Major
* **Affected Scope:** Section 1 (User Story, line 7), Section 3 (Components 3 & 4, lines 46–54), Section 4 (QA Plan, line 63) vs. Section 6 (Detailed Implementation Plan, lines 76–140)
* **Discrepancy Description & Rationale:** Missing Implementation Tasks for External Orchestrator, Deduplication, and Suppression Filters.  
  The User Story and Architecture design state that the SAST engine safely orchestrates external tools (Semgrep, Gosec, Bandit) via `cyberguard-proc`, deduplicates findings with SHA-256 partial fingerprints, and supports suppression filters. However, Section 6's Detailed Implementation Plan (Tasks 1 through 4) only implements the native regex engine, directory crawler, and CLI wiring. External tool orchestration, deduplication logic, and suppression filters have no associated tasks, interfaces, or verification steps in the implementation plan. A new reader cannot tell if these components are deferred to another sprint or omitted by mistake.

#### 2. Severity: Major
* **Affected Scope:** Section 3 (Component 2, line 42), Section 6 (Task 2, lines 95–115)
* **Discrepancy Description & Rationale:** Undefined and Unsupported "AST Token Matcher".  
  Section 3 claims the Native Rule Engine performs "Linear-time regex + AST token matcher (OWASP Top 10 rules)" with zero dependencies. However, Task 2 defines `SastRule` purely with a `pattern: Regex` field, and the crate dependencies in Task 1 contain no AST parsing libraries or tree-sitter grammars. The document provides no explanation or definition of what constitutes this "AST token matcher" or how AST-level matching can occur across multiple source languages without parser dependencies.

#### 3. Severity: Major
* **Affected Scope:** Section 1 (Sprint Objective & User Story, line 7)
* **Discrepancy Description & Rationale:** Undefined Concept: "Suppression Filters".  
  The user story explicitly requires "suppression filters" as a core capability alongside deterministic partial fingerprints. However, the document never defines what a suppression filter is, what syntax or configuration format it uses (e.g., inline source code comments like `// cyberguard:ignore`, a config file, or SARIF suppression objects), or where in the pipeline it is evaluated.

#### 4. Severity: Nit
* **Affected Scope:** Section 3 (Component 1, lines 36–39) vs. Section 6 (Task 1, line 87)
* **Discrepancy Description & Rationale:** Inconsistent `SastAnalyzer` Trait Definition.  
  Section 3 defines the trait interface as having three methods: `name(&self) -> &str`, `is_available(&self) -> bool`, and `analyze(&self, ctx: &ScanContext) -> Result<Vec<SarifResult>>`. In Section 6 (Task 1), the trait signature omits `is_available(&self) -> bool`. Given that the QA plan (line 63) requires graceful fallback when an external scanner is not installed, dropping `is_available` creates an interface mismatch.

#### 5. Severity: Nit
* **Affected Scope:** Section 6 (Task 1 line 87, Task 2 line 103)
* **Discrepancy Description & Rationale:** Unstated Origin for Domain Types (`SarifResult`, `CyberguardError`, `SarifLevel`).  
  The trait and rule signatures introduce `SarifResult`, `CyberguardError`, and `SarifLevel` without documenting where they are imported from. While an experienced workspace engineer might deduce they reside in `cyberguard-core`, the document assumes this institutional knowledge rather than qualifying the crate path (e.g., `cyberguard_core::SarifResult`).

#### 6. Severity: Nit
* **Affected Scope:** Section 6 (Task 2 line 104, Task 4 line 134)
* **Discrepancy Description & Rationale:** Ambiguous Relationship between `NativeRuleEngine` and `SastAnalyzer`.  
  Task 1 creates the pluggable `SastAnalyzer` trait, but Task 2 never specifies that `NativeRuleEngine` implements `SastAnalyzer`. Furthermore, Task 4 states that the CLI invokes `NativeRuleEngine::scan` directly rather than invoking the generic `SastAnalyzer` interface, leaving the role of the pluggable trait disconnected from the CLI integration.

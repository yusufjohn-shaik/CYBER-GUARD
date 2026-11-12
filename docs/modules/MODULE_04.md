# 📦 Module 04: SAST Static Analysis Engine & Multi-Tool Orchestrator
## Sprint Execution Record (Agile-Spiral Hybrid Model)

---

## 1. Sprint Objective & User Story
**User Story:** As a software engineer or DevSecOps lead, I need a fast, extensible Static Application Security Testing (SAST) engine that performs native zero-dependency semantic rule matching across source files, safely orchestrates external specialized analyzers (Semgrep, Gosec, Bandit) inside isolated process groups, and normalizes all findings into OASIS SARIF v2.1.0 with deterministic partial fingerprints and suppression filters.

**Module Number:** 04 of 21  
**Target Delivery Date:** November 13, 2026  
**Primary Crates:** `cyberguard-sast`, `cyberguard-core`, `cyberguard-proc`, `cyberguard-cli`  
**Language:** Rust 1.85+ (2024 Edition)  

---

## 2. Step 1: Spiral Risk Gate (Quadrant II: Risk Analysis)

Before writing any implementation code for Module 04, the engineering team executed the mandatory Spiral Risk Assessment:

| Risk ID | Identified Risk | Impact | Architectural Mitigation Strategy | Gate Status |
| :--- | :--- | :--- | :--- | :--- |
| **RISK-04-01** | **Infinite Symlink Traversal & Directory Bombing:** Scanning recursive directory trees or broken symlinks could trap the scanner in an infinite loop. | Critical | Implement cycle detection and path canonicalization via `walkdir` or standard traversal with configurable depth limits (default max depth: 32) and symlink resolution flags. | **CLEARED ✅** |
| **RISK-04-02** | **External Copyleft Contamination (GPL Tooling):** Integrating GPL-licensed static analysis tools (e.g., certain Semgrep components, Bandit) could risk copyleft contagion. | Critical | Strictly isolate external analyzers behind `cyberguard-proc` as out-of-process CLI executables. Never vendor or link GPL code directly into the Rust binary. Dual-license clean-room Apache-2.0 strictly preserved. | **CLEARED ✅** |
| **RISK-04-03** | **Regular Expression Denial of Service (ReDoS):** Complex regex patterns in native security rules could exhibit exponential backtracking catastrophic failure on malicious inputs. | High | Use the linear-time `regex` crate which is mathematically guaranteed to run in $O(n)$ time with finite automata, completely immune to ReDoS. | **CLEARED ✅** |
| **RISK-04-04** | **Noise from Vendor & Test Directories:** Scanning `node_modules`, `vendor/`, `tests/`, or `.git` generates thousands of irrelevant alerts. | High | Enforce default ignore filters honoring `.gitignore`, standard vendor paths (`node_modules/`, `vendor/`, `target/`, `venv/`, `.git/`), and test folders unless explicitly overridden via CLI flags. | **CLEARED ✅** |
| **RISK-04-05** | **Lossy Normalization Across Analyzers:** External scanners output inconsistent proprietary JSON formats. | Medium | Implement dedicated typed parsers mapping each external format directly into the standardized OASIS SARIF v2.1.0 data bus delivered in Module 03. | **CLEARED ✅** |

---

## 3. Step 2: Architecture & Component Breakdown

```
┌────────────────────────────────────────────────────────────────────────┐
│                        crates/cyberguard-sast                          │
├────────────────────────────────────────────────────────────────────────┤
│ 1. PLUGGABLE ANALYZER TRAIT (SastAnalyzer)                             │
│    • name(&self) -> &str                                               │
│    • is_available(&self) -> bool                                       │
│    • analyze(&self, ctx: &ScanContext) -> Result<Vec<SarifResult>>     │
├────────────────────────────────────────────────────────────────────────┤
│ 2. NATIVE RULE ENGINE (Pure Rust Zero-Dependency)                      │
│    • Linear-time regex + AST token matcher (OWASP Top 10 rules)        │
│    • Rules: SQLi, Command Injection, Path Traversal, Hardcoded Keys,   │
│      Weak Hashing (MD5/SHA1), Insecure TLS, CORS Wildcards.           │
├────────────────────────────────────────────────────────────────────────┤
│ 3. SANDBOXED EXTERNAL ORCHESTRATOR (cyberguard-proc)                   │
│    • Dispatches Semgrep, Gosec, Bandit inside POSIX process groups     │
│    • Bounded 10 MB circular buffers prevent memory exhaustion          │
├────────────────────────────────────────────────────────────────────────┤
│ 4. DEDUPLICATION & FINGERPRINTING ENGINE                               │
│    • Merges native and external findings                               │
│    • Generates SHA-256 partialFingerprints to deduplicate cross-tool   │
│      identical alerts                                                  │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Step 3: QA Verification & Test Coverage Plan
- Unit tests for the `NativeRuleEngine` verifying true positives on standard OWASP vulnerability test files.
- Unit tests verifying zero false positives on safe, parameterized queries and sanitized inputs.
- Directory traversal tests validating `.gitignore` and vendor path exclusions.
- Subprocess orchestration tests verifying graceful fallback when an external scanner is not installed.
- Zero warnings under `cargo clippy --workspace -- -D warnings`.

---

## 5. Step 4: Definition of Done (DoD)
1. `crates/cyberguard-sast` compiles cleanly in the virtual workspace.
2. `cyberguard scan <PATH>` runs native static analysis and emits valid SARIF v2.1.0 and terminal reports.
3. Test coverage on new code exceeds 80% with 100% test pass rate.
4. Clean commit signed with Linux Foundation DCO (`git commit -s`).

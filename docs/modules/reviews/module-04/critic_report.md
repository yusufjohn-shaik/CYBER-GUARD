# Critic Review Report: Stage 7 Critic Review

**Target:** `/home/john/CYBER-GUARD/docs/modules/MODULE_04.md` (Lines 1–75, `FeatureRange`)  
**Standard:** `resources/document_standards/feature-spec-standard.md`

## Reviewer Status

| Reviewer | Lens | Status |
| :--- | :--- | :--- |
| `egm-design` | Hostile Design Critic (Architecture, Scalability, Unmitigated Risks) | completed |
| `egm-structural` | Structural Validator (Hierarchy, Templates, Standards Compliance) | completed |
| `egm-style` | Technical Copy Editor (Clarity, Precision, Claim Calibration) | completed |

---

## Prioritized Findings (Blockers -> Major -> Nits)

### 🔴 Finding 1: Mandatory Alternatives Evaluation Missing (Standard Non-Compliance)
* **Reviewer Lens:** `egm-structural`, `egm-design`
* **Affected Scope:** `MODULE_04.md` (Lines 1–75)
* **Discrepancy Description:** The specification violates the core mandatory requirement in `feature-spec-standard.md`: it proposes a single design without evaluating viable rejected alternatives.
* **Rationale & Recommendation:** Add a dedicated `### Alternatives Considered` section documenting evaluated and rejected designs with concrete technical trade-offs:
  1. *Rule Engine*: Pure regex matching vs. Tree-sitter / syn CST parsing (performance vs. precision).
  2. *External Tool Execution*: Subprocess orchestration (`cyberguard-proc`) vs. in-process WASM or LSP daemons (IPC latency vs. memory isolation & GPL clean-room safety).
  3. *Filesystem Traversal*: Single-threaded `walkdir` vs. multithreaded `ignore` crate traversal.

---

### 🔴 Finding 2: Missing Problem Statement and Explicit Goals / Non-Goals
* **Reviewer Lens:** `egm-structural`, `egm-design`
* **Affected Scope:** Section 1 (Lines 6–14)
* **Discrepancy Description:** The document provides a one-sentence user story but omits a formal Problem Statement and explicit Goals & Non-Goals sections mandated by the standard. This creates major architectural ambiguity between the user story/diagram (which advertise Semgrep/Gosec/Bandit orchestration and suppression filters) and the actual implementation tasks (which only build native regex scanning).
* **Rationale & Recommendation:** Add explicit `Problem Statement`, `Goals`, and `Non-Goals` sections. Explicitly define scope boundaries: Module 04 delivers the `SastAnalyzer` trait and native in-process regex scanner, while multi-tool adapters and cross-tool deduplication pipelines are non-goals for this module.

---

### 🟡 Finding 3: Infeasible Cross-Tool Deduplication & Hashing Contradiction
* **Reviewer Lens:** `egm-design`
* **Affected Scope:** Section 3 (Lines 50–54)
* **Discrepancy Description:** 
  1. *Algorithm Contradiction*: Module 03 establishes BLAKE3 as the platform standard for partial fingerprints, whereas line 52 specifies SHA-256.
  2. *Deduplication Flaw*: Hashing tool-specific `rule_id` and line numbers prevents cross-tool deduplication because external tools use disparate rule schemas (e.g., Semgrep vs Bandit `B303` vs `CG-CRYP-001`).
* **Rationale & Recommendation:** Standardize on BLAKE3 to maintain consistency with Module 03. Specify a canonical taxonomy mapping layer (CWE categories and normalized code token slices) before computing cross-tool deduplication fingerprints.

---

### 🟡 Finding 4: External Subprocess Buffer Truncation Corrupts JSON Payloads
* **Reviewer Lens:** `egm-design`, `egm-style`
* **Affected Scope:** Section 3 (Lines 46–49), Section 2 (RISK-04-05)
* **Discrepancy Description:** The architecture specifies bounded 10 MB buffers for external tool execution via `cyberguard-proc`. For large codebases, output exceeding 10 MB is truncated, causing downstream JSON deserialization to fail on incomplete syntax (`EOF while parsing`) and discarding all scan results. In addition, `cyberguard-proc` uses a linear truncating buffer, not a circular ring buffer.
* **Rationale & Recommendation:** Calibrate terminology from "circular buffers" to "bounded truncating buffers". For large external analyzer outputs, specify redirecting output directly to sandboxed temporary files (`--output <temp_path>.json`) or streaming deserialization.

---

### 🟡 Finding 5: Sequential Filesystem Traversal Bottleneck & Monolithic In-Memory Buffering
* **Reviewer Lens:** `egm-design`
* **Affected Scope:** Section 2 (RISK-04-01, RISK-04-04), Section 6 (Task 3)
* **Discrepancy Description:** Single-threaded crawling with `walkdir` accumulating all paths into a heap-allocated `Vec<PathBuf>` creates memory and latency bottlenecks on large repositories and lacks native `.gitignore` hierarchy evaluation.
* **Rationale & Recommendation:** Adopt the multithreaded `ignore` crate (underlying ripgrep). Stream discovered paths through bounded channels directly to rule evaluation tasks.

---

### 🟡 Finding 6: Uncalibrated "Semantic" and "Zero-Dependency" Claims
* **Reviewer Lens:** `egm-style`, `egm-design`
* **Affected Scope:** Section 1 (Line 7), Section 3 (Lines 41–44)
* **Discrepancy Description:** Promotional and technically inaccurate terms: "zero-dependency", "semantic rule matching", and "AST token matcher". The engine depends on workspace/external crates (`regex`, `tokio`, `thiserror`), and regex matching on text is lexical pattern matching, not semantic AST dataflow analysis.
* **Rationale & Recommendation:** `CALIBRATE`. Replace "zero-dependency semantic rule matching" with "native regex pattern matching", and replace "Pure Rust Zero-Dependency" and "AST token matcher" with "In-process Rust regex rule engine".

---

### 🟡 Finding 7: Hyperbolic and Unverifiable Certainty Claims
* **Reviewer Lens:** `egm-style`
* **Affected Scope:** Section 2 (Line 24), Section 4 (Line 61)
* **Discrepancy Description:** Uncalibrated absolutes: "mathematically guaranteed... completely immune to ReDoS" and "verifying zero false positives". Heuristic security pattern rules cannot guarantee zero false positives across arbitrary code.
* **Rationale & Recommendation:** `CALIBRATE`. Rephrase to: "Use Rust's `regex` crate, which uses finite automata with linear-time search guarantees ($O(n)$) to prevent backtracking ReDoS" and "Unit tests verifying absence of false positives across curated parameterized query and sanitization test fixtures."

---

### 🟢 Finding 8: Missing Operational Constraints and Scalability Limits
* **Reviewer Lens:** `egm-structural`
* **Affected Scope:** Section 2 (Lines 16–27)
* **Discrepancy Description:** Omits explicit operational constraints (e.g., maximum traversal depth limits, memory caps, concurrency bounds) required by the standard.
* **Rationale & Recommendation:** Explicitly declare numerical bounds and operational limits in the risk matrix.

---

### 🟢 Finding 9: Heading Layout & Section Taxonomy Flaws
* **Reviewer Lens:** `egm-structural`, `egm-style`
* **Affected Scope:** Lines 1–4, Lines 6–75
* **Discrepancy Description:** Empty H2 header acting as an orphaned subtitle, dual indexing (`## 2. Step 1: ...`), decorative emoji glyph (`📦`), and unlabelled fenced code block.
* **Rationale & Recommendation:** Format subtitle as italicized text under H1, remove dual indexing, label code block as ```` ```text ````, and remove decorative emojis.

---

### 🟢 Finding 10: Rust Edition Discrepancy
* **Reviewer Lens:** `egm-style`
* **Affected Scope:** Line 12
* **Discrepancy Description:** Line 12 specifies `Rust 1.85+ (2024 Edition)`, but workspace `Cargo.toml` sets `edition = "2021"`.
* **Rationale & Recommendation:** Align specification with workspace manifest (`Rust 1.85+, 2021 Edition`).

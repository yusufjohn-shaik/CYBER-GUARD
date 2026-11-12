# 🛠️ CyberGuard: The Definitive Gap-Filling Blueprint
## Architectural Execution Strategy to Surpass Existing Security Solutions

---

## 1. Executive Strategy

To surpass industry giants (Cloudflare, Wiz, Snyk, Semgrep, Trivy), CyberGuard does not compete on superficial feature checklists. Instead, it systematically resolves the **fundamental architectural flaws** that plague existing tools:
1. **The Code-to-Cloud Divide:** Solved via an **In-Memory Attack Path Graph (DAG)** connecting code ASTs to live cloud IAM.
2. **The 70–90% False Positive Crisis:** Solved via the **Tri-Factor Risk Index (`CVSS × EPSS × Reachability`)**.
3. **Shallow AI Text Hallucinations:** Solved via **Surgical Tree-sitter AST Patching + Automated Unit Regression Tests**.
4. **Prompt-Only Agentic Auditing:** Solved via a **Native Rust Model Context Protocol (MCP) Server (`rmcp`)**.
5. **Runtime Bloat & Zombie Processes:** Solved via a **Single Static Rust Binary with POSIX Process-Group Sandboxing (`setpgid`)**.

---

## 2. Technical Blueprint: The Five Gap-Filling Pillars

```
┌────────────────────────────────────────────────────────────────────────┐
│                        PILLAR 1: ATTACK PATH GRAPH (DAG)               │
│   petgraph::StableGraph uniting:                                       │
│   Public Route ➔ AST Taint ➔ Vulnerable Library ➔ Leaked Credential    │
│   ➔ AWS/K8s IAM Escalation                                            │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                   PILLAR 2: TRI-FACTOR NOISE ELIMINATION               │
│   Risk Score = CVSS (Severity) × EPSS (Threat Intel) × Reachability    │
│   • Reachability = 0.0 if Tree-sitter proves function is never called │
│   • Eradicates 80%+ of false positives and developer alert fatigue     │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                 PILLAR 3: AUTONOMOUS AST REMEDIATION ENGINE            │
│   • Tree-sitter CST Node Replacement (parameterized SQL, sanitizers)   │
│   • Unified diff synthesis (similar / diffy)                           │
│   • Auto-generates unit regression test stubs proving exploit is blocked│
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│               PILLAR 4: MODEL CONTEXT PROTOCOL (MCP) AI SKILL          │
│   • Built with official rmcp SDK over stdio & Server-Sent Events (SSE) │
│   • Tools: cyberguard_scan, cyberguard_trace, cyberguard_generate_fix  │
│   • Powers Claude Code, Antigravity, and Cursor natively               │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│               PILLAR 5: SANDBOXED PROCESS SUPERVISOR                   │
│   • POSIX process group isolation (setpgid) with 2-stage SIGTERM/SIGKILL│
│   • Bounded 10 MB circular memory buffer (prevents OOM DoS)            │
│   • Zero CGO compilation dependencies; single static Rust binary       │
└────────────────────────────────────────────────────────────────────────┘
```

---

### Pillar 1: In-Memory Attack Path Graph (`crates/cyberguard-graph`)
* **How It Bridges the Gap:** Cloudflare and Semgrep operate at isolated layers. CyberGuard constructs an in-memory Directed Acyclic Graph using `petgraph::StableGraph`.
* **Technical Structure:**
  ```rust
  pub enum GraphNode {
      Endpoint { path: String, method: String, is_public: bool },
      TaintedSource { parameter: String, source_type: String },
      CallGraphFunction { symbol: String, file: PathBuf, line: usize },
      VulnerableDependency { package: String, version: String, cve: String },
      CredentialFinding { secret_type: String, file: PathBuf },
      CloudIAMRole { arn: String, permissions: Vec<String> },
  }

  pub enum GraphEdge {
      FlowsInto,
      CallsFunction,
      ImportsPackage,
      AuthenticatesWith,
      EscalatesTo,
  }
  ```
* **Algorithm:** Tarjan's Strongly Connected Components (SCC) algorithm detects and prunes cyclic references. Dijkstra and reverse topological sort determine whether an external attacker can navigate from an exposed endpoint down to a critical sink.

---

### Pillar 2: Tri-Factor Noise Eradication (`crates/cyberguard-core`)
* **How It Bridges the Gap:** Replaces naive manifest matching (Trivy/Grype) and banner matching (Cloudflare Flan Scan).
* **Mathematical Model:**
  $$\text{Final Risk Score} = \text{CVSS} \times \text{EPSS} \times \text{Reachability}$$
  1. **CVSS (0.0 to 10.0):** Theoretical vulnerability severity from NVD/OSV.
  2. **EPSS (0.0 to 1.0):** Real-time exploit probability queried non-blockingly from FIRST.org via `reqwest` with local `redb` caching.
  3. **Reachability (0.0 or 1.0):** Calculated by `cyberguard-ast`. If `Reachability == 0.0` (function is never invoked by any active endpoint), the entire finding score drops to `0.0` (Informational/Suppressed).

---

### Pillar 3: Autonomous AST Remediation Engine (`crates/cyberguard-remediate`)
* **How It Bridges the Gap:** Fixes the hallucination and syntax-breaking problems of GitHub Copilot Autofix and Snyk AI Fix.
* **Deterministic Transformation:**
  1. Parse the target file into a Concrete Syntax Tree (CST) using `tree-sitter`.
  2. Identify the exact byte boundaries of the vulnerable node (e.g., string concatenation in a raw SQL query).
  3. Replace the node with parameterized bindings:
     ```rust
     // Before: format!("SELECT * FROM users WHERE id = '{}'", input)
     // After:  sqlx::query("SELECT * FROM users WHERE id = $1").bind(input)
     ```
  4. Generate a clean unified diff using `similar` and `diffy`.
  5. Auto-generate a unit regression test verifying:
     - Attack payload (`' OR '1'='1`) is rejected.
     - Legitimate payload (`42`) succeeds.

---

### Pillar 4: Model Context Protocol (MCP) Server (`crates/cyberguard-mcp`)
* **How It Bridges the Gap:** Upgrades Cloudflare's prompt-only `security-audit-skill` into a compiled, high-performance JSON-RPC 2.0 tool server.
* **Architecture:**
  - Implemented using the official `rmcp` SDK.
  - Exposes standardized tools to AI agents:
    - `cyberguard_scan`: Fast AST/SAST analysis.
    - `cyberguard_trace_attack_path`: Graph correlation of exploit chains.
    - `cyberguard_generate_patch`: Syntax-verified AST remediation.
  - Supports `stdio` transport for CLI agents (Claude Code, Antigravity) and Server-Sent Events (SSE) for web-based IDEs.

---

### Pillar 5: Subprocess Supervisor Microkernel (`crates/cyberguard-proc`)
* **How It Bridges the Gap:** External scanners (Semgrep, Nmap, Trivy) frequently hang, leak zombie processes, or crash systems via memory exhaustion.
* **Implemented Fortress:**
  - **POSIX `setpgid(0, 0)`:** Spawns children into isolated process groups.
  - **Bounded 10 MB Ring Buffer:** Stdout and stderr are read non-blockingly; if output exceeds 10 MB, excess is drained and flagged as `truncated`, completely preventing Out-Of-Memory (OOM) crashes.
  - **Two-Stage Signal Termination:** Sends `SIGTERM` to `-pgid`, waits a 50ms grace window, and escalates to `SIGKILL` to clean up grandchild processes.

---

## 3. Sprint-by-Sprint Execution Roadmap (Modules 03 to 21)

Every gap is filled systematically through our **Agile-Spiral Hybrid** daily module delivery:

```
[Module 01: Governance] ➔ COMPLETED ✅
[Module 02: Core CLI & Process Supervisor] ➔ COMPLETED ✅
        │
        ▼
[Module 03: Universal SARIF & OCSF Data Bus] ──► Standardize security interchange schemas
        │
        ▼
[Module 04: SAST Static Analysis Engine] ────► Orchestrate Semgrep/CodeQL in isolated sandboxes
        │
        ▼
[Module 05: SCA & Supply Chain Security] ────► SBOM generation (CycloneDX/SPDX) + OSV database
        │
        ▼
[Module 06: Secret Detection Engine] ────────► Pure-Rust gix Git traversal + Shannon entropy
        │
        ▼
[Module 07: Container & OCI Security] ───────► Docker layer unpacking & Hadolint analysis
        │
        ▼
[Module 08: Network Recon & Scope Gate] ─────► Proof-of-Authorization (ed25519) + Origin IP check
        │
        ▼
[Module 09: DAST & Dynamic Security] ────────► Nuclei engine orchestration + Katana crawler
        │
        ▼
[Module 10: API Security & Spec Fuzzing] ────► OpenAPI 3.0/3.1 parser + BOLA/BFLA fuzzer
        │
        ▼
[Module 11: Cloud Security (CSPM/CIEM)] ─────► AWS/GCP IAM role and permission graph ingestion
        │
        ▼
[Module 12: IaC Security & Policy as Code] ──► hcl-rs Terraform parser + OPA/Rego policies
        │
        ▼
[Module 13: CI/CD Pipeline & SLSA] ──────────► GitHub Actions security + Cosign provenance
        │
        ▼
[Module 14: Mobile Security (SAST/DAST)] ────► MobSF static/dynamic security integration
        │
        ▼
[Module 15: Threat Modeling & ATT&CK] ───────► MITRE ATT&CK Navigator mapping
        │
        ▼
[Module 16: Autonomous MCP AI Agent] ────────► Official rmcp SDK server over stdio & SSE
        │
        ▼
[Module 17: Attack Path Engine (DAG)] ───────► petgraph in-memory Directed Acyclic Graph
        │
        ▼
[Module 18: Tri-Factor Prioritizer] ─────────► CVSS × EPSS × Reachability mathematical engine
        │
        ▼
[Module 19: Autonomous AST Remediation] ─────► Tree-sitter CST surgical patcher & test generator
        │
        ▼
[Module 20: TUI Dashboard & Reporting] ──────► ratatui immediate-mode terminal interface
        │
        ▼
[Module 21: Production Release & Ecosystem] ─► Static musl binaries via cargo-zigbuild
```

---

## 4. Definition of Success: How We Know We Won

1. **Noise Eradication:** Benchmark CyberGuard against Trivy and Semgrep on top 100 GitHub repositories; prove CyberGuard eliminates **≥75% of alerts** while maintaining **100% true-positive recall** via reachability.
2. **Deterministic Fixes:** 100% of generated AST patches pass `cargo test` / `pytest` / `jest` with synthesized regression unit tests.
3. **AI Agent Ubiquity:** Any developer using Claude Code, Cursor, or Antigravity CLI can install CyberGuard via `cyberguard mcp` and immediately receive autonomous vulnerability audits.

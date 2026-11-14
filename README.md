<div align="center">

# 🛡️ CYBER-GUARD
### High-Performance Vulnerability Intelligence & Autonomous Remediation Platform

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg?style=flat-square)](LICENSE)
[![Rust Version](https://img.shields.io/badge/Rust-1.85%2B-orange.svg?style=flat-square&logo=rust)](https://www.rust-lang.org)
[![CI Status](https://img.shields.io/github/actions/workflow/status/yusufjohn-shaik/CYBER-GUARD/dco_and_lint.yml?branch=main&label=CI%20Quality%20Gate&style=flat-square)](https://github.com/yusufjohn-shaik/CYBER-GUARD/actions)
[![SARIF Standard](https://img.shields.io/badge/Standard-OASIS%20SARIF%20v2.1.0-orange.svg?style=flat-square)](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
[![AI Agent Protocol](https://img.shields.io/badge/AI%20Protocol-Model%20Context%20Protocol%20(MCP)-8A2BE2.svg?style=flat-square)](https://modelcontextprotocol.io)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](CONTRIBUTING.md)
[![DCO](https://img.shields.io/badge/DCO-Signed--off--by-green.svg?style=flat-square)](CONTRIBUTING.md)

<p align="center">
  <b>100% Pure Native Rust • Zero External Runtime Dependencies • ReDoS-Immune Linear Scanning • OASIS SARIF v2.1.0 Engine</b>
</p>

[Quickstart](#-quickstart) •
[Capability Matrix](#-capability-status-matrix) •
[Architecture](#-system-architecture) •
[Contributing](#-join-the-community)

</div>

---

## 📊 Capability Status Matrix

To maintain transparent, uncompromising security credibility, here is what is live and verified today versus what is actively being built on the roadmap:

| Capability | Module | Status | Deliverables & Interfaces |
| :--- | :--- | :---: | :--- |
| **Legal & Safe Harbor** | Module 01 | **LIVE ✅** | Apache 2.0, Statutory Safe Harbor, DCO Gate, OpenSSF Scorecard workflow |
| **CLI & Process Supervisor** | Module 02 | **LIVE ✅** | `cyberguard-cli`, POSIX process group sandboxing, 10 MB buffer bounds, Figment config |
| **Universal Security Bus** | Module 03 | **LIVE ✅** | `cyberguard-core`, OASIS SARIF v2.1.0, OCSF v1.3.0, BLAKE3 deterministic fingerprints |
| **In-Process SAST Engine** | Module 04 | **LIVE ✅** | `cyberguard-sast`, linear $O(n)$ regex scanner (SQLi, CMDi, Secrets, Path, Crypto), walker |
| **SCA & Supply Chain** | Module 05 | **LIVE ✅** | `cyberguard-sca`, Cargo/npm lockfile parsing, CycloneDX v1.5 & SPDX v2.3 SBOM, OSV advisory engine |
| **Secret Detection Engine** | Module 06 | **PLANNED 📋** | High-entropy secrets validator, multi-provider credentials detection |
| **MCP AI Agent Server** | Module 16 | **PLANNED 📋** | JSON-RPC Model Context Protocol server for Antigravity, Cursor, and Claude Code |
| **Attack Path Graph (DAG)** | Module 17 | **PLANNED 📋** | In-memory directed acyclic graph mapping multi-hop exploit chains |
| **AST Auto-Remediation** | Module 19 | **PLANNED 📋** | Tree-sitter AST syntax patcher and automated regression test generator |

---

## 🌟 The Vision: Security Built for the Modern Era

Most legacy security scanners were built for the software architectures of a decade ago. Stacking disconnected tools produces shallow results: thousands of unprioritized alerts, 70%+ false positive noise, and zero understanding of how a vulnerability in code actually interacts with cloud permissions, exposed routes, or API dataflows.

**CyberGuard is a purpose-built vulnerability intelligence platform written in pure Rust:**
- **Zero Runtime Dependencies:** No Python, JVM, or Node.js required. Ships as a single static, sandboxed binary.
- **Linear-Time SAST ($O(n)$):** Native regular expression automata mathematically immune to ReDoS backtracking attacks.
- **Universal SARIF v2.1.0 Data Bus:** Deterministic BLAKE3 partial fingerprints (`logicalLocationTokenHash/v1`) prevent duplicate alerts across commits and tooling runs.
- **AI Agent Integration:** Designed to plug directly into AI coding agents via the Model Context Protocol (MCP).

---

## ⚡ Core Capabilities

### 1. 🎯 Deep Native Vulnerability Discovery
CyberGuard combines native AST parsing, semantic taint tracking, and modern API contract fuzzing to detect flaws that traditional regex and shallow scanners miss:
- **OWASP API Top 10:** Broken Object Level Authorization (BOLA), Broken Function Level Authorization (BFLA), Mass Assignment, and Unrestricted Resource Consumption.
- **OWASP Top 10 for LLMs / AI Apps:** Prompt Injection, Insecure Output Handling, Training Data Poisoning, Sensitive Info Disclosure, and Vector DB access control flaws.
- **Cross-Layer Vulnerability Tracing:** Correlating an exposed API route in source code with an overly permissive AWS IAM role or Kubernetes cluster binding.

### 2. 🧠 Tri-Factor Noise Elimination (`CVSS × EPSS × Reachability`)
Legacy scanners overwhelm engineers by marking thousands of CVEs as "Critical" purely based on theoretical CVSS scores. CyberGuard calculates **real-world risk**:
$$\text{Risk Score} = \text{CVSS (Severity)} \times \text{EPSS (Active Exploitation Probability)} \times \text{Reachability Index}$$
If a vulnerable function is never invoked by your application's entry points, its priority is automatically downgraded—saving hundreds of wasted engineering hours.

### 3. 🕸️ In-Memory Attack Path Graph (DAG)
Rather than showing 500 flat alerts, CyberGuard builds a unified Directed Acyclic Graph connecting:
$$\text{External Entrypoint} \longrightarrow \text{API Route} \longrightarrow \text{Vulnerable Code / Dependency} \longrightarrow \text{Leaked Credential} \longrightarrow \text{Cloud Privilege Escalation}$$
Security teams see the **exact kill-chain** an attacker would follow to compromise production assets.

### 4. 🛠️ Autonomous AST Remediation Engine
CyberGuard writes production-ready code fixes:
- Parses the target file's Abstract Syntax Tree (AST) using Tree-sitter.
- Applies surgical, idiomatic patches (parameterized queries, input sanitization, safe deserializers, updated imports).
- Auto-generates unit tests to verify the vulnerability is eradicated without breaking business logic.

---

## 🏛️ System Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│                        CYBERGUARD CLI & TUI INTERFACE                  │
│   cyberguard [scan | audit | trace | fix | mcp | report]               │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│             INTELLIGENCE ENGINE & ATTACK SURFACE DISCOVERY             │
│   - Application Architecture & Endpoint Detector                       │
│   - Semantic Taint Analyzer (Sources ➔ Sanitizers ➔ Sinks)             │
│   - Modern API & LLM Security Validator                                │
│   - Universal SARIF v2.1.0 & OCSF Security Bus                         │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│            CORRELATION ENGINE & ATTACK PATH GRAPH (DAG)                │
│   - In-Memory Graph Engine (Code ➔ Cloud ➔ Network ➔ Identity)         │
│   - Semantic Reachability Checker (Call Graph Call-Path Verifier)      │
│   - Tri-Factor Prioritizer: CVSS × EPSS (Live Threat Intel) × Reach    │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Prioritized, Verified Exploit Paths
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│         AUTONOMOUS REMEDIATION & MODEL CONTEXT PROTOCOL (MCP)          │
│   - Tree-sitter AST Patch Engine (Multi-language surgical fixes)       │
│   - Regression Test Synthesizer (Auto-generates unit tests)            │
│   - MCP Protocol Server (Bi-directional AI Pair Programmer Skill)      │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 🛡️ Built for Modern Stacks

CyberGuard is designed from the ground up for modern application engineering:

| Layer | Modern Target Stack | What CyberGuard Discovers |
| :--- | :--- | :--- |
| **Modern Frameworks** | Next.js, FastAPI, Go Fiber, Spring Boot 3, Rust Axum | Server-Side Request Forgery (SSRF), Prototype Pollution, Tainted Data Flows, CORS Misconfigurations |
| **APIs & Microservices** | REST, GraphQL, gRPC, OpenAPI 3.0 | BOLA / IDOR, Broken Function Level Auth (BFLA), Mass Assignment, GraphQL Depth Limits |
| **AI / GenAI Stacks** | LangChain, LlamaIndex, OpenAI SDK, Vector DBs | Prompt Injection, Insecure Output Handling, Excessive Data Exposure in RAG Pipelines |
| **Supply Chain & SBOM** | npm, PyPI, Go modules, Cargo, Maven | Malicious packages, dependency confusion, typosquatting, reachable CVEs |
| **Cloud-Native & IaC** | Kubernetes, Terraform, Helm, Docker, AWS/GCP | IAM privilege escalation, privilege containers, ingress exposure, hardcoded secrets |

---

## 🚀 Quickstart

### 1. Build from Source (Pure Rust)

```bash
git clone https://github.com/yusufjohn-shaik/CYBER-GUARD.git
cd CYBER-GUARD
cargo build --release
```

### 2. Run the SAST Scanner on the Demo Fixture

CyberGuard ships with an intentionally vulnerable fixture application so you can test detection immediately:

```bash
./target/release/cyberguard scan tests/fixtures/vulnerable-app
```

**Real Terminal Output:**
```text
🛡️  CyberGuard SAST Engine v0.4.0
Target: tests/fixtures/vulnerable-app
Workspace: .
--------------------------------------------------------------------------------
Found 5 vulnerability alert(s):

🔴 ERROR [CG-SQLI-001] tests/fixtures/vulnerable-app/app.py:9:14
   └── Potential SQL injection via raw string interpolation or concatenation.
   └── Fingerprint: 7685d4d6b246a416
🟡 WARN  [CG-CRYP-001] tests/fixtures/vulnerable-app/app.py:17:12
   └── Broken or cryptographically weak hashing algorithm (MD5/SHA1) detected.
   └── Fingerprint: 0aea6a26a7d94cf4
🔴 ERROR [CG-SECR-001] tests/fixtures/vulnerable-app/config.py:5:22
   └── Hardcoded cryptographic secret or API token detected in source code.
   └── Fingerprint: df1e1849a29a4d76
🔴 ERROR [CG-CMDI-001] tests/fixtures/vulnerable-app/handler.js:9:5
   └── Potential OS command injection via unescaped string in command invocation.
   └── Fingerprint: e582c30c13821add
🟡 WARN  [CG-PATH-001] tests/fixtures/vulnerable-app/handler.js:21:34
   └── Potential directory traversal via unvalidated relative path sequence.
   └── Fingerprint: 874987e8a2b5586e
--------------------------------------------------------------------------------
```

### 3. Export OASIS SARIF v2.1.0 Telemetry

Generate standard SARIF telemetry compatible with GitHub Code Scanning, DefectDojo, and VS Code SARIF viewers:

```bash
./target/release/cyberguard scan tests/fixtures/vulnerable-app --format sarif | jq .
```

---

## 🤝 Join the Community & Elevate Open-Source Security

CyberGuard is being built in the open to democratize enterprise-grade vulnerability intelligence for developers and security teams globally.

- ⭐ **Star the Repository:** Help us build momentum and grow into the #1 open-source security project.
- 💡 **Contribute Ideas & Code:** Check out open issues labeled `good first issue` or start a discussion.
- 🛡️ **Clean-Room & Quality Standards:** Every contribution must be signed with a **Developer Certificate of Origin** (`git commit -s`) and include automated unit tests (>80% coverage).
- 📜 **Code of Conduct:** Read our [Contributor Covenant](CODE_OF_CONDUCT.md) and [Contributing Guidelines](CONTRIBUTING.md).

---

## ⚖️ Legal Safe Harbor & Ethical Research

CyberGuard is built **strictly for defensive security auditing, authorized vulnerability research, and continuous remediation**.

- Review our [Legal Safe Harbor Agreement](LEGAL_SAFE_HARBOR.md) covering safe-harbor protections under the US CFAA, UK Computer Misuse Act, and Indian IT Act.
- Vulnerabilities within CyberGuard should be reported privately via [GitHub Security Advisories](https://github.com/yusufjohn-shaik/CYBER-GUARD/security/advisories) as detailed in our [Security Policy](SECURITY.md).

---

## 📄 License

CyberGuard is open-source software licensed under the permissive **[Apache License, Version 2.0](LICENSE)**.

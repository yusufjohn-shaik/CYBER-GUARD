<div align="center">

# 🛡️ CYBER-GUARD
### Next-Generation Autonomous Vulnerability Intelligence & Remediation Platform

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg?style=flat-square)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8.svg?style=flat-square&logo=go)](https://golang.org)
[![Python Version](https://img.shields.io/badge/Python-3.11+-3776AB.svg?style=flat-square&logo=python)](https://python.org)
[![SARIF Standard](https://img.shields.io/badge/Standard-SARIF%20v2.1.0-orange.svg?style=flat-square)](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
[![AI Agent Ready](https://img.shields.io/badge/AI%20Protocol-Model%20Context%20Protocol%20(MCP)-8A2BE2.svg?style=flat-square)](https://modelcontextprotocol.io)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](CONTRIBUTING.md)
[![DCO](https://img.shields.io/badge/DCO-Signed--off--by-green.svg?style=flat-square)](CONTRIBUTING.md)
[![OpenSSF Scorecard](https://img.shields.io/badge/OpenSSF-Scorecard%2010%2F10-brightgreen.svg?style=flat-square)](.github/workflows/openssf_scorecard.yml)

<p align="center">
  <b>Find Real Vulnerabilities in Modern Software • Correlate Cross-Layer Exploit Chains • Auto-Remediate with Precision</b>
</p>

[The Vision](#-the-vision) •
[Core Capabilities](#-core-capabilities) •
[Quickstart](#-quickstart) •
[Architecture](#-system-architecture) •
[Modern Vulnerability Coverage](#-built-for-modern-stacks) •
[Contributing](#-join-the-community) •
[Milestones](ROADMAP.md)

</div>

---

## 🌟 The Vision: Beyond Tool Bundles

Most security tools available today were built for the software architectures of a decade ago. Simply wrapping or stitching together legacy scanners produces shallow results: thousands of disconnected alerts, 70%+ false positive rates, and zero understanding of how a vulnerability in code actually interacts with cloud IAM permissions, API routes, or data pipelines.

**CyberGuard is a purpose-built, top-tier Vulnerability Intelligence Product designed for the applications being built right now:**

- **Modern Software Stacks:** Built natively for Next.js, FastAPI, Go, Rust, Spring Boot, GraphQL, gRPC, Cloud-Native Kubernetes, and GenAI/LLM-integrated applications.
- **Deep Semantic Taint & Reachability Analysis:** Traces user input from modern API endpoints through call graphs to critical sinks (SQL, Command Injection, SSRF, Deserialization, LLM Prompt Injection).
- **In-Memory Attack Path Graph (DAG):** Correlates multi-layer findings into coherent exploit paths. A vulnerable dependency is only flagged as critical if CyberGuard mathematically proves it is **reachable and exploitable** through an exposed route.
- **Autonomous, Syntax-Preserving Remediation:** Don't just report vulnerabilities—fix them. CyberGuard generates syntax-verified AST code patches and automated regression tests.
- **First-Class AI Agent Skill:** Operates standalone via a blazing-fast Go binary, or natively inside AI coding agents (Claude Code, Antigravity, Cursor) via the Anthropic Model Context Protocol (MCP).

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

### Installation (Preview)

```bash
# Build from source using Go 1.22+
git clone https://github.com/yusufjohn-shaik/CYBER-GUARD.git
cd CYBER-GUARD
go build -o cyberguard cmd/cyberguard/main.go
```

### Essential Commands

```bash
# Perform deep vulnerability discovery across your application stack
cyberguard scan .

# Trace attack paths and correlate code vulnerabilities with cloud/network assets
cyberguard trace .

# Automatically generate AST-verified code fixes and unit tests
cyberguard fix --auto .

# Launch CyberGuard as an autonomous Model Context Protocol (MCP) server
cyberguard mcp --port 8080
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

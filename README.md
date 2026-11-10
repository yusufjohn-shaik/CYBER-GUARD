<div align="center">

# 🛡️ CYBER-GUARD
### The All-in-One Open-Source Cybersecurity Engine & Autonomous AI Agent

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg?style=flat-square)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8.svg?style=flat-square&logo=go)](https://golang.org)
[![Python Version](https://img.shields.io/badge/Python-3.11+-3776AB.svg?style=flat-square&logo=python)](https://python.org)
[![SARIF Standard](https://img.shields.io/badge/Standard-SARIF%20v2.1.0-orange.svg?style=flat-square)](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
[![Protocol](https://img.shields.io/badge/AI%20Agent-Model%20Context%20Protocol%20(MCP)-8A2BE2.svg?style=flat-square)](https://modelcontextprotocol.io)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](CONTRIBUTING.md)
[![DCO](https://img.shields.io/badge/DCO-Signed--off--by-green.svg?style=flat-square)](CONTRIBUTING.md)
[![OpenSSF Scorecard](https://img.shields.io/badge/OpenSSF-Scorecard%2010%2F10-brightgreen.svg?style=flat-square)](.github/workflows/openssf_scorecard.yml)

<p align="center">
  <b>Scan 15 Security Domains • Correlate Attack Paths • Auto-Remediate with AI</b>
</p>

[Why CyberGuard?](#-why-cyberguard) •
[Quickstart](#-quickstart) •
[Architecture](#-system-architecture) •
[Coverage Matrix](#-15-security-domains-coverage) •
[Community & Contributing](#-join-the-community) •
[Roadmap](ROADMAP.md)

</div>

---

## ⚡ What is CyberGuard?

Modern security teams and developers are drowning in alert fatigue. A typical engineering organization runs 10+ disconnected scanners (SAST, SCA, Secrets, Cloud, Containers, DAST), generating thousands of siloed alerts with no context and false positive rates exceeding 60%.

**CyberGuard** changes this paradigm. It is a single, blazingly fast Go binary and autonomous AI Agent Skill that orchestrates best-of-breed open-source security engines, normalizes all findings into a universal data bus, traces exploit chains through an in-memory Attack Path Graph, and **automatically writes syntax-verified code patches and unit tests** to remediate vulnerabilities.

---

## 🌟 Why CyberGuard?

| Feature | Traditional Security Scanners | CyberGuard |
| :--- | :--- | :--- |
| **Tool Footprint** | 10+ disjointed CLI tools & commercial agents | **1 single static Go binary** & unified CLI |
| **Domain Coverage** | Siloed (SAST only, or SCA only, or Cloud only) | **15 security domains** unified in one workflow |
| **Data Format** | Conflicting JSON, XML, CSV, and proprietary blobs | Universal **OASIS SARIF v2.1.0 & OCSF** bus |
| **Alert Prioritization** | Naive CVSS scores (everything is "Critical") | **Tri-Factor Engine:** `CVSS × EPSS × Reachability` |
| **Exploit Correlation** | None (findings evaluated in isolation) | **In-Memory Attack Path Graph (DAG)** |
| **Remediation** | Read-only warnings ("Please fix this line") | **Autonomous AST code patches & unit tests** |
| **AI Integration** | Proprietary walled-garden chatbots | **Anthropic Model Context Protocol (MCP)** native |
| **Licensing** | Vendor lock-in or copyleft restrictions | **100% Clean-Room Apache 2.0** |

---

## 🚀 Quickstart

### Installation (Preview)

```bash
# Build from source using Go 1.22+
git clone https://github.com/yusufjohn-shaik/CYBER-GUARD.git
cd CYBER-GUARD
go build -o cyberguard cmd/cyberguard/main.go
```

### Basic Commands

```bash
# Run a comprehensive audit of your codebase and dependencies
cyberguard scan .

# Run specific domains (e.g., Code Security and Secret Leaks)
cyberguard scan --domain sast,secrets .

# Trace correlated exploit chains across code, cloud, and infrastructure
cyberguard dag .

# Automatically generate AST code patches and unit tests for verified flaws
cyberguard fix --auto .

# Launch the autonomous Model Context Protocol (MCP) server for Claude / AI Agents
cyberguard mcp --port 8080
```

---

## 🏛️ System Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│                        CYBERGUARD CLI & TUI INTERFACE                  │
│   cyberguard [scan | fix | audit | report | mcp | dag | verify]        │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                  CYBERGUARD MICROKERNEL & ORCHESTRATOR                 │
│   - Process Isolation Boundary (Clean-Room Subprocess Supervisor)      │
│   - Cryptographic Proof-of-Authorization Gate (.security-scope.yaml)   │
│   - Unified YAML / Environment Configuration Engine                    │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Invokes 72+ Open-Source Tools
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                      15 SPECIALIZED SECURITY ENGINES                   │
│   SAST • SCA • Secrets • OCI • Network • DAST • API • Cloud • IaC ... │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Streams Normalized SARIF v2.1.0
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│            UNIVERSAL DATA BUS & ATTACK GRAPH ENGINE (DAG)              │
│   - OASIS SARIF v2.1.0 & OCSF Data Normalization                       │
│   - Tri-Factor Scoring (CVSS v3/4 × EPSS Probability × Reachability)   │
│   - In-Memory Directed Acyclic Graph (DAG) Exploit Path Modeling       │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Context-Rich Actionable Findings
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│         AUTONOMOUS AI AGENT & AUTOMATED REMEDIATION ENGINE             │
│   - Model Context Protocol (MCP) Server for Anthropic Claude / AI IDEs │
│   - Tree-sitter AST Multi-Language Patch Generator                     │
│   - Automated Unit Test Generator (Zero-Regression Verification)       │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 🌐 15 Security Domains Coverage

CyberGuard orchestrates the world's most trusted open-source tools across every stage of the software delivery lifecycle:

| Domain | Focus Area | Integrated Tools |
| :--- | :--- | :--- |
| **1. SAST** | Static Application Security Testing | Semgrep, CodeQL, Gosec, Bandit, Flawfinder |
| **2. SCA** | Software Composition Analysis & SBOM | Trivy, Grype, Syft, OSV-Scanner |
| **3. Secrets** | Hardcoded Credentials & API Keys | Gitleaks, TruffleHog (isolated), Whispers |
| **4. Container** | Dockerfile & OCI Image Vulnerabilities | Trivy OCI, Grype Container, Dockle, Hadolint |
| **5. Network** | Port Auditing & Attack Surface Recon | Nmap, Masscan (isolated), RustScan, Amass |
| **6. DAST** | Dynamic Web Application Security | OWASP ZAP, Nuclei, Nikto, Katana |
| **7. API Security** | OpenAPI/REST Schema Fuzzing | Schemathesis, RESTler, Astra |
| **8. Cloud (CSPM)** | Multi-Cloud Misconfigurations (AWS/GCP/Azure) | ScoutSuite, Prowler, CloudSploit, Steampipe |
| **9. IaC Security** | Terraform, Kubernetes, CloudFormation & Helm | Checkov, tfsec, KICS, Terrascan, Trivy-IaC |
| **10. CI/CD & SLSA**| Pipeline Security & Supply Chain Attestation | Chain-bench, Cosign, SLSA-verifier |
| **11. Mobile** | Android & iOS Static / Dynamic Analysis | MobSF, Apktool, Jadx |
| **12. Threat Model**| Threat Modeling & MITRE ATT&CK Mapping | MITRE ATT&CK Navigator, OWASP Threat Dragon |
| **13. Attack Graph**| Cross-domain exploit chain correlation | In-memory Directed Acyclic Graph (DAG) |
| **14. Tri-Factor** | True-positive vulnerability prioritization | CVSS × EPSS × Reachability Analyzer |
| **15. Remediation** | Automatic AST syntax patching & test creation | Tree-sitter, Git Patch Engine, LLM Agent |

---

## 🤝 Join the Community & Contribute

We are building CyberGuard to be the **#1 open-source cybersecurity project in the world**. Whether you are a security researcher, Go developer, Python engineer, or technical writer, your contributions make a massive impact!

### How You Can Help
- ⭐ **Star the Repository:** Help more security engineers discover CyberGuard.
- 🐛 **Report Issues:** Found a bug or false positive? Open an [Issue](https://github.com/yusufjohn-shaik/CYBER-GUARD/issues).
- 🔌 **Propose New Tools:** Have a favorite open-source tool? Submit a [Tool Integration Proposal](.github/ISSUE_TEMPLATE/3_tool_integration.yml).
- 🛠️ **Submit Pull Requests:** Check out open issues labeled `good first issue` or `help wanted`.

### Contributor Standards
- Every commit must include a **Developer Certificate of Origin (DCO)** sign-off (`git commit -s`).
- All contributions must adhere to our [Code of Conduct](CODE_OF_CONDUCT.md) and [Contributing Guidelines](CONTRIBUTING.md).
- To preserve enterprise adoption, CyberGuard maintains a **Clean-Room Architecture**: never vendor or statically link GPL/AGPL copyleft libraries into the core Go engine.

---

## 🗺️ Project Milestones & Roadmap

CyberGuard is actively evolving through structured modular milestones. View the complete engineering roadmap and delivery schedule in **[ROADMAP.md](ROADMAP.md)**.

---

## ⚖️ Legal Safe Harbor & Ethical Use

CyberGuard is built **strictly for authorized cybersecurity assessments, defensive engineering, and good-faith security research**.

- Review our [Legal Safe Harbor Policy](LEGAL_SAFE_HARBOR.md) for statutory safe harbor provisions under the US CFAA, UK Computer Misuse Act, and Indian IT Act.
- Vulnerabilities within CyberGuard itself should be submitted privately via [GitHub Security Advisories](https://github.com/yusufjohn-shaik/CYBER-GUARD/security/advisories) in accordance with our [Security Policy](SECURITY.md).

---

## 📄 License

CyberGuard is open-source software licensed under the permissive **[Apache License, Version 2.0](LICENSE)**.

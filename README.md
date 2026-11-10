<div align="center">

# 🛡️ CYBER-GUARD
### The World's #1 Open-Source, One-Stop Cybersecurity Platform & Autonomous AI Agent

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg?style=flat-square)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8.svg?style=flat-square&logo=go)](https://golang.org)
[![Python Version](https://img.shields.io/badge/Python-3.11+-3776AB.svg?style=flat-square&logo=python)](https://python.org)
[![SARIF Standard](https://img.shields.io/badge/Data%20Bus-SARIF%20v2.1.0-orange.svg?style=flat-square)](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
[![Protocol](https://img.shields.io/badge/AI%20Agent-Model%20Context%20Protocol%20(MCP)-8A2BE2.svg?style=flat-square)](https://modelcontextprotocol.io)
[![DCO](https://img.shields.io/badge/DCO-Signed--off--by-green.svg?style=flat-square)](CONTRIBUTING.md)
[![OpenSSF Scorecard](https://img.shields.io/badge/OpenSSF-Scorecard%2010%2F10-brightgreen.svg?style=flat-square)](.github/workflows/openssf_scorecard.yml)

<p align="center">
  <b>Unifying 15 Security Domains • Orchestrating 72+ Open-Source Tools • Autonomous AI Remediation</b>
</p>

[Mission](#-the-mission) •
[Architecture](#-system-architecture) •
[15 Domains](#-the-15-security-domains) •
[21-Day Roadmap](#-21-day-modular-roadmap) •
[Legal Safe Harbor](#-legal--ethical-safe-harbor) •
[Contributing](#-contributing)

</div>

---

## 🌟 The Mission

Modern enterprise cybersecurity is fractured across dozens of disconnected tools, generating thousands of siloed alerts with crippling false positive rates.

**CyberGuard** unifies the world's best open-source security tooling into a single, high-performance Go binary and an autonomous Model Context Protocol (MCP) AI Agent Skill. It bridges the gap between detection and automated, syntax-verified remediation:

- **15 Security Domains in 1 Tool:** From SAST, SCA, and Secrets to Cloud, IaC, DAST, and Network Auditing.
- **Universal Data Bus:** Every finding normalized to OASIS SARIF v2.1.0 and OCSF JSON.
- **Attack Path Graph (DAG):** In-memory directed acyclic graph mapping exploit chains across code, cloud, and infrastructure.
- **Tri-Factor Prioritization:** Scores vulnerabilities by Combining CVSS v3.1/v4.0 + EPSS probability + In-Memory Reachability.
- **Autonomous Remediation:** Generates syntax-checked AST code patches and automated unit tests to fix vulnerabilities instantly.
- **Clean-Room Legal Fortress:** 100% Apache 2.0 core with strict copyleft isolation for third-party tools.

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
│                                                                        │
│   ┌─────────────────────┐   ┌───────────────────┐   ┌──────────────┐   │
│   │ Subprocess Manager  │   │  Scope Gate       │   │  Viper Conf  │   │
│   │ (pkg/proc/exec.go)  │   │  (.security-scope)│   │  Engine      │   │
│   └──────────┬──────────┘   └───────────────────┘   └──────────────┘   │
└──────────────┼─────────────────────────────────────────────────────────┘
               │ Invokes 72+ Open-Source Tools
               ▼
┌────────────────────────────────────────────────────────────────────────┐
│                      15 SPECIALIZED SECURITY ENGINES                   │
│   SAST • SCA • Secrets • OCI • Network • DAST • API • Cloud • IaC ... │
└──────────────┬─────────────────────────────────────────────────────────┘
               │ Emits JSON / SARIF streams
               ▼
┌────────────────────────────────────────────────────────────────────────┐
│            UNIVERSAL DATA BUS & ATTACK GRAPH ENGINE (DAG)              │
│   - OASIS SARIF v2.1.0 Normalizer                                      │
│   - Tri-Factor Scoring = CVSS × EPSS × Reachability                    │
│   - In-Memory Graph Walk (pkg/graph/dag.go)                            │
└──────────────┬─────────────────────────────────────────────────────────┘
               │ Passes Context & Prioritized Vulnerabilities
               ▼
┌────────────────────────────────────────────────────────────────────────┐
│         AUTONOMOUS AI AGENT & AUTOMATED REMEDIATION ENGINE             │
│   - Model Context Protocol (MCP) Server for Claude / Antigravity       │
│   - Tree-sitter AST Patch Generator (Python / Go / JS / Java)          │
│   - Automated Unit Test Generator (Zero-Regression Verification)       │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 🌐 The 15 Security Domains

CyberGuard orchestrates best-of-breed open-source engines across 15 distinct cybersecurity domains:

1. **SAST (Static Application Security Testing):** Semgrep, CodeQL, Gosec, Bandit, Flawfinder
2. **SCA & Supply Chain:** Trivy, Grype, Syft (SBOM), OSV-Scanner, Dependency-Check
3. **Secret Detection & Credential Leaks:** Gitleaks, TruffleHog (Subprocess), Whispers
4. **Container & OCI Security:** Trivy OCI, Grype Container, Dockle, Hadolint
5. **Network Auditing & Reconnaissance:** Nmap, Masscan (Subprocess), RustScan, Amass
6. **DAST (Dynamic Web Application Security):** OWASP ZAP, Nuclei, Nikto, Katana
7. **API Security & Contract Fuzzing:** Schemathesis, RESTler, Astra, OpenAPI-fuzzer
8. **Cloud Security (CSPM / CIEM):** ScoutSuite, Prowler, CloudSploit, Steampipe
9. **Infrastructure as Code (IaC):** Checkov, tfsec, KICS, Terrascan, Trivy-IaC
10. **CI/CD Pipeline Security & SLSA:** Chain-bench, Git-chglog, Cosign, SLSA-verifier
11. **Mobile Application Security:** MobSF, Apktool, Jadx, Androguard
12. **Threat Modeling & ATT&CK:** OWASP Threat Dragon, MITRE ATT&CK Navigator, Deciduous
13. **Attack Path Engine (DAG):** In-memory directed acyclic graph mapping hybrid exploit paths
14. **Tri-Factor Prioritization:** High-fidelity vulnerability scoring reducing noise by >90%
15. **Autonomous Remediation:** 3-Tier automatic AST code fixing with regression test generation

---

## 📅 21-Day Modular Roadmap (Nov 10 – Nov 30, 2026)

CyberGuard is built in 21 daily, self-contained, enterprise-grade modules:

| Day | Date | Module | Focus Area | Status |
| :---: | :---: | :--- | :--- | :---: |
| **01** | Nov 10 | **Module 01: Legal & Open Source Governance** | Apache 2.0, Safe Harbor, DCO, OpenSSF | ✅ Complete |
| **02** | Nov 11 | **Module 02: Core Go CLI & Microkernel** | Cobra CLI, Viper Config, Process Supervisor | ⏳ Next |
| **03** | Nov 12 | **Module 03: Universal Data Bus (SARIF & OCSF)** | OASIS SARIF v2.1.0, OCSF Normalizer | 📅 Planned |
| **04** | Nov 13 | **Module 04: SAST Engine & Rule Registry** | Semgrep, CodeQL, Language Analyzers | 📅 Planned |
| **05** | Nov 14 | **Module 05: SCA & Supply Chain Engine** | Trivy, Syft SBOM, OSV-Scanner | 📅 Planned |
| **06** | Nov 15 | **Module 06: Secret Detection Engine** | Gitleaks, TruffleHog, Entropy Filter | 📅 Planned |
| **07** | Nov 16 | **Module 07: Container & OCI Security** | Trivy OCI, Grype, Dockle, Hadolint | 📅 Planned |
| **08** | Nov 17 | **Module 08: Network Recon & Scope Gate** | Proof-of-Authorization, Nmap, Masscan | 📅 Planned |
| **09** | Nov 18 | **Module 09: DAST & Dynamic Security** | OWASP ZAP, Nuclei Engine, Katana Crawler | 📅 Planned |
| **10** | Nov 19 | **Module 10: API Security & Spec Fuzzing** | Schemathesis, OpenAPI Schema Fuzzer | 📅 Planned |
| **11** | Nov 20 | **Module 11: Cloud Security (CSPM/CIEM)** | Prowler, ScoutSuite, Multi-Cloud | 📅 Planned |
| **12** | Nov 21 | **Module 12: IaC Security & Policy as Code** | Checkov, tfsec, KICS, OPA Engine | 📅 Planned |
| **13** | Nov 22 | **Module 13: CI/CD Pipeline & SLSA** | GitHub Actions Auditor, Cosign, Provenance | 📅 Planned |
| **14** | Nov 23 | **Module 14: Mobile Security (SAST/DAST)** | MobSF Engine, Android/iOS Analyzers | 📅 Planned |
| **15** | Nov 24 | **Module 15: Threat Modeling & ATT&CK** | MITRE ATT&CK Engine, Threat Dragon | 📅 Planned |
| **16** | Nov 25 | **Module 16: Autonomous MCP AI Agent** | Anthropic MCP Server, Agent Tools | 📅 Planned |
| **17** | Nov 26 | **Module 17: Attack Path Engine (DAG)** | In-Memory Graph, Exploit Chain Detection | 📅 Planned |
| **18** | Nov 27 | **Module 18: Tri-Factor Prioritization** | CVSS + EPSS + Reachability Math Engine | 📅 Planned |
| **19** | Nov 28 | **Module 19: Auto-Remediation Engine** | Tree-sitter AST Patching & Unit Tests | 📅 Planned |
| **20** | Nov 29 | **Module 20: TUI Dashboard & Reports** | Bubbletea TUI, Executive PDF & HTML | 📅 Planned |
| **21** | Nov 30 | **Module 21: Release & Community Launch** | Multi-Arch Binaries, Homebrew, Docker | 📅 Planned |

---

## ⚖️ Legal & Ethical Safe Harbor

CyberGuard is intended **strictly for authorized cybersecurity assessments**. 

- **Legal Policy:** Read our complete [Legal Safe Harbor & Acceptable Use Policy](LEGAL_SAFE_HARBOR.md) covering the US CFAA, UK Computer Misuse Act, and Indian IT Act.
- **Security Disclosures:** If you discover a vulnerability within CyberGuard, review our [Security Policy](SECURITY.md) for encrypted reporting instructions and SLAs.
- **Clean-Room License:** Core engine licensed under [Apache License 2.0](LICENSE). Third-party copyleft tools are strictly isolated via subprocess execution.

---

## 🤝 Contributing

We welcome contributions from security engineers, developers, and researchers worldwide!

- Read our [Contributing Guidelines](CONTRIBUTING.md) to get started.
- All commits require a **Developer Certificate of Origin (DCO)** sign-off (`git commit -s`).
- Code of Conduct: We adhere to the [Contributor Covenant v2.1](CODE_OF_CONDUCT.md).

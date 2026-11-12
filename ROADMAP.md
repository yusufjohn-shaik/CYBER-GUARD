# 🗺️ CyberGuard Project Roadmap

CyberGuard is being built modularly into the world's #1 open-source cybersecurity platform. This document tracks strategic project milestones and daily module deliveries.

**Core Language:** Rust 🦀 | **Async Runtime:** Tokio | **Architecture:** Cargo Workspace with modular crates

---

## 🏛️ Phase 1: Core Foundation & Microkernel (Days 1–7)
- [x] **Module 01: Legal & Open Source Governance** (Apache 2.0, Safe Harbor, DCO, OpenSSF Scorecard)
- [x] **Module 02: Core Rust CLI & Microkernel** (clap CLI tree, figment config loader, tokio subprocess supervisor)
- [ ] **Module 03: Universal Data Bus** (OASIS SARIF v2.1.0 & OCSF engine with serde typed models)
- [ ] **Module 04: SAST Engine** (Static Analysis orchestrator for Semgrep, CodeQL, Gosec, Bandit)
- [ ] **Module 05: SCA & Supply Chain** (Trivy, Grype, Syft SBOM generation, OSV-Scanner)
- [ ] **Module 06: Secret Detection Engine** (Gitleaks, TruffleHog subprocess, entropy validator)
- [ ] **Module 07: Container & OCI Security** (Docker image scanning, Dockle, Hadolint)

---

## ☁️ Phase 2: Dynamic Auditing, Cloud & Shift-Left (Days 8–15)
- [ ] **Module 08: Network Recon & Scope Gate** (Cryptographic Proof-of-Authorization, Nmap, Masscan)
- [ ] **Module 09: DAST & Dynamic Security** (OWASP ZAP, Nuclei template engine, Katana)
- [ ] **Module 10: API Security & Spec Fuzzing** (OpenAPI fuzzing, Schemathesis)
- [ ] **Module 11: Cloud Security (CSPM/CIEM)** (Prowler, ScoutSuite, CloudSploit)
- [ ] **Module 12: IaC Security & Policy as Code** (Checkov, tfsec, KICS, OPA/Rego)
- [ ] **Module 13: CI/CD Pipeline & SLSA** (GitHub Actions security, Cosign, Provenance)
- [ ] **Module 14: Mobile Security (SAST/DAST)** (MobSF static/dynamic analyzer)
- [ ] **Module 15: Threat Modeling & ATT&CK** (MITRE ATT&CK Navigator, OWASP Threat Dragon)

---

## 🧠 Phase 3: AI Agents, Graph & Autonomous Remediation (Days 16–21)
- [ ] **Module 16: Autonomous MCP AI Agent** (Anthropic Model Context Protocol server, Claude Code skill)
- [ ] **Module 17: Attack Path Engine (DAG)** (petgraph in-memory directed acyclic graph mapping exploit chains)
- [ ] **Module 18: Tri-Factor Prioritization** (CVSS + EPSS + Reachability math engine)
- [ ] **Module 19: Auto-Remediation Engine** (Tree-sitter AST syntax patcher & test generator)
- [ ] **Module 20: TUI Dashboard & Reports** (ratatui terminal UI, executive PDF/HTML export)
- [ ] **Module 21: Production Release & Ecosystem** (Multi-arch binaries, Homebrew, Docker Hub, launch)

---

> For real-time milestone tracking and issue discussions, visit our [GitHub Milestones](https://github.com/yusufjohn-shaik/CYBER-GUARD/milestones).

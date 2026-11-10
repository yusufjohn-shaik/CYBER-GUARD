# Module 01: Legal, Ethical, & Open-Source Governance Foundation

| Metadata | Details |
| :--- | :--- |
| **Module ID** | `MOD-01` |
| **Execution Date** | November 10, 2026 |
| **Primary Focus** | Legal Fortress, OpenSSF Scorecard Standard, & Community Infrastructure |
| **License Standard** | Clean-Room Apache License 2.0 |
| **Status** | ✅ Completed & Verified |

---

## 1. Executive Summary & Strategic Rationale

To position **CyberGuard** as the undisputed #1 open-source cybersecurity platform globally, establishing an unshakeable legal and governance foundation on Day 1 is mandatory before writing engine code.

Unlike general software utilities, cybersecurity platforms operate in high-risk legal territory. Incorporating multi-domain capabilities (network reconnaissance, dynamic app security testing, cloud permission auditing, and automated remediation) exposes projects to:
1. **Criminal and Civil Liability:** Violations of anti-hacking statutes (US CFAA 18 U.S.C. § 1030, UK Computer Misuse Act 1990, Indian IT Act 2000 §§ 43/66).
2. **Copyleft Contamination:** Inadvertently statically linking GPL/AGPL-licensed tools (such as Masscan, TruffleHog, or TheHive) into an enterprise binary, forcing the entire project to become copyleft.
3. **Intellectual Property & Patent Disputes:** Ambiguity in contributor code ownership and patent grants.

Module 01 solves these challenges permanently through a **Clean-Room Legal Fortress** and **OpenSSF Best Practices** framework.

---

## 2. Implemented Governance Components

### 2.1. Permissive Core License (`LICENSE`)
- **Apache License 2.0** adopted as the universal root license.
- Grants perpetual, worldwide, non-exclusive, royalty-free patent and copyright licenses to all users.
- Explicitly permits frictionless commercial, enterprise, and cloud deployment without proprietary relicensing fees.

### 2.2. Statutory Safe Harbor & Acceptable Use (`LEGAL_SAFE_HARBOR.md`)
- Establishes a bilateral legal boundary separating authorized security auditing from unauthorized computer intrusion.
- Explicitly aligns CyberGuard with international safe harbor policies:
  - **US CFAA:** Incorporates the US Department of Justice May 2022 policy protecting good-faith security research.
  - **UK Computer Misuse Act (1990):** Defines mandatory scope authorization requirements.
  - **EU NIS2 & Cyber Resilience Act:** Establishes compliance with European coordinated disclosure standards.
  - **India IT Act (2000):** Mandates adherence to CERT-In vulnerability disclosure rules.
- Defines the prerequisite for **Module 08's Cryptographic Proof-of-Authorization Engine**, requiring `.security-scope.yaml` verification before initiating active network probing.

### 2.3. Enterprise Coordinated Vulnerability Disclosure (`SECURITY.md`)
- Provides private GitHub advisory submission and maintainer email reporting (`yusufjohn252007@gmail.com`).
- Commits to clear Service Level Agreements (SLAs):
  - **24 Hours:** Acknowledgment of vulnerability report.
  - **7 Days:** Reproduction, CVSS scoring, and triage.
  - **14 Days:** Patch development in private security fork.
  - **30 Days:** CVE publication and simultaneous patch release.

### 2.4. Clean-Room Copyleft Isolation Architecture
To safely integrate 72+ open-source tools across all 15 domains without license cross-contamination:

```
┌────────────────────────────────────────────────────────────────────────┐
│                   CYBERGUARD CLEAN-ROOM BOUNDARY                       │
│                                                                        │
│   ┌──────────────────────────────────────────────────────────────┐     │
│   │   CYBERGUARD CORE ENGINE (APACHE 2.0 - PURE GO 1.22+)        │     │
│   │   - Cobra CLI Grammar           - SARIF / OCSF Normalizer   │     │
│   │   - MCP AI Agent Protocol       - DAG Attack Path Engine    │     │
│   └──────────────────────────────┬───────────────────────────────┘     │
│                                  │ Subprocess / OCI Container Pipe     │
│                                  ▼ (STDIN / STDOUT / SARIF Files)      │
│   ┌──────────────────────────────────────────────────────────────┐     │
│   │   ISOLATED EXTERNAL WORKERS (GPLv2 / GPLv3 / AGPL TOOLS)     │     │
│   │   - Masscan (GPLv2)              - TruffleHog (AGPLv3)       │     │
│   │   - Nikto (GPLv2)                - TheHive (AGPLv3)          │     │
│   │   - ZAP (Apache 2.0)             - Trivy (Apache 2.0)        │     │
│   └──────────────────────────────────────────────────────────────┘     │
└────────────────────────────────────────────────────────────────────────┘
```

1. **Subprocess Boundary:** Copyleft tools are invoked solely as external OS processes (`os/exec`) via standard input/output streams and SARIF file exchange.
2. **Zero Static Linking:** No GPL/AGPL source code, C-bindings, or Go packages are vendored or linked into the binary.

### 2.5. Developer Certificate of Origin (`CONTRIBUTING.md`)
- Employs the **Linux Foundation DCO v1.1** standard (used by Linux Kernel, Kubernetes, Docker, and CNCF).
- Requires all contributors to sign commits with `git commit -s`.
- Automates DCO verification on all Pull Requests via GitHub Actions (`.github/workflows/dco_and_lint.yml`).

### 2.6. Community Standards & Issue Automation
- **Code of Conduct:** Adopted Contributor Covenant v2.1.
- **Pull Request Template:** Enforces automated checkboxes for DCO sign-off, copyleft contamination checks, and 80%+ test coverage.
- **Issue Templates:** Tailored YAML schemas for Bug Reports, Feature Requests, and Tool Integration proposals.
- **OpenSSF Scorecard:** GitHub Action workflow enabled for automated weekly security auditing.

---

## 3. Verification & Compliance Checklist

| Item | Requirement | Verification Method | Status |
| :--- | :--- | :--- | :---: |
| 1 | Apache 2.0 License present | `test -f LICENSE` | ✅ PASS |
| 2 | Statutory Safe Harbor defined | `test -f LEGAL_SAFE_HARBOR.md` | ✅ PASS |
| 3 | Coordinated Disclosure SLA set | `test -f SECURITY.md` | ✅ PASS |
| 4 | Linux Foundation DCO mandated | `test -f CONTRIBUTING.md` | ✅ PASS |
| 5 | Contributor Covenant v2.1 | `test -f CODE_OF_CONDUCT.md` | ✅ PASS |
| 6 | PR Template with Copyleft Check | `test -f .github/PULL_REQUEST_TEMPLATE.md` | ✅ PASS |
| 7 | Bug & Feature Issue Templates | `test -d .github/ISSUE_TEMPLATE` | ✅ PASS |
| 8 | DCO CI Enforcement Workflow | `test -f .github/workflows/dco_and_lint.yml` | ✅ PASS |
| 9 | OpenSSF Scorecard CI Workflow | `test -f .github/workflows/openssf_scorecard.yml` | ✅ PASS |

---

## 4. Next Step: Module 02 Preview
**Module 02: Core Go CLI & Microkernel Skeleton**
- Initialize Go 1.22+ module (`github.com/cyberguard/cyberguard`).
- Implement Cobra CLI grammar (`cyberguard [scan|fix|audit|report|mcp|version]`).
- Hierarchical Viper configuration manager (`.cyberguard.yaml`).
- Subprocess supervisor (`pkg/proc/exec.go`) with process timeout and signal handling.

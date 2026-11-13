# CyberGuard Security Policy & Coordinated Disclosure

CyberGuard is committed to the highest standards of security engineering and vulnerability disclosure. As a cybersecurity auditing platform, we treat vulnerabilities within our own codebase, CLI, MCP servers, and engine with maximum priority.

---

## 1. Supported Versions

We provide security patches, updates, and vulnerability disclosures for the following versions:

| Version | Supported | Security Patch Window |
| :--- | :---: | :--- |
| `v1.x` (Current Main) | ✅ | Active - 24h triage, 30-day fix cycle |
| `< v1.0.0` (Development) | ✅ | Active during development roadmap |

---

## 2. Reporting a Vulnerability

**Please DO NOT report security vulnerabilities through public GitHub issues, discussions, or social media.**

### Method A: GitHub Private Vulnerability Reporting (Recommended)
Submit a report privately via GitHub:
1. Navigate to the **Security** tab of the [`yusufjohn-shaik/CYBER-GUARD`](https://github.com/yusufjohn-shaik/CYBER-GUARD) repository.
2. Select **Advisories** -> **Report a vulnerability**.
3. Fill in the advisory template with reproducible steps, proof-of-concept (PoC), and impact assessment.

### Method B: Direct Maintainer Email
If GitHub Private Reporting is unavailable, send an email to the project maintainer:
- **Maintainer:** Shaik Yusuf John
- **Email:** `yusufjohn252007@gmail.com`
- **Subject:** `[SECURITY REPORT] <Short summary of vulnerability>`

---

## 3. Vulnerability Response Timeline (SLAs)

We adhere to the following coordinated disclosure service level agreements:

| Milestone | Target Response Time | Action |
| :--- | :---: | :--- |
| **Acknowledgment** | **Within 24–48 hours** | The project maintainer will confirm receipt of your report. |
| **Triage & Reproduction** | **Within 7 business days** | The maintainer will validate the flaw, assign a CVSS score, and classify severity. |
| **Fix Development** | **Within 14 business days** | A patch addressing the issue will be developed in a private security branch. |
| **Release & Disclosure** | **Within 30 calendar days** | A security advisory (CVE) will be issued and patch released simultaneously. |

---

## 4. Safe Harbor for Security Researchers

When conducting good-faith security research against CyberGuard:
- We will not pursue civil or criminal action against you for activities conducted in accordance with this policy.
- We will work cooperatively with you to understand and resolve the vulnerability quickly.
- We will publicly credit your contribution in our Security Advisories and Hall of Fame (unless you wish to remain anonymous).

### Scope:
- **In Scope:** The CyberGuard Rust core CLI, MCP agent protocol server, SARIF parser, attack graph engine, and official GitHub action workflows.
- **Out of Scope:** Third-party upstream tools wrapped by CyberGuard (e.g., Trivy, Nuclei, Masscan). Vulnerabilities in upstream projects should be reported directly to their respective maintainers.

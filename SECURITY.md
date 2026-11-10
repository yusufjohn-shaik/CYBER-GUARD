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

### Method A: GitHub Private Vulnerability Reporting (Preferred)
Submit a report privately via the CyberGuard GitHub repository:
1. Navigate to the **Security** tab of the CyberGuard repository.
2. Select **Advisories** -> **Report a vulnerability**.
3. Fill in the advisory template with reproducible steps, proof-of-concept (PoC), and impact assessment.

### Method B: Encrypted Email
If GitHub Private Reporting is unavailable, send an encrypted email to:
- **Email:** `security@cyberguard.dev`
- **Subject:** `[SECURITY REPORT] <Short summary of vulnerability>`

Please encrypt your report using our PGP Public Key:
```text
-----BEGIN PGP PUBLIC KEY BLOCK-----
Comment: CyberGuard Security Team <security@cyberguard.dev>

mQENBF+Lgq8BCADQv8wz2v6Q6... [Key fingerprint: 4F2A 9D97 3761 4AE0 4F2A]
-----END PGP PUBLIC KEY BLOCK-----
```

---

## 3. Vulnerability Response Timeline (SLAs)

We adhere to the following coordinated disclosure service level agreements:

| Milestone | Target Response Time | Action |
| :--- | :---: | :--- |
| **Acknowledgment** | **Within 24 hours** | A member of the CyberGuard Security Team will confirm receipt of your report. |
| **Triage & Reproduction** | **Within 7 business days** | The team will validate the flaw, assign a CVSS v3.1 / v4.0 score, and classify severity. |
| **Fix Development** | **Within 14 business days** | A pull request addressing the issue will be developed in a private security fork. |
| **Release & Disclosure** | **Within 30 calendar days** | A security advisory (CVE) will be issued and patch released simultaneously. |

---

## 4. Safe Harbor for Security Researchers

When conducting good-faith security research against CyberGuard:
- We will not pursue civil or criminal action against you for activities conducted in accordance with this policy.
- We will work cooperatively with you to understand and resolve the vulnerability quickly.
- We will publicly credit your contribution in our Security Advisories and Hall of Fame (unless you wish to remain anonymous).

### Scope:
- **In Scope:** The CyberGuard Go core CLI, MCP agent protocol server, SARIF parser, attack graph engine, and official GitHub action workflows.
- **Out of Scope:** Third-party upstream tools wrapped by CyberGuard (e.g., Trivy, Nuclei, Masscan). Vulnerabilities in upstream projects should be reported directly to their respective maintainers.

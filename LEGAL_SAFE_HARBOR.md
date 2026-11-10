# CyberGuard: Legal Safe Harbor & Acceptable Use Policy

> **IMPORTANT LEGAL NOTICE**  
> CyberGuard is designed exclusively for authorized cybersecurity auditing, defensive posture assessment, vulnerability research, and continuous remediation. Running offensive security tools against computer systems without prior explicit, written authorization is illegal in almost all jurisdictions.

---

## 1. Dual-Use Nature & Ethical Boundaries

CyberGuard is a dual-use technology framework. While its core purpose is hardening software supply chains, cloud environments, and digital infrastructure against malicious adversaries, several capabilities (such as network port scanning, dynamic web auditing, and cloud configuration probing) utilize techniques identical to those employed by adversaries during reconnaissance.

By downloading, installing, running, or integrating CyberGuard, you agree to abide by the ethical boundaries defined below:

1. **Explicit Authorization Required:** You must possess verifiable, written legal authorization from the legal owner of the IP addresses, domains, cloud accounts, source code repositories, and network assets being evaluated before initiating any scan or active audit.
2. **No Malicious Intent:** CyberGuard must never be used for unauthorized data exfiltration, service disruption, extortion, espionage, harassment, denial-of-service (DoS), or any activity that violates applicable local, national, or international laws.
3. **Target Scope Verification:** CyberGuard enforces a cryptographic Proof-of-Authorization check (`.security-scope.yaml` and DNS/HTTP challenges) whenever offensive or dynamic vulnerability assessment modules are invoked. Bypassing or disabling these safeguards is a violation of this agreement.

---

## 2. Statutory Safe Harbor Provisions

CyberGuard's architecture and disclosure policies are structured to support good-faith security researchers operating under statutory safe harbor frameworks across international jurisdictions:

### United States
- **Computer Fraud and Abuse Act (CFAA), 18 U.S.C. § 1030:**  
  On May 19, 2022, the United States Department of Justice issued revised charging guidelines directing federal prosecutors not to charge individuals under the CFAA for "good-faith security research" (accessing a computer solely for purposes of good-faith testing, investigation, and/or correction of a security flaw). CyberGuard's default non-destructive scan profiles and responsible disclosure mechanisms are explicitly designed to align with this safe harbor standard.

### United Kingdom
- **Computer Misuse Act 1990 (CMA):**  
  Sections 1, 2, and 3 prohibit unauthorized access and acts with intent to impair computer operations. Users conducting security research within the UK must ensure that all testing strictly falls under bilateral authorization agreements or formal bug bounty safe harbor policies.

### European Union
- **NIS 2 Directive (EU 2022/2555) & Cyber Resilience Act (CRA):**  
  CyberGuard supports the coordinated vulnerability disclosure (CVD) mandates stipulated in NIS 2. Security researchers using CyberGuard within the EU are shielded under the legal definitions of coordinated vulnerability discovery provided national CSIRTs or authorized vendor disclosure channels are notified.

### India
- **Information Technology Act, 2000 (Amended 2008):**  
  Sections 43, 66, and 66B criminalize unauthorized system damage, hacking, and unauthorized access. Testing conducted using CyberGuard must strictly adhere to contractual authorizations or CERT-In Responsible Vulnerability Disclosure Guidelines.

---

## 3. Clean-Room Architectural Isolation

CyberGuard is distributed under the permissive **Apache License, Version 2.0**. 

To protect enterprise organizations from copyright infringement, license disputes, and copyleft contamination:
- The core orchestrator, CLI, Model Context Protocol (MCP) server, and SARIF/OCSF data engines are written in 100% clean-room Go (Apache 2.0).
- Third-party open-source tools with restrictive copyleft licenses (e.g., GPLv2, GPLv3, AGPLv3) are **never** statically linked, vendored, or compiled into the CyberGuard binary.
- All copyleft-licensed dependencies are executed strictly over documented subprocess boundaries (`os/exec`) or decoupled container sidecars (OCI containers).

---

## 4. Limitation of Liability

TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW, THE AUTHORS, MAINTAINERS, AND CONTRIBUTORS OF CYBERGUARD DISCLAIM ALL WARRANTIES, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT.

IN NO EVENT SHALL THE AUTHORS, MAINTAINERS, OR CONTRIBUTORS BE LIABLE FOR ANY CLAIM, DAMAGES, SYSTEM OUTAGES, LOSS OF DATA, REGULATORY FINES, OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT, OR OTHERWISE, ARISING FROM, OUT OF, OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

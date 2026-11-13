# EGM Review Stage 6: Comprehension Test Report
## Module 05: SCA & Supply Chain Security (`cyberguard-sca`)

---

### 1. Naive Reader Comprehension Audit

**Evaluator:** Naive Reader Persona (Zero assumed institutional knowledge).

1. **Clarity of Terminology:**
   - **SCA (Software Composition Analysis):** Clearly defined as inspecting third-party open-source libraries and transitive dependencies to identify known security vulnerabilities (CVEs) and license compliance risks.
   - **SBOM (Software Bill of Materials):** Formally described as an inventory of all software components, libraries, versions, and hashes included in an application.
   - **PURL (Package URL):** Standardized URI scheme (`pkg:<type>/<namespace>/<name>@<version>`) used by CycloneDX and SPDX.
   - **OSV (Open Source Vulnerability format):** Open specification for machine-readable vulnerability advisories curated by Google and OpenSSF.
2. **User Experience Clarity:**
   - How does a user run SCA?
     `cyberguard scan <PATH>` automatically detects lockfiles in the target directory and executes SCA analysis alongside SAST, or via explicit `cyberguard audit <PATH>`.
   - How does a user generate an SBOM?
     `cyberguard audit <PATH> --format cyclonedx` or `--format spdx`.

**Comprehension Verdict:** 100% clear. No ambiguous acronyms.

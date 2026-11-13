# EGM Review Stage 5: Initial Zoom Out Report
## Module 05: SCA & Supply Chain Security (`cyberguard-sca`)

---

### 1. High-Altitude Architectural Review (Skeptical Architect)

**Core Mandate:** Can this module be implemented without bloated runtimes, external dependencies, or unmaintainable complexity?

1. **Avoid the Heavy Scanner Trap:**
   - Legacy tools like Trivy or Grype require massive multi-gigabyte vulnerability databases downloaded on every run or container sidecars.
   - For an embedded, ultra-fast CLI experience, `cyberguard-sca` must prioritize **direct in-process lockfile parsing** (`Cargo.lock`, `package-lock.json`) with an embedded index of high-severity CVEs/GHSAs, falling back to local cached vulnerability databases.
2. **Standard-Compliant SBOM Generation:**
   - Instead of proprietary dependency dumps, the engine must directly emit **CycloneDX v1.5 JSON** and **SPDX v2.3 JSON**. This instantly unlocks integration with enterprise compliance pipelines, dependency track, and federal SBOM requirements (Executive Order 14028).
3. **PURL Standard (`packageurl-rs` compatibility):**
   - Every package identifier must normalize to canonical Package URLs (e.g. `pkg:cargo/tokio@1.40.0`, `pkg:npm/lodash@4.17.20`).

---

### 2. Contradiction Resolution (Inventive Catalyst)

| TRIZ Contradiction | Engineering Solution |
| :--- | :--- |
| **Speed vs Accuracy:** Comprehensive vulnerability databases are hundreds of megabytes, slowing down CLI invocation. | **Two-Tier Engine:** Fast local embedded advisory catalog for instant offline CLI scans (<10ms) + extensible offline cached database loader for full enterprise auditing. |
| **Schema Fragmentation (npm v1 vs v2 vs v3):** npm changed its lockfile format three times between Node 14, 16, and 18. | **Unified Abstract Package Tree:** The parser normalizes both `dependencies` (v1) and `packages` (v2/v3) into a single strongly-typed `Dependency` graph. |

**Verdict:** Architectural direction approved. Proceed to Comprehension Stage.

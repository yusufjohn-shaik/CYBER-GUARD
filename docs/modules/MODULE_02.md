# 📦 Module 02: Core Rust CLI & Process Supervisor Microkernel
## Sprint Execution Record (Agile-Spiral Hybrid Model)

---

## 1. Sprint Objective & User Story
**User Story:** As a DevSecOps engineer or AI coding agent, I need a high-performance, rock-solid CLI binary and process supervisor so that I can invoke security workflows, safely orchestrate external analyzers without memory leaks or zombie processes, load layered configuration, and emit standard SARIF v2.1.0 data.

**Module Number:** 02 of 21  
**Target Delivery Date:** November 11, 2026  
**Primary Crates:** `cyberguard-cli`, `cyberguard-core`, `cyberguard-proc`  
**Language:** Rust 1.85+ (2024 Edition)  

---

## 2. Step 1: Spiral Risk Gate (Quadrant II: Risk Analysis)

Before implementing any code, the engineering team conducted the mandatory Spiral Risk Assessment:

| Risk ID | Identified Risk | Impact | Architectural Mitigation Strategy | Gate Status |
| :--- | :--- | :--- | :--- | :--- |
| **RISK-02-01** | **Subprocess Zombie & Leakage:** Long-running or hung external scanners could remain alive after parent terminates or timeouts trigger. | High | Isolate each child into its own POSIX process group via `setpgid`. Upon timeout, issue `SIGTERM` to the process group (`-pgid`), wait 1s grace period, and terminate via `SIGKILL` if still unresponsive. | **CLEARED ✅** |
| **RISK-02-02** | **Memory Exhaustion via Infinite Stdout:** An external scanner could emit gigabytes of verbose logs or cyclical data, crashing CyberGuard via OOM. | Critical | Implement bounded circular memory buffers in `cyberguard-proc` (default max: 10 MB per stream). Truncate gracefully with a boolean warning flag. | **CLEARED ✅** |
| **RISK-02-03** | **Command Injection in Subprocess Execution:** User input passed to scanner arguments could execute arbitrary shell code if spawned via shell (`sh -c`). | Critical | Strictly forbid shell evaluation (`sh -c`). Use tokenized argument vectors (`Vec<String>`) directly executed via `tokio::process::Command`. | **CLEARED ✅** |
| **RISK-02-04** | **Copyleft / GPL Contamination:** Including external crates under restrictive copyleft licenses. | Critical | Enforce `#![deny(unsafe_code)]` at workspace level; verify all dependencies dual-licensed MIT/Apache-2.0 via `cargo-deny`. | **CLEARED ✅** |
| **RISK-02-05** | **Configuration Drift:** Inconsistent priority between CLI flags, environment variables, and config files. | Medium | Use `figment` with deterministic layering: Defaults ➔ `cyberguard.yaml` ➔ `CYBERGUARD_*` ENV ➔ CLI explicit overrides. | **CLEARED ✅** |

---

## 3. Step 2: Architecture & Component Breakdown

### 3.1 `crates/cyberguard-core`
- **Error System:** Typed enums (`CyberguardError`, `ConfigError`, `ProcessError`) implemented with `thiserror`.
- **Configuration Engine:** `CyberguardConfig` with serialization/deserialization via `figment`, YAML, and ENV.
- **SARIF v2.1.0 Data Model:** Strongly-typed schema structs for OASIS SARIF interoperability.

### 3.2 `crates/cyberguard-proc`
- **Supervisor:** `ProcessSupervisor` with async execution via Tokio.
- **Options:** `ProcessOptions` (timeout, working directory, environment variables, max output bytes).
- **Execution Output:** `ProcessOutput` (exit code, stdout, stderr, execution duration, truncated flag).

### 3.3 `crates/cyberguard-cli`
- **Command Grammar:** `clap` derive parser supporting `scan`, `audit`, `trace`, `fix`, `mcp`, `version`.
- **Output Formatting:** JSON, SARIF, and terminal human-readable output.

---

## 4. Step 3: QA Verification & Test Coverage
- Unit tests for configuration layering and defaults.
- Integration tests for subprocess timeout handling and output truncation.
- SARIF serialization and deserialization validation.
- Zero warnings under `cargo clippy --workspace -- -D warnings`.

---

## 5. Step 4: Review & Sign-Off (Quadrant IV)
- **Linux Foundation DCO:** All commits signed-off (`git commit -s`).
- **Clean Git History:** Atomic commits per architectural boundary.

# Module 02: Core Rust CLI & Process Supervisor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a production-grade, uncompromised Rust foundation for CyberGuard, including a typed error system, layered configuration loader, OASIS SARIF v2.1.0 data model, sandboxed async subprocess supervisor with process-group isolation and bounded memory buffers, and a derive-based Clap CLI tree.

**Architecture:** A virtual Cargo workspace with three decoupled crates (`cyberguard-core`, `cyberguard-proc`, `cyberguard-cli`). Subprocesses are spawned in dedicated POSIX process groups via `setpgid` and monitored with two-stage shutdown (`SIGTERM` ➔ grace period ➔ `SIGKILL`). Stdout/stderr are captured in bounded ring buffers to prevent memory exhaustion DoS.

**Tech Stack:** Rust 1.85+ (2024 edition), `tokio` 1.40+, `clap` 4.5+ (derive), `figment` 0.10+, `serde` 1.0+, `thiserror` 2.0+, `nix` 0.29+, `tracing` 0.1+.

**Spec:** [docs/architecture/RUST_STACK_SPECIFICATION.md](file:///home/john/CYBER-GUARD/docs/architecture/RUST_STACK_SPECIFICATION.md) and [docs/modules/MODULE_02.md](file:///home/john/CYBER-GUARD/docs/modules/MODULE_02.md).

## Global Constraints
- Strictly Apache-2.0 clean-room. No GPL or AGPL crates statically linked.
- Zero `unsafe` blocks outside of required POSIX `pre_exec(setpgid)` with audit justification.
- Automated test coverage >= 80% with all tests passing.
- Zero compiler or clippy warnings (`-D warnings`).
- All commits signed with `git commit -s` (Linux Foundation DCO).

## Review Focus
1. Child subprocess hangs indefinitely when reading or writing large data (solved by Tokio non-blocking pipes).
2. Grandchild processes become orphaned zombies when a scanner spawns child workers (solved by POSIX process group `killpg`).
3. External scanner produces gigabytes of recursive output (solved by 10MB bounded circular buffer with truncation flag).
4. Config file overrides not respecting CLI arguments (solved by Figment deterministic layer priority: Defaults ➔ YAML ➔ ENV ➔ CLI).
5. Deserialization of malformed SARIF crashes the engine (solved by robust Serde validation with default fallbacks).

---

### Task 1: `cyberguard-core` Domain Errors & Configuration Engine
**Files:**
- Create: `crates/cyberguard-core/src/error.rs`
- Create: `crates/cyberguard-core/src/config.rs`
- Modify: `crates/cyberguard-core/src/lib.rs`
- Test: `crates/cyberguard-core/tests/config_test.rs`

**Interfaces:**
- Produces:
  - `enum CyberguardError` (implements `thiserror::Error`)
  - `struct Config` (implements `serde::Serialize, serde::Deserialize`)
  - `impl Config { pub fn load(cli_path: Option<&Path>) -> Result<Self, CyberguardError>; }`

- [ ] **Step 1: Write failing configuration tests in `crates/cyberguard-core/tests/config_test.rs`**
- [ ] **Step 2: Implement domain errors in `crates/cyberguard-core/src/error.rs`**
- [ ] **Step 3: Implement Figment configuration loader in `crates/cyberguard-core/src/config.rs`**
- [ ] **Step 4: Run tests and verify passing**
- [ ] **Step 5: DCO Commit**

---

### Task 2: `cyberguard-core` OASIS SARIF v2.1.0 Data Models
**Files:**
- Create: `crates/cyberguard-core/src/sarif.rs`
- Modify: `crates/cyberguard-core/src/lib.rs`
- Test: `crates/cyberguard-core/tests/sarif_test.rs`

**Interfaces:**
- Produces:
  - `struct SarifLog`, `struct Run`, `struct Tool`, `struct ReportingDescriptor`, `struct ResultFinding`, `struct Location`
  - `impl SarifLog { pub fn new(tool_name: &str, tool_version: &str) -> Self; pub fn add_result(&mut self, result: ResultFinding); }`

- [ ] **Step 1: Write failing SARIF serialization/deserialization tests**
- [ ] **Step 2: Implement SARIF v2.1.0 structs with Serde annotations**
- [ ] **Step 3: Run tests and verify passing**
- [ ] **Step 4: DCO Commit**

---

### Task 3: `cyberguard-proc` Sandboxed Subprocess Supervisor
**Files:**
- Create: `crates/cyberguard-proc/src/supervisor.rs`
- Create: `crates/cyberguard-proc/src/options.rs`
- Create: `crates/cyberguard-proc/src/output.rs`
- Modify: `crates/cyberguard-proc/src/lib.rs`
- Test: `crates/cyberguard-proc/tests/supervisor_test.rs`

**Interfaces:**
- Produces:
  - `struct ProcessOptions` (command, args, cwd, env, timeout_ms, max_output_bytes)
  - `struct ProcessOutput` (exit_code, stdout, stderr, duration, truncated)
  - `pub async fn execute_process(options: ProcessOptions) -> Result<ProcessOutput, CyberguardError>;`

- [ ] **Step 1: Write failing supervisor tests (normal exit, timeout cancellation, bounded output)**
- [ ] **Step 2: Implement `ProcessOptions` and `ProcessOutput`**
- [ ] **Step 3: Implement `execute_process` with Tokio async process, `setpgid`, and circular buffer**
- [ ] **Step 4: Run tests and verify passing**
- [ ] **Step 5: DCO Commit**

---

### Task 4: `cyberguard-cli` Command Tree & Dispatcher
**Files:**
- Create: `crates/cyberguard-cli/src/commands/mod.rs`
- Create: `crates/cyberguard-cli/src/commands/scan.rs`
- Create: `crates/cyberguard-cli/src/commands/audit.rs`
- Create: `crates/cyberguard-cli/src/commands/trace.rs`
- Create: `crates/cyberguard-cli/src/commands/fix.rs`
- Create: `crates/cyberguard-cli/src/commands/mcp.rs`
- Modify: `crates/cyberguard-cli/src/main.rs`
- Test: `crates/cyberguard-cli/tests/cli_test.rs`

**Interfaces:**
- Produces:
  - `clap` parser with subcommands and structured help
  - `cyberguard --version`, `cyberguard scan <PATH>`, `cyberguard trace <PATH>`, `cyberguard fix <PATH>`, `cyberguard mcp`

- [ ] **Step 1: Write failing CLI argument parsing integration tests**
- [ ] **Step 2: Implement command definitions and dispatcher**
- [ ] **Step 3: Run tests and verify binary builds cleanly**
- [ ] **Step 4: DCO Commit**

# 🦀 CyberGuard Rust Architecture & Technical Stack Specification
## Definitive Blueprint for Autonomous Vulnerability Intelligence & Remediation

---

## 1. Executive Summary & Architectural Tenets

CyberGuard is designed as an uncompromising, top-tier open-source platform. Modern software security engines fail when built upon interpreted scripts or high-overhead runtimes because graph reachability traversal, semantic taint tracking across millions of AST nodes, and parallel subprocess supervision require:
1. **Zero Garbage Collection (GC) pauses:** Deterministic memory footprint during deep call-graph and DAG traversal.
2. **Compile-time Concurrency & Memory Safety:** Data-race freedom across multi-threaded static analysis passes.
3. **Pure Native Static Binaries:** Cross-platform single-binary distribution (`x86_64`, `aarch64`) with zero runtime dynamic dependencies (`musl` / `glibc`).
4. **Native Tree-sitter Interoperability:** C-ABI bindings without Go CGO overhead, cross-compilation friction, or garbage collector handoffs.
5. **Clean-Room License Compliance:** Strictly Apache-2.0 / MIT. Zero GPL/AGPL contamination.

---

## 2. Definitive Rust Crate Ecosystem Matrix

Every crate selected for CyberGuard has been evaluated against:
- **License compatibility:** Apache-2.0 or MIT only.
- **Maintenance velocity:** Active in 2026, zero unpatched RustSec advisories.
- **Quality & Community Adoption:** Production-proven across major systems.

| Architectural Layer | Selected Crate | Version | License | Architectural Role & Rationale |
| :--- | :--- | :--- | :--- | :--- |
| **CLI & Commands** | `clap` | `4.6` (derive) | MIT / Apache-2.0 | Type-safe declarative CLI tree, recursive subcommands, shell auto-completion generator. |
| **Rich CLI Diagnostics** | `miette` | `7.6` | Apache-2.0 | Compiler-grade diagnostics rendering (`rustc`-style underlined spans, colors, suggestion hints). |
| **Async Runtime** | `tokio` | `1.54` (full) | MIT | Epoll/kqueue multi-threaded asynchronous reactor, timer wheel, async file/process I/O. |
| **Layered Configuration** | `figment` | `0.10` | MIT / Apache-2.0 | Layered configuration provider (`Defaults -> Config file -> ENV vars -> CLI flags`) with provenance tracking. |
| **Structured Observability** | `tracing` + `tracing-subscriber` | `0.1` / `0.3` | MIT | Context-aware async spans, structured JSON event emission, OpenTelemetry readiness. |
| **Error Handling (Crates)** | `thiserror` | `2.0` | MIT / Apache-2.0 | Zero-boilerplate typed domain error enums across internal crates. |
| **Universal Serialization** | `serde` + `serde_json` | `1.0` | MIT / Apache-2.0 | Zero-copy deserialization framework for SARIF, OCSF, and AST interchange. |
| **High-Perf JSON Hot-Path** | `sonic-rs` | `0.5` | Apache-2.0 | SIMD-accelerated JSON parser with `LazyValue` for processing multi-gigabyte SARIF outputs. |
| **Secure YAML Engine** | `serde-saphyr` | `1.3` | MIT / Apache-2.0 | Modern memory-safe YAML deserializer (replaces archived `serde_yaml` vulnerable to RUSTSEC-2025-0068). |
| **Graph & Attack Paths (DAG)** | `petgraph` | `0.8` | MIT / Apache-2.0 | Fast directed graph engine (`StableGraph`), Tarjan's SCC, Dijkstra, reachability traversal. |
| **Multi-Language AST Parsing** | `tree-sitter` + `tree-sitter-language-pack` | `0.27` / `1.25` | MIT | Incremental CST/AST syntax trees across 300+ languages with zero CGO compilation headaches. |
| **Diff & Patch Visualization** | `similar` | `3.1` | Apache-2.0 | Myers, Patience, and Histogram diff algorithms for syntax-highlighted code terminal previews. |
| **Unified Patch Application** | `diffy` | `0.5` | MIT | Programmatic patch synthesis, validation, and unified diff file application. |
| **Subprocess & OS Isolation** | `nix` | `0.31` | MIT | POSIX process group isolation (`setpgid`), Unix signals (`SIGTERM`/`SIGKILL`), IPC. |
| **Terminal UI (TUI)** | `ratatui` | `0.29` | MIT | Immediate-mode interactive terminal dashboard for live scan monitoring and attack path exploration. |
| **Async HTTP Client** | `reqwest` | `0.13` (rustls) | MIT / Apache-2.0 | Non-blocking HTTP client with pure-Rust TLS (`rustls`) for advisory feeds (NVD, OSV, EPSS). |
| **Embedded Result Store** | `rusqlite` (bundled) | `0.41` | MIT | Fast embedded SQLite engine for relational CWE/CVE indexing, historical diffs, and FTS5 search. |
| **Cache & State Store** | `redb` | `2.6` / `4.5` | MIT / Apache-2.0 | Zero-C pure Rust ACID key-value and tabular store for instant credential/hash lookup. |
| **UUIDs & Hashes** | `uuid` + `sha2` | `1.10` / `0.10` | Apache-2.0 / MIT | Universally unique finding identifiers and cryptographic file/AST hashing. |
| **Terminal Colorization** | `owo-colors` | `4.1` | MIT | Zero-allocation compile-time ANSI terminal styling. |

---

## 3. Cargo Workspace Architecture

CyberGuard is structured as a modular Cargo virtual workspace. This enforces strict separation of concerns, rapid incremental compilation, and modular test boundaries.

```
CYBER-GUARD/
├── Cargo.toml                    # Virtual Workspace Root (shared deps & lints)
├── Cargo.lock                    # Deterministic Dependency Lockfile
├── deny.toml                     # cargo-deny license & advisory policy
├── crates/
│   ├── cyberguard-core/          # SARIF v2.1.0, OCSF, Domain Models, Config, Error Types
│   ├── cyberguard-proc/          # Sandboxed Subprocess Supervisor & Bounded Buffer Engine
│   ├── cyberguard-ast/           # Tree-sitter Parsers, Taint Tracker & Call Graph Extractor
│   ├── cyberguard-graph/         # Attack Path Graph (DAG), Reachability, Tri-Factor Math
│   ├── cyberguard-remediate/     # AST Code Patcher, Diff Synthesizer & Unit Test Generator
│   ├── cyberguard-mcp/           # Anthropic Model Context Protocol Server (Stdio/SSE)
│   ├── cyberguard-tui/           # Ratatui Interactive Terminal Dashboard
│   └── cyberguard-cli/           # Main CyberGuard Unified CLI Binary Entrypoint
```

---

## 4. Subprocess Supervisor & Sandboxing (`cyberguard-proc`)

External scanners and compilers must be treated as untrusted subprocesses. The supervisor guarantees:
1. **Process Group Isolation (`setpgid`):** Every child process is spawned in its own POSIX process group. Child sub-processes (grandchildren) cannot escape termination.
2. **Two-Stage Graceful Shutdown:**
   - Step 1: Send `SIGTERM` to the entire process group (`-pgid`).
   - Step 2: Await a 5-second grace period via `tokio::time::timeout`.
   - Step 3: If unresponsive, escalate to unconditional `SIGKILL` (`-pgid`).
3. **Bounded Memory Circular Buffers:** Stdout and stderr are captured via bounded ring buffers (default: 16 MB max). Any malicious scanner producing infinite stdout will have its output bounded without crashing CyberGuard with an OOM (Out Of Memory) panic.
4. **Clean Exit Code & Signal Capture:** Accurate status reporting mapping OS signals, exits, and execution wall-clock time.

---

## 5. Universal Security Bus & SARIF Standard (`cyberguard-core`)

CyberGuard speaks the international OASIS standard:
- **SARIF v2.1.0** (Static Analysis Results Interchange Format) as first-class citizens.
- Fully typed Rust data models with `serde::Serialize` and `serde::Deserialize`.
- Custom extensions for CyberGuard's **Tri-Factor Risk Index**:
  $$\text{Risk Score} = \text{CVSS} \times \text{EPSS} \times \text{Reachability}$$

---

## 6. Model Context Protocol (MCP) Integration (`cyberguard-mcp`)

CyberGuard exposes its intelligence natively to AI coding agents (Claude Code, Antigravity, Cursor) via the JSON-RPC 2.0 Model Context Protocol:
- **`tools/list`**: `cyberguard_scan`, `cyberguard_trace_path`, `cyberguard_generate_patch`, `cyberguard_verify_fix`.
- **`resources/list`**: `sarif://scan-results`, `graph://attack-paths`, `diff://proposed-fixes`.
- **Transport**: JSON-RPC over `stdio` (local CLI agents) and Server-Sent Events / SSE (remote agents).

---

## 7. Quality, Verification & CI/CD Enforcement

1. **Clippy Zero-Tolerance:** `cargo clippy --workspace --all-targets -- -D warnings`
2. **Unsafe Denied:** Root crate policy `#![deny(unsafe_code)]` with explicit audits for low-level POSIX `setpgid` calls.
3. **Coverage Standard:** `>= 80%` branch coverage verified by `cargo-tarpaulin`.
4. **License Compliance:** `cargo-deny check licenses` enforces zero GPL/AGPL crates.
5. **Security Advisories:** `cargo-deny check advisories` blocks known CVEs.

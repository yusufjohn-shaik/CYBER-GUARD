# 🦀 CyberGuard Rust Architecture & Comprehensive Function-by-Function Ecosystem Specification
## The Definitive High-Performance, Memory-Safe Engineering Blueprint

---

## 1. Architectural Philosophy & Zero-Compromise Standards

CyberGuard is engineered from the ground up to become the world's #1 open-source vulnerability intelligence and autonomous remediation platform. Building an enterprise-grade security product in the open requires uncompromising decisions across every subsystem:

1. **Zero Garbage Collection (GC) Stalls:** In-memory attack path graph traversal and AST reachability analysis across millions of nodes must execute with deterministic microsecond latency.
2. **Clean-Room License Fortress:** Strictly **Apache-2.0, MIT, BSD-3-Clause, or CC0-1.0**. Absolutely zero GPL or AGPL crates statically linked or vendored into the binary.
3. **Zero-Overhead Memory Safety:** Zero `unsafe` blocks in application logic; low-level POSIX process group controls (`setpgid`) strictly isolated and audited.
4. **Pure Native Static Distribution:** Compile to single self-contained binaries (`musl` / `glibc` / macOS `universal` / Windows) with zero C runtime dependencies where possible.
5. **No Deprecated or Vulnerable Crates:** Rejecting abandoned crates (such as `serde_yaml` vulnerable to RUSTSEC-2025-0068, or discontinued `async-std`) in favor of active, secure 2026 standards.

---

## 2. Exhaustive Function-by-Function Stack Matrix

Here is the audited, verified stack covering every critical capability and function in CyberGuard:

| # | System Function | Recommended Crate(s) | Version | License | Ecosystem Stability & Quality Signal | Why It Wins Against Alternatives |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **01** | **CLI Parser & UX** | `clap` (derive + env) | `4.6.x` | MIT / Apache-2.0 | ~17k stars, industry standard | Arbitrary-depth subcommand trees (`scan`, `trace`, `fix`), declarative validation, auto-generated man pages & shell completions. `argh` is too barebones; `bpaf` lacks deep community adoption. |
| **02** | **Compiler-Grade Diagnostics** | `miette` (fancy) | `7.6.x` | Apache-2.0 | ~2.6k stars, production standard | Renders `rustc`-grade diagnostics with colored source snippets, underlined column spans, and remediation hints for misconfigurations and vulnerabilities. Far superior to plain `anyhow` text. |
| **03** | **Async Runtime & I/O** | `tokio` (full) | `1.54.x` | MIT | ~34k stars, 150M+ monthly downloads | Discontinued `async-std` (March 2025) must never be used. Tokio provides the battle-tested multi-threaded epoll/kqueue reactor, async process drivers, channels, and timer wheels. |
| **04** | **Layered Config & Provenance** | `figment` (yaml, env) | `0.10.x` | MIT / Apache-2.0 | Production-tested in Rocket framework | Built-in provenance tracking: records whether a value originated from CLI flags, ENV (`CYBERGUARD_*`), config YAML, or defaults. `config-rs` lacks provenance and CLI struct merging. |
| **05** | **Structured Observability** | `tracing` + `tracing-subscriber` | `0.1.x` / `0.3.x` | MIT | De facto Rust standard | First-class async-aware spans that travel with tasks across threads; JSON formatter for SIEM ingest; native OpenTelemetry bridge (`tracing-opentelemetry`). |
| **06** | **Domain Error System** | `thiserror` | `2.0.x` | MIT / Apache-2.0 | Universal standard | Zero-boilerplate strongly-typed error enums for library crates (`CyberguardError`, `ConfigError`, `ProcessError`). |
| **07** | **Process Supervision & Sandboxing** | `nix` (process, signal) + `tokio::process` | `0.29` / `0.31` | MIT | POSIX standard wrapper | POSIX process group isolation (`setpgid`). Ensures child scanners and their grandchildren are terminated together via group signals (`killpg`) with 2-stage `SIGTERM` ➔ `SIGKILL`. |
| **08** | **Universal SARIF Standard** | `serde` + `serde_json` | `1.0.x` | MIT / Apache-2.0 | Universal Rust serialization | OASIS SARIF v2.1.0 strongly typed schemas with custom CyberGuard Tri-Factor metadata properties. |
| **09** | **SIMD JSON Hot-Path** | `sonic-rs` | `0.5.x` | Apache-2.0 | ByteDance high-perf engine | SIMD-accelerated parser with `LazyValue` API for ingesting multi-gigabyte SARIF/OCSF tool outputs ~2x faster than standard parsers without RAM bloat. |
| **10** | **Secure YAML Parser** | `serde-saphyr` | `1.3.x` | MIT / Apache-2.0 | Actively maintained, panic-free | Replaces archived `serde_yaml` (which suffers from CVE RUSTSEC-2025-0068). Includes Billion Laughs DoS protection for parsing untrusted rule files. |
| **11** | **Multi-Language AST Parsing** | `tree-sitter` + `tree-sitter-language-pack` | `0.27.x` / `1.25.x` | MIT | GitHub standard | Incremental Concrete Syntax Tree (CST) parsing across 300+ programming languages in pure native C-ABI without Go CGO runtime overhead. |
| **12** | **Attack Path Graph (DAG)** | `petgraph` (`StableGraph`) | `0.8.x` | MIT / Apache-2.0 | De facto graph library | Tarjan's Strongly Connected Components (SCC), Dijkstra/A* shortest attack paths, cycle detection, and stable node indexing after edge pruning. |
| **13** | **Diff & Visual Comparison** | `similar` | `3.1.x` | Apache-2.0 | Powers `insta` snapshot testing | Myers, Patience, and Histogram diff algorithms with line, word, and character-level terminal highlighting for security patch inspection. |
| **14** | **Patch File Application** | `diffy` | `0.5.x` | MIT | Clean patch roundtrip library | Programmatic creation and application of unified diffs directly against disk files for automated vulnerability remediation. |
| **15** | **Non-Blocking HTTP Client** | `reqwest` (rustls-tls, json) | `0.13.x` | MIT / Apache-2.0 | Most popular Rust HTTP client | Pure-Rust TLS via `rustls` (eliminates OpenSSL dynamic link issues); connection pooling for fetching live EPSS, NVD, and OSV advisory feeds. |
| **16** | **Pure-Rust Git Traversal** | `gix` (Gitoxide) | `0.66.x+` | MIT / Apache-2.0 | Top-tier pure Rust Git engine | High-speed, memory-safe commit-graph traversal for secret hunting and historical CVE correlation without invoking external git binaries or C-based `libgit2`. |
| **17** | **Fast Cryptographic Hashing** | `blake3` | `1.5.x` | CC0-1.0 / Apache-2.0 | World's fastest cryptographic hash | SIMD-accelerated Merkle tree hash (~10x faster than SHA-256). Used for finding deduplication, AST node fingerprinting, and scan artifact integrity. |
| **18** | **Digital Signatures & Auth** | `ed25519-dalek` | `2.1.x` / `3.x` | BSD-3-Clause | Pure-Rust Edwards-curve cryptography | Cryptographic Proof-of-Authorization verification (`proof_of_authorization.sig`) to prevent unauthorized network or DAST scans. |
| **19** | **SBOM Supply Chain Engine** | `cyclonedx-bom` | `0.8.x` | Apache-2.0 | OWASP standard | Generates and parses OWASP CycloneDX v1.5/v1.6 Software Bills of Materials for container images and package locks. |
| **20** | **Terraform / IaC Parsing** | `hcl-rs` | `0.18.x` | MIT / Apache-2.0 | Standard HashiCorp HCL parser | Parses Terraform `.tf` configurations and HCL blocks into typed AST structures to detect cloud misconfigurations before deployment. |
| **21** | **API Specification Fuzzing** | `openapiv3` | `2.0.x` | MIT / Apache-2.0 | Standard OpenAPI 3 parser | Strongly-typed OpenAPI contract validation, path extraction, and parameter fuzzing for BOLA/IDOR and BFLA detection. |
| **22** | **Relational Scan Persistence** | `rusqlite` (bundled) | `0.41.x` | MIT | Embedded SQLite standard | Bundles SQLite C sources directly; provides relational joins, indexing, and FTS5 full-text search across historical vulnerability records. |
| **23** | **ACID Key-Value Cache** | `redb` | `2.6.x` / `4.5.x` | MIT / Apache-2.0 | Pure Rust LMDB successor | Zero-C dependency, ACID-compliant B+ tree embedded store for ultra-fast local advisory caching and secret hash lookup. |
| **24** | **AI Agent MCP Server** | `rmcp` (server, tokio) | `0.1.x+` | MIT / Apache-2.0 | Official Model Context Protocol SDK | Native JSON-RPC 2.0 protocol implementation for exposing CyberGuard as an AI tool to Claude Code, Antigravity, and Cursor via stdio and SSE. |
| **25** | **Interactive Terminal UI** | `ratatui` + `crossterm` | `0.29.x` / `0.28.x` | MIT | Undisputed Rust TUI leader | Immediate-mode rendering for live scanning dashboards, interactive attack path explorers, and remediation diff approval views. |
| **26** | **Zero-Allocation Terminal Colors** | `owo-colors` | `4.1.x` | MIT | Zero-allocation styling | Compile-time ANSI colorization for high-throughput CLI output with zero string heap allocations. |
| **27** | **Static Cross-Compilation** | `cargo-zigbuild` | `0.24.x` | MIT | Modern cross-toolchain | Compiles static, musl-linked Linux binaries, macOS universal binaries, and Windows executables without requiring heavyweight Docker containers. |
| **28** | **Supply Chain & License Gate** | `cargo-deny` | `0.16.x` | MIT / Apache-2.0 | Embark Studios security gate | Enforces strict license boundaries (rejecting copyleft GPL/AGPL) and blocks dependencies with active RustSec CVEs in CI. |

---

## 3. Subsystem Architecture & Integration Patterns

### 3.1 Subprocess Supervisor & Bounded Buffer Engine (`cyberguard-proc`)
External tools (e.g., Semgrep, Trivy, Nmap) must never crash CyberGuard via memory leaks or hung processes:
- **Process Group Isolation:** Every child process is spawned inside a dedicated POSIX process group using `nix::unistd::setpgid(0, 0)` in `pre_exec`.
- **Bounded Circular Stream:** `stdout` and `stderr` streams are captured via an async non-blocking ring buffer. If a scanner outputs gigabytes of noise, CyberGuard bounds capture to `max_output_bytes` (default: 10 MB), drains the excess to prevent child write-blocking, and sets `truncated = true`.
- **Two-Stage Signal Escalation:** Upon timeout, CyberGuard issues `SIGTERM` to `-pgid`. If unresponsive after a 50ms grace window, it issues unconditional `SIGKILL` to `-pgid`, preventing zombie processes.

### 3.2 In-Memory Attack Path Graph (`cyberguard-graph`)
Traditional scanners produce flat lists of alerts. CyberGuard models software security as an in-memory Directed Acyclic Graph (DAG) using `petgraph::StableGraph`:
- **Nodes:** `Endpoint`, `Controller`, `Function`, `Dependency`, `Secret`, `CloudIAMRole`, `StorageBucket`.
- **Edges:** `DataFlowsTo`, `Calls`, `AuthenticatesWith`, `AssumesRole`, `ReadsFrom`.
- **Reachability Algorithm:** Tarjan's Strongly Connected Components (SCC) to detect cycles, followed by reverse topological reachability queries from exposed entrypoints to vulnerable sinks.

### 3.3 Tri-Factor Risk Index Formula
$$\text{Risk Score} = \text{CVSS} \times \text{EPSS} \times \text{Reachability Index}$$
- **CVSS (0.0 – 10.0):** Theoretical baseline severity.
- **EPSS (0.0 – 1.0):** Real-time probability of active in-the-wild exploitation via live FIRST.org feed.
- **Reachability Index (0.0 or 1.0):** Binary or proportional multiplier determined by Tree-sitter call-graph reachability. If an entrypoint cannot reach the vulnerable sink, risk is immediately scaled down, eradicating 70%+ of developer noise.

### 3.4 Model Context Protocol (MCP) Server (`cyberguard-mcp`)
CyberGuard implements the official `rmcp` protocol:
- **`tools/list`:**
  - `cyberguard_scan`: Execute targeted AST/SAST scans against a file or workspace.
  - `cyberguard_trace_attack_path`: Retrieve full kill-chain graphs leading to a specific vulnerability.
  - `cyberguard_generate_patch`: Produce an AST-verified syntax-preserving code fix.
- **Transports:**
  - `stdio`: Default transport for local AI CLI agents (Claude Code, Antigravity CLI).
  - `sse`: HTTP Server-Sent Events transport for web IDEs and remote AI services.

---

## 4. Stability & Security Checklist

Every crate in CyberGuard's manifest must pass three automated gates:
1. **`cargo deny check licenses`:** Verifies that 100% of transitive dependencies are compatible with Apache-2.0 clean-room requirements.
2. **`cargo deny check advisories`:** Queries the RustSec Advisory Database on every build to block vulnerable dependency versions.
3. **`cargo clippy --workspace -- -D warnings`:** Zero compiler or linter warnings across all crates.

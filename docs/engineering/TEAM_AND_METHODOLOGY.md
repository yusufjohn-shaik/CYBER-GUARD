# 👥 CyberGuard Engineering Team & Methodology
## The Agile-Spiral Hybrid Model (Risk-Driven Agile)

---

## 1. Engineering Philosophy

CyberGuard is built using the **Agile-Spiral Hybrid Model**. 

Standard agile sprints can introduce severe architectural debt or security vulnerabilities if code is rushed without threat analysis. Conversely, the traditional spiral model can become bogged down in excessive paperwork. 

Our hybrid model combines the **shipping velocity of Agile** with the **architectural fortress of the Spiral Model**:
- **Agile Execution:** Daily time-boxed sprint increments, user-story driven development, rapid feature iteration, and functional binaries delivered daily.
- **Spiral Risk Gates:** Every sprint begins with a mandatory 5-minute pre-implementation **Risk & Threat Gate** to eliminate copyleft contamination, subprocess command injection, memory-safety regressions, or parser DoS vulnerabilities before code is merged.

---

## 2. Team Roster & Specialized Roles

To build an enterprise-grade platform at maximum velocity, the engineering team is organized into five specialized roles:

```
┌────────────────────────────────────────────────────────────────────────┐
│               LEAD ARCHITECT & SPRINT ORCHESTRATOR                     │
│  - Roadmap alignment, architectural integrity, and PR review gate      │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
          ┌─────────────────────────┴─────────────────────────┐
          ▼                                                   ▼
┌───────────────────────────────────┐       ┌───────────────────────────────────┐
│     RISK & SECURITY AUDITOR       │       │   CORE RUST SYSTEMS ENGINEER      │
│  - Spiral risk analysis gate      │       │  - Rust 1.99+ async/safe core     │
│  - Clean-room copyleft checks     │       │  - clap CLI, figment config       │
│  - Threat modeling (CFAA/OWASP)   │       │  - tokio subprocess supervisor    │
└─────────────────┬─────────────────┘       └─────────────────┬─────────────────┘
                  │                                           │
                  └─────────────────────┬─────────────────────┘
                                        │
          ┌─────────────────────────────┴─────────────────────────────┐
          ▼                                                           ▼
┌───────────────────────────────────┐       ┌───────────────────────────────────┐
│   AST & REMEDIATION SPECIALIST    │       │     QA & TEST AUTOMATION LEAD     │
│  - Tree-sitter multi-language AST │       │  - Test-Driven Development (TDD)  │
│  - Surgical syntax code patcher   │       │  - >= 80% coverage enforcement    │
│  - Model Context Protocol (MCP)   │       │  - Miri & clippy gates            │
└───────────────────────────────────┘       └───────────────────────────────────┘
```

### 🛡️ Role Responsibilities:

| Role | Subagent Handle | Primary Mandate |
| :--- | :--- | :--- |
| **Lead Architect** | `parent-agent` | Defines sprint backlogs, reviews user stories, maintains roadmap milestones, and enforces clean git history. |
| **Risk & Security Auditor** | `risk-auditor` | Evaluates threat models, ensures GPL/AGPL tools remain strictly isolated as external subprocesses, audits memory and timeout limits. |
| **Core Rust Systems Engineer** | `core-rust-engineer` | Writes safe, idiomatic Rust (`tokio`, `clap`, `petgraph`, `serde`), ensures zero `unsafe` blocks without audit comments, leverages Rust's ownership model for memory safety. |
| **AST & Remediation Specialist**| `ast-remediation-specialist` | Implements Tree-sitter parsers, generates surgical code diffs, synthesizes automated regression unit tests, integrates MCP server. |
| **QA & Verification Engineer** | `qa-verifier` | Enforces TDD, writes comprehensive unit/integration test suites, verifies `cargo test` >= 80% coverage via `cargo-tarpaulin`, runs `clippy` and `cargo deny` gates. |

---

## 3. The 4-Step Sprint Lifecycle

Every daily module is executed through four synchronized phases:

```
[Sprint User Story]
         │
         ▼
 1. Spiral Risk Gate  ──► Threat model & clean-room copyleft verification
         │
         ▼
 2. TDD Implementation ──► Core Rust engineering + AST integration
         │
         ▼
 3. QA & Benchmarking  ──► clippy, test coverage >= 80%, criterion benchmarks
         │
         ▼
 4. Review & DCO Commit──► Clean git commit with Developer Certificate of Origin
```

1. **Step 1: Spiral Risk Gate (Quadrant II):**
   - Identify edge cases, license boundaries, and potential vulnerability vectors in the planned feature.
   - Example: *"Will wrapping this external scanner introduce a shell-injection vector? Solution: enforce tokenized `tokio::process::Command` with timeout and process group isolation via `nix::unistd::setpgid`."*
2. **Step 2: Agile TDD Implementation (Quadrant III):**
   - Write unit test stubs defining expected behavior.
   - Implement clean-room Rust code fulfilling the trait interfaces.
3. **Step 3: QA Verification & Benchmarking (Quadrant III):**
   - Run `cargo test --workspace` and `cargo clippy --workspace -- -D warnings`.
   - Confirm test coverage exceeds 80% via `cargo tarpaulin --workspace`.
4. **Step 4: Review & DCO Commit (Quadrant IV):**
   - Sign off the commit (`git commit -s`).
   - Update module documentation in `docs/modules/` and check off roadmap milestones.

---

## 4. Definition of Done (DoD)

A sprint or module is only declared **DONE** when:
1. **Compiles Cleanly:** `cargo build --workspace` with zero warnings (`-D warnings`).
2. **Passes Linter:** Code satisfies `cargo clippy --workspace -- -D warnings` and `cargo fmt --check`.
3. **Automated Tests:** Minimum **80% test coverage** via `cargo tarpaulin --workspace`.
4. **No Copyleft Contamination:** Verified zero GPL/AGPL crates via `cargo deny check licenses`.
5. **Signed-off Commit:** Conforms to Linux Foundation DCO (`git commit -s`).

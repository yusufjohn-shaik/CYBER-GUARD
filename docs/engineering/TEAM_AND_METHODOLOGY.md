# 👥 CyberGuard Engineering Team & Methodology
## The Agile-Spiral Hybrid Model (Risk-Driven Agile)

---

## 1. Engineering Philosophy

CyberGuard is built using the **Agile-Spiral Hybrid Model**. 

Standard agile sprints can introduce severe architectural debt or security vulnerabilities if code is rushed without threat analysis. Conversely, the traditional spiral model can become bogged down in excessive paperwork. 

Our hybrid model combines the **shipping velocity of Agile** with the **architectural fortress of the Spiral Model**:
- **Agile Execution:** Daily time-boxed sprint increments, user-story driven development, rapid feature iteration, and functional binaries delivered daily.
- **Spiral Risk Gates:** Every sprint begins with a mandatory 5-minute pre-implementation **Risk & Threat Gate** to eliminate copyleft contamination, subprocess command injection, memory leaks, or parser DoS vulnerabilities before code is merged.

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
│     RISK & SECURITY AUDITOR       │       │    CORE GO SYSTEMS ENGINEER       │
│  - Spiral risk analysis gate      │       │  - Go 1.22+ pure compiled core    │
│  - Clean-room copyleft checks     │       │  - Cobra CLI, Viper configuration │
│  - Threat modeling (CFAA/OWASP)   │       │  - Subprocess supervisor & DAG    │
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
│  - Model Context Protocol (MCP)   │       │  - Race detection & OpenSSF gates │
└───────────────────────────────────┘       └───────────────────────────────────┘
```

### 🛡️ Role Responsibilities:

| Role | Subagent Handle | Primary Mandate |
| :--- | :--- | :--- |
| **Lead Architect** | `parent-agent` | Defines sprint backlogs, reviews user stories, maintains roadmap milestones, and enforces clean git history. |
| **Risk & Security Auditor** | `risk-auditor` | Evaluates threat models, ensures GPL/AGPL tools remain strictly isolated as external subprocesses, audits memory and timeout limits. |
| **Core Go Systems Engineer** | `core-go-engineer` | Writes pure Go 1.22+ code (`modernc.org/sqlite`, `spf13/cobra`, `gonum/graph`), ensures zero CGO compilation dependencies. |
| **AST & Remediation Specialist**| `ast-remediation-specialist` | Implements Tree-sitter parsers, generates surgical code diffs, synthesizes automated regression unit tests, integrates MCP server. |
| **QA & Verification Engineer** | `qa-verifier` | Enforces TDD, writes comprehensive unit/integration test suites (`*_test.go`), verifies `go test -race -cover` >= 80%, validates OpenSSF criteria. |

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
 2. TDD Implementation ──► Core Go / Python engineering + AST integration
         │
         ▼
 3. QA & Benchmarking  ──► Race detection, test coverage >= 80%, latency check
         │
         ▼
 4. Review & DCO Commit──► Clean git commit with Developer Certificate of Origin
```

1. **Step 1: Spiral Risk Gate (Quadrant II):**
   - Identify edge cases, license boundaries, and potential vulnerability vectors in the planned feature.
   - Example: *"Will wrapping this external scanner introduce a shell-injection vector? Solution: enforce tokenized `exec.Command` slices with timeout contexts."*
2. **Step 2: Agile TDD Implementation (Quadrant III):**
   - Write unit test stubs defining expected behavior.
   - Implement clean-room Go/Python code fulfilling the interfaces.
3. **Step 3: QA Verification & Benchmarking (Quadrant III):**
   - Run `go test -v -race -covermode=atomic ./...`.
   - Confirm zero memory leaks and test coverage exceeds 80%.
4. **Step 4: Review & DCO Commit (Quadrant IV):**
   - Sign off the commit (`git commit -s`).
   - Update module documentation in `docs/modules/` and check off roadmap milestones.

---

## 4. Definition of Done (DoD)

A sprint or module is only declared **DONE** when:
1. **Compiles Cleanly:** Zero build warnings or CGO runtime dependencies.
2. **Passes Linter:** Code satisfies `golangci-lint` and `gofmt -s`.
3. **Automated Tests:** Minimum **80% test coverage** with race detection enabled (`-race`).
4. **No Copyleft Contamination:** Verified zero GPL/AGPL libraries statically linked or vendored.
5. **Signed-off Commit:** Conforms to Linux Foundation DCO (`git commit -s`).

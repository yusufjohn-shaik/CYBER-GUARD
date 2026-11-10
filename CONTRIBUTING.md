# Contributing to CyberGuard

Thank you for your interest in contributing to **CyberGuard**! We are building the world's #1 open-source, one-stop cybersecurity platform, combining multi-domain security tooling with autonomous AI agents.

To ensure long-term sustainability, enterprise adoption, and community trust, all contributions must adhere to our legal, architectural, and quality standards.

---

## 1. Developer Certificate of Origin (DCO)

To maintain a clean legal chain of custody, CyberGuard utilizes the **Linux Foundation Developer Certificate of Origin (DCO v1.1)** rather than a restrictive Contributor License Agreement (CLA).

By contributing to CyberGuard, you certify that:
- The contribution was created in whole or in part by you, and you have the right to submit it under the Apache License 2.0; or
- The contribution is based upon previous work covered by an appropriate open-source license, and you have preserved the required notices; or
- The contribution was provided directly to you by someone who certified the above, and you have not modified it.

### How to Sign Off Your Commits
You **must** sign off every commit by adding the `-s` flag to your git commit command:

```bash
git commit -s -m "feat(sast): add semgrep SARIF parser integration"
```

This appends a trailer to your commit message:
```text
Signed-off-by: Jane Doe <jane.doe@example.com>
```

PRs with unsigned commits will be automatically blocked by our CI checks.

---

## 2. Clean-Room Architecture & Copyleft Policy

CyberGuard is released under the **Apache License, Version 2.0**.

### ⚠️ Strict Copyleft Prohibition:
1. **Never copy-paste code** from GPLv2, GPLv3, AGPLv3, or SSPL projects into the CyberGuard repository.
2. **Never vendor or statically link** copyleft libraries into the core Go binary.
3. Third-party tools with copyleft licenses (e.g., Masscan, TruffleHog, TheHive) must only be integrated as **isolated external subprocesses** (`pkg/proc/exec.go`) or OCI container sidecars.

Any pull request containing vendored or copyleft code will be closed immediately.

---

## 3. Development Workflow & Standards

### Branch Naming:
- `feat/<short-name>`: New scanner, analyzer, or AI capability
- `fix/<short-name>`: Bug fixes or parser corrections
- `docs/<short-name>`: Documentation, guides, or roadmaps
- `module/<xx-name>`: Daily roadmap module implementations

### Conventional Commit Messages:
All commits must follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:
- `feat:` A new feature or scanner integration
- `fix:` A bug fix or false positive remediation
- `docs:` Documentation only changes
- `refactor:` Code change that neither fixes a bug nor adds a feature
- `test:` Adding missing tests or correcting existing tests
- `chore:` Changes to build process, CI workflows, or dependencies

### Quality & Testing Gates:
1. **Test Coverage:** All new Go packages must include unit tests (`*_test.go`) achieving at least **80% code coverage**:
   ```bash
   go test -race -covermode=atomic -coverprofile=coverage.out ./...
   ```
2. **Go Code Style:** Must pass standard Go linting:
   ```bash
   golangci-lint run ./...
   gofmt -s -w .
   ```
3. **No Weaponized Payloads:** Never commit active exploit payloads, weaponized shellcode, or live attack scripts.

---

## 4. Submitting a Pull Request

1. Fork the CyberGuard repository and clone it locally.
2. Create your feature branch (`git checkout -b feat/my-new-feature`).
3. Make your changes, write tests, and verify tests pass.
4. Commit your changes with a DCO sign-off (`git commit -s -m "feat(...) ..."`).
5. Push to your branch (`git push origin feat/my-new-feature`).
6. Open a Pull Request on GitHub and complete the [PR Template](.github/PULL_REQUEST_TEMPLATE.md) checklist.

# Vulnerable Supply Chain Test Fixture

This directory contains intentionally vulnerable lockfiles for validating the **CyberGuard SCA Engine (`cyberguard-sca`)**.

## Included Vulnerabilities

| Ecosystem | Manifest | Package | Version | Advisory ID | CVE | Severity | Description |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Cargo** | `Cargo.lock` | `chrono` | `0.4.19` | `RUSTSEC-2020-0071` | `CVE-2020-35873` | 🔴 HIGH | Use-after-free in formatting routines |
| **Cargo** | `Cargo.lock` | `tokio` | `1.10.0` | `RUSTSEC-2021-0145` | `CVE-2021-45710` | 🔴 HIGH | Data race in task join handle & mpsc |
| **npm** | `package-lock.json` | `lodash` | `4.17.20` | `GHSA-p6mc-m468-83gw` | `CVE-2020-8203` | 🔴 HIGH | Prototype Pollution via `zipObjectDeep` |
| **npm** | `package-lock.json` | `minimist` | `1.2.5` | `GHSA-xvch-5ox4-994e` | `CVE-2021-44906` | 🔴 CRITICAL | Prototype Pollution via argument keys |

## Verification Commands

### 1. Terminal Audit
```bash
cargo run -- audit tests/fixtures/vulnerable-supply-chain
```

### 2. Export CycloneDX v1.5 SBOM
```bash
cargo run -- audit tests/fixtures/vulnerable-supply-chain --format cyclonedx | jq .
```

### 3. Export SPDX v2.3 SBOM
```bash
cargo run -- audit tests/fixtures/vulnerable-supply-chain --format spdx | jq .
```

### 4. Export OASIS SARIF v2.1.0 Telemetry
```bash
cargo run -- audit tests/fixtures/vulnerable-supply-chain --format sarif | jq .
```

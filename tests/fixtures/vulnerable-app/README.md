# Vulnerable Test Fixture Application

This directory contains intentionally vulnerable code snippets for validating the **CyberGuard SAST Engine**.

## Vulnerability Catalog in this Fixture

| File | Rule ID | Vulnerability Class | Severity | Description |
| :--- | :--- | :--- | :--- | :--- |
| `app.py` | `CG-SQLI-001` | SQL Injection | 🔴 Error | Unparameterized string interpolation in raw SQL query string. |
| `app.py` | `CG-CRYP-001` | Broken Cryptography | 🟡 Warning | Insecure MD5 hashing algorithm in security-sensitive function. |
| `handler.js` | `CG-CMDI-001` | OS Command Injection | 🔴 Error | Shell execution via `child_process.exec` with unescaped argument. |
| `handler.js` | `CG-PATH-001` | Path Traversal | 🟡 Warning | Relative path traversal climb sequence (`../`). |
| `config.py` | `CG-SECR-001` | Hardcoded Secret | 🔴 Error | High-entropy AWS Access Key ID token pattern. |

## Quick Verification
Run CyberGuard against this fixture:
```bash
cargo run -- scan tests/fixtures/vulnerable-app
```
Or export valid OASIS SARIF v2.1.0:
```bash
cargo run -- scan tests/fixtures/vulnerable-app --format sarif | jq .
```

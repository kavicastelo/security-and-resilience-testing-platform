# Context-Aware Injection Fuzzer Engine (`@security-lab/injection-fuzzer`)

## Overview
`@security-lab/injection-fuzzer` is a native Class A offensive security fuzzer for the Security & Resilience Testing Platform. It evaluates endpoints and forms discovered during crawling or direct target inspection, deploying safe non-destructive canary payloads to identify high-impact injection vulnerabilities.

## Vulnerability Detection Capabilities
- **Reflected Cross-Site Scripting (XSS)**:
  - Generates unique randomized canary tokens across HTML body, attribute, and script contexts.
  - Verifies presence of unescaped executable tokens in target HTTP response bodies.
- **SQL Injection (SQLi)**:
  - Error-based SQL dialect probes matching syntax anomalies across PostgreSQL, MySQL, SQLite, and SQL Server.
- **Blind Server-Side Request Forgery (SSRF) with Ephemeral OAST**:
  - Leverages ephemeral Out-of-Band Application Security Testing (OAST) listener (`@security-lab/test-runner/oast-listener`).
  - Emits unique cryptographic correlation tokens in URL parameters, tracking asynchronous HTTP/DNS callbacks.
- **OS Command Injection**:
  - Injects benign echo canaries, verifying command execution output reflections in server responses.

## Target Scope & Safety Guardrails
- Strictly respects target scopes from `@security-lab/domain` via `validateUrlAgainstScope()`.
- Uses safe non-destructive canaries (e.g. `echo seccmd_<token>`, safe boolean SQL logic).
- Accompanies all finding evidence with immutable SHA256 integrity digests conforming to `@security-lab/contracts`.

## Usage
```typescript
import { injectionFuzzerEngine } from '@security-lab/injection-fuzzer';

const result = await injectionFuzzerEngine.execute(
  {
    targetUrl: 'https://staging.example.com',
    options: {
      inventory: crawledInventory,
      fuzzXss: true,
      fuzzSqli: true,
      fuzzSsrf: true,
      fuzzCmd: true,
    },
  },
  context,
);
```

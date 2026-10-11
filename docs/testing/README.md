# Testing Strategy & Quality Assurance

## 1. Overview

Security Lab enforces a rigorous automated testing strategy to guarantee the safety, correctness, and performance of its orchestration pipelines, security boundaries, and domain engines. Testing covers framework-independent unit logic, database-backed integration routes, real Docker container scanners, and adversarial self-security test batteries.

---

## 2. Test Specifications & Frameworks

| Guide / Specification | Path | Focus Area |
| :--- | :--- | :--- |
| **Declarative Test DSL Specification** | [declarative-dsl-spec.md](declarative-dsl-spec.md) | Syntax and architecture for chained multi-step HTTP workflows, request payloads, response extraction, and assertion operators. |
| **OpenAPI Security Contracts & Schema Fuzzing** | [security-contracts.md](security-contracts.md) | Specification ingestion, static contract security rules, and negative deterministic schema fuzzing for APIs. |

---

## 3. Test Suites Hierarchy

The test directory (`tests/`) is organized into four distinct test layers:

### 3.1 Unit Test Suites
Framework-independent unit tests validating pure business logic, mathematical scoring models, and schema validation:
* `@security-lab/domain`: Zod schema validation, IP normalization, and URL boundary checks.
* `@security-lab/evidence`: RFC 8785 canonical JSON serialization and SHA-256 evidence sealing.
* `@security-lab/scoring`: Posture score calculations and severity weighting algorithms.
* `@security-lab/policy-engine`: Policy evaluation, finding waiver expirations, and gate logic.

### 3.2 Integration Test Suites (`tests/integration/`)
Verifies Fastify controller endpoints, database transactions, and engine execution:
* `controller-auth.test.ts`: Centralized Fastify auth guards and constant-time API key comparisons.
* `tenant-isolation.test.ts`: Cross-tenant boundary enforcement and header spoofing rejection.
* `native-engines.test.ts`: Class A in-process engines (headers, CORS, TLS).
* `authentication-engine.test.ts`: JWT algorithm `none` probes, expired token validation, and cookie security.
* `authorization-engine.test.ts`: BOLA/IDOR cross-identity matrix evaluation.
* `security-contracts.test.ts`: OpenAPI contract validation and negative payload mutations.
* `docker-scanners.test.ts`: Real Docker container execution for OWASP ZAP and Aqua Trivy.
* `k6-resilience.test.ts`: Real Grafana k6 container execution with latency metric extraction.
* `cli-standalone.test.ts`: Console CLI offline and remote execution commands.

### 3.3 Defensive Self-Security Tests (`tests/security/`)
Adversarial penetration and boundary test cases targeting the platform itself:
* `scope-propagation-ssrf.test.ts`: Scope tampering, alternative IP encoding attacks, and metadata SSRF probes.
* `result-integrity-idempotency.test.ts`: Result signature forgery and duplicate submission deduplication.
* `distributed-agent-boundaries.test.ts`: Cross-agent job theft, unauthenticated registration rejection, and Docker socket safety.

### 3.4 Browser End-to-End Tests (`tests/e2e/`)
Playwright browser automation testing verifying dashboard triage, real-time SSE event reception, and policy configuration workflows.

---

## 4. Execution Commands

```bash
# Run all unit and mock integration test suites:
pnpm test

# Run real Docker container scanner integration tests (requires Docker daemon):
pnpm test:docker

# Run strict TypeScript typechecking across all monorepo packages:
pnpm run typecheck

# Run ESLint quality checks:
pnpm run lint

# Run tests in watch mode:
pnpm test:watch

# Generate test coverage reports:
pnpm test:coverage
```

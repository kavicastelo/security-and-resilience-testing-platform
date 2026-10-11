# Repository Reality Audit: Security & Resilience Testing Platform

```text
DOCUMENT: docs/product/full-product-gap-analysis/01-repository-reality-audit.md
STATUS: RATIFIED ARCHITECTURE AUDIT
PROJECT: Security & Resilience Testing Platform
EVIDENCE BASELINE: October 2026 Codebase Inspection
```

---

## 1. Executive Summary

This audit establishes the concrete, evidence-based reality of the Security & Resilience Testing Platform repository as of October 2026. Rather than relying on documentation statements, marketing claims, or aspirational architecture designs, this document evaluates the actual code, schemas, APIs, test suites, and operational boundaries implemented in the workspace.

### Summary Assessment
- **Monorepo Architecture**: Clean, modular TypeScript monorepo managed via `pnpm` workspaces and Turborepo references, with strict `tsconfig.base.json` typechecking and ESLint configurations.
- **Current Product Stage**: **Hardened MVP Foundation**. The core execution kernel, native Class A engines, Docker runner sandboxing, target scope validator, cryptographic attestation, database schema, and distributed agent lease state machine are functional, hardened, and verified with 44 automated test suites.
- **Full Product Gap**: The long-term product vision outlined in `docs/product/FULL_PRODUCT_FEATURE_CATALOG.md` (spanning 28 functional feature families, advanced DAST, BOLA matrix, chaos resilience, database adapters, supply chain SBOM, enterprise RBAC, and SaaS control plane) is largely unbuilt. The repository represents approximately 15–20% of the complete product scope described in the feature catalog.

---

## 2. Monorepo Architecture & Workspace Inventory

The monorepo consists of 4 applications (`apps/`), 8 core libraries (`packages/`), and 8 engine specification directories (`engines/`).

### 2.1 Applications (`apps/`)

| Application | Path | Technology Stack | Actual Implementation Reality |
| :--- | :--- | :--- | :--- |
| **Controller** | `apps/controller` | Fastify 5, Drizzle ORM, PostgreSQL driver, SSE stream | **VERIFIED MVP**. Single modular monolith orchestrator. Centralized auth guards, project/target/run/finding/release routes, agent leasing dispatch, and SSE telemetry streaming. |
| **Agent** | `apps/agent` | Node.js 20+, TypeScript, Fastify client, Docker CLI | **VERIFIED MVP**. Standalone daemon polling controller via HTTPS, validating signed scopes, executing test SDK runners, and returning HMAC-signed results. |
| **CLI** | `apps/cli` | Commander 12, Node.js 20+, Chalk, Zod | **VERIFIED MVP**. Dual-mode CLI: remote REST client communicating with controller, and offline standalone runner (`--local`) executing in-process Class A audits without Postgres. |
| **Dashboard** | `apps/dashboard` | React 18, Vite, Tailwind CSS, TanStack Query | **VERIFIED MVP**. Single-page application with dark-mode UI. Views for Overview, Targets, Test Runs, Findings, Policies, Management, and real-time SSE progress streaming. |

### 2.2 Shared Packages (`packages/`)

| Package | Path | Responsibility & Reality |
| :--- | :--- | :--- |
| **`@security-lab/domain`** | `packages/domain` | **Framework-agnostic domain core**. Zod schemas for `TargetScope`, `TestRun`, `Finding`, `Evidence`, `Policy`, `Release`, and `IdentityProfile`. Scope validation utility (`ScopeValidator`) with IP normalization (hex, octal, decimal, IPv6-mapped IPv4) and DNS resolution verification. |
| **`@security-lab/contracts`** | `packages/contracts` | **Cross-boundary DTOs & Reports**. Request/response interfaces for API routes, engine execution inputs/outputs, agent dispatch envelopes, and JUnit/SARIF/HTML report generators. |
| **`@security-lab/config`** | `packages/config` | **Strict environment configuration**. Loads and validates `.env` variables using Zod schemas (`PORT`, `DATABASE_URL`, `SECURITY_LAB_API_KEY`, `AGENT_MASTER_SECRET`). |
| **`@security-lab/logger`** | `packages/logger` | **Structured JSON logging**. Pino-backed logging with correlation IDs (`correlationId`) and automated redaction of sensitive headers (`Authorization`, `Cookie`, `X-Api-Key`). |
| **`@security-lab/evidence`** | `packages/evidence` | **Immutable evidence hashing**. Implements RFC 8785 canonical JSON serialization (`canonicalizeJson`) and SHA-256 evidence fingerprint sealing. |
| **`@security-lab/scoring`** | `packages/scoring` | **Security posture algorithms**. Calculates numeric posture scores (0–100) and letter grades (A–F) based on severity weights, finding counts, and confidence. |
| **`@security-lab/policy-engine`** | `packages/policy-engine` | **Release gate governance**. Evaluates test runs against policies (zero criticals, max high severity count, disallowed categories, p95 latency SLAs, active/expired waivers). |
| **`@security-lab/test-sdk`** | `packages/test-sdk` | **Standardized TestEngine interface & runners**. Defines `TestEngine` and `EngineRegistry`. Houses native engines, `safeFetch` with redirect interception, and `DockerRunner` with CIS security flags. |

### 2.3 Modular Engine Implementations (`packages/test-sdk/src/engines/`)

| Engine ID | Implementation Path | Execution Class | Reality & Verification Evidence |
| :--- | :--- | :--- | :--- |
| `engine-native-headers` | `test-sdk/src/engines/headers.engine.ts` | Class A (In-Process) | **VERIFIED**. Audits CSP, HSTS, X-Frame-Options, X-Content-Type-Options. Uses `safeFetch`. |
| `engine-native-cors` | `test-sdk/src/engines/cors.engine.ts` | Class A (In-Process) | **VERIFIED**. Injects untrusted origins, checks wildcard reflections and credentials. |
| `engine-native-tls` | `test-sdk/src/engines/tls.engine.ts` | Class A (In-Process) | **VERIFIED**. Audits TLS version (1.2+), cert expiry, cipher suites via `node:tls`. |
| `engine-native-rate-limit` | `test-sdk/src/engines/rate-limit.engine.ts` | Class A (In-Process) | **VERIFIED**. Dispatches burst requests, audits 429 status and retry-after headers. |
| `engine-native-auth` | `test-sdk/src/engines/authentication.engine.ts` | Class A (In-Process) | **VERIFIED**. JWT alg `none` tampering, token expiration checks, cookie flags (`HttpOnly`, `Secure`). |
| `engine-native-authorization` | `test-sdk/src/engines/authorization.engine.ts` | Class A (In-Process) | **VERIFIED**. BOLA/IDOR cross-user permutation testing with `IdentityProfile` permissions. |
| `engine-declarative-dsl` | `test-sdk/src/engines/declarative.engine.ts` | Class A (In-Process) | **VERIFIED**. Multi-step HTTP request chaining, variable extraction, assertion operators. |
| `engine-native-contract` | `test-sdk/src/engines/contract.engine.ts` | Class A (In-Process) | **VERIFIED**. OpenAPI 3.0/3.1 static contract checks and negative schema fuzzing. |
| `engine-zap` | `test-sdk/src/engines/zap.engine.ts` | Class B (Container) | **VERIFIED**. Executes real `ghcr.io/zaproxy/zaproxy` container with scratch volume transport. |
| `engine-trivy` | `test-sdk/src/engines/trivy.engine.ts` | Class B (Container) | **VERIFIED**. Executes real `aquasec/trivy` container targeting images/filesystems. |
| `engine-k6` | `test-sdk/src/engines/k6.engine.ts` | Class C (Heavy Worker) | **VERIFIED**. Generates k6 ES module scripts, runs `grafana/k6`, extracts p95/p99 summary metrics. |

---

## 3. Database Schema & Persistence Reality

Database persistence is implemented using **PostgreSQL 16+** and managed through **Drizzle ORM** (`apps/controller/src/services/db/schema.ts`). Migrations reside in `infrastructure/postgres/migrations/` (11 migrations: `0000` through `0010`).

### 3.1 Implemented Relational Tables

1. **`tenants`**: Multi-tenant partitions (`id`, `name`, `slug`, `plan`, `settings`).
2. **`projects`**: Project containers (`id`, `tenant_id`, `name`, `description`).
3. **`environments`**: Execution environments (`id`, `project_id`, `name`, `type`, `variables`, `headers`).
4. **`targets`**: Tested assets (`id`, `tenant_id`, `project_id`, `name`, `base_url`, `scope`).
5. **`test_runs`**: Testing sessions (`id`, `project_id`, `target_id`, `environment_id`, `profile_id`, `status`, `summary`).
6. **`test_executions`**: Sub-engine execution tasks (`id`, `test_run_id`, `engine_id`, `execution_class`, `status`, `raw_result`).
7. **`evidence_records`**: Forensic evidence entries (`id`, `test_run_id`, `execution_id`, `request`, `response`, `immutable_hash`).
8. **`findings`**: Normalized vulnerabilities (`id`, `tenant_id`, `fingerprint`, `severity`, `confidence`, `status`, `occurrence_count`).
9. **`metrics`**: Quantitative telemetry (`id`, `test_run_id`, `execution_id`, `name`, `value`, `unit`, `tags`).
10. **`policies`**: Gate policies (`id`, `tenant_id`, `name`, `rules`, `required_profiles`, `waivers`).
11. **`releases`**: Sealed deployment verdicts (`id`, `project_id`, `test_run_id`, `policy_id`, `decision`, `evaluator_hash`).
12. **`test_definitions`**: Reusable DSL specifications (`id`, `project_id`, `name`, `content_yaml`, `parsed_content`).
13. **`reports`**: Persisted compliance reports (`id`, `test_run_id`, `format`, `filename`, `content`).
14. **`artifacts`**: File storage metadata (`id`, `test_run_id`, `execution_id`, `name`, `sha256`, `storage_path`).
15. **`identity_profiles`**: Synthetic test identities (`id`, `project_id`, `name`, `role`, `headers`).
16. **`credentials`**: Encrypted credentials vault (`id`, `project_id`, `type`, `encrypted_value`, `iv`, `auth_tag`).
17. **`tenant_enrollment_keys`**: Agent enrollment pre-shared keys (`id`, `tenant_id`, `key_hash`, `max_uses`, `expires_at`).
18. **`agents`**: Registered execution workers (`id`, `tenant_id`, `name`, `token_hash`, `capabilities`, `tags`, `status`).
19. **`agent_jobs`**: Distributed execution queue (`id`, `agent_id`, `tenant_id`, `status`, `lease_id`, `lease_expires_at`, `payload`).
20. **`agent_audit_events`**: Append-only security audit log (`id`, `tenant_id`, `agent_id`, `event_type`, `actor_id`).

### 3.2 Implemented Database Constraints & Invariants
- Foreign keys enforce cascading deletes or restrictions.
- Append-only trigger in PostgreSQL prevents modifications or deletes on `evidence_records` (`prevent_evidence_tamper`).
- B-Tree indexes exist on query hot-paths (tenant IDs, fingerprints, run statuses, lease expirations).
- Row-level lock claiming via `FOR UPDATE SKIP LOCKED` in `agent_jobs` polling query.

---

## 4. End-to-End Critical Execution Paths

### Path 1: Local In-Process Audit via CLI (`security-lab run --local`)
1. User invokes `security-lab run --local --target http://localhost:8080 -e headers cors`.
2. CLI validates target URL against `.securitylab.yaml` or generates a dynamic ephemeral `TargetScope`.
3. Standalone runner initializes `EngineRegistry` directly in-process without contacting the Fastify daemon or PostgreSQL.
4. Outbound HTTP requests pass through `safeFetch`:
   - Hostname resolved to IP; checked against private/metadata CIDRs.
   - HTTP 3xx redirects intercepted and re-validated against scope before following.
5. Findings and metrics collected in memory; evaluated against local policy thresholds.
6. Emits exit code (0 for pass, 1 for block) and exports SARIF/JUnit to disk.
- **Status**: `VERIFIED` via `tests/integration/cli-standalone.test.ts`.

### Path 2: Controller-Orchestrated Test Run (REST / Dashboard)
1. Dashboard or CI dispatches `POST /api/v1/test-runs` with `targetId` and `profileId`.
2. Controller `onRequest` hook authenticates request via `SECURITY_LAB_API_KEY` or session header.
3. Controller verifies target exists, validates scope, and creates `test_runs` record in state `'queued'`.
4. `runnerService.startTestRun` enqueues job or launches in-process worker.
5. Engines execute, stream progress via SSE (`/api/v1/stream`), and output normalized findings.
6. Findings inserted into PostgreSQL with collision-resistant SHA-256 fingerprints; finding lifecycle (`open`, `resolved`, `regressed`) reconciled.
7. Evaluator executes `PolicyEngine.evaluate()`, cryptographically seals verdict in `releases` table, and marks test run `'completed'`.
- **Status**: `VERIFIED` via `tests/integration/test-run-execution.test.ts` and `tests/integration/telemetry-triage.test.ts`.

### Path 3: Distributed Execution via Remote Agent (`apps/agent`)
1. Agent daemon starts in private network; authenticates with controller using `AGENT_TOKEN` (`agt_sec_...`).
2. Agent polls `POST /api/v1/agents/poll` declaring its capabilities and tags.
3. Controller executes atomic `SELECT FOR UPDATE SKIP LOCKED` on `agent_jobs`, leases job, and returns `AgentJobDispatch` payload with signed scope and ephemeral `jobDispatchSecret`.
4. Agent verifies scope signature HMAC, initializes `AgentWorker`, executes engines against private target, and renews lease via `/heartbeat` every 15s.
5. Agent computes RFC 8785 canonical JSON hash of findings and executes HMAC result attestation.
6. Agent posts completion to `POST /api/v1/agents/jobs/:id/complete`. Controller verifies HMAC signature, checks holding lease, and persists findings within an ACID transaction.
- **Status**: `VERIFIED` via `tests/security/distributed-agent-boundaries.test.ts` and `tests/security/concurrency-job-leasing.test.ts`.

---

## 5. Security-Sensitive Boundaries & Hardening Status

| Security Boundary | Specification | Implementation Reality | Status |
| :--- | :--- | :--- | :--- |
| **SSRF & Network Boundary** | `docs/security/security-boundary.md` | Strict HTTP/HTTPS scheme, IP canonicalization (decimal/hex/octal/IPv6-mapped), DNS verification (`validateUrlWithDns`), redirect hop re-validation via `safeFetch`. | `VERIFIED` |
| **Container Sandboxing** | `docs/security/security-boundary.md` | `DockerRunner` injects `--cap-drop=ALL`, `--security-opt=no-new-privileges:true`, `--user 10001:10001`, `--read-only`, and confines mounts to `os.tmpdir()` scratch directories. | `VERIFIED` |
| **Docker Socket Prohibition** | `docs/security/security-model.md` | Manifests (`infrastructure/k8s/agent.yaml`) have zero `/var/run/docker.sock` mounts. AST parser in test suite enforces prohibition. | `VERIFIED` |
| **Tenant Isolation** | `docs/security/security-model.md` | Controller rejects client `x-tenant-id` headers; tenant context derived from validated tokens. Cross-tenant job operations rejected with 403. | `VERIFIED` |
| **Result Attestation** | `docs/security/security-model.md` | Agent result payloads signed with HMAC-SHA256 using ephemeral dispatch secrets; verified with `timingSafeEqual`. Duplicate completions deduplicated. | `VERIFIED` |
| **Secrets in Logs** | Architecture Rule 17 | Pino logger redacts `Authorization`, `Cookie`, `X-Api-Key`, `token`, `secret`. Reproduction curl commands redact bearer tokens. | `VERIFIED` |

---

## 6. Demonstrated Limitations & Technical Debt

Despite the hardened MVP baseline, significant architectural limitations exist when compared to the Full Feature Catalog:

1. **Absence of User Authentication & Multi-User RBAC**:
   - Currently, API authentication relies on static pre-shared keys (`SECURITY_LAB_API_KEY`, `SECURITY_LAB_ADMIN_KEY`).
   - There are no user accounts, passwords, sessions, JWTs for human operators, or role permissions (Admin vs. Developer vs. Viewer).
2. **Missing Active Web Application Scanner (DAST) Crawler**:
   - The platform has passive header checks and containerized ZAP/Trivy, but lacks a platform-native crawler capable of discovering forms, client-side routes, and executing active reflected/stored XSS or SQLi probes.
3. **No Dynamic Plugin Packaging**:
   - Engines are hardcoded inside `packages/test-sdk/src/engines/`. There is no dynamic `.tar.gz` or `.zip` plugin loader, no out-of-tree plugin SDK package, and no plugin certification harness.
4. **Synthetic BOLA Matrix Limited to Single-Host Mock Scenarios**:
   - The authorization engine executes cross-identity checks, but test scenarios must be declared statically. There is no automated resource discovery or dynamic permission matrix inference.
5. **Absence of Chaos and Controlled Failure Engines**:
   - There are no adapters for network latency injection (e.g. Toxiproxy, Chaos Mesh), container restarts, or database connection pool starvation.
6. **No Direct Database Driver Testing**:
   - No direct database protocol engines (testing PostgreSQL, MySQL, Redis, Mongo connection timeouts or privilege separation).
7. **Single-Node In-Memory Rate Limiting**:
   - Controller rate limiting uses an in-memory sliding window store (`rate-limit-store.ts`). In a multi-replica controller cluster, rate counters will not synchronize without Redis.
8. **No PDF Exporting or Live Compliance Framework Mapping**:
   - Reports export to SARIF, JUnit, and HTML, but there is no PDF report generator and no direct mapping to NIST, ISO 27001, or SOC 2 controls.

---

## 7. Audit Evidence Matrix (Verified File Paths & Symbols)

| Functional Subsystem | Primary Code Path | Verification Suite | Reality Verdict |
| :--- | :--- | :--- | :--- |
| **Scope Validator** | `packages/domain/src/target/scope-validator.ts` | `tests/integration/scope-validator.test.ts` | `VERIFIED` |
| **safeFetch Dispatcher** | `packages/test-sdk/src/http/safe-fetch.ts` | `tests/security/scope-propagation-ssrf.test.ts` | `VERIFIED` |
| **Docker Policy & Runner** | `packages/test-sdk/src/runners/` | `tests/integration/docker-scanners.test.ts` | `VERIFIED` |
| **Engine Registry** | `packages/test-sdk/src/registry.ts` | `tests/integration/test-run-execution.test.ts` | `VERIFIED` |
| **Authentication Engine** | `packages/test-sdk/src/engines/authentication.engine.ts` | `tests/integration/authentication-engine.test.ts` | `VERIFIED` |
| **Authorization Engine** | `packages/test-sdk/src/engines/authorization.engine.ts` | `tests/integration/authorization-engine.test.ts` | `VERIFIED` |
| **Declarative DSL v2** | `packages/test-sdk/src/engines/declarative.engine.ts` | `tests/integration/dsl-v2.test.ts` | `VERIFIED` |
| **OpenAPI Contract Engine** | `packages/test-sdk/src/engines/contract.engine.ts` | `tests/integration/security-contracts.test.ts` | `VERIFIED` |
| **k6 Resilience Runner** | `packages/test-sdk/src/engines/k6.engine.ts` | `tests/integration/k6-resilience.test.ts` | `VERIFIED` |
| **Evidence & Hashing** | `packages/evidence/src/canonical.ts` | `packages/evidence/tests/attestation.test.ts` | `VERIFIED` |
| **Policy Engine** | `packages/policy-engine/src/evaluator.ts` | `tests/integration/release-gating-and-reports.test.ts` | `VERIFIED` |
| **Agent Leasing FSM** | `apps/controller/src/services/agent-dispatcher.service.ts`| `tests/security/concurrency-job-leasing.test.ts` | `VERIFIED` |
| **Agent Result Integrity**| `apps/agent/src/worker.ts` | `tests/security/result-integrity-idempotency.test.ts` | `VERIFIED` |
| **Console CLI Offline** | `apps/cli/src/runner/standalone-runner.ts` | `tests/integration/cli-standalone.test.ts` | `VERIFIED` |
| **Dashboard SSE Stream** | `apps/dashboard/src/components/LiveRunMonitor.tsx` | `tests/integration/telemetry-triage.test.ts` | `VERIFIED` |

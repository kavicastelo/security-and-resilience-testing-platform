# Current-State Architecture Map

**Project**: Security Lab — Application Security & Resilience Testing Platform  
**Repository**: `https://github.com/kavicastelo/security-and-resilience-testing-platform`  
**Audit Baseline Date**: October 2026  
**Auditor**: Principal Security & System Architecture Review  

---

## 1. System Overview & Product Reality

Security Lab is organized as a **TypeScript monorepo** managed with `pnpm` and Turborepo/pnpm-workspaces. It aims to provide local-first, contract-driven security QA and release-gating for web applications and APIs.

### Current vs. Target Distinction

| Dimension | Current Implementation (Reality) | Target Architecture (Goal) |
| :--- | :--- | :--- |
| **Execution Classes** | Class A is in-process; Class B (ZAP/Trivy) runs via `docker run` but fails over silently to hardcoded mock JSON; Class C (k6) is an in-process JavaScript `fetch()` loop labeled as k6. | Truly decoupled execution: Class A in-process; Class B in sandboxed Docker runners with host-volume artifact transport; Class C in isolated worker containers executing real Grafana k6 scripts. |
| **Engine Registry** | Hardcoded `if/else` and array instantiation in `apps/controller/src/services/runner.service.ts`. | Pluggable, dynamic `EngineRegistry` with capability discovery, lifecycle hooks, versioning, and scope enforcement. |
| **Security Boundary** | String-based hostname and port check in `validateUrlAgainstScope`. No DNS resolution, no DNS rebinding defenses, no IP normalization (octal/hex/decimal/IPv4-mapped IPv6), and native engines follow HTTP redirects without re-validation. | Comprehensive SSRF gateway with socket pinning, IP address normalization, DNS rebinding prevention, redirect interception, and target scope re-checks on every hop. |
| **Container Sandboxing** | `docker run --rm` with CPU/memory limits, but missing `--security-opt=no-new-privileges`, `--cap-drop=ALL`, `--user`, `--read-only`, image allowlisting, or volume mount path restrictions. | Hardened OCI container sandbox with zero new privileges, dropped capabilities, unprivileged UID/GID, read-only rootfs, explicit image digest pinning, and strictly constrained volume mounts. |
| **DSL & Declarative Testing** | Simple single-request assertions with `equals`, `contains`, `matches_regex`. No request bodies, no path variables, no parameter extraction, no multi-step chains. | Full declarative test DSL v2 supporting multi-step request chaining, variable extraction, body payloads, auth contexts, and negative security contracts. |
| **Authentication Testing** | Bearer and API Key header injection in `DeclarativeTestEngine`. `basic` and `oauth2` are enum values only with zero handling. | Comprehensive auth testing suite: JWT security auditing, cookie/session flag audits, OAuth2 token flows, credential profile vaults. |
| **Authorization / BOLA** | Domain placeholders and documentation READMEs only (`engines/authorization/README.md`). Zero runnable code. | Full BOLA/IDOR matrix testing engine with identity profiles, permission matrix evaluations, and cross-tenant privilege escalation audits. |
| **Data Persistence** | PostgreSQL via Drizzle ORM. Missing tables for definitions, reports, artifacts, credentials, identities. Missing indexes in Drizzle schema. | Full relational schema with indexes, finding lifecycle tracking (`open`, `resolved`, `regressed`), append-only forensic audit triggers, and artifact metadata. |
| **Evidence Immutability** | Cryptographic hash computed via `JSON.stringify` (non-canonical key order) and in-memory `Object.freeze`. Database allows arbitrary updates. | Canonical JSON serialization (RFC 8785) with PostgreSQL append-only triggers preventing updates or deletions of evidence records. |
| **Distributed Agent Execution** | `apps/agent` daemon polls jobs and reports findings via `agentDispatcherService`. Polling is non-atomic; jobs lack leases, timeouts, and result signatures. | Cryptographically attested distributed execution: atomic `SKIP LOCKED` leasing, watchdog reapers, HMAC result signatures, and bidirectional cancellation. |
| **Multi-Tenancy & Trust** | Tenant tables and foreign keys exist (`0006_saas_multi_tenancy.sql`), but registration is unauthenticated and agent completion endpoints trust any agent token. | Two-tier key hierarchy (TEK), contextual tenant derivation, and strict route-level cross-tenant barriers. |

---

## 2. Runtime Architecture & Package Dependency Graph

```
                               ┌────────────────────────────────┐
                               │       apps/dashboard           │
                               │  (React 18 / Vite / Tailwind)  │
                               └───────────────┬────────────────┘
                                               │ HTTP / REST
                                               ▼
┌──────────────────────────────┐       ┌────────────────────────────────┐
│          apps/cli            │──────▶│       apps/controller          │
│    (Commander / Node.js)     │       │   (Fastify 5 / TypeScript)     │
└──────────────┬───────────────┘       └───────┬──────────────┬─────────┘
               │                               │              │
               │ REST                          │ Imports      │ SQL Queries
               ▼                               ▼              ▼
┌──────────────────────────────┐       ┌───────────────┐ ┌──────────────┐
│      packages/contracts      │       │packages/test- │ │  PostgreSQL  │
│  (DTOs, Reports, Enums)      │       │     sdk       │ │  (Docker /   │
└──────────────┬───────────────┘       └───────┬───────┘ │  Localhost)  │
               │                               │         └──────────────┘
               ▼                               ▼
┌──────────────────────────────┐       ┌───────────────┐
│       packages/domain        │       │packages/policy│
│   (Entities, Zod Schemas,    │       │    -engine    │
│    Normalizers, Validators)  │       └───────┬───────┘
└──────────────┬───────────────┘               │
               │                               ▼
┌──────────────┴───────────────┐       ┌───────────────┐
│      packages/evidence       │       │packages/score │
│ (SHA-256 Hashing, Freeze)    │       └───────────────┘
└──────────────────────────────┘
```

### Monorepo Workspaces & Package Details

1. **`apps/controller`**: Fastify REST API. Houses routes (`projects`, `targets`, `test-runs`, `findings`, `policies`, `releases`, `reports`), services, and Drizzle schema.
2. **`apps/dashboard`**: Single-page React application with Tailwind CSS and TanStack Query. Talks to controller at `http://localhost:4000`.
3. **`apps/cli`**: Commander CLI with commands: `project`, `target`, `test`, `scan`, `load`, `report`, `gate`, `version`.
4. **`packages/domain`**: Pure TypeScript domain models, Zod validation schemas (`TargetSchema`, `TestRunSchema`, `FindingSchema`), scope validator, and normalizers (`normalizeZapAlerts`, `normalizeTrivyResults`).
5. **`packages/contracts`**: Cross-boundary DTOs, API request/response shapes, and report generators (`generateJUnitXml`, `generateSarifReport`, `generateHtmlExecutiveReport`).
6. **`packages/test-sdk`**: Core `TestEngine` interface, `DockerRunner` wrapper, and built-in engines (`HeadersSecurityEngine`, `CorsSecurityEngine`, `TlsSecurityEngine`, `DeclarativeTestEngine`, `ZapScannerEngine`, `TrivyScannerEngine`, `K6ResilienceEngine`, `RateLimitResilienceEngine`).
7. **`packages/evidence`**: In-memory evidence hashing and factory functions.
8. **`packages/policy-engine`**: Evaluates `Policy` rules against `Finding[]` and `Metric[]`.
9. **`packages/scoring`**: Computes weighted risk posture scores (0–100, grades A–F).
10. **`packages/logger`**: Structured JSON logger using Pino with correlation ID propagation.
11. **`packages/config`**: Validates environment variables using Zod.

---

## 3. Execution Lifecycle (Current Flow)

```
User (CLI / Dashboard / CI)
   │
   ▼ POST /api/v1/test-runs/:id/execute
TestRunnerService.executeTestRun()
   │
   ├─▶ 1. Fetch TestRun & Target from Postgres
   ├─▶ 2. Run validateUrlAgainstScope(target.baseUrl, target.scope)
   │       └─ If invalid: mark TestRun failed with scope error; return immediately
   ├─▶ 3. Resolve engines based on profileId or options.engineIds (Hardcoded list)
   ├─▶ 4. For each engine (Sequential loop):
   │       ├─ Insert test_executions row (status: 'running')
   │       ├─ engine.validate(input)
   │       ├─ await engine.execute(input, context)
   │       ├─ For each raw finding:
   │       │    ├─ Compute sha256 fingerprint (engineId:targetId:title:category:severity)
   │       │    ├─ If rawFinding.evidence: compute hash, insert evidence_records row
   │       │    └─ Insert findings row
   │       ├─ For each metric: insert metrics row
   │       └─ Update test_executions row (status: 'completed' | 'failed', durationMs, rawResult)
   ├─▶ 5. Aggregate summary counts (critical, high, medium, low, info)
   └─▶ 6. Update test_runs row (status: 'completed' | 'failed', summary)
```

---

## 4. Database Schema & Entity Relationships

The PostgreSQL database (managed via Drizzle ORM and forward-only SQL migrations in `infrastructure/postgres/migrations/`) contains 15 tables with relational indexing, append-only forensic audit triggers, and vulnerability lifecycle tracking:

```
projects (id PK, name UNIQUE)
   │
   ├──▶ environments (id PK, project_id FK, name, variables, headers)
   │
   ├──▶ targets (id PK, project_id FK, name, base_url, scope JSONB)
   │       │
   │       ├──▶ test_definitions (id PK, project_id FK, target_id FK, name, version, spec JSONB/YAML)
   │       ├──▶ identity_profiles (id PK, project_id FK, target_id FK, persona_name, role, auth_type, headers JSONB)
   │       ├──▶ credentials (id PK, project_id FK, target_id FK, name, cred_type, encrypted_payload, iv, tag)
   │       │
   │       ▼
   ├──▶ test_runs (id PK, project_id FK, target_id FK, environment_id FK, profile_id, status, summary JSONB)
   │       │
   │       ├──▶ test_executions (id PK, test_run_id FK, engine_id, execution_class, status, duration_ms, raw_result JSONB)
   │       │       │
   │       │       ├──▶ evidence_records [APPEND-ONLY TRIGGER PROTECTED]
   │       │       │    (id PK, test_run_id FK, execution_id FK, request JSONB, response JSONB, immutable_hash)
   │       │       │    Trigger: prevent_evidence_tamper() aborts any UPDATE or DELETE statement.
   │       │       │
   │       │       └──▶ findings [DEDUPLICATED & REGRESSION INTELLIGENCE]
   │       │            (id PK, fingerprint, title, severity, status, occurrence_count, first_detected_at,
   │       │             last_detected_at, fixed_at, fixed_in_run_id, test_run_id FK, execution_id FK, target_id FK)
   │       │
   │       ├──▶ reports (id PK, test_run_id FK, project_id FK, report_type, format, content, generated_at)
   │       ├──▶ artifacts (id PK, test_run_id FK, execution_id FK, name, artifact_type, storage_path, sha256_hash, byte_size)
   │       └──▶ metrics (id PK, test_run_id FK, execution_id FK, name, value, unit, tags JSONB)
   │
   ├──▶ releases (id PK, project_id FK, test_run_id FK, policy_id FK, decision, reason, evaluated_at)
   │
   └──▶ policies (id PK, name, rules JSONB, is_default)
```

### Hardened Database Features (Phase 10):
- **First-Class Persistence Entities**: `test_definitions`, `reports`, `artifacts`, `identity_profiles`, and `credentials` are fully relational tables with cascading foreign keys and Drizzle ORM schemas.
- **Relational Indexing**: All foreign keys and query columns (`testRunId`, `targetId`, `fingerprint`, `status`, `severity`, `fixedInRunId`) feature explicit B-Tree indexes.
- **Forensic Evidence Immutability**: PostgreSQL trigger `trg_evidence_immutable` executes `prevent_evidence_tamper()` on `evidence_records`, raising `EVIDENCE_TAMPER_PROTECTION` (SQLSTATE 55000) on any attempted `UPDATE` or `DELETE`.
- **Deterministic Evidence Hashing**: RFC 8785 canonical JSON serialization ensures identical SHA-256 hashes across varying key ordering.
- **Fingerprint Collision Resistance**: Hardened formula `SHA-256(targetId : engineId : category : ruleOrCweId : endpointPath : (parameterName || ''))` eliminates endpoint and parameter collisions.
- **Automated Regression Intelligence**: Lifecycle state machine (`open`, `resolved`, `regressed`, `false_positive`, `ignored`) with automated reconciliation (`reconcileTestRunFindings`) resolving un-detected findings and tracking recurrence counters (`occurrenceCount`).

---

## 5. Security Boundary & Attack Surface Analysis

The platform is designed to test enterprise applications, but its current security boundary exhibits several critical weaknesses:

1. **Target Scope Blindspots**:
   - `validateUrlAgainstScope()` checks strings only. It does not perform DNS resolution, leaving the system vulnerable to DNS rebinding attacks.
   - Prohibited metadata IPs (`CLOUD_METADATA_IPS`) only includes `169.254.169.254`, `fd00:ec2::254`, and `metadata.google.internal`. It fails to detect IPv4-mapped IPv6 (`::ffff:169.254.169.254`), alternative representations (hex `0xa9fea9fe`, octal `0251.0772.0251.0772`, integer `2852039166`), or AWS IPv6 metadata (`[fd00:ec2::254]`).
   - Private RFC 1918 networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) and loopbacks (`127.0.0.1`, `[::1]`) are not systematically blocked unless explicitly omitted from `allowedHosts`.
2. **HTTP Redirect SSRF Bypass**:
   - Node.js native `fetch()` in `headers.engine.ts`, `cors.engine.ts`, `declarative.engine.ts`, `k6.engine.ts`, and `rate-limit.engine.ts` uses default `redirect: 'follow'`.
   - An authorized target at `http://staging.example.com` can respond with `302 Found` and `Location: http://169.254.169.254/latest/meta-data` or `http://127.0.0.1:5432`, and the runtime will follow the redirect without re-validating against the target scope.
3. **Declarative Engine Path SSRF**:
   - In `DeclarativeTestEngine`, line 126 allows `testSpec.path` to be an absolute URL (`http://...`). This URL is fetched directly without any scope boundary check.
4. **Container Escape & Privilege Escalation Surface**:
   - `DockerRunner` accepts arbitrary volume mounts, images, and network settings from engine options without validation.
   - No `--security-opt=no-new-privileges:true`, `--cap-drop=ALL`, or non-root user enforcement.

---

## 6. CI/CD Architecture Flow

Two GitHub Actions workflows exist:
1. **`.github/workflows/ci.yml`**: Validates monorepo integrity on push/PR (`pnpm run typecheck`, `pnpm run lint`, `pnpm run test`, `docker compose config`).
2. **`.github/workflows/security-gate.yml`**: Spins up Postgres service container, applies migrations via raw `psql`, starts the controller, creates project and target, runs a test run, evaluates policy via CLI (`apps/cli/dist/index.js gate evaluate`), generates JUnit/SARIF/HTML reports, and uploads SARIF to GitHub Code Scanning.
3. **`.gitlab-ci.yml`**: Parallel pipeline definition for GitLab CI.

---

---

## 7. Distributed Execution & Multi-Tenancy Reality (Phase 15 Baseline)

With the introduction of Phase 15, the monorepo introduced `apps/agent` and SaaS multi-tenancy (`0006_saas_multi_tenancy.sql`). Forensic audit reveals critical trust boundary gaps:
1. **Agent Registration**: `POST /api/v1/agents/register` allows unauthenticated callers to enroll under arbitrary tenant IDs by passing `x-tenant-id`.
2. **Cross-Tenant Completion**: Endpoints `/jobs/:jobId/progress`, `/complete`, and `/fail` do not assert that the calling agent owns the job or shares the job's tenant.
3. **Non-Atomic Polling**: Polling uses an unprotected `SELECT` followed by loop `UPDATE`, creating double-claim race conditions.
4. **Missing Leases**: Disconnected agents leave jobs in `'dispatched'` indefinitely without timeouts or reapers.
5. **Docker Socket Exposure**: Deployment manifests mount `/var/run/docker.sock` into the agent container, violating Rule 13.
6. **Cancellation Failure**: Controller cancellations do not propagate to remote agents, and agent completions overwrite user cancellations.

---

## 8. Current Architecture Summary Verdict

The foundation is clean, modular, and well-typed. The TypeScript architecture, Drizzle schemas, Fastify controller, React dashboard, and CLI interfaces establish a strong pattern. However, the distributed execution layer currently relies heavily on unauthenticated registration, header-based tenant trust, unsigned result payloads, and missing concurrency locking. Phase 16 establishes the hardened trust boundary and secure execution plane.

# Comprehensive Architecture & Security Gap Analysis

**Project**: Security Lab — Application Security & Resilience Testing Platform  
**Document**: `docs/architecture/gap-analysis.md`  
**Baseline Date**: October 2026  
**Auditor**: Principal Security Architect, Staff Backend Architect, DevSecOps Architect  

---

## 1. Real Implementation Inventory Matrix

This inventory audits every claimed capability in the repository against verifiable code evidence.

States used:
* `VERIFIED`: Implemented, tested, safe, and meets architectural requirements.
* `IMPLEMENTED`: Implemented and functional, but has minor rough edges or gaps.
* `IMPLEMENTED_BUT_UNSAFE`: Code runs, but introduces serious security risks (e.g. SSRF, container escape, injection).
* `IMPLEMENTED_BUT_INCOMPLETE`: Implemented partially or superficially; core behavior missing, broken, or substituted.
* `PARTIALLY_IMPLEMENTED`: Scaffolding exists with partial logic, but cannot be used end-to-end.
* `SCAFFOLDED`: Interfaces, schemas, or stubs exist without functional business logic.
* `NOT_IMPLEMENTED`: Only documented in READMEs/ADRs or completely missing.

| Capability | Location | Status | Evidence | Arch Quality | Security Risk | Test Coverage | Dependencies | Next Action |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Monorepo & Type System** | Root, `packages/*`, `apps/*` | `VERIFIED` | `pnpm` workspaces, strict `tsconfig.base.json`, `tsc -b` passes cleanly, ESLint passes. | High | Low | High | Node.js 22, pnpm 9/12 | Maintain workspace boundaries |
| **Domain Entities & Zod Schemas** | `packages/domain` | `VERIFIED` | Comprehensive Zod schemas for Target, TestRun, Finding, Policy, Release, Execution. | High | Low | High | Zod | Add schemas for IdentityProfile & TestDefinition v2 |
| **Target Scope Validator** | `packages/domain/src/target/scope-validator.ts` | `IMPLEMENTED_BUT_UNSAFE` | Validates host string, port number, excluded paths string, and testing flags. | Moderate | **CRITICAL** | Moderate | URL parsing | Implement IP normalization, DNS resolution, socket pinning, redirect interception |
| **Class A Headers Engine** | `packages/test-sdk/src/engines/headers.engine.ts` | `IMPLEMENTED_BUT_UNSAFE` | Audits HSTS, CSP, X-Frame-Options, X-Content-Type-Options, server banner. | Good | **HIGH** | Good | Native fetch | Disable default redirect following; validate redirect targets against scope |
| **Class A CORS Engine** | `packages/test-sdk/src/engines/cors.engine.ts` | `IMPLEMENTED_BUT_UNSAFE` | Sends OPTIONS with untrusted origin; audits reflection and credentials. | Good | **HIGH** | Good | Native fetch | Prevent redirect following; enforce scope check on any preflight redirection |
| **Class A TLS Engine** | `packages/test-sdk/src/engines/tls.engine.ts` | `IMPLEMENTED_BUT_UNSAFE` | Connects via `tls.connect`; checks protocol version, cert expiration, cipher. | Good | **HIGH** | Good | node:tls | Perform DNS pinning to prevent DNS rebinding attacks against internal hosts |
| **Declarative Test Engine (DSL)** | `packages/test-sdk/src/engines/declarative.engine.ts` | `IMPLEMENTED_BUT_UNSAFE` | Parses YAML definitions; evaluates status codes and field assertions. | Moderate | **CRITICAL** | Good | YAML parser | Validate absolute URLs in `testSpec.path` against scope; support request bodies & chaining |
| **Docker Runner** | `packages/test-sdk/src/runners/docker.runner.ts` | `IMPLEMENTED_BUT_UNSAFE` | Spawns `docker run --rm` with CPU/memory limits. Silent fallback to mock. | Fragile | **CRITICAL** | Low | Docker CLI | Add security opts (`no-new-privileges`, `cap-drop`), restrict volume paths, image allowlist |
| **OWASP ZAP Scanner (Class B)** | `packages/test-sdk/src/engines/zap.engine.ts` | `IMPLEMENTED_BUT_INCOMPLETE` | Dispatches docker command, but parses stdout while ZAP writes to disk file; always falls back to hardcoded mock. | Poor | **HIGH** | Low (mock only) | Docker, ZAP container | Add host volume mount for report exchange; parse real `report.json`; remove silent mock fallback |
| **Aqua Trivy Scanner (Class B)** | `packages/test-sdk/src/engines/trivy.engine.ts` | `IMPLEMENTED_BUT_INCOMPLETE` | Runs `trivy fs .` inside Trivy image without volume mounting target codebase; ignores target URL; silent mock fallback. | Poor | **HIGH** | Low (mock only) | Docker, Trivy container | Mount target codebase or scan target image; enforce policy failures on critical CVEs |
| **k6 Resilience Engine (Class C)** | `packages/test-sdk/src/engines/k6.engine.ts` | `IMPLEMENTED_BUT_INCOMPLETE` | Does NOT run k6. Runs an in-process JavaScript `fetch()` loop in Node.js event loop. | Misleading | **HIGH** | Moderate | Native fetch | Replace fetch loop with real `grafana/k6` container execution with script generation |
| **Rate Limit Engine (Class C/A)** | `packages/test-sdk/src/engines/rate-limit.engine.ts` | `IMPLEMENTED_BUT_UNSAFE` | Sends burst of requests; checks 429 status and X-RateLimit headers. | Moderate | **HIGH** | Good | Native fetch | Enforce redirect interception; clamp burst requests to target limits |
| **Finding Normalization** | `packages/domain/src/normalizers/` | `VERIFIED` | Normalizes ZAP and Trivy alerts into canonical `NormalizedFinding`. | Good | Low | High | Pure functions | Expand normalizers for k6 and SARIF |
| **Forensic Evidence & Hashing** | `packages/evidence` | `IMPLEMENTED_BUT_INCOMPLETE` | Hashes evidence payload with SHA-256 and freezes in memory. Unstable key ordering in `JSON.stringify`. | Moderate | Moderate | Moderate | node:crypto | Use RFC 8785 canonical JSON; add PostgreSQL append-only triggers |
| **Controller Orchestration Service** | `apps/controller/src/services/runner.service.ts` | `PARTIALLY_IMPLEMENTED` | Hardcoded engine registry; synchronous sequential execution blocks Fastify event loop; unexposed cancellation. | Poor | **HIGH** | Moderate | Fastify, Drizzle | Build dynamic `EngineRegistry`; decouple execution to background job queue; wire cancellation |
| **PostgreSQL Schema & Migrations** | `apps/controller/src/services/db/schema.ts` | `PARTIALLY_IMPLEMENTED` | Tables for projects, targets, environments, test_runs, executions, findings, metrics, policies, releases. | Moderate | Low | High | Drizzle, Postgres | Add missing tables (`test_definitions`, `reports`, `artifacts`), indexes, and lifecycle fields |
| **Finding Fingerprinting & Lifecycle** | `apps/controller/src/services/findings.service.ts` | `IMPLEMENTED_BUT_INCOMPLETE` | Simple hash without endpoint/param causes collisions. Blind insert on every run without lifecycle tracking. | Fragile | Moderate | Moderate | Postgres | Include endpoint/param/cwe in fingerprint; implement `open` -> `resolved` -> `regressed` state machine |
| **Policy Engine & Release Gate** | `packages/policy-engine`, `releases.service.ts` | `IMPLEMENTED` | Evaluates severity counts, disallowed categories, P95 latency, and error rates. Emits gate decision. | Good | Low | High | Pure function | Add required test verification, waiver expiration, and signed release records |
| **Enterprise Reporting (JUnit/SARIF/HTML)** | `packages/contracts/src/reports/` | `VERIFIED` | Full generation of JUnit XML, SARIF v2.1.0 for GitHub Code Scanning, and self-contained executive HTML report. | High | Low | High | Pure functions | Persist reports to database and artifact store; add reproduction curl commands |
| **Console CLI** | `apps/cli` | `VERIFIED` | Comprehensive CLI commands (`target`, `test`, `scan`, `load`, `report`, `gate`). Proper exit codes for CI. | High | Low | High | Commander | Add local offline mode; add YAML configuration support |
| **Web Dashboard** | `apps/dashboard` | `VERIFIED` | Modern React UI with overview, targets, runs, findings, policies, and gate evaluation modals. | High | Low | Manual / E2E | Vite, React | Add real-time execution streaming (SSE/WebSocket), finding triage, and percentile curves |
| **CI/CD Integration** | `.github/workflows/`, `.gitlab-ci.yml` | `IMPLEMENTED` | GitHub Actions and GitLab CI running tests, controller, migrations, and CLI release gating. | Moderate | Low | Moderate | GitHub Actions | Standardize migration execution with dedicated migration runner |
| **Authentication Testing Framework** | `engines/authentication` | `SCAFFOLDED` | Only README in `engines/authentication/README.md`. No engine code. | Stub | Low | None | None | Build `AuthenticationSecurityEngine` (JWT, sessions, cookies, auth workflows) |
| **Authorization / BOLA Testing** | `engines/authorization` | `NOT_IMPLEMENTED` | Only README in `engines/authorization/README.md`. No engine code or schemas. | Stub | Low | None | None | Build `AuthorizationSecurityEngine` with IdentityProfiles and PermissionMatrix |
| **Security Contract Engine** | `examples/security-contracts` | `SCAFFOLDED` | Only example YAML files and domain enum. No contract evaluator. | Stub | Low | None | None | Build contract evaluator against OpenAPI specifications |
| **Local / Enterprise Agent** | `docs/architecture` | `NOT_IMPLEMENTED` | Architectural concept only. Controller directly invokes Docker/Node. | None | N/A | None | None | Design agent communication protocol and worker daemon |

---

## 2. Categorized Gaps by Severity

### 2.1 CRITICAL Gaps (P0) — Immediate Blockers

1. **Platform Security Boundary & SSRF Vulnerabilities**:
   - `validateUrlAgainstScope()` does not resolve DNS or validate resolved IP addresses. An attacker-controlled target domain can resolve to `169.254.169.254` (cloud metadata) or `127.0.0.1` (Postgres, controller).
   - In-process HTTP requests in `headers`, `cors`, `tls`, `declarative`, `k6`, and `rate-limit` engines follow HTTP redirects without re-checking the destination against the target scope. A target responding with a 302 redirect can pivot the platform into internal networks.
   - `DeclarativeTestEngine` accepts absolute URLs in `testSpec.path` (e.g. `http://internal-db:5432`) and executes requests without running `validateUrlAgainstScope()`.
   - Incomplete cloud metadata IP filtering: does not block IPv4-mapped IPv6, decimal, octal, or hex IP encodings.
2. **Container Runner Insecurity & Host Takeover Surface**:
   - `DockerRunner` accepts arbitrary volume mounts without validating host paths. A malicious test definition could mount `/var/run/docker.sock` or `/etc` with read-write permissions, resulting in full host compromise.
   - Missing container hardening flags: no `--security-opt=no-new-privileges:true`, no `--cap-drop=ALL`, runs as `root` by default, root filesystem is writable, no PID limits.
   - `DockerRunner` accepts arbitrary image names with no allowlist or digest verification.
3. **Misleading / Simulated Scanners in Production Path**:
   - **OWASP ZAP**: The container writes `report.json` to the container filesystem; the engine attempts to read it from `stdout`, which fails and causes a silent fallback to `SAMPLE_ZAP_BASELINE_REPORT`. Real scan findings are never captured.
   - **Aqua Trivy**: Runs `trivy fs .` inside the container without mounting any target code, scanning only Trivy's own image; on error, falls back to `SAMPLE_TRIVY_REPORT`.
   - **Grafana k6**: Claimed as a Class C k6 worker, but actually runs a custom in-process JavaScript `fetch()` loop in Node.js.
   - **Docker Runner**: If Docker daemon is unavailable, silently returns mock output instead of failing.

### 2.2 HIGH Gaps (P1) — Major Architectural & Functional Defects

1. **Controller Monolithic Blocking & Hardcoded Engine Registry**:
   - `TestRunnerService` hardcodes engine instantiation in an array and dispatches them via if-else statements.
   - No pluggable `EngineRegistry` with lifecycle management (`init`, `healthCheck`, `execute`, `cleanup`).
   - Execution is strictly sequential and synchronous within the Fastify request handler. Long-running scans block the Node.js event loop and controller process.
   - No execution queue (e.g. Postgres-backed job table or in-memory queue worker).
2. **Unusable Cancellation / Signal Handling**:
   - `AbortController` is instantiated inside a local loop in `runner.service.ts` and discarded. There is no controller endpoint or service method to abort a running test run.
   - If the controller process is killed, running Docker containers are orphaned on the host.
3. **Flawed Finding Fingerprinting & Missing Finding Lifecycle**:
   - Fingerprint hash only includes `engineId:targetId:title:category:severity`. Missing endpoint path, query parameters, rule ID, and CVE ID. This results in false collisions between different endpoints.
   - Every test run blindly inserts new rows into `findings`. There is no tracking of `firstDetectedAt`, `lastDetectedAt`, `retestRunId`, or resolution status (`open`, `resolved`, `regressed`).
4. **Complete Absence of Authorization / BOLA Testing**:
   - Despite being a primary product differentiator, authorization testing is completely unimplemented (only placeholder markdown exists).
   - No data models for user personas, role hierarchies, or permission matrices.
5. **DSL Expressiveness Limitations**:
   - `DeclarativeTestEngine` cannot send request bodies (JSON, form data), path parameters (`/api/users/:id`), or extract variables from responses to chain multiple requests.

### 2.3 MEDIUM Gaps (P2) — Data Integrity & Enterprise Readiness

1. **Database Schema Deficiencies**:
   - Missing tables: `test_definitions` (YAML specs are unmanaged strings), `reports` (reports are dynamically generated and lost), `artifacts` (no log or raw file storage), `credentials` (no encrypted vault for auth tokens).
   - Missing foreign key indexes in Drizzle schema.
   - No database triggers or append-only constraints on `evidence_records` (allows manual modification or deletion).
2. **Non-Canonical Evidence Serialization**:
   - `computeEvidenceHash` uses standard `JSON.stringify` which does not sort object keys. Hashes are unstable across different runtimes or post-database JSONB formatting.
3. **Authentication Framework Limitations**:
   - No support for basic auth, OAuth2 flows, cookie jars, or session tracking. Only static Bearer and API Key headers are injected.
4. **Policy Engine Completeness**:
   - Policies cannot require specific mandatory test profiles (e.g. "must run TLS and Headers tests").
   - No support for finding exemptions/waivers with expiration dates.
5. **Container-in-Container Deployment Flaw**:
   - In `docker-compose.yml`, the controller runs inside a container without Docker CLI or Docker socket access, guaranteeing that Class B/C engines will fail and fall back to mock data when deployed via Docker Compose.

### 2.4 LOW Gaps (P3) — Polishing & Developer Experience

1. **Dashboard Telemetry**: Real-time progress depends on manual polling rather than Server-Sent Events (SSE) or WebSockets.
2. **CLI Offline Execution**: The CLI currently requires a running controller server; cannot execute Class A tests in pure standalone offline mode.
3. **OpenAPI / Swagger Contract Importer**: No automatic ingestion of OpenAPI specifications to generate test definitions.

---

## 3. Special Security Evaluation: Platform Self-Defense & Abuse Vector Audit

Because Security Lab is a security testing platform, it can inadvertently become an **SSRF attack vector, proxy, or DoS weapon** if misused. The following vectors were evaluated:

| Attack Vector | Current Defense Status | Risk Level | Specific Vulnerability in Code |
| :--- | :--- | :--- | :--- |
| **SSRF via Target Scope** | Partially Defended | **CRITICAL** | String-only check in `scope-validator.ts`. No DNS resolution. Hex, octal, decimal, IPv4-mapped IPv6 not normalized. |
| **SSRF via Redirects** | **VULNERABLE** | **CRITICAL** | All native engines use default Node.js `fetch()` with `redirect: 'follow'`. 302 redirects to `169.254.169.254` or `127.0.0.1` succeed. |
| **SSRF via Declarative Test Paths** | **VULNERABLE** | **CRITICAL** | `DeclarativeTestEngine` line 126 accepts absolute URLs (`http://...`) and fetches them without scope validation. |
| **DNS Rebinding** | **VULNERABLE** | **CRITICAL** | Zero protection. Initial hostname check passes, but subsequent socket connection resolves to internal IP. |
| **Docker Command Injection** | Defended | Low | Arguments are passed as an array to `spawn('docker', args)`, avoiding shell expansion. |
| **Docker Socket Takeover** | **VULNERABLE** | **CRITICAL** | `DockerRunner` accepts any volume mount from options. Mounting `/var/run/docker.sock` allows root host takeover. |
| **Host Filesystem Mount Escape** | **VULNERABLE** | **CRITICAL** | No path allowlist on `VolumeMount.hostPath`. Can mount `/etc` or `C:\` into container. |
| **Container Breakout / Privileges** | **VULNERABLE** | **HIGH** | No `--security-opt=no-new-privileges:true`. No `--cap-drop=ALL`. Runs as root. |
| **Arbitrary Image Execution** | **VULNERABLE** | **HIGH** | No image allowlist. User options can specify any Docker image to pull and execute. |
| **Unbounded RPS / Concurrency** | Partially Defended | Moderate | Scopes define `limits.maxRps` and `maxConcurrency`, but in-process engines only clamp `burstCount` to 15. |
| **Unbounded Test Duration / DoS** | Partially Defended | Moderate | `DockerRunner` supports `timeoutMs`, but native `fetch()` calls do not configure timeouts on individual connections. |
| **Secret / Credential Persistence** | Partially Defended | Moderate | Environment variables passed directly in plain text in target/environment tables without encryption at rest. |

---

## 4. Priority Ranking Model (P0 – P3)

Gaps are prioritized based on:
`Priority = Security Risk (40%) + Architectural Dependency (30%) + Product Value (20%) + Implementation Complexity (10%)`

### P0 (Must Fix Immediately Before Expanding Features):
1. **Security Boundary & SSRF Hardening**: IP normalization, DNS resolution check, socket pinning, redirect re-validation, declarative URL scoping.
2. **Container Runner Hardening**: Prohibit Docker socket mounts, restrict host volumes to temporary sandboxes, drop all capabilities, enforce non-root UID, enforce image allowlist, eliminate silent mock fallback.
3. **Execution Kernel & Real Runner Architecture**: Decouple execution from Fastify event loop, eliminate false k6 fetch loop, fix ZAP container report transport, fix Trivy filesystem mounting.

### P1 (Core Product Foundations):
4. **Engine Registry & Lifecycle**: Dynamic discovery, capability negotiation, and cancellation.
5. **Declarative Test DSL v2**: Request bodies, parameter substitution, and multi-step chained requests.
6. **Authentication Testing Suite**: Dedicated engine for JWT, cookies, sessions, and auth workflows.
7. **Authorization & BOLA Engine**: Identity profiles, permission matrix, cross-user testing.
8. **Finding Lifecycle & Fingerprint Hardening**: Fix collision bugs, track regressions, re-tests, and fixes.

### P2 (Enterprise Quality & Governance):
9. **Database Schema Completion**: Add missing tables (`test_definitions`, `reports`, `artifacts`), indexes, and triggers.
10. **Policy Engine v2**: Mandatory tests, waiver expiration, and signed release records.
11. **Enterprise Reporting & Artifact Persistence**: Store reports and raw artifacts; generate reproduction curl commands.

### P3 (Scale & Ecosystem):
12. **CLI & CI/CD Productization**: Standalone offline execution, YAML config.
13. **Dashboard Real-Time Telemetry**: SSE/WebSockets and finding triage.
14. **Distributed Agent Architecture**: Local Agent vs SaaS Control Plane decoupling.

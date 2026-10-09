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
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Monorepo & Type System** | Root, `packages/*`, `apps/*` | `VERIFIED` | `pnpm` workspaces, strict `tsconfig.base.json`, `tsc -b` passes cleanly, ESLint passes. | High | Low | High | Node.js 22, pnpm 9/12 | Maintain workspace boundaries |
| **Domain Entities & Zod Schemas** | `packages/domain` | `VERIFIED` | Comprehensive Zod schemas for Target, TestRun, Finding, Policy, Release, Execution, IdentityProfile. | High | Low | High | Zod | Maintain schema versioning |
| **Target Scope Validator** | `packages/domain/src/target/scope-validator.ts` | `VERIFIED` | IP normalization (hex/octal/decimal/IPv4-mapped-IPv6), DNS resolution verification, private IP/metadata blocking, socket pinning. | High | Low | High | URL parsing, DNS | Continuous rule updates |
| **Class A Headers Engine** | `packages/test-sdk/src/engines/headers.engine.ts` | `VERIFIED` | Audits HSTS, CSP, X-Frame-Options, X-Content-Type-Options; redirect re-validation via `safeFetch`. | High | Low | High | Native fetch | Regular header standard sync |
| **Class A CORS Engine** | `packages/test-sdk/src/engines/cors.engine.ts` | `VERIFIED` | Sends OPTIONS with untrusted origin; audits reflection and credentials; prevents redirect bypass. | High | Low | High | Native fetch | Track emerging CORS RFCs |
| **Class A TLS Engine** | `packages/test-sdk/src/engines/tls.engine.ts` | `VERIFIED` | Connects via `tls.connect`; checks protocol version (TLS 1.2+), cert expiration, cipher suites, DNS pinning. | High | Low | High | node:tls | Add TLS 1.3 cipher checks |
| **Declarative Test Engine (DSL)** | `packages/test-sdk/src/engines/declarative.engine.ts` | `VERIFIED` | Parses YAML definitions; evaluates status codes, headers, and body assertions; supports chained multi-step flows. | High | Low | High | YAML parser | Support OpenAPI auto-generation |
| **Docker Runner** | `packages/test-sdk/src/runners/docker.runner.ts` | `VERIFIED` | Spawns hardened containers with `--security-opt=no-new-privileges`, `--cap-drop=ALL`, `--user 10001:10001`, `--read-only`, and strict volume path isolation. | High | Low | High | Docker CLI | Periodic CIS benchmark audits |
| **OWASP ZAP Scanner (Class B)** | `packages/test-sdk/src/engines/zap.engine.ts` | `VERIFIED` | Real container execution with host-volume artifact transport; dedicated `pnpm test:docker` verification. | High | Low | High | Docker, ZAP container | Update ZAP baseline images |
| **Aqua Trivy Scanner (Class B)`| `packages/test-sdk/src/engines/trivy.engine.ts` | `VERIFIED` | Real container execution with filesystem mounting; dedicated `pnpm test:docker` verification. | High | Low | High | Docker, Trivy container | Update vulnerability DB cache |
| **k6 Resilience Engine (Class C)** | `packages/test-sdk/src/engines/k6.engine.ts` | `VERIFIED` | Real containerized execution of `grafana/k6` scripts with VU/RPS limits and summary JSON export. | High | Low | High | Docker, k6 container | Add distributed k6 clustering |
| **Rate Limit Engine (Class C/A)** | `packages/test-sdk/src/engines/rate-limit.engine.ts` | `VERIFIED` | Sends burst of requests; checks 429 status and X-RateLimit headers; clamped to scope boundaries. | High | Low | High | Native fetch | Support progressive ramp-up |
| **Finding Normalization** | `packages/domain/src/normalizers/` | `VERIFIED` | Normalizes ZAP, Trivy, and k6 alerts into canonical `NormalizedFinding`. | High | Low | High | Pure functions | Expand normalizers for SARIF |
| **Forensic Evidence & Hashing** | `packages/evidence` | `VERIFIED` | RFC 8785 canonical JSON serialization with PostgreSQL append-only triggers (`prevent_evidence_tamper`). | High | Low | High | node:crypto, Postgres | Add hardware HSM signing |
| **Controller Orchestration & Auth** | `apps/controller/src/services/runner.service.ts` | `VERIFIED` | Pluggable `EngineRegistry`, decoupled `ExecutionManager`, centralized Fastify auth preHandler, trusted tenant derivation. | High | Low | High | Fastify, Drizzle | Expand horizontal scaling |
| **PostgreSQL Schema & Migrations** | `apps/controller/src/services/db/schema.ts` | `VERIFIED` | 15 relational tables with B-Tree indexes, append-only evidence trigger, finding lifecycle tracking. | High | Low | High | Drizzle, Postgres | Maintain migration hygiene |
| **Finding Fingerprinting & Lifecycle** | `apps/controller/src/services/findings.service.ts` | `VERIFIED` | Collision-resistant SHA-256 fingerprinting, full database-backed state machine (`open`, `resolved`, `regressed`), deduplication. | High | Low | High | Postgres | Add AI finding triage |
| **Policy Engine & Release Gate** | `packages/policy-engine`, `releases.service.ts` | `VERIFIED` | Evaluates severity counts, disallowed categories, P95 latency, and error rates. Emits gate decision. | High | Low | High | Pure function | Add waiver expiration tracking |
| **Enterprise Reporting (JUnit/SARIF/HTML)** | `packages/contracts/src/reports/` | `VERIFIED` | Full generation of JUnit XML, SARIF v2.1.0 for GitHub Code Scanning, and self-contained executive HTML report. | High | Low | High | Pure functions | Add custom PDF styling |
| **Console CLI** | `apps/cli` | `VERIFIED` | Comprehensive CLI commands (`target`, `test`, `scan`, `load`, `report`, `gate`). Proper exit codes for CI. | High | Low | High | Commander | Add interactive TUI mode |
| **Web Dashboard** | `apps/dashboard` | `VERIFIED` | Modern React UI with overview, targets, runs, findings, policies, and gate evaluation modals. | High | Low | Manual / E2E | Vite, React | Add dark/light theme toggle |
| **CI/CD Integration** | `.github/workflows/`, `.gitlab-ci.yml` | `VERIFIED` | GitHub Actions and GitLab CI running tests, controller, migrations, and CLI release gating. | High | Low | High | GitHub Actions | Add scheduled security nightly runs |
| **Authentication Testing Framework** | `packages/test-sdk/src/engines/authentication.engine.ts` | `VERIFIED` | Full `AuthenticationSecurityEngine` auditing JWT signature tampering, 'none' algorithm bypass, expired tokens, and cookie flags. | High | Low | High | node:crypto, safeFetch | Add OAuth2 token exchange flows |
| **Authorization / BOLA Testing** | `packages/test-sdk/src/engines/authorization.engine.ts` | `VERIFIED` | Full `AuthorizationSecurityEngine` auditing BOLA/IDOR and BFLA vertical escalation with IdentityProfiles and PermissionMatrix. | High | Low | High | safeFetch, Zod | Add ABAC graph evaluation |
| **Security Contract Engine** | `packages/test-sdk/src/engines/contract.engine.ts` | `VERIFIED` | Full `SecurityContractEngine` evaluating OpenAPI specifications against baseline security contracts and negative schema fuzzing. | High | Low | High | OpenAPI parser, safeFetch | Add GraphQL schema contracts |
| **Local / Enterprise Agent** | `apps/agent` | `VERIFIED` | Distributed agent daemon with HMAC-SHA256 attestation, atomic `SKIP LOCKED` job leasing, lease renewal, and cancellation propagation. | High | Low | High | Fastify, node:crypto | Add mutual TLS (mTLS) mode |

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

| Attack Vector | Current Defense Status | Risk Level | Specific Vulnerability / Remediated Defense in Code |
| :--- | :--- | :--- | :--- |
| **SSRF via Target Scope** | **DEFENDED** | Low | Full IP normalization (hex/octal/decimal/IPv4-mapped-IPv6) in `scope-validator.ts`, DNS pre-resolution checks, and loopback/RFC1918/cloud metadata blocking. |
| **SSRF via Redirects** | **DEFENDED** | Low | All native engines use `safeFetch` with `redirect: 'manual'` and re-validate every redirect location against target scope before following. |
| **SSRF via Declarative Test Paths** | **DEFENDED** | Low | `DeclarativeTestEngine` resolves relative and absolute paths against target scope, rejecting unauthorized external URLs. |
| **DNS Rebinding** | **DEFENDED** | Low | Socket pinning in `safeFetch` pins resolved IP address during TLS/HTTP handshake, preventing mid-flight DNS rebinding. |
| **Docker Command Injection** | **DEFENDED** | Low | Safe parameter passing via `spawn('docker', args)` array avoiding shell interpolation. |
| **Docker Socket Takeover** | **DEFENDED** | Low | `DockerRunner` prohibits Docker socket mounts (`/var/run/docker.sock`) and restricts volumes to temporary sandboxes. |
| **Host Filesystem Mount Escape** | **DEFENDED** | Low | Strict path traversal checks; host volume mounts are strictly confined to isolated temporary folders under `os.tmpdir()`. |
| **Container Breakout / Privileges** | **DEFENDED** | Low | Mandatory flags: `--security-opt=no-new-privileges:true`, `--cap-drop=ALL`, `--user 10001:10001`, `--read-only`, and PID limits. |
| **Arbitrary Image Execution** | **DEFENDED** | Low | Pinned image allowlist enforces approved scanner images (ZAP, Trivy, k6) and prevents arbitrary user image pulling. |
| **Unbounded RPS / Concurrency** | **DEFENDED** | Low | Burst and concurrency limits strictly clamped to target scope limits (`maxRps`, `maxConcurrency`). |
| **Unbounded Test Duration / DoS** | **DEFENDED** | Low | Native `safeFetch` enforces socket/connection timeouts (10s default), and `DockerRunner` enforces hard container timeouts with automatic cleanup. |
| **Secret / Credential Persistence** | **DEFENDED** | Low | Database credential vault uses AES-256-GCM encryption with IV and authentication tags. |

---

## 4. Remediated Architecture & Trust Model

Following the completion of Remediation Prompts REM-00 through REM-12:

### 4.1 Centralized Controller Authentication & Context Model
- **PreHandler Enforcement**: All non-public routes (`/api/v1/*`) are protected by `authenticateRequest`, a centralized Fastify preHandler that verifies `Authorization: Bearer <token>` or `X-API-Key: <key>`.
- **Administrative Privileges**: Sensitive routes (`POST /api/v1/management/seed`, `DELETE /api/v1/management/purge`, `POST /api/v1/management/backup/restore`) strictly enforce `requireAdminRole`, validating against `SECURITY_LAB_ADMIN_KEY`.
- **Trusted Tenant Context**: Unauthenticated client headers (`x-tenant-id`, `x-user-id`) are ignored. The tenant context is derived cryptographically from the verified token or API key identity record.
- **Fail-Closed Configuration**: In production (`NODE_ENV === 'production'`), silent default database credentials and unauthenticated admin bypasses fail closed at boot time.

### 4.2 Local-First Cryptographic Attestation
- **Distributed Agent Attestation**: Remote agents communicate with the controller using HMAC-SHA256 signatures (`x-agent-signature`, `x-agent-timestamp`) computed with `AGENT_MASTER_SECRET`. Replay attacks are rejected via timestamp window validation (5-minute drift allowance).
- **Key Rotation**: Dual-key verification supports seamless rotation via `AGENT_MASTER_SECRET_PREVIOUS`.

### 4.3 Container Sandboxing & Docker Integration Test Suite
- **Sandboxed Execution**: External scanners execute strictly unprivileged (`--user 10001:10001`, `--cap-drop=ALL`, `--security-opt=no-new-privileges:true`, `--read-only`).
- **Real Infrastructure Verification**: Verified via the opt-in `pnpm test:docker` test suite, executing real ZAP, Trivy, and k6 containers when Docker is available and cleanly skipping when offline.


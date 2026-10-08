# Product Roadmap & Phased Implementation Master Plan

**Project**: Security Lab — Application Security & Resilience Testing Platform  
**Document**: `docs/architecture/product-roadmap.md`  
**Baseline Date**: October 2026  
**Auditor & Planner**: Principal Security Architect & Technical Program Planner  

---

## 1. Product Horizon Strategy

To prevent scope creep and maintain architectural clarity, the platform roadmap is partitioned into four distinct product horizons:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        HORIZON 1: LOCAL MVP                            │
│  Hardened, reliable, local security QA tool running on workstation.    │
│  Real Class A/B/C execution, unbreachable scope, truthful telemetry.   │
├────────────────────────────────────────────────────────────────────────┤
│                        HORIZON 2: TEAM V1                              │
│  CI/CD release gating, declarative DSL v2, auth/BOLA testing,          │
│  finding regression intelligence, and deterministic compliance reports.│
├────────────────────────────────────────────────────────────────────────┤
│                        HORIZON 3: ENTERPRISE V2                        │
│  Full authorization matrix, OpenAPI contract fuzzing, encrypted vault, │
│  policy waivers, artifact storage, and dashboard triage workflows.    │
├────────────────────────────────────────────────────────────────────────┤
│                        HORIZON 4: SAAS & HYBRID CLOUD                  │
│  Multi-tenant control plane, distributed ephemeral agents, mTLS tunnel,│
│  enterprise RBAC, audit exports, and centralized compliance dashboard. │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Product Horizon Breakdown

### Horizon 1: Local MVP (True Local Foundation)
* **Goal**: Provide a rock-solid, secure, local-first security testing platform for developers and AppSec engineers.
* **Essential Capabilities**:
  1. Unbreachable target scope boundary with IP normalization, DNS pinning, and redirect re-validation.
  2. Hardened Docker runner with capability dropping, non-root user, and restricted volume mounts.
  3. Real container artifact transport for OWASP ZAP (reading real `report.json` via mounted volumes; eliminating mock fallbacks).
  4. Real Aqua Trivy scanner with target repository/image mounting.
  5. Real Grafana k6 runner running containerized k6 scripts (eliminating simulated in-process fetch loops).
  6. Pluggable `EngineRegistry` with true cancellation and decoupled execution queue.
  7. Accurate finding fingerprinting and basic lifecycle (`open`, `resolved`, `regressed`).

### Horizon 2: Team V1 (Engineering Team Security QA)
* **Goal**: Enable engineering teams to embed automated security contracts into pull requests and CI/CD pipelines.
* **Essential Capabilities**:
  1. Declarative Test DSL v2 supporting request bodies, path parameters, and multi-step chained workflows.
  2. Dedicated Authentication Testing Engine (JWT validation, cookie security, session lifecycle).
  3. Dedicated Authorization & BOLA Testing Engine (User A vs User B cross-tenant resource access).
  4. Policy Engine v2 with mandatory test profiles and SLA gate enforcement.
  5. Persistent enterprise reporting (JUnit, SARIF v2.1.0, HTML) with reproduction `curl` commands.
  6. CLI offline execution mode (`security-lab run --local`) and automated GitHub Actions / GitLab CI integrations.

### Horizon 3: Enterprise V2 (Enterprise-Grade Security Lab)
* **Goal**: Standardize AppSec compliance and resilience validation across large organizations.
* **Essential Capabilities**:
  1. Full Authorization Matrix (Roles x Endpoints x Allowed Methods) with automatic permission auditing.
  2. Security Contract Engine with automated test generation from OpenAPI / Swagger specifications.
  3. Encrypted Credentials Vault for test identities and API tokens.
  4. Comprehensive finding regression intelligence with automated re-tests and waiver management.
  5. Artifact Storage subsystem (local disk / object storage) for scanner dumps, pcaps, and execution logs.
  6. Interactive dashboard triage workflows (false-positive marking, SLA tracking, posture trends).

### Horizon 4: SaaS & Hybrid Cloud (Enterprise Scale)
* **Goal**: Deliver a centralized multi-tenant management plane with distributed private agents.
* **Essential Capabilities**:
  1. Separation of Controller into SaaS Control Plane and Local/Private Execution Agents.
  2. Secure agent communication over encrypted WebSockets / gRPC with mTLS.
  3. Multi-tenant database partitioning, organization isolation, and tenant-level encryption.
  4. Cloud-native worker scaling on Kubernetes (K8s Jobs / Knative).
  5. Enterprise SSO (SAML 2.0 / OIDC), SCIM user provisioning, and SOC 2 Type II audit logs.

---

## 3. Phased Implementation Roadmap

Based on the actual codebase audit, the implementation sequence has been re-baselined into **16 sequential, verifiable engineering phases**:

```
Phase 00: Codebase Baseline & Reality Correction
   │
   ▼
Phase 01: Platform Security Boundary & SSRF Hardening
   │
   ▼
Phase 02: Execution Kernel & Container Runner Hardening
   │
   ▼
Phase 03: Engine Registry, Lifecycle & Decoupled Execution Queue
   │
   ▼
Phase 04: Real Container Scanner Runners (OWASP ZAP & Aqua Trivy)
   │
   ▼
Phase 05: Real Performance & Resilience Engine (Grafana k6)
   │
   ▼
Phase 06: Declarative Test DSL v2 & HTTP Engine Expansion
   │
   ▼
Phase 07: Authentication Testing Framework
   │
   ▼
Phase 08: Authorization & BOLA/IDOR Testing Framework
   │
   ▼
Phase 09: Security Contract Engine & OpenAPI Discovery
   │
   ▼
Phase 10: Database Hardening, Finding Lifecycle & Regression Intelligence
   │
   ▼
Phase 11: Policy Engine v2 & Release Governance
   │
   ▼
Phase 12: Enterprise Reporting, Artifact Management & Storage
   │
   ▼
Phase 13: CLI & CI/CD Pipeline Productization
   │
   ▼
Phase 14: Web Dashboard Productization & Real-Time Telemetry
   │
   ▼
Phase 15: Distributed Agent Architecture & Hybrid Cloud / SaaS Foundation
   │
   ▼
Phase 16: Distributed Agent Trust Boundary & Secure Execution Plane
```

---

## 4. Phase Specifications

### Phase 00 — Codebase Baseline & Reality Correction
* **Objective**: Reconcile documentation with actual codebase reality, remove misleading completion claims, and establish a truthful engineering baseline.
* **Why this phase exists**: The current README, roadmap, and engine READMEs claim features are "IMPLEMENTED" when they actually use mocks or in-process stubs (e.g. k6 using fetch, ZAP report transport broken, BOLA non-existent). Continuing development on false claims breeds architectural debt.
* **Current-state dependencies**: Existing repo documentation.
* **Prerequisites**: None.
* **Implementation scope**:
  - Update `README.md` completion status tables and roadmap checklist.
  - Update `engines/*/README.md` to reflect true statuses (`SCAFFOLDED`, `PARTIALLY_IMPLEMENTED`).
  - Document known limitations in `docs/architecture/`.
* **Out of scope**: Code refactoring or feature additions.
* **Affected packages**: Documentation only.
* **Affected applications**: None.
* **Affected database tables**: None.
* **Affected APIs**: None.
* **Affected tests**: None.
* **Security considerations**: Establishes transparent security posture baseline.
* **Migration considerations**: None.
* **Expected deliverables**: Truthful `README.md`, accurate engine docs.
* **Acceptance criteria**: Every claim in the README matches real code behavior verified by tests.
* **Validation commands**: Review diffs; verify all links and references.
* **Rollback strategy**: `git revert`.
* **Definition of Done**: Documentation 100% reflects code reality.
* **Next-phase dependency**: Unlocks Phase 01.

---

### Phase 01 — Platform Security Boundary & SSRF Hardening
* **Objective**: Transform `validateUrlAgainstScope` into an unbreachable defensive gateway and eliminate all SSRF and redirect bypass vectors.
* **Why this phase exists**: As a security testing tool, the platform must never be exploitable as an SSRF proxy against cloud metadata (`169.254.169.254`), private RFC 1918 subnets, or internal services.
* **Current-state dependencies**: `packages/domain/src/target/scope-validator.ts`, native engines.
* **Prerequisites**: Phase 00.
* **Implementation scope**:
  - Full IP parsing and normalization: handle decimal (`2852039166`), octal, hex, IPv4-mapped IPv6 (`::ffff:169.254.169.254`), and IPv6 loopbacks (`::1`).
  - DNS resolution check during validation; verify all resolved A/AAAA records against scope.
  - Implement custom HTTP request dispatcher in `@security-lab/test-sdk` that disables default `redirect: 'follow'`, intercepts 3xx responses, and validates every redirect `Location` against target scope before following.
  - Harden `DeclarativeTestEngine`: validate `testSpec.path` against target scope if it contains an absolute URL.
  - Enforce strict wildcard subdomain matching (prevent `*.example.com` matching `badexample.com`).
* **Out of scope**: Modifying external Docker runners.
* **Affected packages**: `@security-lab/domain`, `@security-lab/test-sdk`.
* **Affected applications**: `@security-lab/controller`.
* **Affected database tables**: None.
* **Affected APIs**: Target validation and test execution endpoints.
* **Affected tests**: `tests/security/platform-security.test.ts`, `tests/integration/scope-validator.test.ts`.
* **Security considerations**: Direct remediation of Critical P0 vulnerabilities.
* **Migration considerations**: Fully backward-compatible for valid targets.
* **Expected deliverables**: Hardened `scope-validator.ts`, safe HTTP client wrapper with redirect guards, comprehensive negative security tests.
* **Acceptance criteria**: All SSRF bypass vectors (redirects, metadata IPs, DNS rebinding simulations, encoded IPs) are rejected with deterministic error messages.
* **Validation commands**: `pnpm --filter @security-lab/domain test`, `pnpm vitest run tests/security/platform-security.test.ts`.
* **Rollback strategy**: Git revert.
* **Definition of Done**: Zero SSRF or redirect escape vectors exist in native engines.
* **Next-phase dependency**: Unlocks Phase 02.

---

### Phase 02 — Execution Kernel & Container Runner Hardening
* **Objective**: Harden `DockerRunner` into an isolated, secure container sandbox and eliminate host compromise risks.
* **Why this phase exists**: `DockerRunner` currently accepts arbitrary images and volume mounts, runs as root, and silently falls back to mock data on execution errors.
* **Current-state dependencies**: `packages/test-sdk/src/runners/docker.runner.ts`.
* **Prerequisites**: Phase 01.
* **Implementation scope**:
  - Add mandatory security flags to `docker run`: `--security-opt=no-new-privileges:true`, `--cap-drop=ALL`, `--user=10001:10001`, `--read-only`, `--pids-limit=100`.
  - Prohibit dangerous volume mounts: strictly reject mounting `/var/run/docker.sock`, `/etc`, or root paths. Restrict mounts to dedicated temporary host scratch directories.
  - Implement container image allowlist and digest validation (only approved images: ZAP, Trivy, k6).
  - Network isolation: default to isolated Docker bridge network; strictly reject `--network host`.
  - Process lifecycle & cleanup: assign deterministic container names (`security-lab-run-${id}`); implement explicit `docker stop` and container removal upon timeout or abort signal.
  - Eliminate silent fallback to mock data: when container execution fails or Docker is unavailable, throw an explicit, actionable error.
* **Out of scope**: Scanner-specific report parsing (handled in Phase 04).
* **Affected packages**: `@security-lab/test-sdk`.
* **Affected applications**: `@security-lab/controller`.
* **Affected database tables**: None.
* **Affected APIs**: None.
* **Affected tests**: Container runner integration tests in `tests/integration/container-scanners.test.ts`.
* **Security considerations**: Eliminates container breakout and host takeover vectors.
* **Migration considerations**: None.
* **Expected deliverables**: Hardened `DockerRunner`, container test suite verifying security flags and rejection of dangerous mounts.
* **Acceptance criteria**: Attempts to mount Docker socket or run unauthorized images fail immediately with security errors; timeouts cleanly kill container.
* **Validation commands**: `pnpm vitest run tests/integration/container-scanners.test.ts`.
* **Rollback strategy**: Git revert.
* **Definition of Done**: `DockerRunner` meets strict CIS Docker benchmark sandboxing standards.
* **Next-phase dependency**: Unlocks Phase 03.

---

### Phase 03 — Engine Registry, Lifecycle & Decoupled Execution Queue
* **Objective**: Replace the hardcoded controller engine switch with a pluggable `EngineRegistry` and decouple test execution from the Fastify HTTP request loop.
* **Why this phase exists**: Currently, `runner.service.ts` hardcodes engine instantiation in an array and runs engines sequentially within the HTTP request, blocking the server and making cancellation impossible.
* **Current-state dependencies**: `apps/controller/src/services/runner.service.ts`, `packages/test-sdk/src/engine.ts`.
* **Prerequisites**: Phase 02.
* **Implementation scope**:
  - Implement `EngineRegistry` in `@security-lab/test-sdk`: allows registering engines with capability discovery, category grouping, and versioning.
  - Implement engine lifecycle hooks: `init()`, `validate()`, `execute()`, `cleanup()`.
  - Implement an asynchronous execution queue in `@security-lab/controller` (in-memory event queue with concurrency limits for local runs).
  - True cancellation support: store active `AbortController` instances in an execution manager; implement `POST /api/v1/test-runs/:id/cancel` and CLI `security-lab test cancel <id>`.
  - Add execution status polling and streaming events.
* **Out of scope**: External distributed worker daemons (Phase 15).
* **Affected packages**: `@security-lab/test-sdk`, `@security-lab/contracts`.
* **Affected applications**: `@security-lab/controller`, `@security-lab/cli`.
* **Affected database tables**: `test_runs` (status: 'cancelled'), `test_executions`.
* **Affected APIs**: `POST /api/v1/test-runs/:id/cancel`, `POST /api/v1/test-runs/:id/execute` (returns 202 Accepted).
* **Affected tests**: `tests/integration/test-run-execution.test.ts`.
* **Security considerations**: Prevents server DoS and resource starvation from unbounded long-running scans.
* **Migration considerations**: None.
* **Expected deliverables**: `EngineRegistry` class, execution queue, cancellation API, updated CLI.
* **Acceptance criteria**: Triggering a test run returns immediately with execution ID; user can cancel running test run cleanly; engines register dynamically.
* **Validation commands**: `pnpm test`.
* **Rollback strategy**: Git revert.
* **Definition of Done**: Zero hardcoded engine switches in controller; cancellation terminates in-flight operations within 2 seconds.
* **Next-phase dependency**: Unlocks Phase 04 and Phase 05.

---

### Phase 04 — Real Container Scanner Runners (OWASP ZAP & Aqua Trivy)
* **Objective**: Implement genuine, reliable container execution and artifact transport for OWASP ZAP and Aqua Trivy, eliminating mock fallbacks.
* **Why this phase exists**: Currently, ZAP attempts to parse JSON from stdout while ZAP writes to disk, causing silent fallback to hardcoded mock JSON. Trivy scans its own image without target code.
* **Current-state dependencies**: `packages/test-sdk/src/engines/zap.engine.ts`, `trivy.engine.ts`, `packages/domain/src/normalizers/`.
* **Prerequisites**: Phase 02, Phase 03.
* **Implementation scope**:
  - **OWASP ZAP**:
    - Create a temporary host directory mounted to container path `/zap/wrk:rw`.
    - Run `zap-baseline.py -t <targetUrl> -J report.json`.
    - After container exit, read `report.json` from the temporary host directory.
    - Pass raw JSON to `normalizeZapAlerts()`.
    - Clean up temporary scratch directory in `finally` block.
    - Remove hardcoded `SAMPLE_ZAP_BASELINE_REPORT` fallback; report true failure if report missing.
  - **Aqua Trivy**:
    - Support scanning local directories (mount target repo into container read-only) or target container images.
    - Run `trivy fs --format json --output /tmp/trivy/report.json /target-src`.
    - Read and parse real Trivy report JSON from host scratch volume.
    - Remove hardcoded `SAMPLE_TRIVY_REPORT` fallback.
* **Out of scope**: k6 load testing (Phase 05).
* **Affected packages**: `@security-lab/test-sdk`, `@security-lab/domain`.
* **Affected applications**: `@security-lab/controller`.
* **Affected database tables**: `test_executions.raw_result`.
* **Affected APIs**: None.
* **Affected tests**: `tests/integration/container-scanners.test.ts`.
* **Security considerations**: Scratch volume paths must be isolated under OS temp directory with strict permissions.
* **Migration considerations**: None.
* **Expected deliverables**: Reliable ZAP and Trivy runners reading real reports from mounted scratch volumes; integration tests verifying file-based artifact transport.
* **Acceptance criteria**: Running ZAP against a real HTTP service captures actual HTTP findings without mock substitution.
* **Validation commands**: `pnpm vitest run tests/integration/container-scanners.test.ts`.
* **Rollback strategy**: Git revert.
* **Definition of Done**: Zero mock fallbacks in container scanner execution path.
* **Next-phase dependency**: Unlocks Phase 05 and Phase 10.

---

### Phase 05 — Real Performance & Resilience Engine (Grafana k6)
* **Objective**: Replace the in-process JavaScript `fetch()` loop with genuine Grafana k6 containerized execution for latency SLA and resilience audits.
* **Why this phase exists**: `K6ResilienceEngine` is currently mislabeled; it uses Node.js `fetch()` which does not generate true concurrent load and skews percentile measurements due to event loop lag.
* **Current-state dependencies**: `packages/test-sdk/src/engines/k6.engine.ts`.
* **Prerequisites**: Phase 02, Phase 03.
* **Implementation scope**:
  - Implement k6 test script generator: creates JavaScript test files defining VUs, duration, target URL, headers, and thresholds based on target scope and test options.
  - Mount generated script into `grafana/k6:latest` container via `DockerRunner`.
  - Configure k6 summary export (`--summary-export=/tmp/k6/summary.json`).
  - Read `summary.json` from host scratch directory upon completion.
  - Extract true k6 metrics: `http_req_duration` (p50, p90, p95, p99, avg, max), `http_req_failed`, `http_reqs`, `vus`.
  - Persist quantitative metrics into `metrics` table.
  - Differentiate clearly between load testing, soak testing, and rate-limiting burst testing.
* **Out of scope**: Chaos engineering fault injection.
* **Affected packages**: `@security-lab/test-sdk`.
* **Affected applications**: `@security-lab/controller`.
* **Affected database tables**: `metrics`.
* **Affected APIs**: None.
* **Affected tests**: `tests/integration/k6-resilience.test.ts`.
* **Security considerations**: Strictly enforce `target.scope.limits.maxConcurrency` and `maxRps` in generated k6 scripts.
* **Migration considerations**: None.
* **Expected deliverables**: True `K6ResilienceEngine` executing `grafana/k6` container; test suite asserting real k6 execution.
* **Acceptance criteria**: Load tests invoke real k6 binary and generate authentic latency distributions and percentile summaries.
* **Validation commands**: `pnpm vitest run tests/integration/k6-resilience.test.ts`.
* **Rollback strategy**: Git revert.
* **Definition of Done**: In-process fetch loop is completely replaced by real k6 runner.
* **Next-phase dependency**: Unlocks Phase 06.

---

### Phase 06 — Declarative Test DSL v2 & HTTP Engine Expansion
* **Objective**: Upgrade the declarative test definition language to support request bodies, path variables, response variable extraction, and chained multi-step requests.
* **Why this phase exists**: The current DSL only supports single GET/POST requests without bodies or parameter extraction, making it impossible to test authenticated APIs, stateful workflows, or business logic.
* **Current-state dependencies**: `packages/domain/src/test-definition/`, `packages/test-sdk/src/engines/declarative.engine.ts`.
* **Prerequisites**: Phase 01, Phase 03.
* **Implementation scope**:
  - Expand `SingleTestSpecSchema`:
    - `body`: support JSON objects, form-encoded, and raw text with MIME type.
    - `params`: path variable mapping (e.g. `/users/{userId}`) and query parameters.
    - `extract`: extract variables from response headers or JSON body (`extract: { token: 'body.access_token', userId: 'body.user.id' }`).
    - `setup` and `teardown` request steps.
    - `dependsOn`: sequential dependency between steps.
  - Update `DeclarativeTestEngine` to maintain workflow execution state across steps in a test suite.
  - Support negative security assertions (e.g. expected 401/403, missing sensitive data fields).
* **Out of scope**: BOLA identity matrix (Phase 08).
* **Affected packages**: `@security-lab/domain`, `@security-lab/test-sdk`.
* **Affected applications**: `@security-lab/controller`.
* **Affected database tables**: None (definition schema update).
* **Affected APIs**: Test definition validation routes.
* **Affected tests**: `tests/integration/native-engines.test.ts`, `tests/integration/domain-contracts.test.ts`.
* **Security considerations**: Variable extraction must sanitize values before using in downstream URLs or headers.
* **Migration considerations**: Backward-compatible with DSL v1 specifications.
* **Expected deliverables**: `TestDefinitionSchema` v2, workflow state evaluator, example YAMLs for multi-step API tests.
* **Acceptance criteria**: A multi-step test definition can send a POST request with body, extract an auth token from JSON, and pass it in a subsequent GET request.
* **Validation commands**: `pnpm test`.
* **Rollback strategy**: Git revert.
* **Definition of Done**: Declarative DSL v2 passes comprehensive assertion and chaining test suite.
* **Next-phase dependency**: Unlocks Phase 07 and Phase 08.

---

### Phase 07 — Authentication Testing Framework
* **Objective**: Implement a dedicated `AuthenticationSecurityEngine` for automated auditing of tokens, cookies, sessions, and authentication endpoints.
* **Why this phase exists**: Authentication testing currently consists only of static header injection. The platform cannot audit JWT vulnerabilities, session fixation, cookie flags, or brute-force protections.
* **Current-state dependencies**: `engines/authentication/README.md`, `@security-lab/test-sdk`.
* **Prerequisites**: Phase 06.
* **Implementation scope**:
  - Implement `AuthenticationSecurityEngine` implementing `TestEngine`.
  - Capabilities:
    - `auth_jwt_audit`: Token decoding, expiration checks, algorithm confusion checks (e.g. `none` alg, weak HMAC secret checks), missing signature verification.
    - `auth_cookie_flags`: Audits `HttpOnly`, `Secure`, `SameSite` flags, and `__Host-` / `__Secure-` prefixes on all Set-Cookie headers.
    - `auth_credential_stuffing_resilience`: Audits login endpoints for rate-limiting, account lockout, or response time variance.
  - Implement encrypted credential vault model in `@security-lab/domain`.
* **Out of scope**: BOLA / authorization matrix (Phase 08).
* **Affected packages**: `@security-lab/domain`, `@security-lab/test-sdk`.
* **Affected applications**: `@security-lab/controller`.
* **Affected database tables**: None.
* **Affected APIs**: None.
* **Affected tests**: Integration tests for authentication engine.
* **Security considerations**: Sensitive tokens used during testing must never be stored in plain text in logs or findings.
* **Migration considerations**: None.
* **Expected deliverables**: `AuthenticationSecurityEngine`, capability definitions, unit and integration tests.
* **Acceptance criteria**: Identifies weak JWT signatures, missing cookie security flags, and unprotected auth routes.
* **Validation commands**: `pnpm test`.
* **Rollback strategy**: Git revert.
* **Definition of Done**: Engine is registered and executable via standard test run profiles.
* **Next-phase dependency**: Unlocks Phase 08.

---

### Phase 08 — Authorization & BOLA/IDOR Testing Framework
* **Objective**: Build the platform's core product differentiator: a native `AuthorizationSecurityEngine` for automated BOLA/IDOR and privilege escalation testing.
* **Why this phase exists**: Authorization defects (BOLA/BFLA) are the #1 vulnerability in modern APIs (OWASP API Top 10). The platform currently has zero authorization testing code.
* **Current-state dependencies**: `engines/authorization/README.md`.
* **Prerequisites**: Phase 06, Phase 07.
* **Implementation scope**:
  - Define domain entities in `@security-lab/domain`:
    - `IdentityProfile`: represents a test user (e.g. User A, User B, Admin, Anonymous) with credentials/tokens.
    - `AuthorizationMatrix`: defines expected access permissions (Role x Endpoint x Method -> ALLOW / DENY).
    - `ResourcePermutation`: test pairs of object IDs owned by User A executed with User B's token.
  - Implement `AuthorizationSecurityEngine`:
    - Tests horizontal privilege escalation (User B accesses User A's private resource via GET/PUT/DELETE).
    - Tests vertical privilege escalation (Standard user accesses Admin endpoints).
    - Tests unauthenticated access (Anonymous accesses protected endpoints).
  - Normalize unauthorized 200 OK responses into high/critical BOLA findings with reproducible evidence.
* **Out of scope**: Business workflow logic (Phase 10).
* **Affected packages**: `@security-lab/domain`, `@security-lab/test-sdk`, `@security-lab/contracts`.
* **Affected applications**: `@security-lab/controller`.
* **Affected database tables**: `identity_profiles`, `authorization_matrices` (added in Phase 10).
* **Affected APIs**: Authorization test execution routes.
* **Affected tests**: Unit and integration tests for BOLA detection.
* **Security considerations**: BOLA tests must use synthetic, non-production test object identifiers.
* **Migration considerations**: None.
* **Expected deliverables**: `AuthorizationSecurityEngine`, BOLA test definition schema, integration tests against mock vulnerable multi-user API.
* **Acceptance criteria**: Engine reliably flags horizontal and vertical privilege escalation vulnerabilities when User B accesses User A's resource.
* **Validation commands**: `pnpm test`.
* **Rollback strategy**: Git revert.
* **Definition of Done**: Authorization engine detects simulated BOLA with 100% precision and zero false positives.
* **Next-phase dependency**: Unlocks Phase 09.

---

### Phase 09 — Security Contract Engine & OpenAPI Discovery
* **Objective**: Implement automated security contract enforcement and test generation directly from OpenAPI 3.0/3.1 specifications.
* **Why this phase exists**: Security QA should be contract-driven. Developers maintain OpenAPI specs; Security Lab should automatically audit all declared endpoints for required security controls.
* **Current-state dependencies**: `examples/security-contracts/`, `@security-lab/domain`.
* **Prerequisites**: Phase 06, Phase 08.
* **Implementation scope**:
  - OpenAPI 3.0/3.1 parser: extracts endpoints, methods, parameters, and security requirements.
  - Contract rules:
    - Every endpoint must declare authentication security scheme.
    - Sensitive parameters must not appear in query strings.
    - Response headers must conform to security baseline.
  - Automated test generation: generate declarative test definitions from OpenAPI specs for fuzzing and type boundary validation.
  - CLI command: `security-lab contract verify --spec openapi.yaml`.
* **Out of scope**: Dynamic fuzzing engines.
* **Affected packages**: `@security-lab/domain`, `@security-lab/test-sdk`, `@security-lab/contracts`.
* **Affected applications**: `@security-lab/controller`, `@security-lab/cli`.
* **Affected database tables**: None.
* **Affected APIs**: `POST /api/v1/contracts/evaluate`.
* **Affected tests**: Contract verification tests.
* **Security considerations**: OpenAPI parsers must guard against YAML bombs and deeply nested schemas.
* **Migration considerations**: None.
* **Expected deliverables**: OpenAPI contract parser, contract evaluator, CLI verify command.
* **Acceptance criteria**: OpenAPI specs with missing security schemes or sensitive query params fail contract verification with detailed line citations.
* **Validation commands**: `pnpm test`.
* **Rollback strategy**: Git revert.
* **Definition of Done**: Security contract engine generates runnable declarative tests from OpenAPI specs.
* **Next-phase dependency**: Unlocks Phase 10.

---

### Phase 10 — Database Hardening, Finding Lifecycle & Regression Intelligence
* **Objective**: Evolve the database schema with missing tables, foreign key indexes, finding lifecycle tracking (`open`, `resolved`, `regressed`), and append-only forensic audit triggers.
* **Why this phase exists**: Currently, every test run inserts duplicate finding rows; fingerprints collide across endpoints; reports and artifacts are ephemeral; database allows manual tampering of evidence.
* **Current-state dependencies**: `apps/controller/src/services/db/`, `infrastructure/postgres/migrations/`.
* **Prerequisites**: Phase 03, Phase 04.
* **Implementation scope**:
  - Drizzle schema & SQL migrations:
    - Create `test_definitions`, `reports`, `artifacts`, `identity_profiles`, `credentials` tables.
    - Add missing indexes across all foreign keys and search fields.
    - Add PostgreSQL trigger to `evidence_records` preventing `UPDATE` and `DELETE` (enforcing append-only immutability).
  - Fingerprint algorithm hardening: include `targetId`, `engineId`, `endpoint`, `parameter`, `ruleId`/`cweId` to prevent finding collisions.
  - Finding state machine:
    - If finding seen again: update `lastDetectedAt` and increment `occurrenceCount`.
    - If previously resolved finding is seen again: transition status to `regressed`.
    - If previously open finding is not detected in a comprehensive re-test: transition status to `resolved` and record `fixedAt`.
  - Canonical JSON serialization (RFC 8785) for evidence hashing.
* **Out of scope**: Multi-tenant SaaS schemas (Phase 15).
* **Affected packages**: `@security-lab/domain`, `@security-lab/evidence`.
* **Affected applications**: `@security-lab/controller`.
* **Affected database tables**: All existing tables + 5 new tables.
* **Affected APIs**: Findings API (`GET /api/v1/findings` with status filtering and history).
* **Affected tests**: Database migration and finding lifecycle tests.
* **Security considerations**: Cryptographic tamper detection and database immutability guarantees.
* **Migration considerations**: Forward-only SQL migration (`0004_finding_lifecycle_and_artifacts.sql`).
* **Expected deliverables**: New migration file, updated Drizzle schema, regression intelligence service.
* **Acceptance criteria**: Re-running a scan updates existing findings instead of creating duplicates; fixed and regressed findings are accurately tracked.
* **Validation commands**: `pnpm test`.
* **Rollback strategy**: Revert migration and code.
* **Definition of Done**: Finding lifecycle state machine verified by comprehensive regression tests.
* **Next-phase dependency**: Unlocks Phase 11.

---

### Phase 11 — Policy Engine v2 & Release Governance
* **Objective**: Expand the policy engine to support mandatory test profile enforcement, waiver exemptions with expiration dates, and signed release records.
* **Why this phase exists**: Current policies only check severity counts and P95 latency. Enterprise CI/CD release gates require enforcing that specific test profiles actually ran, and need waiver workflows for known risks.
* **Current-state dependencies**: `packages/policy-engine/src/index.ts`, `apps/controller/src/services/releases.service.ts`.
* **Prerequisites**: Phase 10.
* **Implementation scope**:
  - Policy schema expansions:
    - `requiredProfiles`: list of profiles that must be executed (e.g. `['headers', 'tls', 'authorization']`).
    - `waivers`: list of exempted finding fingerprints with `reason`, `approvedBy`, and `expiresAt`.
    - `slaThresholds`: per-endpoint latency SLA gates.
  - Cryptographically seal release evaluations: store `evaluatorHash` and git commit SHA in `releases` table.
  - CLI `security-lab gate evaluate` outputs structured GitHub Actions job summaries and step outputs.
* **Out of scope**: Visual dashboard waiver approval modal (Phase 14).
* **Affected packages**: `@security-lab/domain`, `@security-lab/policy-engine`, `@security-lab/contracts`.
* **Affected applications**: `@security-lab/controller`, `@security-lab/cli`.
* **Affected database tables**: `policies`, `releases`.
* **Affected APIs**: `POST /api/v1/releases/evaluate`.
* **Affected tests**: `tests/integration/release-gating-and-reports.test.ts`.
* **Security considerations**: Expired waivers must be automatically rejected by the policy engine.
* **Migration considerations**: Forward-only migration adding waiver fields to policy rules JSONB.
* **Expected deliverables**: Policy Engine v2, waiver evaluation logic, CLI gate enhancements.
* **Acceptance criteria**: Release gate fails if a required profile was omitted; valid unexpired waivers allow release with warning; expired waivers block release.
* **Validation commands**: `pnpm test`.
* **Rollback strategy**: Git revert.
* **Definition of Done**: Deterministic release gate decisions with full waiver auditing.
* **Next-phase dependency**: Unlocks Phase 12.

---

### Phase 12 — Enterprise Reporting, Artifact Management & Storage
* **Objective**: Build an artifact persistence subsystem and enhance JUnit, SARIF, and HTML reports with reproducible `curl` commands and execution telemetry.
* **Why this phase exists**: Reports are currently ephemeral; raw scanner artifacts (ZAP logs, Trivy dumps, k6 outputs) are lost post-execution.
* **Current-state dependencies**: `packages/contracts/src/reports/`, `apps/controller/src/services/reports.service.ts`.
* **Prerequisites**: Phase 10, Phase 11.
* **Implementation scope**:
  - Implement `ArtifactStorageService`: stores raw execution outputs, scanner logs, and generated reports in a local storage directory (`DATA_DIR/artifacts`) with SHA-256 integrity verification.
  - Persist generated reports in PostgreSQL `reports` table with metadata.
  - Enhance report contents:
    - Add reproducible `curl` commands for every finding based on evidence request.
    - Include git commit, branch, environment, and release decision.
    - Include finding diffs relative to previous baseline run (new, recurring, resolved).
* **Out of scope**: S3/GCS cloud object storage (Phase 15).
* **Affected packages**: `@security-lab/contracts`.
* **Affected applications**: `@security-lab/controller`, `@security-lab/cli`.
* **Affected database tables**: `reports`, `artifacts`.
* **Affected APIs**: `GET /api/v1/test-runs/:id/reports/:reportId/download`, `GET /api/v1/artifacts/:id`.
* **Affected tests**: Report generation tests.
* **Security considerations**: Stored artifacts must be sanitized to prevent directory traversal (`../`).
* **Migration considerations**: Uses `reports` and `artifacts` tables created in Phase 10.
* **Expected deliverables**: Artifact storage service, enhanced reports with curl commands, download APIs.
* **Acceptance criteria**: Reports are stored persistently and downloadable via API and CLI; finding includes working `curl` command.
* **Validation commands**: `pnpm test`.
* **Rollback strategy**: Git revert.
* **Definition of Done**: Every test run produces stored, verifiable report artifacts.
* **Next-phase dependency**: Unlocks Phase 13.

---

### Phase 13 — CLI & CI/CD Pipeline Productization
* **Objective**: Productize the CLI into an enterprise-grade command-line tool with local offline execution, YAML project configurations, and zero-dependency CI integration.
* **Why this phase exists**: Developers want to run fast security audits locally without spinning up a background controller daemon; CI pipelines need a simple binary/action.
* **Current-state dependencies**: `apps/cli/`.
* **Prerequisites**: Phase 01, Phase 06, Phase 11, Phase 12.
* **Implementation scope**:
  - Add standalone local execution mode to CLI: `security-lab run --local --config security-lab.yaml`. Runs Class A engines in-process without requiring a running Fastify controller or PostgreSQL.
  - Add configuration file support: `.securitylab.yaml` defining targets, profiles, and policies.
  - Create native GitHub Action (`.github/actions/security-lab/action.yml`) packaging the CLI and SARIF upload.
  - Implement human-friendly interactive terminal formatters with colors and tables.
* **Out of scope**: Web dashboard changes (Phase 14).
* **Affected packages**: `@security-lab/contracts`.
* **Affected applications**: `@security-lab/cli`.
* **Affected database tables**: None.
* **Affected APIs**: CLI-only features.
* **Affected tests**: CLI command integration tests.
* **Security considerations**: Local execution must respect all scope and SSRF security boundaries.
* **Migration considerations**: None.
* **Expected deliverables**: Standalone CLI runner, `.securitylab.yaml` parser, reusable GitHub Action.
* **Acceptance criteria**: `security-lab run --local` executes target assertions and outputs SARIF directly in terminal in < 2 seconds.
* **Validation commands**: `pnpm --filter @security-lab/cli test`.
* **Rollback strategy**: Git revert.
* **Definition of Done**: CLI works both as a REST client to the controller and as an autonomous local runner.
* **Next-phase dependency**: Unlocks Phase 14.

---

### Phase 14 — Web Dashboard Productization & Real-Time Telemetry
* **Objective**: Upgrade the React dashboard with real-time execution progress, interactive finding triage, latency percentile charts, and policy editors.
* **Why this phase exists**: The current dashboard relies on manual polling, lacks visualization for latency distributions, and cannot perform finding triage (marking false positives or waivers).
* **Current-state dependencies**: `apps/dashboard/`.
* **Prerequisites**: Phase 10, Phase 11, Phase 12.
* **Implementation scope**:
  - Server-Sent Events (SSE) route in controller (`GET /api/v1/test-runs/:id/events`) streaming execution progress.
  - Dashboard live run progress bar with real-time log stream.
  - Finding triage interface: mark finding as `false_positive` or `resolved`, view evidence diffs, copy `curl` reproduction command.
  - Latency SLA visualizer: percentile curve chart (p50, p90, p95, p99).
  - Visual policy editor and release gate simulator.
* **Out of scope**: Multi-tenant auth UI (Phase 15).
* **Affected packages**: None.
* **Affected applications**: `@security-lab/dashboard`, `@security-lab/controller`.
* **Affected database tables**: None.
* **Affected APIs**: SSE events endpoint, finding status update endpoint.
* **Affected tests**: Dashboard component tests and E2E workflow tests.
* **Security considerations**: Prevent XSS in log streaming view; sanitize finding comments.
* **Migration considerations**: None.
* **Expected deliverables**: Real-time SSE streaming, interactive triage UI, latency chart components.
* **Acceptance criteria**: Test execution updates in real-time on dashboard without page refresh; users can triage findings.
* **Validation commands**: `pnpm --filter @security-lab/dashboard test`, `pnpm --filter @security-lab/dashboard build`.
* **Rollback strategy**: Git revert.
* **Definition of Done**: Dashboard provides complete visual lifecycle management for AppSec teams.
* **Next-phase dependency**: Unlocks Phase 15.

---

### Phase 15 — Distributed Agent Architecture & Hybrid Cloud / SaaS Foundation
* **Objective**: Decouple the controller into a centralized control plane and distributed lightweight execution agents for enterprise and hybrid cloud deployments.
* **Why this phase exists**: Enterprise organizations cannot execute active scans or stress tests against private VPCs from a public cloud; they require distributed agents running behind corporate firewalls reporting back to a central console.
* **Current-state dependencies**: `@security-lab/controller`, `@security-lab/test-sdk`.
* **Prerequisites**: Phase 03, Phase 10, Phase 12.
* **Implementation scope**:
  - Define Agent-to-Control-Plane protocol (WebSocket / gRPC with mTLS and mutual API token auth).
  - Extract agent worker daemon: pulls test jobs from queue, executes in local container/native sandbox, streams progress and results back.
  - Multi-tenant tenant ID isolation across database schemas.
  - Agent registration, heartbeat, and health monitoring APIs.
* **Out of scope**: Public billing and multi-region routing.
* **Affected packages**: `@security-lab/test-sdk`, `@security-lab/contracts`.
* **Affected applications**: New `apps/agent`, `@security-lab/controller`.
* **Affected database tables**: `agents`, `tenants`.
* **Affected APIs**: Agent communication APIs.
* **Affected tests**: Agent-controller protocol integration tests.
* **Security considerations**: Cryptographic attestation of agent identity and token rotation.
* **Migration considerations**: Add `tenant_id` to database tables.
* **Expected deliverables**: `apps/agent` worker application, agent registration APIs, protocol specification.
* **Acceptance criteria**: Agent runs in an isolated network, connects out to controller, receives test dispatch, and safely returns normalized findings.
* **Validation commands**: `pnpm test`.
* **Rollback strategy**: Git revert.
* **Definition of Done**: Control plane orchestrates multiple distributed agents cleanly.

---

### Phase 16 — Distributed Agent Trust Boundary & Secure Execution Plane
* **Objective**: Transform distributed agent execution into a cryptographically verified, tenant-isolated, atomic, and secure execution plane.
* **Why this phase exists**: Phase 15 proved distributed execution viability, but an architectural audit revealed critical trust boundary vulnerabilities: unauthenticated agent enrollment, client-controlled tenant headers, cross-tenant job completion, non-atomic polling races, unsigned findings, and privileged Docker socket mounts. Phase 16 closes every vulnerability.
* **Current-state dependencies**: Phase 15 code baseline.
* **Prerequisites**: Phase 15.
* **Implementation scope**:
  - Divided into 11 sub-phases (16.0 to 16.10).
  - Pre-shared Tenant Enrollment Keys (TEK), token expiration, revocation, and rotation.
  - Contextual tenant derivation (eliminate client header trust).
  - Atomic leasing (`FOR UPDATE SKIP LOCKED`), lease timeouts, and background watchdog reaper.
  - Result attestation HMAC signatures and idempotent completion deduplication.
  - Cryptographically signed target scopes and in-agent metadata SSRF defenses.
  - Bidirectional cancellation propagation and rate limiting.
  - Elimination of Docker socket mounts from deployment manifests.
  - Protocol versioning headers and capability-based routing.
  - Append-only security audit event logging.
  - Comprehensive adversarial penetration testing.
* **Out of scope**: Public billing, enterprise SSO (SAML/OIDC).
* **Affected packages**: `@security-lab/contracts`, `@security-lab/domain`, `@security-lab/test-sdk`.
* **Affected applications**: `apps/controller`, `apps/agent`.
* **Affected database tables**: `tenant_enrollment_keys`, `agent_audit_events`, alter `agents`, alter `agent_jobs`.
* **Affected APIs**: All agent endpoints (`/register`, `/heartbeat`, `/poll`, `/jobs/*`).
* **Affected tests**: `tests/security/distributed-agent-boundaries.test.ts`, `tests/security/distributed-agent-penetration.test.ts`.
* **Security considerations**: Cryptographic result attestation, CIS benchmark compliance, complete cross-tenant barrier.
* **Migration considerations**: Forward-only SQL migration `0007_agent_trust_boundary.sql`.
* **Expected deliverables**: Hardened agent daemon, secure controller dispatcher, 11 sub-phase prompt library, adversarial test battery.
* **Acceptance criteria**: 100% of 18 threat scenarios demonstrably mitigated in automated tests; zero regressions across existing 269 tests.
* **Validation commands**: `pnpm test && pnpm run typecheck && pnpm run lint`.
* **Rollback strategy**: Git revert.
* **Definition of Done**: A controller can safely dispatch an authorized test job to a remote agent, and the platform can cryptographically and deterministically establish authentic execution without breaking tenant isolation or local-first operation.

---

## 5. Implementation Roadmap Summary Matrix

| Phase | Phase Name | Primary Objective | Risk Addressed | Target Horizon |
| :---: | :--- | :--- | :---: | :---: |
| **00** | Codebase Baseline Correction | Reconcile docs with actual code reality | Deceptive completion claims | **Local MVP** |
| **01** | Security Boundary Hardening | Eliminate SSRF, DNS rebinding, redirect escapes | **CRITICAL (P0)** SSRF | **Local MVP** |
| **02** | Container Runner Hardening | Secure Docker execution, drop caps, no root | **CRITICAL (P0)** Host Takeover | **Local MVP** |
| **03** | Engine Registry & Queue | Pluggable registry, async queue, cancellation | Server blocking & lack of control | **Local MVP** |
| **04** | Real Scanner Runners | Host-volume report transport for ZAP & Trivy | Misleading mock fallbacks | **Local MVP** |
| **05** | Real k6 Resilience Runner | True containerized k6 load generator | Inaccurate fetch concurrency | **Local MVP** |
| **06** | Declarative DSL v2 | Request bodies, path vars, multi-step chains | Expressiveness limitations | **Team V1** |
| **07** | Authentication Testing | Dedicated JWT, cookie, session security engine | Missing auth vulnerability checks | **Team V1** |
| **08** | Authorization & BOLA | Identity profiles, permission matrix, IDOR | Critical API vuln blindspot | **Team V1** |
| **09** | Security Contracts | Automated OpenAPI specification auditing | Unaligned API security standards | **Enterprise V2** |
| **10** | Database & Finding Lifecycle | Indexes, triggers, regression state machine | Duplicate findings & data collisions | **Enterprise V2** |
| **11** | Policy Engine v2 | Required test enforcement & waiver auditing | Gating compliance gaps | **Enterprise V2** |
| **12** | Enterprise Reporting | Artifact persistence, reproduction curl commands | Ephemeral reports & lost logs | **Enterprise V2** |
| **13** | CLI Productization | Offline local runner, GitHub Action | High friction for developers | **Enterprise V2** |
| **14** | Dashboard Productization | Real-time SSE progress, finding triage, charts | Lack of visibility & triage UI | **Enterprise V2** |
| **15** | Distributed Agent Architecture | Decoupled agent worker for private VPCs | Inability to test internal networks | **SaaS / Hybrid** |
| **16** | Distributed Agent Trust Boundary | Cryptographic attestation, atomic leases, tenant isolation | **CRITICAL (P0)** Agent Hijack & Forgery | **SaaS Trust Boundary** |

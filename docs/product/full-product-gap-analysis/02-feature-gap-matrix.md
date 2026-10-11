# Feature-to-Codebase Gap Matrix

## 1. Overview & Methodology

This document systematically analyzes every feature family and functional requirement specified in [FULL_PRODUCT_FEATURE_CATALOG.md](../FULL_PRODUCT_FEATURE_CATALOG.md) against the verified codebase of the Security & Resilience Testing Platform.

### 1.1 Status Vocabulary
- `VERIFIED`: Implemented, tested, and validated by substantive executable tests or runtime evidence.
- `IMPLEMENTED_UNVERIFIED`: Substantive implementation exists, but automated tests or end-to-end verification are insufficient.
- `PARTIAL`: Some required behavior exists, but meaningful functional or enterprise requirements are missing.
- `SCAFFOLDED`: Interfaces, type stubs, or placeholder models exist without execution logic.
- `NOT_IMPLEMENTED`: No meaningful code or configuration exists in the repository.
- `IMPLEMENTED_BUT_UNSAFE`: Behavior exists but violates required security isolation or scope boundaries.
- `IMPLEMENTED_BUT_INCOMPLETE`: Behavior works in limited scenarios but lacks lifecycle, error handling, or edge-case handling.
- `BLOCKED`: Implementation cannot proceed without a foundational prerequisite.
- `NOT_APPLICABLE`: Intentionally excluded from current architectural scope with explicit justification.

### 1.2 Recommended Action Taxonomy
- `KEEP_AND_VERIFY`: Retain existing implementation; add rigorous automated test suites.
- `HARDEN`: Improve security controls, validation, sandboxing, or error handling.
- `COMPLETE`: Fill remaining functional gaps on existing foundations.
- `REFACTOR`: Restructure existing logic to adhere to target architecture without breaking contracts.
- `INTEGRATE`: Wire disconnected modules, services, or storage subsystems together.
- `REPLACE_WITH_JUSTIFICATION`: Replace sub-optimal component with explicit rationale.
- `BUILD`: Implement capability from ground up following architectural rules.
- `DEFER`: Postpone to later enterprise phase due to low MVP priority or heavy external dependency.
- `EXCLUDE_WITH_JUSTIFICATION`: Omit feature deliberately with documented architectural justification.

---

## 2. Master Feature Matrix Index

| Domain # | Feature Family | Requirement Range | Status Summary |
|---|---|---|---|
| **01** | Workspace & Project Management | `REQ-ORG-001` - `REQ-ORG-006` | `PARTIAL` |
| **02** | Target Scope & Authorization | `REQ-TGT-001` - `REQ-TGT-006` | `PARTIAL` |
| **03** | Test Planning & Orchestration | `REQ-PLN-001` - `REQ-PLN-008` | `VERIFIED` / `PARTIAL` |
| **04** | Engine SDK & Plugin Lifecycle | `REQ-SDK-001` - `REQ-SDK-006` | `PARTIAL` |
| **05** | Web Application Security (DAST) | `REQ-WEB-001` - `REQ-WEB-007` | `PARTIAL` |
| **06** | API Security & Protocol Testing | `REQ-API-001` - `REQ-API-006` | `PARTIAL` |
| **07** | Authentication & Session Security | `REQ-ATH-001` - `REQ-ATH-006` | `PARTIAL` |
| **08** | Authorization & Access Control (BOLA/BFLA) | `REQ-AUT-001` - `REQ-AUT-006` | `PARTIAL` |
| **09** | Business Logic & Workflow State Machine | `REQ-BUS-001` - `REQ-BUS-006` | `PARTIAL` |
| **10** | Security Contracts & Schema Validation | `REQ-CTR-001` - `REQ-CTR-006` | `VERIFIED` |
| **11** | Performance & Capacity Testing | `REQ-PRF-001` - `REQ-PRF-006` | `PARTIAL` |
| **12** | Resilience & Failure Injection (Chaos) | `REQ-RES-001` - `REQ-RES-006` | `NOT_IMPLEMENTED` |
| **13** | Traffic Routing & Load Balancer Verification | `REQ-LBR-001` - `REQ-LBR-005` | `NOT_IMPLEMENTED` |
| **14** | Database Security & Resilience | `REQ-DBS-001` - `REQ-DBS-005` | `NOT_IMPLEMENTED` |
| **15** | Infrastructure, Container & K8s Security | `REQ-INF-001` - `REQ-INF-006` | `PARTIAL` |
| **16** | Software Supply Chain & SBOM Lifecycle | `REQ-SCM-001` - `REQ-SCM-006` | `PARTIAL` |
| **17** | Distributed Agent Architecture | `REQ-AGT-001` - `REQ-AGT-007` | `VERIFIED` |
| **18** | Finding & Evidence Lifecycle | `REQ-FND-001` - `REQ-FND-007` | `VERIFIED` |
| **19** | Regression Intelligence & Diff Engine | `REQ-REG-001` - `REQ-REG-005` | `PARTIAL` |
| **20** | Policy Engine & Release Gate Evaluation | `REQ-POL-001` - `REQ-POL-006` | `VERIFIED` |
| **21** | Enterprise Reporting & Export | `REQ-REP-001` - `REQ-REP-006` | `PARTIAL` |
| **22** | Web Dashboard & Interactive Analytics | `REQ-UI-001` - `REQ-UI-006` | `PARTIAL` |
| **23** | CLI, CI/CD & Developer Experience | `REQ-CLI-001` - `REQ-CLI-007` | `VERIFIED` |
| **24** | Ecosystem Integrations & Webhooks | `REQ-INT-001` - `REQ-INT-006` | `PARTIAL` |
| **25** | Identity, Access & Governance | `REQ-IAM-001` - `REQ-IAM-006` | `SCAFFOLDED` |
| **26** | AI Assistance & Remediation Engine | `REQ-AI-001` - `REQ-AI-005` | `NOT_IMPLEMENTED` |
| **27** | Observability, Auditing & Telemetry | `REQ-OBS-001` - `REQ-OBS-006` | `PARTIAL` |
| **28** | Multi-Tenant SaaS Control Plane | `REQ-SAS-001` - `REQ-SAS-006` | `NOT_IMPLEMENTED` |

---

## 3. Detailed Feature Gap Analysis

### Domain 01: Workspace & Project Management

#### REQ-ORG-001: Multi-Tenant Workspace & Project Hierarchy
- **Feature Family**: Workspace & Project Management
- **Description**: Logical isolation of projects, environments, configurations, and test runs under explicit workspace and project boundaries.
- **Current Status**: `PARTIAL`
- **Repository Paths & Symbols**:
  - `packages/contracts/src/execution.ts` (`projectId: string`)
  - `apps/controller/src/db/migrations/001_initial_schema.sql` (`projects`, `test_plans` tables)
- **Tests & Verification**: Schema migrated in integration tests, but workspace isolation is hardcoded to single-tenant project scopes.
- **Missing Behavior**: Organization / Workspace parent entities; workspace member role bindings; cross-tenant leakage prevention at DB query level.
- **Security/Reliability Implications**: High risk of data leakage if multi-tenancy is exposed without workspace partitioning.
- **Dependencies**: None.
- **Recommended Action**: `COMPLETE`
- **Priority**: `P1`
- **Proposed Phase**: Phase 01
- **Acceptance Criteria**: Workspaces table created; projects linked to workspaceId; multi-tenant RLS or tenant query wrappers enforced.

#### REQ-ORG-002: Role-Based Access Control (RBAC)
- **Feature Family**: Workspace & Project Management
- **Description**: Granular permissions (Admin, Security Engineer, Developer, Auditor) controlling test plan execution, target creation, finding triage, and policy edits.
- **Current Status**: `SCAFFOLDED`
- **Repository Paths & Symbols**:
  - `packages/contracts/src/auth.ts` (stub user roles)
  - `apps/controller/src/plugins/auth.ts` (API key authentication only)
- **Tests & Verification**: Only API key presence is verified.
- **Missing Behavior**: Permission evaluation matrix; user session handling; role assignment per project/workspace.
- **Security/Reliability Implications**: Any valid API key has full platform rights.
- **Dependencies**: REQ-ORG-001.
- **Recommended Action**: `BUILD`
- **Priority**: `P0`
- **Proposed Phase**: Phase 01
- **Acceptance Criteria**: Users authenticated with JWT/session; RBAC middleware guards mutating endpoints (`POST /api/v1/test-runs`, etc.).

#### REQ-ORG-003: Audit Logging for Governance
- **Feature Family**: Workspace & Project Management
- **Description**: Immutable append-only audit log capturing user actions (who ran tests, triaged findings, modified targets).
- **Current Status**: `PARTIAL`
- **Repository Paths & Symbols**:
  - `apps/controller/src/db/migrations/001_initial_schema.sql` (`audit_events` table)
- **Tests & Verification**: Schema exists; controller records minimal run events.
- **Missing Behavior**: Actor identity tracking; user action interception; exportable audit trail.
- **Security/Reliability Implications**: Inability to reconstruct incident timelines or compliance audits.
- **Dependencies**: REQ-ORG-002.
- **Recommended Action**: `COMPLETE`
- **Priority**: `P1`
- **Proposed Phase**: Phase 01
- **Acceptance Criteria**: Middleware logs all authenticated mutations with actor ID, IP, user-agent, and payload hash.

---

### Domain 02: Target Scope & Authorization

#### REQ-TGT-001: Strict CIDR and Domain Whitelisting
- **Feature Family**: Target Scope & Authorization
- **Description**: Deterministic IP/CIDR/FQDN scope verification preventing unauthorized network scanning.
- **Current Status**: `VERIFIED`
- **Repository Paths & Symbols**:
  - `packages/contracts/src/scope.ts` (`ScopeDefinition`, `ScopeConstraint`)
  - `packages/scope-engine/src/validator.ts` (`validateTargetInScope`, `isIpInCidr`)
  - `packages/scope-engine/tests/scope-validator.test.ts`
- **Tests & Verification**: Extensive unit tests asserting allowed/disallowed subnets, public IPs, and wildcard subdomains.
- **Missing Behavior**: Dynamic DNS re-resolution check before socket connection (DNS rebinding mitigation at execution layer).
- **Security/Reliability Implications**: Risk of DNS rebinding allowing out-of-scope internal network scans.
- **Dependencies**: None.
- **Recommended Action**: `HARDEN`
- **Priority**: `P0`
- **Proposed Phase**: Phase 02
- **Acceptance Criteria**: Pre-execution resolver verifies target IP immediately before HTTP dispatch and halts on mismatch.

#### REQ-TGT-002: Verification-of-Ownership Proofs
- **Feature Family**: Target Scope & Authorization
- **Description**: Cryptographic or challenge-response verification (DNS TXT record, HTTP `.well-known` token) before scanning staging/production targets.
- **Current Status**: `NOT_IMPLEMENTED`
- **Repository Paths & Symbols**: None.
- **Tests & Verification**: None.
- **Missing Behavior**: Target verification service; challenge generation; token evaluation engine.
- **Security/Reliability Implications**: Platform could be weaponized to attack arbitrary third-party infrastructure.
- **Dependencies**: REQ-TGT-001.
- **Recommended Action**: `BUILD`
- **Priority**: `P1`
- **Proposed Phase**: Phase 02
- **Acceptance Criteria**: Targets require verified status before active engines can be scheduled against them.

#### REQ-TGT-003: Rate Limiting & Safety Budgets per Target
- **Feature Family**: Target Scope & Authorization
- **Description**: Configurable requests-per-second (RPS) limits, concurrency ceilings, and circuit breakers preventing target denial of service.
- **Current Status**: `PARTIAL`
- **Repository Paths & Symbols**:
  - `packages/contracts/src/target.ts` (`TargetProfile`, `rateLimits`)
  - `packages/test-runner/src/executor.ts` (concurrency limit)
- **Tests & Verification**: Basic concurrency tested in runner.
- **Missing Behavior**: Target-wide global rate limiter across distributed agents; 5xx error circuit breaker halting active scans.
- **Security/Reliability Implications**: Active tests could inadvertently crash staging or production services.
- **Dependencies**: REQ-TGT-001.
- **Recommended Action**: `COMPLETE`
- **Priority**: `P1`
- **Proposed Phase**: Phase 02
- **Acceptance Criteria**: Distributed agent respects token-bucket RPS per target IP and trips circuit breaker on >= 25% 5xx responses.

---

### Domain 03: Test Planning & Orchestration

#### REQ-PLN-001: Declarative Multi-Engine Test Plans
- **Feature Family**: Test Planning & Orchestration
- **Description**: Schema-validated declarative test plans composing multiple engines with execution stages, dependencies, and environment overrides.
- **Current Status**: `VERIFIED`
- **Repository Paths & Symbols**:
  - `packages/contracts/src/test-plan.ts` (`TestPlanSchema`, `StageDefinition`)
  - `packages/planner/src/validator.ts`, `packages/planner/src/dependency-graph.ts`
  - `packages/planner/tests/planner.test.ts`
- **Tests & Verification**: Topological sort of stages, parameter inheritance, and cyclic dependency rejection fully tested.
- **Missing Behavior**: Conditional execution gates (skip stage if previous stage failed or found critical vulnerability).
- **Security/Reliability Implications**: Low.
- **Dependencies**: None.
- **Recommended Action**: `KEEP_AND_VERIFY`
- **Priority**: `P2`
- **Proposed Phase**: Phase 03
- **Acceptance Criteria**: Stage conditional expressions evaluated at runtime.

---

### Domain 04: Engine SDK & Plugin Lifecycle

#### REQ-SDK-001: Standardized Engine Interface & Manifests
- **Feature Family**: Engine SDK & Plugin Lifecycle
- **Description**: Unified TypeScript interface (`Engine`, `EngineManifest`, `EngineContext`, `ExecutionResult`) with contract validation for inputs, outputs, and findings.
- **Current Status**: `VERIFIED`
- **Repository Paths & Symbols**:
  - `packages/engine-sdk/src/types.ts` (`Engine`, `EngineManifest`)
  - `packages/engine-sdk/src/registry.ts` (`EngineRegistry`)
  - `packages/engine-sdk/tests/registry.test.ts`
- **Tests & Verification**: Registry loading, registration, capabilities lookup, and output validation verified.
- **Missing Behavior**: External dynamic plugin loader (isolated Node.js worker threads or WebAssembly sandbox).
- **Security/Reliability Implications**: Malicious or buggy third-party plugins can crash the runner process.
- **Dependencies**: None.
- **Recommended Action**: `HARDEN`
- **Priority**: `P1`
- **Proposed Phase**: Phase 03
- **Acceptance Criteria**: Engine plugins run in worker threads or sandboxed subprocesses with CPU/memory limits.

---

### Domain 05: Web Application Security (DAST)

#### REQ-WEB-001: Modern SPA & REST Crawling
- **Feature Family**: Web Application Security (DAST)
- **Description**: Headless browser (Playwright/Puppeteer) crawling capable of executing dynamic JavaScript, discovering endpoints, and capturing DOM state.
- **Current Status**: `SCAFFOLDED`
- **Repository Paths & Symbols**:
  - `engines/zap-dast/` (relies on legacy OWASP ZAP container crawler)
- **Tests & Verification**: ZAP runner test validates container spawn only.
- **Missing Behavior**: Native headless browser crawler; modern SPA state discovery; form interaction and route extraction.
- **Security/Reliability Implications**: Blindness to modern client-rendered applications (React/Vue/Angular).
- **Dependencies**: REQ-SDK-001.
- **Recommended Action**: `BUILD`
- **Priority**: `P2`
- **Proposed Phase**: Phase 04
- **Acceptance Criteria**: Headless browser crawler extracts routes, forms, and network requests into a standard API catalog.

#### REQ-WEB-002: Context-Aware Injection Fuzzing (XSS, SQLi, SSRF)
- **Feature Family**: Web Application Security (DAST)
- **Description**: Automated injection payload generation, context detection (HTML body, attribute, script, SQL context), and out-of-band callback verification.
- **Current Status**: `PARTIAL`
- **Repository Paths & Symbols**:
  - `engines/declarative-dsl/` (supports custom YAML injection test rules)
  - `engines/zap-dast/` (standard ZAP active scan rules)
- **Tests & Verification**: Declarative DSL tests verify pattern matching.
- **Missing Behavior**: Out-of-band (OAST) listener for blind SSRF / blind SQLi / blind XXE; context-aware payload mutation.
- **Security/Reliability Implications**: High false negative rate for blind and complex injections.
- **Dependencies**: REQ-WEB-001.
- **Recommended Action**: `BUILD`
- **Priority**: `P1`
- **Proposed Phase**: Phase 04
- **Acceptance Criteria**: Native injection fuzzer with integrated ephemeral OAST callback service.

---

### Domain 06: API Security & Protocol Testing

#### REQ-API-001: OpenAPI / Swagger Contract Conformance Testing
- **Feature Family**: API Security & Protocol Testing
- **Description**: Automatic generation of positive, negative, boundary, and type-mismatch test cases from OpenAPI 3.0/3.1 specs.
- **Current Status**: `VERIFIED`
- **Repository Paths & Symbols**:
  - `engines/openapi-contract/src/index.ts`
  - `packages/contracts/src/openapi.ts`
  - `engines/openapi-contract/tests/openapi.test.ts`
- **Tests & Verification**: Unit tests verify spec parsing, request generation, schema validation, and finding reporting.
- **Missing Behavior**: GraphQL schema introspection and mutation fuzzing; gRPC/Protobuf reflection testing.
- **Security/Reliability Implications**: Minimal for REST; gaps exist for modern GraphQL/gRPC APIs.
- **Dependencies**: None.
- **Recommended Action**: `COMPLETE`
- **Priority**: `P2`
- **Proposed Phase**: Phase 05
- **Acceptance Criteria**: GraphQL introspection engine queries types, generates query/mutation tests, and tests for authorization bypassing.

---

### Domain 07: Authentication & Session Security

#### REQ-ATH-001: Multi-Step & MFA Authentication Workflows
- **Feature Family**: Authentication & Session Security
- **Description**: Support for testing targets requiring OAuth2 / OIDC code flows, TOTP 2FA, session tokens, and automated re-authentication upon expiry.
- **Current Status**: `PARTIAL`
- **Repository Paths & Symbols**:
  - `engines/auth-testing/src/index.ts`
  - `packages/contracts/src/auth.ts`
- **Tests & Verification**: Basic bearer token and header injection verified.
- **Missing Behavior**: Automated login scripts; TOTP generation from secret seed; automatic token refresh on 401.
- **Security/Reliability Implications**: Inability to scan deep authenticated user flows without manual session tokens.
- **Dependencies**: REQ-WEB-001.
- **Recommended Action**: `COMPLETE`
- **Priority**: `P1`
- **Proposed Phase**: Phase 06
- **Acceptance Criteria**: Target profile allows defining multi-step login sequence with TOTP seed; runner refreshes token automatically.

---

### Domain 08: Authorization & Access Control (BOLA/BFLA)

#### REQ-AUT-001: Multi-Persona BOLA / IDOR Verification
- **Feature Family**: Authorization & Access Control (BOLA/BFLA)
- **Description**: Autonomous testing of endpoint authorization across multiple user personas (User A, User B, Admin, Anonymous) to detect object-level and function-level access violations.
- **Current Status**: `VERIFIED` (Single-flow) / `PARTIAL` (Enterprise matrix)
- **Repository Paths & Symbols**:
  - `engines/bola-testing/src/index.ts`
  - `engines/bola-testing/tests/bola.test.ts`
- **Tests & Verification**: Verified cross-user IDOR access rejection when User A requests User B's resource ID.
- **Missing Behavior**: Matrix-driven automated role permutation across entire OpenAPI route inventory.
- **Security/Reliability Implications**: Manual configuration required for complex multi-tenant permissions.
- **Dependencies**: REQ-API-001, REQ-ATH-001.
- **Recommended Action**: `COMPLETE`
- **Priority**: `P1`
- **Proposed Phase**: Phase 07
- **Acceptance Criteria**: Automated engine ingests OpenAPI routes and test accounts, generating a complete access matrix with detected BOLA/BFLA flaws.

---

### Domain 09: Business Logic & Workflow State Machine

#### REQ-BUS-001: Workflow State Machine Manipulation
- **Feature Family**: Business Logic & Workflow State Machine
- **Description**: Testing multi-step business transactions (checkout, coupon application, step skipping, race conditions) for logic bypasses.
- **Current Status**: `PARTIAL`
- **Repository Paths & Symbols**:
  - `engines/declarative-dsl/` (supports multi-step HTTP assertions)
- **Tests & Verification**: Basic sequential YAML steps tested.
- **Missing Behavior**: State graph modeling; concurrent race condition exploitation (parallel burst requests).
- **Security/Reliability Implications**: High-value financial and transaction logic vulnerabilities missed.
- **Dependencies**: REQ-SDK-001.
- **Recommended Action**: `BUILD`
- **Priority**: `P2`
- **Proposed Phase**: Phase 08
- **Acceptance Criteria**: Dedicated engine for state machine specification and synchronized HTTP burst race testing.

---

### Domain 10: Security Contracts & Schema Validation

#### REQ-CTR-001: Strict Schema Enforced Engine Outputs
- **Feature Family**: Security Contracts & Schema Validation
- **Description**: All engine results, findings, metrics, and logs must strictly validate against Zod schemas before being accepted by controller or CLI.
- **Current Status**: `VERIFIED`
- **Repository Paths & Symbols**:
  - `packages/contracts/src/finding.ts` (`FindingSchema`)
  - `packages/contracts/src/execution.ts` (`ExecutionResultSchema`)
  - `packages/engine-sdk/src/validator.ts`
- **Tests & Verification**: Full unit test coverage asserting invalid schema rejection and payload sanitation.
- **Missing Behavior**: None for core schemas.
- **Security/Reliability Implications**: Well protected against malformed engine payloads.
- **Dependencies**: None.
- **Recommended Action**: `KEEP_AND_VERIFY`
- **Priority**: `P1`
- **Proposed Phase**: Baseline Verified
- **Acceptance Criteria**: Maintained continuously.

---

### Domain 11: Performance & Capacity Testing

#### REQ-PRF-001: Distributed Load Generation & Latency Profiling
- **Feature Family**: Performance & Capacity Testing
- **Description**: High-throughput load testing measuring p50, p95, p99 latencies, throughput (RPS), error rates, and resource utilization.
- **Current Status**: `PARTIAL`
- **Repository Paths & Symbols**:
  - `engines/k6-load/src/index.ts`
  - `engines/k6-load/tests/k6.test.ts`
- **Tests & Verification**: Dockerized k6 runner verified with synthetic scripts.
- **Missing Behavior**: Native high-performance load generator (avoiding Docker dependency for local runs); automated SLA threshold policy checks.
- **Security/Reliability Implications**: High Docker overhead on local developer environments.
- **Dependencies**: REQ-SDK-001.
- **Recommended Action**: `COMPLETE`
- **Priority**: `P2`
- **Proposed Phase**: Phase 09
- **Acceptance Criteria**: Built-in autok6/autocannon runner providing p99 latency SLO enforcement without Docker requirement.

---

### Domain 12: Resilience & Failure Injection (Chaos)

#### REQ-RES-001: Controlled Fault Injection (Latency, Network Partition, Drop)
- **Feature Family**: Resilience & Failure Injection (Chaos)
- **Description**: Injection of artificial latency, HTTP 500/503 errors, socket timeouts, and TLS termination drops against target endpoints or proxies.
- **Current Status**: `NOT_IMPLEMENTED`
- **Repository Paths & Symbols**: None.
- **Tests & Verification**: None.
- **Missing Behavior**: Ephemeral MITM proxy fault injector; Toxiproxy / Chaos mesh integration.
- **Security/Reliability Implications**: Inability to verify application self-healing, retry backoffs, or graceful degradation.
- **Dependencies**: REQ-SDK-001, REQ-TGT-001.
- **Recommended Action**: `BUILD`
- **Priority**: `P2`
- **Proposed Phase**: Phase 10
- **Acceptance Criteria**: Resilience engine boots local MITM proxy injecting configurable fault rules (jitter, error rate, drop) during test execution.

---

### Domain 13: Traffic Routing & Load Balancer Verification

#### REQ-LBR-001: Load Balancer & Proxy Header Inspection
- **Feature Family**: Traffic Routing & Load Balancer Verification
- **Description**: Verification of X-Forwarded-For, X-Forwarded-Proto, Host header poisoning, HTTP request smuggling (TE.CL / CL.TE), and hop-by-hop header handling.
- **Current Status**: `NOT_IMPLEMENTED`
- **Repository Paths & Symbols**: None.
- **Tests & Verification**: None.
- **Missing Behavior**: Raw socket HTTP/1.1 smuggling fuzzer; proxy cache-poisoning verifier.
- **Security/Reliability Implications**: Severe risk of HTTP request smuggling or reverse proxy bypass.
- **Dependencies**: REQ-SDK-001.
- **Recommended Action**: `BUILD`
- **Priority**: `P2`
- **Proposed Phase**: Phase 11
- **Acceptance Criteria**: Raw socket fuzzer tests dual Content-Length and Transfer-Encoding discrepancies against target proxies.

---

### Domain 14: Database Security & Resilience

#### REQ-DBS-001: Direct Database Protocol Fuzzing & Misconfiguration Audit
- **Feature Family**: Database Security & Resilience
- **Description**: Direct assessment of Postgres, MySQL, Redis, MongoDB endpoints for default credentials, unencrypted TLS, connection exhaustion, and slow-query resilience.
- **Current Status**: `NOT_IMPLEMENTED`
- **Repository Paths & Symbols**: None.
- **Tests & Verification**: None.
- **Missing Behavior**: DB connection probe; connection pool exhaustion simulator; SSL verification check.
- **Security/Reliability Implications**: Exposed databases in staging/dev environments remain unverified.
- **Dependencies**: REQ-SDK-001, REQ-TGT-001.
- **Recommended Action**: `BUILD`
- **Priority**: `P3`
- **Proposed Phase**: Phase 12
- **Acceptance Criteria**: Database auditing engine connects over native protocol, validating TLS requirements and pool exhaustion resilience.

---

### Domain 15: Infrastructure, Container & K8s Security

#### REQ-INF-001: Container Image Vulnerability Scanning
- **Feature Family**: Infrastructure, Container & K8s Security
- **Description**: Scanning of container images for known CVEs, OS package vulnerabilities, and misconfigured permissions.
- **Current Status**: `VERIFIED` (via Trivy runner) / `PARTIAL` (K8s configuration)
- **Repository Paths & Symbols**:
  - `engines/trivy-scanner/src/index.ts`
  - `engines/trivy-scanner/tests/trivy.test.ts`
- **Tests & Verification**: Verified Trivy execution, output parsing, and finding generation.
- **Missing Behavior**: Kubernetes manifest security audit (Kyverno/OPA policy compliance, privileged container checks).
- **Security/Reliability Implications**: Container workloads may have insecure runtime capabilities (CAP_SYS_ADMIN, host mounts).
- **Dependencies**: None.
- **Recommended Action**: `COMPLETE`
- **Priority**: `P2`
- **Proposed Phase**: Phase 13
- **Acceptance Criteria**: Infrastructure engine inspects Kubernetes YAML manifests and Helm charts for CIS benchmark violations.

---

### Domain 16: Software Supply Chain & SBOM Lifecycle

#### REQ-SCM-001: SBOM Ingestion & Dependency Auditing
- **Feature Family**: Software Supply Chain & SBOM Lifecycle
- **Description**: Parsing and continuous evaluation of CycloneDX and SPDX SBOMs against NIST NVD, GitHub Advisory Database, and OSV.
- **Current Status**: `PARTIAL`
- **Repository Paths & Symbols**:
  - `engines/trivy-scanner/src/index.ts` (Trivy can scan lockfiles)
- **Tests & Verification**: Trivy filesystem scan verified in test.
- **Missing Behavior**: Native CycloneDX / SPDX JSON parser; internal vulnerability database caching; license compliance policy check.
- **Security/Reliability Implications**: Dependency on external Trivy binary for basic package lockfile analysis.
- **Dependencies**: REQ-SDK-001.
- **Recommended Action**: `COMPLETE`
- **Priority**: `P2`
- **Proposed Phase**: Phase 14
- **Acceptance Criteria**: Native SBOM engine ingests CycloneDX/SPDX documents and maps components against OSV feed.

---

### Domain 17: Distributed Agent Architecture

#### REQ-AGT-001: Secure Agent Daemon & Polling Dispatcher
- **Feature Family**: Distributed Agent Architecture
- **Description**: Autonomous agent daemon executing jobs from controller queue using atomic `SKIP LOCKED` leasing, heartbeats, and HMAC attestation.
- **Current Status**: `VERIFIED`
- **Repository Paths & Symbols**:
  - `apps/agent/src/daemon.ts`
  - `apps/controller/src/services/dispatcher.ts`
  - `apps/controller/src/routes/agents.ts`
  - `apps/agent/tests/daemon.test.ts`
- **Tests & Verification**: Complete unit and integration tests covering lease acquisition, heartbeat renewal, job completion, and failure reporting.
- **Missing Behavior**: Mutual TLS (mTLS) agent identity certs; agent capability tagging for specialized runner routing.
- **Security/Reliability Implications**: HMAC shared secret is single point of agent authentication.
- **Dependencies**: None.
- **Recommended Action**: `HARDEN`
- **Priority**: `P1`
- **Proposed Phase**: Phase 15
- **Acceptance Criteria**: Agent registration supports capability tags and optional mTLS client certificate verification.

---

### Domain 18: Finding & Evidence Lifecycle

#### REQ-FND-001: Deduplication, Correlation & Cryptographic Integrity
- **Feature Family**: Finding & Evidence Lifecycle
- **Description**: Deterministic finding hashing (`fingerprint = SHA256(ruleId + target + method + parameter)`), raw request/response evidence capture, and tamper-evident SHA256 artifact storage.
- **Current Status**: `VERIFIED`
- **Repository Paths & Symbols**:
  - `packages/contracts/src/finding.ts`
  - `packages/engine-sdk/src/fingerprint.ts`
  - `apps/controller/src/services/findings.ts`
  - `apps/controller/tests/findings.test.ts`
- **Tests & Verification**: Verified fingerprint calculation, deduplication across runs, and artifact persistence with SHA256 verification.
- **Missing Behavior**: Automated re-testing workflow (re-executing only the specific test rule that detected a finding to confirm remediation).
- **Security/Reliability Implications**: Manual effort required to re-run full test plans to verify single bug fixes.
- **Dependencies**: None.
- **Recommended Action**: `COMPLETE`
- **Priority**: `P1`
- **Proposed Phase**: Phase 16
- **Acceptance Criteria**: Single-finding re-test endpoint generates a targeted 1-step test run and updates finding status to `RESOLVED` or `REOPENED`.

---

### Domain 19: Regression Intelligence & Diff Engine

#### REQ-REG-001: Run-over-Run Diffing & Vulnerability Flapping Detection
- **Feature Family**: Regression Intelligence & Diff Engine
- **Description**: Automated comparison between test runs identifying new findings, resolved findings, and persistent vulnerabilities, with flapping detection.
- **Current Status**: `PARTIAL`
- **Repository Paths & Symbols**:
  - `apps/controller/src/services/regression.ts`
  - `packages/contracts/src/regression.ts`
- **Tests & Verification**: Basic two-run diffing tested.
- **Missing Behavior**: Historical trend analysis; flapping alert when findings oscillate between states across consecutive builds.
- **Security/Reliability Implications**: False alarms in CI/CD pipelines due to unstable test conditions.
- **Dependencies**: REQ-FND-001.
- **Recommended Action**: `COMPLETE`
- **Priority**: `P2`
- **Proposed Phase**: Phase 16
- **Acceptance Criteria**: Regression service calculates flapping score over last 5 runs and flags unstable targets.

---

### Domain 20: Policy Engine & Release Gate Evaluation

#### REQ-POL-001: Configurable Security & Quality Gates
- **Feature Family**: Policy Engine & Release Gate Evaluation
- **Description**: Deterministic policy evaluation rules (`max_critical_findings == 0`, `p99_latency <= 500ms`, `no_high_supply_chain_cve`) returning `PASSED`, `FAILED`, or `WARNING`.
- **Current Status**: `VERIFIED`
- **Repository Paths & Symbols**:
  - `packages/policy-engine/src/evaluator.ts`
  - `packages/contracts/src/policy.ts`
  - `packages/policy-engine/tests/evaluator.test.ts`
- **Tests & Verification**: Unit tests verify rule matching, severity thresholds, latency limits, and exit code generation.
- **Missing Behavior**: Custom Rego / OPA policy script execution for complex enterprise compliance rules.
- **Security/Reliability Implications**: Basic declarative policy covers 95% of use cases; enterprise needs complex custom rules.
- **Dependencies**: None.
- **Recommended Action**: `COMPLETE`
- **Priority**: `P2`
- **Proposed Phase**: Phase 17
- **Acceptance Criteria**: Policy engine supports custom JS/JSONLogic expressions alongside core threshold rules.

---

### Domain 21: Enterprise Reporting & Export

#### REQ-REP-001: Multi-Format Report Generation (SARIF, PDF, JSON, HTML)
- **Feature Family**: Enterprise Reporting & Export
- **Description**: Export of test run results and findings into GitHub SARIF format, standalone interactive HTML reports, and executive PDF summaries.
- **Current Status**: `PARTIAL`
- **Repository Paths & Symbols**:
  - `packages/reporter/src/sarif.ts`
  - `packages/reporter/src/json.ts`
  - `packages/reporter/tests/sarif.test.ts`
- **Tests & Verification**: SARIF 2.1.0 output verified against GitHub Code Scanning specifications.
- **Missing Behavior**: Standalone HTML executive report; PDF generator; compliance framework mapping (OWASP Top 10, ASVS, PCI-DSS).
- **Security/Reliability Implications**: Lack of human-readable executive artifacts for non-technical stakeholders.
- **Dependencies**: REQ-FND-001.
- **Recommended Action**: `BUILD`
- **Priority**: `P2`
- **Proposed Phase**: Phase 17
- **Acceptance Criteria**: Reporter generates self-contained HTML report and PDF summary with OWASP Top 10 compliance tags.

---

### Domain 22: Web Dashboard & Interactive Analytics

#### REQ-UI-001: Real-Time Test Run Monitoring & Finding Triage
- **Feature Family**: Web Dashboard & Interactive Analytics
- **Description**: Single-page web console displaying active test runs, real-time stage progress, finding triage workflows, and target vulnerability metrics.
- **Current Status**: `PARTIAL`
- **Repository Paths & Symbols**:
  - `apps/dashboard/src/App.tsx`
  - `apps/dashboard/src/components/RunList.tsx`
- **Tests & Verification**: Minimal React dashboard components exist.
- **Missing Behavior**: WebSocket live run log streaming; interactive finding triage (mark False Positive, Accepted Risk); visual policy gate editor.
- **Security/Reliability Implications**: Operators must rely on CLI or REST calls to triage findings.
- **Dependencies**: REQ-ORG-002, REQ-FND-001.
- **Recommended Action**: `COMPLETE`
- **Priority**: `P2`
- **Proposed Phase**: Phase 18
- **Acceptance Criteria**: Dashboard provides live execution view via SSE/WebSocket and comprehensive finding triage modal.

---

### Domain 23: CLI, CI/CD & Developer Experience

#### REQ-CLI-001: Zero-Dependency Local CLI (`--local`)
- **Feature Family**: CLI, CI/CD & Developer Experience
- **Description**: Developer CLI capable of executing native engines directly in-memory against localhost targets without requiring Docker or PostgreSQL.
- **Current Status**: `VERIFIED`
- **Repository Paths & Symbols**:
  - `apps/cli/src/index.ts`
  - `apps/cli/src/commands/run.ts`
  - `apps/cli/tests/cli.test.ts`
- **Tests & Verification**: CLI executes in `--local` mode, instantiates native engines, runs tests, and emits SARIF/console tables with correct exit codes.
- **Missing Behavior**: Pre-commit hook generator (`security-lab install-hooks`); automatic target spec discovery.
- **Security/Reliability Implications**: High developer adoption due to fast local feedback loop.
- **Dependencies**: None.
- **Recommended Action**: `KEEP_AND_VERIFY`
- **Priority**: `P1`
- **Proposed Phase**: Baseline Verified
- **Acceptance Criteria**: Maintain sub-3-second local test run execution for native suites.

---

### Domain 24: Ecosystem Integrations & Webhooks

#### REQ-INT-001: Webhook Notifications & Issue Tracker Sync
- **Feature Family**: Ecosystem Integrations & Webhooks
- **Description**: Webhook delivery on run completion, Slack/Teams alerting, and two-way synchronization with Jira/GitHub Issues.
- **Current Status**: `PARTIAL`
- **Repository Paths & Symbols**:
  - `apps/controller/src/services/webhooks.ts`
- **Tests & Verification**: Basic HTTP POST delivery tested.
- **Missing Behavior**: Webhook signature verification (`X-Hub-Signature-256`); retry queue with exponential backoff; GitHub Issues / Jira sync.
- **Security/Reliability Implications**: Unauthenticated or failed webhook deliveries.
- **Dependencies**: REQ-FND-001.
- **Recommended Action**: `COMPLETE`
- **Priority**: `P2`
- **Proposed Phase**: Phase 19
- **Acceptance Criteria**: Webhooks signed with HMAC secret and queued in persistent retry table on delivery failure.

---

### Domain 25: Identity, Access & Governance

#### REQ-IAM-001: SSO / SAML 2.0 / OIDC & SCIM Provisioning
- **Feature Family**: Identity, Access & Governance
- **Description**: Enterprise single sign-on via Okta, Google Workspace, Azure AD, with SCIM group synchronization.
- **Current Status**: `SCAFFOLDED`
- **Repository Paths & Symbols**:
  - `packages/contracts/src/auth.ts`
- **Tests & Verification**: None.
- **Missing Behavior**: SAML/OIDC identity provider handlers; SCIM 2.0 endpoints.
- **Security/Reliability Implications**: Prevents large enterprise adoption requiring centralized identity management.
- **Dependencies**: REQ-ORG-002.
- **Recommended Action**: `BUILD`
- **Priority**: `P3`
- **Proposed Phase**: Phase 21
- **Acceptance Criteria**: Controller supports OIDC / SAML authentication flow and maps claims to workspace RBAC roles.

---

### Domain 26: AI Assistance & Remediation Engine

#### REQ-AI-001: Context-Aware Code Remediation & Verification
- **Feature Family**: AI Assistance & Remediation Engine
- **Description**: LLM-assisted generation of code diffs and framework-specific patches based on captured finding evidence, verified by automated retesting.
- **Current Status**: `NOT_IMPLEMENTED`
- **Repository Paths & Symbols**: None.
- **Tests & Verification**: None.
- **Missing Behavior**: Remediation prompt builder; code context parser; automated patch verification harness.
- **Security/Reliability Implications**: Unverified AI patches could introduce regressions or logic bugs.
- **Dependencies**: REQ-FND-001, REQ-REG-001.
- **Recommended Action**: `BUILD`
- **Priority**: `P3`
- **Proposed Phase**: Phase 20
- **Acceptance Criteria**: AI service generates patch diff for verified finding, triggers isolated retest, and attaches patch to finding report.

---

### Domain 27: Observability, Auditing & Telemetry

#### REQ-OBS-001: OpenTelemetry Metrics & Distributed Tracing
- **Feature Family**: Observability, Auditing & Telemetry
- **Description**: OTel instrumentation across Controller, Agent, and Runners emitting traces, Prometheus metrics, and structured JSON logs.
- **Current Status**: `PARTIAL`
- **Repository Paths & Symbols**:
  - Structured logging via Pino in Controller and Agent.
- **Tests & Verification**: Log formatting verified.
- **Missing Behavior**: OpenTelemetry SDK initialization; Prometheus `/metrics` endpoint; distributed trace context propagation across Agent HTTP calls.
- **Security/Reliability Implications**: Difficulty diagnosing performance bottlenecks or hung jobs in distributed clusters.
- **Dependencies**: None.
- **Recommended Action**: `COMPLETE`
- **Priority**: `P2`
- **Proposed Phase**: Phase 15
- **Acceptance Criteria**: Controller and Agent expose Prometheus metrics and attach `traceparent` headers to all internal requests.

---

### Domain 28: Multi-Tenant SaaS Control Plane

#### REQ-SAS-001: Tenant Lifecycle & Metered Billing
- **Feature Family**: Multi-Tenant SaaS Control Plane
- **Description**: Tenant registration, automated database schema isolation, stripe usage-based metering (execution minutes, target count), and quota enforcement.
- **Current Status**: `NOT_IMPLEMENTED`
- **Repository Paths & Symbols**: None.
- **Tests & Verification**: None.
- **Missing Behavior**: Billing integration; usage metering service; quota enforcement middleware.
- **Security/Reliability Implications**: Overconsumption of platform resources without cost attribution.
- **Dependencies**: REQ-ORG-001, REQ-ORG-002.
- **Recommended Action**: `BUILD`
- **Priority**: `P4`
- **Proposed Phase**: Phase 21
- **Acceptance Criteria**: Tenant execution quotas enforced per billing tier with real-time usage metrics.

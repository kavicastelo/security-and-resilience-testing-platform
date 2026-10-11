# Prioritized Full-Product Implementation Roadmap

## 1. Prioritization Framework & Principles

The implementation sequence is structured according to strict architectural dependencies, security risk reduction, and platform integrity invariants:

### 1.1 Priority Levels
- **`P0` (Blocking Security & Core Integrity)**: Critical access control, scope enforcement, and execution trust boundaries required before expanding capabilities.
- **`P1` (Foundational Capability)**: Prerequisite data models, engine abstractions, and target safety controls required for reliable feature scaling.
- **`P2` (Major Product Capability)**: Core offensive, defensive, and resilience testing features serving primary product workflows.
- **`P3` (Advanced & Enterprise Intelligence)**: Ecosystem integrations, compliance reporting, and AI remediation capabilities.
- **`P4` (Multi-Tenant SaaS Control Plane)**: Commercial billing, tenant self-service, and global public infrastructure.

### 1.2 Core Architectural Principles
1. **Security Precedes Execution**: Never add more destructive or aggressive testing engines without first hardening scope validation, rate-limiting circuit breakers, and target ownership verification.
2. **Local-First Preservation**: Every native capability added to the platform must run in-memory within the CLI (`--local`) without mandatory cloud or container dependencies.
3. **Additive, Non-Breaking Evolution**: Database schemas and shared contracts must evolve through non-breaking additions; existing migrations and verified engine contracts must be preserved.

---

## 2. Roadmap Phase Summary Matrix

| Phase | Title | Priority | Complexity | Primary Gaps Addressed | Dependencies |
|---|---|---|---|---|---|
| **Phase 01** | Core RBAC & Multi-User Workspaces | `P0` | Medium | `REQ-ORG-001`, `REQ-ORG-002`, `REQ-ORG-003` | None |
| **Phase 02** | Advanced Target Scope, DNS Pinning & Ownership Verification | `P0` | Medium | `REQ-TGT-001`, `REQ-TGT-002`, `REQ-TGT-003` | Phase 01 |
| **Phase 03** | Engine SDK Worker Sandboxing & Dynamic Lifecycle | `P1` | Medium | `REQ-SDK-001`, `REQ-PLN-001` | Baseline |
| **Phase 04** | Web Application DAST Crawler & Dynamic Injection Fuzzing | `P1` | Large | `REQ-WEB-001`, `REQ-WEB-002` | Phase 02, Phase 03 |
| **Phase 05** | API Security, GraphQL Introspection & Schema Conformance | `P1` | Medium | `REQ-API-001` | Phase 03 |
| **Phase 06** | Stateful Authentication Flows & Secrets Vault Integration | `P1` | Medium | `REQ-ATH-001` | Phase 01, Phase 04 |
| **Phase 07** | Automated BOLA / BFLA Matrix & Access Graph Evaluation | `P1` | Medium | `REQ-AUT-001` | Phase 05, Phase 06 |
| **Phase 08** | Business Logic State Machine Testing & Race Conditions | `P2` | Medium | `REQ-BUS-001` | Phase 03 |
| **Phase 09** | Native Performance Engineering & Capacity Benchmarking | `P2` | Medium | `REQ-PRF-001` | Phase 03 |
| **Phase 10** | Resilience & Controlled Fault Injection (Chaos MITM) | `P2` | Large | `REQ-RES-001` | Phase 02, Phase 03 |
| **Phase 11** | Traffic Routing & HTTP Request Smuggling Verifier | `P2` | Medium | `REQ-LBR-001` | Phase 03 |
| **Phase 12** | Direct Database Protocol Security & Connection Resilience | `P3` | Medium | `REQ-DBS-001` | Phase 02, Phase 03 |
| **Phase 13** | Kubernetes & Cloud-Native Infrastructure Security Audit | `P2` | Medium | `REQ-INF-001` | Baseline |
| **Phase 14** | Software Supply Chain SBOM Lifecycle & Advisory Feeds | `P2` | Medium | `REQ-SCM-001` | Baseline |
| **Phase 15** | Enterprise Private Agent Fleet Management & Mutual TLS | `P1` | Large | `REQ-AGT-001`, `REQ-OBS-001` | Phase 01 |
| **Phase 16** | Finding Lifecycle Intelligence, Retesting & Flapping Detection | `P1` | Medium | `REQ-FND-001`, `REQ-REG-001` | Baseline |
| **Phase 17** | Enterprise Compliance Reporting (OWASP/ASVS) & PDF Export | `P2` | Medium | `REQ-REP-001`, `REQ-POL-001` | Phase 16 |
| **Phase 18** | Enterprise Operations Console & Interactive Triage Dashboard | `P2` | Large | `REQ-UI-001` | Phase 01, Phase 16 |
| **Phase 19** | CI/CD Ecosystem Integrations, Webhooks & Issue Tracker Sync | `P2` | Medium | `REQ-INT-001` | Phase 16 |
| **Phase 20** | AI-Assisted Security Analysis & Remediation Verification | `P3` | Large | `REQ-AI-001` | Phase 16 |
| **Phase 21** | Multi-Tenant SaaS Control Plane & Enterprise Governance | `P4` | Extra Large | `REQ-SAS-001`, `REQ-IAM-001` | Phase 01, Phase 18 |

---

## 3. Detailed Phase Specifications

### Phase 01: Core RBAC & Multi-User Workspaces
- **Objective**: Establish workspace tenant isolation, user identity, and granular role-based access control.
- **Current Gap**: Controller currently accepts single global API key; lacks user identity, workspace isolation, and RBAC matrix (`REQ-ORG-001`, `REQ-ORG-002`).
- **Dependencies**: None (first foundation phase).
- **In-Scope**:
  - Migration `012_workspaces_and_rbac.sql`.
  - Workspace and project hierarchy models.
  - User session / JWT authentication and API key management with role scopes.
  - Role evaluation middleware (`Admin`, `Engineer`, `Auditor`).
  - Immutable audit logging middleware.
- **Explicitly Excluded**: SAML/OIDC enterprise SSO (deferred to Phase 21); multi-tenant billing.
- **Estimated Complexity**: Medium.

### Phase 02: Advanced Target Scope, DNS Pinning & Ownership Verification
- **Objective**: Prevent unauthorized scanning, DNS rebinding attacks, and accidental target disruption.
- **Current Gap**: Static CIDR checks in `packages/scope-engine` are vulnerable to TOCTOU DNS rebinding; targets lack ownership verification (`REQ-TGT-001`, `REQ-TGT-002`, `REQ-TGT-003`).
- **Dependencies**: Phase 01.
- **In-Scope**:
  - Pre-socket connection DNS pinning in `packages/scope-engine` and `packages/test-runner`.
  - Automatic rejection of loopback, link-local, and RFC-1918 addresses unless private mode is authorized.
  - Target ownership challenges: DNS TXT and HTTP `/.well-known` token verification.
  - Dynamic circuit breaker tripping execution when target emits >= 25% 5xx errors.
- **Explicitly Excluded**: Modifying existing native engine test rules.
- **Estimated Complexity**: Medium.

### Phase 03: Engine SDK Worker Sandboxing & Dynamic Lifecycle
- **Objective**: Isolate engine execution in worker threads with CPU and memory limits to protect runner stability.
- **Current Gap**: Native engines run directly on main thread; an unhandled exception or CPU spin hangs the runner (`REQ-SDK-001`).
- **Dependencies**: Baseline contracts.
- **In-Scope**:
  - `packages/engine-sdk` worker thread runner harness.
  - Per-engine execution timeouts and memory ceilings.
  - Dynamic plugin manifest validator and sandboxed execution wrapper.
- **Explicitly Excluded**: Rewriting existing native engines.
- **Estimated Complexity**: Medium.

### Phase 04: Web Application DAST Crawler & Dynamic Injection Fuzzing
- **Objective**: Provide automated modern SPA crawling and context-aware injection fuzzing (XSS, SQLi, SSRF).
- **Current Gap**: Current DAST relies entirely on external OWASP ZAP Docker container; no modern client-rendered crawling (`REQ-WEB-001`, `REQ-WEB-002`).
- **Dependencies**: Phase 02, Phase 03.
- **In-Scope**:
  - Playwright-based headless browser crawler engine.
  - Context-aware injection fuzzer with ephemeral out-of-band (OAST) callback listener.
  - DOM state and form discovery feeding into standard attack catalog.
- **Explicitly Excluded**: Full web application firewall evasion.
- **Estimated Complexity**: Large.

### Phase 05: API Security, GraphQL Introspection & Schema Conformance
- **Objective**: Expand API contract testing to cover GraphQL schemas and deep mutation fuzzing.
- **Current Gap**: Current `openapi-contract` engine only supports REST/OpenAPI; no GraphQL coverage (`REQ-API-001`).
- **Dependencies**: Phase 03.
- **In-Scope**:
  - Native GraphQL introspection parser and query generator.
  - GraphQL security checks (circular query depth limit, field suggestions leak, unauthorized mutation).
  - Integration with `packages/engine-sdk`.
- **Explicitly Excluded**: gRPC streaming testing (deferred).
- **Estimated Complexity**: Medium.

### Phase 06: Stateful Authentication Flows & Secrets Vault Integration
- **Objective**: Enable scanning authenticated user workflows with automated MFA/TOTP handling and secure credential storage.
- **Current Gap**: Plaintext credentials in database; no automated multi-step login or TOTP generation (`REQ-ATH-001`, `GAP-SEC-04`).
- **Dependencies**: Phase 01, Phase 04.
- **In-Scope**:
  - Envelope encryption (`packages/crypto`) for stored target credentials using AES-256-GCM.
  - Stateful authentication engine supporting OAuth2/OIDC code flows, session cookie handling, and TOTP generation from secret seeds.
  - Automatic token refresh on 401 Unauthorized responses during test runs.
- **Explicitly Excluded**: Hardware security module (HSM) direct integration.
- **Estimated Complexity**: Medium.

### Phase 07: Automated BOLA / BFLA Matrix & Access Graph Evaluation
- **Objective**: Automate role permutation testing across API routes to detect cross-tenant authorization flaws.
- **Current Gap**: Current `bola-testing` engine requires manual endpoint specification; lacks automatic route matrix permutation (`REQ-AUT-001`).
- **Dependencies**: Phase 05, Phase 06.
- **In-Scope**:
  - Automated route-to-role access matrix generator ingesting OpenAPI / GraphQL specs.
  - Autonomous multi-persona execution comparing response status, body size, and payload similarity.
- **Explicitly Excluded**: Modifying business logic engine rules.
- **Estimated Complexity**: Medium.

### Phase 08: Business Logic State Machine Testing & Race Conditions
- **Objective**: Detect workflow state skipping and concurrent race condition vulnerabilities.
- **Current Gap**: Multi-step HTTP testing is limited to basic sequential assertions in `declarative-dsl` (`REQ-BUS-001`).
- **Dependencies**: Phase 03.
- **In-Scope**:
  - State machine workflow engine modeling multi-step business transactions.
  - Synchronized HTTP burst engine using raw sockets to trigger concurrent race conditions.
- **Explicitly Excluded**: Protocol-level TCP state fuzzing.
- **Estimated Complexity**: Medium.

### Phase 09: Native Performance Engineering & Capacity Benchmarking
- **Objective**: High-throughput in-memory load generation without requiring Docker.
- **Current Gap**: Current load testing requires Dockerized k6 container (`REQ-PRF-001`).
- **Dependencies**: Phase 03.
- **In-Scope**:
  - Built-in high-performance HTTP load generator package.
  - Latency profiling (p50, p95, p99, p99.9), RPS, and error rate telemetry.
  - Automated performance SLA threshold policy gates.
- **Explicitly Excluded**: Distributed multi-node load clustering (deferred).
- **Estimated Complexity**: Medium.

### Phase 10: Resilience & Controlled Fault Injection (Chaos MITM)
- **Objective**: Test system resilience and graceful degradation under controlled network failure conditions.
- **Current Gap**: Zero chaos or resilience testing capability in current codebase (`REQ-RES-001`).
- **Dependencies**: Phase 02, Phase 03.
- **In-Scope**:
  - Ephemeral MITM proxy injecting latency, jitter, HTTP error codes, socket drops, and packet truncation.
  - Resilience test runner validating client retry backoff, timeout handling, and fallback behavior.
- **Explicitly Excluded**: Kernel-level or hypervisor-level chaos injection.
- **Estimated Complexity**: Large.

### Phase 11: Traffic Routing & HTTP Request Smuggling Verifier
- **Objective**: Verify reverse proxy header handling and detect HTTP request smuggling (TE.CL, CL.TE).
- **Current Gap**: Zero proxy routing or smuggling verification (`REQ-LBR-001`).
- **Dependencies**: Phase 03.
- **In-Scope**:
  - Raw TCP socket engine sending desynchronized HTTP/1.1 pipelined requests.
  - Reverse proxy header validation (`X-Forwarded-For`, Host header injection).
- **Explicitly Excluded**: HTTP/2 and HTTP/3 multiplexing desynchronization (deferred).
- **Estimated Complexity**: Medium.

### Phase 12: Direct Database Protocol Security & Connection Resilience
- **Objective**: Direct audit of database endpoints for unencrypted TLS, default credentials, and pool exhaustion.
- **Current Gap**: Only HTTP endpoints can be tested currently (`REQ-DBS-001`).
- **Dependencies**: Phase 02, Phase 03.
- **In-Scope**:
  - Protocol probes for PostgreSQL, MySQL, and Redis.
  - TLS enforcement audit, connection pool saturation test, and configuration checks.
- **Explicitly Excluded**: Exploitation of database memory corruption.
- **Estimated Complexity**: Medium.

### Phase 13: Kubernetes & Cloud-Native Infrastructure Security Audit
- **Objective**: Ingest and audit Kubernetes manifests, Helm charts, and container runtime security policies.
- **Current Gap**: Only image CVE scanning is implemented via Trivy container (`REQ-INF-001`).
- **Dependencies**: Baseline contracts.
- **In-Scope**:
  - Static manifest analyzer evaluating PodSecurityStandards, privileged flags, and capabilities.
  - Rule-based evaluation mapping against CIS Kubernetes Benchmark.
- **Explicitly Excluded**: Live Kubernetes cluster node compromise testing.
- **Estimated Complexity**: Medium.

### Phase 14: Software Supply Chain SBOM Lifecycle & Advisory Feeds
- **Objective**: Native CycloneDX / SPDX SBOM parsing and vulnerability evaluation against public advisories.
- **Current Gap**: Relies entirely on external Trivy container for package scanning (`REQ-SCM-001`).
- **Dependencies**: Baseline contracts.
- **In-Scope**:
  - Native CycloneDX (JSON) and SPDX parser.
  - Local caching of OSV (Open Source Vulnerabilities) database feed.
  - License compliance rule evaluation (GPL, AGPL, MIT).
- **Explicitly Excluded**: Proprietary commercial vulnerability intelligence feeds.
- **Estimated Complexity**: Medium.

### Phase 15: Enterprise Private Agent Fleet Management & Mutual TLS
- **Objective**: Secure enterprise agent clusters with per-agent asymmetric cryptographic attestation, mTLS, and capability routing.
- **Current Gap**: Shared symmetric HMAC secret; no capability tagging or mutual TLS (`REQ-AGT-001`, `GAP-SEC-03`).
- **Dependencies**: Phase 01.
- **In-Scope**:
  - Agent registration with unique public keys and enrollment tokens.
  - Mutual TLS (mTLS) listener on controller agent endpoints.
  - Agent capability tagging (`internal-network`, `gpu-enabled`, `dmz-scanner`) and scheduler matching.
  - OpenTelemetry trace propagation and Prometheus metric export.
- **Explicitly Excluded**: Multi-cloud agent mesh overlay network.
- **Estimated Complexity**: Large.

### Phase 16: Finding Lifecycle Intelligence, Retesting & Flapping Detection
- **Objective**: Enable single-finding retesting workflows, historical diffing, and flapping detection.
- **Current Gap**: Users must re-run full test plans to verify single fixes; no vulnerability flapping metrics (`REQ-FND-001`, `REQ-REG-001`).
- **Dependencies**: Baseline finding services.
- **In-Scope**:
  - Targeted single-finding retest runner.
  - Historical regression engine computing flapping scores across consecutive runs.
  - Finding triage state transitions (`CONFIRMED`, `FALSE_POSITIVE`, `ACCEPTED_RISK`, `RESOLVED`).
- **Explicitly Excluded**: Machine learning triage predictions (deferred to Phase 20).
- **Estimated Complexity**: Medium.

### Phase 17: Enterprise Compliance Reporting (OWASP/ASVS) & PDF Export
- **Objective**: Generate executive PDF reports and interactive standalone HTML reports mapped to compliance standards.
- **Current Gap**: Only SARIF and JSON exports exist; no executive PDF or compliance mapping (`REQ-REP-001`).
- **Dependencies**: Phase 16.
- **In-Scope**:
  - Compliance mapping engine (OWASP Top 10 2021, ASVS 4.0, PCI-DSS 4.0).
  - Standalone self-contained HTML report bundle.
  - Headless PDF generation service with executive summaries and severity distribution charts.
- **Explicitly Excluded**: Custom drag-and-drop report layout designer.
- **Estimated Complexity**: Medium.

### Phase 18: Enterprise Operations Console & Interactive Triage Dashboard
- **Objective**: Deliver a full-featured web dashboard for live run monitoring, finding triage, and visual policy editing.
- **Current Gap**: Dashboard is a minimal scaffold (`REQ-UI-001`).
- **Dependencies**: Phase 01, Phase 16.
- **In-Scope**:
  - Live execution streaming via Server-Sent Events (SSE).
  - Interactive finding triage workspace with evidence viewer and syntax highlighting.
  - Visual target profile and test plan configuration builders.
  - Workspace and team member management settings.
- **Explicitly Excluded**: Custom white-label branding.
- **Estimated Complexity**: Large.

### Phase 19: CI/CD Ecosystem Integrations, Webhooks & Issue Tracker Sync
- **Objective**: Integrate seamlessly into GitHub Actions, GitLab CI, Slack, Teams, Jira, and GitHub Issues.
- **Current Gap**: Basic webhook delivery without retries or HMAC signatures (`REQ-INT-001`).
- **Dependencies**: Phase 16.
- **In-Scope**:
  - Signed HMAC webhooks with persistent retry queue and exponential backoff.
  - Two-way issue synchronization with GitHub Issues and Jira.
  - Official GitHub Action and GitLab CI templates for automated release gating.
- **Explicitly Excluded**: Proprietary ITSM platforms (ServiceNow).
- **Estimated Complexity**: Medium.

### Phase 20: AI-Assisted Security Analysis & Remediation Verification
- **Objective**: Provide automated code remediation diffs and explainability for verified findings.
- **Current Gap**: Zero AI or automated remediation assistance (`REQ-AI-001`).
- **Dependencies**: Phase 16.
- **In-Scope**:
  - Contextual prompt builder synthesizing finding evidence, code context, and security rules.
  - Remediation patch generator producing git diffs.
  - Automated verification loop re-running targeted tests against patched test branch.
- **Explicitly Excluded**: Unsupervised production auto-patching without human sign-off.
- **Estimated Complexity**: Large.

### Phase 21: Multi-Tenant SaaS Control Plane & Enterprise Governance
- **Objective**: Enable commercial SaaS operation with tenant billing, enterprise SSO (SAML/OIDC), and SCIM.
- **Current Gap**: Platform is configured for self-hosted single-tenant or internal enterprise deployments (`REQ-SAS-001`, `REQ-IAM-001`).
- **Dependencies**: Phase 01, Phase 18.
- **In-Scope**:
  - SAML 2.0 / OIDC enterprise identity provider integrations.
  - SCIM 2.0 automated user and group provisioning.
  - Metered usage billing (execution minutes, target quotas, seat limits).
  - Cross-tenant data isolation verification suites.
- **Explicitly Excluded**: Multi-region active-active database replication.
- **Estimated Complexity**: Extra Large.

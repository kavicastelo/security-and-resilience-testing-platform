# Product Roadmap & Architecture Horizons

```text
DOCUMENT: docs/architecture/product-roadmap.md
STATUS: RATIFIED ROADMAP
REVISION: 2.0.0
```

---

## 1. Executive Summary & Vision

**Security Lab** bridges the gap between software development and application security engineering. Rather than treating security as an external audit performed late in the software lifecycle, Security Lab delivers automated, reproducible, contract-driven security QA that runs on a developer's workstation, inside local CI/CD pipelines, or across distributed enterprise private agents.

To prevent scope creep and maintain architectural clarity, the platform roadmap is partitioned into four progressive product horizons:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        HORIZON 1: LOCAL MVP                            │
│  Current Release. Hardened, local-first security QA platform.         │
│  Class A/B/C execution, unbreachable scope, forensic evidence sealing. │
├────────────────────────────────────────────────────────────────────────┤
│                        HORIZON 2: TEAM COLLABORATION                   │
│  CI/CD release gating, team workspaces, pull request automation,       │
│  finding regression tracking, and deterministic compliance reporting.  │
├────────────────────────────────────────────────────────────────────────┤
│                        HORIZON 3: ENTERPRISE GOVERNANCE                │
│  Full authorization matrix, OpenAPI contract fuzzing, encrypted vault, │
│  policy waivers, artifact storage, and compliance mapping.             │
├────────────────────────────────────────────────────────────────────────┤
│                        HORIZON 4: SAAS & HYBRID CLOUD                  │
│  Multi-tenant control plane, distributed private agents, mTLS tunnel,  │
│  enterprise RBAC, audit exports, and centralized compliance dashboard. │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Product Horizon Breakdown

### Horizon 1: Local MVP (Current Release — Delivered & Verified)

* **Objective**: Deliver a robust, local-first security testing platform for developers, QA engineers, and application security practitioners that functions completely offline without cloud dependencies.
* **Delivered Capabilities**:
  1. **Hardened Security Boundary & SSRF Shielding**: Strict protocol filtering (HTTP/HTTPS only), IP address canonicalization (handling octal, hex, decimal, and IPv4-mapped IPv6 formats), prohibited CIDR blocking (cloud metadata `169.254.169.254`, loopback, link-local), DNS resolution verification, and redirect re-validation via `safeFetch`.
  2. **Three-Tier Engine Architecture**:
     - **Class A (Native In-Process)**: Sub-second audits of HTTP security headers (CSP, HSTS, X-Frame-Options), CORS configurations, TLS cipher suites, and baseline rate limits.
     - **Class B (Isolated Container Scanners)**: Hardened Docker runners executing OWASP ZAP and Aqua Trivy with dropped Linux capabilities (`--cap-drop=ALL`), non-root UID/GID (`10001:10001`), read-only root filesystems, and temporary scratch volume exchange.
     - **Class C (Resilience & Performance Workers)**: Containerized Grafana k6 runner generating real load scripts, enforcing concurrency caps, and calculating p95/p99 latency percentiles and error ratios.
  3. **Declarative Test DSL**: Stateful, multi-step HTTP test execution supporting JSON request bodies, variable extraction (session cookies, tokens), path and query templating, and deep assertion evaluation.
  4. **Authentication Testing Framework**: Dedicated non-invasive probes verifying JWT algorithm `none` signature bypasses, token expiration enforcement, session cookie flags (`HttpOnly`, `Secure`, `SameSite`), and login route throttling.
  5. **Authorization & BOLA Testing Framework**: Cross-identity permutation testing (evaluating User A vs. User B access) and vertical privilege escalation audits against administrative endpoints.
  6. **Security Contract Engine**: OpenAPI 3.0/3.1 specification ingestion, static contract rule verification, and deterministic negative schema fuzzing.
  7. **Forensic Evidence & Hashing**: RFC 8785 canonical JSON serialization with SHA-256 fingerprinting and database append-only protection.
  8. **Deterministic Policy Gating**: Policy Engine evaluating severity limits, disallowed vulnerability categories, and latency SLAs to produce deterministic gate decisions.
  9. **Console CLI**: Standalone offline mode (`security-lab run --local`) requiring zero daemon dependencies, alongside full REST client commands.
  10. **Web Dashboard & Real-Time Telemetry**: React 18 / Vite single-page application with Server-Sent Events (SSE) streaming execution progress and interactive finding triage.

---

### Horizon 2: Team Collaboration & CI/CD Orchestration (Near-Term)

* **Objective**: Enable engineering organizations to embed automated security contracts into team pull requests and developer workflows with collaborative triage.
* **Planned Capabilities**:
  1. **Automated Pull Request Integration**: GitHub App and GitLab webhook integration posting rich Markdown finding tables and posture scores directly onto pull requests.
  2. **Team Workspaces & Shared Projects**: Role-based access control (RBAC) supporting Admin, Developer, and Security Reviewer roles per project.
  3. **Scheduled Drift Audits**: Background cron triggers executing recurring security audits to detect configuration drift and newly discovered vulnerabilities.
  4. **Finding Triage Collaboration**: Interactive finding lifecycle management with false-positive annotations, developer comments, and two-way Jira / Linear issue synchronization.
  5. **Automated Flaky Test Suppression**: Intelligence layer identifying and dampening non-deterministic network assertions while preserving security-critical findings.

---

### Horizon 3: Enterprise Posture & Compliance Governance

* **Objective**: Standardize security posture governance, regulatory compliance verification, and secrets management across enterprise engineering portfolios.
* **Planned Capabilities**:
  1. **Compliance Evidence Mapping**: Automatic mapping of normalized findings and test evidence to regulatory standards including SOC 2 Type II, ISO 27001, and NIST CSF.
  2. **Enterprise Posture Scoring**: Cross-team security posture aggregations, letter grades (A–F), and trend analysis dashboards for engineering leadership.
  3. **Encrypted Secrets Vault Integration**: Direct integration with HashiCorp Vault, AWS Secrets Manager, and Azure Key Vault for dynamic injection of test credentials without disk persistence.
  4. **Policy Waiver Workflows**: Multi-step approval workflows for temporary finding waivers with mandatory expiration dates and compliance tracking.
  5. **Artifact Storage Connectors**: Pluggable storage providers (AWS S3, Google Cloud Storage, Azure Blob Storage) for long-term retention of raw scanner logs, pcaps, and compliance exports.

---

### Horizon 4: Managed Cloud & Multi-Tenant SaaS

* **Objective**: Provide a globally distributed, multi-tenant SaaS management plane with private execution worker fleets deployed inside customer VPCs.
* **Planned Capabilities**:
  1. **Outbound-Only Private VPC Agents**: Distributed execution worker daemons (`apps/agent`) deployed in Kubernetes or VMs that connect outbound over TLS 1.3 to execute tests against private services without inbound firewall holes.
  2. **Mutual TLS (mTLS) Agent Tunnel**: High-security tunnel using cryptographic mutual certificate authentication and hardware-backed key attestation.
  3. **Multi-Tenant Data Partitioning**: Complete tenant isolation with per-tenant encryption keys, row-level database security, and isolated execution quotas.
  4. **Enterprise Identity Federation**: Single Sign-On (SSO) via SAML 2.0 and OIDC (Okta, Azure AD, Ping Identity) with automated SCIM user provisioning.
  5. **Real-Time Threat Intelligence Ingestion**: Automated synchronization with national vulnerability databases (NVD) and CVE feeds to instantly flag affected components.

---

## 3. Architecture Alignment Summary

| Product Capability | Architectural Location | Primary Contract / Interface |
| :--- | :--- | :--- |
| **Scope Validation & SSRF Guard** | `packages/domain` | `ScopeValidator`, `safeFetch` |
| **Engine Registry & Runners** | `packages/test-sdk` | `TestEngine`, `EngineRegistry`, `DockerRunner` |
| **Declarative DSL & Assertions** | `packages/domain`, `packages/test-sdk` | `DeclarativeTestEngine`, `dsl-v2.schema` |
| **Auth & Authorization Testing** | `packages/test-sdk` | `AuthenticationSecurityEngine`, `AuthorizationSecurityEngine` |
| **OpenAPI Contract Fuzzing** | `packages/test-sdk` | `SecurityContractEngine` |
| **Forensic Evidence & Hashing** | `packages/evidence` | `EvidenceRecord`, RFC 8785 Canonical JSON |
| **Release Gating & Governance** | `packages/policy-engine` | `PolicyEngine`, `ReleaseGateEvaluator` |
| **Offline & Pipeline CLI** | `apps/cli` | `security-lab run --local` |
| **Web Dashboard & Streams** | `apps/dashboard` | SSE Stream `/api/v1/stream` |
| **Distributed Agent Execution** | `apps/agent`, `apps/controller` | Agent Protocol v1.0.0, HMAC Attestation |

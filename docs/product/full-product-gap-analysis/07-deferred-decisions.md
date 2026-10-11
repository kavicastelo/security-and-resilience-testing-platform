# Deferred Architecture & Product Decisions

## 1. Overview & Purpose

This document explicitly captures architectural decisions, enterprise features, and infrastructure complexities that have been deliberately deferred from early implementation phases. 

Premature architectural optimization (such as decomposing into microservices or requiring Kubernetes) increases operational friction without delivering customer value during initial phases. Documenting these decisions prevents accidental scope creep and establishes clear trigger criteria for revisiting them.

---

## 2. Deferred Decisions Registry

### DEC-01: Modular Monolith vs. Microservices Decomposition
- **Proposed Feature / Architecture**: Splitting the Controller into independent microservices (Auth Service, Target Service, Execution Scheduler, Finding Service, Policy Service).
- **Current Decision**: **DEFERRED**. Maintain a clean modular monolith architecture within `apps/controller`.
- **Rationale**:
  - The current Fastify controller handles thousands of requests per second with negligible latency.
  - Decomposing into distributed microservices introduces network latency, distributed transaction overhead, cross-service auth tokens, and complex local developer setup.
  - Modular boundaries inside the monorepo (`src/routes`, `src/services`, `src/db`) provide strong domain separation without operational penalty.
- **Trigger Criteria for Reconsideration**:
  - Controller database connection pool saturation under extreme agent fleet load (> 1,000 concurrent agents).
  - Multiple independent product teams requiring separate release cycles for finding ingestion vs. execution scheduling.
- **Interim Architecture**: Domain-partitioned services within `apps/controller` backed by PostgreSQL row-level locks and read replicas.

---

### DEC-02: Mandatory Kubernetes Deployment vs. Self-Hosted Docker / Host Daemon
- **Proposed Feature / Architecture**: Mandating Kubernetes (K8s) deployment, Helm charts, and custom Kubernetes Operators for all platform deployments.
- **Current Decision**: **DEFERRED**. Retain standalone Docker Compose and bare Node.js daemon support as first-class deployment targets.
- **Rationale**:
  - Mandating Kubernetes violates the core **local-first** product invariant.
  - A significant portion of security engineers and developers test on single workstations, staging VMs, or isolated lab networks where K8s is unavailable or overly cumbersome.
- **Trigger Criteria for Reconsideration**:
  - Customers managing > 500 distributed execution runners requiring dynamic auto-scaling on cloud infrastructure (EKS, GKE, AKS).
- **Interim Architecture**: Agent daemon packaged as both a standalone binary/systemd service and a lightweight Docker container. Kubernetes manifest templates provided as optional add-ons in Phase 13.

---

### DEC-03: External HashiCorp Vault / Cloud KMS Integration vs. Local Envelope Encryption
- **Proposed Feature / Architecture**: Direct runtime dependency on external enterprise secret stores (HashiCorp Vault, AWS KMS, Google Cloud KMS).
- **Current Decision**: **DEFERRED** to Phase 21. Implement standard envelope encryption (`AES-256-GCM`) with local master key configuration first (Phase 06).
- **Rationale**:
  - Requiring HashiCorp Vault breaks zero-dependency local development and simple self-hosted deployments.
  - Envelope encryption with a local master key (provided via environment variable or secret file) provides cryptographic security at rest without external network dependencies.
- **Trigger Criteria for Reconsideration**:
  - Enterprise SOC2 / ISO-27001 requirements demanding hardware-backed key rotation (HSM) or dynamic short-lived credentials.
- **Interim Architecture**: Pluggable `KeyProvider` interface in `packages/crypto`: default `LocalEnvKeyProvider` (AES-256-GCM) with future drop-in `VaultKeyProvider` and `AwsKmsKeyProvider`.

---

### DEC-04: Commercial Vulnerability Threat Intelligence Feeds vs. Open Feeds (OSV / NVD)
- **Proposed Feature / Architecture**: Ingestion and subscription to commercial vulnerability databases (Snyk Intel, Recorded Future).
- **Current Decision**: **DEFERRED**. Utilize open public feeds (OSV - Open Source Vulnerabilities, GitHub Advisory Database, NIST NVD) in Phase 14.
- **Rationale**:
  - Open feeds provide comprehensive, community-validated CVE data without commercial licensing fees or proprietary API keys.
  - Allows zero-friction open-source and self-hosted usage.
- **Trigger Criteria for Reconsideration**:
  - Commercial enterprise customers requesting proprietary zero-day vulnerability feeds and enriched remediation intelligence.
- **Interim Architecture**: Standardized advisory interface allowing pluggable intelligence providers.

---

### DEC-05: Multi-Region Active-Active Database Replication
- **Proposed Feature / Architecture**: Distributed multi-region CockroachDB or Spanner database cluster for active-active multi-region scanning.
- **Current Decision**: **DEFERRED**. Maintain single-region primary PostgreSQL with local read replicas and geo-distributed agents.
- **Rationale**:
  - Distributed SQL engines introduce significant write latencies and operational complexity.
  - Agents can execute in disparate cloud regions worldwide while reporting back to a central regional controller over HTTPS with minimal overhead.
- **Trigger Criteria for Reconsideration**:
  - Data sovereignty regulations (e.g., strict GDPR/CCPA mandates requiring findings and customer data to reside exclusively within specific geographic boundaries).
- **Interim Architecture**: Central controller with geo-distributed agent fleet and tenant data locality routing in Phase 21.

---

### DEC-06: Autonomous Exploitation & Weaponized Post-Exploitation
- **Proposed Feature / Architecture**: Autonomous multi-stage exploitation (e.g., automated remote shell spawning, privilege escalation, credential dumping).
- **Current Decision**: **PERMANENTLY EXCLUDED / DEFERRED**. Platform scope is restricted to vulnerability detection, verification of impact, and non-destructive proof-of-concept capture.
- **Rationale**:
  - Uncontrolled or autonomous exploitation creates extreme legal and operational risk for customers (unintended system outages, data corruption).
  - Safety and resilience testing must be strictly controlled, deterministic, and auditable.
- **Trigger Criteria for Reconsideration**:
  - None for general product. Any specialized red-teaming capability must require multi-party cryptographic authorization and air-gapped sandboxes.

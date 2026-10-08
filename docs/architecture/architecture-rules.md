# Master Architecture Rules

```text
DOCUMENT: docs/architecture/architecture-rules.md
PROJECT: Security Lab — Application Security & Resilience Testing Platform
STATUS: RATIFIED SPECIFICATION
REVISION: 2.0.0
```

Every AI agent and software engineer working on this repository must strictly obey the following **25 architectural rules**:

---

### Rule 1: Local-First Execution Must Continue Working Without SaaS
Local-first developer workflows are foundational to Security Lab. The CLI and local controller must remain 100% operational offline without external cloud dependencies, internet access, or SaaS subscriptions.

### Rule 2: Distributed Execution Must Reuse Local Execution Contracts
When executing tests on distributed agents, the platform must reuse the exact same domain contracts, DTOs, `EngineRegistry`, and `TestEngine` interfaces implemented for local execution. Never create divergent or incompatible execution contracts.

### Rule 3: Controller Owns Authorization and Orchestration
The controller is the sole authority for tenant isolation, target scopes, policy evaluation, and release gating. The agent is an execution worker, not an authorization authority.

### Rule 4: Agent Executes Only Authenticated, Authorized Jobs
An agent must never accept or execute arbitrary URLs, commands, or jobs without validating that the dispatch originates from an authenticated, authorized controller and holds an active, unexpired lease.

### Rule 5: Tenant Identity Must Never Be Trusted From an Arbitrary Request Header Alone
Client-supplied headers such as `x-tenant-id` are untrusted and must never serve as authorization authority. Tenant identity must be derived strictly from authenticated credentials (e.g. database-backed Agent Token or Tenant Enrollment Key).

### Rule 6: Job Ownership Must Be Cryptographically and Logically Bound to the Authenticated Agent
Only the agent holding the active, unexpired lease on a job may submit progress, completion, or failure reports for that job. Cross-tenant or cross-agent job modifications must be rejected with 403 Forbidden.

### Rule 7: Job Completion Must Be Idempotent
Submitting a job completion report multiple times must produce identical results without duplicating test executions, duplicating findings, or corrupting metrics. Terminal states are immutable.

### Rule 8: Expired or Revoked Jobs Must Not Execute
If an agent lease expires or a job is cancelled, the agent must immediately abort execution. The controller must reject late completion reports for expired or cancelled jobs.

### Rule 9: Target Scope is a Hard Security Boundary
No network request or container run may ever be initiated without being validated against a verified, registered `TargetScope`. The platform must never accept arbitrary target URLs on the fly.

### Rule 10: Agent Cannot Expand Target Scope
An agent must never widen, alter, or bypass the target scope issued by the controller. All outbound HTTP requests and redirects must undergo continuous scope validation and SSRF filtering.

### Rule 11: Capability Does Not Equal Authorization
An agent having the technical capability to execute an engine (e.g. Docker, k6, ZAP) does not grant it authorization to run that engine against all targets or tenants. The controller enforces routing permissions.

### Rule 12: Docker Execution is an Explicit Security Boundary
Running third-party container scanners (ZAP, Trivy, k6) is an explicit attack surface. Containers must run with dropped Linux capabilities (`--cap-drop=ALL`), non-root users (`--user=10001:10001`), read-only root filesystems, and strict PID/resource limits.

### Rule 13: No Unrestricted Docker Socket Exposure
Under no circumstances may `/var/run/docker.sock` be mounted directly into untrusted containers or exposed without an explicit threat-model-approved architecture. Host socket access is equivalent to root host takeover.

### Rule 14: No Privileged Containers
Scanner and worker containers must never run with `--privileged` or with elevated security options. `--security-opt=no-new-privileges:true` is mandatory on all container invocations.

### Rule 15: No Arbitrary Host Filesystem Mounts
Container volume mounts must never point to host root (`/`), `/etc`, `/var/run`, or sensitive system paths. Mounts are restricted strictly to ephemeral temporary scratch directories under the OS temp directory, destroyed immediately post-execution.

### Rule 16: No Unrestricted Target URLs (SSRF Shielding)
All outbound URLs must undergo IP normalization and DNS verification. Probing private RFC 1918 subnets, cloud metadata endpoints (`169.254.169.254`), or loopback addresses is strictly forbidden unless explicitly authorized in the target scope. HTTP redirects must be intercepted and re-validated on every hop.

### Rule 17: No Raw Secrets in Logs
API tokens, Bearer headers, passwords, and private keys must never appear in plaintext in application logs, database payloads, error messages, or reports. All logging layers must enforce automated redaction.

### Rule 18: No Silent Fallback from Real Execution to Simulated Execution
Never silently fall back to simulated, mock, or hardcoded findings when an external tool or Docker daemon fails. Mocks are permitted only when explicitly requested via test flags. Real failures must fail fast and truthfully.

### Rule 19: Resource Limits Are Mandatory
Every execution must enforce hard caps on requests per second (`maxRps`), concurrent connections (`maxConcurrency`), test duration (`maxDuration`), output size, and container memory/CPU.

### Rule 20: Every Distributed Execution Must Be Auditable
Every state transition, registration, lease claim, heartbeat, cancellation, and finding ingestion must be captured in an append-only, tamper-evident audit log with structured timestamps and actor IDs.

### Rule 21: Deterministic State Transitions
Job states must follow an explicit, mathematically sound finite state machine (`queued -> leased -> running -> completed/failed/cancelled/expired`). Invalid or undefined state transitions must fail closed.

### Rule 22: Machine-Readable Failure Semantics
All API endpoints and CLI commands must emit standardized error envelopes with explicit, machine-readable error codes (e.g. `LEASE_EXPIRED`, `TENANT_MISMATCH`, `SCOPE_VIOLATION`) and standard exit codes.

### Rule 23: Future SaaS Must Not Force Cloud Dependencies Into Local Mode
Enhancements designed for multi-tenant cloud operations (e.g. mTLS, object storage, distributed queues) must remain modular plugins. Local offline mode must never require cloud infrastructure.

### Rule 24: Do Not Introduce Kubernetes Prematurely
Do not force complex Kubernetes operators, custom resource definitions (CRDs), or multi-cluster meshes into the core platform when simple, hardened container execution satisfies requirements.

### Rule 25: Do Not Introduce Microservices Merely for Architectural Appearance
The platform is organized as a modular monolith. Do not split services into independent microservices without an approved Architecture Decision Record (ADR). Keep the operational footprint minimal.

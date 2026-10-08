# Phase 16: Distributed Agent Security Model & Trust Architecture

```text
DOCUMENT: docs/architecture/phase-16-agent-security-model.md
STATUS: RATIFIED SPECIFICATION
PHASE: Phase 16 — Distributed Agent Trust Boundary & Secure Execution Plane
REVISION: 1.0.0
```

---

## 1. Overview & Security Philosophy

The core architectural invariant of Security Lab is:

> **Core Invariant**: A controller can safely dispatch an authorized security testing job to a remote or private execution agent, and the platform can cryptographically and deterministically establish that the correct agent executed the correct job for the correct tenant within the authorized target scope, and returned an authentic, untampered result without compromising host security or tenant isolation.

### Threat Environment & Assumptions
- **The network is hostile**: All traffic traversing the network between Controller and Agent is subject to interception, eavesdropping, and replay. TLS 1.3 encryption is mandatory.
- **The agent is untrusted by default**: An agent running in a customer VPC or on a developer workstation may be misconfigured, compromised, or running outdated software. The controller must never accept arbitrary target URLs, arbitrary tenant IDs, or unverified findings from the agent.
- **The controller owns authorization**: The agent is an execution worker, not an authorization authority. The controller decides what target, what scope, what engines, and what parameters are permitted.
- **Zero cross-tenant leakage**: A multi-tenant control plane must never allow one tenant's agent to read, claim, modify, or complete another tenant's jobs.

---

## 2. Comprehensive Trust Boundary Matrix

The platform spans 11 discrete architectural actors across multiple network and process boundaries. Every boundary is governed by strict security controls:

| Boundary | Interacting Actors | Authentication | Authorization | Integrity | Confidentiality | Replay Protection | Tenant Isolation | Auditability | Failure Behavior |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **TB-01** | User / Dashboard / CLI ➔ Controller | Session Cookie / API Token | RBAC (Admin, Tester, Viewer) | TLS 1.3 / HTTPS | TLS 1.3 | Nonce / CSRF Token | Scoped to user's assigned Tenant | Auth log + API access log | 401 Unauthorized / 403 Forbidden |
| **TB-02** | Controller ➔ Database (PostgreSQL) | DB User Password / IAM Auth | Connection Role (least privilege) | TLS within DB cluster | Encrypted at rest + TLS in transit | DB Transaction MVCC | Foreign key constraint on `tenant_id` + Row-level filtering | PostgreSQL transaction log | Fail-closed: 503 DB Unavailable |
| **TB-03** | Agent ➔ Controller (Enrollment) | Pre-shared Tenant Enrollment Key (`tek_...`) | Verified against active Tenant ID in DB | SHA-256 HMAC of registration payload | TLS 1.3 | Enrollment Nonce + Expiry timestamp | Agent permanently bound to Tenant UUID | `agent.enrolled` audit event | 401 Invalid or Expired Enrollment Key |
| **TB-04** | Agent ➔ Controller (Polling & Heartbeat) | Agent Bearer Token (`agt_sec_...`) | Verified by SHA-256 token hash lookup in `agents` table | TLS 1.3 | TLS 1.3 | Timestamp drift check (max 60s) | Query strictly filters `WHERE tenant_id = agent.tenant_id` | `agent.heartbeat` / `agent.poll` log | 401 Unauthorized; agent enters backoff loop |
| **TB-05** | Agent ➔ Controller (Job Claiming) | Agent Bearer Token | Match `agent.tenant_id == job.tenant_id` & capabilities match | Atomic DB lease lock (`FOR UPDATE SKIP LOCKED`) | TLS 1.3 | Unique `lease_id` per dispatch attempt | Cross-tenant claim strictly rejected | `job.leased` audit event | Empty job list if no authorized jobs |
| **TB-06** | Agent ➔ Controller (Result Submission) | Agent Token + HMAC signature of Job Result | Caller must hold active, unexpired lease on `job_id` | HMAC-SHA256(`job_id` + `test_run_id` + `findings_hash`, agentSecret) | TLS 1.3 | Unique idempotency key; duplicate submissions rejected | Validated: `agent.tenant_id == job.tenant_id` | `result.accepted` / `result.rejected` audit | 409 Conflict if expired/duplicate; 403 if unauthorized |
| **TB-07** | Agent Daemon ➔ Agent Host | Local OS User (`securitylab` UID 10001) | Non-root system account, no sudo | OS file permissions | OS memory isolation | N/A | Host-level process isolation | Host systemd / container log | Process abort if permissions insufficient |
| **TB-08** | Agent Daemon ➔ Docker Daemon / Sandbox | Restricted Unix Socket or Local Proxy | Command allowlist: only approved images and run flags | Docker API TLS / Socket Permissions | Container filesystem isolation | Ephemeral execution IDs | Scanners isolated per job execution | Execution audit log with container ID | Fail-closed: reject execution if policy violated |
| **TB-09** | Scanner Container ➔ Agent Host | OCI Runtime (cgroups v2, namespaces) | Dropped caps (`ALL`), `--security-opt=no-new-privileges` | Read-only rootfs; ephemeral scratch mount | Isolated mount namespace | Ephemeral container | Cannot access agent process memory or host | Container exit codes & error logs | Container killed on timeout or policy violation |
| **TB-10** | Agent / Scanner ➔ Target Application | Target Credentials (Vault / Job Options) | Constrained by Controller-issued Target Scope | TLS 1.3 / HTTP probing | Probing payloads encrypted in transit | N/A | Target belongs to tenant project | Forensic evidence records with SHA-256 hash | Probes aborted if SSRF boundary violated |
| **TB-11** | Future SaaS Control Plane ➔ Private Agent | mTLS mutual certificates (X.509) | SAN contains Tenant UUID + Agent UUID | Mutual TLS cryptographic verification | End-to-end TLS encryption | TLS 1.3 session tickets & sequence counters | Enforced at TLS handshake termination | Centralized audit stream | Connection dropped if cert invalid/revoked |

---

## 3. Agent Identity & Credential Lifecycle Architecture

### 3.1 Enrollment Keys vs. Agent Tokens
To eliminate the critical vulnerability where anonymous callers register agents under arbitrary tenants, authentication is decoupled into a two-tiered key hierarchy:

```text
[ Tenant Admin in Dashboard/CLI ]
              |
              v Generates
   Tenant Enrollment Key (TEK)
   Format: "tek_<tenant_slug>_<32 random bytes>"
   Stored: Hashed in PostgreSQL (with expiration & max uses)
              |
              v Distributed to Agent Operator (Env / K8s Secret)
[ Agent Daemon Startup ]
              |
              v POST /api/v1/agents/register (Bearer: TEK)
[ Controller Validation ]
              |
              v Validates TEK, asserts Tenant ID, decrements usage counter
      Generates Agent Instance Token
      Format: "agt_sec_<32 random bytes>"
      Stored: SHA-256 hashed in `agents` table
              |
              v Returns to Agent (Shown ONCE)
[ Agent Operates Using Instance Token ]
```

### 3.2 Token Storage, Expiration & Revocation
- **Storage**: Plaintext tokens are NEVER stored in the database. Only `SHA-256(token)` is persisted.
- **Expiration**: Agent tokens have a configurable TTL (default: 90 days for production agents; 24 hours for ephemeral CI agents).
- **Revocation**: The `agents` table includes `revoked_at TIMESTAMPTZ` and `revocation_reason VARCHAR(100)`. If `revoked_at IS NOT NULL`, all requests from that agent are immediately rejected with `401 Agent Revoked`.
- **Token Rotation**: An authenticated agent can request token rotation via `POST /api/v1/agents/rotate-token`. The controller issues a new token, marks the previous token to expire in a 10-minute grace period, and transitions smoothly without downtime.

---

## 4. Tenant Isolation Architecture (Enforced in Phase 16.2)

### 4.1 Rejection of Client-Controlled Tenant Headers (Rule 5)
In the Security Lab multi-tenant execution architecture, the HTTP request header `x-tenant-id` is **never** used as an authorization authority for agent operations:
- On **registration**: Tenant identity is cryptographically and logically derived from the validated Tenant Enrollment Key (`tek_...`).
- On **polling, heartbeats, job progress, and job completion/failure**: Tenant identity is extracted directly from the authenticated `agents` database record bound to the Bearer token.
- **Active Spoofing Prevention**: Any attempt by an agent to supply an `x-tenant-id` header differing from its authenticated database record results in immediate request rejection with HTTP `403 Forbidden` (`TENANT_MISMATCH`) and an alert log:
  ```json
  {
    "event": "security.tenant_spoof_attempt",
    "callerAgentId": "...",
    "tokenTenantId": "...",
    "headerTenantId": "...",
    "url": "..."
  }
  ```
- On **agent listing (`GET /api/v1/agents`)**: Scoped strictly to the authenticated agent's tenant when invoked with a Bearer token, blocking cross-tenant visibility.

### 4.2 Cross-Tenant and Worker Lease Boundary Invariants (Rule 6)
All job state transition endpoints (`POST /api/v1/agents/jobs/:jobId/progress`, `POST /api/v1/agents/jobs/:jobId/complete`, `POST /api/v1/agents/jobs/:jobId/fail`) pass the verified `agent` identity to `AgentDispatcherService`, which asserts two strict security invariants:

1. **Tenant Boundary Invariant**:
   ```ts
   if (job.tenantId !== agent.tenantId) {
     logger.warn({
       event: 'security.cross_tenant_attempt',
       attemptedJobId: jobId,
       callerAgentId: agent.id,
       callerTenantId: agent.tenantId,
       targetTenantId: job.tenantId,
       action: 'progress' | 'complete' | 'fail',
     }, 'Blocked unauthorized cross-tenant job operation');
     throw new AuthorizationError(
       `Tenant mismatch: agent "${agent.id}" cannot access job belonging to tenant "${job.tenantId}"`,
       'TENANT_MISMATCH',
     );
   }
   ```
2. **Worker Lease Ownership Invariant**:
   ```ts
   if (job.agentId !== agent.id) {
     logger.warn({
       event: 'security.cross_agent_attempt',
       attemptedJobId: jobId,
       callerAgentId: agent.id,
       assignedAgentId: job.agentId,
       action: 'progress' | 'complete' | 'fail',
     }, 'Blocked unauthorized job operation by non-assigned agent');
     throw new AuthorizationError(
       `Agent mismatch: job "${jobId}" is not assigned to agent "${agent.id}"`,
       'AGENT_MISMATCH',
     );
   }
   ```

### 4.3 Automated Verification
These isolation invariants are provably verified by:
- `tests/security/tenant-isolation.test.ts` (11 adversarial multi-tenant integration tests).
- `tests/security/distributed-agent-boundaries.test.ts` (6 boundary and regression tests).
- `tests/integration/agent-orchestration.test.ts` (8 multi-tenant SaaS integration tests).

---

## 5. Result Authenticity & Attestation Model

To prevent result forgery where an unauthorized party fabricates findings:

### 5.1 Job-Bound Result Submission
Every dispatched job includes an ephemeral **Job Dispatch Token** or HMAC signature computed by the controller:
```text
JobDispatchSecret = HMAC-SHA256(ControllerMasterKey, jobId + testRunId + agentId + leaseId)
```
When submitting the completion report:
1. The agent computes a hash over all normalized findings and execution summaries:
   ```text
   FindingsHash = SHA-256(CanonicalJSON(report.findings) + CanonicalJSON(report.executions))
   ```
2. The agent includes an attestation signature:
   ```text
   ResultSignature = HMAC-SHA256(JobDispatchSecret, jobId + FindingsHash)
   ```
3. The controller recalculates `JobDispatchSecret` and verifies `ResultSignature`.
4. If the signature matches, the controller verifies that `job.status === 'running' || job.status === 'dispatched'`, and that the caller holds the active unexpired lease.
### 5.2 Target Scope Attestation & Distributed SSRF Defense (Enforced in Phase 16.5)

To prevent scope expansion or redirection where a compromised or tampered job payload directs an agent in a customer VPC to scan internal networks or cloud metadata:

```text
[ Controller Job Enqueue / Dispatch ]
              |
              v Computes Scope Attestation Signature
    scopeSignature = HMAC-SHA256(MasterKey, target.id + target.baseUrl + CanonicalJSON(target.scope))
              |
              v Transmitted inside AgentJobDispatch.target.scopeSignature
[ Distributed Agent Worker in Customer VPC ]
              |
              +---> 1. Cryptographic Scope Signature Verification
              |        Recomputes HMAC over target.id + target.baseUrl + CanonicalJSON(target.scope)
              |        If signature is missing or mismatched:
              |        - Emits "security.scope_violation_blocked"
              |        - Reports catastrophic job failure to Controller
              |        - Throws ScopeTamperingError (ABORTS BEFORE ANY PROBE)
              |
              +---> 2. In-Agent Defense-in-Depth Cloud Metadata Shield
              |        Strictly blocks target.baseUrl or target.scope.allowedHosts targeting:
              |        - AWS/Azure/OpenStack IMDS: 169.254.169.254 (and decimal 2852039166, hex, octal)
              |        - AWS IPv6 IMDS: fd00:ec2::254
              |        - Google Cloud Metadata: metadata.google.internal, metadata.local, instance-data
              |        - Alibaba Cloud Metadata: 100.100.100.200
              |        - Link-Local subnets: 169.254.0.0/16, fe80::/10
              |        FAILS CLOSED: Rejects with SecurityBoundaryError even if authorized by controller
              |
              +---> 3. Local Loopback Protection on Agent Host
              |        Blocks scanning agent host localhost / 127.0.0.0/8 / ::1
              |        Forbidden unless explicitly permitted via CLI startup flag: --allow-local-testing
              |
              v
[ Probing Executed Strictly Within Authorized Scope ]
```

### 5.3 Automated Scope Security Verification
The cryptographic scope attestation and SSRF protections are provably verified by:
- `tests/security/scope-propagation-ssrf.test.ts` (12 adversarial scope tampering and SSRF tests).
- `tests/integration/agent-orchestration.test.ts` (end-to-end remote runner execution).
- `tests/security/result-integrity-idempotency.test.ts` (result attestation & worker signing).

---

## 6. Docker Sandbox & Host Boundary Hardening

### 6.1 The Docker Socket Hazard
Mounting `/var/run/docker.sock` into an agent container grants effective root on the host machine. If an agent or a container scanner suffers an exploitation (e.g. command injection in an engine or scanner vulnerability in ZAP/Trivy), the attacker can escape to the host.

### 6.2 Hardened Execution Plane Alternatives

```text
[ Option A: Unrestricted Docker Socket Mount ]
   Agent Container ──> /var/run/docker.sock (UNSAFE - REJECTED)

[ Option B: Dedicated Host Daemon / Local Execution Broker ]
   Agent Container ──> Restricted Unix Domain Socket (Proxy) ──> Docker Daemon
   Proxy enforces: only approved image digests, strictly dropped capabilities, no host mounts.

[ Option C: Dedicated Execution VM / Bare-Metal Agent (RECOMMENDED FOR LOCAL/HYBRID) ]
   Agent runs as dedicated system service (systemd) on VM with local Docker daemon.
   No container-inside-container nesting.

[ Option D: Rootless Docker / Podman ]
   Agent runs inside a user namespace without root privileges on the host.

[ Option E: Future Kubernetes Jobs API ]
   Agent uses Kubernetes ServiceAccount to launch isolated ephemeral Pods instead of Docker socket.
```

### 6.3 Security Policy for Agent Container Runners
For the current architecture:
1. The agent must NEVER expose `/var/run/docker.sock` to third-party network traffic.
2. In Kubernetes deployments, the agent will execute Class A native engines in-pod. Class B/C scanner containers will be managed via Kubernetes ephemeral jobs rather than hostPath socket mounts.
3. In Docker deployments, container executions must strictly use `packages/test-sdk/src/runners/docker-policy.ts` rules:
   - Image allowlist pinned to official repositories (`zaproxy/zaproxy`, `aquasec/trivy`, `grafana/k6`).
   - Mandatory flags: `--security-opt=no-new-privileges:true`, `--cap-drop=ALL`, `--read-only`, `--user=10001:10001`, `--pids-limit=100`.
   - Volumes restricted exclusively to temporary scratch paths verified to be subdirectories of `os.tmpdir()`.

---

## 7. Future mTLS Integration Roadmap

When transitioning to the SaaS Control Plane:
1. **Termination Layer**: mTLS terminates at the API Gateway / Load Balancer (Envoy / Cloudflare / Traefik) or directly in Fastify via Node.js `tls` options.
2. **Certificate Enrollment**: Agents generate an RSA 4096-bit or Ed25519 keypair locally. The agent sends a Certificate Signing Request (CSR) during initial enrollment. The controller CA signs the client certificate with Subject Alternative Name (SAN) containing `tenantId` and `agentId`.
3. **Local Mode Fallback**: For local-first developer workstations, plain HTTPS / HTTP continues to be supported without requiring local PKI infrastructure.

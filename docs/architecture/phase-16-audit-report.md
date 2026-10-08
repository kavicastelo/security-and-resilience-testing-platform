# Phase 16 Codebase Audit Report: Distributed Execution Reality & Trust Boundary Analysis

```text
DOCUMENT: docs/architecture/phase-16-audit-report.md
STATUS: COMPLETE & RATIFIED
CLASSIFICATION: PRINCIPAL ARCHITECTURE & SECURITY AUDIT
REPOSITORY: kavicastelo/security-and-resilience-testing-platform
DEFAULT BRANCH: master
AUDIT DATE: October 2026
AUDITORS: Principal Security Architect, Distributed Systems Architect, Application Security Engineer
TARGET PHASE: Phase 16 — Distributed Agent Trust Boundary & Secure Execution Plane
```

---

## 1. Executive Summary

Following the introduction of the distributed execution agent (`apps/agent`, `apps/controller/src/services/agent-dispatcher.service.ts`, `apps/controller/src/routes/agents.ts`, and migration `0006_saas_multi_tenancy.sql`), a deep forensic audit was conducted on the actual implementation across the repository.

### Key Verdict
The repository possesses a well-structured foundational scaffold for distributed agent execution, successfully enabling an agent daemon to register with the controller, report periodic heartbeats, poll pending jobs, execute test engines locally, and return finding summaries. In automated happy-path testing (`tests/integration/agent-orchestration.test.ts`), 8 integration tests pass cleanly, and the token hash is verified in PostgreSQL.

**However, the distributed execution plane currently operates without essential cryptographic and logical security boundaries.** In an adversarial or multi-tenant deployment, the current implementation exhibits critical, exploitable vulnerabilities:
1. **Unauthenticated Agent Enrollment**: `POST /api/v1/agents/register` allows anonymous registration under arbitrary tenant UUIDs without pre-shared keys, enrollment secrets, or administrative approval.
2. **Client-Controlled Tenant Header Spoofing**: Tenant identity is trusted directly from the incoming HTTP `x-tenant-id` header on registration and dispatch.
3. **Cross-Tenant Job Hijacking & Forgery**: While polling filters by tenant, `/jobs/:jobId/progress`, `/jobs/:jobId/complete`, and `/jobs/:jobId/fail` do not verify that the calling agent is the leaseholder of the job or belongs to the job's tenant. Any authenticated agent from Tenant B can forge results, inject findings, or fail jobs for Tenant A.
4. **Non-Atomic Job Claiming & Zero Lease Expiration**: Polling uses an unprotected `SELECT` followed by a non-atomic `UPDATE`, causing double-dispatch races under concurrent polling. Jobs have no lease timers; crashed agents leave jobs in `'dispatched'` indefinitely with zero automated requeueing.
5. **No Result Integrity or Cryptographic Attestation**: The controller blindly accepts raw JSON finding arrays from agents without signature verification, raw output hashes, or evidence validation.
6. **Privileged Docker Socket Host Exposure**: Deployment manifests (`infrastructure/k8s/agent.yaml` and `docs/architecture/saas-and-agent-architecture.md`) instruct mounting `/var/run/docker.sock` directly into the agent container, providing trivial host root takeover vectors.
7. **Broken Cancellation Propagation**: Controller cancellations do not reach remote agents, and agent completions arriving after cancellation overwrite the cancelled state.
8. **Zero Protocol Versioning**: No protocol handshake or version negotiation exists between agent and controller.

The platform requires **Phase 16: Distributed Agent Trust Boundary & Secure Execution Plane** to transform this prototype into a hardened, enterprise-trustworthy distributed execution plane.

---

## 2. Current Distributed Architecture

### Components in Reality
1. **`apps/agent`**:
   - `client.ts`: HTTP wrapper around Node.js `fetch()`. Handles `register`, `heartbeat`, `poll`, `reportProgress`, `reportCompletion`, and `reportFailure`. Stores bearer token in-memory.
   - `config.ts`: Loads configuration from environment variables with hardcoded fallbacks (`CONTROLLER_URL=http://localhost:4000`, `pollIntervalMs=2000`, `heartbeatIntervalMs=10000`). Self-declares capabilities and tags.
   - `daemon.ts`: Starts heartbeat timer and polling timer. Enrolls dynamically if unauthenticated. Single concurrency (`activeJobsCount` toggled between 0 and 1).
   - `worker.ts`: Iterates over `job.engineIds`, queries `@security-lab/test-sdk` singleton `engineRegistry`, executes engines sequentially, constructs `AgentJobCompletionReport`, and posts to `/jobs/:id/complete`.
   - `index.ts`: Commander CLI exposing `start` and `register` commands.

2. **`apps/controller`**:
   - `routes/agents.ts`: Fastify routes for agent interactions (`/register`, `/heartbeat`, `/poll`, `/jobs/:id/progress`, `/jobs/:id/complete`, `/jobs/:id/fail`, `/dispatch`). Uses `requireAgentAuth` middleware checking token SHA-256 in PostgreSQL.
   - `services/agent-dispatcher.service.ts`: Database queries against `agents` and `agent_jobs`. Handles token hashing, heartbeat timestamps, job enqueuing, polling queries, and ingestion of completion reports into `testExecutions`, `findings`, and `metrics`.

3. **`packages/contracts/src/agent`**:
   - Zod schemas: `AgentRegistrationRequestSchema`, `AgentHeartbeatRequestSchema`, `AgentPollRequestSchema`, `AgentJobDispatchSchema`, `AgentJobProgressReportSchema`, `AgentJobCompletionReportSchema`, `AgentSummarySchema`.

4. **Database (Migration `0006_saas_multi_tenancy.sql`)**:
   - Tables: `tenants`, `agents`, `agent_jobs`. Added `tenant_id` foreign keys to `projects`, `targets`, `policies`, and `findings`.

---

## 3. Trust Boundaries & Reality Classification

```text
[ User / Dashboard / CLI ]
           |  (Trust Boundary 1: User / API Gateway)
           v
[ Controller API Gateway (Fastify) ]
           |  (Trust Boundary 2: Tenant Context Derivation)
           v
[ PostgreSQL Database (Shared Schema) ]
           ^
           |  (Trust Boundary 3: Agent Authentication & Job Leases)
           |
[ Remote / Private Agent Daemon (Node.js) ]
           |  (Trust Boundary 4: Agent Host / Docker Daemon)
           v
[ Scanner Containers (ZAP / Trivy / k6) ]
           |  (Trust Boundary 5: Target Network / Scope Boundary)
           v
[ Target Enterprise Application / VPC ]
```

### Reality Classification by Subsystem

| Subsystem | Status Classification | Reality Analysis |
| :--- | :--- | :--- |
| **Agent Registration** | `IMPLEMENTED_BUT_UNSAFE` | Token generation & SHA-256 hashing works; completely unauthenticated and open to arbitrary tenant spoofing. |
| **Agent Authentication** | `PARTIALLY_IMPLEMENTED` | Bearer token hashed and looked up in DB. Missing expiration, revocation, rotation, and rate-limiting. |
| **Tenant Isolation (API)** | `IMPLEMENTED_BUT_UNSAFE` | Client `x-tenant-id` trusted blindly on registration and dispatch. Cross-tenant job completion possible. |
| **Job Dispatch Queue** | `IMPLEMENTED_BUT_UNSAFE` | Non-atomic polling query. Zero row locking. Two agents polling simultaneously will claim the exact same job. |
| **Job Lease & Timeout** | `NOT_IMPLEMENTED` | No lease duration, no lease expiration, no requeueing, no reaper, no attempt counter. Dead agents stall jobs forever. |
| **Result Ingestion** | `IMPLEMENTED_BUT_UNSAFE` | Ingests findings, metrics, and updates test run. Zero result signature, zero HMAC, zero idempotency protection. |
| **Scope Enforcement** | `PARTIALLY_IMPLEMENTED` | Agent receives scope in payload and passes to engine. No agent-side cryptographic verification; Class B/C Docker runners lack egress controls. |
| **Agent Cancellation** | `NOT_IMPLEMENTED` | Controller cancellation does not propagate to agent. Agent completion overwrites controller cancellation. |
| **Docker Sandboxing** | `IMPLEMENTED_BUT_UNSAFE` | `docker.policy.ts` enforces non-root in containers, but deployment mounts `/var/run/docker.sock` to agent container. |
| **Protocol Negotiation**| `NOT_IMPLEMENTED` | No protocol versioning fields, no handshake, no compatibility matrix. |
| **Audit Logging** | `SCAFFOLDED` | Standard Pino debug/info logs only. No persistent, structured, tamper-evident security audit trail. |

---

## 4. Security Findings (Detailed Forensic Vulnerability Analysis)

### Finding SEC-01: Anonymous Agent Enrollment & Tenant Hijacking (P0 - CRITICAL)
- **Code Path**: `apps/controller/src/routes/agents.ts:15-41`, `apps/controller/src/services/tenant-context.ts:4-16`
- **Vulnerability**: `POST /api/v1/agents/register` requires no authentication. The caller passes `x-tenant-id: <VICTIM_TENANT_UUID>` in the header. The controller accepts the registration, creates an agent record assigned to the victim tenant, and returns an authenticated bearer token.
- **Impact**: Any unauthenticated network client can register as an authorized execution agent for any tenant in the platform, gain access to queued security test runs, and extract proprietary target URLs and configurations.

### Finding SEC-02: Missing Authorization on Job Completion & Progress Endpoints (P0 - CRITICAL)
- **Code Path**: `apps/controller/src/routes/agents.ts:148-173`, `apps/controller/src/services/agent-dispatcher.service.ts:289-447`
- **Vulnerability**: The route `POST /api/v1/agents/jobs/:jobId/complete` invokes `requireAgentAuth(request, reply)` which verifies that the caller has *a* valid agent token. However, `completeJob(jobId, report)` is called with only `jobId` and `report`. It does **not** check:
  1. Does `agent.id === job.agentId`? (Did this agent claim this job?)
  2. Does `agent.tenantId === job.tenantId`? (Does this agent belong to the tenant owning the job?)
- **Impact**: An attacker who registers an agent under Tenant B can monitor or guess job IDs and submit forged completion reports for Tenant A's jobs, injecting fabricated vulnerabilities or wiping legitimate findings to pass release gates.

### Finding SEC-03: Race Condition in Job Polling & Lack of Row Locking (P1 - HIGH)
- **Code Path**: `apps/controller/src/services/agent-dispatcher.service.ts:223-247`
- **Vulnerability**: 
  ```ts
  const pending = await db.select().from(agentJobs).where(...).limit(maxJobs);
  for (const job of pending) {
    await db.update(agentJobs).set({ agentId, status: 'dispatched', ... }).where(eq(agentJobs.id, job.id));
  }
  ```
- **Impact**: Under concurrent load, multiple agents polling at the same moment execute the `SELECT` query before any `UPDATE` is committed. Both agents receive the same pending job ID, both set `agentId`, and both execute the job against the target concurrently, doubling load and causing duplicate finding generation.

### Finding SEC-04: Non-Idempotent Job Completion (P1 - HIGH)
- **Code Path**: `apps/controller/src/services/agent-dispatcher.service.ts:312-435`
- **Vulnerability**: If an agent retries `POST /jobs/:jobId/complete` due to network timeout or retry policy, `completeJob` does not check `if (job.status === 'completed') return;`. It unconditionally inserts new `test_executions`, inserts new `findings`, inserts new `metrics`, updates `testRunStatus`, and triggers new report generation.
- **Impact**: Duplicate findings, skewed metrics, corrupt vulnerability occurrence counts, and database bloat.

### Finding SEC-05: Missing Lease Timers & Orphaned Job Starvation (P1 - HIGH)
- **Code Path**: `apps/controller/src/services/agent-dispatcher.service.ts:233-242`
- **Vulnerability**: When an agent polls and receives a job, the job status moves to `'dispatched'`. If the agent crashes, loses power, or disconnects before calling `/progress` or `/complete`, the job remains in `'dispatched'` permanently. The database schema has no `lease_expires_at`, and the controller has no background reaper or retry mechanism.
- **Impact**: Permanent job stall. Target never finishes execution, blocking CI/CD pipelines indefinitely.

### Finding SEC-06: Container Escape Risk via Docker Socket Mount (P0 - CRITICAL)
- **Code Path**: `infrastructure/k8s/agent.yaml:118-127`, `docs/architecture/saas-and-agent-architecture.md:281`
- **Vulnerability**: The deployment guides instruct mounting `/var/run/docker.sock` into the agent container. Access to the Docker socket allows any container process to issue API commands directly to the host Docker daemon, launch privileged containers with host root filesystem mounts, and achieve complete node compromise.
- **Impact**: Total host/cluster compromise if the agent container or any Class B/C scanner is compromised.

### Finding SEC-07: Unidirectional Heartbeat & Broken Cancellation Propagation (P1 - HIGH)
- **Code Path**: `apps/controller/src/services/execution-manager.ts:168-264`, `apps/agent/src/client.ts:59-76`, `apps/agent/src/daemon.ts:62-78`
- **Vulnerability**: `executionManager.cancel(testRunId)` only aborts in-memory local runs. If a test run is running on a distributed agent, the controller updates the DB status to `'cancelled'`, but never signals the agent. The agent daemon continues running the attack tools against the target, and upon finishing calls `/complete`, which silently transitions the test run from `'cancelled'` back to `'completed'`.
- **Impact**: Inability to stop aggressive or damaging scans; emergency user cancellation is ineffective and overridden.

### Finding SEC-08: Target Scope Blind Trust by Agent Worker (P1 - HIGH)
- **Code Path**: `apps/agent/src/worker.ts:56-71`
- **Vulnerability**: The agent worker extracts `job.target.baseUrl` and `job.target.scope` directly from the job dispatch payload and passes them into the engine execution context without verifying authenticity or policy compliance. If the control plane or communication link is tampered with, an attacker can dispatch jobs instructing customer agents to attack unauthorized internal IP addresses or cloud metadata endpoints within their private VPC.
- **Impact**: Private network reconnaissance and SSRF using the customer's own trusted agent.

### Finding SEC-09: Unbounded Finding Payload Ingestion & Controller Denial of Service (P2 - MEDIUM)
- **Code Path**: `apps/controller/src/routes/agents.ts:148-161`, `apps/controller/src/services/agent-dispatcher.service.ts:363-392`
- **Vulnerability**: The controller accepts an unbounded array of findings in `AgentJobCompletionReportSchema`. If a compromised or malfunctioning agent reports 500,000 findings, the controller loops over every item, executes fingerprinting and database inserts, exhausting controller memory and database connections.
- **Impact**: Control plane denial of service and database exhaustion.

### Finding SEC-10: Plaintext Secret Exposure in Job Payloads & Database (P2 - MEDIUM)
- **Code Path**: `apps/controller/src/services/agent-dispatcher.service.ts:187-196`
- **Vulnerability**: The `AgentJobDispatch` payload contains `customHeaders` (which often contain `Authorization: Bearer <API_KEY>`) and `options`. The controller persists this entire object as plaintext JSON inside `agent_jobs.payload`.
- **Impact**: Long-term database exposure of customer API keys, session tokens, and passwords in cleartext.

---

## 5. Documentation-vs-Code Contradictions

| Topic | Documentation Claim | Actual Code Reality | Contradiction Severity |
| :--- | :--- | :--- | :--- |
| **mTLS Communication** | Roadmap (Horizon 4) claims "mTLS tunnel" and "encrypted WebSockets / gRPC with mTLS". | Plain HTTP/HTTPS polling via `fetch()`. No mTLS, no WebSockets, no gRPC, no certificates. | **HIGH** (Future capability stated as present) |
| **Forensically Signed Results** | Architecture doc claims "normalized, forensically signed results". | Agent sends unsigned raw JSON via `POST /complete`. Zero cryptographic signatures or HMAC. | **CRITICAL** (Security boundary non-existent) |
| **Tag & Capability Routing** | Roadmap claims controller "routes jobs to connected agents based on target tags". | `pollJobs()` prefixes `_capabilities` and `_tags` with underscores and completely ignores them. Any agent gets any job. | **HIGH** (Capability routing is completely bypassed) |
| **Docker Socket Security** | `prompts/architecture-rules.md` Rule 10: "No Arbitrary Docker Socket Exposure". | `infrastructure/k8s/agent.yaml` and `docs/.../saas-and-agent-architecture.md` explicitly mount `/var/run/docker.sock`. | **CRITICAL** (Direct rule violation in deployment code) |
| **Job State Tracking** | Architecture doc claims states: `pending`, `assigned`, `running`, `completed`, `failed`. | Schema defines default `'pending'`, code uses `'dispatched'`, `'running'`, `'completed'`, `'failed'`. No `'assigned'`, no `'leased'`. | **MEDIUM** (State model inconsistency) |
| **Prompt Library Git Tracking**| README claims prompt library is part of the engineering process. | `.gitignore` explicitly contained `prompts/` on line 56, hiding the engineering prompts from git. | **HIGH** (Corrected during this audit) |

---

## 6. Risk Classification Matrix

```text
+-------------------------------------------------------------------------------+
| CRITICAL (P0) - IMMEDIATE VULNERABILITY / COMPROMISE RISK                     |
| SEC-01: Anonymous agent enrollment & tenant spoofing                         |
| SEC-02: Cross-tenant job completion and finding forgery                       |
| SEC-06: Privileged Docker socket exposure in Kubernetes & Docker deployment   |
+-------------------------------------------------------------------------------+
| HIGH (P1) - RELIABILITY, CONCURRENCY & INTEGRITY THREATS                     |
| SEC-03: Race condition in job polling (no atomic lease / row locking)         |
| SEC-04: Non-idempotent job completion (finding duplication)                  |
| SEC-05: Missing lease timeout & dead agent job starvation                    |
| SEC-07: Broken cancellation propagation across agent boundary                |
| SEC-08: Target scope blind trust by agent worker                             |
+-------------------------------------------------------------------------------+
| MEDIUM (P2) - GOVERNANCE, OBSERVABILITY & SECRETS HYGIENE                    |
| SEC-09: Unbounded finding ingestion (controller DoS)                         |
| SEC-10: Plaintext secrets in job payloads and database                       |
| Missing protocol version negotiation                                          |
| Missing structured audit logging of agent events                             |
+-------------------------------------------------------------------------------+
| LOW (P3) - OPTIMIZATIONS & FUTURE ARCHITECTURE                                |
| mTLS mutual certificate enrollment                                            |
| Real-time WebSocket/gRPC streaming backchannel                               |
+-------------------------------------------------------------------------------+
```

---

## 7. Recommended Phase 16 Target Architecture

### Guiding Principles
1. **Zero Trust Agent Boundary**: The controller must treat execution agents as untrusted remote workers. Agent claims must be authenticated, authorized, and cryptographically verified.
2. **Deterministic State Machine**: Every job transition (`queued -> leased -> running -> completed/failed/cancelled/expired`) must be atomic, lease-bounded, and idempotent.
3. **Strict Tenant Binding**: Tenant identity is an immutable attribute of authenticated credentials, never derived from client request headers.
4. **Isolated Host Execution**: The agent must never expose the host Docker daemon socket directly. Class B/C scanner containers must run through a hardened execution broker or dedicated VM sandbox.
5. **Local-First Preservation**: Local CLI and single-tenant in-process controller workflows must remain completely uninterrupted and zero-friction.

### Target Architecture Schematic
```text
Control Plane (Controller)                          Distributed Agent
==========================                          =================
1. Tenant Admin creates Agent Enrollment Key
2. Agent enrolls with Key + SHA-256 Secret -------> Controller validates Key & Tenant
                                                    Generates Agent Token (Hashed in DB)
3. Atomic Poll with Capability Filter
   [SELECT FOR UPDATE SKIP LOCKED]
   Lease established (Expires in 5m) -------------> Job Dispatch Token (HMAC signed by Controller)
                                                    Contains: jobId, tenantId, leaseId, authorizedScope
4. Agent executes engines
   Heartbeat extends lease every 30s -------------> Heartbeat response carries commands (continue/cancel)
5. Agent packages results + Evidence Hashes
   Signs result with Job Dispatch Secret ---------> Controller validates signature & lease
                                                    Enforces idempotency (rejects duplicates)
                                                    Ingests findings into tenant boundary
```

---

## 8. Phase Breakdown: Sub-Phases 16.0 to 16.10

```text
Phase 16.0: Distributed Execution Reality Audit (Baseline, Test Suite & Contract Lock)
   │
   ▼
Phase 16.1: Agent Identity, Enrollment Keys & Authentication Hardening
   │
   ▼
Phase 16.2: Tenant Isolation, Contextual Binding & Route Authorization
   │
   ▼
Phase 16.3: Atomic Job Leasing, Watchdog Reaper & State Machine
   │
   ▼
Phase 16.4: Result Authenticity, Evidence HMAC & Idempotent Ingestion
   │
   ▼
Phase 16.5: Scope Cryptographic Binding & Distributed SSRF Defense
   │
   ▼
Phase 16.6: Resource Governance, Execution Timeouts & Bidirectional Cancellation
   │
   ▼
Phase 16.7: Agent Docker Sandbox Hardening & Host Boundary Protection
   │
   ▼
Phase 16.8: Protocol Handshake, Semantic Versioning & Capability Negotiation
   │
   ▼
Phase 16.9: Security Audit Logging & Distributed Telemetry Observability
   │
   ▼
Phase 16.10: End-to-End Adversarial Security & Penetration Verification
```

---

## 9. Exactly One Recommended Next Phase

### **Recommendation: Phase 16.0 — Distributed Execution Reality Audit & Baseline Verification**

- **Why now**: Before modifying authentication schemas, database tables, or controller endpoints, we must establish a baseline test suite that formally exercises and proves the identified vulnerabilities (tenant spoofing, double claiming, cross-tenant completion, Docker socket escape). Attempting code changes without establishing reproducible security regression tests risks false confidence.
- **Blocking Risks**: Proceeding directly to refactoring without Phase 16.0 risks breaking the 269 existing tests that currently pass in the repository.
- **Prerequisites**: Phase 15 code baseline (currently verified).
- **Expected Outcome**: A dedicated adversarial test fixture demonstrating every identified trust boundary failure, a finalized DTO contract specification for Phase 16, and an immutable reference point for subsequent sub-phases.
- **Why other features should wait**: Identity (16.1) and leasing (16.3) must be verified against the test harness delivered in 16.0.

---

## 10. Audit Conclusion & Sign-Off

The Security Lab distributed agent architecture has completed initial scaffolding, but requires rigorous trust boundary engineering before it can be deployed in production or hybrid-cloud environments. The blueprint set forth in Phase 16 addresses every identified vulnerability in dependency order.

---

## 11. Security Audit Logging & Compliance Event Subsystem (Phase 16.9)

### 11.1 Architecture & Objectives
Phase 16.9 establishes an enterprise-grade, append-only, tamper-evident audit logging subsystem satisfying SOC 2 Type II and ISO 27001 requirements across all distributed agent interactions.

### 11.2 Database Schema (`agent_audit_events`)
Created in Migration `0010_agent_audit_events.sql`:
```sql
CREATE TABLE IF NOT EXISTS agent_audit_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  agent_id UUID REFERENCES agents(id) ON DELETE SET NULL,
  event_type VARCHAR(50) NOT NULL,
  actor_type VARCHAR(30) NOT NULL,
  actor_id VARCHAR(100) NOT NULL,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  ip_address VARCHAR(45),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_agent_audit_events_tenant_created ON agent_audit_events(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_agent_audit_events_agent_created ON agent_audit_events(agent_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_agent_audit_events_event_type ON agent_audit_events(event_type);
```

### 11.3 Database Immutability & Append-Only Trigger (Rule 20)
To prevent rogue insiders or SQL injection attacks from tampering with audit trails, a database-level trigger prohibits all `UPDATE` and `DELETE` operations on `agent_audit_events`:
```sql
CREATE OR REPLACE FUNCTION prevent_agent_audit_event_tamper()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'AUDIT_LOG_IMMUTABLE: Audit events are append-only. UPDATE and DELETE operations are forbidden.';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_agent_audit_events_immutable
BEFORE UPDATE OR DELETE ON agent_audit_events
FOR EACH ROW EXECUTE FUNCTION prevent_agent_audit_event_tamper();
```

### 11.4 Automated Secret Scrubbing (Rule 17)
The `AgentAuditService` enforces strict recursive secret sanitization prior to database persistence:
- Sensitive key names (`token`, `secret`, `password`, `key`, `authorization`, `apiKey`, `auth_header`, etc.) are masked with `***REDACTED***`.
- Raw credential values starting with `Bearer `, `tek_`, or `agt_sec_` are automatically detected and masked.
- Object traversal is protected against circular references.
- Zero raw secrets or plaintext tokens appear in audit payloads.

### 11.5 Event Taxonomy
| Event Type | Actor Type | Trigger Point | Payload Metadata |
| :--- | :--- | :--- | :--- |
| `agent.enrolled` | `admin` | TEK-authorized agent registration | Agent name, tags, capabilities, expiration |
| `agent.token_rotated` | `agent` | Instance token rotation | Token expiration timestamp |
| `agent.revoked` | `admin` | Administrative revocation | Reason, revokedAt timestamp |
| `job.leased` | `agent` | Atomic `SELECT FOR UPDATE SKIP LOCKED` poll | JobId, testRunId, leaseId, leaseExpiresAt, attempts |
| `job.completed` | `agent` | Signed completion ingestion | JobId, testRunId, leaseId, findingsCount, executionsCount |
| `job.failed` | `agent` | Failure report or timeout reap | JobId, testRunId, leaseId, error message |
| `job.cancelled` | `admin`/`agent` | User cancellation / cancel-ack | JobId, testRunId, reason |
| `security.tenant_mismatch` | `agent`/`admin` | Header spoofing / cross-tenant job access | Action, callerTenantId, targetTenantId, request IP |
| `security.scope_tampering` | `agent` | HMAC result signature verification failure | JobId, testRunId, leaseId, reason: SIGNATURE_MISMATCH |
| `security.protocol_violation` | `agent` | Missing or outdated protocol handshake | ClientVersion, minSupportedVersion, errorCode, request IP |

### 11.6 Admin Query API
- `GET /api/v1/agents/:id/audit-events`: Returns paginated audit trail for a specific agent scoped strictly to the authenticated tenant. Cross-tenant access is rejected with `403 TENANT_MISMATCH`. Non-existent agents return `404 AGENT_NOT_FOUND`.

# Phase 16: Implementation Master Plan & Sub-Phase Specifications

```text
DOCUMENT: docs/architecture/phase-16-implementation-plan.md
STATUS: RATIFIED MASTER SPECIFICATION
PROGRAM: Phase 16 — Distributed Agent Trust Boundary & Secure Execution Plane
REVISION: 1.0.0
```

---

## 1. Program Strategy & Phased Sequencing

To ensure strict engineering rigor, zero false completion claims, and uninterrupted local-first developer operation, Phase 16 is structured into **11 sequential, independently verifiable sub-phases**:

```text
Phase 16.0: Distributed Execution Reality Audit (Baseline, Test Harness & Contract Lock)
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

## 2. Detailed Sub-Phase Specifications

---

### Phase 16.0 — Distributed Execution Reality Audit (Baseline & Contract Lock)
* **Phase ID**: `phase-16-00-distributed-execution-audit`
* **Objective**: Reconcile codebase reality, lock in Phase 16 contracts, remove deceptive claims, and establish an adversarial baseline test suite demonstrating current trust boundary gaps.
* **Why**: Modifying code without a baseline test fixture demonstrating the vulnerabilities risks introducing regressions or declaring false completion.
* **Dependencies**: Existing codebase baseline.
* **Prerequisites**: Phase 15 code present in repository.
* **Current Code Reality**: 269 passing tests, but `agent-orchestration.test.ts` tests only happy-path; does not assert cross-tenant isolation on completion or check atomic claiming.
* **Implementation Scope**:
  - Create `tests/security/distributed-agent-boundaries.test.ts` testing for: anonymous registration, tenant header spoofing, cross-tenant job completion, and non-atomic claiming race conditions.
  - Document all baseline test assertions.
* **Non-Goals**: Do not implement fixes in this phase.
* **Affected Files**: `tests/security/distributed-agent-boundaries.test.ts`, `docs/architecture/current-state.md`.
* **Affected Packages**: Tests only.
* **Affected Applications**: None.
* **Database Changes**: None.
* **API Changes**: None.
* **Security Requirements**: Baseline tests must accurately capture known vulnerabilities without crashing the test runner.
* **Migration Requirements**: None.
* **Tests**: `pnpm exec vitest run tests/security/distributed-agent-boundaries.test.ts`.
* **Observability**: Log test failures indicating exposed trust boundaries.
* **Documentation**: Update `current-state.md` with Phase 15/16 baseline reality.
* **Validation Commands**: `pnpm test`.
* **Failure Conditions**: Baseline tests do not run or pass when they should document gaps.
* **Rollback Strategy**: Git revert.
* **Definition of Done**: Baseline gap test suite committed and documenting current vulnerabilities.
* **Next Phase Dependency**: Unlocks Phase 16.1.

---

### Phase 16.1 — Agent Identity, Enrollment Keys & Authentication Hardening
* **Phase ID**: `phase-16-01-agent-identity-authentication`
* **Objective**: Eliminate anonymous agent registration by implementing Tenant Enrollment Keys (TEK), agent token expiration, revocation, and rotation.
* **Why**: Anyone can currently register an agent under any tenant UUID and receive a valid token.
* **Dependencies**: Phase 16.0.
* **Prerequisites**: Phase 16.0 verified.
* **Current Code Reality**: `POST /api/v1/agents/register` has zero authentication; tokens have no expiration or revocation in `agents` table.
* **Implementation Scope**:
  - Add `tenant_enrollment_keys` table in PostgreSQL migration `0007_agent_trust_boundary.sql`.
  - Add `expires_at`, `revoked_at`, `revocation_reason` columns to `agents` table.
  - Update `POST /api/v1/agents/register` to require `Bearer tek_...`.
  - Add agent revocation and rotation APIs.
* **Non-Goals**: Do not touch job claiming logic.
* **Affected Files**: `apps/controller/src/routes/agents.ts`, `apps/controller/src/services/agent-dispatcher.service.ts`, `apps/controller/src/services/db/schema.ts`, `apps/agent/src/client.ts`, `apps/agent/src/daemon.ts`.
* **Affected Packages**: `@security-lab/contracts`, `@security-lab/controller`, `@security-lab/agent`.
* **Affected Applications**: `apps/controller`, `apps/agent`.
* **Database Changes**: New table `tenant_enrollment_keys`; alter `agents` table.
* **API Changes**: `POST /agents/register` requires TEK; add `POST /agents/:id/revoke`, `POST /agents/rotate-token`.
* **Security Requirements**: TEK and Agent Tokens must be stored only as SHA-256 hashes.
* **Migration Requirements**: Migration `0007_agent_trust_boundary.sql`.
* **Tests**: Unit & integration tests for valid TEK, expired TEK, invalid TEK, revoked token rejection.
* **Observability**: Structured audit logs for `agent.enrolled`, `agent.revoked`, `agent.rotated`.
* **Documentation**: Update `docs/architecture/saas-and-agent-architecture.md`.
* **Validation Commands**: `pnpm --filter @security-lab/agent build && pnpm test`.
* **Failure Conditions**: Anonymous registration still succeeds.
* **Rollback Strategy**: Git revert migration and code.
* **Definition of Done**: 100% of registrations require valid TEK; token revocation strictly enforced.
* **Next Phase Dependency**: Unlocks Phase 16.2.

---

### Phase 16.2 — Tenant Isolation, Contextual Binding & Route Authorization
* **Phase ID**: `phase-16-02-tenant-isolation-authorization`
* **Objective**: Remove client-controlled tenant headers and enforce strict cryptographic and contextual tenant derivation across all controller agent routes.
* **Why**: Attackers can spoof `x-tenant-id` to complete jobs belonging to other tenants.
* **Dependencies**: Phase 16.1.
* **Prerequisites**: Phase 16.1 verified.
* **Current Code Reality**: `extractTenantId` pulls from headers; `completeJob` and `reportJobProgress` do not check if calling agent belongs to job tenant.
* **Implementation Scope**:
  - Bind agent requests strictly to `agent.tenantId` extracted from DB session.
  - Enforce tenant match in `reportJobProgress`, `completeJob`, and `failJob`.
  - Reject any cross-tenant request with `403 Forbidden` and log security alert.
* **Non-Goals**: Do not alter leasing concurrency logic.
* **Affected Files**: `apps/controller/src/routes/agents.ts`, `apps/controller/src/services/tenant-context.ts`, `apps/controller/src/services/agent-dispatcher.service.ts`.
* **Affected Packages**: `@security-lab/controller`.
* **Affected Applications**: `apps/controller`.
* **Database Changes**: Ensure compound indexes on `(tenant_id, id)` across all tenant entities.
* **API Changes**: Rejection of mismatched `x-tenant-id`.
* **Security Requirements**: No header-based tenant trust for agent routes.
* **Migration Requirements**: None.
* **Tests**: Cross-tenant injection tests: Agent B attempting to complete Agent A's job returns 403.
* **Observability**: Emit `security.cross_tenant_attempt` alert.
* **Documentation**: Document tenant isolation guarantee.
* **Validation Commands**: `pnpm test`.
* **Failure Conditions**: Any cross-tenant job modification succeeds.
* **Rollback Strategy**: Git revert.
* **Definition of Done**: Cross-tenant job access is provably impossible.
* **Next Phase Dependency**: Unlocks Phase 16.3.

---

### Phase 16.3 — Atomic Job Leasing, Watchdog Reaper & State Machine
* **Phase ID**: `phase-16-03-job-leasing-state-machine`
* **Objective**: Implement atomic job claiming via PostgreSQL `SELECT FOR UPDATE SKIP LOCKED`, explicit lease expiration, and a background reaper service with bounded retries.
* **Why**: Current polling has a race condition allowing two agents to claim the same job; dead agents cause permanent job starvation.
* **Dependencies**: Phase 16.2.
* **Prerequisites**: Phase 16.2 verified.
* **Current Code Reality**: `pollJobs()` runs simple `SELECT` followed by `UPDATE`. No lease expiration, no reaper.
* **Implementation Scope**:
  - Add `lease_id`, `lease_expires_at`, `attempts`, `max_attempts` columns to `agent_jobs`.
  - Implement atomic claim query using `FOR UPDATE SKIP LOCKED`.
  - Implement `AgentJobReaper` running every 30s to requeue expired leases up to `maxAttempts = 3`.
  - Support heartbeat lease extensions.
* **Non-Goals**: Do not implement result signatures yet.
* **Affected Files**: `apps/controller/src/services/agent-dispatcher.service.ts`, `apps/controller/src/services/db/schema.ts`, `apps/agent/src/client.ts`, `apps/agent/src/daemon.ts`.
* **Affected Packages**: `@security-lab/contracts`, `@security-lab/controller`.
* **Affected Applications**: `apps/controller`, `apps/agent`.
* **Database Changes**: New columns in `agent_jobs` (in migration `0007`).
* **API Changes**: Polling returns `leaseId` and `leaseExpiresAt`.
* **Security Requirements**: At-most-once execution per lease; zero concurrency double-dispatch.
* **Migration Requirements**: Schema update.
* **Tests**: Concurrency test with 5 concurrent agents polling 1 job; lease timeout and reaper test.
* **Observability**: Metrics on `queue_depth`, `active_leases`, `reaped_jobs_count`.
* **Documentation**: Ratify `phase-16-job-state-machine.md`.
* **Validation Commands**: `pnpm test`.
* **Failure Conditions**: Concurrency test yields > 1 claim for a single job.
* **Rollback Strategy**: Git revert.
* **Definition of Done**: Atomic leasing verified under load; expired jobs cleanly reaped and retried.
* **Next Phase Dependency**: Unlocks Phase 16.4.

---

### Phase 16.4 — Result Authenticity, Evidence HMAC & Idempotent Ingestion
* **Phase ID**: `phase-16-04-result-integrity-idempotency`
* **Objective**: Guarantee result authenticity using HMAC attestation signatures and enforce idempotent terminal state completion.
* **Why**: Controller currently accepts raw, unsigned JSON findings; duplicate completions duplicate database records.
* **Dependencies**: Phase 16.3.
* **Prerequisites**: Phase 16.3 verified.
* **Current Code Reality**: `completeJob` accepts raw findings and blindly inserts them without signature checks or deduplication.
* **Implementation Scope**:
  - Issue ephemeral `jobDispatchSecret` with lease.
  - Agent computes HMAC-SHA256 signature over findings hash and submits with completion report.
  - Controller validates signature and lease ID before persisting.
  - Deduplicate repeat submissions: return 200 OK without re-inserting findings.
* **Non-Goals**: Do not touch Docker sandboxing.
* **Affected Files**: `packages/contracts/src/agent/index.ts`, `apps/agent/src/worker.ts`, `apps/controller/src/services/agent-dispatcher.service.ts`, `apps/controller/src/routes/agents.ts`.
* **Affected Packages**: `@security-lab/contracts`, `@security-lab/agent`, `@security-lab/controller`.
* **Affected Applications**: `apps/agent`, `apps/controller`.
* **Database Changes**: Store `result_signature` in `agent_jobs`.
* **API Changes**: `AgentJobCompletionReportSchema` includes `resultSignature` and `leaseId`.
* **Security Requirements**: Any modified finding byte must invalidate signature and reject report.
* **Migration Requirements**: None.
* **Tests**: Result tampering test; duplicate completion idempotency test.
* **Observability**: Audit events `result.accepted`, `result.rejected_tampered`, `result.deduplicated`.
* **Documentation**: Document result signing in `phase-16-agent-protocol.md`.
* **Validation Commands**: `pnpm test`.
* **Failure Conditions**: Tampered findings are accepted into database.
* **Rollback Strategy**: Git revert.
* **Definition of Done**: Tampered results rejected with 403; duplicate submissions safely deduplicated.
* **Next Phase Dependency**: Unlocks Phase 16.5.

---

### Phase 16.5 — Scope Cryptographic Binding & Distributed SSRF Defense
* **Phase ID**: `phase-16-05-scope-propagation-execution-authorization`
* **Objective**: Prevent scope tampering and in-VPC SSRF by cryptographically signing target scopes and enforcing agent-side defensive boundaries.
* **Why**: The agent worker currently trusts whatever scope is sent in the job payload and could be coerced into attacking internal cloud metadata or forbidden subnets.
* **Dependencies**: Phase 16.4.
* **Prerequisites**: Phase 16.4 verified.
* **Current Code Reality**: Agent accepts scope as raw object and passes to `safeFetch`.
* **Implementation Scope**:
  - Controller signs `TargetScope` with HMAC.
  - Agent worker verifies scope signature before execution.
  - Agent runtime enforces hardcoded prohibition against AWS/GCP metadata endpoints (`169.254.169.254`) regardless of job payload.
* **Non-Goals**: Do not modify Docker policy.
* **Affected Files**: `apps/controller/src/services/agent-dispatcher.service.ts`, `apps/agent/src/worker.ts`, `packages/test-sdk/src/http/safe-fetch.ts`.
* **Affected Packages**: `@security-lab/contracts`, `@security-lab/test-sdk`, `@security-lab/agent`.
* **Affected Applications**: `apps/agent`, `apps/controller`.
* **Database Changes**: None.
* **API Changes**: `AgentJobDispatchSchema` includes `scopeSignature`.
* **Security Requirements**: In-agent defense-in-depth: agent refuses to attack cloud metadata even if controller is compromised.
* **Migration Requirements**: None.
* **Tests**: Agent scope tampering test; in-VPC SSRF metadata probe test.
* **Observability**: Emit `security.scope_tampering_detected` alert.
* **Documentation**: Document scope boundary in `phase-16-agent-security-model.md`.
* **Validation Commands**: `pnpm test`.
* **Failure Conditions**: Tampered scope allows scanning unapproved host.
* **Rollback Strategy**: Git revert.
* **Definition of Done**: Cryptographically verified scope execution; agent blocks metadata attacks locally.
* **Next Phase Dependency**: Unlocks Phase 16.6.

---

### Phase 16.6 — Resource Governance, Execution Timeouts & Bidirectional Cancellation
* **Phase ID**: `phase-16-06-resource-governance-cancellation`
* **Objective**: Implement bidirectional cancellation propagation, hard execution timeouts, and rate limiting on agent endpoints.
* **Why**: Cancelling a test run currently does not stop the remote agent, and late completions overwrite cancellations.
* **Dependencies**: Phase 16.3, Phase 16.4.
* **Prerequisites**: Phase 16.4 verified.
* **Current Code Reality**: Controller updates DB to `'cancelled'`; agent never receives signal.
* **Implementation Scope**:
  - Heartbeat response includes `cancelledJobIds: string[]`.
  - Agent daemon invokes `abortController.abort()` on cancelled jobs and terminates child processes/containers within 2 seconds.
  - Enforce maximum job execution timeout (`limits.maxDuration`, default 15m).
  - Rate limit agent API endpoints (max 120 req/min for heartbeat/poll).
* **Non-Goals**: Do not re-architect container runner.
* **Affected Files**: `apps/controller/src/routes/agents.ts`, `apps/controller/src/services/agent-dispatcher.service.ts`, `apps/agent/src/daemon.ts`, `apps/agent/src/worker.ts`.
* **Affected Packages**: `@security-lab/contracts`, `@security-lab/controller`, `@security-lab/agent`.
* **Affected Applications**: `apps/controller`, `apps/agent`.
* **Database Changes**: None.
* **API Changes**: Heartbeat response schema includes `cancelledJobIds`.
* **Security Requirements**: Cancellation must terminate active execution and prevent subsequent result ingestion.
* **Migration Requirements**: None.
* **Tests**: Test cancelling a running distributed job; verify agent aborts and test run remains cancelled.
* **Observability**: Log `job.cancelled_propagated`, rate limit breach warnings.
* **Documentation**: Update cancellation flow in `phase-16-job-state-machine.md`.
* **Validation Commands**: `pnpm test`.
* **Failure Conditions**: Agent completion overwrites cancelled state.
* **Rollback Strategy**: Git revert.
* **Definition of Done**: Emergency user cancellation stops agent within 2 heartbeat cycles.
* **Next Phase Dependency**: Unlocks Phase 16.7.

---

### Phase 16.7 — Agent Docker Sandbox Hardening & Host Boundary Protection
* **Phase ID**: `phase-16-07-agent-docker-host-security`
* **Objective**: Eliminate raw `/var/run/docker.sock` host-takeover risks in agent deployments and harden container scanner execution.
* **Why**: Deployment documentation and K8s manifests currently mount Docker socket directly into the agent container.
* **Dependencies**: Phase 16.5.
* **Prerequisites**: Phase 16.5 verified.
* **Current Code Reality**: `infrastructure/k8s/agent.yaml` has `hostPath: /var/run/docker.sock`; docs instruct `-v /var/run/docker.sock:/var/run/docker.sock`.
* **Implementation Scope**:
  - Update `infrastructure/k8s/agent.yaml` to remove privileged Docker socket hostPath mount; document in-pod native scanning and external runner options.
  - Update `docs/architecture/saas-and-agent-architecture.md` to remove unsafe Docker socket examples and replace with least-privilege deployment architecture.
  - Enforce strict image digest verification in `docker-policy.ts`.
* **Non-Goals**: Do not implement a complex Kubernetes operator.
* **Affected Files**: `infrastructure/k8s/agent.yaml`, `docs/architecture/saas-and-agent-architecture.md`, `packages/test-sdk/src/runners/docker-policy.ts`.
* **Affected Packages**: `@security-lab/test-sdk`, `infrastructure`.
* **Affected Applications**: `apps/agent`.
* **Database Changes**: None.
* **API Changes**: None.
* **Security Requirements**: Zero unrestricted Docker socket exposure.
* **Migration Requirements**: None.
* **Tests**: Security benchmark assertion verifying K8s manifest contains no privileged or socket mounts.
* **Observability**: Log container execution events with image digest and dropped capabilities.
* **Documentation**: Ratify hardened deployment architecture.
* **Validation Commands**: `pnpm test`.
* **Failure Conditions**: Docker socket mount remains in recommended deployment manifests.
* **Rollback Strategy**: Git revert.
* **Definition of Done**: Zero Docker socket mounts in production deployment templates.
* **Next Phase Dependency**: Unlocks Phase 16.8.

---

### Phase 16.8 — Protocol Handshake, Semantic Versioning & Capability Negotiation
* **Phase ID**: `phase-16-08-protocol-versioning`
* **Objective**: Implement explicit protocol version headers, handshake negotiation, and capability matching in job polling.
* **Why**: Controller currently has no protocol versioning and ignores agent capabilities/tags during job dispatch.
* **Dependencies**: Phase 16.3, Phase 16.7.
* **Prerequisites**: Phase 16.7 verified.
* **Current Code Reality**: Zero protocol version headers; `pollJobs()` parameter `_capabilities` is ignored.
* **Implementation Scope**:
  - Add `X-Protocol-Version` and `X-Agent-Version` headers.
  - Implement handshake compatibility check (compatible, upgrade required, incompatible).
  - Update atomic poll query to enforce capability and tag containment (`required_capabilities <@ agent_capabilities`).
* **Non-Goals**: Do not introduce breaking protocol changes for existing local CLI mode.
* **Affected Files**: `packages/contracts/src/agent/index.ts`, `apps/controller/src/routes/agents.ts`, `apps/controller/src/services/agent-dispatcher.service.ts`, `apps/agent/src/client.ts`.
* **Affected Packages**: `@security-lab/contracts`, `@security-lab/controller`, `@security-lab/agent`.
* **Affected Applications**: `apps/controller`, `apps/agent`.
* **Database Changes**: Add `required_capabilities` and `required_tags` JSONB columns to `agent_jobs`.
* **API Changes**: Version headers in all agent endpoints; `426 Upgrade Required` on outdated protocol.
* **Security Requirements**: Incompatible or spoofed protocol versions must fail closed.
* **Migration Requirements**: Migration script updates.
* **Tests**: Version compatibility tests: compatible version succeeds, outdated version returns 426; capability matching test.
* **Observability**: Log protocol version distribution metrics.
* **Documentation**: Ratify `phase-16-agent-protocol.md`.
* **Validation Commands**: `pnpm test`.
* **Failure Conditions**: Agent with mismatched capabilities receives incompatible job.
* **Rollback Strategy**: Git revert.
* **Definition of Done**: Protocol versioning strictly enforced; capability-based routing fully functional.
* **Next Phase Dependency**: Unlocks Phase 16.9.

---

### Phase 16.9 — Security Audit Logging & Distributed Telemetry Observability
* **Phase ID**: `phase-16-09-audit-observability`
* **Objective**: Implement dedicated append-only audit event logging for all agent lifecycle events and distributed execution telemetry.
* **Why**: Controller currently relies on generic Pino logs; compliance standards require immutable, queryable audit trails.
* **Dependencies**: Phase 16.1 through Phase 16.8.
* **Prerequisites**: Phase 16.8 verified.
* **Current Code Reality**: Generic Pino logs only; no audit events table.
* **Implementation Scope**:
  - Add `agent_audit_events` table in PostgreSQL migration.
  - Record events: `agent.enrolled`, `agent.authenticated`, `agent.revoked`, `job.leased`, `job.completed`, `job.failed`, `job.cancelled`, `scope.violation`, `tenant.spoof_attempt`.
  - Redact all secrets and credentials from audit metadata.
  - Expose `GET /api/v1/agents/:id/audit-events` for tenant administrators.
* **Non-Goals**: Do not build an external SIEM exporter.
* **Affected Files**: `apps/controller/src/services/db/schema.ts`, `apps/controller/src/services/agent-dispatcher.service.ts`, `apps/controller/src/routes/agents.ts`.
* **Affected Packages**: `@security-lab/controller`.
* **Affected Applications**: `apps/controller`.
* **Database Changes**: New table `agent_audit_events`.
* **API Changes**: New audit query endpoint.
* **Security Requirements**: Zero sensitive credentials in audit payloads; append-only storage.
* **Migration Requirements**: Database migration.
* **Tests**: Audit logging verification: assert events recorded on enrollment, claim, and completion.
* **Observability**: Audit event counter metrics.
* **Documentation**: Document audit events in architecture guide.
* **Validation Commands**: `pnpm test`.
* **Failure Conditions**: Audit records fail to record or leak secrets.
* **Rollback Strategy**: Git revert.
* **Definition of Done**: Comprehensive, secret-scrubbed audit trail recorded for all agent actions.
* **Next Phase Dependency**: Unlocks Phase 16.10.

---

### Phase 16.10 — End-to-End Adversarial Security & Penetration Verification
* **Phase ID**: `phase-16-10-end-to-end-verification`
* **Objective**: Execute a comprehensive adversarial penetration test suite verifying all 18 threat mitigations across the distributed execution plane.
* **Why**: Proves that the platform meets the highest standards of enterprise security QA before release.
* **Dependencies**: Phase 16.0 through Phase 16.9.
* **Prerequisites**: Phase 16.9 verified.
* **Current Code Reality**: 8 happy-path tests in `agent-orchestration.test.ts`.
* **Implementation Scope**:
  - Implement full adversarial test suite in `tests/security/distributed-agent-penetration.test.ts` covering:
    1. Anonymous registration attempts (blocked)
    2. Tenant spoofing via headers (blocked)
    3. Cross-tenant job completion (blocked)
    4. Replay attacks with stale tokens/nonces (blocked)
    5. Result finding forgery and tampering (blocked)
    6. Scope expansion and private IP probing (blocked)
    7. High-concurrency race condition claiming (atomic)
    8. Lease expiration, reaping, and late completion deduplication
    9. Emergency cancellation propagation
    10. Docker container breakout policy enforcement
* **Non-Goals**: Do not add new features.
* **Affected Files**: `tests/security/distributed-agent-penetration.test.ts`, `prompts/README.md`.
* **Affected Packages**: Tests only.
* **Affected Applications**: All.
* **Database Changes**: None.
* **API Changes**: None.
* **Security Requirements**: 100% of adversarial penetration tests must pass.
* **Migration Requirements**: None.
* **Tests**: `pnpm exec vitest run tests/security/distributed-agent-penetration.test.ts`.
* **Observability**: Comprehensive test report logging.
* **Documentation**: Finalize Phase 16 verification sign-off.
* **Validation Commands**: `pnpm test && pnpm run typecheck && pnpm run lint`.
* **Failure Conditions**: Any penetration test fails.
* **Rollback Strategy**: Fix discovered gaps.
* **Definition of Done**: All 18 threats provably mitigated and passing automated verification tests.
* **Next Phase Dependency**: Completes Phase 16; unlocks Horizon 4 production release.

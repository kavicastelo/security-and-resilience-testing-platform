# Phase 16: Distributed Agent Threat Model (STRIDE & Threat Matrix)

```text
DOCUMENT: docs/architecture/phase-16-threat-model.md
STATUS: RATIFIED SPECIFICATION
PHASE: Phase 16 — Distributed Agent Trust Boundary & Secure Execution Plane
METHODOLOGY: STRIDE & Attack Surface Analysis
REVISION: 1.0.0
```

---

## 1. Executive Summary

Distributed security testing systems possess a unique security profile: they are purposefully designed to execute security probes, vulnerability audits, and stress testing against target applications. If the control plane, agent, or communication link is subverted, the platform itself becomes an unconstrained, privileged offensive weapon inside customer enterprise networks.

This threat model rigorously evaluates the 18 critical threat scenarios defined for the distributed execution architecture.

---

## 2. Threat Scenarios Analysis Matrix (T1 – T18)

### T1: Agent Impersonation
- **Threat**: An unauthorized adversary registers as an agent or impersonates a legitimate agent daemon.
- **Attack Path**: Attacker calls `POST /api/v1/agents/register` anonymously or steals an agent token from logs/environment.
- **Impact**: Attacker pulls proprietary test jobs, learns internal IP topologies, and receives sensitive scan configs.
- **Current Mitigation**: Agent tokens are prefixed with `agt_sec_` and hashed with SHA-256 before storage in database.
- **Gap**: Registration requires zero authentication; anyone can register an agent. Tokens never expire and cannot be revoked.
- **Required Mitigation**: Two-tier key hierarchy: registration requires a pre-shared Tenant Enrollment Key (`tek_...`) with expiration and maximum usage caps. Tokens support instant administrative revocation and rotation.
- **Verification Method**: Test registration without TEK fails with 401; test with revoked agent token fails with 403.

---

### T2: Tenant Spoofing
- **Threat**: An attacker or rogue tenant registers or executes operations on behalf of another tenant.
- **Attack Path**: Attacker includes `x-tenant-id: <VICTIM_TENANT_UUID>` header in registration or API dispatch.
- **Impact**: Full cross-tenant contamination: accessing victim's target definitions, stealing jobs, or injecting false reports.
- **Current Mitigation**: None for registration. Polling uses the agent's registered tenant ID.
- **Gap**: `extractTenantId` trusts client-supplied `x-tenant-id` header without cryptographic validation.
- **Required Mitigation**: Eliminate header-based tenant trust. Derive tenant identity exclusively from the authenticated TEK or database-persisted agent record.
- **Verification Method**: Adversarial integration test: client sends `x-tenant-id` of Tenant B using credentials of Tenant A; controller rejects request or binds strictly to Tenant A.

---

### T3: Job Theft (Cross-Tenant Job Claiming)
- **Threat**: Agent belonging to Tenant A claims or executes a job intended for Tenant B.
- **Attack Path**: Agent calls `POST /api/v1/agents/poll` or crafts job claim requests.
- **Impact**: Data leakage of target endpoints, proprietary API routes, and intellectual property.
- **Current Mitigation**: `pollJobs()` filters database query by `agent.tenantId`.
- **Gap**: Job completion (`POST /jobs/:id/complete`) does NOT check tenant ID or agent ownership.
- **Required Mitigation**: Compound authorization checks on claim and completion: assert `job.tenant_id == agent.tenant_id` and `job.agent_id == agent.id`.
- **Verification Method**: Attempt to complete Tenant A's job using Tenant B's agent token returns 403 Forbidden.

---

### T4: Job Replay Attacks
- **Threat**: An eavesdropper or malicious agent captures and replays historical registration, heartbeat, or job messages.
- **Attack Path**: Re-sending previously recorded completion or heartbeat payloads over the network.
- **Impact**: Overwriting active test run statuses, triggering redundant gate evaluations, or desynchronizing metrics.
- **Current Mitigation**: TLS 1.3 encryption prevents casual passive eavesdropping.
- **Gap**: Controller lacks nonce/timestamp freshness checks; completion route has no idempotency deduplication.
- **Required Mitigation**: Mandatory `Idempotency-Key: <UUID>` header; heartbeat timestamp drift check (reject if `|serverTime - clientTime| > 60s`); terminal state immutability.
- **Verification Method**: Replaying an identical completion request twice returns `200 OK` with `{ deduplicated: true }` and exactly one set of DB records.

---

### T5: Result Forgery & Finding Manipulation
- **Threat**: A compromised agent or network attacker alters finding severities (e.g. downgrading Critical to Info) or fabricates vulnerabilities.
- **Attack Path**: Modifying JSON payload in `POST /jobs/:id/complete`.
- **Impact**: Vulnerable code is deployed to production by falsely passing release gates; or false alarms cause denial of service.
- **Current Mitigation**: Database stores findings with fingerprint hashes.
- **Gap**: The controller accepts unauthenticated, unsigned JSON finding arrays from the agent.
- **Required Mitigation**: Ephemeral `JobDispatchSecret` issued to the agent during leasing. Agent signs `SHA-256(findings + executions)` using HMAC-SHA256. Controller validates signature before persisting.
- **Verification Method**: Modifying 1 byte of finding description in completion payload causes signature mismatch and 403 rejection.

---

### T6: Target Scope Expansion
- **Threat**: An agent modifies the authorized target scope to scan unauthorized external third-party systems or private cloud infrastructure.
- **Attack Path**: Tampering with `target.scope` in the agent worker before invoking engines.
- **Impact**: Legal liability from unauthorized port scanning, denial of service against third parties, or cloud provider abuse violations.
- **Current Mitigation**: `validateUrlAgainstScope` checks URLs in `safeFetch`.
- **Gap**: The agent worker trusts whatever scope object was sent in the job payload without controller signature.
- **Required Mitigation**: Controller signs the authorized `TargetScope` with HMAC. Agent verifies scope signature prior to dispatching any probe. In-agent egress filtering blocks private metadata addresses (`169.254.169.254`).
- **Verification Method**: Test altering `allowedHosts` in agent payload; agent worker halts with `ScopeTamperingError`.

---

### T7: Target URL Tampering
- **Threat**: Man-in-the-middle or agent attacker mutates `target.baseUrl` to redirect scanning traffic to internal administrative panels.
- **Attack Path**: Changing `http://target-api:8080` to `http://internal-consul:8500`.
- **Impact**: Accidental or malicious disruption of critical internal services.
- **Current Mitigation**: Target baseUrl is saved in PostgreSQL.
- **Gap**: Unsigned in transit between controller and agent.
- **Required Mitigation**: Controller-signed job payload binding `target.id`, `target.baseUrl`, and `target.scope` together in an immutable dispatch token.
- **Verification Method**: Tampering with target URL fails dispatch token verification.

---

### T8: Capability Spoofing
- **Threat**: An agent falsely advertises high-security or specialized capabilities (e.g. `pci-zone-worker`, `engine-zap`) that it cannot or should not execute.
- **Attack Path**: Agent self-declares arbitrary strings in `AgentRegistrationRequest.capabilities`.
- **Impact**: Jobs requiring container scanners or specific network placement are routed to incapable agents, failing scans.
- **Current Mitigation**: None; `pollJobs()` currently ignores capabilities completely.
- **Gap**: Complete absence of capability authorization.
- **Required Mitigation**: Distinguish self-declared agent capabilities from controller-approved tenant capabilities. Admin approves agent tags. Polling checks DB array containment.
- **Verification Method**: Agent without `engine-zap` capability never receives jobs requiring ZAP.

---

### T9: Credential Leakage in Job Payloads & Logs
- **Threat**: API keys, Basic Auth headers, or JWT tokens embedded in test definitions leak through logs or database records.
- **Attack Path**: Viewing application logs or querying `agent_jobs.payload`.
- **Impact**: Compromise of target application administrative credentials.
- **Current Mitigation**: AES-256-GCM encryption used in `credentials` table for vault storage.
- **Gap**: `agent_jobs.payload` stores plaintext `customHeaders` with raw `Authorization` tokens.
- **Required Mitigation**: Redact sensitive headers (`Authorization`, `X-Api-Key`, `Cookie`) from all structured logs. Ephemeral injection into agent memory; database stores only encrypted payload references.
- **Verification Method**: Grep logs during test run with bearer tokens; verify zero raw token matches.

---

### T10: Agent Compromise
- **Threat**: An attacker achieves Remote Code Execution (RCE) on the host or container running the agent daemon.
- **Attack Path**: Exploiting a vulnerability in a third-party scanning engine or dependency.
- **Impact**: Attacker pivots into customer internal network / VPC.
- **Current Mitigation**: Agent Docker container runs as non-root user `securitylab` (UID 10001).
- **Gap**: Mounting `/var/run/docker.sock` allows trivial escape from container to host root.
- **Required Mitigation**: Strictly prohibit `/var/run/docker.sock` in containerized agent deployments. Run scanners via rootless execution or isolated ephemeral VM/Kubernetes Job brokers.
- **Verification Method**: Security benchmark inspection: verify agent container has no socket mounts and operates under read-only rootfs.

---

### T11: Docker Host Compromise via Scanner Containers
- **Threat**: A malicious test payload or malicious container image compromises the Docker daemon host.
- **Attack Path**: Container breakout, kernel privilege escalation, or mounting host root `/`.
- **Impact**: Full root compromise of the machine hosting the agent.
- **Current Mitigation**: `packages/test-sdk/src/runners/docker-policy.ts` enforces `isApprovedImage()`, `--security-opt=no-new-privileges:true`, `--cap-drop=ALL`, and volume path sanitization.
- **Gap**: Deployment manifests currently bypass this by mounting Docker socket to the agent itself.
- **Required Mitigation**: Defense-in-depth: strict image digest pinning, no-new-privileges, dropped Linux capabilities, and scratch-only ephemeral directory mounts.
- **Verification Method**: Attempt to execute an unapproved image (e.g. `ubuntu:latest`) or mount `/etc`; runner throws `ContainerSecurityError`.

---

### T12: Resource Exhaustion & Denial of Service
- **Threat**: A rogue or misconfigured agent floods the controller with 10,000 requests/sec, or submits 1GB result payloads.
- **Attack Path**: High-frequency polling loops or multi-megabyte JSON finding arrays.
- **Impact**: Control plane memory exhaustion, PostgreSQL connection pool starvation, service outage.
- **Current Mitigation**: Node.js event loop handles async I/O.
- **Gap**: No rate limiting on `/heartbeat` or `/poll`. Fastify payload limits not tuned per route.
- **Required Mitigation**: Per-agent sliding-window rate limiting (max 120 req/min for heartbeats/polling). Max payload size of 5MB for `/complete`. Hard cap of 5,000 findings per report.
- **Verification Method**: Load test exceeding rate limit returns 429 Too Many Requests.

---

### T13: Controller Compromise
- **Threat**: The central SaaS control plane is compromised by an attacker.
- **Attack Path**: Exploiting an API vulnerability in Fastify or gaining administrative access.
- **Impact**: Attacker could attempt to dispatch malicious scanning jobs to private customer agents.
- **Current Mitigation**: Multi-tenant database partitioning.
- **Gap**: If controller is compromised, agents currently execute any target URL dispatched to them.
- **Required Mitigation**: In-agent defensive boundaries: the agent daemon enforces local policy rules (e.g. hardcoded refusal to scan private cloud metadata or loopbacks unless agent configuration explicitly enables internal mode).
- **Verification Method**: Dispatching a job targeting `169.254.169.254` causes the agent worker to abort locally with `SecurityBoundaryError`.

---

### T14: Database Compromise
- **Threat**: Direct read/write access to PostgreSQL database is obtained by an unauthorized actor.
- **Attack Path**: SQL injection or compromised database credentials.
- **Impact**: Access to historical findings, agent tokens, and target configurations.
- **Current Mitigation**: Drizzle ORM uses parameterized queries throughout. Agent tokens stored as SHA-256 hashes.
- **Gap**: Tenant data resides in a shared schema without PostgreSQL Row Level Security (RLS) policies.
- **Required Mitigation**: Implement PostgreSQL Row Level Security (RLS) policies using session tenant variables; maintain append-only triggers on evidence records.
- **Verification Method**: Direct query without setting `app.current_tenant_id` returns 0 rows.

---

### T15: Network Interception & Man-in-the-Middle
- **Threat**: Network attacker intercepts, modifies, or drops traffic between Agent and Controller.
- **Attack Path**: Compromised proxy, rogue Wi-Fi, or DNS hijacking.
- **Impact**: Credential theft, job tampering, result manipulation.
- **Current Mitigation**: HTTPS/TLS encryption.
- **Gap**: Agent does not pin certificate authorities or certificates; vulnerable to enterprise SSL inspection proxies.
- **Required Mitigation**: Enforce TLS 1.3 with optional CA pinning or future mTLS mutual certificate validation.
- **Verification Method**: Plaintext HTTP connection rejected; invalid TLS cert rejected.

---

### T16: Malicious or Misconfigured Private Agent
- **Threat**: A customer's internal agent is deliberately configured to act maliciously or is deployed in the wrong environment.
- **Attack Path**: Malicious internal employee registers an agent and points it at production targets.
- **Impact**: Production service degradation or unauthorized penetration testing.
- **Current Mitigation**: Role-based access control on project and target creation.
- **Gap**: Agent capabilities and tags are self-declared without control plane approval.
- **Required Mitigation**: Administrative agent approval workflow: new agents start in `pending_approval` status until tenant admin authorizes them for specific project scopes.
- **Verification Method**: Unapproved agent polling returns zero jobs.

---

### T17: Stale Agent Execution
- **Threat**: An agent that has been disconnected for hours reconnects and attempts to execute or complete stale jobs.
- **Attack Path**: Long network partition followed by delayed job execution.
- **Impact**: Findings generated against an old target state overwrite newer test run results.
- **Current Mitigation**: None.
- **Gap**: Dispatched jobs never expire in current schema.
- **Required Mitigation**: Lease timeouts: jobs expire in 5 minutes unless renewed. Stale completions rejected with `409 Conflict (LEASE_EXPIRED)`.
- **Verification Method**: Simulate agent sleeping past lease expiration; completion attempt is rejected.

---

### T18: Concurrency Race Conditions
- **Threat**: Simultaneous polling or simultaneous cancellation/completion creates undefined database states.
- **Attack Path**: Parallel requests hitting controller endpoints at the exact same millisecond.
- **Impact**: Two agents running the same job, or completion overwriting a user cancellation.
- **Current Mitigation**: In-memory `ExecutionManager` uses a local queue with concurrency limit.
- **Gap**: Controller database queries lack atomic row locks (`FOR UPDATE SKIP LOCKED`).
- **Required Mitigation**: Atomic claim queries with `SKIP LOCKED`; atomic conditional updates on state transitions (`UPDATE ... WHERE id = $1 AND status = 'running'`).
- **Verification Method**: Concurrency test with 10 agents polling 1 job: exactly 1 agent receives the job; 9 receive empty lists.

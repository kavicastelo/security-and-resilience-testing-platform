# Phase 16: Agent-to-Controller Communication Protocol Specification

```text
DOCUMENT: docs/architecture/phase-16-agent-protocol.md
STATUS: RATIFIED SPECIFICATION
PHASE: Phase 16 — Distributed Agent Trust Boundary & Secure Execution Plane
PROTOCOL VERSION: 1.0.0
COMPATIBLE CONTROLLER VERSIONS: >= 0.2.0
```

---

## 1. Protocol Architecture & Overview

The Security Lab Agent Protocol is a resilient, outbound-only, REST/JSON and Server-Sent Events (SSE) protocol connecting distributed private execution agents to the central control plane over TLS 1.3.

### Core Principles
1. **Outbound Only**: The agent initiates all connections over HTTPS (Port 443). The controller NEVER initiates an inbound TCP connection into the customer network.
2. **Strict Protocol Versioning**: Every request and response carries semantic protocol version headers (`X-Protocol-Version`).
3. **Deterministic Idempotency**: All state-mutating requests carry unique idempotency keys (`Idempotency-Key: <UUID>`).
4. **Machine-Readable Errors**: Standardized JSON error envelopes with explicit diagnostic error codes.

---

## 2. Protocol Version Negotiation & Compatibility Matrix

### Version Headers
- `X-Protocol-Version`: Declares protocol specification version (e.g. `1.0.0`).
- `X-Agent-Version`: Semantic version of agent daemon (e.g. `0.2.0`).
- `X-Controller-Version`: Semantic version of controller (e.g. `0.2.0`).

### Active Protocol Constants (Phase 16.8)
- `CURRENT_PROTOCOL_VERSION`: `'1.0.0'`
- `MIN_SUPPORTED_PROTOCOL_VERSION`: `'1.0.0'`
- `CONTROLLER_VERSION`: `'0.2.0'`
- `AGENT_VERSION`: `'0.2.0'`

### Compatibility & Negotiation Matrix

| Client Protocol | Controller Protocol | Handshake Result | HTTP Status | Error Code | Action Taken |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `1.0.0` | `1.0.0` | `COMPATIBLE` | `200/201` | None | Normal operation. All responses carry `X-Protocol-Version` and `X-Controller-Version`. |
| Missing | `1.0.0` | `UNSUPPORTED_MISSING` | `426 Upgrade Required` | `PROTOCOL_INCOMPATIBLE` | Rejected. Agent shuts down cleanly. |
| `< 1.0.0` (e.g. `0.8.0`) | `1.0.0` | `UNSUPPORTED_OUTDATED` | `426 Upgrade Required` | `PROTOCOL_INCOMPATIBLE` | Rejected. Agent shuts down cleanly. |
| `2.0.0` (major mismatch) | `1.0.0` | `INCOMPATIBLE_MAJOR` | `400 Bad Request` | `INCOMPATIBLE_MAJOR` | Rejected with diagnostic mismatch error. |

### Capability & Tag Negotiation in Job Leasing
Pending jobs specify required execution capabilities and network zone tags. The controller enforces array containment at the database engine level using PostgreSQL JSONB containment (`<@`):
```sql
AND (required_capabilities <@ ${capsJson}::jsonb OR required_capabilities = '[]'::jsonb)
AND (required_tags <@ ${tagsJson}::jsonb OR required_tags = '[]'::jsonb)
```
- An agent without `engine-zap` will never be leased a job requiring ZAP scanning.
- An agent in `vpc-dev` will never be leased a job targeted strictly to `vpc-prod`.
- Jobs with empty requirement arrays remain 100% backward-compatible and claimable by any agent in the tenant.


---

## 3. Standard Request & Response Envelopes

### Standard Success Envelope
```json
{
  "success": true,
  "data": { ... },
  "metadata": {
    "serverTime": "2026-10-07T07:30:00.000Z",
    "protocolVersion": "1.0.0"
  }
}
```

### Standard Error Envelope
```json
{
  "success": false,
  "error": {
    "code": "AGENT_UNAUTHORIZED",
    "message": "Bearer token is invalid, expired, or has been revoked.",
    "details": {
      "reason": "token_expired",
      "expiredAt": "2026-10-06T23:59:59.000Z"
    }
  },
  "metadata": {
    "serverTime": "2026-10-07T07:30:00.000Z",
    "protocolVersion": "1.0.0"
  }
}
```

---

## 4. API Endpoints Specification

### 4.1 Endpoint 1: Agent Registration / Enrollment
- **Path**: `POST /api/v1/agents/register`
- **Purpose**: Enrolls a new distributed execution agent under a tenant.
- **Authentication**: `Bearer tek_<tenant_slug>_<random_hex>` (Tenant Enrollment Key).
- **Authorization**: Validates active TEK in database; extracts Tenant ID directly from the enrollment record.
- **Tenant Derivation**: DERIVED FROM ENROLLMENT KEY. Client `x-tenant-id` header is IGNORED.
- **Audit Event**: `agent.enrolled`

#### Request Body
```json
{
  "name": "internal-vpc-agent-01",
  "tags": ["vpc-internal", "staging", "us-east-1"],
  "capabilities": [
    "engine-native-headers",
    "engine-native-cors",
    "engine-native-tls",
    "engine-native-auth",
    "engine-native-resilience",
    "declarative",
    "engine-zap",
    "engine-trivy",
    "engine-k6"
  ],
  "systemInfo": {
    "os": "linux",
    "arch": "x64",
    "nodeVersion": "v20.18.0",
    "cpuCount": 4,
    "totalMemoryMb": 8192,
    "hostname": "k8s-node-worker-4a"
  }
}
```

#### Response Body (`201 Created`)
```json
{
  "success": true,
  "data": {
    "agentId": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "tenantId": "c1313d63-6e53-47b3-b308-57c99ee3520f",
    "name": "internal-vpc-agent-01",
    "token": "agt_sec_8f9c1b72a4...<32 random bytes>",
    "tokenExpiresAt": "2027-01-05T07:30:00.000Z",
    "status": "offline",
    "tags": ["vpc-internal", "staging", "us-east-1"],
    "capabilities": ["engine-native-headers", "engine-native-cors", "engine-zap"],
    "createdAt": "2026-10-07T07:30:00.000Z"
  }
}
```

---

### 4.2 Endpoint 2: Agent Heartbeat Telemetry & Command Backchannel
- **Path**: `POST /api/v1/agents/heartbeat`
- **Purpose**: Checks in every 10–30s with resource telemetry and receives pending controller commands.
- **Authentication**: `Bearer agt_sec_...`
- **Tenant Derivation**: Looked up via `agent.tenantId`.
- **Audit Event**: `agent.heartbeat` (logged at info/debug; warned if high resource usage).

#### Request Body
```json
{
  "agentId": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "status": "online",
  "metrics": {
    "cpuUsagePercent": 14.2,
    "memoryUsageMb": 312,
    "activeJobsCount": 1
  },
  "activeJobLeases": [
    {
      "jobId": "7a94f6c1-5717-4562-b3fc-2c963f66afa6",
      "leaseId": "ls_9f8a7b6c5d4e",
      "elapsedMs": 45000
    }
  ]
}
```

#### Response Body (`200 OK`)
```json
{
  "success": true,
  "data": {
    "acknowledged": true,
    "timestamp": "2026-10-07T07:30:15.000Z",
    "command": "continue",
    "commandPayload": null,
    "renewedLeases": [
      {
        "jobId": "7a94f6c1-5717-4562-b3fc-2c963f66afa6",
        "leaseExpiresAt": "2026-10-07T07:35:15.000Z"
      }
    ],
    "cancelledJobIds": []
  }
}
```
*Note on Cancellation*: If a job was cancelled by a user in the UI, `cancelledJobIds` includes `["7a94f6c1-..."]`. The agent daemon immediately aborts the corresponding worker's `AbortController`.

---

### 4.3 Endpoint 3: Secure Job Polling & Atomic Leasing
- **Path**: `POST /api/v1/agents/poll`
- **Purpose**: Atomically claims available pending jobs matching agent capabilities and tenant.
- **Authentication**: `Bearer agt_sec_...`
- **Concurrency & Atomicity**: The controller executes PostgreSQL `SELECT ... FOR UPDATE SKIP LOCKED`.
- **Audit Event**: `job.leased`

#### Request Body
```json
{
  "agentId": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "maxJobs": 1,
  "capabilities": [
    "engine-native-headers",
    "engine-native-cors",
    "engine-native-tls",
    "engine-zap"
  ],
  "tags": ["vpc-internal", "staging"]
}
```

#### Response Body (`200 OK`)
```json
{
  "success": true,
  "data": {
    "jobs": [
      {
        "jobId": "7a94f6c1-5717-4562-b3fc-2c963f66afa6",
        "leaseId": "ls_9f8a7b6c5d4e3f2a1b",
        "leaseExpiresAt": "2026-10-07T07:35:00.000Z",
        "testRunId": "91d7c041-5717-4562-b3fc-2c963f66afa6",
        "tenantId": "c1313d63-6e53-47b3-b308-57c99ee3520f",
        "target": {
          "id": "e2b3c4d5-5717-4562-b3fc-2c963f66afa6",
          "name": "Internal Billing Service",
          "baseUrl": "http://billing.internal.vpc:8080",
          "scope": {
            "allowedHosts": ["billing.internal.vpc"],
            "allowedPorts": [8080],
            "excludedPaths": ["/admin/shutdown"],
            "testing": { "activeScanning": true, "loadTesting": false, "chaosTesting": false },
            "limits": { "maxRps": 20, "maxConcurrency": 2, "maxDuration": "3m" }
          },
          "scopeSignature": "hmac_sha256_controller_signed_scope_hash"
        },
        "engineIds": ["engine-native-headers", "engine-native-cors"],
        "options": {},
        "jobDispatchSecret": "ephemeral_hmac_secret_for_result_signing"
      }
    ]
  }
}
```

---

### 4.4 Endpoint 4: In-Flight Job Execution Progress
- **Path**: `POST /api/v1/agents/jobs/:jobId/progress`
- **Purpose**: Relays live execution progress to the control plane (relayed via SSE to the dashboard).
- **Authentication**: `Bearer agt_sec_...`
- **Authorization**: Caller MUST hold the active lease on `:jobId`.
- **Audit Event**: Relayed to real-time `executionManager` event emitter.

#### Request Body
```json
{
  "jobId": "7a94f6c1-5717-4562-b3fc-2c963f66afa6",
  "leaseId": "ls_9f8a7b6c5d4e3f2a1b",
  "testRunId": "91d7c041-5717-4562-b3fc-2c963f66afa6",
  "percent": 50,
  "message": "Executing engine-native-cors against http://billing.internal.vpc:8080...",
  "currentEngineId": "engine-native-cors"
}
```

#### Response Body (`200 OK`)
```json
{
  "success": true,
  "data": { "acknowledged": true }
}
```

---

### 4.5 Endpoint 5: Secure Job Completion & Result Ingestion
- **Path**: `POST /api/v1/agents/jobs/:jobId/complete`
- **Purpose**: Submits normalized findings, quantitative metrics, and execution summaries.
- **Authentication**: `Bearer agt_sec_...`
- **Authorization**: Caller MUST hold the active, unexpired lease on `:jobId` and match `job.tenant_id`.
- **Integrity**: Verifies `resultSignature` computed with `jobDispatchSecret`:
  1. `JobDispatchSecret = HMAC-SHA256(MasterKey, jobId + ":" + leaseId + ":" + agentId)`
  2. `FindingsHash = SHA-256(CanonicalJSON(findings) + CanonicalJSON(executions))` using RFC 8785 canonical JSON
  3. `ResultSignature = HMAC-SHA256(JobDispatchSecret, jobId + ":" + FindingsHash)`
  4. Timing-safe verification (`crypto.timingSafeEqual`) ensures resilience against side-channel timing attacks.
- **Idempotency**: Submitting duplicate completion reports for an already completed job immediately returns `200 OK` with `{ deduplicated: true }` without database mutation, eliminating metric skew and finding duplication.
- **Transactional Atomicity**: All findings, metrics, test executions, and test run status updates are executed within a single ACID PostgreSQL transaction (`db.transaction()`).
- **Audit Events**:
  - `result.accepted`: Successfully verified and ingested report.
  - `result.rejected_tampered`: Emitted on signature mismatch or payload modification.
  - `result.deduplicated`: Emitted when an already completed job receives a duplicate report.

#### Request Body
```json
{
  "jobId": "7a94f6c1-5717-4562-b3fc-2c963f66afa6",
  "leaseId": "ls_9f8a7b6c5d4e3f2a1b",
  "testRunId": "91d7c041-5717-4562-b3fc-2c963f66afa6",
  "status": "completed",
  "resultSignature": "hmac_sha256_result_attestation_signature",
  "findings": [
    {
      "sourceEngine": "engine-native-cors",
      "title": "CORS Wildcard with Credentials",
      "description": "Access-Control-Allow-Origin contains wildcard * while Access-Control-Allow-Credentials is true",
      "rawSeverity": "high",
      "location": "/api/v1/accounts",
      "evidenceData": {
        "requestHeaders": { "Origin": "http://evil.com" },
        "responseHeaders": { "Access-Control-Allow-Origin": "*" }
      }
    }
  ],
  "metrics": [
    {
      "name": "engine-native-cors_duration_ms",
      "value": 142,
      "unit": "ms",
      "tags": { "engineId": "engine-native-cors", "status": "completed" }
    }
  ],
  "executions": [
    {
      "engineId": "engine-native-cors",
      "status": "completed",
      "durationMs": 142
    }
  ]
}
```

#### Response Body (`200 OK`)
```json
{
  "success": true,
  "data": {
    "status": "ingested",
    "testRunId": "91d7c041-5717-4562-b3fc-2c963f66afa6",
    "findingsIngested": 1,
    "metricsIngested": 1
  }
}
```

---

### 4.6 Endpoint 6: Job Failure Notification
- **Path**: `POST /api/v1/agents/jobs/:jobId/fail`
- **Purpose**: Informs the controller that a catastrophic engine or runner failure occurred.
- **Authentication**: `Bearer agt_sec_...`
- **Authorization**: Caller MUST hold active lease on `:jobId`.
- **Retry Handling**: If retry count `< maxRetries`, controller automatically requeues the job.
- **Audit Event**: `job.failed`

#### Request Body
```json
{
  "jobId": "7a94f6c1-5717-4562-b3fc-2c963f66afa6",
  "leaseId": "ls_9f8a7b6c5d4e3f2a1b",
  "error": "Docker daemon unavailable or unresponsive during ZAP container initialization",
  "retryEligible": true
}
```

#### Response Body (`200 OK`)
```json
{
  "success": true,
  "data": {
    "acknowledged": true,
    "action": "requeued",
    "attemptsRemaining": 2
  }
}
```

---

## 5. Machine-Readable Failure Codes

| Error Code | HTTP Status | Description | Recovery Strategy |
| :--- | :---: | :--- | :--- |
| `ENROLLMENT_KEY_INVALID` | `401` | Pre-shared enrollment key not found or expired | Operator must generate a new TEK |
| `AGENT_UNAUTHORIZED` | `401` | Agent Bearer token is invalid or missing | Agent initiates re-enrollment |
| `AGENT_REVOKED` | `403` | Agent has been explicitly revoked by tenant admin | Agent terminates process |
| `LEASE_EXPIRED` | `409` | The lease expired before completion was submitted | Discard local result; do not overwrite |
| `LEASE_NOT_FOUND` | `404` | Job ID or lease ID is unknown to the controller | Discard execution |
| `TENANT_MISMATCH` | `403` | Agent attempted to interact with a different tenant | Terminate connection; emit security alert |
| `SIGNATURE_INVALID` | `403` | Result HMAC attestation signature verification failed | Reject findings; log tampering alert |
| `PAYLOAD_TOO_LARGE` | `413` | Finding array or evidence size exceeds maximum cap | Agent summarizes or truncates non-critical evidence |
| `PROTOCOL_INCOMPATIBLE` | `426` | Agent protocol version is too old for this controller | Upgrade agent binary |

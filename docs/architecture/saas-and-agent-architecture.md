# SaaS Control Plane & Distributed Agent Architecture

```text
STATUS: ACTIVE
PHASE: Phase 15 — Distributed Agent Architecture & Hybrid Cloud / SaaS Foundation
REVISION: 1.0.0
AUTHORS: Principal Cloud Infrastructure Architect & SaaS Systems Specialist
```

---

## 1. Executive Summary & Problem Statement

Modern enterprise environments host internal microservices, private VPCs, air-gapped staging clusters, and on-premise infrastructure behind strict egress-only firewalls. Traditional centralized scanners fail in these environments because:
1. Public SaaS control planes cannot reach private `10.0.0.0/8`, `172.16.0.0/12`, or `192.168.0.0/16` networks without risky inbound firewall holes or complex site-to-site VPNs.
2. Compliance standards prohibit routing raw target traffic or internal secrets through third-party multi-tenant networks.
3. Heavy container-based scanners require local execution environments with direct Docker socket access and zero external network exposure.

The **Security Lab Distributed Agent Architecture** decouples the platform into:
- **Central SaaS Control Plane (`apps/controller`)**: Manages multi-tenant policies, test run definitions, target scopes, triage state, and analytics.
- **Distributed Execution Agents (`apps/agent`)**: Lightweight daemons deployed directly inside customer VPCs/clusters that make **outbound-only** connections to the control plane, pull dispatched test jobs, execute tests locally via `@security-lab/test-sdk`, and stream back normalized, forensically signed results.

---

## 2. Hybrid-Cloud Topology & Outbound Connection Model

```
+---------------------------------------------------------------------------------------------------+
|                                  CENTRAL SAAS CONTROL PLANE                                       |
|                                                                                                   |
|   +-----------------------+     +--------------------------+     +----------------------------+   |
|   |   Web Dashboard UI    |     |    Fastify API Gateway   |     |    PostgreSQL Database     |   |
|   |    (apps/dashboard)   |---->|     (apps/controller)    |<--->|   Multi-Tenant Partition   |   |
|   +-----------------------+     +--------------------------+     +----------------------------+   |
|                                              ^                                                    |
+----------------------------------------------|----------------------------------------------------+
                                               |
                          Outbound HTTPS Poll / Heartbeat (Port 443)
                          NO INBOUND PORTS INTO CUSTOMER NETWORK
                                               |
+----------------------------------------------|----------------------------------------------------+
| CUSTOMER PRIVATE VPC / KUBERNETES CLUSTER    |                                                    |
|                                              v                                                    |
|   +-------------------------------------------------------------------------------------------+   |
|   |                              DISTRIBUTED AGENT (apps/agent)                               |   |
|   |                                                                                           |   |
|   |  +--------------------+    +-----------------------+    +-----------------------------+   |   |
|   |  |  Polling & Worker  |--->|  Engine Registry &    |--->|  Local Sandboxed Targets    |   |   |
|   |  |     Lifecycle      |    |  SDK Runners          |    |  (Private VPC / Localhost)  |   |   |
|   |  +--------------------+    +-----------------------+    +-----------------------------+   |   |
|   |                                       |                                                   |   |
|   |                          +------------+------------+                                      |   |
|   |                          |                         |                                      |   |
|   |                          v                         v                                      |   |
|   |                 Class A Native Engines    Class B/C Docker Sandbox                        |   |   |
|   |                  (HTTP/TLS/Auth/DSL)        (ZAP / Trivy / k6)                            |   |   |
|   +-------------------------------------------------------------------------------------------+   |
+---------------------------------------------------------------------------------------------------+
```

### Key Architectural Tenets:
1. **Outbound-Only Connectivity**: The agent initiates all communication over standard HTTPS/TLS (Port 443). The customer firewall requires **zero inbound open ports**.
2. **Local Execution Autonomy (Rule 18)**: The agent imports and uses the exact same execution contracts, engines, and normalizers from `@security-lab/test-sdk` as local CLI runs.
3. **Data Residency & Minimization**: Test payloads, raw HTTP probe bodies, and credentials remain inside the customer VPC. Only normalized finding metadata and aggregated performance telemetry are sent back to the control plane.

---

## 3. Multi-Tenant Database Architecture

Multi-tenancy is enforced at the database layer via migration `0006_saas_multi_tenancy.sql`.

### Core Tenant Isolation Entities

1. **`tenants`**:
   - `id UUID PRIMARY KEY DEFAULT gen_random_uuid()`
   - `name VARCHAR(255) NOT NULL`
   - `slug VARCHAR(100) UNIQUE NOT NULL`
   - `plan VARCHAR(50) DEFAULT 'enterprise'`
   - `settings JSONB DEFAULT '{}'`
   - `created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()`
   - `updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()`

2. **`agents`**:
   - `id UUID PRIMARY KEY DEFAULT gen_random_uuid()`
   - `tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE`
   - `name VARCHAR(255) NOT NULL`
   - `token_hash VARCHAR(64) NOT NULL UNIQUE` (SHA-256 of agent enrollment token)
   - `status VARCHAR(50) DEFAULT 'offline'` (`online`, `busy`, `draining`, `offline`)
   - `tags JSONB DEFAULT '[]'` (e.g. `["vpc-prod", "k8s-us-west", "pci-zone"]`)
   - `capabilities JSONB DEFAULT '[]'` (e.g. `["native-http", "auth-audit", "docker-sandbox"]`)
   - `system_info JSONB DEFAULT '{}'` (CPU, RAM, platform details)
   - `last_heartbeat_at TIMESTAMP WITH TIME ZONE`

3. **`agent_jobs`**:
   - `id UUID PRIMARY KEY`
   - `tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE`
   - `test_run_id UUID NOT NULL REFERENCES test_runs(id) ON DELETE CASCADE`
   - `agent_id UUID REFERENCES agents(id) ON DELETE SET NULL`
   - `status VARCHAR(50) DEFAULT 'pending'` (`pending`, `assigned`, `running`, `completed`, `failed`)
   - `payload JSONB NOT NULL` (Target URL, scope, engines, options)
   - `result JSONB` (Findings summary, execution duration, metrics)
   - `error_message TEXT`

4. **Row-Level Tenant Partitioning Across Core Entities**:
   - `projects.tenant_id UUID REFERENCES tenants(id)`
   - `targets.tenant_id UUID REFERENCES tenants(id)`
   - `policies.tenant_id UUID REFERENCES tenants(id)`
   - `findings.tenant_id UUID REFERENCES tenants(id)`

Every query in controller services filters by `tenant_id`, guaranteeing cross-tenant data isolation. The default tenant ID `00000000-0000-0000-0000-000000000000` is retained for local offline developer mode (Rule 19).

---

## 4. Agent Protocol & Lifecycle

### Step 1: Enrollment & Registration
The customer generates an agent enrollment request via the dashboard or CLI:
```http
POST /api/v1/agents/register
Headers:
  x-tenant-id: <TENANT_UUID>
Content-Type: application/json

{
  "name": "internal-vpc-agent-01",
  "tags": ["vpc-internal", "staging"],
  "capabilities": ["native-http", "auth-audit", "docker-sandbox"],
  "systemInfo": {
    "arch": "x64",
    "platform": "linux",
    "cpus": 4,
    "memoryMb": 8192
  }
}
```
**Response**:
```json
{
  "agentId": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "name": "internal-vpc-agent-01",
  "token": "agt_sec_e8b919...<32 random bytes>",
  "tenantId": "00000000-0000-0000-0000-000000000000"
}
```
*Security Invariant*: The raw `token` is shown **only once**. The control plane stores only `SHA-256(token)`.

### Step 2: Health Heartbeat & Metrics Telemetry
The agent sends periodic heartbeats every 10 seconds:
```http
POST /api/v1/agents/heartbeat
Authorization: Bearer agt_sec_...
Content-Type: application/json

{
  "status": "online",
  "metrics": {
    "cpuUsage": 12.4,
    "memoryUsageMb": 184,
    "activeJobs": 0
  }
}
```

### Step 3: Work Queue Polling
The agent polls for dispatched tasks:
```http
POST /api/v1/agents/poll
Authorization: Bearer agt_sec_...
Content-Type: application/json

{
  "maxJobs": 1,
  "capabilities": ["native-http", "auth-audit", "docker-sandbox"],
  "tags": ["vpc-internal", "staging"]
}
```

If a task is available:
```json
{
  "jobs": [
    {
      "jobId": "7a94f6c1-...",
      "testRunId": "91d7c041-...",
      "tenantId": "...",
      "target": {
        "id": "...",
        "name": "Private Billing API",
        "baseUrl": "http://billing.internal.svc:8080",
        "scope": {
          "allowedHosts": ["billing.internal.svc"]
        }
      },
      "engineIds": ["headers", "cors", "auth-jwt"],
      "options": {}
    }
  ]
}
```

### Step 4: Execution & Real-Time Progress Streaming
The agent worker processes the task:
1. Validates target scope against the agent's safe fetch / isolation boundaries.
2. Executes engines sequentially or concurrently using `TestRegistry`.
3. Reports step-level progress back to the control plane:
   ```http
   POST /api/v1/agents/jobs/:jobId/progress
   Authorization: Bearer agt_sec_...
   Content-Type: application/json

   {
     "status": "running",
     "progress": 50,
     "message": "Executing cors engine",
     "currentEngine": "cors"
   }
   ```
4. Control plane relays progress via Server-Sent Events (SSE) to the Web Dashboard.

### Step 5: Completion & Evidence Reporting
Upon test completion, the agent submits the normalized findings and duration:
```http
POST /api/v1/agents/jobs/:jobId/complete
Authorization: Bearer agt_sec_...
Content-Type: application/json

{
  "findings": [
    {
      "ruleId": "CORS-WILDCARD-ORIGIN",
      "severity": "high",
      "category": "cors",
      "title": "CORS wildcard origin with credentials allowed",
      "description": "Access-Control-Allow-Origin header is set to * while credentials are true",
      "remediation": "Restrict allowed origins to trusted domains",
      "evidence": { "header": "Access-Control-Allow-Origin: *" },
      "endpointPath": "/api/v1/accounts"
    }
  ],
  "durationMs": 482,
  "metrics": {
    "totalEngines": 3,
    "successfulEngines": 3
  }
}
```
The control plane:
1. Hardens finding fingerprints with `computeHardenedFindingFingerprint`.
2. Persists findings under the test run's `tenant_id`.
3. Updates test run status to `completed`.
4. Saves execution duration metrics.
5. Generates forensic Markdown/JSON compliance reporting artifacts.

---

## 5. Deployment Guide

### Option A: Kubernetes (Recommended for Clusters)
Deploy the agent using the provided manifest:
```bash
kubectl apply -f infrastructure/k8s/agent.yaml
```

Update the secret with your enrollment token:
```bash
kubectl create secret generic security-lab-agent-credentials \
  --namespace security-lab \
  --from-literal=agent-token="agt_sec_YOUR_ENROLLMENT_TOKEN" \
  --dry-run=client -o yaml | kubectl apply -f -
```

### Option B: Docker Container (Standalone VM / EC2)
```bash
docker run -d \
  --name security-lab-agent \
  --restart unless-stopped \
  -e SECURITY_LAB_CONTROLLER_URL="https://securitylab.mycompany.com" \
  -e SECURITY_LAB_AGENT_TOKEN="agt_sec_YOUR_ENROLLMENT_TOKEN" \
  -e SECURITY_LAB_AGENT_NAME="aws-vpc-us-east-1" \
  -e SECURITY_LAB_AGENT_TAGS="vpc,aws,prod" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  ghcr.io/kavicastelo/security-lab-agent:latest
```

### Option C: CLI Standalone Daemon (Developer Testing)
```bash
# Register agent
security-lab-agent register --name "dev-agent" --controller "http://localhost:3000"

# Start agent
security-lab-agent start \
  --controller "http://localhost:3000" \
  --token "agt_sec_..." \
  --name "dev-agent" \
  --tags "local,dev"
```

---

## 6. Architectural Rules Compliance Matrix

| Rule | Requirement | Implementation Status |
| :--- | :--- | :--- |
| **Rule 18** | Future SaaS must reuse local execution contracts | **Compliant**: `apps/agent` directly imports `@security-lab/test-sdk` engines, registries, and normalizers. Zero custom scanning code or divergent contracts. |
| **Rule 19** | Local offline developer mode must never break | **Compliant**: Default tenant `00000000-0000-0000-0000-000000000000` is automatically provisioned. Controller functions identically without `x-tenant-id` header. Standalone CLI and in-process execution remain 100% operational. |
| **Outbound Only** | No incoming ports to customer environments | **Compliant**: Agent uses outbound HTTPS polling (`POST /poll`) and heartbeats (`POST /heartbeat`). |
| **Credential Security** | Agent tokens hashed before storage | **Compliant**: SHA-256 token hashing in database with `agt_sec_` prefix validation. |

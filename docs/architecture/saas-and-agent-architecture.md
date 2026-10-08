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

### Step 1: Tenant Enrollment Key (TEK) Generation & Agent Registration

#### Step 1a: Tenant Admin Provisions TEK
The organization administrator provisions a cryptographically random, two-tiered Tenant Enrollment Key (TEK) with optional expiration and usage caps:
```http
POST /api/v1/tenants/:tenantId/enrollment-keys
Content-Type: application/json

{
  "name": "Production VPC CI Key",
  "maxUses": 10,
  "expiresInDays": 30
}
```
**Response (`201 Created`)**:
```json
{
  "success": true,
  "data": {
    "id": "e4a1599f-72d8-4f51-b856-bbba09ec2541",
    "tenantId": "c1313d63-6e53-47b3-b308-57c99ee3520f",
    "name": "Production VPC CI Key",
    "key": "tek_default_e4a1599fa28c...<32 random bytes>",
    "keyPrefix": "tek_default_e4a1...",
    "maxUses": 10,
    "usesCount": 0,
    "expiresAt": "2026-11-07T07:30:00.000Z",
    "createdAt": "2026-10-08T02:00:00.000Z"
  }
}
```
*Security Invariant (Rule 17)*: Plaintext `key` is returned **only once** upon creation. Only its SHA-256 hash is persisted in `tenant_enrollment_keys`.

#### Step 1b: Agent Registration / Enrollment
The agent daemon initiates registration using the TEK in the `Authorization` header. Tenant identity is derived strictly from the TEK; client `x-tenant-id` headers are ignored:
```http
POST /api/v1/agents/register
Authorization: Bearer tek_default_e4a1599fa28c...
Content-Type: application/json

{
  "name": "internal-vpc-agent-01",
  "tags": ["vpc-internal", "staging"],
  "capabilities": ["native-http", "auth-audit", "declarative-dsl"],
  "systemInfo": {
    "arch": "x64",
    "platform": "linux",
    "cpus": 4,
    "memoryMb": 8192
  }
}
```
**Response (`201 Created`)**:
```json
{
  "success": true,
  "data": {
    "agentId": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "tenantId": "c1313d63-6e53-47b3-b308-57c99ee3520f",
    "name": "internal-vpc-agent-01",
    "token": "agt_sec_e8b919...<32 random bytes>",
    "tokenExpiresAt": "2027-01-06T02:00:00.000Z",
    "status": "offline",
    "tags": ["vpc-internal", "staging"],
    "capabilities": ["native-http", "auth-audit", "declarative-dsl"],
    "createdAt": "2026-10-08T02:00:00.000Z"
  }
}
```
*Security Invariants*:
1. The plaintext instance `token` is shown **only once**. The database stores only `SHA-256(token)`.
2. The agent token is assigned an explicit expiration (`expires_at`), defaulting to 90 days.
3. If an agent is revoked (`POST /api/v1/agents/:id/revoke`), all subsequent requests immediately return `401 Agent Revoked`.
4. Active agents can seamlessly rotate tokens via `POST /api/v1/agents/rotate-token`.

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

## 5. Deployment Guide & Host Hardening

### The Docker Socket Mounting Anti-Pattern
> [!CAUTION]
> **Never mount `/var/run/docker.sock` into Kubernetes Pods or Execution Containers.**
> Mounting the host Docker daemon socket into a container grants effective root access to the entire host node, completely undermining container sandboxing, namespace isolation, and CIS benchmarks. If a scanner (e.g. ZAP, Trivy) or agent process were exploited, an attacker could spawn a privileged container with the host root filesystem mounted (`-v /:/host`) and achieve immediate cluster node compromise.

Security Lab enforces two approved execution profiles:
1. **Profile 1: In-Cluster Native Scanning (Kubernetes)**: Runs unprivileged within the cluster (`readOnlyRootFilesystem: true`, `allowPrivilegeEscalation: false`, capabilities dropped to `ALL`) to execute Class A native in-process engines (`native-http`, `auth-audit`, `declarative-dsl`).
2. **Profile 2: Dedicated Execution VM / Bare-Metal Agent (External Runner)**: For running Class B/C container scanners (OWASP ZAP, Aqua Trivy, Grafana k6). The agent runs as a dedicated system service (`systemd`) under a restricted system user (`securitylab`) on an isolated VM, eliminating container-in-container nesting and socket exposure.

---

### Step 0: Provision Tenant Enrollment Key (TEK)
Before deploying any agent instance, obtain a TEK from your organization dashboard or via API:
```bash
curl -X POST https://securitylab.mycompany.com/api/v1/tenants/$TENANT_ID/enrollment-keys \
  -H "Content-Type: application/json" \
  -d '{"name": "Cluster-West-Agent-Key", "maxUses": 5, "expiresInDays": 30}'
# Output contains: "key": "tek_default_a1b2c3..."
```

---

### Option A: Kubernetes In-Cluster Agent (Profile 1: Native In-Process Scanning)
Deploy the agent using the hardened manifest with a read-only root filesystem and zero host socket mounts:
```bash
kubectl apply -f infrastructure/k8s/agent.yaml
```

Update the secret with your enrollment key:
```bash
kubectl create secret generic security-lab-agent-credentials \
  --namespace security-lab \
  --from-literal=agent-enrollment-key="tek_default_YOUR_ENROLLMENT_KEY" \
  --dry-run=client -o yaml | kubectl apply -f -
```

---

### Option B: Dedicated VM Execution Worker (Profile 2: Container Scanners via systemd)
For running containerized scanners (ZAP, Trivy, k6) on an isolated Linux VM / EC2 instance:

1. **Create dedicated unprivileged system user**:
   ```bash
   sudo useradd -r -s /usr/sbin/nologin -d /opt/security-lab securitylab
   sudo usermod -aG docker securitylab
   ```

2. **Install and configure agent**:
   ```bash
   sudo mkdir -p /opt/security-lab /etc/security-lab
   sudo chown -R securitylab:securitylab /opt/security-lab

   cat << 'EOF' | sudo tee /etc/security-lab/agent.env
   SECURITY_LAB_CONTROLLER_URL="https://securitylab.mycompany.com"
   SECURITY_LAB_AGENT_ENROLLMENT_KEY="tek_default_YOUR_ENROLLMENT_KEY"
   SECURITY_LAB_AGENT_NAME="dedicated-scanner-worker-01"
   SECURITY_LAB_AGENT_TAGS="vm,dedicated-worker,zap,trivy,k6"
   SECURITY_LAB_AGENT_CAPABILITIES="native-http,auth-audit,declarative-dsl,zap,trivy,k6,docker-sandbox"
   EOF
   sudo chmod 600 /etc/security-lab/agent.env
   sudo chown securitylab:securitylab /etc/security-lab/agent.env
   ```

3. **Deploy systemd service unit (`/etc/systemd/system/security-lab-agent.service`)**:
   ```ini
   [Unit]
   Description=Security Lab Distributed Execution Agent
   After=network.target docker.service
   Requires=docker.service

   [Service]
   Type=simple
   User=securitylab
   Group=securitylab
   WorkingDirectory=/opt/security-lab
   EnvironmentFile=/etc/security-lab/agent.env
   ExecStart=/usr/bin/node /opt/security-lab/dist/index.js
   Restart=always
   RestartSec=5s

   # Sandboxing & Hardening
   ProtectSystem=strict
   ProtectHome=true
   NoNewPrivileges=true
   PrivateTmp=true

   [Install]
   WantedBy=multi-user.target
   ```

4. **Enable and start service**:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now security-lab-agent
   ```

---

### Option C: CLI Standalone Daemon (Developer Testing)
```bash
# Start agent daemon with enrollment key
pnpm --filter @security-lab/agent dev \
  --controller "http://localhost:4000" \
  --enrollment-key "tek_default_..." \
  --name "local-dev-agent" \
  --tags "local,dev"
```

---

## 6. Architectural Rules Compliance Matrix

| Rule | Requirement | Implementation Status |
| :--- | :--- | :--- |
| **Rule 4** | Multi-Tenancy by Design | **Compliant**: Every agent is permanently bound to a verified Tenant ID derived from a validated TEK. |
| **Rule 5** | No Implicit Trust of Client Headers | **Compliant**: Registration ignores client-provided `x-tenant-id`; tenant is strictly resolved from the authenticated TEK record. |
| **Rule 12** | Docker Execution Security Boundary | **Compliant**: All container executions drop all capabilities (`--cap-drop=ALL`), run as non-root (`10001:10001`), enforce read-only root filesystems, and strict PID/resource limits. |
| **Rule 13** | No Unrestricted Docker Socket Exposure | **Compliant**: Removed `/var/run/docker.sock` from Kubernetes manifests and docs. Prohibited Docker socket volume mounts in container runners. Container scanners run on dedicated systemd VMs. |
| **Rule 14** | No Privileged Containers | **Compliant**: `--privileged` is strictly prohibited. Mandatory `--security-opt=no-new-privileges:true` on all container invocations. |
| **Rule 15** | No Arbitrary Host Filesystem Mounts | **Compliant**: Volume mounts are restricted strictly to validated scratch subdirectories under OS temp directory (`os.tmpdir()`). Path traversal, system directories, and socket files are blocked. |
| **Rule 17** | No Plaintext Secrets in Persistence or Logs | **Compliant**: Plaintext TEK and Agent Instance Tokens are hashed with SHA-256 before persistence and masked in logs. |
| **Rule 18** | Future SaaS must reuse local execution contracts | **Compliant**: `apps/agent` directly imports `@security-lab/test-sdk` engines, registries, and normalizers. Zero custom scanning code or divergent contracts. |
| **Rule 19** | Local offline developer mode must never break | **Compliant**: Default tenant `00000000-0000-0000-0000-000000000000` is automatically provisioned. Controller functions identically without `x-tenant-id` header. Standalone CLI and in-process execution remain 100% operational. |
| **Outbound Only** | No incoming ports to customer environments | **Compliant**: Agent uses outbound HTTPS polling (`POST /poll`) and heartbeats (`POST /heartbeat`). |
| **Credential Lifecycle** | Mandatory token expiration, revocation, rotation | **Compliant**: Agent tokens expire after 90 days, support instant administrative revocation (`/revoke`), and zero-downtime rotation (`/rotate-token`). |


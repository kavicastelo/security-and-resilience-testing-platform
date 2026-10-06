# Engine: Authorization & BOLA (Class A Native)

## Responsibility
In-process native engine for automated, contract-driven testing of Broken Object Level Authorization (BOLA/IDOR), Broken Function Level Authorization (BFLA), and missing access controls across multi-tenant and role-based boundaries.

### What belongs here:
* Cross-user identity permutation testing (e.g., User B accessing User A's private resources using User B's credentials).
* Role-based access control (RBAC) and attribute-based access control (ABAC) matrix validation.
* Verification of function-level administrative privilege boundaries (`/admin/*`).
* Unauthenticated / anonymous access rejection audits on protected endpoints.
* Forensic evidence generation capturing both legitimate baseline owner requests and unauthorized exploit requests with reproducible `curl` commands.

### What does NOT belong here:
* Blind brute-force ID guessing or fuzzing (relies on explicit declared synthetic test resource identifiers).
* Destructive data deletion or mutation without explicit scope authorization.
* Network-level firewall or IP whitelist auditing.

### Execution Class:
* **Class A (Native In-Process)**: Orchestrated via native HTTP permutations using `@security-lab/domain` matrix schemas and scope-hardened `safeFetch` dispatcher with zero external container dependencies.

### Implementation Status:
* **Status**: `VERIFIED`
* **Current Behavior**: Fully implemented and registered in `EngineRegistry`. Executes cross-identity test permutations, evaluates owner baseline vs. non-owner attack responses, and emits high-fidelity findings with forensic evidence and reproducible curl commands.
* **Verified Phase**: [Phase 08 — Authorization & BOLA/IDOR Testing Framework](../../prompts/phase-08-authorization-bola-testing-framework.md)

---

## Capabilities

| Capability ID | Category | Disruptive | Description |
| :--- | :--- | :---: | :--- |
| `bola_horizontal_idor` | `protocol_audit` | No | Tests cross-user object access by replaying requests with unauthorized user identities against private resource IDs. |
| `bfla_vertical_escalation` | `protocol_audit` | No | Tests vertical privilege escalation by dispatching unprivileged user identities against administrative routes. |
| `auth_missing_control` | `passive_analysis` | No | Verifies that protected routes reject unauthenticated requests with HTTP 401 or 403. |

---

## Declarative Suite Syntax

Authorization tests are declared using `AuthorizationTestSuiteSchema` or YAML definitions:

```yaml
id: bola-api-matrix-001
name: Multi-User BOLA and BFLA Access Control Matrix
version: 1.0.0
category: authorization

identities:
  - id: user_a
    name: Standard User A
    role: user
    token: Bearer token-user-a-101

  - id: user_b
    name: Standard User B
    role: user
    token: Bearer token-user-b-102

  - id: admin_user
    name: Platform Administrator
    role: admin
    token: Bearer token-admin-999

resources:
  - id: doc-user-a
    ownerIdentityId: user_a
    resourceType: document
    pathParam: documentId
    value: doc-101

rules:
  - id: rule-document-read
    name: Document Object Access Control
    path: /api/documents/{documentId}
    method: GET
    resourceType: document
    action: read
    allowOwner: true
    allowedRoles:
      - admin
    allowGuest: false
    expectedAllowedStatus: [200]
    expectedDeniedStatus: [401, 403, 404]

  - id: rule-admin-users
    name: Admin Users List
    path: /api/admin/users
    method: GET
    allowedRoles:
      - admin
    allowGuest: false
    expectedAllowedStatus: [200]
    expectedDeniedStatus: [401, 403]
```

---

## Findings & Severity Matrix

| Finding Title | Severity | Category | Remediation |
| :--- | :---: | :---: | :--- |
| `Critical Vulnerability: BOLA / IDOR on [METHOD /path]` | `critical` | `authorization` | Enforce object-level access controls: verify caller ownership before returning or mutating data. |
| `Critical Vulnerability: BFLA Vertical Privilege Escalation on [METHOD /path]` | `critical` | `authorization` | Enforce role-based access control middleware verifying administrative privileges before executing function. |
| `Vulnerability: Missing Authentication / Access Control on [METHOD /path]` | `high` | `authorization` | Require authentication on private API endpoints and reject unauthenticated requests with HTTP 401. |

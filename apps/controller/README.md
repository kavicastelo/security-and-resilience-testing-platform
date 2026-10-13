# Controller Service

The Security & Resilience Testing Platform Controller is the central orchestration server managing test runs, target scopes, execution engines, findings lifecycles, release governance policies, and multi-tenant workspaces.

---

## Architecture & Authentication (Phase 01)

The Controller enforces multi-tenant workspace partitioning, user identity models, and role-based access control (RBAC).

### Role Hierarchy
1. **`ADMIN`**:
   - Full workspace management (create workspaces, manage memberships, generate scoped API keys).
   - Administrative destructive operations (delete targets, delete projects).
   - Policy authoring and updating.
2. **`ENGINEER`**:
   - Operational security testing within their workspace.
   - Project and target registration.
   - Test plan creation and scan execution (`POST /api/v1/test-runs`, `POST /api/v1/test-runs/:id/execute`).
   - Read-only inspection of policies, findings, and reports.
3. **`AUDITOR`**:
   - Read-only inspection across their workspace.
   - Access to findings, projects, targets, and release governance reports.
   - Mutation and execution endpoints are strictly blocked with `403 Forbidden`.

### Authentication Schemes
- **Bearer JWT**: Tokens signed via HMAC-SHA256 containing `sub`, `email`, `role`, and `workspaceId`.
  ```http
  Authorization: Bearer <jwt_token>
  ```
- **Scoped API Keys**: Generated per workspace with SHA-256 storage (`sec_key_<hex>`). Passed via header:
  ```http
  Authorization: Bearer sec_key_...
  # or
  X-Api-Key: sec_key_...
  ```
- **Workspace Header Isolation**: Requests are bound to the user's workspace. Cross-workspace access attempts without matching credentials return `403 Forbidden` or `404 Not Found`.

---

## Workspace REST API (`/api/v1/workspaces`)

All endpoints below require authentication.

### 1. Create Workspace
- **Route**: `POST /api/v1/workspaces`
- **Permissions**: `ADMIN`
- **Payload**:
  ```json
  {
    "name": "Alpha Security Operations",
    "slug": "alpha-sec-ops",
    "description": "Primary testing workspace"
  }
  ```
- **Response**: `201 Created` with created workspace object.

### 2. List Workspaces
- **Route**: `GET /api/v1/workspaces`
- **Permissions**: `ADMIN`, `ENGINEER`, `AUDITOR`
- **Behavior**: Returns workspaces where the authenticated actor has an active membership.

### 3. Get Workspace by ID
- **Route**: `GET /api/v1/workspaces/:id`
- **Permissions**: `ADMIN`, `ENGINEER`, `AUDITOR` (Must belong to workspace)
- **Response**: `200 OK` or `404 Not Found`.

### 4. Update Workspace
- **Route**: `PATCH /api/v1/workspaces/:id` (also supports `PUT`)
- **Permissions**: `ADMIN`
- **Payload**:
  ```json
  {
    "name": "Updated Name",
    "description": "Updated Description"
  }
  ```
- **Response**: `200 OK` with updated workspace.

### 5. Delete Workspace
- **Route**: `DELETE /api/v1/workspaces/:id`
- **Permissions**: `ADMIN`
- **Response**: `200 OK` with `{ "id": "...", "deleted": true }`.

### 6. Workspace Memberships
- **List Members**: `GET /api/v1/workspaces/:id/members` (`ADMIN`, `ENGINEER`, `AUDITOR`)
- **Add Member**: `POST /api/v1/workspaces/:id/members` (`ADMIN`)
  ```json
  {
    "userId": "uuid-of-user",
    "role": "ENGINEER"
  }
  ```
- **Remove Member**: `DELETE /api/v1/workspaces/:id/members/:userId` (`ADMIN`)

### 7. Scoped API Key Management
- **List Keys**: `GET /api/v1/workspaces/:id/api-keys` (`ADMIN`)
- **Generate Key**: `POST /api/v1/workspaces/:id/api-keys` (`ADMIN`)
  ```json
  {
    "name": "CI/CD Deployment Key",
    "role": "ENGINEER",
    "expiresInDays": 30
  }
  ```
  Returns `201 Created` with plaintext `secretKey` (only displayed once upon creation) and metadata.
- **Revoke Key**: `DELETE /api/v1/workspaces/:id/api-keys/:keyId` (`ADMIN`)

---

## Authentication Endpoints (`/api/v1/auth`)

### 1. User Registration
- **Route**: `POST /api/v1/auth/register`
- **Payload**:
  ```json
  {
    "email": "analyst@security-lab.local",
    "name": "Security Analyst",
    "password": "SecurePassword123!",
    "workspaceName": "Analyst Testing Lab"
  }
  ```
- **Response**: `201 Created` with `user`, `workspace`, and `token`.

### 2. User Login
- **Route**: `POST /api/v1/auth/login`
- **Payload**:
  ```json
  {
    "email": "analyst@security-lab.local",
    "password": "SecurePassword123!"
  }
  ```
- **Response**: `200 OK` with user details, workspace context, and JWT bearer `token`.

### 3. Current User Context
- **Route**: `GET /api/v1/auth/me`
- **Headers**: `Authorization: Bearer <token>`
- **Response**: `200 OK` with authenticated user profile and active workspace ID.

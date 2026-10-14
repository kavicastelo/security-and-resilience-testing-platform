# Enterprise Single Sign-On (SSO) & SCIM 2.0 Integration Guide

## 1. Overview
The Security & Resilience Testing Platform supports commercial enterprise identity federation through:
1. **SAML 2.0**: Standard enterprise federation compatible with Okta, Azure Active Directory / Entra ID, PingFederate, and Google Workspace.
2. **OpenID Connect (OIDC)**: Modern OAuth 2.0 + OIDC identity federation for cloud identity providers.
3. **Just-In-Time (JIT) Provisioning**: Automatic account creation and role claim mapping upon successful login.
4. **SCIM 2.0**: Directory synchronization for automated onboarding, role updating, and employee offboarding.

---

## 2. SAML 2.0 Configuration

### 2.1 Service Provider (SP) Metadata
For each workspace, the platform exposes a standard SAML 2.0 SP EntityDescriptor:

```http
GET /api/v1/auth/sso/saml/:workspaceId/metadata
```

- **Entity ID**: `https://<controller-host>/api/v1/auth/sso/saml/:workspaceId/metadata`
- **Assertion Consumer Service (ACS) URL**: `https://<controller-host>/api/v1/auth/sso/saml/:workspaceId/acs`
- **Binding**: `urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST`
- **NameID Format**: `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress`

### 2.2 Configuring SAML via Controller API
Admins can enable SAML SSO per workspace:

```http
PUT /api/v1/workspaces/:id/sso
Authorization: Bearer <ADMIN_JWT_OR_KEY>
Content-Type: application/json

{
  "enabled": true,
  "provider": "saml",
  "domain": "acme.corp",
  "saml": {
    "entryPoint": "https://idp.okta.com/app/acme/sso/saml",
    "issuer": "https://idp.okta.com/idp-issuer-id",
    "cert": "-----BEGIN CERTIFICATE-----\nMIIDpDCCAoygAwIBAgIGAX...\n-----END CERTIFICATE-----"
  },
  "roleMapping": {
    "Security-Admins": "ADMIN",
    "Application-SecOps": "ENGINEER",
    "Compliance-Auditors": "AUDITOR"
  },
  "defaultRole": "ENGINEER"
}
```

### 2.3 SAML Security & Anti-Replay Guarantees
- **Clock Drift & Anti-Replay**: The ACS validator enforces assertion conditions (`NotBefore` and `NotOnOrAfter` with a 5-minute tolerance window). Replayed or expired assertions are rejected with `401 Unauthorized`.
- **Digital Signatures**: Assertion signatures are verified against the configured public X.509 certificate using `RSA-SHA256`.

---

## 3. OpenID Connect (OIDC) Configuration

### 3.1 Configuring OIDC via Controller API
```http
PUT /api/v1/workspaces/:id/sso
Authorization: Bearer <ADMIN_JWT_OR_KEY>
Content-Type: application/json

{
  "enabled": true,
  "provider": "oidc",
  "domain": "acme.corp",
  "oidc": {
    "issuer": "https://login.microsoftonline.com/<tenant-id>/v2.0",
    "clientId": "<client-id>",
    "clientSecret": "<client-secret>",
    "authorizationUrl": "https://login.microsoftonline.com/<tenant-id>/oauth2/v2.0/authorize",
    "tokenUrl": "https://login.microsoftonline.com/<tenant-id>/oauth2/v2.0/token"
  },
  "roleMapping": {
    "SecOpsAdmins": "ADMIN",
    "Engineering": "ENGINEER",
    "SecurityAuditors": "AUDITOR"
  },
  "defaultRole": "ENGINEER"
}
```

### 3.2 OIDC Login Flow
1. Client requests authorization URL: `GET /api/v1/auth/sso/oidc/:workspaceId/login`
2. User authenticates with IdP and is redirected back with authorization code or ID token.
3. Client posts credentials to `POST /api/v1/auth/sso/oidc/:workspaceId/callback`.
4. Platform validates ID token claims (`iss`, `aud`, `exp`, `email`, `groups`), JIT provisions the user, and returns a signed platform session JWT.

---

## 4. SCIM 2.0 Directory Synchronization

The platform supports RFC 7643 / RFC 7644 SCIM 2.0 endpoints for automated lifecycle management from Okta, Azure AD, or OneLogin.

### 4.1 Endpoints
- `GET /scim/v2/ServiceProviderConfig`: Discovers supported features (PATCH supported, Bearer token authentication).
- `GET /scim/v2/Schemas`: Schema definitions for `User` and `Group`.
- `GET /scim/v2/Users`: Query and filter users with pagination (`filter=userName eq "user@example.com"`).
- `POST /scim/v2/Users`: Provision new user account and attach to workspace.
- `GET /scim/v2/Users/:id`: Inspect provisioned user.
- `PUT /scim/v2/Users/:id` & `PATCH /scim/v2/Users/:id`: Update user profile, role, or active status (`active: false` deprovisions user access).
- `DELETE /scim/v2/Users/:id`: Remove user from workspace.
- `GET /scim/v2/Groups`: Enumerate workspace RBAC groups (`ADMIN`, `ENGINEER`, `AUDITOR`) with current members.

### 4.2 Authentication
SCIM requests authenticate using standard Bearer authentication:
```http
Authorization: Bearer <WORKSPACE_API_KEY>
X-Workspace-Id: <WORKSPACE_UUID>
Content-Type: application/scim+json
```

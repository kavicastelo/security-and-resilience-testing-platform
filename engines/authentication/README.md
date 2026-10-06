# Engine: Authentication (Class A Native)

## Responsibility
In-process native engine for automated, non-invasive security auditing of authentication mechanisms, JSON Web Tokens (JWTs), cookie security attributes, session lifecycle, and login route throttling.

### What belongs here:
* Token verification auditing: algorithm `none` signature bypass, expired token enforcement, signature-stripped token acceptance, and weak HMAC secret probing.
* Session cookie attributes audit (`HttpOnly`, `Secure`, `SameSite=Lax/Strict`, and RFC 6265bis prefixes `__Host-`, `__Secure-`).
* Session fixation detection across authentication state transitions.
* Login route brute-force and credential stuffing defense auditing (detecting HTTP 429 rate limiting, CAPTCHA challenges, or account lockout).

### What does NOT belong here:
* Distributed credential stuffing or high-volume password cracking attacks (Hashcat, John the Ripper).
* Exploitation scripts targeting third-party OAuth/OIDC identity providers.
* Multi-user horizontal authorization matrix testing (handled in Phase 08 BOLA/BFLA testing).

### Execution Class:
* **Class A (Native In-Process)**: Fast non-invasive probes utilizing Node.js native `node:crypto` and scope-hardened `safeFetch` dispatcher with zero external container dependencies.

### Implementation Status:
* **Status**: `VERIFIED`
* **Current Behavior**: Fully implemented and registered in `EngineRegistry`. Supports token tampering mutations, comprehensive cookie attribute audits, session fixation verification, and login rate limiting evaluation.
* **Verified Phase**: [Phase 07 — Authentication Testing Framework](../../prompts/phase-07-authentication-testing-framework.md)

---

## Capabilities

| Capability ID | Category | Disruptive | Description |
| :--- | :--- | :---: | :--- |
| `auth_jwt_audit` | `protocol_audit` | No | Audits JWT verification rigor, testing for alg: none signature bypass, expiration enforcement, stripped signatures, and weak HMAC secrets. |
| `auth_cookie_flags` | `passive_analysis` | No | Audits `Set-Cookie` headers for `HttpOnly`, `Secure`, `SameSite`, and RFC 6265bis prefix requirements (`__Host-`, `__Secure-`). |
| `auth_session_fixation` | `protocol_audit` | No | Verifies whether session identifiers are properly regenerated upon successful user authentication. |
| `auth_login_brute_force` | `active_fuzzing` | No | Evaluates login route resilience against rapid repeated failed attempts for rate limiting (HTTP 429) or lockout controls. |

---

## Configuration & Usage

```typescript
import { AuthenticationSecurityEngine, createDefaultEngineRegistry } from '@security-lab/test-sdk';

const engine = new AuthenticationSecurityEngine();

const result = await engine.execute(
  {
    targetUrl: 'https://api.example.com',
    options: {
      protectedPath: '/api/v1/profile',
      loginPath: '/auth/login',
      sampleToken: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
      credentials: {
        username: 'auditor',
        password: 'sample-password',
      },
      checkJwt: true,
      checkCookies: true,
      checkSessionFixation: true,
      checkBruteForce: true,
      bruteForceAttempts: 10,
    },
  },
  context,
);
```

---

## Findings & Severity Matrix

| Finding Title | Severity | Category | Remediation |
| :--- | :---: | :---: | :--- |
| `Critical Vulnerability: Target Accepts Algorithm 'none' JWT Signature Bypass` | `critical` | `authentication` | Configure JWT verification library to whitelist allowed algorithms and strictly reject `none`. |
| `Critical Vulnerability: Unsigned / Signature-Stripped JWT Accepted` | `critical` | `authentication` | Enforce signature segment verification on all incoming tokens. |
| `Critical Vulnerability: JWT Signed with Weak / Predictable Secret Accepted` | `critical` | `authentication` | Use high-entropy random secrets (>= 256 bits) stored in secret managers. |
| `Vulnerability: Expired JWT Accepted by Protected Route` | `high` | `authentication` | Ensure token verification enforces `exp` timestamps without excessive clock skew. |
| `Session Fixation: Session Identifier Not Regenerated Post-Authentication` | `high` | `authentication` | Invalidate pre-authentication session and issue newly generated session identifier upon login. |
| `Missing HttpOnly Flag on Sensitive Cookie` | `high` | `cookies` | Set `HttpOnly` flag on all session and authentication cookies. |
| `Missing Secure Flag on Cookie` | `high` / `medium` | `cookies` | Set `Secure` flag to ensure cookie is only transmitted over HTTPS. |
| `Missing SameSite Attribute on Cookie` | `medium` / `low` | `cookies` | Explicitly set `SameSite=Lax` or `SameSite=Strict`. |
| `Missing Rate Limiting / Brute-Force Protection on Login Route` | `medium` | `authentication` | Implement IP/account rate limiting (HTTP 429) or progressive delays. |

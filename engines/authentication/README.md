# Engine: Authentication (Class A Native)

## Responsibility
In-process native engine for verifying authentication mechanisms, JWT handling, session flags, and credential policies.

### What belongs here:
* TestEngine implementation for token validation (e.g. signature validation, expiration enforcement, alg: none detection).
* Session cookie attributes audit (Secure, HttpOnly, SameSite).
* Basic authentication and API key handling verification.

### What does NOT belong here:
* Distributed credential stuffing attacks.
* Exploitation scripts targeting external OAuth providers.

### Execution Class:
* **Class A (Native In-Process)**: Fast non-invasive assertions on token payloads and session responses.

### Implementation Status:
* **Status**: SCAFFOLDED (Interface boundary defined in `@security-lab/test-sdk`)
* **Planned Phase**: Phase 2 (Native Test Engines & Scanners)

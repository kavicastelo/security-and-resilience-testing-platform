# Platform Self-Security Tests

## Responsibility
Verifies that the Security Lab platform itself adheres to strict defensive security practices.

### What belongs here:
* Security regression tests verifying:
  - Controller endpoints do not leak internal stack traces in production mode.
  - CORS policies are strictly enforced.
  - Target URL scopes cannot be bypassed via DNS rebinding or path traversal.
  - Dependency audit validation (`pnpm audit`).

### Implementation Status:
* **Status**: PLANNED
* **Planned Phase**: Phase 5 (Security Hardening & Self-Audit)

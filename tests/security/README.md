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
* **Status**: IMPLEMENTED
* **Test Suite**: `platform-security.test.ts` (14 passing tests)
* **Coverage**: SSRF protection, RFC1918 private IP defense, cloud metadata shielding, protocol whitelisting, controller error sanitization without stack traces, evidence SHA-256 tamper-proofing, fail-safe policy gating.

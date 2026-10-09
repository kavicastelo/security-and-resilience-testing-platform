# Engine: Security Headers (Class A Native)

## Responsibility
In-process native engine for validating mandatory security headers against best-practice standards (OWASP Secure Headers Project).

### What belongs here:
* TestEngine validating presence and syntax of:
  - `Content-Security-Policy` (CSP)
  - `Strict-Transport-Security` (HSTS)
  - `X-Content-Type-Options`
  - `X-Frame-Options`
  - `Referrer-Policy`
  - `Permissions-Policy`

### What does NOT belong here:
* Invasive browser execution or DOM exploitation.

### Execution Class:
* **Class A (Native In-Process)**: Extremely fast, lightweight passive response inspection.

### Implementation Status:
* **Status**: `VERIFIED`
* **Current Behavior**: Fully implemented in `@security-lab/test-sdk` as `HeadersSecurityEngine`. Enforces scope validation, redirect interception, and validates all OWASP security header best practices.


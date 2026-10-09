# Profile: API Security Audit (`api-security`)

## Overview
Comprehensive REST / GraphQL API security audit targeting authentication, object-level authorization, and schema validation.

### Engines & Test Categories
* `authentication`: JWT validation, expired/tampered tokens, alg:none bypass checks.
* `authorization`: BOLA (Broken Object Level Authorization) / IDOR role permutation checks.
* `headers`: API cache-control, content-type sniffing protection.
* `http-security`: Rate limit baseline enforcement, error stack trace leaks.

### Safety Constraints
* Requires registered staging/QA target with test credentials.
* Rate limit safe: Max RPS capped at target scope definition.
* Max duration: 5m.

### Status:
* **Status**: `VERIFIED`
* **Current Behavior**: Fully active profile supported in the controller and CLI. Dispatches `authentication`, `authorization` (BOLA/IDOR), and `headers` audits against authenticated target endpoints.


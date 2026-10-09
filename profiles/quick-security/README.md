# Profile: Quick Security Audit (`quick-security`)

## Overview
A lightweight, non-intrusive security posture audit designed for PR checks and fast local developer feedback loops (execution time: < 30 seconds).

### Engines & Test Categories
* `headers`: Complete OWASP Secure Headers compliance.
* `tls`: Protocol version (TLS 1.2+), cipher suites, certificate validation.
* `cors`: Permissive `*` origins and credentials combinations check.
* `http-security`: Disallowed HTTP methods (TRACE, TRACK), server disclosure.

### Safety Constraints
* Non-disruptive, read-only passive inspection.
* Zero data mutation or heavy network traffic.
* Max concurrency: 5, Max duration: 1m.

### Status:
* **Status**: `VERIFIED`
* **Current Behavior**: Fully active profile supported in the controller and CLI. Dispatches `headers`, `tls`, and `cors` native engines with passive inspection.


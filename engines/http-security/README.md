# Engine: HTTP Security (Class A Native)

## Responsibility
In-process native engine for inspecting HTTP security configurations, verbs, methods, error disclosures, and CORS configurations.

### What belongs here:
* TestEngine implementation for HTTP protocol baseline verification.
* Method tampering and disallowed HTTP verb checks (e.g. TRACE, TRACK).
* Information disclosure checks in response headers or default error pages.

### What does NOT belong here:
* Uncontrolled web crawling or invasive vulnerability exploitation.
* Heavy load generation or stress testing.

### Execution Class:
* **Class A (Native In-Process)**: Fast execution directly orchestrated within the test runner process.

### Implementation Status:
* **Status**: `VERIFIED`
* **Current Behavior**: Fully implemented across `@security-lab/test-sdk` engines (`CorsSecurityEngine`, `HeadersSecurityEngine`, and `RateLimitResilienceEngine`). Audits CORS misconfigurations, disallowed HTTP methods, security headers, and rate limits with strict SSRF scope enforcement.


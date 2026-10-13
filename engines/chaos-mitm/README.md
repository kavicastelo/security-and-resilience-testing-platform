# @security-lab/chaos-mitm

## Overview
The `engine-chaos-mitm` is a Class A Native execution engine conforming to `@security-lab/engine-sdk`. It provides ephemeral in-process HTTP/HTTPS fault injection proxy capabilities to test modern application resilience, retry loops, circuit breaking, and graceful degradation without external proxy binaries (e.g. Toxiproxy, Chaos Mesh, or Envoy).

---

## Fault Injection Capabilities
1. **Latency & Jitter Injection (`LATENCY`)**:
   - Injects artificial millisecond delays with Gaussian/uniform jitter (`delayMs +/- jitterMs`) on matching HTTP routes to test client timeout thresholds and downstream queuing.
2. **Upstream Gateway Error Injection (`STATUS_CODE`)**:
   - Synthesizes HTTP 500, 502, 503, or 504 errors on a specified percentage of requests (e.g. 30% transient failures) to evaluate client retry loops and fallback policies.
3. **TCP Connection Drop (`DROP`)**:
   - Forcibly closes or resets the TCP socket immediately upon request arrival to simulate network cuts and dead upstream nodes.
4. **Mid-Stream Payload Truncation (`TRUNCATE`)**:
   - Streams partial response payloads (e.g. 64 bytes) and abruptly severs the connection to test client JSON stream parser resilience against malformed/truncated transfers.

---

## Safety Invariants & Security Boundaries
- **Strict Target Scope Verification (Rule 2 / Safety Req 13)**: The proxy verifies target hostnames against the registered `TargetScope`. The proxy cannot be exploited as an open forward proxy to external internet targets.
- **Scope Authorization Guard**: Prohibits execution if `scope.testing.chaosTesting` is explicitly disabled in the target security scope.
- **Port Lifecycle Cleanup**: Ephemeral proxy servers are dynamically allocated on port `0` and guaranteed to terminate in `finally` blocks, preventing port or socket leaks.
- **Sensitive Header Redaction (Rule 4)**: Masks sensitive headers (`Authorization`, `Cookie`, `X-Api-Key`) in finding evidence payloads.
- **Worker Sandboxing**: Fully isolated in V8 worker threads via `executeSandboxedEngine`.

---

## Usage Example

```typescript
import { chaosMitmEngine } from '@security-lab/chaos-mitm';

const result = await chaosMitmEngine.execute(
  {
    targetUrl: 'http://127.0.0.1:3000',
    options: {
      faultRules: [
        {
          id: 'checkout-503-transient',
          name: 'Transient 503 on Checkout',
          match: { path: '/api/checkout', method: 'POST' },
          action: 'STATUS_CODE',
          statusCode: 503,
          percentage: 40,
        },
      ],
      scenarioSteps: [
        {
          name: 'Client Checkout with Retry',
          method: 'POST',
          path: '/api/checkout',
          maxRetries: 3,
          retryBackoffMs: 100,
          expectedFinalStatus: 200,
        },
      ],
    },
  },
  context,
);
```

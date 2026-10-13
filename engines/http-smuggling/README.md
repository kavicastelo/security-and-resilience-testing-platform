# HTTP Request Smuggling & Reverse Proxy Routing Verifier (`@security-lab/http-smuggling`)

## 1. Overview
The **HTTP Request Smuggling Verifier Engine** provides raw TCP and TLS socket transmission capabilities to test for request desynchronization vulnerabilities (CL.TE, TE.CL, TE.TE permutations), reverse proxy Host header poisoning, and hop-by-hop header stripping across load balancers, CDNs, and backend application servers.

Standard HTTP client libraries (such as `fetch`, `axios`, or standard `http.request`) normalize headers, strip invalid or duplicate `Content-Length` and `Transfer-Encoding` values, and automatically reformat CRLF delimiters. This engine bypasses standard HTTP client normalization by directly opening `net.Socket` and `tls.TLSSocket` streams and transmitting precisely crafted byte payloads.

---

## 2. Capabilities

| Capability ID | Name | Description |
|---|---|---|
| `http_smuggling_cl_te` | CL.TE Smuggling Detection | Tests whether frontend prioritizes `Content-Length` and backend prioritizes `Transfer-Encoding`. |
| `http_smuggling_te_cl` | TE.CL Smuggling Detection | Tests whether frontend prioritizes `Transfer-Encoding` and backend prioritizes `Content-Length`. |
| `http_smuggling_te_te` | TE.TE Obfuscation Fuzzing | Sends malformed/obfuscated `Transfer-Encoding` headers (spacing, tabs, dual headers) to induce differential parsing. |
| `reverse_proxy_host_poisoning` | Reverse Proxy Host Poisoning | Injects `X-Forwarded-Host`, `X-Host`, and `Host` variations to detect reflection in redirects or `<base href>`. |
| `hop_by_hop_header_manipulation` | Hop-by-Hop Header Stripping | Tests whether custom security tokens listed in `Connection:` are stripped by intermediate proxies. |

---

## 3. Safety & Non-Destructive Invariants

1. **Canary Prefixing**:
   - Rather than poisoning victim sessions or executing destructive mutations, the engine appends safe canary markers (`canary-<uuid>`) pointing to non-destructive paths (such as `/robots.txt` or `/healthz`).
   - If desynchronization occurs, subsequent requests reflect the canary marker without affecting live traffic.

2. **Differential Timing**:
   - Evaluates whether malformed chunked requests cause backend chunk starvation delays compared to baseline requests.

3. **Target Scope Enforcement (Rule 2)**:
   - Evaluates targets against `TargetScopeSchema`. Desynchronization requests are strictly rejected if the target is outside authorized boundaries.

4. **Zero Plaintext Secrets (Rule 4) & Cryptographic Non-Repudiation (Rule 5)**:
   - Sensitive headers (`Authorization`, `Cookie`, `X-Api-Key`) are redacted.
   - Evidence records include raw byte hex dumps and immutable SHA256 hashes.

---

## 4. Usage Example

```typescript
import { HttpSmugglingEngine } from '@security-lab/http-smuggling';

const engine = new HttpSmugglingEngine();

const result = await engine.execute(
  {
    targetUrl: 'http://127.0.0.1:8080',
    options: {
      canaryPath: '/robots.txt',
      normalPath: '/',
      timeoutMs: 5000,
      timingDelayThresholdMs: 1500,
    },
  },
  {
    executionId: 'exec-123',
    testRunId: 'run-456',
    target: {
      id: 'target-789',
      baseUrl: 'http://127.0.0.1:8080',
      scope: {
        allowedHosts: ['127.0.0.1', 'localhost'],
        allowPrivateRanges: true,
      },
    },
  }
);

console.log(result.findings);
```

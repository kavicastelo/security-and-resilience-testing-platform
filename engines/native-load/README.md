# @security-lab/native-load

## Overview
The `engine-native-load` is a Class A Native execution engine conforming to `@security-lab/engine-sdk`. It provides in-memory, high-throughput HTTP load generation, empirical HDR latency percentile benchmarking, and service level objective (SLO) policy evaluation without requiring Docker, Grafana k6 containers, or external binaries.

---

## Capabilities
1. **In-Memory High-Throughput HTTP Load Generation**:
   - Generates up to 5,000+ requests per second on developer machines using native Node.js HTTP/1.1 socket connection pooling and keep-alive pipelines.
   - Operates in zero-dependency `--local` CLI mode without Docker.
2. **Empirical HDR Latency Percentile Distribution**:
   - Computes statistical percentiles: **P50**, **P90**, **P95**, **P99**, and **P99.9** (sub-millisecond precision).
   - Records minimum, maximum, mean average, standard deviation, and throughput (RPS).
3. **Configurable Load Profiles**:
   - `constant`: Steady concurrency and target throughput across duration.
   - `ramping`: Staged or linear ramping of virtual user connections over time.
   - `spike`: Instantaneous burst to detect resource starvation and queue backup.
4. **SLO Policy Enforcement & CI Gates**:
   - Validates live latency metrics against configured thresholds (e.g. `maxP99Ms`, `maxP95Ms`, `minRps`, `maxErrorRate`).
   - Automatically generates a `HIGH` severity finding (`PERFORMANCE_SLO_BREACH`) when latency or error SLAs are breached, failing release gates via `@security-lab/policy-engine`.

---

## Architectural & Safety Invariants
- **Localhost Safety Ceiling (Rule 13)**: Hard-caps throughput on `localhost` / `127.0.0.1` to a maximum of 5,000 RPS to prevent CPU starvation and machine lockups.
- **Target Scope Compliance (Rule 2)**: Strictly honors `scope.testing.loadTesting` and clamps concurrency to `scope.limits.maxConcurrency`.
- **Target Circuit Breaker**: Automatically halts load generation if target endpoints produce continuous 500 Internal Server Errors (25 consecutive 5xx errors).
- **Sensitive Header Redaction (Rule 4)**: Masks sensitive headers (`Authorization`, `Cookie`, `X-Api-Key`) in finding evidence payloads.
- **Worker Sandboxed**: Fully isolated in V8 worker threads via `executeSandboxedEngine`.

---

## Usage Example

```typescript
import { nativeLoadEngine } from '@security-lab/native-load';

const result = await nativeLoadEngine.execute(
  {
    targetUrl: 'http://127.0.0.1:3000',
    options: {
      type: 'constant',
      durationSec: 5,
      connections: 20,
      thresholds: {
        maxP95Ms: 50,
        maxP99Ms: 100,
        maxErrorRate: 0.01,
      },
    },
  },
  context,
);

console.log(`Throughput: ${result.metrics.find(m => m.name === 'http_rps')?.value} RPS`);
console.log(`P99 Latency: ${result.metrics.find(m => m.name === 'http_req_duration_p99')?.value} ms`);
```

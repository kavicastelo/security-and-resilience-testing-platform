# Test Runner (`@security-lab/test-runner`)

The Test Runner package provides secure HTTP execution primitives with adaptive circuit breaking, target distress backoff, and redirect boundary enforcement for the Security & Resilience Testing Platform.

---

## 1. Adaptive Target Circuit Breaker

Automated security scanners, fuzzers, and resilience suites generate intense synthetic traffic. If a target begins failing under test, continuing to bombard it can cause complete operational outages or data corruption.

### Circuit Breaker Invariants
- **Sliding Window**: Evaluates the trailing 10 HTTP requests.
- **Threshold**: Trips to `OPEN` state if >= 25% of responses are 5xx server errors (`500`-`599`).
- **Cooldown Backoff**: Pauses further requests to the target for 30 seconds (configurable).
- **Probing (Half-Open)**: After cooldown, transitions to `HALF_OPEN` and sends probe requests to verify target health before resuming full traffic.
- **Observability**: Tripping the circuit breaker emits a structured `WARN` event (`circuit_breaker.tripped`) and creates a distress finding for triage.

---

## 2. Usage

```typescript
import { executeHttpRequest } from '@security-lab/test-runner';
import { TargetScope } from '@security-lab/domain';

const scope: TargetScope = {
  allowedHosts: ['api.example.com'],
  allowedPorts: [80, 443],
  excludedPaths: [],
  testing: { activeScanning: true, loadTesting: false, chaosTesting: false },
  limits: { maxRps: 100, maxConcurrency: 10, maxDuration: '10m' },
};

try {
  const response = await executeHttpRequest('https://api.example.com/v1/users', {
    method: 'GET',
    scope,
    targetId: 'target-uuid-here',
  });
  console.log('Response status:', response.status);
} catch (err) {
  if (err.name === 'TargetCircuitBreakerOpenError') {
    console.warn('Execution paused due to target distress:', err.message);
  }
}
```

# Profile: Performance & Resilience Baseline (`performance`)

## Overview
Stress and resilience evaluation to measure API latency distributions, degradation thresholds, and throughput under controlled load.

### Engines & Test Categories
* `k6`: Step load ramps, p95/p99 latency analysis, error-rate tracking under concurrency.
* `resilience`: Recovery time after brief concurrency spikes, connection pool saturation.

### Safety Constraints
* Strictly requires `testing.loadTesting: true` in target scope.
* Automatic abort if error rate exceeds 5% or response latency exceeds 5000ms.
* Max concurrency: 50 VUs, Max duration: 10m.

### Status:
* **Status**: PLANNED
* **Planned Phase**: Phase 4

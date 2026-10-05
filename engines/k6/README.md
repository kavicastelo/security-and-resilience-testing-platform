# Engine: k6 Resilience & Performance Runner (Class C Heavy Worker)

## Responsibility
Heavy worker runner executing Grafana k6 performance scenarios to evaluate application resilience under stress, load, and simulated concurrency spikes.

### What belongs here:
* TestEngine adapter generating k6 test execution scripts from platform-native test definitions.
* Spawning isolated k6 container or process runners with controlled virtual user (VU) limits and duration caps.
* Telemetry ingestion streaming k6 metrics (p95 latency, error rates, http_reqs, http_req_duration) into platform-native `Metric` records.

### What does NOT belong here:
* Distributed denial-of-service (DDoS) without rate/concurrency clamps.
* Running heavy load tests directly on controller event loop threads.

### Execution Class:
* **Class C (Heavy Worker)**: Isolated worker process/container with dedicated CPU/memory limits and explicit target scope thresholds.

### Implementation Status:
* **Status**: PLANNED (Engine boundary established)
* **Planned Phase**: Phase 4 (Resilience & Performance Testing)

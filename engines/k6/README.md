# Engine: k6 Resilience & Performance Runner (Class C Heavy Worker)

## Responsibility
Heavy worker runner executing Grafana k6 performance scenarios to evaluate application resilience under stress, load, and simulated concurrency spikes.

### What belongs here:
* TestEngine adapter (`K6ResilienceEngine`) generating k6 ES module execution scripts via `buildK6Script()`.
* Ephemeral scratch volume transport (`/scripts`) for test scripts (`script.js`) and summary report export (`summary.json`).
* Spawning isolated `grafana/k6:latest` container runners with controlled virtual user (VU) limits clamped to `target.scope.limits.maxConcurrency` and duration caps.
* Enforcing mandatory CIS benchmark resource limits: `--memory="512m"` (Rule 8) and `--cpus="1.0"`.
* Telemetry ingestion parsing native k6 summary export JSON (`parseK6Summary()`) into canonical platform `Metric` records:
  - `http_req_duration_p95`, `http_req_duration_p99`, `http_req_duration_med`, `http_req_duration_avg`, `http_req_duration_max`
  - `http_reqs_total`, `http_rps`, `http_req_failed_ratio`
* Quantitative Latency SLA evaluation generating `Finding` records when p95 thresholds are breached.

### What does NOT belong here:
* Distributed denial-of-service (DDoS) without rate/concurrency clamps.
* Running in-process JavaScript `fetch()` loops on the controller event loop thread.
* Silent mock fallbacks on container failures in production paths.

### Execution Class:
* **Class C (Heavy Worker)**: Isolated worker container execution with dedicated CPU/memory limits and explicit target scope thresholds (`loadTesting: true`).

### Implementation Status:
* **Status**: `VERIFIED`
* **Verified Phase**: [Phase 05 — Real Performance & Resilience Engine (Grafana k6)](../../prompts/phase-05-resilience-k6-runner.md)
* **Behavior**: In-process `fetch()` loop replaced with dynamic k6 ES-module script generation and real summary JSON export transport via mounted scratch volumes.

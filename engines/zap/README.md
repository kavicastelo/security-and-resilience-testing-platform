# Engine: OWASP ZAP Runner (Class B Container)

## Responsibility
Isolated containerized test runner integrating OWASP Zed Attack Proxy (ZAP) for baseline and active web application vulnerability scanning.

### What belongs here:
* TestEngine adapter (`ZapScannerEngine`) wrapping the OWASP ZAP CLI (`zap-baseline.py`) via ephemeral Docker runner containers.
* Ephemeral scratch volume exchange (`hostScratchDir:/zap/wrk:rw`) under `os.tmpdir()` for secure report transport.
* Real artifact collection reading `report.json` directly from the mounted scratch volume post-container execution.
* Normalization logic transforming raw ZAP alerts into platform-native `Finding` entities via `normalizeZapAlerts()`.
* Exit code handling: ZAP exit codes 0 (pass), 1 (fail), and 2 (warn) generate reports without discarding findings.
* Safety scope constraints injected into ZAP scan policies to prevent scanning out-of-scope hosts.

### What does NOT belong here:
* Unrestricted or untargeted internet crawling.
* Embedding ZAP binaries or Java runtime directly into the controller monolith.
* Silent mock fallbacks on container failures in production paths.

### Execution Class:
* **Class B (External Scanner Container)**: Spawns ephemeral Docker container runners on-demand, mounts isolated scratch volumes with restricted permissions (`0700`), and cleans them up in a `finally` block post-execution.

### Implementation Status:
* **Status**: `VERIFIED`
* **Verified Phase**: [Phase 04 — Container Scanner Runners (ZAP & Trivy)](../../prompts/phase-04-container-scanner-runners-zap-trivy.md)
* **Behavior**: Full volume mount transport implemented. Ephemeral host scratch directory is mounted to `/zap/wrk:rw`, `report.json` is parsed from the host filesystem, alerts are normalized into platform findings, and all scratch files are destroyed on completion.

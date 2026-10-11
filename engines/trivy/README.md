# Engine: Trivy Vulnerability & Misconfig Runner (Class B Container)

## Responsibility
Isolated containerized runner executing Aqua Security Trivy for container image, filesystem, and misconfiguration scans.

### What belongs here:
* TestEngine adapter (`TrivyScannerEngine`) executing Trivy CLI within an ephemeral container runner.
* Target resolution:
  - Container image scanning via `trivy image --format json --output /trivy-out/report.json <image>` with output scratch volume mounted.
  - Filesystem/repo scanning via `trivy fs --format json --output /trivy-out/report.json /target-src` with read-only target mount (`:ro`) and read-write output scratch mount (`:rw`).
* Ephemeral scratch volume exchange under `os.tmpdir()` with restricted permissions (`0700`).
* Normalization logic transforming Trivy JSON findings (CVEs, misconfigurations) into platform-native `Finding` entities via `normalizeTrivyResults()`.
* Evidence collection linking specific dependency manifests or container layers to findings.

### What does NOT belong here:
* Bundling Trivy binary directly into the controller application.
* Arbitrary host filesystem mounts without restricted scope directories or temp-bound sandboxes.
* Silent mock fallbacks on container failures in production paths.

### Execution Class:
* **Class B (External Scanner Container)**: Spawns ephemeral container runner targeting designated artifacts or directories with CIS-hardened sandboxing.

### Implementation Status:
* **Status**: `VERIFIED`
* **Architecture Reference**: [Test Engine Architecture](../../docs/architecture/test-engine-architecture.md)
* **Verification Suite**: `tests/integration/docker-scanners.test.ts`
* **Behavior**: Full volume mount transport and target resolution implemented. Report files are read from mounted scratch volumes, normalized, and all scratch directories are destroyed in `finally` blocks.

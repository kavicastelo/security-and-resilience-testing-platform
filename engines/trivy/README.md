# Engine: Trivy Vulnerability & Misconfig Runner (Class B Container)

## Responsibility
Isolated containerized runner executing Aqua Security Trivy for container image, filesystem, and misconfiguration scans.

### What belongs here:
* TestEngine adapter executing Trivy CLI within an ephemeral container runner.
* Normalization logic transforming Trivy JSON findings (CVEs, misconfigurations) into platform-native `Finding` entities.
* Evidence collection linking specific dependency manifests or container layers to findings.

### What does NOT belong here:
* Bundling Trivy binary directly into the controller application.
* Arbitrary host filesystem mounts without restricted scope directories.

### Execution Class:
* **Class B (External Scanner Container)**: Spawns ephemeral container runner targeting designated artifacts or directories.

### Implementation Status:
* **Status**: PLANNED (Engine boundary established)
* **Planned Phase**: Phase 3 (Containerized Scanner Integrations)

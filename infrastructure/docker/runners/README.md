# Docker Test Runners

## Responsibility
This directory will contain Dockerfiles and build specifications for isolated, ephemeral containerized test runners (Class B scanners and Class C heavy workers).

### What belongs here:
* Runner container definitions for external scanners (e.g. OWASP ZAP runner Dockerfile, Trivy vulnerability runner Dockerfile, k6 load runner Dockerfile).
* Base runner image configurations with strict least-privilege non-root execution users.

### What does NOT belong here:
* Persistent long-running daemon configurations.
* Platform controller application logic.

### Future Phase Implementation:
* **Phase 2**: Packaging Class B (ZAP, Trivy) and Class C (k6) runner images and lifecycle orchestrators.

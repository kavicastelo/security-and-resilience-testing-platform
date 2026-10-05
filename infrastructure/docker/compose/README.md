# Docker Compose Configurations

## Responsibility
This directory provides modular and environment-specific Docker Compose extension files for varying deployment contexts (e.g. CI testing, local development with mock targets).

### What belongs here:
* `docker-compose.override.yml` templates for local dev mounts.
* `docker-compose.ci.yml` optimized for CI pipelines without volume persistence.
* Mock target environment compose files (e.g. vulnerable reference testbed container).

### What does NOT belong here:
* Monolithic production Kubernetes manifests or unapproved multi-cloud orchestration setups.

### Future Phase Implementation:
* **Phase 1**: Reference target container compose definitions (e.g. mock vulnerable target for test-suite verification).

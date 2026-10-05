# Engine: OWASP ZAP Runner (Class B Container)

## Responsibility
Isolated containerized test runner integrating OWASP Zed Attack Proxy (ZAP) for baseline and active web application vulnerability scanning.

### What belongs here:
* TestEngine adapter wrapping the OWASP ZAP API / CLI via ephemeral Docker runner containers.
* Normalization logic transforming raw ZAP alerts into platform-native `Finding` entities.
* Safety scope constraints injected into ZAP scan policies to prevent scanning out-of-scope hosts.

### What does NOT belong here:
* Unrestricted or untargeted internet crawling.
* Embedding ZAP binaries or Java runtime directly into the controller monolith.

### Execution Class:
* **Class B (External Scanner Container)**: Spawns ephemeral Docker container runners on-demand and tears them down post-execution.

### Implementation Status:
* **Status**: PLANNED (Container wrapper architecture defined)
* **Planned Phase**: Phase 3 (Containerized Scanner Integrations)

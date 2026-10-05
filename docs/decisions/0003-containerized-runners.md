# ADR 0003: Isolated Ephemeral Containerized Test Runners

## Status
Accepted

## Context
Security scanners (such as OWASP ZAP and Trivy) and load-generation tools (such as k6) have diverse runtime requirements (Java, Go, specific native libraries), high memory footprints, and distinct failure modes. Running all these engines permanently inside the controller process or keeping permanent background daemons running consumes substantial system resources and creates severe dependency sprawl.

## Decision
We adopt **isolated, ephemeral containerized runners** for external scanning (Class B) and heavy resilience workers (Class C):
* The controller coordinates the test run and dynamically launches a runner container via Docker only when needed.
* The container runs the test against the target, writes output/evidence, and exits immediately.
* Containers run with unprivileged user permissions, strict memory limits, and isolated network parameters.
* Class A native checks (headers, TLS, CORS) continue to run in-process for sub-second efficiency.

## Consequences
### Positive
* Prevents the controller from crashing due to scanner memory leaks or Java JVM memory consumption.
* Zero persistent resource waste when tests are idle.
* Clean separation of concerns and dependency isolation.

### Negative
* Requires Docker to be available when executing Class B/C scanner tests.

# ADR 0004: Division of Responsibility Between Platform and Test Engines

## Status
Accepted

## Context
When building a security testing product, there is an architectural temptation to either:
1. Re-implement every existing vulnerability scanner from scratch inside the application, OR
2. Become a pure UI shell that dumps raw, unformatted scanner logs onto the user.

Both extremes fail enterprise needs:
* Re-implementing every scanner takes decades and produces inferior coverage.
* Merely dumping raw scanner logs creates vendor lock-in, alert fatigue, unnormalized severities, and inability to enforce unified release gates.

## Decision
We enforce a strict **Separation of Platform and Test Engine Responsibilities**:

1. **What the Platform Owns**:
   * Target scope boundaries and defensive safety authorization.
   * Test planning, scheduling, and lifecycle state machines.
   * Domain finding normalization into canonical `Finding` entities.
   * Cryptographic evidence capture and immutable hashing.
   * Security posture scoring and policy release gating.
   * User interfaces (CLI and Dashboard).

2. **What the Test Engines Own**:
   * Execution of protocol-specific checks and payloads against authorized targets.
   * Emitting raw results and progress telemetry.
   * Conforming to the standardized `TestEngine` contract (`@security-lab/test-sdk`).

## Consequences
### Positive
* The platform can incorporate best-in-class open-source or proprietary scanners without rewriting orchestration logic.
* Findings from diverse tools (ZAP, Trivy, native TLS checks) are normalized into a unified, actionable pane of glass.
* Releases are gated by platform-level policies rather than idiosyncratic tool exit codes.

### Negative
* Requires maintaining robust normalization adapters for each integrated scanner engine.

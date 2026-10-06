# Engine: Authorization & BOLA (Class A Native)

## Responsibility
In-process native engine for evaluating object-level and function-level access control (BOLA / IDOR).

### What belongs here:
* TestEngine implementation for dual-token role permutation tests (e.g. User A accessing User B's resources).
* Role-based access control (RBAC) matrix assertions.
* Scope enforcement tests across tenant boundaries.

### What does NOT belong here:
* Brute-force credential cracking or password spraying.
* Destructive data mutation without dry-run scope flags.

### Execution Class:
* **Class A (Native In-Process)**: Orchestrated via dual-context HTTP client calls.

### Implementation Status:
* **Status**: `NOT_IMPLEMENTED`
* **Current Behavior**: Architectural specification only. Zero code, domain entities, or permission matrices currently exist in the repository.
* **Planned Hardening Phase**: [Phase 08 — Authorization & BOLA/IDOR Testing Framework](../../prompts/phase-08-authorization-bola-testing-framework.md)


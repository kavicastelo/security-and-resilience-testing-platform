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
* **Status**: SCAFFOLDED (Interface boundary defined in `@security-lab/test-sdk`)
* **Planned Phase**: Phase 3 (Advanced Authorization & BOLA Verification)

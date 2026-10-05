# Controller Services

## Responsibility
Encapsulates backend domain services, orchestration logic, and persistence operations.

### What belongs here:
* Infrastructure service integrations (e.g. database client, cache, execution container manager).
* Cross-cutting domain services (e.g. project service, target scope evaluator, test scheduler).

### What does NOT belong here:
* Fastify HTTP route definitions.
* Direct scanner execution logic (scanners execute via isolated runners).

### Future Phase Implementation:
* **Phase 1**: `target.service.ts`, `test-run.service.ts`, `finding.service.ts`.

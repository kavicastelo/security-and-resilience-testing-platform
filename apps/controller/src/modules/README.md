# Controller Business Modules

## Responsibility
Encapsulates domain feature modules following the modular monolith pattern.

### What belongs here:
* Cohesive domain module slices containing their respective schemas, controllers, and domain logic:
  - `projects/`
  - `targets/`
  - `test-runs/`
  - `findings/`
  - `evidence/`
  - `policies/`

### What does NOT belong here:
* Generic server middleware or plugins.
* Direct shell execution of vulnerability tools.

### Future Phase Implementation:
* **Phase 1**: Initial CRUD and orchestration endpoints for Projects, Targets, and TestRuns.

# End-to-End (E2E) Tests

## Responsibility
Contains browser-driven and full-stack workflow tests using Playwright.

### What belongs here:
* Playwright test specs validating end-to-end user workflows:
  - Dashboard navigation, target registration, test run kickoff, and report viewing.
  - CLI execution workflows against a live test environment.

### What does NOT belong here:
* Low-level unit or schema tests.

### Implementation Status:
* **Status**: IMPLEMENTED
* **Test Suite**: `e2e-workflow.test.ts`
* **Coverage**: Full lifecycle workflow testing: Target Registration -> Scope Enforcement -> Test Run Execution -> Findings & Evidence Verification -> Release Gate Evaluation -> Multi-Format Enterprise Reporting (HTML, JUnit XML, SARIF v2.1.0) -> Release Audit Trail.

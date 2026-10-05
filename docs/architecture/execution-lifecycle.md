# Execution Lifecycle Architecture

## 1. Complete Lifecycle Overview

Every security and resilience test executed by Security Lab follows a deterministic, 12-stage pipeline. This guarantees safety, reproducibility, and audit-grade forensic traceability.

```
Target
  ↓
Scope Validation
  ↓
Test Definition
  ↓
Test Planning
  ↓
TestRun
  ↓
TestExecution
  ↓
Engine
  ↓
Raw Result
  ↓
Normalization
  ↓
Evidence Collection (Immutable)
  ↓
Finding / Metric Mapping
  ↓
Policy Evaluation
  ↓
Release Decision
```

---

## 2. Detailed Lifecycle Stages

### Stage 1: Target Registration
An operator or pipeline registers an authorized target. The target specification defines:
* Base URL and hostnames
* Allowed network ports
* Excluded subpaths
* Authorized test classes (active scanning, load testing, chaos testing)
* Operational safety limits (max RPS, max concurrency, max duration)

### Stage 2: Scope Validation
Before any network packet is dispatched, the Scope Validator checks:
* Is the target domain in the allowed hosts list?
* Does the requested test exceed allowed ports or RPS?
* Does the test type require active scanning consent?
If validation fails, execution is immediately rejected with a scope boundary violation error.

### Stage 3: Test Definition Resolution
The platform loads platform-native declarative test definitions (`TestDefinition`) or profiles (e.g. `quick-security`, `api-security`). Each definition outlines the protocol checks, assertions, and threshold criteria.

### Stage 4: Test Planning
The scheduler plans the test sequence:
* Classifies tests into Class A (native), Class B (container scanner), or Class C (heavy worker).
* Orders executions (e.g. passive checks run before any active checks).
* Prepares execution contexts and correlation identifiers.

### Stage 5: TestRun Creation
A `TestRun` record is persisted in PostgreSQL in the `pending` state, establishing the session boundary and audit trail.

### Stage 6: TestExecution Dispatch
Each individual engine task creates a child `TestExecution` record. Depending on its execution class, the job is dispatched to:
* The native worker in-process, OR
* An isolated Docker runner container.

### Stage 7: Engine Execution
The assigned `TestEngine` executes the assertions:
* Handshakes are performed.
* HTTP requests/responses are observed.
* Streaming progress is reported to the controller via `ExecutionContext`.

### Stage 8: Raw Result Capture
The engine outputs its raw, vendor-specific result (e.g. raw HTTP headers, ZAP alert JSON, or k6 telemetry stream).

### Stage 9: Normalization
The normalization adapter maps the raw vendor output into standard platform schemas (`RawFindingPayload` -> `Finding`). Vendor-specific quirks are stripped.

### Stage 10: Immutable Evidence Creation
For each assertion or detected vulnerability, a cryptographically signed, immutable `Evidence` record is generated:
* Contains HTTP request, response, expected condition, actual outcome, environment tags, and git commit.
* Sealed with a SHA-256 fingerprint (`immutableHash`).

### Stage 11: Finding & Metric Ingestion
Normalized findings and quantitative telemetry (p95 latency, error rate) are stored and linked to the `TestRun` and `Target`.

### Stage 12: Policy Evaluation & Release Decision
The `PolicyEngine` evaluates the findings and metrics against the active policy:
* Checks critical/high finding limits.
* Checks performance SLAs.
* Produces a machine-readable verdict: `passed`, `failed` (blocked), or `warning`.
* Emits exit codes for CI/CD gates.

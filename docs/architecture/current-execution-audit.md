# Current Execution Lifecycle Audit

**Project**: Security Lab — Application Security & Resilience Testing Platform  
**Document**: `docs/architecture/current-execution-audit.md`  
**Baseline Date**: October 2026  
**Auditor**: Principal Security Architect & Staff Backend Architect  

---

## 1. Executive Summary

This document traces the complete execution lifecycle of Security Lab from high-level project definition down to raw packet generation, artifact normalization, forensic evidence storage, and release gating:

```
Project
  ↓
Target
  ↓
Scope
  ↓
TestRun
  ↓
Planner (Implicit / Hardcoded Dispatcher)
  ↓
Execution
  ↓
TestEngine
  ↓
Runner (Native In-Process / DockerRunner)
  ↓
Raw Result
  ↓
Normalization
  ↓
Evidence
  ↓
Finding
  ↓
Metric
  ↓
Policy
  ↓
Release
  ↓
Report
```

For every transition, this audit evaluates the actual implementation in the repository, responsible module, data contract, persistence mechanism, error handling, cancellation support, security controls, and existing test coverage.

---

## 2. Transition-by-Transition Lifecycle Analysis

### Transition 1: Project ➔ Target

* **Actual Implementation**:
  - Targets are registered as children of Projects via Fastify REST endpoints (`POST /api/v1/projects/:projectId/targets`) or CLI (`security-lab target create`).
  - Implemented in `apps/controller/src/routes/targets.ts` and `apps/controller/src/services/targets.service.ts`.
* **Responsible Module**: `targets.service.ts` in `@security-lab/controller`.
* **Data Contract**:
  - `CreateTargetInputSchema` (`packages/domain/src/target/index.ts`).
  - Requires: `projectId` (UUID), `name` (string), `baseUrl` (URL), `allowedHosts` (string[]), `allowedPorts` (number[]), `excludedPaths` (string[]), `testing` (capabilities), `limits` (RPS, concurrency, duration).
* **Persistence**: Persisted in PostgreSQL table `targets`. Columns: `id`, `project_id`, `name`, `base_url`, `scope` (JSONB), timestamps.
* **Error Handling**: Zod validation via Fastify route schema. If validation fails, returns HTTP 400 with structured validation errors.
* **Cancellation**: N/A (synchronous metadata operation).
* **Security Controls**:
  - `baseUrl` is validated as a standard URL.
  - Foreign key constraint `targets.project_id` references `projects.id` with `ON DELETE CASCADE`.
  - Unique constraint `(project_id, name)`.
* **Test Coverage**:
  - `tests/integration/target-management.test.ts` (CRUD and target validation).
  - `tests/integration/crud-operations.test.ts`.

---

### Transition 2: Target ➔ Scope

* **Actual Implementation**:
  - Scope is defined as an embedded JSONB property within each target record (`target.scope`).
  - Defines the legal and technical boundaries for all automated tests against that target.
* **Responsible Module**: `packages/domain/src/target/scope-validator.ts` and `packages/domain/src/target/index.ts`.
* **Data Contract**: `TargetScopeSchema` (`TargetScope` TypeScript type).
* **Persistence**: Stored in PostgreSQL `targets.scope` as JSONB.
* **Error Handling**: Parsed and validated on target creation and update. Default values supplied for `allowedPorts` ([80, 443]) and `limits` (100 RPS, 20 concurrency, '10m' duration).
* **Cancellation**: N/A.
* **Security Controls**:
  - Intended to be the primary security boundary of the platform.
  - Scope limits include: `activeScanning` (boolean default false), `loadTesting` (boolean default false), `chaosTesting` (boolean default false).
  - Safety limits include: `maxRps`, `maxConcurrency`, `maxDuration`.
* **Test Coverage**:
  - `tests/integration/scope-validator.test.ts` (9 unit tests).
  - `tests/security/platform-security.test.ts`.

---

### Transition 3: Scope ➔ TestRun

* **Actual Implementation**:
  - A test run session is initialized via `POST /api/v1/test-runs`.
  - Links a target to an execution request with a specific profile or engine configuration.
* **Responsible Module**: `apps/controller/src/services/test-runs.service.ts`.
* **Data Contract**: `CreateTestRunInputSchema` (`CreateTestRunInput`). Accepts `projectId`, `targetId`, `environmentId`, `profileId`, `triggeredBy`, `metadata`.
* **Persistence**: Persisted in PostgreSQL table `test_runs` with initial status `'pending'`.
* **Error Handling**: Verifies target exists and belongs to the specified project. Returns HTTP 404 or 400 if target missing.
* **Cancellation**: N/A during creation.
* **Security Controls**: Foreign key constraint `test_runs.target_id` references `targets.id` with `ON DELETE RESTRICT` (preventing target deletion while runs exist).
* **Test Coverage**:
  - `tests/integration/test-run-execution.test.ts`.
  - `tests/e2e/e2e-workflow.test.ts`.

---

### Transition 4: TestRun ➔ Planner

* **Actual Implementation**:
  - **CRITICAL ARCHITECTURAL FINDING**: There is NO standalone planner module or execution scheduler.
  - Planning logic is an inlined `if/else` block inside `TestRunnerService.executeTestRun()` (`apps/controller/src/services/runner.service.ts`, lines 124–161).
  - Engines are selected strictly by matching string names: `profileId === 'declarative'`, `profileId === 'class-b-scanners'`, `profileId === 'zap'`, `profileId === 'trivy'`, `profileId === 'class-c-resilience'`, etc.
* **Responsible Module**: `runner.service.ts` in `apps/controller`.
* **Data Contract**: Implicit string matching against hardcoded list of engine constructors.
* **Persistence**: None. Engine resolution happens in-memory upon execution trigger.
* **Error Handling**: If `options.engineIds` matches no known engines, falls back to `defaultEngines` (`HeadersSecurityEngine`, `CorsSecurityEngine`, `TlsSecurityEngine`).
* **Cancellation**: None.
* **Security Controls**:
  - Before engine selection, `validateUrlAgainstScope(target.baseUrl, target.scope)` is executed.
  - If scope validation fails, the run is immediately aborted and marked as `'failed'` with a `scope-boundary-gate` execution record.
* **Test Coverage**:
  - `tests/integration/test-run-execution.test.ts`.
  - `tests/integration/scope-validator.test.ts`.

---

### Transition 5: Planner ➔ Execution

* **Actual Implementation**:
  - Execution is dispatched synchronously inside the controller process when `POST /api/v1/test-runs/:id/execute` is invoked.
  - The controller loops sequentially through each resolved engine in a `for...of` loop (`runner.service.ts`, line 176).
  - For each engine, an entry is inserted into `test_executions` with status `'running'`.
* **Responsible Module**: `TestRunnerService` in `apps/controller/src/services/runner.service.ts`.
* **Data Contract**: `testExecutions` table insert row (`id`, `testRunId`, `engineId`, `executionClass`, `status`, `startedAt`).
* **Persistence**: Persisted in PostgreSQL table `test_executions`.
* **Error Handling**: Try/catch around each engine execution. Engine errors are recorded in `test_executions.error_message`, and the execution record is marked `'failed'`.
* **Cancellation**:
  - An `AbortController` is instantiated on line 201 (`const abortController = new AbortController();`).
  - **Weakness**: This `abortController` is local to the for-loop iteration. It is not stored in a registry, not exposed to any HTTP endpoint, and cannot be triggered by the user or an external signal.
* **Security Controls**: Execution class classification (`class_a_native`, `class_b_container`, `class_c_worker`) is tracked for auditing.
* **Test Coverage**:
  - `tests/integration/test-run-execution.test.ts`.

---

### Transition 6: Execution ➔ TestEngine

* **Actual Implementation**:
  - The controller calls `engine.validate(engineInput)` followed by `engine.execute(engineInput, context)`.
  - Input parameters: `targetUrl`, `customHeaders`, `options` (including YAML definition if declarative).
* **Responsible Module**: Individual implementations of `TestEngine` in `packages/test-sdk/src/engines/`:
  - `HeadersSecurityEngine` (Class A)
  - `CorsSecurityEngine` (Class A)
  - `TlsSecurityEngine` (Class A)
  - `DeclarativeTestEngine` (Class A)
  - `ZapScannerEngine` (Class B)
  - `TrivyScannerEngine` (Class B)
  - `K6ResilienceEngine` (Class C)
  - `RateLimitResilienceEngine` (Class A/C)
* **Data Contract**:
  - `TestInput` (`targetUrl`, `customHeaders`, `options`, `timeoutMs`).
  - `ExecutionContext` (`correlationId`, `testRunId`, `executionId`, `target`, `abortSignal`, `reportProgress`, `logger`).
* **Persistence**: Progress logs emitted via `context.reportProgress()`.
* **Error Handling**: `engine.validate()` must return `{ valid: true }` before `execute()` is called. If invalid, marks execution `'failed'` with error details and skips execution.
* **Cancellation**: `context.abortSignal` is passed into the engine.
* **Security Controls**:
  - Active scanning check in `ZapScannerEngine`: verifies `context.target.scope.testing.activeScanning === true`.
  - Load testing check in `K6ResilienceEngine`: verifies `context.target.scope.testing.loadTesting === true` and clamps VUs to `target.scope.limits.maxConcurrency`.
* **Test Coverage**:
  - `tests/integration/native-engines.test.ts`.
  - `tests/integration/container-scanners.test.ts`.
  - `tests/integration/k6-resilience.test.ts`.

---

### Transition 7: TestEngine ➔ Runner

* **Actual Implementation**:
  - **Class A**: No external runner. Uses Node.js built-ins (`fetch()`, `node:tls`, `JSON.parse`).
  - **Class B (ZapScannerEngine & TrivyScannerEngine)**: Dispatches via `DockerRunner.execute()` (`packages/test-sdk/src/runners/docker.runner.ts`).
  - **Class C (K6ResilienceEngine)**:
    - **CRITICAL DEFECT**: Does NOT use `DockerRunner` to execute k6.
    - Uses in-process `fetch()` loop (`executeConcurrentLoad()`) in TypeScript.
    - If `opts.dockerImage` is supplied, it merely runs `docker run ... args: ['version']` in simulation mode.
* **Responsible Module**:
  - In-process: Node.js global `fetch`, `node:tls`.
  - Containerized: `DockerRunner` (`packages/test-sdk/src/runners/docker.runner.ts`).
* **Data Contract**: `DockerRunOptions` (`image`, `args`, `env`, `volumes`, `network`, `memoryLimit`, `cpuLimit`, `timeoutMs`, `abortSignal`, `simulated`, `mockStdout`).
* **Persistence**: None at runner level.
* **Error Handling**:
  - `DockerRunner.execute()` returns `DockerRunResult` (`exitCode`, `stdout`, `stderr`, `durationMs`, `simulated`).
  - **CRITICAL DEFECT**: If `spawn('docker')` fails (e.g. Docker not running), `DockerRunner` silently resolves with `mockStdout` if provided instead of throwing an error.
* **Cancellation**: Passes `abortSignal` to `spawn()`. If `timeoutMs` triggers, sends `SIGTERM` to the local docker CLI process.
* **Security Controls**:
  - Passes `--memory` (default 1024m) and `--cpus` (default 1.0).
  - Adds `--rm` flag.
  - **Critical Gaps**: Missing `--security-opt=no-new-privileges`, missing `--cap-drop=ALL`, missing `--user`, arbitrary volume mounts permitted, arbitrary image names allowed.
* **Test Coverage**:
  - `tests/integration/container-scanners.test.ts` (runs in simulation mode).

---

### Transition 8: Runner ➔ Raw Result

* **Actual Implementation**:
  - For Class A: Raw HTTP headers object, TLS peer certificate object, or assertion failure list.
  - For Class B:
    - `ZapScannerEngine`: Expects JSON string on `runResult.stdout`.
    - **CRITICAL DEFECT**: ZAP writes its report to `report.json` on disk, NOT stdout. `JSON.parse(runResult.stdout)` fails and triggers the catch block, which falls back to the hardcoded `SAMPLE_ZAP_BASELINE_REPORT`.
    - `TrivyScannerEngine`: Runs `trivy fs --format json .` inside the container without mounting host code. If parsing fails, falls back to `SAMPLE_TRIVY_REPORT`.
  - For Class C: `LatencyStats` object computed from `fetch()` timings.
* **Responsible Module**: Engine execution handlers in `packages/test-sdk/src/engines/`.
* **Data Contract**: `TestResult` (`engineId`, `durationMs`, `success`, `findings: RawEngineFinding[]`, `metrics: RawEngineMetric[]`, `rawOutput: unknown`, `error?: string`).
* **Persistence**: `test_executions.raw_result` (JSONB) in PostgreSQL.
* **Error Handling**: Wrapped in try/catch. Errors recorded in `TestResult.error`.
* **Cancellation**: Abort signal checked between loop iterations.
* **Security Controls**: Truncates large string bodies to 1000 characters in evidence.
* **Test Coverage**: Tested in `tests/integration/native-engines.test.ts`.

---

### Transition 9: Raw Result ➔ Normalization

* **Actual Implementation**:
  - Normalization adapters translate tool-specific alerts into canonical platform structures:
    - `normalizeZapAlerts()` (`packages/domain/src/normalizers/zap.normalizer.ts`) maps ZAP risk codes (3->critical, 2->high, 1->medium, 0->low) to `FindingSeverity`.
    - `normalizeTrivyResults()` (`packages/domain/src/normalizers/trivy.normalizer.ts`) maps CVEs and misconfigurations to `FindingSeverity`.
* **Responsible Module**: `packages/domain/src/normalizers/`.
* **Data Contract**: Vendor JSON ➔ `NormalizedFinding[]` (`title`, `category`, `severity`, `description`, `recommendation`, `evidence`, `metadata`).
* **Persistence**: None (in-memory transformation).
* **Error Handling**: Fallbacks for undefined alert arrays or missing fields.
* **Cancellation**: N/A.
* **Security Controls**: Strips vendor-specific internal paths from normalized description.
* **Test Coverage**:
  - `tests/integration/zap-normalizer.test.ts` (2 tests).
  - `tests/integration/trivy-normalizer.test.ts` (2 tests).

---

### Transition 10: Normalization ➔ Evidence

* **Actual Implementation**:
  - For every finding with evidence, `createImmutableEvidence()` creates a forensic record.
  - Computes `immutableHash = SHA-256(canonicalString)`.
  - Applies `Object.freeze()` in-memory.
  - Calls `evidenceService.saveEvidence(evidence)`.
* **Responsible Module**:
  - `packages/evidence/src/index.ts` (`createImmutableEvidence`, `computeEvidenceHash`).
  - `apps/controller/src/services/evidence.service.ts`.
* **Data Contract**: `Evidence` (`id`, `testRunId`, `executionId`, `request`, `response`, `expected`, `actual`, `metadata`, `timestamp`, `environment`, `immutableHash`).
* **Persistence**: Persisted in PostgreSQL table `evidence_records`.
* **Error Handling**: Throws if database insertion fails.
* **Cancellation**: N/A.
* **Security Controls**:
  - Cryptographic SHA-256 fingerprinting.
  - **Weakness**: `JSON.stringify` does not sort keys before hashing. Object key ordering in Node.js can produce unstable hashes across platforms or post-PostgreSQL JSONB round-trip.
  - **Weakness**: No PostgreSQL trigger or rule prevents `UPDATE` or `DELETE` on `evidence_records`.
* **Test Coverage**:
  - `tests/security/platform-security.test.ts` (2 tests for tamper detection).
  - `tests/integration/crud-operations.test.ts`.

---

### Transition 11: Normalization ➔ Finding

* **Actual Implementation**:
  - Controller generates a SHA-256 fingerprint:
    `SHA-256(engine.id : target.id : rawFinding.title : rawFinding.category : rawFinding.severity)`
  - Calls `findingsService.saveFinding(...)`.
* **Responsible Module**: `apps/controller/src/services/findings.service.ts`.
* **Data Contract**: `CreateFindingInput` ➔ `Finding`.
* **Persistence**: Persisted in PostgreSQL table `findings`.
* **Error Handling**: Throws if insert fails.
* **Cancellation**: N/A.
* **Security Controls**:
  - **Critical Flaw**: Fingerprint does NOT incorporate endpoint path, parameter, rule ID, or CVE ID. Two different endpoints with the same missing header generate identical fingerprints and collide!
  - **Critical Flaw**: No deduplication or status tracking. Every test run blindly inserts new rows with duplicate fingerprints instead of updating `lastDetectedAt` or managing lifecycle (`open` -> `resolved` -> `regressed`).
* **Test Coverage**:
  - `tests/integration/test-run-execution.test.ts`.
  - `tests/integration/crud-operations.test.ts`.

---

### Transition 12: Normalization ➔ Metric

* **Actual Implementation**:
  - Quantitative telemetry from engines (e.g. `http_req_duration_p95`, `http_req_duration_p99`, `http_rps`, `http_req_failed_ratio`, `zap_findings_count`) are ingested into `metricsService.saveMetric(...)`.
* **Responsible Module**: `apps/controller/src/services/metrics.service.ts`.
* **Data Contract**: `SaveMetricInput` (`testRunId`, `executionId`, `name`, `value`, `unit`, `tags`, `threshold`).
* **Persistence**: Persisted in PostgreSQL table `metrics`.
* **Error Handling**: Wrapped in try/catch during execution.
* **Cancellation**: N/A.
* **Security Controls**: Double precision numeric bounds checking.
* **Test Coverage**:
  - `tests/integration/k6-resilience.test.ts`.

---

### Transition 13: Finding / Metric ➔ Policy

* **Actual Implementation**:
  - `evaluatePolicy()` evaluates findings and metrics against active rules.
  - Checks: `maxAllowedSeverity`, `maxCountBySeverity`, `disallowCategories`, `maxP95LatencyMs`, `maxErrorRatePercent`.
  - Emits decision: `'passed'`, `'warning'`, or `'failed'`.
* **Responsible Module**: `packages/policy-engine/src/index.ts`.
* **Data Contract**: `evaluatePolicy(policy: Policy, findings: Finding[], metrics: Metric[]): PolicyEvaluationResult`.
* **Persistence**: Evaluated dynamically or during release evaluation.
* **Error Handling**: Returns empty violation list if policy has no rules.
* **Cancellation**: N/A (pure synchronous function).
* **Security Controls**: Strict zero-tolerance for blocking rules.
* **Test Coverage**:
  - `tests/integration/release-gating-and-reports.test.ts`.
  - `tests/security/platform-security.test.ts`.

---

### Transition 14: Policy ➔ Release

* **Actual Implementation**:
  - Controller evaluates policy via `POST /api/v1/releases/evaluate` or CLI `security-lab gate evaluate`.
  - Creates or updates a record in the `releases` table with decision and reason.
* **Responsible Module**: `apps/controller/src/services/releases.service.ts`.
* **Data Contract**: `EvaluateReleaseGateInput` (`testRunId`, `policyId`, `name`, `version`, `gitCommit`, `gitBranch`).
* **Persistence**: Persisted in PostgreSQL table `releases`.
* **Error Handling**: Returns HTTP 400 if `testRunId` is missing or not found.
* **Cancellation**: N/A.
* **Security Controls**: Audit trail with `evaluated_at`, `git_commit`, and `git_branch`.
* **Test Coverage**:
  - `tests/integration/release-gating-and-reports.test.ts`.
  - `tests/e2e/e2e-workflow.test.ts`.

---

### Transition 15: Release ➔ Report

* **Actual Implementation**:
  - `ReportsService.generateReport(testRunId, format)` generates:
    - JUnit XML (`generateJUnitXml`)
    - SARIF v2.1.0 (`generateSarifReport`)
    - HTML Executive Dashboard (`generateHtmlExecutiveReport`)
    - JSON
* **Responsible Module**:
  - `apps/controller/src/services/reports.service.ts`.
  - `packages/contracts/src/reports/`.
* **Data Contract**: `ReportInput` ➔ `GeneratedReport` (`format`, `content`, `contentType`, `filename`).
* **Persistence**:
  - **Gap**: Reports are generated dynamically in memory and returned as HTTP download attachments or CLI stdout/files. There is NO `reports` table in PostgreSQL to store historical reports or artifacts.
* **Error Handling**: Returns HTTP 404 if `testRunId` does not exist.
* **Cancellation**: N/A.
* **Security Controls**:
  - HTML report escapes user input to prevent XSS.
  - SARIF report conforms to OASIS SARIF v2.1.0 specification for GitHub Code Scanning integration.
* **Test Coverage**:
  - `tests/integration/release-gating-and-reports.test.ts`.
  - `tests/e2e/e2e-workflow.test.ts`.

---

## 3. Summary of Execution Architectural Weaknesses

| Lifecycle Stage | Identified Weakness | Architectural Severity |
| :--- | :--- | :--- |
| **Scope Validation** | String-only check without DNS resolution, socket pinning, or redirect re-validation. SSRF vectors present. | **CRITICAL** |
| **Planner** | No real planner or queue. Hardcoded in-line dispatching in controller service. | **HIGH** |
| **Execution Dispatch** | Synchronous sequential loop blocks Fastify controller event loop during long runs. | **HIGH** |
| **Cancellation** | `AbortController` created locally per iteration and lost; cannot be cancelled externally. | **HIGH** |
| **Class B Scanners (ZAP)** | Output written to container disk is never read from host; parser fails and silently falls back to mock JSON. | **CRITICAL** |
| **Class B Scanners (Trivy)** | Scans Trivy's own container filesystem (`fs .`) rather than target repository/image; silent mock fallback on error. | **CRITICAL** |
| **Class C Workers (k6)** | Labeled as k6, but actually an in-process JavaScript `fetch()` loop in Node.js. | **CRITICAL** |
| **Fingerprinting** | Excludes endpoint URL, parameter, rule ID, and CVE ID. Causes finding collisions across endpoints. | **HIGH** |
| **Finding Lifecycle** | Blind insert of duplicates on every test run. No status tracking (`open`, `resolved`, `regressed`). | **HIGH** |
| **Evidence Immutability** | Database allows updates/deletes; hash uses non-canonical JSON serialization. | **MEDIUM** |
| **Report Persistence** | Ephemeral only. No database storage or artifact repository. | **MEDIUM** |

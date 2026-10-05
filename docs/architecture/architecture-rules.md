# Architectural Rules & Tenets

These 12 architectural rules govern the design, implementation, and evolution of the Security Lab platform. Every module, contributor, and agent must adhere to them.

---

### Rule 1: Orchestration Separation
**The controller orchestrates tests; it does not become the scanner implementation.**
The controller application coordinates test planning, schedules runs, enforces scopes, ingests results, and evaluates release gates. It must never embed ad-hoc attack payloads or bloated third-party scanning engines into its process space.

---

### Rule 2: Contract-Driven Testing Engines
**Security engines must communicate through stable test-engine contracts.**
Every testing capability—whether native or external—must interface exclusively through the standardized `TestEngine` contract defined in `@security-lab/test-sdk`.

---

### Rule 3: Replaceable Scanners
**External scanners are replaceable implementation details.**
Tools such as OWASP ZAP, Aqua Trivy, and Grafana k6 are wrapped behind standardized adapters. The core platform must never couple to vendor-specific APIs or schemas.

---

### Rule 4: Unified Finding Normalization
**Findings must be normalized into the platform's own domain model.**
Regardless of whether an alert is detected by a native header check, a containerized ZAP scan, or a future scanner, it must be mapped into the canonical `Finding` entity schema defined in `@security-lab/domain`.

---

### Rule 5: Immutable Forensic Evidence
**Evidence must be reproducible and immutable.**
Evidence captured during test runs constitutes a forensic audit record. Evidence objects are hashed with SHA-256 upon creation and sealed against modification. Re-testing generates a new test run; previous records are never altered.

---

### Rule 6: Mandatory Target Scoping
**Targets must have explicit scopes.**
Testing requires a registered `Target` record defining an allowed host list and port boundaries. Passing arbitrary, unverified URLs to execution engines is strictly prohibited.

---

### Rule 7: Safety Limits on Disruptive Tests
**Potentially disruptive testing requires explicit enablement and safety limits.**
Active fuzzing, load testing, or state-mutating requests require explicit target capability flags (`activeScanning: true`, `loadTesting: true`) and rate clamps (`maxRps`, `maxConcurrency`, `maxDuration`).

---

### Rule 8: Modular Monolith Foundation
**The MVP is a modular monolith.**
All controller subsystems reside within a single, cohesive, well-modularized codebase. This ensures low operational complexity, high velocity, and straightforward local execution.

---

### Rule 9: No Premature Microservices
**Do not introduce microservices until a demonstrated scaling requirement exists.**
Do not decompose controller modules into independent network services without empirical operational necessity.

---

### Rule 10: Ubiquitous Contract Reusability
**The SaaS architecture must eventually reuse the same test-engine and execution contracts.**
Future enterprise agents and cloud-hosted control planes must utilize the exact same domain entities, DTOs, and test engine contracts initialized in this foundation.

---

### Rule 11: AI Positioning
**AI is an analysis/remediation layer, not the primary vulnerability detector.**
Deterministic protocol checks, verified assertions, and established scanners identify security findings. AI assistance is reserved for triage, root-cause explanation, code remediation suggestions, and policy synthesis.

---

### Rule 12: Deterministic Machine-Readable Outputs
**Every test must eventually produce deterministic machine-readable results.**
All test executions must generate structured, machine-parsable JSON/SARIF/JUnit outputs that can be evaluated deterministically in automated CI/CD release gates.

# Enterprise Operations Console & Interactive Triage Dashboard (`@security-lab/dashboard`)

The Security & Resilience Testing Platform Operations Console is a high-performance, real-time web application built with React, Vite, TanStack Query, and Tailwind CSS. It serves as the primary visual mission control for platform operators, security engineers, and compliance auditors.

---

## Key Capabilities

### 1. Real-Time Test Run Operations & SSE Streaming
- **Server-Sent Events (SSE)**: Streams live run lifecycle updates, engine transitions, and execution throughput directly from `GET /api/v1/test-runs/:id/stream`.
- **Active Stage Visualizer**: Visual stage stepper tracking engine lifecycles (`pending`, `running`, `completed`, `failed`).
- **Telemetry Console**: Auto-scrolling terminal log stream with pause/resume controls and syntax highlighting.
- **Resilient Fallback**: Graceful degradation to 5-second polling interval in environments blocking persistent HTTP streaming connections.

### 2. Interactive Finding Triage Console
- **Multi-Criteria Filtering**: Filter by severity (`critical`, `high`, `medium`, `low`, `info`), triage status (`open`, `resolved`, `false_positive`, `accepted_risk`, `suppressed`), or search text.
- **One-Click Triage Workflow**:
  - `Mark False Positive`: Transitions state machine with engineering justification.
  - `Accept Risk`: Configures timed policy waivers (7, 30, 60, 90 days) with approver attribution.
  - `Targeted Retest`: Triggers isolated single-finding retesting engines (`POST /api/v1/findings/:id/retest`) directly from the table row.
- **CLI Command Generator**: Copies exact reproduction commands for terminal execution.

### 3. Forensic Evidence Modal & HTTP Diff Inspector
- **HTTP Request/Response Viewer**: Inspect captured headers, status codes, and bodies.
- **Expected vs Actual Diff**: Visual contract assertion comparison.
- **Cryptographic Hash Verification**: SHA-256 integrity badges verifying tamper resistance.
- **Executable cURL Snippet**: One-click generation of escaped, copy-pasteable terminal commands to reproduce vulnerabilities locally.

### 4. Target Profile & Test Plan Builder
- **Scope Boundary Constraints**: Configure authorized hostnames, ports, and blacklisted paths.
- **Engine Sequencing**: Select permitted engine suites (active fuzzing, load testing, chaos injection).
- **Rate Limit Throttles**: Define safe ceiling thresholds for concurrency and requests-per-second.
- **Scope Playground**: Interactive in-form URL validator testing candidate endpoints against declared boundary constraints.

---

## Development & Testing

```bash
# Run local development server
pnpm --filter @security-lab/dashboard dev

# Typecheck and build production bundle
pnpm --filter @security-lab/dashboard build

# Run dashboard test suite
npx vitest run apps/dashboard/tests/dashboard.test.ts
```

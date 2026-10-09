# Security Lab

> **Security QA for Enterprise Applications**
> *(A local-first security and resilience testing laboratory).*

[![CI](https://github.com/security-lab/security-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/security-lab/security-lab/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-blue.svg)](https://www.typescriptlang.org/)
[![Fastify](https://img.shields.io/badge/Fastify-5.2-black.svg)](https://fastify.dev/)
[![React](https://img.shields.io/badge/React-18.3-cyan.svg)](https://react.dev/)

---

> [!IMPORTANT]
> **Authorization & Legal Notice**:
> This project is designed for authorized security testing of applications and infrastructure owned or explicitly authorized by the operator.
> The platform enforces strict target scope boundaries and defensive safety controls. It is **NOT** an unrestricted hacking framework.

---

## 1. What Security Lab Is

**Security Lab** is an enterprise-grade, local-first platform designed to test web applications, APIs, authentication workflows, and system resilience. It bridges the gap between software development and security engineering by providing automated, reproducible, contract-driven security QA that can run on a developer's workstation or within automated CI/CD release gates.

Unlike ad-hoc security scanning scripts, Security Lab organizes testing around:
* **Explicit Target Scopes**: Enforcing allowed hosts, ports, and safety limits.
* **Declarative Test Definitions**: Specifying assertions, headers, and protocol expectations.
* **Unified Finding Normalization**: Mapping alerts from diverse tools into a single canonical model.
* **Forensically Immutable Evidence**: Cryptographically hashing request/response payloads.
* **Automated Policy Gating**: Deterministically blocking or approving code releases based on security criteria.

---

## 2. Product Philosophy

* **Security as a Quality Dimension**: Security defects are software bugs. They should be identified, verified, and gated using reproducible tests, just like functional regressions.
* **Shift Left, Not Overhead**: Fast, passive audits (Class A) should run in seconds on pull requests; heavy scans (Class B/C) should run asynchronously in isolated containers.
* **Replaceable Implementations**: Scanners (e.g. ZAP, Trivy, k6) are interchangeable execution engines. The platform owns the scopes, policies, evidence, and release decisions.
* **Forensic Integrity**: Findings without immutable evidence are noise. Every reported issue must be backed by reproducible evidence.

---

## 3. Intended Users

* **Application Security Engineers**: Establishing baseline security contracts and automating QA checks across internal services.
* **DevSecOps & Platform Engineers**: Implementing deterministic CI/CD release gates and preventing vulnerable code deployments.
* **Software Developers**: Testing authorization, API endpoints, and security headers locally before pushing code.
* **QA & Resilience Engineers**: Measuring API performance degradation and failure modes under stress.

---

## 4. Local-First Architecture

Security Lab operates completely offline on a developer's laptop or inside an ephemeral CI runner:
* **Zero Mandatory Cloud Dependencies**: No third-party SaaS required for core orchestration.
* **Lightweight Backing Services**: A single PostgreSQL instance provides state persistence.
* **Ephemeral Runner Containers**: Heavy scanners and workers are launched dynamically on-demand and terminated immediately post-test, keeping local resource usage minimal.

---

## 5. High-Level Architecture

The system is built as a **Modular Monolith + Isolated Execution Containers**:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        Security Lab Platform                           │
│                                                                        │
│   ┌────────────────────┐                 ┌─────────────────────────┐   │
│   │   Web Dashboard    │                 │       Console CLI       │   │
│   │ (React/Vite/TS/UI) │                 │  (Commander/Typescript) │   │
│   └─────────┬──────────┘                 └────────────┬────────────┘   │
│             │                                         │                │
│             └───────────────────┬─────────────────────┘                │
│                                 │ REST API                             │
│                                 ▼                                      │
│   ┌────────────────────────────────────────────────────────────────┐   │
│   │                     Controller Application                     │   │
│   │                 (Fastify / TypeScript / Zod)                   │   │
│   │                                                                │   │
│   │  ┌──────────────┐ ┌──────────────┐ ┌─────────────┐ ┌─────────┐ │   │
│   │  │   Projects   │ │   Targets    │ │  Test Runs  │ │ Policies│ │   │
│   │  └──────────────┘ └──────────────┘ └─────────────┘ └─────────┘ │   │
│   │  ┌───────────────────────────────────────────────────────────┐ │   │
│   │  │       Execution Dispatcher & Scope Security Enforcer      │ │   │
│   │  └───────────┬───────────────────┬───────────────────┬───────┘ │   │
│   └──────────────┼───────────────────┼───────────────────┼─────────┘   │
│                  │                   │                   │             │
│                  ▼                   ▼                   ▼             │
│          ┌───────────────┐   ┌───────────────┐   ┌───────────────┐     │
│          │    Class A    │   │    Class B    │   │    Class C    │     │
│          │ Native Engine │   │   Container   │   │ Heavy Worker  │     │
│          │  (In-Process) │   │  (ZAP/Trivy)  │   │ (k6/Resilience│     │
│          └───────┬───────┘   └───────┬───────┘   └───────┬───────┘     │
│                  │                   │                   │             │
│                  └───────────────────┼───────────────────┘             │
│                                      ▼                                 │
│                      Normalized Evidence & Findings                    │
│                                      │                                 │
│                                      ▼                                 │
│                        PostgreSQL (System of Record)                   │
└────────────────────────────────────────────────────────────────────────┘
```

### Execution Classes:
* **Class A (Native In-Process)**: HTTP headers, TLS, CORS, cookies, authorization matrix, rate limits.
* **Class B (Scanner Container)**: OWASP ZAP, Aqua Trivy (ephemeral sandboxed Docker runners).
* **Class C (Heavy Worker)**: Grafana k6, browser-based tests, soak and resilience experiments.

---

## 6. Repository Structure

```text
security-lab/
├── apps/
│   ├── dashboard/          # React / Vite / Tailwind / TanStack Query dashboard
│   ├── controller/         # Fastify orchestration controller application
│   └── cli/                # Commander-based CLI tool
├── packages/
│   ├── domain/             # Framework-agnostic domain models & Zod schemas
│   ├── contracts/          # Cross-boundary API, engine, and execution DTOs
│   ├── config/             # Strict validated environment configuration
│   ├── logger/             # Structured JSON logging abstraction with correlation
│   ├── evidence/           # Immutable, cryptographically hashed evidence module
│   ├── scoring/            # Security posture score calculations
│   ├── policy-engine/      # Release gate policy evaluation engine
│   └── test-sdk/           # Standardized TestEngine plugin interface
├── engines/                # Modular engine specifications (Class A, B, C)
├── profiles/               # Audit profiles (quick-security, api-security, release-gate)
├── infrastructure/         # Docker Compose files, PostgreSQL migrations & seeds
├── examples/               # Declarative target scopes, test definitions, and policies
├── tests/                  # Automated integration, E2E, fixture, and security tests
├── docs/                   # Architectural blueprints and Decision Records (ADRs)
└── scripts/                # Development, setup, and verification scripts
```

---

## 7. Development Prerequisites

* **Node.js**: >= 20.0.0 (Node 22 LTS recommended)
* **pnpm**: >= 9.0.0 (or pnpm 12)
* **Docker & Docker Compose**: Installed and running locally
* **Git**: Installed

---

## 8. Installation

Clone the repository and install workspace dependencies:

```bash
# Clone the repository
git clone https://github.com/security-lab/security-lab.git
cd security-lab

# Install monorepo dependencies
pnpm install
```

---

## 9. Running Locally

### 1. Configure Environment
```bash
cp .env.example .env
```

### 2. Generate Local Cryptographic Secrets
Security Lab utilizes high-entropy 256-bit keys for local API authentication and distributed job lease attestation. Generate your local keys using Node.js without any cloud dependencies:

```bash
# Generate Operator API Key
node -e "console.log('SECURITY_LAB_API_KEY=' + crypto.randomBytes(32).toString('hex'))"

# Generate Admin API Key (for purges, seeds, and backups)
node -e "console.log('SECURITY_LAB_ADMIN_KEY=' + crypto.randomBytes(32).toString('hex'))"

# Generate Agent Attestation Master Secret
node -e "console.log('AGENT_MASTER_SECRET=' + crypto.randomBytes(32).toString('hex'))"
```
Paste the generated values into your local `.env` file.

### 3. Start PostgreSQL
```bash
docker compose up -d postgres
```
*Migrations located in `infrastructure/postgres/migrations` are automatically mounted and applied on first container startup.*

### 4. Launch Development Mode
```bash
# Starts the controller and dashboard in parallel watch mode
pnpm run dev:all
```

* **Dashboard Web UI**: [http://localhost:3000](http://localhost:3000)
* **Controller API**: [http://localhost:4000](http://localhost:4000)
* **API Health Check**: [http://localhost:4000/health](http://localhost:4000/health)

### 5. Run the Console CLI
```bash
# Display CLI commands and options
pnpm --filter @security-lab/cli start --help

# Authenticate CLI with your local controller
pnpm --filter @security-lab/cli start login -k <YOUR_SECURITY_LAB_API_KEY>

# Run a local-first security scan
pnpm --filter @security-lab/cli start scan --target http://localhost:4000/health
```

---

## 10. Running Tests & Quality Gates

```bash
# Run unit and integration tests across all workspaces
pnpm test

# Run real Docker container scanner integration test suite (requires Docker daemon)
pnpm test:docker

# Run strict TypeScript compilation check
pnpm run typecheck

# Run ESLint quality gate
pnpm run lint
```

---

## 11. Docker Scanner Prerequisites & Sandboxing

Security Lab executes heavy scanners (OWASP ZAP, Aqua Trivy, Grafana k6) inside ephemeral Docker containers without running as root:

* **Prerequisites**: Docker Desktop or Docker Engine running with active socket permissions.
* **Unprivileged Execution**:
  * Container runs with non-root user (`--user 10001:10001`).
  * Linux capabilities completely dropped (`--cap-drop=ALL`).
  * Kernel privilege escalation disabled (`--security-opt=no-new-privileges`).
  * Ephemeral container root filesystems mounted read-only (`--read-only`).
  * Temporary scratch volumes isolated to `.data/artifacts/<runId>`.
* **Offline Mock Fallback**: For environments without Docker, set `SECURITY_LAB_MOCK_CONTAINERS=true` in `.env` to execute in simulated sandbox mode.

---

## 12. Local-First Security & Trust Model

The platform enforces a multi-tier defense-in-depth security model:

1. **Centralized Authentication Hook**:
   * Every protected endpoint is verified via Fastify `onRequest` auth guards using constant-time token comparisons (`timingSafeEqual`).
   * Supports `SECURITY_LAB_API_KEY` for standard operators, and `SECURITY_LAB_ADMIN_KEY` for administrative routes.
2. **Contextual Tenant Scoping & Anti-Spoofing**:
   * Tenant IDs are resolved cryptographically from authenticated tokens (`extractTenantScope`), never from untrusted client-supplied headers.
   * Cross-tenant access and header spoofing (`x-tenant-id`) attempts by non-admin roles are rejected with HTTP 403 Forbidden.
3. **Cryptographic Attestation**:
   * Distributed worker jobs and scope permissions are cryptographically signed with HMAC-SHA256 using `AGENT_MASTER_SECRET`.
   * Workers verify signatures before opening any network sockets.
4. **Tiered Rate Limiting & Anti-DoS**:
   * Fine-grained, memory-backed rate limits protect expensive scan dispatchers (10 req/min per tenant) and database purges (3 req/5min).
   * Real-time SSE telemetry streams (`/stream`) are exempt from rate counters and socket timeouts.

---

## 13. Current Implementation Status (Audited & Verified)

All core security engines, scope validators, container runners, and management subsystems have been implemented, hardened, and verified via end-to-end integration test suites:

| Subsystem / Area | Verified Status | Architecture & Reality | Verification Suite |
| :--- | :---: | :--- | :--- |
| **Monorepo Foundation** | `VERIFIED` | Strict `pnpm` workspaces, TypeScript project references, 0 type errors, 0 ESLint errors. | `pnpm typecheck && pnpm lint` |
| **Centralized Authentication** | `VERIFIED` | Fastify auth hooks, Bearer / API key validation, constant-time compare, fail-closed production mode. | `tests/integration/controller-auth.test.ts` |
| **Tenant Isolation & Anti-Spoof** | `VERIFIED` | Server-derived tenant context, foreign key enforcement, header spoofing rejection. | `tests/integration/tenant-isolation.test.ts` |
| **Class A Native Engines** | `VERIFIED` | In-process HTTP Headers, CORS, TLS, and rate-limiting with DNS pinning and redirect re-validation. | `tests/integration/native-engines.test.ts` |
| **Authentication Testing Engine**| `VERIFIED` | Automated JWT algorithm `none` probes, expired token audits, cookie flags, and brute-force throttling. | `tests/integration/authentication-engine.test.ts` |
| **Authorization / BOLA Engine** | `VERIFIED` | Cross-identity permission matrix evaluation, horizontal IDOR, vertical BFLA, and curl reproduction evidence. | `tests/integration/authorization-engine.test.ts` |
| **Security Contracts (OpenAPI)** | `VERIFIED` | Declarative contract rules, schema fuzzing, and unhandled 500 error detection. | `tests/integration/security-contracts.test.ts` |
| **Class B Container Scanners** | `VERIFIED` | Real OWASP ZAP and Aqua Trivy container execution with volume artifact transport and fail-closed errors. | `tests/integration/docker-scanners.test.ts` |
| **Class C Resilience Engine** | `VERIFIED` | Real Grafana k6 container execution with script generation, latency percentiles, and thresholds. | `tests/integration/k6-resilience.test.ts` |
| **Declarative Test DSL v2** | `VERIFIED` | Chained multi-step HTTP workflows, request body payloads, variable extraction, and negative assertions. | `tests/integration/dsl-v2.test.ts` |
| **Forensic Evidence & Hashing** | `VERIFIED` | RFC 8785 canonical JSON serialization, SHA-256 evidence hashing, and tamper-resistant storage. | `packages/evidence/tests/attestation.test.ts` |
| **Cryptographic Attestation** | `VERIFIED` | HMAC-SHA256 signed job scopes and attestation tokens; zero static secrets; key rotation support. | `tests/security/scope-propagation-ssrf.test.ts` |
| **Universal Platform Management**| `VERIFIED` | System overview, authenticated non-destructive seeds, rate-limited purges, and encrypted backup vault. | `tests/integration/universal-management.test.ts` |
| **Rate Limiting & Anti-DoS** | `VERIFIED` | Tiered per-route rate limits (scan: 10/min, purge: 3/5min) with RFC 6585 429 Retry-After responses. | `tests/integration/rate-limit.test.ts` |
| **Console CLI** | `VERIFIED` | Offline scanning, `.securitylab.yaml` configuration, API key synchronization, and CI/CD exit codes. | `tests/integration/cli-standalone.test.ts` |
| **Web Dashboard** | `VERIFIED` | Real-time SSE telemetry streaming, SVG latency percentiles, policy builder, and backup management. | `tests/integration/telemetry-triage.test.ts` |

---

## 14. License

Distributed under the Apache 2.0 License. See `LICENSE` for details.

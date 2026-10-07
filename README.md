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

### 2. Start PostgreSQL
```bash
docker compose up -d postgres
```

### 3. Launch Development Mode
```bash
# Starts both the controller and dashboard in watch mode
pnpm run dev:all
```

* **Dashboard Web UI**: [http://localhost:3000](http://localhost:3000)
* **Controller API**: [http://localhost:4000](http://localhost:4000)
* **API Health Check**: [http://localhost:4000/health](http://localhost:4000/health)

### 4. Run CLI
```bash
pnpm --filter @security-lab/cli start --help
pnpm --filter @security-lab/cli start version
```

---

## 10. Running Tests

```bash
# Run unit and integration tests across all workspaces
pnpm test

# Run strict TypeScript typecheck
pnpm run typecheck

# Run ESLint validation
pnpm run lint
```

---

## 11. Docker Usage

To spin up the entire platform in production container mode:

```bash
# Build and start all services
docker compose up -d --build

# Inspect service logs
docker compose logs -f controller

# Verify health status
curl -i http://localhost:4000/health

# Clean shutdown
docker compose down
```

---

## 12. Current Implementation Status (Audited Baseline)

> [!WARNING]
> **Engineering Baseline Notice (October 2026 Audit)**:
> The codebase has completed foundational scaffolding and prototype workflows. However, an in-depth architectural audit identified that several subsystems currently use simulated fallbacks, in-process stubs, or string-based scope validations.
> The platform is actively undergoing an **agentic 16-phase hardening program** specified in [`docs/architecture/product-roadmap.md`](docs/architecture/product-roadmap.md) and [`prompts/`](prompts/README.md).
>
> **Safety Warning**: Native engines currently follow HTTP redirects by default. Until **Phase 01** is implemented, only run tests against strictly controlled and isolated test targets.

| Subsystem / Area | Verified Status | Evidence & Reality | Next Action |
| :--- | :---: | :--- | :--- |
| **Monorepo Foundation** | `VERIFIED` | `pnpm` workspaces, strict TypeScript references, clean typecheck and linting. | Maintain boundaries |
| **Domain Models & Schemas** | `VERIFIED` | Pure domain entities with strict Zod validation (`@security-lab/domain`). | Add Identity & DSL v2 models |
| **Cross-Boundary Contracts** | `VERIFIED` | API DTOs, execution messages, CLI options (`@security-lab/contracts`). | Maintain contracts |
| **Enterprise Reporting** | `VERIFIED` | JUnit XML, SARIF v2.1.0, HTML executive reports, and immutable artifact storage. | Complete |
| **Console CLI** | `VERIFIED` | Commander CLI with standalone offline testing, `.securitylab.yaml`, and GitHub Action. | Complete |
| **Web Dashboard** | `VERIFIED` | Real-time SSE telemetry streaming, live progress & logs, interactive triage, SVG latency percentile curves, and visual policy builder. | Complete |
| **Class A Native Engines** | `IMPLEMENTED_BUT_UNSAFE` | OWASP Headers, CORS, TLS, and baseline rate-limiting run in-process; follow redirects without re-checking scope. | Phase 01: Redirect interception |
| **Target Scope Validator** | `IMPLEMENTED_BUT_UNSAFE` | Validates host string and port; lacks DNS resolution, socket pinning, and IP normalization. | Phase 01: DNS & IP hardening |
| **Docker Runner Sandbox** | `IMPLEMENTED_BUT_UNSAFE` | Spawns containers with CPU/RAM caps; missing capability dropping, non-root user, and socket path restrictions. | Phase 02: Container hardening |
| **Controller Orchestration** | `PARTIALLY_IMPLEMENTED` | Fastify REST API; contains hardcoded engine array, sequential blocking loop, unexposed cancellation. | Phase 03: EngineRegistry & queue |
| **Class B Container Scanners** | `IMPLEMENTED_BUT_INCOMPLETE` | ZAP container report transport broken; Trivy scans own image; both fall back silently to mock JSON. | Phase 04: Real volume transport |
| **Class C Resilience Workers** | `IMPLEMENTED_BUT_INCOMPLETE` | Labeled as Grafana k6, but actually runs an in-process JavaScript `fetch()` loop in Node.js. | Phase 05: Real k6 container runner |
| **Declarative Test DSL** | `IMPLEMENTED_BUT_INCOMPLETE` | Evaluates single HTTP assertions; lacks request bodies, path parameters, and request chaining. | Phase 06: Declarative DSL v2 |
| **Authentication Testing** | `SCAFFOLDED` | Header injection only; JWT audits, cookie flags, and session testing are stubs in README. | Phase 07: Auth testing engine |
| **Authorization / BOLA** | `NOT_IMPLEMENTED` | Documentation specifications only (`engines/authorization/README.md`); zero code in repository. | Phase 08: BOLA testing engine |
| **PostgreSQL & Findings** | `PARTIALLY_IMPLEMENTED` | 8 tables; missing definitions, reports, artifacts; fingerprint collisions; lacks lifecycle state machine. | Phase 10: Database hardening |
| **Policy Engine & Gate** | `IMPLEMENTED` | Deterministic evaluation of severity, categories, and latency; lacks required profile gating & waivers. | Phase 11: Policy Engine v2 |

---

## 13. Phased Implementation Roadmap

The project is governed by a **16-phase sequential implementation roadmap**. Each phase is backed by an independent, executable agent prompt under [`prompts/`](prompts/README.md).

For the complete architectural blueprint and dependency order, see:
* **Current State Architecture**: [`docs/architecture/current-state.md`](docs/architecture/current-state.md)
* **Execution Lifecycle Audit**: [`docs/architecture/current-execution-audit.md`](docs/architecture/current-execution-audit.md)
* **Gap Analysis & Inventory**: [`docs/architecture/gap-analysis.md`](docs/architecture/gap-analysis.md)
* **Product Roadmap Master Plan**: [`docs/architecture/product-roadmap.md`](docs/architecture/product-roadmap.md)
* **Prompt Library & Status**: [`prompts/README.md`](prompts/README.md)

### Implementation Horizons:
* **Horizon 1: Local MVP (Phases 00–05)**: Truthful baseline, SSRF & scope boundary hardening, container sandboxing, asynchronous engine registry, and real container scanner runners (ZAP, Trivy, k6).
* **Horizon 2: Team V1 (Phases 06–08)**: Declarative DSL v2 with request bodies & chaining, dedicated Authentication Testing Framework, and native Authorization & BOLA/IDOR Testing Engine.
* **Horizon 3: Enterprise V2 (Phases 09–14)**: Security Contracts & OpenAPI discovery, database hardening & finding regression intelligence, Policy Engine v2 with waivers, artifact persistence, offline CLI, and real-time dashboard telemetry.
* **Horizon 4: SaaS & Hybrid Cloud (Phase 15)**: Distributed private execution agents (`apps/agent`) and multi-tenant SaaS control plane.





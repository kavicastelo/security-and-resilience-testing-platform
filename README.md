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

## 12. Current Status (Phase 0 Initialization)

| Subsystem / Area | Status | Description |
| :--- | :--- | :--- |
| **Monorepo Foundation** | **IMPLEMENTED** | pnpm workspaces, strict TypeScript references, ESLint, Prettier |
| **Domain Models & Schemas** | **IMPLEMENTED** | Pure domain entities with strict Zod validation (`@security-lab/domain`) |
| **Cross-Boundary Contracts** | **IMPLEMENTED** | API DTOs, execution messages, CLI options (`@security-lab/contracts`) |
| **TestEngine SDK** | **IMPLEMENTED** | Standardized `TestEngine` interface boundary (`@security-lab/test-sdk`) |
| **Evidence Immutability** | **IMPLEMENTED** | SHA-256 cryptographic hashing and tamper freeze (`@security-lab/evidence`) |
| **Configuration & Logging** | **IMPLEMENTED** | Zod-validated config, structured correlation logging |
| **PostgreSQL Foundation** | **IMPLEMENTED** | Forward-only migration schema (`0000_initial_schema.sql`) and seeds |
| **Controller Application** | **IMPLEMENTED** | Fastify service with `/health`, `/api/v1/health`, graceful shutdown |
| **Web Dashboard** | **IMPLEMENTED** | React/Vite shell with dark theme, health polling, architecture views |
| **CLI Skeleton** | **IMPLEMENTED** | Commander CLI with `version`, `--help`, and future command stubs |
| **Architecture Blueprints** | **IMPLEMENTED** | 5 detailed architecture docs and 4 Architecture Decision Records |
| **Real Attack / Scanner Logic** | **NOT IMPLEMENTED** | Intentionally deferred to subsequent implementation phases |

---

## 13. Future Roadmap

* **Phase 1: Target Management & Security Boundary Enforcement**
  * CRUD APIs and CLI for projects, environments, and targets.
  * Target Scope Validator with DNS rebinding and subnet protection.
  * TestRun state machine and persistence in PostgreSQL via Drizzle.
* **Phase 2: Native Test Engines (Class A)**
  * Implementation of `headers`, `tls`, `cors`, and `http-security` native engines.
  * Execution of platform-native declarative YAML test definitions.
* **Phase 3: Containerized Scanner Integrations (Class B)**
  * Ephemeral Docker runner orchestrator for OWASP ZAP and Trivy.
  * Finding ingestion and normalization pipeline.
* **Phase 4: Resilience & Load Testing (Class C)**
  * Integration with Grafana k6 for automated latency SLA and concurrency soak testing.
* **Phase 5: Release Gating & Enterprise Reporting**
  * Automated JUnit, SARIF, and PDF/HTML report generators.
  * CI/CD GitHub Actions / GitLab CI release gating integrations.

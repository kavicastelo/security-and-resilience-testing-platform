# System Overview: Security Lab Platform

## 1. Product Positioning & Purpose

**Security Lab** is a local-first security QA laboratory engineered specifically for applications and infrastructure owned or explicitly authorized to test.

The platform's positioning is strictly:
> **Security QA for Enterprise Applications**
> *(NOT an unrestricted hacking framework).*

Modern engineering organizations require continuous, deterministic security and resilience assurance built into their software development lifecycles (SDLC) and CI/CD pipelines. Security Lab fills this critical gap by treating security tests with the same rigor, reproducibility, and contract-driven approach as unit and integration tests.

---

## 2. High-Level Architecture Model

Security Lab is architected as a **Modular Monolith + Isolated Execution Containers**.

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
│                                 │ REST / OpenAPI                       │
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
│          │  (In-Process) │   │   (ZAP/Trivy) │   │ (k6/Resilience│     │
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

---

## 3. Core Architectural Subsystems

### 3.1 Controller (`apps/controller`)
The central coordinator and state manager. It exposes the HTTP management APIs, authenticates callers, strictly validates target scopes, schedules test runs, ingests normalized findings, and evaluates release gate decisions. It does **not** become an all-in-one bloated scanner; instead, it delegates test execution through stable contracts.

### 3.2 Dashboard (`apps/dashboard`)
A modern, dark-mode first, responsive UI for visualizing testing telemetry, target boundaries, historical test runs, and policy pass/fail statuses. Built with React, Vite, Tailwind CSS, TanStack Query, and Zustand.

### 3.3 Command-Line Interface (`apps/cli`)
The direct pipeline integration tool. Enables engineers and DevSecOps practitioners to run audits, register targets, and gate CI/CD workflows locally or inside build agents.

### 3.4 Shared Domain & Contracts Layer (`packages/*`)
Framework-agnostic domain entities (`@security-lab/domain`), cross-boundary DTOs (`@security-lab/contracts`), unified logging (`@security-lab/logger`), configuration loading (`@security-lab/config`), immutable evidence verification (`@security-lab/evidence`), scoring algorithms (`@security-lab/scoring`), policy gating (`@security-lab/policy-engine`), and the standardized test engine interface (`@security-lab/test-sdk`).

---

## 4. Key Tenets & Design Principles

1. **Local-First & Ephemeral**: Runs entirely on a developer laptop or local CI agent without mandatory external cloud connections.
2. **Defensive Target Scoping**: No scan or test can execute without an explicit, validated target scope boundary.
3. **Forensic Evidence Immutability**: All evidence collected during tests is hashed with SHA-256 and treated as an immutable record.
4. **Replaceable Scanner Implementations**: External scanners (such as ZAP or Trivy) are ephemeral implementation details wrapped behind stable contracts.

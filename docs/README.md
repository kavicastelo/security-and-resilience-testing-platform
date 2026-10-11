# Security Lab Technical Documentation Library

> **Enterprise-grade, local-first security and resilience testing laboratory.**  
> Official technical specifications, architecture blueprints, security models, and developer guides for the MVP release.

---

## 1. Documentation Structure

The documentation library is organized into five specialized knowledge domains:

```text
docs/
├── README.md                           # Master Documentation Portal (This Document)
│
├── architecture/                       # Core Architecture & System Blueprints
│   ├── system-overview.md              # System Overview, positioning, and modular monolith model
│   ├── architecture-rules.md           # Master Architecture Rules (25 Invariants)
│   ├── execution-lifecycle.md          # 12-stage test execution lifecycle pipeline
│   ├── distributed-data-flow.md        # End-to-end distributed execution data flow sequence
│   ├── test-engine-architecture.md     # Class A, B, C execution engines & dynamic registry
│   ├── agent-protocol.md               # Agent-to-Controller communication protocol spec
│   ├── job-state-machine.md            # Distributed job leasing & FSM lifecycle
│   ├── policy-engine.md                # Policy Engine & release governance specification
│   ├── repository-structure.md         # Monorepo directory layout & package organization
│   └── product-roadmap.md              # Strategic product horizons & development roadmap
│
├── security/                           # Defensive Engineering & Trust Specifications
│   ├── README.md                       # Security philosophy & legal notice
│   ├── security-boundary.md            # Multi-layer SSRF shielding, IP canonicalization, & sandboxing
│   ├── security-model.md               # Trust boundaries, key hierarchy (TEK), & attestation
│   └── threat-model.md                 # STRIDE threat model & attack surface analysis
│
├── testing/                            # Testing Frameworks & Verification Standards
│   ├── README.md                       # Testing strategy, QA standards, & verification suites
│   ├── declarative-dsl-spec.md         # Declarative Test DSL specification & assertion schema
│   └── security-contracts.md           # OpenAPI security contract engine & schema fuzzing
│
├── development/                        # Contributor & Operator Guides
│   ├── README.md                       # Developer onboarding, setup, local run & artifact storage
│   └── cli-guide.md                    # CLI reference, offline mode, & CI/CD pipeline integration
│
└── decisions/                          # Architecture Decision Records (ADRs)
    ├── 0001-modular-monolith.md        # ADR 0001: Modular Monolith Architecture for Controller
    ├── 0002-postgresql.md              # ADR 0002: PostgreSQL as Primary Datastore with Drizzle ORM
    ├── 0003-containerized-runners.md   # ADR 0003: Isolated Ephemeral Containerized Test Runners
    └── 0004-platform-vs-scanner-responsibility.md # ADR 0004: Platform vs. Scanner Responsibilities
```

---

## 2. Directory Index & Specifications

### 2.1 Architecture & Blueprints (`docs/architecture/`)
* [System Overview](architecture/system-overview.md): High-level platform architecture, modular monolith model, and core subsystems.
* [Master Architecture Rules](architecture/architecture-rules.md): The 25 non-negotiable architectural invariants governing platform design and execution safety.
* [Execution Lifecycle Architecture](architecture/execution-lifecycle.md): The deterministic 12-stage pipeline from target registration to release decisions.
* [Distributed Execution Data Flow](architecture/distributed-data-flow.md): Sequence diagrams and boundary transformations for distributed testing.
* [Test Engine Architecture](architecture/test-engine-architecture.md): Specifications for Class A (Native), Class B (Container Scanner), and Class C (Heavy Worker) engines and the dynamic `EngineRegistry`.
* [Agent Communication Protocol](architecture/agent-protocol.md): REST and SSE communication protocol between private execution agents and the central control plane.
* [Distributed Job State Machine](architecture/job-state-machine.md): Finite state machine, atomic lease claiming (`SKIP LOCKED`), and cancellation handling.
* [Policy Engine & Release Governance](architecture/policy-engine.md): Declarative policy rules, temporal finding waiver tracking, and cryptographic release sealing.
* [Repository Structure](architecture/repository-structure.md): Comprehensive monorepo workspace directory tree and module responsibilities.
* [Product Roadmap & Horizons](architecture/product-roadmap.md): Strategic product vision spanning Horizons 1 through 4.

### 2.2 Security & Defensive Controls (`docs/security/`)
* [Security Overview](security/README.md): Legal authorization notices and defensive engineering principles.
* [Security Boundaries & Defensive Controls](security/security-boundary.md): Multi-layer SSRF defenses, decimal/octal/hex IP normalization, DNS rebinding shielding, and container sandboxing flags.
* [Platform Security Model & Trust Architecture](security/security-model.md): Trust boundary matrix (TB-01 to TB-11), two-tier key hierarchy (TEK), tenant isolation, and cryptographic result attestation.
* [Platform Threat Model](security/threat-model.md): Comprehensive STRIDE analysis evaluating 18 critical threat scenarios.

### 2.3 Testing & Quality Assurance (`docs/testing/`)
* [Testing Strategy & QA Guide](testing/README.md): Unit, integration, Docker scanner, and adversarial self-security test suites.
* [Declarative Test DSL Specification](testing/declarative-dsl-spec.md): Schema for chained multi-step HTTP tests, variable extraction, and assertion operators.
* [OpenAPI Security Contracts & Schema Fuzzing](testing/security-contracts.md): API contract verification and deterministic negative schema fuzzing.

### 2.4 Developer & Operator Guides (`docs/development/`)
* [Development Guide](development/README.md): Prerequisites, local environment setup, PostgreSQL migration instructions, and artifact storage.
* [CLI & CI/CD Guide](development/cli-guide.md): Console CLI documentation, offline standalone runner (`--local`), and GitHub Actions integration.

### 2.5 Architecture Decision Records (`docs/decisions/`)
* [ADR 0001: Modular Monolith Architecture](decisions/0001-modular-monolith.md): Selection of a modular Fastify monolith over premature microservices.
* [ADR 0002: PostgreSQL with Drizzle ORM](decisions/0002-postgresql.md): Selection of PostgreSQL as the ACID-compliant primary datastore.
* [ADR 0003: Isolated Ephemeral Containerized Runners](decisions/0003-containerized-runners.md): Decoupling heavy scanners into ephemeral Docker containers.
* [ADR 0004: Platform vs. Scanner Responsibilities](decisions/0004-platform-vs-scanner-responsibility.md): Clear division between platform policies and scanner engines.

---

## 3. Recommended Reading Paths

### For Application Developers & QA Engineers
1. [Developer Onboarding & Setup](development/README.md)
2. [CLI & CI/CD Guide](development/cli-guide.md)
3. [Declarative Test DSL Specification](testing/declarative-dsl-spec.md)
4. [OpenAPI Security Contracts](testing/security-contracts.md)

### For AppSec & DevSecOps Practitioners
1. [System Overview](architecture/system-overview.md)
2. [Security Boundaries & Defensive Controls](security/security-boundary.md)
3. [Policy Engine & Release Governance](architecture/policy-engine.md)
4. [Testing Strategy & QA Guide](testing/README.md)

### For Infrastructure & Security Architects
1. [Master Architecture Rules](architecture/architecture-rules.md)
2. [Platform Security Model & Trust Architecture](security/security-model.md)
3. [Platform Threat Model](security/threat-model.md)
4. [Agent Communication Protocol](architecture/agent-protocol.md)
5. [Distributed Job State Machine](architecture/job-state-machine.md)
6. [Architecture Decision Records](decisions/0001-modular-monolith.md)

# Repository Structure & Workspace Organization

```text
security-lab/
│
├── apps/
│   ├── dashboard/          # React / Vite / Tailwind / shadcn frontend UI
│   ├── controller/         # Fastify orchestration controller application
│   └── cli/                # Commander-based CLI tool
│
├── packages/
│   ├── domain/             # Framework-agnostic core domain models & Zod schemas
│   ├── contracts/          # Cross-boundary API, test engine, and CLI contracts
│   ├── config/             # Strict validated environment configuration
│   ├── logger/             # Structured JSON logging abstraction with correlation IDs
│   ├── evidence/           # Immutable, cryptographically hashed evidence module
│   ├── scoring/            # Security & resilience posture score algorithms
│   ├── policy-engine/      # Release gate policy evaluation engine
│   └── test-sdk/           # Standardized TestEngine plugin interface
│
├── engines/                # Pluggable testing engine implementations & wrappers
│   ├── http-security/      # HTTP verb, CORS, method tampering checks (Class A)
│   ├── authorization/      # BOLA, IDOR, role permutation checks (Class A)
│   ├── authentication/     # Token, session, JWT validation (Class A)
│   ├── headers/            # OWASP secure headers compliance checks (Class A)
│   ├── tls/                # TLS 1.2+, cipher suites, cert validation (Class A)
│   ├── zap/                # OWASP ZAP container runner adapter (Class B)
│   ├── trivy/              # Aqua Trivy container runner adapter (Class B)
│   └── k6/                 # Grafana k6 resilience & load runner (Class C)
│
├── profiles/               # Pre-packaged audit and test configurations
│   ├── quick-security/     # Fast (<30s) passive security audit for PR checks
│   ├── api-security/       # In-depth REST/GraphQL security verification
│   ├── performance/        # Stress and latency resilience benchmarks
│   └── release-gate/       # Deterministic CI/CD deployment gating profile
│
├── infrastructure/         # Local deployment and database configurations
│   ├── docker/
│   │   ├── runners/        # Dockerfiles for Class B and Class C runner containers
│   │   └── compose/        # Specialized Compose overlays for CI and mock targets
│   └── postgres/
│       ├── migrations/     # Versioned, forward-only SQL migration scripts
│       └── seeds/          # Development and QA reference seed datasets
│
├── examples/               # Sample declarative contracts and definitions
│   ├── targets/            # Target scope examples with safety limits
│   ├── test-definitions/   # Platform-native declarative test definitions
│   ├── security-contracts/ # API security contract specifications
│   └── policies/           # CI/CD release gate policy rule examples
│
├── tests/                  # Automated platform verification test suites
│   ├── integration/        # Controller API & contract integration tests
│   ├── e2e/                # Playwright end-to-end browser workflow tests
│   ├── fixtures/           # Mock payloads and test certificates
│   └── security/           # Platform defensive self-audit tests
│
├── docs/                   # Architectural blueprints and decision records
│   ├── architecture/       # System diagrams, lifecycles, and security models
│   ├── decisions/          # Architecture Decision Records (ADRs)
│   ├── development/        # Developer onboarding and contributor guidelines
│   ├── testing/            # Testing strategy and coverage standards
│   └── security/           # Threat model and responsible disclosure
│
├── scripts/                # Development, setup, and CI verification scripts
├── .github/workflows/      # Automated GitHub Actions CI pipeline
├── .env.example            # Environment configuration template
├── docker-compose.yml      # Local development container orchestration
├── pnpm-workspace.yaml     # Monorepo workspace package configuration
├── tsconfig.json           # Root TypeScript configuration with project references
└── README.md               # Primary project documentation
```

# Testing Strategy & Quality Assurance

## Overview
Security Lab utilizes automated testing to ensure the integrity of its orchestration, domain contracts, and execution pipelines.

### Test Categories
* **Unit Tests**: Framework-independent domain tests (`packages/domain`, `@security-lab/evidence`, `@security-lab/scoring`, `@security-lab/policy-engine`).
* **Integration Tests**: Fastify HTTP controller routes, database transactions, and correlation tracing (`tests/integration/`).
* **E2E Tests**: Playwright browser tests verifying dashboard workflows (`tests/e2e/`).
* **Self-Security Tests**: Security regressions and boundary validation (`tests/security/`).

### Running Tests
```bash
# Run all tests
pnpm test

# Run tests in watch mode
pnpm test:watch

# Run tests with coverage
pnpm test:coverage
```

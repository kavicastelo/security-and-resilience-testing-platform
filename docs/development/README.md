# Development Guide

## Getting Started
Follow these steps to set up the development environment:

### Prerequisites
* Node.js >= 20.0.0
* pnpm >= 9.0.0 (or pnpm 12)
* Docker & Docker Compose

### Local Setup
1. Clone the repository and install dependencies:
   ```bash
   pnpm install
   ```

2. Generate local secrets and configure `.env`:
   ```bash
   cp .env.example .env
   ```
   Generate high-entropy keys using native Node.js:
   ```bash
   # Generate API Key
   node -e "console.log(crypto.randomBytes(32).toString('hex'))"

   # Generate Admin Key
   node -e "console.log(crypto.randomBytes(32).toString('hex'))"

   # Generate Agent Master Secret
   node -e "console.log(crypto.randomBytes(32).toString('hex'))"
   ```
   Set `SECURITY_LAB_API_KEY`, `SECURITY_LAB_ADMIN_KEY`, and `AGENT_MASTER_SECRET` in your `.env` file.

3. Start backing services (PostgreSQL):
   ```bash
   docker compose up -d postgres
   ```
   *Note: Database migrations in `infrastructure/postgres/migrations/` are applied automatically by the PostgreSQL Docker container on initial startup.*

4. Launch services in development watch mode:
   ```bash
   pnpm dev:all
   ```
   * Dashboard: `http://localhost:3000`
   * Controller API: `http://localhost:4000`
   * Controller Health: `http://localhost:4000/health`

### Controller Authentication
All non-public routes (`/api/v1/*`) require authentication:
```bash
# Standard user/agent request:
curl -H "X-API-Key: <your-api-key>" http://localhost:4000/api/v1/targets

# Administrative request (seeding/purging/restore):
curl -X POST -H "X-Admin-Key: <your-admin-key>" http://localhost:4000/api/v1/management/seed
```

### Running Tests
```bash
# Run unit and mock integration test suites (560+ tests):
pnpm test

# Run dedicated real Docker scanner integration tests (requires Docker daemon running):
pnpm test:docker

# Type checking and linting:
pnpm typecheck
pnpm lint
```

### Docker Scanner Prerequisites & Sandboxing
To execute Class B (OWASP ZAP, Aqua Trivy) or Class C (Grafana k6) scans locally:
* **Docker Daemon**: Ensure Docker is installed and running.
* **Pull Scanner Images**:
  ```bash
  docker pull ghcr.io/zaproxy/zaproxy:stable
  docker pull aquasec/trivy:latest
  docker pull grafana/k6:latest
  ```
* **Unprivileged Execution**: All container runners operate with hardened security flags:
  - `--cap-drop=ALL` (drops all Linux capabilities)
  - `--security-opt=no-new-privileges:true` (prevents privilege escalation)
  - `--user 10001:10001` (runs as unprivileged user)
  - `--read-only` (read-only root filesystem)
  - Strictly confined temporary scratch directory mounts under `os.tmpdir()` with automatic post-run teardown.


---

## Artifact Storage & Report Persistence Subsystem

### Storage Architecture
The platform features an immutable, forensics-grade artifact storage subsystem backed by local filesystem storage and PostgreSQL:
* **Storage Location**: Configured via `ARTIFACTS_DIR` (defaults to `./.data/artifacts`). Files are partitioned safely by test run ID:
  ```text
  .data/artifacts/<testRunId>/<filename>
  ```
* **Path Traversal Prevention**: Strict sanitization rejects any filename containing path traversal characters (`..`, `/`, `\`, null bytes, or URL-encoded equivalents).
* **Forensic Integrity (SHA-256)**: Every stored file has its SHA-256 checksum calculated at storage time and recorded in the `artifacts` table. Retrieval operations re-verify disk content against the database checksum to detect tampering.

### Enterprise Reporting & Formats
Upon test run completion or release evaluation, reports are automatically generated and persisted in both PostgreSQL (`reports` table) and disk storage (`artifacts` table):
1. **JUnit XML** (`application/xml`): Compatible with CI/CD systems (Jenkins, GitLab CI, GitHub Actions). Includes test cases, error traces, finding diff counts, and curl reproduction commands in failure tags.
2. **SARIF v2.1.0** (`application/sarif+json`): OASIS standard compatible with GitHub Code Scanning and GitLab SAST. Embeds rule definitions, precision levels, finding diff status (`diffStatus`), and reproducible `curlCommand` in result properties.
3. **Executive HTML** (`text/html`): Self-contained visual report suitable for browser viewing or PDF generation. Highlights overall security grade, posture score, quantitative latency SLAs, finding diff intelligence (`NEW`, `RECURRING`, `FIXED`), and copy-pasteable terminal cURL commands.

### Reproducible cURL Generation
Finding evidence records (`evidence.request`) are automatically translated into executable bash cURL commands with:
* Exact HTTP method and target URL
* Request headers with single-quote shell escaping
* Request body `--data-raw` with POSIX bash single-quote escaping

### Report & Artifact REST APIs

| Endpoint | Method | Description | Content-Type / Headers |
| :--- | :--- | :--- | :--- |
| `/api/v1/test-runs/:id/reports` | `GET` | Lists all persisted reports for a test run | `application/json` |
| `/api/v1/test-runs/:id/reports/:reportId/download` | `GET` | Downloads a specific generated report | `attachment; filename="..."` |
| `/api/v1/test-runs/:id/artifacts` | `GET` | Lists all forensic artifacts for a test run | `application/json` |
| `/api/v1/test-runs/:id/artifacts/:artifactId/download` | `GET` | Downloads a raw artifact (logs, telemetry, reports) | `X-Artifact-SHA256: <hash>` |
| `/api/v1/test-runs/:id/report?format=<fmt>` | `GET` | Generates report dynamically on demand | `inline; filename="..."` |

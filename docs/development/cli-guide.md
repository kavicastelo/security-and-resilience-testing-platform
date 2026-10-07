# Security Lab CLI & CI/CD Guide

The Security Lab CLI (`@security-lab/cli`, executable as `security-lab`) provides developer-first security and resilience quality gates for modern engineering teams.

Starting in **Phase 13**, the CLI features a **Standalone Local Execution Runner** (`--local`), enabling engineers and CI/CD pipelines to run fast, in-process Class A security audits directly on local branches without starting PostgreSQL or the Fastify controller daemon.

---

## Table of Contents
1. [Key Features](#key-features)
2. [Quickstart: Standalone Offline Mode](#quickstart-standalone-offline-mode)
3. [Configuration File (`.securitylab.yaml`)](#configuration-file-securitylabyaml)
4. [Command Reference](#command-reference)
5. [GitHub Actions Integration](#github-actions-integration)
6. [Exit Codes & Release Governance](#exit-codes--release-governance)
7. [Reporting Artifacts](#reporting-artifacts)

---

## 1. Key Features

- ⚡ **Offline & Autonomous**: Runs in < 2 seconds in-process using native Node.js HTTP/TLS engines.
- 🛡️ **Zero Cloud/Database Dependency**: Evaluates headers, CORS, TLS, and declarative contracts without Postgres or Docker.
- 📐 **Scope Hardened**: Strictly enforces target scope boundaries, allowed hostnames, and ports.
- 📋 **Repo-Level Policy as Code**: Configure targets, thresholds, waivers, and test definitions in `.securitylab.yaml`.
- 📊 **Universal Reporting**: Directly exports SARIF (v2.1.0) for GitHub Code Scanning, JUnit XML for CI/CD test dashboards, and styled Executive HTML summaries.
- 🤖 **GitHub Step Summary**: Automatically appends rich Markdown tables with findings and posture scores to `$GITHUB_STEP_SUMMARY`.

---

## 2. Quickstart: Standalone Offline Mode

Run a security audit against a local development server or API endpoint:

```bash
# Standalone execution against target
security-lab run --local --target http://localhost:8080

# Fail pipeline only if release gate policy fails (exit code 1)
security-lab run --local --target http://localhost:8080 --fail-on failed

# Export SARIF directly for GitHub code scanning
security-lab run --local --target http://localhost:8080 --format sarif --output reports/security-lab.sarif

# Run specific engines only
security-lab run --local --target http://localhost:8080 -e headers cors
```

---

## 3. Configuration File (`.securitylab.yaml`)

The CLI automatically looks for `.securitylab.yaml` or `.securitylab.yml` in the current working directory. You can also specify an explicit path using `-c, --config <path>`.

### Complete `.securitylab.yaml` Reference

```yaml
version: "1.0"
name: "Order Service Security Contract"

# Target Specification & Scope Clamps
target:
  name: "Order API Service"
  baseUrl: "http://localhost:8080"
  allowedHosts:
    - "localhost"
    - "127.0.0.1"
  allowedPorts:
    - 8080
    - 8443
  excludedPaths:
    - "/admin/internal"

# Test Engine Configuration & Declarative Definitions
definitions:
  engines:
    - headers
    - cors
    - tls
    - declarative
  declarativeFiles:
    - "./tests/security/**/*.yaml"

# Release Governance Policy
policy:
  name: "Production Release Gate"
  failOn: "failed"            # Options: 'failed', 'warning', 'never'
  maxAllowedSeverity: "high"  # Fails if higher severity findings exist
  maxCriticalFindings: 0
  maxHighFindings: 0
  minPostureScore: 80         # Minimum posture score (0 - 100)
  waivers:
    - findingFingerprint: "sha256-finding-fingerprint"
      reason: "Legacy endpoint undergoing deprecation"
      author: "security-team"
      expiresAt: "2026-12-31T23:59:59Z"

# Artifact Reporters & Output Destinations
reporters:
  formats:
    - terminal
    - sarif
    - junit
    - html
  outputDir: "./reports"
  sarifFile: "reports/security-lab.sarif"
  junitFile: "reports/junit.xml"
  htmlFile: "reports/executive-report.html"
```

---

## 4. Command Reference

### `security-lab run`
Executes security and resilience test suites against a target.

```text
Usage: security-lab run [options]

Options:
  -l, --local                    Execute in standalone local offline mode (no controller or database required)
  -t, --target <url>             Target URL to test
  -c, --config <path>            Path to project configuration file (.securitylab.yaml)
  -f, --format <format>          Report format to export: terminal, sarif, junit, html, json (default: "terminal")
  -o, --output <path>            Output file path for generated report
  --fail-on <decision>           Fail threshold: failed, warning, or never (default: "failed")
  -e, --engines <engines...>     Specific Class A engines to execute (headers, cors, tls, auth, bola, contract)
  --silent                       Suppress console logs (exit code only)
  -h, --help                     Display help for command
```

### `security-lab gate evaluate`
Evaluates release governance policies against a completed test run ID stored in the controller.

```bash
security-lab gate evaluate --run-id <id> --fail-on failed
```

### `security-lab report generate`
Generates persisted or streamed SARIF, JUnit, or HTML reports from the controller.

```bash
security-lab report generate -r <runId> -f sarif -o reports/security-lab.sarif
```

---

## 5. GitHub Actions Integration

Use the zero-configuration composite GitHub Action located at `.github/actions/security-lab`:

```yaml
name: Security & Resilience Gate

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  security-test:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Setup Node.js & pnpm
        uses: actions/setup-node@v4
        with:
          node-version: 22

      - name: Install Dependencies & Build
        run: |
          pnpm install --frozen-lockfile
          pnpm run build

      - name: Run Security Lab Gate
        uses: ./.github/actions/security-lab
        with:
          target-url: 'http://localhost:8080'
          sarif-output: 'reports/security-lab.sarif'
          fail-on: 'failed'

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: reports/security-lab.sarif
          category: security-lab
```

---

## 6. Exit Codes & Release Governance

The CLI communicates gate verdicts directly to CI/CD shells:

| Exit Code | Meaning | Condition |
| :---: | :--- | :--- |
| **0** | **Passed** | All policy criteria met, or `--fail-on never` specified. |
| **1** | **Policy Gate Failed** | Critical/high findings exceed threshold, or posture score fell below `minPostureScore`. |
| **1** | **Runtime Error** | Scope boundary violation, network failure, or invalid configuration. |

---

## 7. Reporting Artifacts

When executing locally or in CI/CD, the following reports can be generated simultaneously:

1. **SARIF 2.1.0** (`--format sarif --output <file>`):
   - Fully compatible with GitHub Code Scanning, GitLab Security Dashboard, and SonarQube.
   - Includes precise CWE identifiers, Markdown remediation notes, and affected URIs.
2. **JUnit XML** (`--format junit --output <file>`):
   - Integrates with Jenkins, GitLab CI, GitHub Actions, and CircleCI test reporting plugins.
3. **Executive HTML** (`--format html --output <file>`):
   - Visual dashboard with posture score badges, latency percentile stats, and copy-pasteable curl reproduction commands.
4. **JSON Summary** (`--format json --output <file>`):
   - Raw machine-readable payload for custom pipelines and automated telemetry collection.

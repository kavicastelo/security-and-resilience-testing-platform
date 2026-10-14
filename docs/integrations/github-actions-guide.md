# CI/CD Ecosystem Integration Guide: GitHub Actions & Webhooks

The **Security & Resilience Testing Platform** integrates directly into developer CI/CD workflows through native GitHub Actions, GitLab CI/CD, HMAC-signed webhooks, and two-way issue tracker synchronization (GitHub Issues and Jira Cloud).

---

## 1. Official GitHub Action Workflow

Use `.github/actions/security-lab-scan/action.yml` to execute local or central security audits on every Pull Request.

### Example Workflow: `.github/workflows/security-scan.yml`

```yaml
name: Security & Resilience Testing Gate

on:
  pull_request:
    branches: [main, develop]
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write
  pull-requests: write

jobs:
  security-audit:
    name: Application Security Scan
    runs-on: ubuntu-latest

    steps:
      - name: Checkout Source Code
        uses: actions/checkout@v4

      - name: Run Security Lab Scan Action
        uses: ./.github/actions/security-lab-scan
        with:
          target-url: 'https://staging.internal.example.com'
          config-path: '.securitylab.yaml'
          fail-on: 'failed'
          sarif-file: 'security-results.sarif'
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

---

## 2. Reliable HMAC-Signed Webhook Delivery

Security Lab exposes an event queue with exponential backoff retries and cryptographic authenticity signatures.

### Webhook Event Types
- `finding.created`: Emitted when an engine identifies a new vulnerability.
- `finding.triaged`: Emitted when an analyst transitions a finding status (e.g. false positive, risk accepted).
- `release.evaluated`: Emitted when a release gate policy evaluation seals a decision (`passed`, `warning`, `failed`).
- `test_run.completed`: Emitted upon execution run completion.

### Validating Payload Signatures
Every webhook delivery includes an `X-SecurityLab-Signature` header:
`sha256=<hex_digest>`

Verify the HMAC-SHA256 signature using your webhook secret:

```javascript
import crypto from 'node:crypto';

function verifySignature(payloadRaw, signatureHeader, secret) {
  const expected = 'sha256=' + crypto
    .createHmac('sha256', secret)
    .update(payloadRaw, 'utf8')
    .digest('hex');
  return crypto.timingSafeEqual(Buffer.from(signatureHeader), Buffer.from(expected));
}
```

### Exponential Backoff Retry Schedule
If your receiving server returns an HTTP `5xx` error, `429 Too Many Requests`, or connection timeout, deliveries are rescheduled according to:
$$t_{\text{retry}} = \text{now} + 2^{\text{attempt}} \times 10\text{ seconds}$$
- Attempt 1: 20 seconds
- Attempt 2: 40 seconds
- Attempt 3: 80 seconds
- Attempt 4: 160 seconds
- Attempt 5: 320 seconds
- Beyond 5 attempts: Transitioned to `dead_letter` queue.

---

## 3. Two-Way Issue Tracker Synchronization

### GitHub Issues Sync
- When a vulnerability is recorded, the controller invokes `GitHubSyncService.syncFindingToIssue()` to create or update an issue labeled `security` and tagged with the finding fingerprint.
- When an engineer closes the GitHub issue, an incoming webhook to `POST /api/v1/integrations/github/webhook` triggers an automated, isolated targeted retest engine to verify the fix in under 5 seconds.

### Jira Cloud Sync
- Finding tickets are automatically logged into Jira projects as `Bug` with corresponding severity priorities (`Highest` for Critical, `High` for High, etc.).
- When the Jira ticket status transitions to `Done` or `Resolved`, an incoming webhook to `POST /api/v1/integrations/jira/webhook` triggers the single-finding retesting engine.

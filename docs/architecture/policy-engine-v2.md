# Policy Engine v2 & Release Governance Specification

## 1. Overview
The **Security Lab Policy Engine (v2)** provides deterministic, declarative policy-as-code governance for continuous integration and continuous delivery (CI/CD) pipelines. It transforms raw vulnerability findings, load test metrics, and test execution metadata into an authoritative, cryptographically sealed release decision (`passed`, `warning`, or `failed`).

---

## 2. Policy Specification Syntax

Policies are expressed declaratively and evaluated in-memory without external network dependencies:

```yaml
id: "00000000-0000-0000-0000-000000000001"
name: "Enterprise Production Gate Policy"
description: "Strict baseline enforcing zero critical vulnerabilities, mandatory profiles, endpoint SLAs, and active waiver tracking"

# 1. Mandatory Test Profiles
# All listed profiles or engine IDs MUST be executed in the TestRun.
# If omitted, release is blocked immediately.
requiredProfiles:
  - "engine-native-tls"
  - "engine-native-headers"
  - "engine-native-authorization"

# 2. Finding Waivers (Exemptions)
# Allows temporary release passage for accepted risks with mandatory expiration dates.
waivers:
  - fingerprint: "7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e"
    reason: "Legacy cipher suite accepted during staging proxy migration window"
    approvedBy: "ciso-office@enterprise.internal"
    expiresAt: "2026-11-01T00:00:00.000Z"

# 3. Governance Rules
rules:
  # Rule: Maximum allowed severity
  - id: "rule-zero-critical"
    name: "Zero Critical Vulnerabilities"
    description: "Releases are blocked if any active critical findings are detected"
    condition:
      maxAllowedSeverity: "high" # Permits up to high, blocks critical
    action: "block_release"

  # Rule: Severity counts
  - id: "rule-high-severity-threshold"
    name: "Maximum High Severity Threshold"
    description: "No more than 2 high-severity findings permitted"
    condition:
      maxCountBySeverity:
        high: 2
    action: "warn"

  # Rule: Disallowed categories
  - id: "rule-disallow-injection"
    name: "Zero Injection Tolerances"
    condition:
      disallowCategories:
        - "injection"
        - "sqli"
        - "command_injection"
    action: "block_release"

  # Rule: Global latency SLA
  - id: "rule-p95-latency-sla"
    name: "Global Response Latency SLA"
    condition:
      maxP95LatencyMs: 500
      maxErrorRatePercent: 1.0
    action: "block_release"

  # Rule: Per-Endpoint SLAs
  - id: "rule-endpoint-slas"
    name: "High-Priority Endpoint Latency SLAs"
    condition:
      endpointSlas:
        - path: "/api/v1/auth"
          maxP95LatencyMs: 150
          maxErrorRatePercent: 0.1
        - path: "/api/v1/checkout"
          maxP95LatencyMs: 250
          maxErrorRatePercent: 0.5
    action: "block_release"
```

---

## 3. Waiver Lifecycle & Expiration Enforcement

Temporary security exceptions frequently become permanent security debt. Policy Engine v2 strictly enforces temporal boundaries on all finding waivers:

1. **Waiver Matching**:
   Each finding's unique SHA-256 fingerprint is checked against `policy.waivers`:
   - If a matching waiver exists and `now <= waiver.expiresAt`:
     - Finding is classified as **Waived**.
     - Finding is removed from active evaluation (does not trigger severity/count/category blocks).
     - Telemetry is recorded in `gateResult.waivedFindings`.
2. **Expired Waiver Enforcement**:
   - If a matching waiver exists but `now > waiver.expiresAt`:
     - The waiver is immediately **Rejected**.
     - An explicit blocking violation (`ruleId: 'waiver-expired'`) is emitted:
       > `"Finding waiver for fingerprint ... approved by ... expired on ... Temporary security exemption has lapsed."`
     - The finding is re-introduced to active evaluation and assessed against all baseline rules.
     - Telemetry is recorded in `gateResult.expiredWaivers`.

---

## 4. Cryptographic Release Sealing

To satisfy **Rule 15** (immutable audit trails), each evaluated release is cryptographically sealed with a SHA-256 digest:

$$\text{evaluatorHash} = \text{SHA-256}\Big(\text{policyId} : \text{testRunId} : \text{decision} : \text{timestamp.toISOString()}\Big)$$

The `evaluatorHash` is permanently recorded in the PostgreSQL `releases` table alongside:
- `git_commit`: Associated VCS commit SHA.
- `git_branch`: Branch being gated.
- `metadata`: Complete snapshot of evaluated rules, active waivers, expired waivers, and posture scores.

---

## 5. CLI & CI/CD Pipeline Integration

### CLI Command
```bash
security-lab gate evaluate --run <testRunId> [--policy <policyId>] [--fail-on failed|warning] [--json]
```

### GitHub Actions Integration
When `$GITHUB_STEP_SUMMARY` is present in the execution environment, `security-lab gate evaluate` automatically generates an executive summary markdown table detailing:
- Gate Decision (`PASSED`, `WARNING`, `BLOCKED`)
- Posture Score & Letter Grade
- Evaluated Rule Count
- Violations Table with actions and evidence references
- Approved Active Finding Waivers
- Cryptographic Seal Hash

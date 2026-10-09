# Profile: Production Release Gate (`release-gate`)

## Overview
Automated CI/CD deployment gating profile combining passive security audits, critical policy evaluation, and SLA thresholds.

### Engines & Test Categories
* `quick-security`: Zero critical/high misconfigurations allowed.
* `security-contracts`: Enforces required headers and TLS minimums.
* `policy-engine`: Blocks release if any open critical or unaccepted high findings exist.

### Safety Constraints
* Deterministic, reproducible machine-readable verdicts.
* Non-disruptive: Can be safely run against pre-release staging or canary environments.

### Status:
* **Status**: `VERIFIED`
* **Current Behavior**: Fully active profile supported in the controller and CLI (`security-lab gate evaluate`). Enforces policy rules, evaluates critical/high finding counts, checks SLA thresholds, and issues release decisions.


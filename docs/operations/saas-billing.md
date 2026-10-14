# Multi-Tenant SaaS Metered Billing & Quota Management

## 1. Overview
The platform includes an automated usage-based metering and subscription governance system integrated with Stripe. It enables hosted commercial deployments while preserving complete local-first, zero-external-dependency execution for self-hosted community installations.

---

## 2. Subscription Tiers & Quota Limits

| Tier | Monthly Execution Minutes | Active Targets | Max Concurrent Runs | Support Level |
|---|---|---|---|---|
| **Free** | 100 minutes | 2 targets | 1 concurrent run | Community |
| **Starter** | 1,000 minutes | 10 targets | 3 concurrent runs | Standard Business |
| **Enterprise** | 10,000 minutes | 100 targets | 10 concurrent runs | 24/7 Dedicated SLA |

---

## 3. Stripe Webhook Integration

### 3.1 Webhook Endpoint
The controller handles inbound Stripe webhooks at:
```http
POST /api/v1/billing/webhook
Stripe-Signature: t=<timestamp>,v1=<hmac_sha256>
Content-Type: application/json
```

### 3.2 Supported Stripe Events
1. `customer.subscription.created` & `customer.subscription.updated`:
   - Extracts customer ID and tier (`starter` or `enterprise`).
   - Updates workspace `subscription_tier` and assigns new `quota_limits`.
2. `customer.subscription.deleted`:
   - Downgrades workspace to `free` tier and restores default free quotas.
3. `invoice.payment_succeeded`:
   - Resets monthly `usage_minutes = 0` for the new billing cycle.

### 3.3 Cryptographic Signature Verification
All webhook payloads are verified using HMAC-SHA256 against `STRIPE_WEBHOOK_SECRET` with a 300-second timestamp tolerance to defend against replay attacks.

---

## 4. Quota Guard & 402 Payment Required

When a user initiates or queues a test run (`POST /api/v1/test-runs`), the platform checks workspace quota before execution:
- If `usage_minutes >= quota_limits.maxExecutionMinutesPerMonth`, the request is rejected with `402 Payment Required`:

```json
{
  "success": false,
  "error": {
    "code": "QUOTA_EXCEEDED",
    "message": "Monthly execution quota exceeded for \"starter\" tier (1005/1000 minutes used). Please upgrade your subscription tier to continue.",
    "details": {
      "tier": "starter",
      "usageMinutes": 1005,
      "maxMinutes": 1000
    }
  }
}
```

---

## 5. Runtime Usage Metering & Observability

### 5.1 Automatic Execution Tracking
Upon completion of every test run (whether `completed`, `failed`, or `cancelled`), the duration is calculated:
$$\text{durationSeconds} = t_{\text{completed}} - t_{\text{started}}$$
$$\Delta \text{minutes} = \max\left(1, \lceil \text{durationSeconds} / 60 \rceil\right)$$

The duration is atomically incremented on `workspaces.usage_minutes`.

### 5.2 Prometheus Telemetry
The controller exports tenant runtime usage:
```prometheus
# HELP security_lab_tenant_usage_seconds_total Total execution runtime consumed by workspace in seconds
# TYPE security_lab_tenant_usage_seconds_total counter
security_lab_tenant_usage_seconds_total{workspace_id="a1b2c3d4-..."} 12480
```

---

## 6. Self-Hosted & Local-First Backward Compatibility
If `STRIPE_SECRET_KEY` and `STRIPE_WEBHOOK_SECRET` are not set in the environment:
- Billing quotas are automatically bypassed.
- CLI scans and central controller test runs execute without subscription restrictions.

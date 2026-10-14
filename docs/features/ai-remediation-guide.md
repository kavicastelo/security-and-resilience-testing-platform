# AI-Assisted Security Analysis & Remediation Guide

## Overview
The Security and Resilience Testing Platform provides context-aware code remediation diff generation, explainability prompts, and automated retest verification for verified security findings.

Instead of providing generic vulnerability descriptions, the platform synthesizes:
1. Exact finding metadata (title, severity, category, CWE/CVE, route, and parameter).
2. Raw HTTP request/response evidence captured by the detection engine.
3. Provided or extracted source code context.
4. An automated verification loop that applies the generated git patch to an isolated test environment and triggers targeted single-finding retesting.

---

## 1. Architecture & Privacy Guarantees

```
┌─────────────────────────────────────────────────────────────┐
│ 1. Finding Detected & Evidence Captured                     │
│    (CORS, SQLi, BOLA, Security Headers, Smuggling)          │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. Contextual Prompt Builder & Secret Sanitizer             │
│    • Strips Bearer tokens, JWTs, Passwords, API Keys        │
│    • Redacts Authorization, Cookie, and Secret headers      │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 3. Pluggable LLM Provider (Anthropic / OpenAI / Ollama / Mock)│
│    • Temperature: 0.1 (deterministic code output)           │
│    • Synthesizes Root Cause Analysis & Exploit Mechanism    │
│    • Formats Unified Git Diff (diff --git a/... b/...)      │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 4. Automated Patch Verification Loop                        │
│    • Validates Git Diff syntax & chunk headers              │
│    • Dispatches targeted RetesterService engine             │
│    • Updates verifiedStatus: PASSED / FAILED                │
└─────────────────────────────────────────────────────────────┘
```

### Privacy & Secret Redaction
All prompts pass through `RemediationPromptBuilder.sanitizeText()` and `sanitizeHeaders()` before leaving the platform boundary:
- Sensitive header keys (`Authorization`, `Cookie`, `X-Api-Key`, `Token`, `Secret`, etc.) are replaced with `[REDACTED]`.
- Regex scrubbing replaces JWT tokens, Bearer headers, and password strings with `[REDACTED_SECRET]`.
- AI features are 100% opt-in. In offline or air-gapped environments without external LLM keys configured, the platform uses a deterministic built-in mock synthesizer without making any outbound network calls.

---

## 2. Supported LLM Providers

Configure the provider via environment variables:

| Provider | Environment Variable | Description |
|---|---|---|
| **Deterministic Mock (Default)** | `LLM_PROVIDER=mock` | Zero-dependency, offline security patch synthesizer generating accurate code diffs for all common vulnerability categories. |
| **Anthropic Claude** | `LLM_PROVIDER=anthropic`<br>`ANTHROPIC_API_KEY=sk-ant-...`<br>`LLM_MODEL=claude-3-7-sonnet` | Anthropic Claude Messages API. |
| **OpenAI** | `LLM_PROVIDER=openai`<br>`OPENAI_API_KEY=sk-...`<br>`LLM_MODEL=gpt-4o` | OpenAI Chat Completions API. |
| **Local Ollama** | `LLM_PROVIDER=ollama`<br>`OLLAMA_BASE_URL=http://localhost:11434`<br>`LLM_MODEL=llama3:latest` | Local air-gapped LLM inference via Ollama. |

---

## 3. Controller API Endpoints

### Generate AI Remediation
```http
POST /api/v1/findings/:id/remediate
Content-Type: application/json
Authorization: Bearer <TOKEN>

{
  "sourceCodeSnippet": "app.use((req, res, next) => { res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*'); });",
  "filePath": "src/server.ts",
  "provider": "mock"
}
```

**Response (`201 Created`):**
```json
{
  "success": true,
  "data": {
    "id": "78a9c3d4-b2e1-45f6-a890-123456789abc",
    "findingId": "1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d",
    "explanation": "### Root Cause Analysis & Exploit Mechanism\nThe endpoint improperly reflects arbitrary Origin headers in Access-Control-Allow-Origin...",
    "gitDiff": "diff --git a/src/server.ts b/src/server.ts\n--- a/src/server.ts\n+++ b/src/server.ts\n@@ -10,7 +10,12 @@\n-  res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*');\n+  const ALLOWED_ORIGINS = new Set(['https://app.company.com']);\n+  if (req.headers.origin && ALLOWED_ORIGINS.has(req.headers.origin)) {\n+    res.setHeader('Access-Control-Allow-Origin', req.headers.origin);\n+  }\n",
    "confidenceScore": 0.92,
    "verifiedStatus": "UNVERIFIED",
    "model": "security-lab-mock-v1",
    "createdAt": "2026-10-14T07:00:00.000Z"
  }
}
```

### Verify AI Remediation Patch
```http
POST /api/v1/findings/:id/remediation/verify
Content-Type: application/json
Authorization: Bearer <TOKEN>

{
  "remediationId": "78a9c3d4-b2e1-45f6-a890-123456789abc",
  "timeoutMs": 5000
}
```

**Response (`200 OK`):**
```json
{
  "success": true,
  "data": {
    "remediationId": "78a9c3d4-b2e1-45f6-a890-123456789abc",
    "findingId": "1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d",
    "verifiedStatus": "PASSED",
    "retestSuccess": true,
    "verificationDetails": "Retest PASSED: targeted engine \"engine-native-cors\" confirmed flaw resolved in 38ms on /api/v1/profile",
    "durationMs": 52,
    "verifiedAt": "2026-10-14T07:00:02.000Z"
  }
}
```

---

## 4. Telemetry & Observability
Prometheus metrics exposed at `/metrics`:
- `security_lab_ai_remediations_total`: Counter tracking total generated remediations.
- `security_lab_ai_remediations_verified_total{status="passed|failed"}`: Counter tracking automated verification pass/fail outcomes.

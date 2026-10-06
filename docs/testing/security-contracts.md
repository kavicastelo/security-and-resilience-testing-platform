# OpenAPI Security Contract Engine & Negative Schema Fuzzing

## Overview

The `SecurityContractEngine` (`engine-native-contract`) is a Class A native testing engine within Security Lab. It ingests OpenAPI 3.0.x and 3.1.x specifications (in YAML or JSON format), performs static security contract audits, generates deterministic negative test suites, and executes schema fuzzing against target API services to verify robust error handling.

---

## Architectural Principles

1. **Deterministic Negative Fuzzing**: Rather than unbounded random generation, test cases systematically mutate declared request body schemas (omitting required fields, sending conflicting data types, providing empty payloads, or injecting oversized strings).
2. **Crash & Unhandled Exception Detection**: APIs should cleanly reject malformed input with HTTP `400 Bad Request` or `422 Unprocessable Entity`. Unhandled crashes returning HTTP `500 Internal Server Error` are flagged as **High** severity vulnerabilities.
3. **Strict Scope Validation**: Every network probe passes through `safeFetch` and is strictly clamped to the registered `TargetScope` (obeying concurrency, RPS, and network boundaries).

---

## Static Security Contract Rules

The engine audits specifications against four core rules:

| Rule ID | Severity | Description |
| :--- | :--- | :--- |
| `no-unprotected-endpoints` | **Critical** (Mutating) / **Medium** (Read) | Flags mutating operations (`POST`, `PUT`, `DELETE`, `PATCH`) that lack authentication definitions, allowing anonymous state changes. Explicitly public routes (`security: []`) or authentication entrypoints (`/login`, `/signup`) are excluded. |
| `no-sensitive-query-params` | **High** | Flags sensitive tokens, secrets, passwords, or API keys defined in query parameters. Query parameters leak into access logs, browser history, and HTTP `Referer` headers. |
| `require-https-servers` | **High** | Flags declared server URLs that specify cleartext HTTP (`http://`) for non-local addresses. |
| `no-cleartext-basic-auth` | **Medium** | Flags HTTP Basic authentication schemes (`type: http`, `scheme: basic`) that transmit credentials via static Base64 encoding. |

---

## Negative Schema Fuzzing Mutations

When active schema fuzzing is enabled against a live target service, the engine performs deterministic mutations for every endpoint declaring a JSON `requestBody`:

1. **Missing Required Fields**:
   Constructs a baseline valid-like payload, then sequentially omits each field listed in `schema.required`.
   *Expected Response*: HTTP 400 or 422.
   *Failure Condition*: HTTP 500 (Unhandled Server Error) or HTTP 2xx (Schema Bypass).

2. **Invalid Data Types**:
   Replaces fields with incompatible data types (e.g., numeric integers for strings, alphabetic strings for numeric types, strings for booleans).
   *Expected Response*: HTTP 400 or 422.
   *Failure Condition*: HTTP 500.

3. **Empty Payloads on Required Schemas**:
   Dispatches `{}` to endpoints marked `required: true` or possessing mandatory fields.
   *Expected Response*: HTTP 400 or 422.

4. **Oversized String Inputs**:
   Injects a 10,000-character string payload to test buffer limits, memory handling, and deserialization performance.
   *Expected Response*: HTTP 400, 413, or 422.
   *Failure Condition*: HTTP 500.

---

## CLI Usage

### Command Syntax

```bash
security-lab contract verify --spec <pathOrUrl> [--target <targetUrl>] [options]
```

### Options

| Flag | Description | Default |
| :--- | :--- | :--- |
| `-s, --spec <pathOrUrl>` | Path to local OpenAPI YAML/JSON document or remote URL | **Required** |
| `-t, --target <targetUrl>` | Target base URL for live schema fuzzing | Optional |
| `--no-fuzz` | Disable active schema fuzzing (perform static contract audit only) | `false` |
| `--fail-on <severity>` | Failure exit code threshold (`critical`, `high`, `medium`, `low`) | `high` |

### Examples

#### 1. Static Contract Audit of OpenAPI Specification
```bash
security-lab contract verify --spec ./specs/openapi.yaml
```

#### 2. Live Contract Verification and Schema Fuzzing against Staging
```bash
security-lab contract verify \
  --spec ./specs/openapi.yaml \
  --target https://api.staging.example.com \
  --fail-on high
```

---

## Controller API Endpoint

### `POST /api/v1/contracts/verify`

#### Request Payload
```json
{
  "spec": "openapi: 3.0.3\n...",
  "targetUrl": "https://api.example.com",
  "options": {
    "fuzzing": true
  }
}
```

#### Response Payload
```json
{
  "success": true,
  "data": {
    "engineId": "engine-native-contract",
    "durationMs": 420,
    "success": true,
    "findings": [
      {
        "title": "Sensitive Parameter in Query String: [api_key]",
        "severity": "high",
        "category": "compliance",
        "description": "Endpoint GET /api/v1/data declares sensitive parameter in query string.",
        "recommendation": "Transmit credentials via HTTP Authorization header."
      }
    ],
    "metrics": [
      { "name": "openapi_endpoints_count", "value": 14, "unit": "endpoints" },
      { "name": "contract_violations_count", "value": 1, "unit": "violations" },
      { "name": "fuzz_tests_executed", "value": 28, "unit": "tests" },
      { "name": "fuzz_server_errors", "value": 0, "unit": "findings" }
    ]
  }
}
```

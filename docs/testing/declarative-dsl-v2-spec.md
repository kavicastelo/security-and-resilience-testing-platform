# Declarative Test DSL v2 — Specification & Architecture Guide

## 1. Overview

The **Security Lab Declarative Test DSL v2** is an expressive, declarative test definition format designed for API security auditing, protocol validation, and multi-step stateful security workflows.

DSL v2 expands beyond isolated single-request checks by adding:
1. **Request Payloads**: Support for JSON objects, URL-encoded forms, and raw text.
2. **Variable Extraction & Chaining**: Extraction of response fields (tokens, IDs, cookies) into a workflow context for dynamic use in subsequent test steps.
3. **Path & Query Templating**: Dynamic substitution of path parameters (`/items/{itemId}`) and query string parameters.
4. **Session Cookie Management**: Automatic cookie jar persistence across chained steps within a test run.
5. **Execution Dependencies**: Explicit predecessor requirements (`dependsOn`) enabling conditional workflow execution.
6. **Advanced Assertion Operators**: Deep JSON path inspection (`contains_json_path`), absence checks (`not_contains_json_path`), and type/schema assertions (`schema_matches`).

---

## 2. Schema Specification

### 2.1 Test Definition Root

| Field | Type | Required | Description |
| :--- | :--- | :---: | :--- |
| `id` | `string` | Yes | Unique test definition identifier (e.g. `test-def-auth-001`). |
| `name` | `string` | Yes | Human-readable title of the test suite. |
| `version` | `string` | Yes | SemVer version string (e.g. `2.0.0`). |
| `category` | `TestCategory` | Yes | Security category (e.g. `authentication`, `authorization`, `api_schema`). |
| `description` | `string` | No | Architectural purpose or threat model context. |
| `target` | `object` | Yes | Target constraints and `requiredCapabilities`. |
| `inputs` | `Record<string, any>` | No | Initial static variables seeded into the workflow context. |
| `authentication` | `object` | No | Default authentication scheme (`none`, `bearer`, `api_key`). |
| `tests` | `SingleTestSpec[]` | Yes | Sequential list of test steps to execute. |
| `thresholds` | `object` | No | Finding thresholds and SLA requirements for gating. |

---

### 2.2 Test Step Specification (`SingleTestSpec`)

```yaml
- id: step-create-user
  name: Create Test Account
  description: Registers a user via POST and extracts the assigned account ID
  path: /api/v1/users
  method: POST
  headers:
    Content-Type: application/json
  body:
    username: "audit-user"
    email: "audit-user@example.com"
  expectedStatus: [201]
  extract:
    - field: body.id
      as: newUserId
    - field: headers.set-cookie
      as: sessionCookie
      regex: "session_id=([^;]+)"
  assertions:
    - field: body.id
      operator: exists
      severity: critical
    - field: body.status
      operator: equals
      value: active
      severity: medium
```

#### Fields Description:

- **`path`** (`string`): Target endpoint route. Supports path templates (`/users/{userId}`) and variables (`/users/${userId}`).
- **`method`** (`string`): HTTP verb (`GET`, `POST`, `PUT`, `DELETE`, `PATCH`, `HEAD`, `OPTIONS`). Default: `GET`.
- **`headers`** (`Record<string, string>`): Request headers. Values support variable interpolation (`Authorization: Bearer ${authToken}`).
- **`body`** (`any`): Request payload. Can be a JSON object, array, or string. Object keys and values are recursively interpolated.
- **`contentType`** (`string`): Explicit Content-Type (e.g. `application/json`, `application/x-www-form-urlencoded`). Automatically inferred if omitted.
- **`params`** (`Record<string, any>`): Query string parameters appended to the URL. Values support variable interpolation.
- **`pathParams`** (`Record<string, any>`): Key-value pairs replacing `{param}` or `:param` in `path`.
- **`extract`** (`ExtractionRule[]`): Response variables to extract into the workflow context:
  - `field`: Dot-notation path to extract (e.g. `body.token`, `body.data.items[0].id`, `headers.set-cookie`).
  - `as`: Variable name to store (e.g. `authToken`).
  - `regex` (optional): Regular expression applied to the extracted string (extracts capture group 1 if present).
  - `defaultValue` (optional): Fallback value if field is missing.
- **`dependsOn`** (`string | string[]`): Test IDs that must pass before this step runs. If any dependency fails, this step is skipped.
- **`expectedStatus`** (`number[] | number`): Expected HTTP status code(s). Can be single or array.
- **`assertions`** (`Assertion[]`): Evaluation criteria tested against the response.

---

## 3. Assertion Operators

| Operator | Evaluates | Example |
| :--- | :--- | :--- |
| `equals` | Case-insensitive string equality | `field: status`, `value: 200` |
| `not_equals` | Value inequality | `field: body.role`, `value: guest` |
| `contains` | Substring inclusion (or array member) | `field: headers.content-type`, `value: application/json` |
| `not_contains` | Substring exclusion (or array absence) | `field: body.error`, `value: unauthorized` |
| `exists` | Field is defined, non-null, and non-empty | `field: headers.strict-transport-security` |
| `does_not_exist`| Field is missing, null, or undefined | `field: body.stackTrace` |
| `matches_regex` | Regex pattern matching | `field: body.token`, `value: "^eyJ[A-Za-z0-9-_]+"` |
| `contains_json_path` | Presence of nested path inside body | `field: body`, `value: "data.profile.email"` |
| `not_contains_json_path`| Absence of nested path inside body | `field: body`, `value: "internal_debug_info"` |
| `schema_matches`| Type verification (`string`, `number`, `boolean`, `array`, `object`) | `field: body.userId`, `value: "string"` |

---

## 4. Multi-Step Execution & State Machine

```mermaid
flowchart TD
    Init[Initialize Workflow Context & Cookie Jar] --> Step1[Step 1: POST /auth/login]
    Step1 --> Extract[Extract authToken & set-cookie]
    Extract --> CookieJar[(Cookie Jar: session_id)]
    Extract --> Context[(Workflow Context: authToken)]
    Context --> CheckDep{dependsOn Check}
    CookieJar --> CheckDep
    CheckDep -->|Dependencies Passed| Step2[Step 2: GET /api/profile with Bearer ${authToken}]
    Step2 --> Assertions[Evaluate Assertions & SLA]
    Assertions --> Output[Generate Platform Findings & Metrics]
```

---

## 5. Security & Isolation Constraints

1. **Strict Target Scope Re-Validation**:
   All dynamically interpolated URLs are re-checked against `TargetScope.allowedHosts` and `TargetScope.allowedPorts` before dispatching. Even if an attacker attempts an SSRF escape through variable interpolation (`${untrustedDomain}`), the request is blocked.
2. **Prototype Pollution Defense**:
   Variable lookup and object interpolation explicitly forbid sensitive keys (`__proto__`, `constructor`, `prototype`).
3. **Backward Compatibility**:
   DSL v1 test specifications without bodies, extractions, or pathParams continue to validate and execute with identical semantics.

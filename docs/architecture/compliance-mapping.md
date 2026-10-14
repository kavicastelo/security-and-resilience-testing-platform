# Enterprise Compliance Mapping & PDF Reporting Architecture

## 1. Overview
The Security & Resilience Testing Platform features an automated enterprise compliance reporting subsystem located in `@security-lab/reporter`. While technical security engineers and CI/CD systems ingest SARIF 2.1.0 and JUnit XML, compliance auditors, Chief Information Security Officers (CISOs), and external pen-test reviewers require human-readable, executive-ready documentation mapped to recognized regulatory standards.

The compliance engine maps platform findings to three industry frameworks:
1. **OWASP Top 10:2021** (Web Application Security Risks)
2. **OWASP ASVS 4.0** (Application Security Verification Standard)
3. **PCI-DSS 4.0 Section 6** (Develop and Maintain Secure Systems and Software)

---

## 2. Compliance Mapping Matrix

### 2.1 OWASP Top 10:2021
Every test rule ID, category, or title is systematically evaluated and categorized into one of the 10 canonical risk classes:

| OWASP ID | Category Name | Typical Rule / Defect Match | Associated CWEs |
|---|---|---|---|
| `A01:2021` | Broken Access Control | `BOLA`, `IDOR`, `CORS`, `step-skipping`, `privilege` | CWE-200, CWE-284, CWE-639 |
| `A02:2021` | Cryptographic Failures | `weak-cipher`, `tls`, `ssl`, `cleartext`, `certificate` | CWE-326, CWE-327, CWE-319 |
| `A03:2021` | Injection | `sqli`, `nosql`, `command-injection`, `ldap`, `template` | CWE-89, CWE-77, CWE-78 |
| `A04:2021` | Insecure Design | `rate-limit`, `anti-automation`, `business-logic` | CWE-209, CWE-256, CWE-501 |
| `A05:2021` | Security Misconfiguration | `headers`, `csp`, `x-frame-options`, `cors-wildcard` | CWE-16, CWE-1004, CWE-693 |
| `A06:2021` | Vulnerable and Outdated Components | `sbom`, `cve`, `outdated-lib`, `supply-chain` | CWE-1104, CWE-1395 |
| `A07:2021` | Identification and Authentication Failures | `auth`, `password`, `brute-force`, `session-fixation` | CWE-287, CWE-384, CWE-798 |
| `A08:2021` | Software and Data Integrity Failures | `smuggling`, `cl-te`, `deserialization`, `integrity` | CWE-444, CWE-502, CWE-829 |
| `A09:2021` | Security Logging and Monitoring Failures | `log-injection`, `audit-leak`, `tampering` | CWE-117, CWE-223, CWE-778 |
| `A10:2021` | Server-Side Request Forgery (SSRF) | `ssrf`, `url-redirection`, `cloud-metadata` | CWE-918 |

### 2.2 OWASP ASVS 4.0
The platform associates findings with specific ASVS Level 1, 2, and 3 verification requirements:
- **V2 (Authentication)**: V2.1.1 Password strength, multi-factor authentication, and brute-force prevention.
- **V3 (Session Management)**: V3.2.1 Token entropy, cookie attributes (`Secure`, `HttpOnly`, `SameSite`), and expiration.
- **V4 (Access Control)**: V4.1.1 Principle of least privilege, BOLA/BFLA authorization gates, and direct object references.
- **V5 (Validation, Sanitization and Encoding)**: V5.1.1 Context-aware output encoding, SQL parameterization, and command escaping.
- **V8 (Data Protection)**: V8.1.1 Encryption of sensitive parameters at rest and in transit.
- **V9 (Communications)**: V9.1.1 Strict TLS 1.2/1.3 configurations, HSTS enforcement, and secure cipher suites.
- **V10 (Malicious Code & Supply Chain)**: V10.2.1 Third-party dependencies, open-source vulnerability CVE tracking.
- **V13 (API and Web Service)**: V13.1.1 Schema enforcement, rate limiting, and business-logic verification.
- **V14 (Configuration)**: V14.4.1 Defensive HTTP headers (`CSP`, `X-Content-Type-Options`, `X-Frame-Options`).

### 2.3 PCI-DSS 4.0 Requirement 6
Targeted verification against PCI-DSS software security directives:
- **6.2.4**: Software Development & Vulnerability Prevention (general input and error handling controls).
- **6.3.1**: Software Vulnerability Identification & Patching (SBOM components and CVE management).
- **6.4.1**: Public-Facing Web Applications Defense (dynamic security testing and active shielding).
- **6.4.3**: Client-Side Script & Header Integrity (defensive header enforcement and clickjacking defense).
- **6.5.1**: Injection Flaws Prevention (SQL injection, LDAP, command execution).
- **6.5.7**: Cross-Site Scripting (XSS) Prevention (context-aware escaping and strict CSP).
- **6.5.8**: Improper Access Control (BOLA, IDOR, privilege escalation).
- **6.5.10**: Authentication & Session Integrity (credential security and payment route authentication).

---

## 3. Standalone Interactive HTML Reports

### 3.1 Self-Contained Design Directive
The HTML generator (`packages/reporter/src/html.ts`) produces single-file, 100% self-contained bundles:
- **Zero External Dependencies**: No remote Google Fonts, Tailwind CDN, FontAwesome, or script includes.
- **Embedded CSS Design System**: Features modern glassmorphism, responsive grid layout, typography styles, and dark/light mode switching via CSS variables.
- **Embedded Inline SVG**: Dynamic donut charts representing severity distribution rendered using pure mathematical SVG stroke calculations (`stroke-dasharray` and `stroke-dashoffset`).
- **Client-Side Vanilla JS**: Instant interactive filtering by severity level (Critical, High, Medium, Low) and text search without reloading or network calls.

### 3.2 Security & Stored XSS Mitigation
Because vulnerability titles, payloads, and raw responses can contain malicious input, all dynamic fields undergo strict HTML character escaping before insertion into templates:
```typescript
function escapeHtml(unsafe: string): string {
  return unsafe
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
```

---

## 4. Headless Executive PDF Generation

### 4.1 Vector PDF 1.4 Engine
Rather than requiring heavy, platform-specific headless Chrome/Puppeteer processes (which frequently fail in air-gapped or memory-constrained CI/CD runners), `@security-lab/reporter` implements a zero-dependency, pure-TypeScript PDF 1.4 generator (`PdfDocumentBuilder`):
- Produces valid PDF 1.4 binary streams with header (`%PDF-1.4`), cross-reference table (`xref`), and trailer (`%%EOF`).
- Embeds standard Helvetica (`/F1`), Helvetica-Bold (`/F2`), and Courier (`/F3`) Type 1 font dictionaries.
- Renders vector graphics (headers, cards, severity tags, progress bars) using native PDF content stream operators (`re`, `rg`, `f`, `s`, `BT`, `Tf`, `Td`, `Tj`, `ET`).
- Provides automated text wrapping (`drawWrappedText`) to prevent text overflowing margins.

### 4.2 Report Structure
1. **Page 1: Executive Cover Page & Scorecard**:
   - Branded header banner (`SECURITY LAB & COMPLIANCE ASSESSMENT`).
   - Audit target URL, execution timestamp, and test run identifier.
   - Overall Security Posture Score (0-100), letter grade (A-F), and risk level.
   - CI/CD Release Gate Decision badge (PASSED, WARNING, FAILED).
   - Severity breakdown table with SLA deadlines and release impact.
   - Regulatory compliance scorecard with progress bars for OWASP, ASVS, and PCI-DSS.
2. **Page 2: Detailed Vulnerability Findings Dossier**:
   - Header with finding counts and categorization.
   - Per-finding card with severity badge, finding status, and full compliance mapping line:
     `OWASP: A03:2021 (Injection) | ASVS: V5.1.1 | PCI: 6.5.1 | CWE-89`
   - Detailed vulnerability description.
   - Remediation guidance box with actionable engineering steps.

---

## 5. Integration Endpoints & CLI Usage

### 5.1 Controller REST API
- `GET /api/v1/test-runs/:id/report?format=pdf`:
  - Returns `Content-Type: application/pdf` binary stream.
  - Header: `Content-Disposition: inline; filename="security-report-<id>.pdf"`.
- `GET /api/v1/test-runs/:id/reports/:reportId/download`:
  - Returns stored PDF or HTML artifact.

### 5.2 Command-Line Interface (CLI)
Export compliance reports directly from the terminal:
```bash
# Export Executive PDF report
security-lab report --run <testRunId> --format pdf --output ./reports/executive-report.pdf

# Export both standalone HTML and PDF
security-lab report --run <testRunId> --format html,pdf --output ./reports/security-report
```

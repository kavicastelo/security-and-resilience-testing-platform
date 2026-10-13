# Software Supply Chain SBOM Lifecycle & Advisory Feeds (`@security-lab/sbom-supply-chain`)

## 1. Overview
The **Software Supply Chain SBOM Lifecycle Engine** provides native parsing and continuous security evaluation for CycloneDX and SPDX Software Bill of Materials (SBOMs), npm lockfiles, and direct dependency declarations without requiring external container dependencies (e.g. Docker or Trivy binaries).

Regulatory mandates (such as US Executive Order 14028, NIST SP 800-218 SSDF, and the EU Cyber Resilience Act) require continuous software supply chain visibility. This engine ingests standardized SBOMs, correlates package inventories against Open Source Vulnerability (OSV) feeds, and enforces enterprise Open Source Software (OSS) license compliance policies.

---

## 2. Capabilities

| Capability ID | Name | Category | Description |
|---|---|---|---|
| `sbom_ingestion` | CycloneDX & SPDX SBOM Document Parsing | `passive_analysis` | Statically parses and extracts component inventories from standard CycloneDX 1.4/1.5 JSON, SPDX 2.2/2.3 JSON, and npm package-lock.json files. |
| `osv_vulnerability_mapping` | Open Source Vulnerability (OSV) Advisory Matching | `passive_analysis` | Correlates component versions against OSV feeds (including GHSA and CVE databases) to detect vulnerabilities, CVSS scores, and upgrade remediations. |
| `license_compliance_audit` | Open Source Software (OSS) License Policy Audit | `compliance_check` | Evaluates component SPDX license expressions against organizational policies to identify disallowed copyleft (AGPL, GPL-3.0) and restrictive licenses. |

---

## 3. Supported SBOM Standards & Ingestion Formats

1. **CycloneDX JSON (1.3, 1.4, 1.5)**:
   - Ingests `components` array, parsing package URLs (`purl`), versions, package types, cryptographic hashes, and declared license expressions.
2. **SPDX JSON (2.2, 2.3)**:
   - Ingests `packages` array, extracting package names, `versionInfo`, `externalRefs` (purl), `licenseConcluded`, and `licenseDeclared`.
3. **Lockfiles (npm `package-lock.json` v1/v2/v3)**:
   - Directly maps package lockfile trees to standardized component inventories.
4. **Vulnerability Advisory Sources**:
   - Queries Google Open Source Vulnerabilities (OSV) API (`api.osv.dev`) with a built-in offline advisory database cache for air-gapped and local offline auditing.
5. **License Compliance Evaluation**:
   - Compares declared and concluded licenses against whitelists or blacklists (banning copyleft licenses such as `AGPL-3.0-only`, `GPL-3.0-only`, `SSPL-1.0`, `EUPL-1.2` by default).

---

## 4. Usage Example

```typescript
import { SbomSupplyChainEngine } from '@security-lab/sbom-supply-chain';

const engine = new SbomSupplyChainEngine();

const result = await engine.execute(
  {
    targetUrl: 'sbom://inventory',
    options: {
      sbomContent: JSON.stringify({
        bomFormat: 'CycloneDX',
        specVersion: '1.4',
        components: [
          {
            name: 'lodash',
            version: '4.17.20',
            purl: 'pkg:npm/lodash@4.17.20',
            licenses: [{ license: { id: 'MIT' } }],
          },
          {
            name: 'log4j-core',
            version: '2.14.1',
            purl: 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1',
            licenses: [{ license: { id: 'Apache-2.0' } }],
          },
          {
            name: 'copyleft-tool',
            version: '1.0.0',
            licenses: [{ license: { id: 'AGPL-3.0-only' } }],
          },
        ],
      }),
      enableOsvLookup: true,
      offlineMode: true,
    },
  },
  {
    executionId: 'exec-sbom-001',
    testRunId: 'run-sbom-001',
    target: {
      id: 'target-sbom',
      baseUrl: 'sbom://inventory',
      scope: {
        allowedHosts: ['localhost'],
        allowedPorts: [80],
        allowPrivateIps: true,
        excludedPaths: [],
      },
    },
  }
);

console.log(result.findings);
```

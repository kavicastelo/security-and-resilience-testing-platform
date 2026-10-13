import { describe, it, expect } from 'vitest';
import {
  SbomSupplyChainEngine,
  sbomSupplyChainEngine,
  parseCycloneDXJson,
  parseSpdxJson,
  parsePackageLockJson,
  evaluateLicenseCompliance,
  OsvClient,
} from '../src/index.js';
import { WorkerRunner } from '@security-lab/engine-sdk';

describe('Phase 14: Software Supply Chain SBOM Lifecycle & Advisory Feeds', () => {
  const dummyContext = {
    correlationId: 'test-sbom-corr-001',
    executionId: 'exec-sbom-001',
    testRunId: 'run-sbom-001',
    target: {
      id: 'target-sbom-01',
      name: 'Application SBOM Target',
      baseUrl: 'sbom://inventory',
      scope: {
        allowedHosts: ['localhost', '127.0.0.1'],
        allowedPorts: [80, 443],
        allowPrivateIps: true,
        excludedPaths: [],
      },
    },
    reportProgress: () => {},
  };

  const sampleCycloneDxJson = JSON.stringify({
    bomFormat: 'CycloneDX',
    specVersion: '1.4',
    serialNumber: 'urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79',
    version: 1,
    metadata: {
      timestamp: '2026-10-14T00:00:00Z',
      tools: [{ vendor: 'SecurityLab', name: 'sbom-generator', version: '1.0.0' }],
    },
    components: [
      {
        type: 'library',
        name: 'lodash',
        version: '4.17.20',
        purl: 'pkg:npm/lodash@4.17.20',
        description: 'Lodash modular utilities.',
        licenses: [{ license: { id: 'MIT' } }],
        hashes: [{ alg: 'SHA-256', content: 'abc123hash' }],
      },
      {
        type: 'library',
        name: 'log4j-core',
        version: '2.14.1',
        purl: 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1',
        description: 'Apache Log4j Core',
        licenses: [{ license: { id: 'Apache-2.0' } }],
      },
      {
        type: 'library',
        name: 'restricted-copyleft-pkg',
        version: '1.0.0',
        purl: 'pkg:npm/restricted-copyleft-pkg@1.0.0',
        licenses: [{ license: { id: 'AGPL-3.0-only' } }],
      },
      {
        type: 'library',
        name: 'safe-clean-dep',
        version: '2.0.0',
        purl: 'pkg:npm/safe-clean-dep@2.0.0',
        licenses: [{ license: { id: 'BSD-3-Clause' } }],
      },
    ],
  });

  const sampleSpdxJson = JSON.stringify({
    spdxVersion: 'SPDX-2.3',
    dataLicense: 'CC0-1.0',
    SPDXID: 'SPDXRef-DOCUMENT',
    name: 'Sample-SPDX-Document',
    creationInfo: {
      created: '2026-10-14T00:00:00Z',
      creators: ['Tool: SecurityLab-SPDX-1.0'],
    },
    packages: [
      {
        name: 'axios',
        SPDXID: 'SPDXRef-Package-axios',
        versionInfo: '0.21.1',
        licenseConcluded: 'MIT',
        licenseDeclared: 'MIT',
        externalRefs: [
          {
            referenceCategory: 'PACKAGE-MANAGER',
            referenceType: 'purl',
            referenceLocator: 'pkg:npm/axios@0.21.1',
          },
        ],
        checksums: [{ algorithm: 'SHA256', checksumValue: 'def456hash' }],
      },
      {
        name: 'gpl-utility',
        SPDXID: 'SPDXRef-Package-gpl',
        versionInfo: '3.1.0',
        licenseConcluded: 'GPL-3.0-only',
        licenseDeclared: 'GPL-3.0-only',
      },
    ],
  });

  describe('1. Native CycloneDX & SPDX Document Parsers', () => {
    it('parses CycloneDX 1.4 JSON into normalized component records', () => {
      const parsed = parseCycloneDXJson(sampleCycloneDxJson, 'test-bom.json');
      expect(parsed.errors).toHaveLength(0);
      expect(parsed.sbom).toBeDefined();
      expect(parsed.sbom?.format).toBe('cyclonedx_json');
      expect(parsed.sbom?.components).toHaveLength(4);

      const lodash = parsed.sbom?.components.find((c) => c.name === 'lodash');
      expect(lodash).toBeDefined();
      expect(lodash?.version).toBe('4.17.20');
      expect(lodash?.purl).toBe('pkg:npm/lodash@4.17.20');
      expect(lodash?.ecosystem).toBe('npm');
      expect(lodash?.licenses).toContain('MIT');
      expect(lodash?.hashes?.['SHA-256']).toBe('abc123hash');
    });

    it('parses SPDX 2.3 JSON into normalized component records', () => {
      const parsed = parseSpdxJson(sampleSpdxJson, 'test-spdx.json');
      expect(parsed.errors).toHaveLength(0);
      expect(parsed.sbom).toBeDefined();
      expect(parsed.sbom?.format).toBe('spdx_json');
      expect(parsed.sbom?.components).toHaveLength(2);

      const axiosPkg = parsed.sbom?.components.find((c) => c.name === 'axios');
      expect(axiosPkg).toBeDefined();
      expect(axiosPkg?.version).toBe('0.21.1');
      expect(axiosPkg?.purl).toBe('pkg:npm/axios@0.21.1');
      expect(axiosPkg?.licenses).toContain('MIT');
    });

    it('parses npm package-lock.json v2/v3 dependencies', () => {
      const lockfileJson = JSON.stringify({
        name: 'my-web-app',
        version: '1.0.0',
        lockfileVersion: 3,
        packages: {
          '': { name: 'my-web-app', version: '1.0.0' },
          'node_modules/lodash': {
            version: '4.17.20',
            license: 'MIT',
          },
          'node_modules/minimist': {
            version: '1.2.5',
            license: 'MIT',
          },
        },
      });

      const parsed = parsePackageLockJson(lockfileJson, 'package-lock.json');
      expect(parsed.errors).toHaveLength(0);
      expect(parsed.sbom?.components).toHaveLength(2);
      expect(parsed.sbom?.components.map((c) => c.name)).toContain('lodash');
      expect(parsed.sbom?.components.map((c) => c.name)).toContain('minimist');
    });

    it('handles malformed JSON gracefully with structured error findings without crashing', async () => {
      const invalidJson = '{ "bomFormat": "CycloneDX", components: [ broken-unquoted-json ] }';
      const engine = new SbomSupplyChainEngine();
      const res = await engine.execute(
        {
          targetUrl: 'sbom://inventory',
          options: { sbomContent: invalidJson },
        },
        dummyContext,
      );

      expect(res.success).toBe(true);
      expect(res.findings.length).toBeGreaterThan(0);
      expect(res.findings[0]?.title).toMatch(/SBOM Parsing Failure/i);
    });
  });

  describe('2. Open Source Vulnerability (OSV) Advisory Matching', () => {
    it('correlates known vulnerable components against OSV advisories and identifies CVEs', async () => {
      const client = new OsvClient({ offlineMode: true });
      const components = [
        { name: 'lodash', version: '4.17.20', purl: 'pkg:npm/lodash@4.17.20', licenses: ['MIT'] },
        { name: 'log4j-core', version: '2.14.1', purl: 'pkg:maven/log4j-core@2.14.1', licenses: ['Apache-2.0'] },
        { name: 'lodash', version: '4.17.21', purl: 'pkg:npm/lodash@4.17.21', licenses: ['MIT'] }, // Patched version
      ];

      const matches = await client.matchComponents(components);

      // Vulnerable lodash@4.17.20 must have matches
      const lodashVulns = matches.get('lodash@4.17.20');
      expect(lodashVulns).toBeDefined();
      expect(lodashVulns?.length).toBeGreaterThan(0);
      expect(lodashVulns?.some((v) => v.aliases.includes('CVE-2021-23337'))).toBe(true);
      expect(lodashVulns?.[0]?.fixedVersion).toBe('4.17.21');

      // Critical Log4Shell must be detected
      const log4jVulns = matches.get('log4j-core@2.14.1');
      expect(log4jVulns).toBeDefined();
      expect(log4jVulns?.some((v) => v.aliases.includes('CVE-2021-44228'))).toBe(true);
      expect(log4jVulns?.[0]?.severity).toBe('critical');

      // Patched lodash@4.17.21 must have zero matches
      const patchedLodash = matches.get('lodash@4.17.21');
      expect(patchedLodash).toBeUndefined();
    });
  });

  describe('3. Open Source Software (OSS) License Compliance Policy Audit', () => {
    it('detects banned copyleft licenses (AGPL, GPL-3.0) and emits violation findings', () => {
      const components = [
        { name: 'permissive-tool', version: '1.0.0', licenses: ['MIT'] },
        { name: 'apache-lib', version: '2.0.0', licenses: ['Apache-2.0'] },
        { name: 'copyleft-app', version: '3.0.0', licenses: ['AGPL-3.0-only'] },
        { name: 'gpl-driver', version: '1.2.0', licenses: ['GPL-3.0-or-later'] },
      ];

      const results = evaluateLicenseCompliance(components);
      expect(results).toHaveLength(2);
      expect(results.some((r) => r.component.name === 'copyleft-app')).toBe(true);
      expect(results.some((r) => r.component.name === 'gpl-driver')).toBe(true);
    });

    it('evaluates dual and composite license expressions correctly', () => {
      const components = [
        // OR expression where one option is allowed (permissive MIT) -> No violation
        { name: 'dual-choice', version: '1.0.0', licenses: ['MIT OR AGPL-3.0-only'] },
        // AND expression where one component is disallowed -> Violation
        { name: 'combined-obligations', version: '1.0.0', licenses: ['MIT AND GPL-3.0-only'] },
      ];

      const results = evaluateLicenseCompliance(components);
      expect(results).toHaveLength(1);
      expect(results[0]?.component.name).toBe('combined-obligations');
    });
  });

  describe('4. Full Engine Execution with Advisory & License Findings', () => {
    it('executes full audit on CycloneDX SBOM and emits both CVE and license findings', async () => {
      const engine = new SbomSupplyChainEngine();
      const res = await engine.execute(
        {
          targetUrl: 'sbom://inventory',
          options: {
            sbomContent: sampleCycloneDxJson,
            enableOsvLookup: true,
            offlineMode: true,
          },
        },
        dummyContext,
      );

      expect(res.success).toBe(true);
      expect(res.findings.length).toBeGreaterThan(0);

      // Check Log4Shell critical finding
      const log4jFinding = res.findings.find((f) => f.title.includes('CVE-2021-44228') || f.title.includes('log4j-core'));
      expect(log4jFinding).toBeDefined();
      expect(log4jFinding?.severity).toBe('critical');
      expect(log4jFinding?.recommendation).toMatch(/Upgrade log4j-core/);

      // Check Lodash high finding
      const lodashFinding = res.findings.find((f) => f.title.includes('CVE-2021-23337') || f.title.includes('lodash'));
      expect(lodashFinding).toBeDefined();
      expect(lodashFinding?.severity).toBe('high');

      // Check Disallowed License finding
      const licFinding = res.findings.find((f) => f.title.includes('Disallowed Software License'));
      expect(licFinding).toBeDefined();
      expect(licFinding?.severity).toBe('high');
      expect(licFinding?.description).toMatch(/AGPL-3.0-only/);

      // Verify metrics
      const totalCompMetric = res.metrics.find((m) => m.name === 'sbom_components_total');
      expect(totalCompMetric?.value).toBe(4);

      const vulnsCountMetric = res.metrics.find((m) => m.name === 'sbom_vulnerabilities_total');
      expect(vulnsCountMetric?.value).toBeGreaterThan(0);
    });

    it('executes full audit on SPDX JSON SBOM and emits advisory and license findings', async () => {
      const engine = new SbomSupplyChainEngine();
      const res = await engine.execute(
        {
          targetUrl: 'sbom://inventory',
          options: {
            sbomContent: sampleSpdxJson,
            enableOsvLookup: true,
            offlineMode: true,
          },
        },
        dummyContext,
      );

      expect(res.success).toBe(true);

      // Axios vulnerability
      const axiosFinding = res.findings.find((f) => f.title.includes('axios'));
      expect(axiosFinding).toBeDefined();
      expect(axiosFinding?.severity).toBe('high');

      // GPL-3.0 license violation
      const gplFinding = res.findings.find((f) => f.title.includes('Disallowed Software License'));
      expect(gplFinding).toBeDefined();
    });
  });

  describe('5. Input Validation & Capabilities', () => {
    it('declares passive_analysis and compliance_check capabilities', () => {
      const caps = sbomSupplyChainEngine.capabilities();
      expect(caps.some((c) => c.id === 'sbom_ingestion')).toBe(true);
      expect(caps.some((c) => c.id === 'osv_vulnerability_mapping')).toBe(true);
      expect(caps.some((c) => c.id === 'license_compliance_audit')).toBe(true);
    });

    it('rejects execution when no SBOM content or target files are provided', () => {
      const validation = sbomSupplyChainEngine.validate({
        targetUrl: 'https://example.com',
        options: {},
      });
      expect(validation.valid).toBe(false);
      expect(validation.errors?.[0]?.message).toMatch(/SBOM Engine requires/);
    });
  });

  describe('6. Worker Sandboxing Execution (Phase 03 Integration)', () => {
    it('executes sbom-supply-chain engine inside isolated V8 worker thread harness', async () => {
      const runner = new WorkerRunner();
      const result = await runner.execute(
        'engine-sbom-supply-chain',
        {
          targetUrl: 'sbom://inventory',
          options: {
            sbomContent: sampleCycloneDxJson,
            enableOsvLookup: true,
            offlineMode: true,
          },
        },
        dummyContext,
        { enabled: true, timeoutMs: 10000 },
      );

      expect(result.success).toBe(true);
      expect(result.engineId).toBe('engine-sbom-supply-chain');
      expect(result.findings.length).toBeGreaterThan(0);
      expect(result.findings.some((f) => f.title.includes('CVE-2021-44228') || f.title.includes('log4j-core'))).toBe(true);
    });
  });
});

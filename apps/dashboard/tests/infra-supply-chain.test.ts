import { describe, it, expect } from 'vitest';
import {
  SAMPLE_K8S_AUDIT,
  SAMPLE_SBOM_GRAPH,
  SAMPLE_SMUGGLING_SNAPSHOT,
  SAMPLE_DATABASE_SECURITY,
  fetchInfraStudioOverview,
  fetchK8sAuditData,
  fetchSbomGraphData,
  fetchSmugglingWireData,
  fetchDatabaseSecurityData,
} from '../src/api/infra.js';

describe('Phase UI-11: Infrastructure K8s, SBOM Supply Chain & Wire Protocol Console', () => {
  describe('Kubernetes Workload Security & Pod Security Standards (PSS)', () => {
    it('provides cluster workload compliance posture with correct PSS distribution', () => {
      expect(SAMPLE_K8S_AUDIT.clusterName).toContain('k8s.security-lab.local');
      expect(SAMPLE_K8S_AUDIT.totalWorkloads).toBe(14);
      expect(SAMPLE_K8S_AUDIT.overallComplianceScore).toBeGreaterThanOrEqual(0);
      expect(SAMPLE_K8S_AUDIT.overallComplianceScore).toBeLessThanOrEqual(100);

      const pss = SAMPLE_K8S_AUDIT.pssDistribution;
      expect(pss.restricted + pss.baseline + pss.privileged).toBe(SAMPLE_K8S_AUDIT.totalWorkloads);
    });

    it('identifies critical workload misconfigurations (privileged containers and hostPath mounts)', () => {
      const nodeAgent = SAMPLE_K8S_AUDIT.workloads.find(
        (w) => w.name === 'security-node-daemon'
      );
      expect(nodeAgent).toBeDefined();
      expect(nodeAgent!.hasPrivilegedContainer).toBe(true);
      expect(nodeAgent!.hasSensitiveHostPath).toBe(true);
      expect(nodeAgent!.pssLevel).toBe('privileged');
      expect(nodeAgent!.findings.some((f) => f.ruleId === 'K8S-001-PRIVILEGED-CONTAINER')).toBe(true);
      expect(nodeAgent!.findings.some((f) => f.ruleId === 'K8S-003-SENSITIVE-HOSTPATH')).toBe(true);
    });

    it('verifies that hardened PCI workloads achieve 100% compliance with zero findings', () => {
      const paymentWorkload = SAMPLE_K8S_AUDIT.workloads.find(
        (w) => w.name === 'payment-processor'
      );
      expect(paymentWorkload).toBeDefined();
      expect(paymentWorkload!.pssLevel).toBe('restricted');
      expect(paymentWorkload!.complianceScore).toBe(100);
      expect(paymentWorkload!.findings.length).toBe(0);
      expect(paymentWorkload!.droppedAllCapabilities).toBe(true);
      expect(paymentWorkload!.runsAsRoot).toBe(false);
    });

    it('summarizes namespace-level compliance scores correctly', () => {
      expect(SAMPLE_K8S_AUDIT.namespaces.length).toBeGreaterThanOrEqual(4);
      const pciNs = SAMPLE_K8S_AUDIT.namespaces.find((ns) => ns.namespace === 'payments-pci');
      expect(pciNs).toBeDefined();
      expect(pciNs!.complianceScore).toBe(100);
    });
  });

  describe('SBOM & Supply Chain Dependency Graph', () => {
    it('provides standardized CycloneDX 1.5 SBOM metadata and component counts', () => {
      expect(SAMPLE_SBOM_GRAPH.format).toBe('cyclonedx_json');
      expect(SAMPLE_SBOM_GRAPH.specVersion).toBe('1.5');
      expect(SAMPLE_SBOM_GRAPH.totalComponents).toBe(124);
      expect(
        SAMPLE_SBOM_GRAPH.directDependenciesCount + SAMPLE_SBOM_GRAPH.transitiveDependenciesCount
      ).toBe(SAMPLE_SBOM_GRAPH.totalComponents);
    });

    it('identifies critical supply chain vulnerabilities with CVSS scores >= 9.0', () => {
      const jsonwebtoken = SAMPLE_SBOM_GRAPH.components.find((c) => c.name === 'jsonwebtoken');
      expect(jsonwebtoken).toBeDefined();
      expect(jsonwebtoken!.cveMatches.length).toBeGreaterThan(0);

      const criticalCve = jsonwebtoken!.cveMatches.find((cve) => cve.severity === 'critical');
      expect(criticalCve).toBeDefined();
      expect(criticalCve!.id).toBe('CVE-2022-23529');
      expect(criticalCve!.cvssScore).toBeGreaterThanOrEqual(9.0);
      expect(criticalCve!.fixedVersion).toBe('9.0.0');
    });

    it('flags corporate license policy violations for banned copyleft licenses (AGPL-3.0)', () => {
      const agplComp = SAMPLE_SBOM_GRAPH.components.find(
        (c) => c.name === 'internal-exporter-daemon'
      );
      expect(agplComp).toBeDefined();
      expect(agplComp!.licenseRisk).toBe('CRITICAL');
      expect(agplComp!.licenses).toContain('AGPL-3.0-only');
      expect(agplComp!.licenseViolationReason).toContain('Disallowed copyleft license AGPL-3.0');
    });

    it('contains valid cryptographic integrity hashes for audited packages', () => {
      const axiosComp = SAMPLE_SBOM_GRAPH.components.find((c) => c.name === 'axios');
      expect(axiosComp).toBeDefined();
      expect(axiosComp!.hashes['sha-256']).toBeDefined();
      expect(axiosComp!.hashes['sha-256'].length).toBe(64);
    });
  });

  describe('HTTP Request Smuggling Wire Protocol Inspector', () => {
    it('contains core desync variants (CL.TE, TE.CL, TE.TE)', () => {
      const techniques = SAMPLE_SMUGGLING_SNAPSHOT.variants.map((v) => v.technique);
      expect(techniques).toContain('CL_TE');
      expect(techniques).toContain('TE_CL');
      expect(techniques).toContain('TE_TE');
    });

    it('preserves exact CRLF line delimiters in raw socket payloads', () => {
      const clTe = SAMPLE_SMUGGLING_SNAPSHOT.variants.find((v) => v.technique === 'CL_TE');
      expect(clTe).toBeDefined();
      expect(clTe!.rawSocketRequest).toContain('\r\n');
      expect(clTe!.rawSocketRequest).toContain('Content-Length: 6');
      expect(clTe!.rawSocketRequest).toContain('Transfer-Encoding: chunked');
      expect(clTe!.vulnerabilityStatus).toBe('CONFIRMED');
      expect(clTe!.canaryReflected).toBe(true);
    });

    it('provides dual-sided parser asymmetry explanations', () => {
      const teCl = SAMPLE_SMUGGLING_SNAPSHOT.variants.find((v) => v.technique === 'TE_CL');
      expect(teCl).toBeDefined();
      expect(teCl!.frontendExpectation).toContain('Frontend');
      expect(teCl!.backendExpectation).toContain('Backend');
      expect(teCl!.desyncExplanation).toContain('smuggled');
    });

    it('includes raw hex dump representation of socket payloads', () => {
      const clTe = SAMPLE_SMUGGLING_SNAPSHOT.variants.find((v) => v.technique === 'CL_TE');
      expect(clTe!.requestHexDump).toContain('50 4f 53 54'); // 'POST'
      expect(clTe!.requestHexDump).toContain('|POST / HTTP/1.1.|');
    });
  });

  describe('Direct Database Protocol Security & Connection Stress', () => {
    it('audits PostgreSQL, MySQL, and Redis wire endpoints', () => {
      const types = SAMPLE_DATABASE_SECURITY.probes.map((p) => p.databaseType);
      expect(types).toContain('POSTGRES');
      expect(types).toContain('MYSQL');
      expect(types).toContain('REDIS');
    });

    it('detects unencrypted cleartext wire protocol allowed on PostgreSQL probe', () => {
      const pg = SAMPLE_DATABASE_SECURITY.probes.find((p) => p.databaseType === 'POSTGRES');
      expect(pg).toBeDefined();
      expect(pg!.tlsMandated).toBe(false);
      expect(pg!.defaultCredentialsMatched).toBe(true);
      expect(pg!.matchedCredentialUser).toBe('postgres / postgres');
      expect(pg!.findings.some((f) => f.id === 'DB-001-CLEARTEXT-ALLOWED')).toBe(true);
    });

    it('detects unauthenticated open Redis instance responding to raw PING', () => {
      const redis = SAMPLE_DATABASE_SECURITY.probes.find((p) => p.databaseType === 'REDIS');
      expect(redis).toBeDefined();
      expect(redis!.unauthenticatedAccessAllowed).toBe(true);
      expect(redis!.rawBannerHex).toContain('2b 50 4f 4e 47'); // "+PONG\r\n"
      expect(redis!.findings.some((f) => f.id === 'DB-003-OPEN-REDIS')).toBe(true);
    });

    it('evaluates database connection pool saturation ceiling and graceful rejection', () => {
      const mysql = SAMPLE_DATABASE_SECURITY.probes.find((p) => p.databaseType === 'MYSQL');
      expect(mysql).toBeDefined();
      expect(mysql!.saturation.serverGraceful).toBe(true);
      expect(mysql!.saturation.attemptedConnections).toBe(40);
      expect(mysql!.saturation.successfulConnections).toBe(35);
      expect(mysql!.saturation.rejectedConnections).toBe(5);
      expect(mysql!.saturation.rejectionReason).toContain('ER_CON_COUNT_ERROR');
    });
  });

  describe('Asynchronous Data Fetchers', () => {
    it('fetches consolidated studio overview snapshot with all 4 subdomains', async () => {
      const overview = await fetchInfraStudioOverview();
      expect(overview.k8s).toBeDefined();
      expect(overview.sbom).toBeDefined();
      expect(overview.smuggling).toBeDefined();
      expect(overview.database).toBeDefined();
    });

    it('fetches domain snapshots individually', async () => {
      const k8s = await fetchK8sAuditData();
      const sbom = await fetchSbomGraphData();
      const smuggling = await fetchSmugglingWireData();
      const db = await fetchDatabaseSecurityData();

      expect(k8s.workloads.length).toBeGreaterThan(0);
      expect(sbom.components.length).toBeGreaterThan(0);
      expect(smuggling.variants.length).toBeGreaterThan(0);
      expect(db.probes.length).toBeGreaterThan(0);
    });
  });
});

import crypto from 'node:crypto';
import {
  TestEngine,
  TestCapability,
  ExecutionContext,
  TestInput,
  TestResult,
  ValidationResult,
  RawEngineFinding,
  RawEngineMetric,
  dynamicWorkerEngineRegistry,
} from '@security-lab/engine-sdk';
import { validateUrlAgainstScope } from '@security-lab/domain';
import { createLogger } from '@security-lab/logger';
import {
  DatabaseType,
  DatabaseEngineOptions,
  DatabaseEngineOptionsSchema,
  DatabaseExecutionSummary,
} from './types.js';
import { probePostgres } from './postgres-probe.js';
import { probeRedis } from './redis-probe.js';
import { probeMySql } from './mysql-probe.js';
import { testConnectionSaturation } from './saturation.js';

export * from './types.js';
export * from './postgres-probe.js';
export * from './redis-probe.js';
export * from './mysql-probe.js';
export * from './saturation.js';

const logger = createLogger({ name: 'engine-db-security' });

export class DatabaseSecurityEngine implements TestEngine {
  readonly id = 'engine-db-security';
  readonly version = '1.0.0';
  readonly executionClass = 'class_a_native' as const;

  capabilities(): TestCapability[] {
    return [
      {
        id: 'database_tls_enforcement',
        name: 'Database TLS / In-Transit Encryption Enforcement Probe',
        category: 'protocol_audit',
        description:
          'Probes PostgreSQL SSLRequest, MySQL HandshakeV10 CLIENT_SSL capabilities, and Redis TLS configurations to detect unencrypted plaintext database traffic.',
        isDisruptive: false,
      },
      {
        id: 'database_unauthenticated_access',
        name: 'Database Unauthenticated / Default Access Detection',
        category: 'protocol_audit',
        description:
          'Sends native wire-level commands (e.g. Redis PING/INFO, Postgres trust mode) to detect databases exposed with zero authentication.',
        isDisruptive: false,
      },
      {
        id: 'database_default_credentials',
        name: 'Database Default & Weak Credential Probe',
        category: 'protocol_audit',
        description:
          'Safely audits common default accounts (e.g. postgres/postgres, root/root) with immediate termination upon detection.',
        isDisruptive: false,
      },
      {
        id: 'database_connection_saturation',
        name: 'Database Connection Pool Saturation Resilience',
        category: 'resilience_stress',
        description:
          'Performs connection burst probing to evaluate database max_connections limits, rejection behavior, and resilience against connection starvation.',
        isDisruptive: true,
      },
    ];
  }

  validate(input: TestInput): ValidationResult {
    try {
      const url = new URL(input.targetUrl);
      const supportedProtocols = [
        'postgres:',
        'postgresql:',
        'mysql:',
        'redis:',
        'http:',
        'https:',
      ];
      if (!supportedProtocols.includes(url.protocol)) {
        return {
          valid: false,
          errors: [
            {
              path: 'targetUrl',
              message: `Target protocol "${url.protocol}" is not supported for database testing. Use postgres:, mysql:, or redis:.`,
            },
          ],
        };
      }
      return { valid: true };
    } catch {
      return {
        valid: false,
        errors: [{ path: 'targetUrl', message: 'Invalid target database URL format' }],
      };
    }
  }

  async execute(input: TestInput, context: ExecutionContext): Promise<TestResult> {
    const startTime = Date.now();
    const findings: RawEngineFinding[] = [];
    const metrics: RawEngineMetric[] = [];

    // Parse target URL
    const targetUrlObj = new URL(input.targetUrl);
    const host = targetUrlObj.hostname;
    const protocol = targetUrlObj.protocol;

    // Detect database type and default port
    let dbType: DatabaseType = 'POSTGRES';
    let defaultPort = 5432;

    if (protocol === 'redis:' || targetUrlObj.port === '6379') {
      dbType = 'REDIS';
      defaultPort = 6379;
    } else if (protocol === 'mysql:' || targetUrlObj.port === '3306') {
      dbType = 'MYSQL';
      defaultPort = 3306;
    } else if (protocol === 'postgres:' || protocol === 'postgresql:' || targetUrlObj.port === '5432') {
      dbType = 'POSTGRES';
      defaultPort = 5432;
    }

    const port = targetUrlObj.port ? parseInt(targetUrlObj.port, 10) : defaultPort;

    // Parse options
    const optionsParsed = DatabaseEngineOptionsSchema.safeParse(input.options || {});
    const options: DatabaseEngineOptions = optionsParsed.success
      ? optionsParsed.data
      : DatabaseEngineOptionsSchema.parse({});

    if (options.databaseType) {
      dbType = options.databaseType;
    }

    // Target Scope Verification (Rule 2 Compliance)
    if (context.target?.scope) {
      const scopeResult = validateUrlAgainstScope(input.targetUrl, context.target.scope as any, {
        allowedProtocols: ['http:', 'https:', 'postgres:', 'postgresql:', 'mysql:', 'redis:'],
      });
      if (!scopeResult.valid) {
        logger.warn(
          { targetUrl: input.targetUrl, violations: scopeResult.violations },
          'Target database URL is outside authorized scope. Halting execution.',
        );
        return {
          engineId: this.id,
          success: false,
          durationMs: Date.now() - startTime,
          findings: [],
          metrics: [],
          error: `Execution prohibited: Target URL "${input.targetUrl}" is not within authorized scope. Violations: ${scopeResult.violations.join(', ')}`,
        };
      }
    }

    logger.info(
      { host, port, dbType, protocol },
      'Starting direct database protocol security audit and resilience verification',
    );

    context.reportProgress?.(10, `Connecting to ${dbType} endpoint on port ${port}`);

    // 1. Direct Protocol Handshake Probe
    let probeResult: any;
    if (dbType === 'POSTGRES') {
      context.reportProgress?.(25, 'Probing PostgreSQL SSLRequest and StartupMessage');
      probeResult = await probePostgres({
        host,
        port,
        timeoutMs: options.timeoutMs,
        testDefaultCredentials: options.checkDefaultCredentials,
      });
    } else if (dbType === 'REDIS') {
      context.reportProgress?.(25, 'Probing Redis RESP commands and unauthenticated access');
      probeResult = await probeRedis({
        host,
        port,
        timeoutMs: options.timeoutMs,
        testDefaultCredentials: options.checkDefaultCredentials,
      });
    } else {
      context.reportProgress?.(25, 'Probing MySQL HandshakeV10 packet and CLIENT_SSL capability');
      probeResult = await probeMySql({
        host,
        port,
        timeoutMs: options.timeoutMs,
      });
    }

    if (!probeResult.success) {
      logger.warn({ host, port, error: probeResult.error }, 'Failed to establish database protocol connection');
      return {
        engineId: this.id,
        success: false,
        durationMs: Date.now() - startTime,
        findings: [],
        metrics: [],
        error: probeResult.error || `Failed to connect to ${dbType} at ${host}:${port}`,
      };
    }

    // 2. Evaluate Protocol Security Findings
    context.reportProgress?.(50, 'Evaluating protocol security configurations and findings');

    // Finding A: Missing TLS / Plaintext Permitted
    if (!probeResult.tlsSupported || !probeResult.tlsMandated) {
      const evidenceHash = crypto
        .createHash('sha256')
        .update(`${dbType}:${host}:${port}:unencrypted_allowed`)
        .digest('hex');

      findings.push({
        title: `Database Plaintext Communication Permitted (${dbType})`,
        description: `The ${dbType} server at ${host}:${port} allows unencrypted cleartext database connections without mandating TLS. Sensitive queries, credentials, and records can be intercepted or manipulated in transit.`,
        severity: 'high',
        category: 'protocol_audit',
        recommendation:
          'Enforce SSL/TLS encryption for all client connections. For PostgreSQL, set "ssl = on" and configure pg_hba.conf to require "hostssl". For MySQL, set "require_secure_transport = ON".',
        evidence: {
          request: {
            url: input.targetUrl,
            method: 'PROTOCOL_HANDSHAKE',
            headers: { Host: host, Port: String(port) },
            body: `Protocol handshake initiated for ${dbType}`,
          },
          response: {
            statusCode: 0,
            headers: {},
            body: `TLS Supported: ${probeResult.tlsSupported}, TLS Mandated: ${probeResult.tlsMandated}`,
            responseTimeMs: probeResult.latencyMs,
          },
          immutableHash: evidenceHash,
          metadata: {
            databaseType: dbType,
            tlsSupported: probeResult.tlsSupported,
            tlsMandated: probeResult.tlsMandated,
            rawBannerHex: probeResult.rawBannerHex,
            evidenceHash,
          },
        },
      });
    }

    // Finding B: Unauthenticated Access Allowed
    if (probeResult.unauthenticatedAccessAllowed) {
      const evidenceHash = crypto
        .createHash('sha256')
        .update(`${dbType}:${host}:${port}:unauthenticated_access`)
        .digest('hex');

      findings.push({
        title: `Critical Database Unauthenticated Access (${dbType})`,
        description: `The ${dbType} instance at ${host}:${port} permits complete access without requiring any password or authentication token (e.g. open Redis instance or PostgreSQL trust authentication).`,
        severity: 'critical',
        category: 'protocol_audit',
        recommendation:
          'Immediately require strong authentication. For Redis, configure "requirepass" in redis.conf. For PostgreSQL, replace "trust" authentication with "scram-sha-256" in pg_hba.conf.',
        evidence: {
          request: {
            url: input.targetUrl,
            method: dbType === 'REDIS' ? 'PING' : 'StartupMessage',
            headers: { Host: host, Port: String(port) },
          },
          response: {
            statusCode: 0,
            headers: {},
            body: `Unauthenticated access permitted: ${probeResult.matchedCredentialUser || 'Open instance'}`,
            responseTimeMs: probeResult.latencyMs,
          },
          immutableHash: evidenceHash,
          metadata: {
            databaseType: dbType,
            serverVersion: probeResult.serverVersion,
            unauthenticatedAccess: true,
            evidenceHash,
          },
        },
      });
    }

    // Finding C: Default Credentials Accepted
    if (probeResult.defaultCredentialsMatched && !probeResult.unauthenticatedAccessAllowed) {
      const evidenceHash = crypto
        .createHash('sha256')
        .update(`${dbType}:${host}:${port}:default_credentials`)
        .digest('hex');

      findings.push({
        title: `Default Database Credentials Accepted (${dbType})`,
        description: `The ${dbType} server at ${host}:${port} authenticated successfully using common default credentials ("${probeResult.matchedCredentialUser}").`,
        severity: 'critical',
        category: 'protocol_audit',
        recommendation:
          'Change default database account passwords immediately. Enforce strong, randomly generated passwords stored in an encrypted secrets vault.',
        evidence: {
          request: {
            url: input.targetUrl,
            method: 'AUTH_PROBE',
            headers: { Host: host, Port: String(port) },
          },
          response: {
            statusCode: 0,
            headers: {},
            body: `Authenticated as: ${probeResult.matchedCredentialUser}`,
            responseTimeMs: probeResult.latencyMs,
          },
          immutableHash: evidenceHash,
          metadata: {
            databaseType: dbType,
            account: probeResult.matchedCredentialUser,
            evidenceHash,
          },
        },
      });
    }

    // 3. Optional Connection Saturation Resilience Test
    let saturationSummary: any;
    if (options.testSaturation) {
      context.reportProgress?.(75, 'Running database connection pool saturation test');
      saturationSummary = await testConnectionSaturation({
        host,
        port,
        targetConnections: options.saturationTargetConnections || 25,
        timeoutMs: options.timeoutMs,
      });

      if (!saturationSummary.serverGraceful) {
        const evidenceHash = crypto
          .createHash('sha256')
          .update(`${dbType}:${host}:${port}:saturation_failure`)
          .digest('hex');

        findings.push({
          title: `Database Connection Pool Exhaustion Resilience Failure (${dbType})`,
          description: `The ${dbType} server at ${host}:${port} failed to reject excess connection bursts gracefully during saturation testing. Connections timed out rather than receiving clean connection-limit rejections.`,
          severity: 'medium',
          category: 'reliability',
          recommendation:
            'Tune database "max_connections" and connection pooler settings (such as PgBouncer or ProxySQL) to fast-reject connections when pool capacity is exceeded.',
          evidence: {
            request: {
              url: input.targetUrl,
              method: 'SATURATION_BURST',
              headers: { Host: host, TargetConnections: String(options.saturationTargetConnections) },
            },
            response: {
              statusCode: 0,
              headers: {},
              body: `Attempted: ${saturationSummary.attemptedConnections}, Rejected: ${saturationSummary.rejectedConnections}, Reason: ${saturationSummary.rejectionReason}`,
              responseTimeMs: saturationSummary.avgConnectionTimeMs,
            },
            immutableHash: evidenceHash,
            metadata: {
              saturationSummary,
              evidenceHash,
            },
          },
        });
      }
    }

    // 4. Metrics
    metrics.push(
      { name: 'db_tls_supported', value: probeResult.tlsSupported ? 1 : 0, unit: 'boolean' },
      { name: 'db_tls_mandated', value: probeResult.tlsMandated ? 1 : 0, unit: 'boolean' },
      { name: 'db_unauthenticated_access', value: probeResult.unauthenticatedAccessAllowed ? 1 : 0, unit: 'boolean' },
      { name: 'db_handshake_latency_ms', value: probeResult.latencyMs, unit: 'ms' },
    );

    if (saturationSummary) {
      metrics.push(
        { name: 'db_connections_successful', value: saturationSummary.successfulConnections, unit: 'count' },
        { name: 'db_connections_rejected', value: saturationSummary.rejectedConnections, unit: 'count' },
      );
    }

    const durationMs = Date.now() - startTime;
    context.reportProgress?.(100, `Database audit complete. Generated ${findings.length} findings.`);

    logger.info(
      { dbType, findingsCount: findings.length, durationMs },
      'Database security audit completed successfully',
    );

    const summary: DatabaseExecutionSummary = {
      targetHost: host,
      targetPort: port,
      protocol: protocol as any,
      databaseType: dbType,
      handshake: probeResult,
      saturation: saturationSummary,
      findingsCount: findings.length,
      durationMs,
    };

    return {
      engineId: this.id,
      success: true,
      durationMs,
      findings,
      metrics,
      rawOutput: JSON.stringify(summary, null, 2),
    };
  }
}

export const databaseSecurityEngine = new DatabaseSecurityEngine();
dynamicWorkerEngineRegistry.register(databaseSecurityEngine);

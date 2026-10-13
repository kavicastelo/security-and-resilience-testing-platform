import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import net from 'node:net';
import { AddressInfo } from 'node:net';
import {
  DatabaseSecurityEngine,
  probePostgres,
  probeRedis,
  probeMySql,
  testConnectionSaturation,
} from '../src/index.js';
import { executeSandboxedEngine } from '@security-lab/test-runner';

describe('Phase 12: Direct Database Protocol Security & Connection Resilience', () => {
  let pgServer: net.Server;
  let pgPort: number;

  let redisServer: net.Server;
  let redisPort: number;

  let mysqlServer: net.Server;
  let mysqlPort: number;

  beforeAll(async () => {
    // 1. Mock PostgreSQL Server simulating plaintext-only database (SSL disabled)
    pgServer = net.createServer((socket) => {
      socket.on('data', (data) => {
        // SSLRequest check: 00 00 00 08 04 d2 16 2f
        if (data.length === 8 && data.readInt32BE(4) === 80877103) {
          // Send 'N' indicating SSL is not supported (unencrypted plaintext allowed)
          socket.write(Buffer.from([0x4e]));
        } else if (data.length >= 8 && data.readInt32BE(4) === 196608) {
          // StartupMessage (protocol 3.0): reply with AuthenticationOk (trust auth, code 0)
          const authOk = Buffer.alloc(9);
          authOk[0] = 0x52; // 'R'
          authOk.writeInt32BE(8, 1);
          authOk.writeInt32BE(0, 5); // Code 0 = AuthenticationOk
          socket.write(authOk);
        }
      });
    });

    await new Promise<void>((resolve) => {
      pgServer.listen(0, '127.0.0.1', () => {
        pgPort = (pgServer.address() as AddressInfo).port;
        resolve();
      });
    });

    // 2. Mock Redis Server simulating unauthenticated open access
    redisServer = net.createServer((socket) => {
      socket.on('data', (data) => {
        const text = data.toString('utf-8');
        if (text.includes('PING')) {
          socket.write('+PONG\r\n');
        } else if (text.includes('INFO')) {
          const info =
            '# Server\r\nredis_version:7.0.12\r\nos:Linux 5.15.0\r\nuptime_in_seconds:3600\r\nrole:master\r\n';
          socket.write(`$${Buffer.byteLength(info)}\r\n${info}\r\n`);
        }
      });
    });

    await new Promise<void>((resolve) => {
      redisServer.listen(0, '127.0.0.1', () => {
        redisPort = (redisServer.address() as AddressInfo).port;
        resolve();
      });
    });

    // 3. Mock MySQL Server sending HandshakeV10 packet without CLIENT_SSL
    mysqlServer = net.createServer((socket) => {
      // Build HandshakeV10 payload
      const versionStr = '8.0.32\0';
      const versionBuf = Buffer.from(versionStr, 'utf-8');
      const authPart1 = Buffer.from([1, 2, 3, 4, 5, 6, 7, 8]);
      const authPlugin = Buffer.from('mysql_native_password\0', 'utf-8');

      const payload = Buffer.concat([
        Buffer.from([0x0a]), // Protocol 10
        versionBuf,
        Buffer.from([0x01, 0x00, 0x00, 0x00]), // Connection ID
        authPart1,
        Buffer.from([0x00]), // Filler
        Buffer.from([0x00, 0x00]), // Lower capabilities (CLIENT_SSL bit 11 is 0!)
        Buffer.from([0x21]), // Collation
        Buffer.from([0x02, 0x00]), // Status
        Buffer.from([0x00, 0x00]), // Upper capabilities
        Buffer.from([0x15]), // Auth plugin data len
        Buffer.alloc(10, 0), // Reserved
        Buffer.alloc(12, 1), // Auth part 2
        Buffer.from([0x00]), // Null
        authPlugin,
      ]);

      const packetLen = payload.length;
      const header = Buffer.alloc(4);
      header[0] = packetLen & 0xff;
      header[1] = (packetLen >> 8) & 0xff;
      header[2] = (packetLen >> 16) & 0xff;
      header[3] = 0; // Seq 0

      socket.write(Buffer.concat([header, payload]));
    });

    await new Promise<void>((resolve) => {
      mysqlServer.listen(0, '127.0.0.1', () => {
        mysqlPort = (mysqlServer.address() as AddressInfo).port;
        resolve();
      });
    });
  });

  afterAll(async () => {
    await Promise.all([
      new Promise<void>((r) => pgServer.close(() => r())),
      new Promise<void>((r) => redisServer.close(() => r())),
      new Promise<void>((r) => mysqlServer.close(() => r())),
    ]);
  });

  it('1. PostgreSQL Protocol Probe > detects missing TLS and trust authentication', async () => {
    const probe = await probePostgres({
      host: '127.0.0.1',
      port: pgPort,
      timeoutMs: 2000,
      testDefaultCredentials: true,
    });

    expect(probe.success).toBe(true);
    expect(probe.tlsSupported).toBe(false);
    expect(probe.tlsMandated).toBe(false);
    expect(probe.unauthenticatedAccessAllowed).toBe(true);
    expect(probe.authMethod).toBe('trust');
  });

  it('2. Redis Protocol Probe > detects unauthenticated open instance and retrieves version', async () => {
    const probe = await probeRedis({
      host: '127.0.0.1',
      port: redisPort,
      timeoutMs: 2000,
    });

    expect(probe.success).toBe(true);
    expect(probe.unauthenticatedAccessAllowed).toBe(true);
    expect(probe.serverVersion).toBe('7.0.12');
    expect(probe.details?.os).toBe('Linux 5.15.0');
  });

  it('3. MySQL Protocol Probe > detects missing CLIENT_SSL capability in HandshakeV10', async () => {
    const probe = await probeMySql({
      host: '127.0.0.1',
      port: mysqlPort,
      timeoutMs: 2000,
    });

    expect(probe.success).toBe(true);
    expect(probe.tlsSupported).toBe(false);
    expect(probe.serverVersion).toBe('8.0.32');
    expect(probe.authMethod).toBe('mysql_native_password');
  });

  it('4. Connection Saturation Resilience > bursts concurrent connections and measures capacity', async () => {
    const saturation = await testConnectionSaturation({
      host: '127.0.0.1',
      port: redisPort,
      targetConnections: 15,
      timeoutMs: 2000,
    });

    expect(saturation.attemptedConnections).toBe(15);
    expect(saturation.successfulConnections).toBe(15);
    expect(saturation.rejectedConnections).toBe(0);
    expect(saturation.serverGraceful).toBe(true);
  });

  it('5. Database Security Engine Execution > executes against Postgres and generates critical findings', async () => {
    const engine = new DatabaseSecurityEngine();
    const result = await engine.execute(
      {
        targetUrl: `postgres://127.0.0.1:${pgPort}`,
        options: {
          testSaturation: false,
          timeoutMs: 2000,
        },
      },
      {
        executionId: 'exec-pg-test',
        testRunId: 'run-pg-test',
        target: {
          id: 'target-mock',
          baseUrl: `postgres://127.0.0.1:${pgPort}`,
          scope: {
            allowedHosts: ['127.0.0.1', 'localhost'],
            allowedPorts: [pgPort],
            allowPrivateIps: true,
            excludedPaths: [],
          },
        },
      },
    );

    expect(result.success).toBe(true);
    expect(result.findings.length).toBeGreaterThanOrEqual(2);

    const tlsFinding = result.findings.find((f) => f.title.includes('Plaintext Communication Permitted'));
    expect(tlsFinding).toBeDefined();
    expect(tlsFinding?.severity).toBe('high');

    const authFinding = result.findings.find((f) => f.title.includes('Unauthenticated Access'));
    expect(authFinding).toBeDefined();
    expect(authFinding?.severity).toBe('critical');
  });

  it('6. Database Security Engine Execution > executes against Redis and detects open instance', async () => {
    const engine = new DatabaseSecurityEngine();
    const result = await engine.execute(
      {
        targetUrl: `redis://127.0.0.1:${redisPort}`,
        options: {
          testSaturation: false,
          timeoutMs: 2000,
        },
      },
      {
        executionId: 'exec-redis-test',
        testRunId: 'run-redis-test',
        target: {
          id: 'target-mock',
          baseUrl: `redis://127.0.0.1:${redisPort}`,
          scope: {
            allowedHosts: ['127.0.0.1', 'localhost'],
            allowedPorts: [redisPort],
            allowPrivateIps: true,
            excludedPaths: [],
          },
        },
      },
    );

    expect(result.success).toBe(true);
    const unauthFinding = result.findings.find((f) => f.title.includes('Unauthenticated Access'));
    expect(unauthFinding).toBeDefined();
    expect(unauthFinding?.severity).toBe('critical');
  });

  it('7. Database Security Engine Execution > executes against MySQL and detects plaintext transport allowed', async () => {
    const engine = new DatabaseSecurityEngine();
    const result = await engine.execute(
      {
        targetUrl: `mysql://127.0.0.1:${mysqlPort}`,
        options: {
          testSaturation: false,
          timeoutMs: 2000,
        },
      },
      {
        executionId: 'exec-mysql-test',
        testRunId: 'run-mysql-test',
        target: {
          id: 'target-mock',
          baseUrl: `mysql://127.0.0.1:${mysqlPort}`,
          scope: {
            allowedHosts: ['127.0.0.1', 'localhost'],
            allowedPorts: [mysqlPort],
            allowPrivateIps: true,
            excludedPaths: [],
          },
        },
      },
    );

    expect(result.success).toBe(true);
    const plaintextFinding = result.findings.find((f) => f.title.includes('Plaintext Communication Permitted (MYSQL)'));
    expect(plaintextFinding).toBeDefined();
    expect(plaintextFinding?.severity).toBe('high');
  });

  it('8. Target Scope Enforcement Invariants > strictly blocks out-of-scope database targets (Rule 2 Compliance)', async () => {
    const engine = new DatabaseSecurityEngine();
    const result = await engine.execute(
      {
        targetUrl: 'postgres://unauthorized.internal.db:5432',
      },
      {
        executionId: 'exec-scope-test',
        testRunId: 'run-scope-test',
        target: {
          id: 'target-mock',
          baseUrl: 'postgres://unauthorized.internal.db:5432',
          scope: {
            allowedHosts: ['127.0.0.1'],
            allowedPorts: [5432],
            allowPrivateIps: true,
            excludedPaths: [],
          },
        },
      },
    );

    expect(result.success).toBe(false);
    expect(result.error).toContain('is not within authorized scope');
    expect(result.findings).toHaveLength(0);
  });

  it('9. Input Validation & Capabilities > validates database protocols and capabilities', () => {
    const engine = new DatabaseSecurityEngine();
    expect(engine.validate({ targetUrl: 'postgres://localhost:5432' }).valid).toBe(true);
    expect(engine.validate({ targetUrl: 'mysql://localhost:3306' }).valid).toBe(true);
    expect(engine.validate({ targetUrl: 'redis://localhost:6379' }).valid).toBe(true);
    expect(engine.validate({ targetUrl: 'ftp://localhost:21' }).valid).toBe(false);

    const capabilities = engine.capabilities();
    expect(capabilities.length).toBe(4);
    expect(capabilities.map((c) => c.id)).toContain('database_tls_enforcement');
    expect(capabilities.map((c) => c.id)).toContain('database_unauthenticated_access');
    expect(capabilities.map((c) => c.id)).toContain('database_connection_saturation');
  });

  it('10. Worker Thread Sandboxed Execution > executes db-security engine in isolated V8 worker thread', async () => {
    const result = await executeSandboxedEngine(
      'engine-db-security',
      {
        targetUrl: `redis://127.0.0.1:${redisPort}`,
        options: {
          testSaturation: false,
          timeoutMs: 2000,
        },
      },
      {
        runId: 'run-worker-db',
        engineId: 'engine-db-security',
        target: {
          id: 'target-mock-db',
          url: `redis://127.0.0.1:${redisPort}`,
          scope: {
            allowedHosts: ['127.0.0.1', 'localhost'],
            allowedPorts: [redisPort],
            allowPrivateIps: true,
            excludedPaths: [],
          },
        },
      },
      {
        timeoutMs: 15000,
      },
    );

    expect(result.engineId).toBe('engine-db-security');
    expect(result.success).toBe(true);
    expect(result.findings.length).toBeGreaterThan(0);
    const unauth = result.findings.find((f) => f.title.includes('Unauthenticated Access'));
    expect(unauth).toBeDefined();
  });
});

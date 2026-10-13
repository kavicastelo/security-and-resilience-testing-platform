# Direct Database Protocol Security & Connection Resilience Engine (`@security-lab/db-security`)

## 1. Overview
The **Database Protocol Security Engine** audits direct wire-level database handshakes and tests connection pool exhaustion resilience across PostgreSQL, MySQL, and Redis endpoints without requiring external client tools (like `psql`, `mysql`, or `redis-cli`) or native database drivers.

In staging environments, cloud VPCs, and container networks, databases are often exposed with unencrypted plaintext traffic, default credentials, or unauthenticated open access. This engine operates at the raw TCP socket layer to verify security controls and evaluate resilience against connection starvation.

---

## 2. Capabilities

| Capability ID | Name | Category | Description |
|---|---|---|---|
| `database_tls_enforcement` | Database TLS Enforcement Probe | `protocol_audit` | Probes PostgreSQL `SSLRequest`, MySQL `HandshakeV10 CLIENT_SSL` flags, and Redis cleartext transport to detect unencrypted plaintext communication. |
| `database_unauthenticated_access` | Database Unauthenticated Access | `protocol_audit` | Sends native commands (`PING/INFO`, PostgreSQL `StartupMessage` trust mode) to detect instances accessible with zero credentials. |
| `database_default_credentials` | Database Default Credential Audit | `protocol_audit` | Safely audits common default accounts (e.g. `postgres/postgres`, `root/root`) with immediate termination upon first match. |
| `database_connection_saturation` | Connection Pool Saturation Resilience | `resilience_stress` | Performs connection bursts to evaluate `max_connections` ceilings, rejection behavior, and pool starvation resilience. |

---

## 3. Protocol Probes & Handshakes

### A. PostgreSQL (Port 5432)
1. **SSLRequest Probe**: Sends standard 8-byte packet `00 00 00 08 04 d2 16 2f`.
   - Reads 1-byte server reply:
     - `'S'` (`0x53`): Server supports TLS.
     - `'N'` (`0x4e`): Server does NOT support TLS (unencrypted plaintext allowed).
2. **Cleartext StartupMessage Probe**: Sends standard protocol 3.0 StartupMessage.
   - If server accepts connection without TLS (`authCode: 0`), flags trust authentication and lack of TLS enforcement.
   - If server returns `ErrorResponse` requiring TLS, verifies `tlsMandated: true`.

### B. Redis (Port 6379)
1. **PING / INFO Probe**: Sends RESP `PING\r\n`.
   - If server responds with `+PONG`, unauthenticated access is permitted (`CRITICAL REDIS_UNAUTHENTICATED_ACCESS`).
   - Gathers version, OS, and uptime via `INFO server\r\n`.
2. **AUTH Probe**: If `-NOAUTH` is returned, audits common default passwords with immediate abort.

### C. MySQL (Port 3306)
1. **HandshakeV10 Inspection**: Server sends initial handshake packet upon TCP connection.
   - Inspects `CLIENT_SSL = 0x00000800` capability bit (bit 11).
   - If `CLIENT_SSL` is absent, server cannot negotiate TLS.
   - Extracts server version and default authentication plugin (e.g. `caching_sha2_password`, `mysql_native_password`).

### D. Connection Saturation Resilience
- Concurrently opens bursts of TCP connections (default 25-50) up to target limit.
- Measures connection acceptance rate, rejection reasons (`ECONNREFUSED`, `ETIMEDOUT`, or connection limits), and graceful error handling.
- Deterministically cleans up all sockets in `finally` blocks to prevent descriptor leaks.

---

## 4. Usage Example

```typescript
import { DatabaseSecurityEngine } from '@security-lab/db-security';

const engine = new DatabaseSecurityEngine();

const result = await engine.execute(
  {
    targetUrl: 'postgres://127.0.0.1:5432',
    options: {
      checkTls: true,
      checkAuth: true,
      testSaturation: true,
      saturationTargetConnections: 25,
      timeoutMs: 3000,
    },
  },
  {
    executionId: 'exec-db-001',
    testRunId: 'run-db-001',
    target: {
      id: 'target-postgres',
      baseUrl: 'postgres://127.0.0.1:5432',
      scope: {
        allowedHosts: ['127.0.0.1'],
        allowedPorts: [5432],
        allowPrivateIps: true,
        excludedPaths: [],
      },
    },
  }
);

console.log(result.findings);
```

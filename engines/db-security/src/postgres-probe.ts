import net from 'node:net';
import { RawProbeResult } from './types.js';

/**
 * 8-byte PostgreSQL SSLRequest packet:
 * Int32(8) + Int32(80877103) -> 00 00 00 08 04 d2 16 2f
 */
const PG_SSL_REQUEST = Buffer.from([0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f]);

export interface PostgresProbeOptions {
  host: string;
  port: number;
  timeoutMs?: number;
  testDefaultCredentials?: boolean;
}

/**
 * Connects to PostgreSQL directly via raw TCP socket, tests for SSLRequest negotiation,
 * verifies whether unencrypted connections are permitted, and optionally tests default credentials.
 */
export async function probePostgres(options: PostgresProbeOptions): Promise<RawProbeResult> {
  const { host, port, timeoutMs = 5000, testDefaultCredentials = true } = options;
  const startTime = Date.now();

  let tlsSupported = false;
  let tlsMandated = false;
  let unauthenticatedAccessAllowed = false;
  let defaultCredentialsMatched = false;
  let matchedCredentialUser: string | undefined;
  let serverVersion: string | undefined;
  let authMethod: string | undefined;
  let rawBannerHex: string | undefined;

  // Step 1: Probe SSLRequest
  try {
    const sslByte = await new Promise<string>((resolve, reject) => {
      const socket = net.connect({ host, port }, () => {
        socket.write(PG_SSL_REQUEST);
      });

      const timer = setTimeout(() => {
        socket.destroy();
        reject(new Error(`Postgres probe timed out after ${timeoutMs}ms`));
      }, timeoutMs);

      socket.once('data', (data: Buffer) => {
        clearTimeout(timer);
        const char = String.fromCharCode(data[0] || 0);
        rawBannerHex = data.toString('hex');
        socket.destroy();
        resolve(char);
      });

      socket.once('error', (err) => {
        clearTimeout(timer);
        socket.destroy();
        reject(err);
      });
    });

    if (sslByte === 'S') {
      tlsSupported = true;
    } else if (sslByte === 'N') {
      tlsSupported = false;
      tlsMandated = false;
    }
  } catch (err: any) {
    return {
      success: false,
      tlsSupported: false,
      tlsMandated: false,
      unauthenticatedAccessAllowed: false,
      defaultCredentialsMatched: false,
      error: err.message || 'Failed to connect to PostgreSQL endpoint',
      latencyMs: Date.now() - startTime,
    };
  }

  // Step 2: Cleartext StartupMessage probe to test TLS enforcement and default/trust auth
  if (testDefaultCredentials) {
    try {
      const startupResult = await new Promise<{
      responseType: string;
      authCode?: number;
      errorMessage?: string;
    }>((resolve, reject) => {
      const socket = net.connect({ host, port }, () => {
        // StartupMessage (protocol 3.0) with user 'postgres' and database 'postgres'
        const params = 'user\0postgres\0database\0postgres\0\0';
        const paramBuf = Buffer.from(params, 'utf-8');
        const totalLen = 4 + 4 + paramBuf.length;
        const startupBuf = Buffer.alloc(totalLen);
        startupBuf.writeInt32BE(totalLen, 0);
        startupBuf.writeInt32BE(196608, 4); // Protocol 3.0
        paramBuf.copy(startupBuf, 8);

        socket.write(startupBuf);
      });

      const timer = setTimeout(() => {
        socket.destroy();
        reject(new Error('Postgres startup message probe timed out'));
      }, timeoutMs);

      socket.once('data', (data: Buffer) => {
        clearTimeout(timer);
        const type = String.fromCharCode(data[0] || 0);
        let authCode: number | undefined;
        let errorMessage: string | undefined;

        if (type === 'R' && data.length >= 9) {
          authCode = data.readInt32BE(5);
        } else if (type === 'E') {
          errorMessage = data.toString('utf-8');
        }

        socket.destroy();
        resolve({ responseType: type, authCode, errorMessage });
      });

      socket.once('error', (err) => {
        clearTimeout(timer);
        socket.destroy();
        reject(err);
      });
    });

    if (startupResult.responseType === 'E') {
      const errMsg = startupResult.errorMessage?.toLowerCase() || '';
      if (errMsg.includes('ssl') || errMsg.includes('encryption') || errMsg.includes('tls required')) {
        tlsMandated = true;
      }
    } else if (startupResult.responseType === 'R') {
      // Server accepted non-SSL StartupMessage without rejecting for missing SSL!
      tlsMandated = false;

      // authCode: 0 = AuthenticationOk (trust authentication!), 3 = CleartextPassword, 5 = MD5Password, 10 = SASL (SCRAM)
      if (startupResult.authCode === 0) {
        unauthenticatedAccessAllowed = true;
        defaultCredentialsMatched = true;
        matchedCredentialUser = 'postgres (trust)';
        authMethod = 'trust';
      } else if (startupResult.authCode === 3) {
        authMethod = 'cleartext_password';
      } else if (startupResult.authCode === 5) {
        authMethod = 'md5';
      } else if (startupResult.authCode === 10) {
        authMethod = 'scram_sha_256';
      }
    }
  } catch {
    // If startup message fails or is rejected, continue with available information
  }
}

  return {
    success: true,
    tlsSupported,
    tlsMandated,
    unauthenticatedAccessAllowed,
    defaultCredentialsMatched,
    matchedCredentialUser,
    serverVersion,
    authMethod,
    rawBannerHex,
    latencyMs: Date.now() - startTime,
    details: {
      protocolVersion: '3.0',
      sslByteReceived: tlsSupported ? 'S' : 'N',
    },
  };
}

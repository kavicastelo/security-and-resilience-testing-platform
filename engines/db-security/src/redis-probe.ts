import net from 'node:net';
import { RawProbeResult } from './types.js';

export interface RedisProbeOptions {
  host: string;
  port: number;
  timeoutMs?: number;
  testDefaultCredentials?: boolean;
}

/**
 * Connects to Redis via raw socket, sends RESP commands (PING, INFO, AUTH)
 * to detect unauthenticated instances, weak default credentials, and server metadata.
 */
export async function probeRedis(options: RedisProbeOptions): Promise<RawProbeResult> {
  const { host, port, timeoutMs = 5000, testDefaultCredentials = true } = options;
  const startTime = Date.now();

  let unauthenticatedAccessAllowed = false;
  let defaultCredentialsMatched = false;
  let matchedCredentialUser: string | undefined;
  let serverVersion: string | undefined;
  let rawBannerHex: string | undefined;
  const details: Record<string, unknown> = {};

  try {
    const pingResponse = await new Promise<string>((resolve, reject) => {
      const socket = net.connect({ host, port }, () => {
        socket.write('PING\r\n');
      });

      const timer = setTimeout(() => {
        socket.destroy();
        reject(new Error(`Redis probe timed out after ${timeoutMs}ms`));
      }, timeoutMs);

      socket.once('data', (data: Buffer) => {
        clearTimeout(timer);
        rawBannerHex = data.toString('hex');
        const text = data.toString('utf-8');
        socket.destroy();
        resolve(text);
      });

      socket.once('error', (err) => {
        clearTimeout(timer);
        socket.destroy();
        reject(err);
      });
    });

    if (pingResponse.startsWith('+PONG') || pingResponse.includes('PONG')) {
      // Unauthenticated instance! Full open access.
      unauthenticatedAccessAllowed = true;
      defaultCredentialsMatched = true;
      matchedCredentialUser = 'none (unauthenticated)';

      // Fetch server info
      try {
        const infoResponse = await new Promise<string>((resolve) => {
          const socket = net.connect({ host, port }, () => {
            socket.write('INFO server\r\n');
          });

          const timer = setTimeout(() => {
            socket.destroy();
            resolve('');
          }, 1500);

          socket.once('data', (data: Buffer) => {
            clearTimeout(timer);
            socket.destroy();
            resolve(data.toString('utf-8'));
          });

          socket.once('error', () => {
            clearTimeout(timer);
            socket.destroy();
            resolve('');
          });
        });

        const vMatch = /redis_version:([^\r\n]+)/i.exec(infoResponse);
        if (vMatch && vMatch[1]) {
          serverVersion = vMatch[1].trim();
          details.serverVersion = serverVersion;
        }

        const osMatch = /os:([^\r\n]+)/i.exec(infoResponse);
        if (osMatch && osMatch[1]) {
          details.os = osMatch[1].trim();
        }
      } catch {
        // Non-critical if INFO fails
      }
    } else if (pingResponse.includes('NOAUTH') && testDefaultCredentials) {
      // Authentication is enabled; test common default passwords
      const weakPasswords = ['redis', 'root', 'admin', 'password', '123456'];
      for (const pass of weakPasswords) {
        try {
          const authResult = await new Promise<boolean>((resolve) => {
            const socket = net.connect({ host, port }, () => {
              socket.write(`AUTH ${pass}\r\n`);
            });

            const timer = setTimeout(() => {
              socket.destroy();
              resolve(false);
            }, 1000);

            socket.once('data', (data: Buffer) => {
              clearTimeout(timer);
              socket.destroy();
              const str = data.toString('utf-8');
              resolve(str.startsWith('+OK'));
            });

            socket.once('error', () => {
              clearTimeout(timer);
              socket.destroy();
              resolve(false);
            });
          });

          if (authResult) {
            defaultCredentialsMatched = true;
            matchedCredentialUser = `default (password: ${pass})`;
            break;
          }
        } catch {
          break;
        }
      }
    }
  } catch (err: any) {
    return {
      success: false,
      tlsSupported: false,
      tlsMandated: false,
      unauthenticatedAccessAllowed: false,
      defaultCredentialsMatched: false,
      error: err.message || 'Failed to connect to Redis endpoint',
      latencyMs: Date.now() - startTime,
    };
  }

  return {
    success: true,
    tlsSupported: false, // Standard Redis port 6379 is cleartext; 6380 is rediss
    tlsMandated: false,
    unauthenticatedAccessAllowed,
    defaultCredentialsMatched,
    matchedCredentialUser,
    serverVersion,
    rawBannerHex,
    latencyMs: Date.now() - startTime,
    details,
  };
}

import net from 'node:net';
import { RawProbeResult } from './types.js';

export interface MySqlProbeOptions {
  host: string;
  port: number;
  timeoutMs?: number;
}

const CLIENT_SSL = 0x00000800; // Bit 11 of capability flags

/**
 * Connects to MySQL, parses the server's initial HandshakeV10 packet,
 * inspects CLIENT_SSL capability, server version, and default auth plugin.
 */
export async function probeMySql(options: MySqlProbeOptions): Promise<RawProbeResult> {
  const { host, port, timeoutMs = 5000 } = options;
  const startTime = Date.now();

  let tlsSupported = false;
  let serverVersion: string | undefined;
  let authMethod: string | undefined;
  let rawBannerHex: string | undefined;
  const details: Record<string, unknown> = {};

  try {
    const handshakeData = await new Promise<Buffer>((resolve, reject) => {
      const socket = net.connect({ host, port });

      const timer = setTimeout(() => {
        socket.destroy();
        reject(new Error(`MySQL probe timed out after ${timeoutMs}ms`));
      }, timeoutMs);

      socket.once('data', (data: Buffer) => {
        clearTimeout(timer);
        socket.destroy();
        resolve(data);
      });

      socket.once('error', (err) => {
        clearTimeout(timer);
        socket.destroy();
        reject(err);
      });
    });

    rawBannerHex = handshakeData.toString('hex');

    // Parse HandshakeV10
    // Byte 0-2: length, Byte 3: seq id, Byte 4: protocol version
    if (handshakeData.length > 5) {
      const protocolVersion = handshakeData[4];
      details.protocolVersion = protocolVersion;

      // Find null terminator for server version string starting at offset 5
      const nullIdx = handshakeData.indexOf(0x00, 5);
      if (nullIdx !== -1) {
        serverVersion = handshakeData.subarray(5, nullIdx).toString('utf-8');
        details.serverVersion = serverVersion;

        // After null terminator: 4 bytes connectionId + 8 bytes auth_plugin_data_part_1 + 1 byte filter = 13 bytes
        const capsLowerOffset = nullIdx + 1 + 13;
        if (handshakeData.length >= capsLowerOffset + 2) {
          const lowerCaps = handshakeData.readUInt16LE(capsLowerOffset);
          let upperCaps = 0;

          // Upper capability flags are 2 bytes after collation (1 byte) and status flags (2 bytes) = 3 bytes
          const capsUpperOffset = capsLowerOffset + 2 + 1 + 2;
          if (handshakeData.length >= capsUpperOffset + 2) {
            upperCaps = handshakeData.readUInt16LE(capsUpperOffset);
          }

          const capabilities = lowerCaps | (upperCaps << 16);
          details.capabilities = capabilities;

          if ((capabilities & CLIENT_SSL) !== 0) {
            tlsSupported = true;
          }

          // Extract auth plugin name (either via known plugin signatures or trailing packet string)
          const knownPlugins = [
            'mysql_native_password',
            'caching_sha2_password',
            'sha256_password',
            'mysql_clear_password',
            'dialog',
            'auth_gssapi_client',
          ];
          const fullText = handshakeData.toString('utf-8');
          for (const plugin of knownPlugins) {
            if (fullText.includes(plugin)) {
              authMethod = plugin;
              details.authPlugin = authMethod;
              break;
            }
          }

          if (!authMethod && handshakeData.length > 30) {
            const trailingSlice = handshakeData.subarray(handshakeData.length - 64);
            const parts = trailingSlice
              .toString('utf-8')
              .split('\0')
              .map((s) => s.trim())
              .filter((s) => s.length >= 4);
            if (parts.length > 0) {
              authMethod = parts[parts.length - 1];
              details.authPlugin = authMethod;
            }
          }
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
      error: err.message || 'Failed to connect to MySQL endpoint',
      latencyMs: Date.now() - startTime,
    };
  }

  return {
    success: true,
    tlsSupported,
    tlsMandated: false,
    unauthenticatedAccessAllowed: false,
    defaultCredentialsMatched: false,
    serverVersion,
    authMethod,
    rawBannerHex,
    latencyMs: Date.now() - startTime,
    details,
  };
}

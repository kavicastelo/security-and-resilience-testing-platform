import net from 'node:net';
import { DatabaseSaturationSummary } from './types.js';

export interface SaturationTestOptions {
  host: string;
  port: number;
  targetConnections?: number;
  timeoutMs?: number;
}

/**
 * Concurrently opens a burst of TCP connections up to targetConnections
 * to assess database connection limit ceilings, rejection behavior, and resilience.
 */
export async function testConnectionSaturation(
  options: SaturationTestOptions,
): Promise<DatabaseSaturationSummary> {
  const { host, port, targetConnections = 25, timeoutMs = 3000 } = options;
  const sockets: net.Socket[] = [];
  const latencies: number[] = [];
  let successfulConnections = 0;
  let rejectedConnections = 0;
  let rejectionReason: string | undefined;

  try {
    const connectionPromises = Array.from({ length: targetConnections }, () => {
      return new Promise<void>((resolve) => {
        const start = Date.now();
        let isSettled = false;

        const socket = net.connect({ host, port }, () => {
          if (!isSettled) {
            isSettled = true;
            successfulConnections++;
            latencies.push(Date.now() - start);
            sockets.push(socket);
            resolve();
          }
        });

        const timer = setTimeout(() => {
          if (!isSettled) {
            isSettled = true;
            rejectedConnections++;
            rejectionReason = rejectionReason || 'Connection timed out under saturation load';
            try {
              socket.destroy();
            } catch {
              // ignore
            }
            resolve();
          }
        }, timeoutMs);

        socket.on('error', (err) => {
          if (!isSettled) {
            isSettled = true;
            clearTimeout(timer);
            rejectedConnections++;
            rejectionReason = rejectionReason || err.message;
            try {
              socket.destroy();
            } catch {
              // ignore
            }
            resolve();
          }
        });
      });
    });

    await Promise.all(connectionPromises);
  } finally {
    // Deterministic cleanup: close all active connection sockets
    for (const socket of sockets) {
      try {
        socket.destroy();
      } catch {
        // ignore
      }
    }
  }

  const avgConnectionTimeMs =
    latencies.length > 0 ? Math.round(latencies.reduce((a, b) => a + b, 0) / latencies.length) : 0;

  // If rejections occurred gracefully (via fast error/reset rather than timeouts), server is graceful
  const serverGraceful =
    rejectedConnections === 0 || (rejectionReason !== undefined && !rejectionReason.includes('timed out'));

  return {
    attemptedConnections: targetConnections,
    successfulConnections,
    rejectedConnections,
    rejectionReason,
    avgConnectionTimeMs,
    serverGraceful,
  };
}

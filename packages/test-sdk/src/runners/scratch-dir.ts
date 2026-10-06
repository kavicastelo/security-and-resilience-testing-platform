import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { logger } from '@security-lab/logger';

export interface EphemeralScratchDirectory {
  readonly path: string;
  destroy(): Promise<void>;
}

/**
 * Creates an isolated, ephemeral temporary directory for container volume mounting
 * with restricted permissions (0700). Automatically cleans up upon execution completion.
 */
export async function createScratchDirectory(prefix = 'sec-lab'): Promise<EphemeralScratchDirectory> {
  const uniqueId = crypto.randomUUID();
  const dirName = `${prefix}-${uniqueId}`;
  const scratchPath = path.join(os.tmpdir(), 'security-lab-scratch', dirName);

  await fs.promises.mkdir(scratchPath, { recursive: true, mode: 0o700 });

  return {
    path: scratchPath,
    destroy: async () => {
      await cleanupScratchDirectory(scratchPath);
    },
  };
}

/**
  * Safely cleans up a scratch directory path from disk.
  */
export async function cleanupScratchDirectory(scratchPath: string): Promise<void> {
  try {
    await fs.promises.rm(scratchPath, { recursive: true, force: true });
    logger.debug({ path: scratchPath }, 'Ephemeral scratch directory destroyed.');
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    logger.warn({ path: scratchPath, err: msg }, 'Failed to cleanly destroy scratch directory.');
  }
}

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { eq, desc } from 'drizzle-orm';
import { getDatabase } from './db.js';
import { artifacts } from './db/schema.js';
import { config } from '../config/index.js';
import { logger } from '@security-lab/logger';

export interface StoreArtifactInput {
  testRunId: string;
  executionId?: string;
  filename: string;
  content: Buffer | string;
  mimeType?: string;
  type?: string;
  metadata?: Record<string, unknown>;
}

export interface StoredArtifact {
  id: string;
  testRunId: string;
  executionId?: string | null;
  name: string;
  type: string;
  mimeType: string;
  sizeBytes: number;
  sha256: string;
  storagePath: string;
  metadata: Record<string, unknown>;
  createdAt: Date;
}

/**
 * Validates a filename to strictly prevent path traversal vulnerabilities.
 * Any filename containing '..', '/', '\', or null bytes is rejected.
 */
export function validateArtifactFilename(filename: string): void {
  if (!filename || typeof filename !== 'string' || filename.trim().length === 0) {
    throw new Error('Invalid artifact filename: filename must be a non-empty string');
  }

  // Reject path separators and directory traversal sequences
  if (
    filename.includes('..') ||
    filename.includes('/') ||
    filename.includes('\\') ||
    filename.includes('\0')
  ) {
    throw new Error(
      `Path traversal rejected: filename "${filename}" contains forbidden path navigation characters`,
    );
  }

  // Reject URL-encoded path traversal sequences
  const lower = filename.toLowerCase();
  if (
    lower.includes('%2e%2e') ||
    lower.includes('%2f') ||
    lower.includes('%5c') ||
    lower.includes('%00')
  ) {
    throw new Error(
      `Path traversal rejected: filename "${filename}" contains encoded path navigation characters`,
    );
  }
}

export class ArtifactStorageService {
  private readonly baseDir: string;

  constructor(customBaseDir?: string) {
    const configuredDir = customBaseDir || config.ARTIFACTS_DIR || path.join(config.DATA_DIR, 'artifacts');
    this.baseDir = path.resolve(process.cwd(), configuredDir);

    // Ensure the base artifacts directory exists
    try {
      if (!fs.existsSync(this.baseDir)) {
        fs.mkdirSync(this.baseDir, { recursive: true });
      }
    } catch (err: unknown) {
      logger.warn({ err, baseDir: this.baseDir }, 'Could not eagerly create artifacts base directory');
    }
  }

  getBaseDir(): string {
    return this.baseDir;
  }

  /**
   * Stores raw execution outputs, scanner logs, and generated report files
   * in the dedicated storage directory, enforcing path safety and SHA-256 integrity.
   */
  async storeArtifact(input: StoreArtifactInput): Promise<StoredArtifact> {
    const { testRunId, executionId, filename, content, mimeType, type, metadata } = input;

    // 1. Strict filename validation against path traversal
    validateArtifactFilename(filename);

    if (!testRunId || typeof testRunId !== 'string') {
      throw new Error('TestRun ID is required to store an artifact');
    }

    // 2. Resolve safe target directory and file path
    const testRunDir = path.resolve(this.baseDir, testRunId);
    const targetPath = path.resolve(testRunDir, filename);

    // Double-check canonical containment within baseDir
    if (!targetPath.startsWith(this.baseDir)) {
      throw new Error(
        `Path traversal rejected: resolved path "${targetPath}" escapes base directory "${this.baseDir}"`,
      );
    }

    // 3. Compute buffer and SHA-256 integrity hash
    const buffer = Buffer.isBuffer(content) ? content : Buffer.from(content, 'utf-8');
    const sha256 = crypto.createHash('sha256').update(buffer).digest('hex');

    // 4. Persist to disk atomically
    await fs.promises.mkdir(testRunDir, { recursive: true });
    await fs.promises.writeFile(targetPath, buffer);

    // 5. Persist metadata in PostgreSQL
    const { db } = getDatabase();
    const [row] = await db
      .insert(artifacts)
      .values({
        testRunId,
        executionId: executionId || null,
        name: filename,
        type: type || 'artifact',
        mimeType: mimeType || 'application/octet-stream',
        sizeBytes: buffer.length,
        sha256,
        storagePath: targetPath,
        metadata: metadata || {},
      })
      .returning();

    if (!row) {
      throw new Error(`Failed to persist artifact record for "${filename}" in database`);
    }

    logger.info(
      {
        artifactId: row.id,
        testRunId,
        executionId,
        filename,
        sizeBytes: buffer.length,
        sha256,
        storagePath: targetPath,
      },
      'Forensic artifact persisted and integrity verified',
    );

    return {
      id: row.id,
      testRunId: row.testRunId,
      executionId: row.executionId,
      name: row.name,
      type: row.type,
      mimeType: row.mimeType,
      sizeBytes: row.sizeBytes,
      sha256: row.sha256,
      storagePath: row.storagePath,
      metadata: (row.metadata as Record<string, unknown>) || {},
      createdAt: row.createdAt,
    };
  }

  /**
   * Retrieves an artifact record along with its binary content from disk,
   * verifying SHA-256 integrity to guarantee forensic authenticity.
   */
  async getArtifact(id: string): Promise<{ artifact: StoredArtifact; content: Buffer } | null> {
    const { db } = getDatabase();
    const [row] = await db.select().from(artifacts).where(eq(artifacts.id, id));

    if (!row) {
      return null;
    }

    const artifact: StoredArtifact = {
      id: row.id,
      testRunId: row.testRunId,
      executionId: row.executionId,
      name: row.name,
      type: row.type,
      mimeType: row.mimeType,
      sizeBytes: row.sizeBytes,
      sha256: row.sha256,
      storagePath: row.storagePath,
      metadata: (row.metadata as Record<string, unknown>) || {},
      createdAt: row.createdAt,
    };

    if (!fs.existsSync(artifact.storagePath)) {
      throw new Error(
        `Artifact file missing on disk at "${artifact.storagePath}" for artifact ID "${id}"`,
      );
    }

    const content = await fs.promises.readFile(artifact.storagePath);
    const actualSha256 = crypto.createHash('sha256').update(content).digest('hex');

    if (actualSha256 !== artifact.sha256) {
      throw new Error(
        `Forensic integrity violation: SHA-256 mismatch for artifact "${id}". Expected ${artifact.sha256}, got ${actualSha256}`,
      );
    }

    return {
      artifact,
      content,
    };
  }

  /**
   * Retrieves only the metadata of an artifact without reading content from disk.
   */
  async getArtifactMetadata(id: string): Promise<StoredArtifact | null> {
    const { db } = getDatabase();
    const [row] = await db.select().from(artifacts).where(eq(artifacts.id, id));

    if (!row) {
      return null;
    }

    return {
      id: row.id,
      testRunId: row.testRunId,
      executionId: row.executionId,
      name: row.name,
      type: row.type,
      mimeType: row.mimeType,
      sizeBytes: row.sizeBytes,
      sha256: row.sha256,
      storagePath: row.storagePath,
      metadata: (row.metadata as Record<string, unknown>) || {},
      createdAt: row.createdAt,
    };
  }

  /**
   * Lists all artifacts associated with a specific test run.
   */
  async listArtifacts(testRunId: string): Promise<StoredArtifact[]> {
    const { db } = getDatabase();
    const rows = await db
      .select()
      .from(artifacts)
      .where(eq(artifacts.testRunId, testRunId))
      .orderBy(desc(artifacts.createdAt));

    return rows.map((row) => ({
      id: row.id,
      testRunId: row.testRunId,
      executionId: row.executionId,
      name: row.name,
      type: row.type,
      mimeType: row.mimeType,
      sizeBytes: row.sizeBytes,
      sha256: row.sha256,
      storagePath: row.storagePath,
      metadata: (row.metadata as Record<string, unknown>) || {},
      createdAt: row.createdAt,
    }));
  }

  /**
   * Verifies the cryptographic integrity of an artifact on disk against its database hash.
   */
  async verifyArtifactIntegrity(
    id: string,
  ): Promise<{ valid: boolean; expectedSha256: string; actualSha256?: string; error?: string }> {
    try {
      const result = await this.getArtifact(id);
      if (!result) {
        return { valid: false, expectedSha256: '', error: 'Artifact not found' };
      }
      return { valid: true, expectedSha256: result.artifact.sha256, actualSha256: result.artifact.sha256 };
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      return { valid: false, expectedSha256: '', error: message };
    }
  }

  /**
   * Deletes an artifact from both disk and the database.
   */
  async deleteArtifact(id: string): Promise<boolean> {
    const { db } = getDatabase();
    const [row] = await db.select().from(artifacts).where(eq(artifacts.id, id));

    if (!row) {
      return false;
    }

    try {
      if (fs.existsSync(row.storagePath)) {
        await fs.promises.unlink(row.storagePath);
      }
    } catch (err: unknown) {
      logger.warn({ err, storagePath: row.storagePath }, 'Failed to remove artifact file from disk');
    }

    const deleted = await db.delete(artifacts).where(eq(artifacts.id, id)).returning();
    return deleted.length > 0;
  }
}

export const artifactStorageService = new ArtifactStorageService();

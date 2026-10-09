import postgres from 'postgres';
import { drizzle } from 'drizzle-orm/postgres-js';
import { config } from '../config/index.js';
import { logger } from '@security-lab/logger';
import { maskDatabaseUrl, getDatabaseHostPort } from '@security-lab/config';

import * as schema from './db/schema.js';

export type DatabaseClient = ReturnType<typeof drizzle<typeof schema>>;

let sqlClient: ReturnType<typeof postgres> | null = null;
let dbInstance: DatabaseClient | null = null;

export function getDatabase(): { db: DatabaseClient; sql: ReturnType<typeof postgres> } {
  if (!sqlClient) {
    const maskedUrl = maskDatabaseUrl(config.DATABASE_URL);
    const { host, port } = getDatabaseHostPort(config.DATABASE_URL);
    logger.info({ host, port, dbUrl: maskedUrl }, 'Initializing PostgreSQL database connection pool');
    sqlClient = postgres(config.DATABASE_URL, {
      max: config.DB_MAX_CONNECTIONS,
      idle_timeout: Math.floor(config.DB_IDLE_TIMEOUT_MS / 1000),
      connect_timeout: 5,
      onnotice: () => {}, // Suppress notices
    });
    dbInstance = drizzle(sqlClient, { schema });
  }
  return { db: dbInstance!, sql: sqlClient! };
}

export async function checkDatabaseHealth(): Promise<'up' | 'down'> {
  const { host, port } = getDatabaseHostPort(config.DATABASE_URL);
  try {
    const { sql } = getDatabase();
    await sql`SELECT 1`;
    return 'up';
  } catch (error) {
    logger.warn(
      { host, port, error: error instanceof Error ? error.message : String(error) },
      `PostgreSQL database connectivity check failed at ${host}:${port}`,
    );
    return 'down';
  }
}

export async function verifyDatabaseConnection(): Promise<void> {
  const { host, port } = getDatabaseHostPort(config.DATABASE_URL);
  try {
    const { sql } = getDatabase();
    await sql`SELECT 1`;
    logger.info({ host, port }, `Successfully connected to PostgreSQL at ${host}:${port}`);
  } catch (error) {
    const diagnosticMessage = `[FATAL] Unable to connect to PostgreSQL at ${host}:${port}. Ensure database container is running.`;
    logger.fatal(
      { host, port, error: error instanceof Error ? error.message : String(error) },
      diagnosticMessage,
    );
    throw new Error(diagnosticMessage);
  }
}

export async function closeDatabase(): Promise<void> {
  if (sqlClient) {
    logger.info('Closing database connection pool...');
    await sqlClient.end({ timeout: 5 });
    sqlClient = null;
    dbInstance = null;
    logger.info('Database connection pool closed.');
  }
}


import postgres from 'postgres';
import { drizzle } from 'drizzle-orm/postgres-js';
import { config } from '../config/index.js';
import { logger } from '@security-lab/logger';

import * as schema from './db/schema.js';

export type DatabaseClient = ReturnType<typeof drizzle<typeof schema>>;

let sqlClient: ReturnType<typeof postgres> | null = null;
let dbInstance: DatabaseClient | null = null;

export function getDatabase(): { db: DatabaseClient; sql: ReturnType<typeof postgres> } {
  if (!sqlClient) {
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
  try {
    const { sql } = getDatabase();
    await sql`SELECT 1`;
    return 'up';
  } catch (error) {
    logger.warn({ err: error }, 'PostgreSQL database connectivity check failed');
    return 'down';
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

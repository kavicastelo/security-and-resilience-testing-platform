import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import postgres from 'postgres';
import { config } from '../src/config/index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function runMigrations() {
  const sql = postgres(config.DATABASE_URL, { max: 1 });

  try {
    console.info('Connecting to database...');
    await sql`SELECT 1`;
    console.info('Connected.');

    // Create migrations tracker table if not exists
    await sql`
      CREATE TABLE IF NOT EXISTS _schema_migrations (
        version VARCHAR(255) PRIMARY KEY,
        applied_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      );
    `;

    const migrationsDir = path.resolve(__dirname, '../../../infrastructure/postgres/migrations');
    const files = fs.readdirSync(migrationsDir)
      .filter((f) => f.endsWith('.sql'))
      .sort();

    const applied = await sql<{ version: string }[]>`SELECT version FROM _schema_migrations`;
    const appliedSet = new Set(applied.map((r) => r.version));

    for (const file of files) {
      if (appliedSet.has(file)) {
        console.info(`Migration ${file} already applied.`);
        continue;
      }

      console.info(`Applying migration ${file}...`);
      const filePath = path.join(migrationsDir, file);
      const sqlContent = fs.readFileSync(filePath, 'utf8');

      await sql.begin(async (tx) => {
        await tx.unsafe(sqlContent);
        await tx`INSERT INTO _schema_migrations (version) VALUES (${file})`;
      });

      console.info(`Applied migration ${file} successfully.`);
    }

    console.info('All migrations applied successfully.');
  } catch (err) {
    console.error('Migration error:', err);
    process.exit(1);
  } finally {
    await sql.end();
  }
}

runMigrations();

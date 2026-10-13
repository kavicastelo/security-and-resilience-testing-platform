import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import postgres from 'postgres';
import { config } from '../src/config/index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function testMigration() {
  const sql = postgres(config.DATABASE_URL, { max: 1 });
  try {
    const downPath = path.resolve(__dirname, '../../../infrastructure/postgres/migrations/012_workspaces_and_rbac.down.sql');
    const upPath = path.resolve(__dirname, '../../../infrastructure/postgres/migrations/012_workspaces_and_rbac.sql');

    console.log('1. Applying rollback (down)...');
    const downSql = fs.readFileSync(downPath, 'utf8');
    await sql.unsafe(downSql);
    console.log('Rollback applied cleanly.');

    console.log('2. Applying migration forward (up)...');
    const upSql = fs.readFileSync(upPath, 'utf8');
    await sql.unsafe(upSql);
    await sql.unsafe(`INSERT INTO _schema_migrations (version) VALUES ('012_workspaces_and_rbac.sql') ON CONFLICT DO NOTHING`);
    console.log('Migration 012 forward applied cleanly.');
  } catch (err) {
    console.error('Migration test error:', err);
    process.exit(1);
  } finally {
    await sql.end();
  }
}

testMigration();

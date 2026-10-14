import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { getDatabase, closeDatabase } from '../src/services/db.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function run() {
  const { sql } = getDatabase();
  const upSql = fs.readFileSync(
    path.resolve(__dirname, '../src/db/migrations/017_webhooks_queue.sql'),
    'utf-8',
  );
  const downSql = fs.readFileSync(
    path.resolve(__dirname, '../src/db/migrations/017_webhooks_queue.down.sql'),
    'utf-8',
  );

  console.log('Testing rollback (down)...');
  await sql.unsafe(downSql);
  console.log('Rollback down migration executed successfully.');

  console.log('Testing forward migration (up)...');
  await sql.unsafe(upSql);
  console.log('Forward migration executed successfully.');

  // Verify tables exist
  const tables = await sql<{ table_name: string }[]>`
    SELECT table_name
    FROM information_schema.tables
    WHERE table_name IN ('webhooks', 'webhook_deliveries')
      AND table_schema = 'public';
  `;
  console.log('Found tables:', tables.map((t) => t.table_name));
  if (tables.length !== 2) {
    throw new Error(`Expected 2 tables (webhooks, webhook_deliveries), found ${tables.length}`);
  }

  await closeDatabase();
  console.log('Migration 017 verification passed completely!');
}

run().catch((err) => {
  console.error('Migration 017 test failed:', err);
  process.exit(1);
});

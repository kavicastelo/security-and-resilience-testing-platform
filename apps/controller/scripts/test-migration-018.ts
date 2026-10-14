import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { getDatabase, closeDatabase } from '../src/services/db.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function run() {
  const { sql } = getDatabase();
  const upSql = fs.readFileSync(
    path.resolve(__dirname, '../src/db/migrations/018_ai_remediations.sql'),
    'utf-8',
  );
  const downSql = fs.readFileSync(
    path.resolve(__dirname, '../src/db/migrations/018_ai_remediations.down.sql'),
    'utf-8',
  );

  console.log('Testing rollback (down)...');
  await sql.unsafe(downSql);
  console.log('Rollback down migration executed successfully.');

  console.log('Testing forward migration (up)...');
  await sql.unsafe(upSql);
  console.log('Forward migration executed successfully.');

  // Verify table exists
  const tables = await sql<{ table_name: string }[]>`
    SELECT table_name
    FROM information_schema.tables
    WHERE table_name = 'ai_remediations'
      AND table_schema = 'public';
  `;
  console.log('Found tables:', tables.map((t) => t.table_name));
  if (tables.length !== 1) {
    throw new Error(`Expected 1 table (ai_remediations), found ${tables.length}`);
  }

  await closeDatabase();
  console.log('Migration 018 verification passed completely!');
}

run().catch((err) => {
  console.error('Migration 018 test failed:', err);
  process.exit(1);
});

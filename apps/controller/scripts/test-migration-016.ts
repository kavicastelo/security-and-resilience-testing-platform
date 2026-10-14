import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { getDatabase, closeDatabase } from '../src/services/db.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function run() {
  const { sql } = getDatabase();
  const upSql = fs.readFileSync(
    path.resolve(__dirname, '../src/db/migrations/016_finding_flapping_and_history.sql'),
    'utf-8',
  );
  const downSql = fs.readFileSync(
    path.resolve(__dirname, '../src/db/migrations/016_finding_flapping_and_history.down.sql'),
    'utf-8',
  );

  console.log('Testing rollback (down)...');
  await sql.unsafe(downSql);
  console.log('Rollback down migration executed successfully.');

  console.log('Testing forward migration (up)...');
  await sql.unsafe(upSql);
  console.log('Forward migration executed successfully.');

  // Verify new columns exist on findings
  const columns = await sql<{ column_name: string }[]>`
    SELECT column_name
    FROM information_schema.columns
    WHERE table_name = 'findings'
      AND column_name IN ('flapping_score', 'is_flapping', 'triage_history');
  `;
  console.log('Found columns on findings:', columns.map((c) => c.column_name));
  if (columns.length !== 3) {
    throw new Error(`Expected 3 columns on findings, found ${columns.length}`);
  }

  await closeDatabase();
  console.log('Migration 016 verification passed completely!');
}

run().catch((err) => {
  console.error('Migration 016 test failed:', err);
  process.exit(1);
});

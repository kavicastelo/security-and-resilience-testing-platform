import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { getDatabase, closeDatabase } from '../src/services/db.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function run() {
  const { sql } = getDatabase();
  const upSql = fs.readFileSync(
    path.resolve(__dirname, '../src/db/migrations/013_target_ownership_challenges.sql'),
    'utf-8',
  );
  const downSql = fs.readFileSync(
    path.resolve(__dirname, '../src/db/migrations/013_target_ownership_challenges.down.sql'),
    'utf-8',
  );

  console.log('Testing rollback (down)...');
  await sql.unsafe(downSql);
  console.log('Rollback down migration executed successfully.');

  console.log('Testing forward migration (up)...');
  await sql.unsafe(upSql);
  console.log('Forward migration executed successfully.');

  // Verify columns exist on targets
  const columns = await sql<{ column_name: string }[]>`
    SELECT column_name
    FROM information_schema.columns
    WHERE table_name = 'targets'
      AND column_name IN ('verification_token', 'verification_status', 'verified_at', 'verification_method');
  `;
  console.log('Found columns on targets:', columns.map((c) => c.column_name));
  if (columns.length !== 4) {
    throw new Error(`Expected 4 columns on targets, found ${columns.length}`);
  }

  // Verify target_profiles view exists
  const views = await sql<{ table_name: string }[]>`
    SELECT table_name
    FROM information_schema.views
    WHERE table_name = 'target_profiles';
  `;
  console.log('Found views:', views.map((v) => v.table_name));
  if (views.length !== 1) {
    throw new Error('Expected target_profiles view to exist');
  }

  await closeDatabase();
  console.log('Migration 013 verification passed completely!');
}

run().catch((err) => {
  console.error('Migration test failed:', err);
  process.exit(1);
});

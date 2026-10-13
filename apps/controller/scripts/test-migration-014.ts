import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { getDatabase, closeDatabase } from '../src/services/db.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function run() {
  const { sql } = getDatabase();
  const upSql = fs.readFileSync(
    path.resolve(__dirname, '../src/db/migrations/014_encrypted_target_credentials.sql'),
    'utf-8',
  );
  const downSql = fs.readFileSync(
    path.resolve(__dirname, '../src/db/migrations/014_encrypted_target_credentials.down.sql'),
    'utf-8',
  );

  console.log('Testing rollback (down)...');
  await sql.unsafe(downSql);
  console.log('Rollback down migration executed successfully.');

  console.log('Testing forward migration (up)...');
  await sql.unsafe(upSql);
  console.log('Forward migration executed successfully.');

  // Verify encrypted_auth_data column exists on targets
  const columns = await sql<{ column_name: string }[]>`
    SELECT column_name
    FROM information_schema.columns
    WHERE table_name = 'targets'
      AND column_name = 'encrypted_auth_data';
  `;
  console.log('Found columns on targets:', columns.map((c) => c.column_name));
  if (columns.length !== 1) {
    throw new Error(`Expected encrypted_auth_data column on targets, found ${columns.length}`);
  }

  // Verify target_profiles view exists and includes encrypted_auth_data
  const viewCols = await sql<{ column_name: string }[]>`
    SELECT column_name
    FROM information_schema.columns
    WHERE table_name = 'target_profiles'
      AND column_name = 'encrypted_auth_data';
  `;
  console.log('Found columns on target_profiles view:', viewCols.map((c) => c.column_name));
  if (viewCols.length !== 1) {
    throw new Error('Expected target_profiles view to include encrypted_auth_data column');
  }

  await closeDatabase();
  console.log('Migration 014 verification passed completely!');
}

run().catch((err) => {
  console.error('Migration test failed:', err);
  process.exit(1);
});

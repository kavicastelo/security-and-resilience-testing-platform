import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { getDatabase, closeDatabase } from '../src/services/db.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function run() {
  const { sql } = getDatabase();
  const upSql = fs.readFileSync(
    path.resolve(__dirname, '../src/db/migrations/019_saas_billing_and_sso.sql'),
    'utf-8',
  );
  const downSql = fs.readFileSync(
    path.resolve(__dirname, '../src/db/migrations/019_saas_billing_and_sso.down.sql'),
    'utf-8',
  );

  console.log('Testing rollback (down)...');
  await sql.unsafe(downSql);
  console.log('Rollback down migration executed successfully.');

  console.log('Testing forward migration (up)...');
  await sql.unsafe(upSql);
  console.log('Forward migration executed successfully.');

  // Verify columns exist on workspaces table
  const columns = await sql<{ column_name: string }[]>`
    SELECT column_name
    FROM information_schema.columns
    WHERE table_name = 'workspaces'
      AND column_name IN ('sso_config', 'stripe_customer_id', 'subscription_tier', 'quota_limits', 'usage_minutes');
  `;
  console.log('Found columns on workspaces:', columns.map((c) => c.column_name));
  if (columns.length !== 5) {
    throw new Error(`Expected 5 new columns on workspaces, found ${columns.length}`);
  }

  await closeDatabase();
  console.log('Migration 019 verification passed completely!');
}

run().catch((err) => {
  console.error('Migration 019 test failed:', err);
  process.exit(1);
});

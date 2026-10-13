import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { getDatabase, closeDatabase } from '../src/services/db.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function run() {
  const { sql } = getDatabase();
  const upSql = fs.readFileSync(
    path.resolve(__dirname, '../src/db/migrations/015_agent_fleet_attestation.sql'),
    'utf-8',
  );
  const downSql = fs.readFileSync(
    path.resolve(__dirname, '../src/db/migrations/015_agent_fleet_attestation.down.sql'),
    'utf-8',
  );

  console.log('Testing rollback (down)...');
  await sql.unsafe(downSql);
  console.log('Rollback down migration executed successfully.');

  console.log('Testing forward migration (up)...');
  await sql.unsafe(upSql);
  console.log('Forward migration executed successfully.');

  // Verify new columns exist on agents
  const columns = await sql<{ column_name: string }[]>`
    SELECT column_name
    FROM information_schema.columns
    WHERE table_name = 'agents'
      AND column_name IN ('public_key', 'fingerprint', 'enrollment_token', 'auth_mode');
  `;
  console.log('Found columns on agents:', columns.map((c) => c.column_name));
  if (columns.length !== 4) {
    throw new Error(`Expected 4 columns on agents, found ${columns.length}`);
  }

  await closeDatabase();
  console.log('Migration 015 verification passed completely!');
}

run().catch((err) => {
  console.error('Migration 015 test failed:', err);
  process.exit(1);
});

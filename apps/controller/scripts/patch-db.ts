import { getDatabase, closeDatabase } from '../src/services/db.js';

async function patch() {
  const { sql } = getDatabase();
  await sql`
    ALTER TABLE policies
    ADD COLUMN IF NOT EXISTS required_profiles JSONB NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS waivers JSONB NOT NULL DEFAULT '[]'::jsonb;
  `;
  console.info('Policies table updated with required_profiles and waivers.');
  await closeDatabase();
}

patch();

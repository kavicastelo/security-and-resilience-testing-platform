# Database Migrations

## Responsibility
This directory houses version-controlled, forward-only SQL migration scripts for PostgreSQL.

### What belongs here:
* Sequential, immutable SQL migration files (e.g. `0000_initial_schema.sql`, `0001_add_findings_table.sql`).
* Drizzle migration journal metadata when generated.

### What does NOT belong here:
* Ephemeral or ad-hoc manual database patches.
* Destructive schema resets or direct table drops.
* Application business logic.

### Future Phase Implementation:
* **Phase 1**: Introduction of `findings`, `evidence_records`, `metrics`, and `policies` migration tables.
* **Phase 2**: Partitioning strategy for high-volume historical metric data.

# ADR 0002: PostgreSQL as Primary Datastore with Drizzle ORM

## Status
Accepted

## Context
The platform requires a reliable, ACID-compliant persistence layer capable of handling:
* Structured relational records (Projects, Targets, Environments, TestRuns).
* Semi-structured, evolving payloads (Raw engine output, JSON evidence, flexible test inputs).
* Time-series telemetry (performance and resilience metrics).
* Version-controlled, forward-only migrations.

## Decision
We select **PostgreSQL** (version 16+) as the primary system of record, accessed via **Drizzle ORM** and the `postgres` native driver:
* Relational foreign keys enforce referential integrity across projects, targets, and test runs.
* Native `JSONB` columns store flexible scope parameters, execution metadata, and assertions without schema explosion.
* Drizzle ORM provides lightweight, type-safe SQL query generation without heavyweight runtime overhead or complex query engine abstractions.
* Schema evolution is managed via forward-only SQL migration scripts (`0000_initial_schema.sql`).

## Consequences
### Positive
* Single, battle-tested database engine covering relational, document, and metric data.
* Excellent indexing support for JSONB (GIN indexes).
* Zero lock-in: standard PostgreSQL runs effortlessly in Docker, local bare-metal, or managed cloud services (RDS/Cloud SQL).

### Negative
* Requires running a PostgreSQL container or local daemon during local development.

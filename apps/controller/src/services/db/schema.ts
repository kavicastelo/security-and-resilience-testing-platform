import { pgTable, uuid, varchar, text, timestamp, jsonb, integer, doublePrecision } from 'drizzle-orm/pg-core';
import { TargetScope, FindingSeverity, FindingConfidence, FindingStatus } from '@security-lab/domain';

export const projects = pgTable('projects', {
  id: uuid('id').primaryKey().defaultRandom(),
  name: varchar('name', { length: 100 }).notNull().unique(),
  description: text('description'),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
});

export const environments = pgTable('environments', {
  id: uuid('id').primaryKey().defaultRandom(),
  projectId: uuid('project_id')
    .notNull()
    .references(() => projects.id, { onDelete: 'cascade' }),
  name: varchar('name', { length: 100 }).notNull(),
  type: varchar('type', { length: 30 }).notNull().default('development'),
  variables: jsonb('variables').notNull().default({}),
  headers: jsonb('headers').notNull().default({}),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
});

export const targets = pgTable('targets', {
  id: uuid('id').primaryKey().defaultRandom(),
  projectId: uuid('project_id')
    .notNull()
    .references(() => projects.id, { onDelete: 'cascade' }),
  name: varchar('name', { length: 100 }).notNull(),
  baseUrl: text('base_url').notNull(),
  scope: jsonb('scope').$type<TargetScope>().notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
});

export const testRuns = pgTable('test_runs', {
  id: uuid('id').primaryKey().defaultRandom(),
  projectId: uuid('project_id')
    .notNull()
    .references(() => projects.id, { onDelete: 'cascade' }),
  targetId: uuid('target_id')
    .notNull()
    .references(() => targets.id, { onDelete: 'restrict' }),
  environmentId: uuid('environment_id').references(() => environments.id, { onDelete: 'set null' }),
  profileId: varchar('profile_id', { length: 100 }),
  status: varchar('status', { length: 30 }).notNull().default('pending'),
  triggeredBy: varchar('triggered_by', { length: 30 }).notNull().default('manual'),
  startedAt: timestamp('started_at', { withTimezone: true }),
  completedAt: timestamp('completed_at', { withTimezone: true }),
  summary: jsonb('summary').notNull().default({
    totalTests: 0,
    passedTests: 0,
    failedTests: 0,
    errorTests: 0,
    findingsCount: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
  }),
  metadata: jsonb('metadata').notNull().default({}),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
});

export const testExecutions = pgTable('test_executions', {
  id: uuid('id').primaryKey().defaultRandom(),
  testRunId: uuid('test_run_id')
    .notNull()
    .references(() => testRuns.id, { onDelete: 'cascade' }),
  engineId: varchar('engine_id', { length: 100 }).notNull(),
  executionClass: varchar('execution_class', { length: 50 }).notNull().default('class_a_native'),
  status: varchar('status', { length: 30 }).notNull().default('pending'),
  startedAt: timestamp('started_at', { withTimezone: true }),
  completedAt: timestamp('completed_at', { withTimezone: true }),
  durationMs: integer('duration_ms'),
  exitCode: integer('exit_code'),
  errorMessage: text('error_message'),
  rawResult: jsonb('raw_result'),
  metadata: jsonb('metadata').notNull().default({}),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
});

export const evidenceRecords = pgTable('evidence_records', {
  id: uuid('id').primaryKey().defaultRandom(),
  testRunId: uuid('test_run_id')
    .notNull()
    .references(() => testRuns.id, { onDelete: 'cascade' }),
  executionId: uuid('execution_id')
    .notNull()
    .references(() => testExecutions.id, { onDelete: 'cascade' }),
  request: jsonb('request'),
  response: jsonb('response'),
  expected: jsonb('expected'),
  actual: jsonb('actual'),
  metadata: jsonb('metadata').notNull().default({}),
  timestamp: timestamp('timestamp', { withTimezone: true }).notNull().defaultNow(),
  environment: varchar('environment', { length: 100 }).notNull().default('default'),
  applicationVersion: varchar('application_version', { length: 100 }),
  gitCommit: varchar('git_commit', { length: 100 }),
  immutableHash: varchar('immutable_hash', { length: 64 }).notNull(),
});

export const findings = pgTable('findings', {
  id: uuid('id').primaryKey().defaultRandom(),
  fingerprint: varchar('fingerprint', { length: 128 }).notNull(),
  title: varchar('title', { length: 200 }).notNull(),
  category: varchar('category', { length: 100 }).notNull(),
  severity: varchar('severity', { length: 20 }).$type<FindingSeverity>().notNull(),
  confidence: varchar('confidence', { length: 20 }).$type<FindingConfidence>().notNull().default('firm'),
  status: varchar('status', { length: 30 }).$type<FindingStatus>().notNull().default('open'),
  description: text('description').notNull(),
  risk: text('risk'),
  recommendation: text('recommendation'),
  testDefinitionId: varchar('test_definition_id', { length: 100 }).notNull(),
  testRunId: uuid('test_run_id')
    .notNull()
    .references(() => testRuns.id, { onDelete: 'cascade' }),
  executionId: uuid('execution_id')
    .notNull()
    .references(() => testExecutions.id, { onDelete: 'cascade' }),
  targetId: uuid('target_id')
    .notNull()
    .references(() => targets.id, { onDelete: 'cascade' }),
  releaseId: uuid('release_id'),
  evidenceId: uuid('evidence_id').references(() => evidenceRecords.id, { onDelete: 'set null' }),
  firstDetectedAt: timestamp('first_detected_at', { withTimezone: true }).notNull().defaultNow(),
  lastDetectedAt: timestamp('last_detected_at', { withTimezone: true }).notNull().defaultNow(),
  fixedAt: timestamp('fixed_at', { withTimezone: true }),
  metadata: jsonb('metadata').notNull().default({}),
});

export const metrics = pgTable('metrics', {
  id: uuid('id').primaryKey().defaultRandom(),
  testRunId: uuid('test_run_id')
    .notNull()
    .references(() => testRuns.id, { onDelete: 'cascade' }),
  executionId: uuid('execution_id')
    .notNull()
    .references(() => testExecutions.id, { onDelete: 'cascade' }),
  name: varchar('name', { length: 100 }).notNull(),
  value: doublePrecision('value').notNull(),
  unit: varchar('unit', { length: 20 }).notNull().default('ms'),
  tags: jsonb('tags').notNull().default({}),
  threshold: jsonb('threshold'),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
});


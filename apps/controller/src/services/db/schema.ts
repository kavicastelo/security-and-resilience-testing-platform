import {
  pgTable,
  uuid,
  varchar,
  text,
  timestamp,
  jsonb,
  integer,
  doublePrecision,
  boolean,
  index,
} from 'drizzle-orm/pg-core';
import {
  TargetScope,
  FindingSeverity,
  FindingConfidence,
  FindingStatus,
  ReleaseGateDecision,
} from '@security-lab/domain';

export const tenants = pgTable('tenants', {
  id: uuid('id').primaryKey().defaultRandom(),
  name: varchar('name', { length: 100 }).notNull(),
  slug: varchar('slug', { length: 100 }).notNull().unique(),
  plan: varchar('plan', { length: 50 }).notNull().default('enterprise'),
  settings: jsonb('settings').notNull().default({}),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
});

export const projects = pgTable('projects', {
  id: uuid('id').primaryKey().defaultRandom(),
  tenantId: uuid('tenant_id').references(() => tenants.id, { onDelete: 'cascade' }),
  name: varchar('name', { length: 100 }).notNull().unique(),
  description: text('description'),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
});

export const environments = pgTable(
  'environments',
  {
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
  },
  (table) => [
    index('idx_environments_project_id').on(table.projectId),
  ],
);

export const targets = pgTable(
  'targets',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    tenantId: uuid('tenant_id').references(() => tenants.id, { onDelete: 'cascade' }),
    projectId: uuid('project_id')
      .notNull()
      .references(() => projects.id, { onDelete: 'cascade' }),
    name: varchar('name', { length: 100 }).notNull(),
    baseUrl: text('base_url').notNull(),
    scope: jsonb('scope').$type<TargetScope>().notNull(),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    index('idx_targets_project_id').on(table.projectId),
    index('idx_targets_tenant_id').on(table.tenantId),
  ],
);

export const testRuns = pgTable(
  'test_runs',
  {
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
  },
  (table) => [
    index('idx_test_runs_project_id').on(table.projectId),
    index('idx_test_runs_target_id').on(table.targetId),
    index('idx_test_runs_status').on(table.status),
    index('idx_test_runs_created_at').on(table.createdAt),
  ],
);

export const testExecutions = pgTable(
  'test_executions',
  {
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
  },
  (table) => [
    index('idx_test_executions_test_run_id').on(table.testRunId),
    index('idx_test_executions_status').on(table.status),
    index('idx_test_executions_engine_id').on(table.engineId),
  ],
);

export const evidenceRecords = pgTable(
  'evidence_records',
  {
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
  },
  (table) => [
    index('idx_evidence_records_test_run_id').on(table.testRunId),
    index('idx_evidence_records_execution_id').on(table.executionId),
    index('idx_evidence_records_immutable_hash').on(table.immutableHash),
  ],
);

export const findings = pgTable(
  'findings',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    tenantId: uuid('tenant_id').references(() => tenants.id, { onDelete: 'cascade' }),
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
    occurrenceCount: integer('occurrence_count').notNull().default(1),
    fixedInRunId: uuid('fixed_in_run_id').references(() => testRuns.id, { onDelete: 'set null' }),
    firstDetectedAt: timestamp('first_detected_at', { withTimezone: true }).notNull().defaultNow(),
    lastDetectedAt: timestamp('last_detected_at', { withTimezone: true }).notNull().defaultNow(),
    fixedAt: timestamp('fixed_at', { withTimezone: true }),
    metadata: jsonb('metadata').notNull().default({}),
  },
  (table) => [
    index('idx_findings_tenant_id').on(table.tenantId),
    index('idx_findings_test_run_id').on(table.testRunId),
    index('idx_findings_target_id').on(table.targetId),
    index('idx_findings_execution_id').on(table.executionId),
    index('idx_findings_severity').on(table.severity),
    index('idx_findings_status').on(table.status),
    index('idx_findings_fingerprint').on(table.fingerprint),
    index('idx_findings_fixed_in_run_id').on(table.fixedInRunId),
    index('idx_findings_target_fingerprint').on(table.targetId, table.fingerprint),
  ],
);

export const metrics = pgTable(
  'metrics',
  {
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
  },
  (table) => [
    index('idx_metrics_test_run_id').on(table.testRunId),
    index('idx_metrics_execution_id').on(table.executionId),
    index('idx_metrics_name').on(table.name),
  ],
);

export const policies = pgTable(
  'policies',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    tenantId: uuid('tenant_id').references(() => tenants.id, { onDelete: 'cascade' }),
    name: varchar('name', { length: 100 }).notNull(),
    description: text('description'),
    rules: jsonb('rules').notNull().default([]),
    requiredProfiles: jsonb('required_profiles').notNull().default([]),
    waivers: jsonb('waivers').notNull().default([]),
    isDefault: boolean('is_default').notNull().default(false),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    index('idx_policies_tenant_id').on(table.tenantId),
    index('idx_policies_name').on(table.name),
  ],
);

export const releases = pgTable(
  'releases',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    projectId: uuid('project_id')
      .notNull()
      .references(() => projects.id, { onDelete: 'cascade' }),
    name: varchar('name', { length: 100 }).notNull(),
    version: varchar('version', { length: 100 }).notNull(),
    gitCommit: varchar('git_commit', { length: 100 }),
    gitBranch: varchar('git_branch', { length: 100 }),
    testRunId: uuid('test_run_id').references(() => testRuns.id, { onDelete: 'set null' }),
    policyId: uuid('policy_id').references(() => policies.id, { onDelete: 'set null' }),
    decision: varchar('decision', { length: 30 }).$type<ReleaseGateDecision>().notNull().default('warning'),
    reason: text('reason'),
    evaluatorHash: varchar('evaluator_hash', { length: 64 }),
    metadata: jsonb('metadata').notNull().default({}),
    evaluatedAt: timestamp('evaluated_at', { withTimezone: true }),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    index('idx_releases_project_id').on(table.projectId),
    index('idx_releases_test_run_id').on(table.testRunId),
    index('idx_releases_decision').on(table.decision),
    index('idx_releases_evaluator_hash').on(table.evaluatorHash),
  ],
);

export const testDefinitions = pgTable(
  'test_definitions',
  {
    id: varchar('id', { length: 100 }).primaryKey(),
    projectId: uuid('project_id').references(() => projects.id, { onDelete: 'cascade' }),
    name: varchar('name', { length: 200 }).notNull(),
    version: varchar('version', { length: 50 }).notNull().default('1.0.0'),
    category: varchar('category', { length: 50 }).notNull().default('http_security'),
    description: text('description'),
    contentYaml: text('content_yaml').notNull(),
    parsedContent: jsonb('parsed_content').notNull().default({}),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    index('idx_test_definitions_project_id').on(table.projectId),
    index('idx_test_definitions_category').on(table.category),
  ],
);

export const reports = pgTable(
  'reports',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    testRunId: uuid('test_run_id')
      .notNull()
      .references(() => testRuns.id, { onDelete: 'cascade' }),
    format: varchar('format', { length: 30 }).notNull(),
    filename: varchar('filename', { length: 255 }).notNull(),
    contentType: varchar('content_type', { length: 100 }).notNull(),
    content: text('content').notNull(),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    index('idx_reports_test_run_id').on(table.testRunId),
    index('idx_reports_format').on(table.format),
  ],
);

export const artifacts = pgTable(
  'artifacts',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    testRunId: uuid('test_run_id')
      .notNull()
      .references(() => testRuns.id, { onDelete: 'cascade' }),
    executionId: uuid('execution_id').references(() => testExecutions.id, { onDelete: 'set null' }),
    name: varchar('name', { length: 200 }).notNull(),
    type: varchar('type', { length: 50 }).notNull(),
    mimeType: varchar('mime_type', { length: 100 }).notNull().default('application/octet-stream'),
    sizeBytes: integer('size_bytes').notNull().default(0),
    sha256: varchar('sha256', { length: 64 }).notNull(),
    storagePath: text('storage_path').notNull(),
    metadata: jsonb('metadata').notNull().default({}),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    index('idx_artifacts_test_run_id').on(table.testRunId),
    index('idx_artifacts_execution_id').on(table.executionId),
    index('idx_artifacts_sha256').on(table.sha256),
    index('idx_artifacts_type').on(table.type),
  ],
);

export const identityProfiles = pgTable(
  'identity_profiles',
  {
    id: varchar('id', { length: 100 }).primaryKey(),
    projectId: uuid('project_id').references(() => projects.id, { onDelete: 'cascade' }),
    name: varchar('name', { length: 100 }).notNull(),
    role: varchar('role', { length: 50 }).notNull().default('user'),
    isGuest: boolean('is_guest').notNull().default(false),
    headers: jsonb('headers').notNull().default({}),
    metadata: jsonb('metadata').notNull().default({}),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    index('idx_identity_profiles_project_id').on(table.projectId),
    index('idx_identity_profiles_role').on(table.role),
  ],
);

export const credentials = pgTable(
  'credentials',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    projectId: uuid('project_id')
      .notNull()
      .references(() => projects.id, { onDelete: 'cascade' }),
    name: varchar('name', { length: 100 }).notNull(),
    type: varchar('type', { length: 50 }).notNull(),
    encryptedValue: text('encrypted_value').notNull(),
    iv: varchar('iv', { length: 64 }).notNull(),
    authTag: varchar('auth_tag', { length: 64 }).notNull(),
    keyId: varchar('50', { length: 50 }).notNull().default('default'),
    description: text('description'),
    metadata: jsonb('metadata').notNull().default({}),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    index('idx_credentials_project_id').on(table.projectId),
    index('idx_credentials_type').on(table.type),
  ],
);

export const tenantEnrollmentKeys = pgTable(
  'tenant_enrollment_keys',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    tenantId: uuid('tenant_id')
      .notNull()
      .references(() => tenants.id, { onDelete: 'cascade' }),
    name: varchar('name', { length: 100 }).notNull(),
    keyHash: varchar('key_hash', { length: 64 }).notNull(),
    keyPrefix: varchar('key_prefix', { length: 32 }).notNull(),
    maxUses: integer('max_uses'),
    usesCount: integer('uses_count').notNull().default(0),
    expiresAt: timestamp('expires_at', { withTimezone: true }),
    revokedAt: timestamp('revoked_at', { withTimezone: true }),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    index('idx_tek_tenant_id').on(table.tenantId),
    index('idx_tek_key_hash').on(table.keyHash),
    index('idx_tek_expires_at').on(table.expiresAt),
  ],
);

export const agents = pgTable(
  'agents',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    tenantId: uuid('tenant_id')
      .notNull()
      .references(() => tenants.id, { onDelete: 'cascade' }),
    name: varchar('name', { length: 100 }).notNull(),
    tokenHash: varchar('token_hash', { length: 64 }).notNull(),
    status: varchar('status', { length: 30 }).notNull().default('offline'),
    capabilities: jsonb('capabilities').notNull().default([]),
    tags: jsonb('tags').notNull().default([]),
    systemInfo: jsonb('system_info').notNull().default({}),
    lastHeartbeatAt: timestamp('last_heartbeat_at', { withTimezone: true }),
    expiresAt: timestamp('expires_at', { withTimezone: true }),
    revokedAt: timestamp('revoked_at', { withTimezone: true }),
    revocationReason: varchar('revocation_reason', { length: 100 }),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    index('idx_agents_tenant_id').on(table.tenantId),
    index('idx_agents_token_hash').on(table.tokenHash),
    index('idx_agents_status').on(table.status),
    index('idx_agents_expires_at').on(table.expiresAt),
    index('idx_agents_revoked_at').on(table.revokedAt),
  ],
);

export const agentJobs = pgTable(
  'agent_jobs',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    agentId: uuid('agent_id').references(() => agents.id, { onDelete: 'set null' }),
    tenantId: uuid('tenant_id')
      .notNull()
      .references(() => tenants.id, { onDelete: 'cascade' }),
    testRunId: uuid('test_run_id')
      .notNull()
      .references(() => testRuns.id, { onDelete: 'cascade' }),
    status: varchar('status', { length: 30 }).notNull().default('queued'),
    leaseId: uuid('lease_id'),
    leaseExpiresAt: timestamp('lease_expires_at', { withTimezone: true }),
    attempts: integer('attempts').notNull().default(0),
    maxAttempts: integer('max_attempts').notNull().default(3),
    requiredCapabilities: jsonb('required_capabilities').notNull().default([]),
    requiredTags: jsonb('required_tags').notNull().default([]),
    payload: jsonb('payload').notNull().default({}),
    result: jsonb('result'),
    error: text('error'),
    dispatchedAt: timestamp('dispatched_at', { withTimezone: true }),
    completedAt: timestamp('completed_at', { withTimezone: true }),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    index('idx_agent_jobs_agent_id').on(table.agentId),
    index('idx_agent_jobs_tenant_id').on(table.tenantId),
    index('idx_agent_jobs_test_run_id').on(table.testRunId),
    index('idx_agent_jobs_status').on(table.status),
    index('idx_agent_jobs_reaper').on(table.status, table.leaseExpiresAt),
    index('idx_agent_jobs_lease_id').on(table.leaseId),
    index('idx_agent_jobs_claim').on(table.tenantId, table.status, table.attempts),
  ],
);

export const agentAuditEvents = pgTable(
  'agent_audit_events',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    tenantId: uuid('tenant_id')
      .notNull()
      .references(() => tenants.id, { onDelete: 'cascade' }),
    agentId: uuid('agent_id').references(() => agents.id, { onDelete: 'set null' }),
    eventType: varchar('event_type', { length: 50 }).notNull(),
    actorType: varchar('actor_type', { length: 30 }).notNull(),
    actorId: varchar('actor_id', { length: 100 }).notNull(),
    metadata: jsonb('metadata').notNull().default({}),
    ipAddress: varchar('ip_address', { length: 45 }),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    index('idx_agent_audit_events_tenant_created').on(table.tenantId, table.createdAt),
    index('idx_agent_audit_events_agent_created').on(table.agentId, table.createdAt),
    index('idx_agent_audit_events_event_type').on(table.eventType),
  ],
);

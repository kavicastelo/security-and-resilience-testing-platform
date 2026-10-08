import { z } from 'zod';

export const PurgeModeSchema = z.enum([
  'all',        // Factory reset: wipes all test data, resets default tenant & baseline policy
  'executions', // Clears all test runs, executions, findings, evidence, metrics, reports, agent jobs
  'findings',   // Clears findings, evidence records, metrics
  'artifacts',  // Clears disk artifacts, generated reports and metadata
  'jobs',       // Clears agent jobs queue and audit logs
]);

export type PurgeMode = z.infer<typeof PurgeModeSchema>;

export const PurgeDataRequestSchema = z.object({
  mode: PurgeModeSchema.default('all'),
  confirmation: z.string().min(1, 'Confirmation keyword is required'),
});

export type PurgeDataRequest = z.infer<typeof PurgeDataRequestSchema>;

export interface SystemOverviewStats {
  counts: {
    projects: number;
    targets: number;
    environments: number;
    testRuns: number;
    testExecutions: number;
    findings: number;
    criticalFindings: number;
    highFindings: number;
    mediumFindings: number;
    lowFindings: number;
    infoFindings: number;
    evidenceRecords: number;
    metrics: number;
    policies: number;
    releases: number;
    reports: number;
    artifacts: number;
    agents: number;
    agentJobs: number;
    tenants: number;
  };
  storage: {
    evidenceSizeBytes: number;
    evidenceFileCount: number;
    reportsSizeBytes: number;
    reportsFileCount: number;
    artifactsSizeBytes: number;
    artifactsFileCount: number;
    totalDiskBytes: number;
  };
  system: {
    nodeVersion: string;
    platform: string;
    uptimeSeconds: number;
    pid: number;
    memoryUsage: {
      rssMb: number;
      heapTotalMb: number;
      heapUsedMb: number;
      externalMb: number;
    };
  };
  database: {
    status: 'up' | 'down';
    pingMs: number;
    poolMax: number;
    databaseName: string;
  };
  agentSummary: {
    totalAgents: number;
    onlineAgents: number;
    offlineAgents: number;
    queuedJobs: number;
    activeJobs: number;
    completedJobs: number;
    failedJobs: number;
  };
}

export interface PurgeDataResult {
  success: boolean;
  mode: PurgeMode;
  cleared: Record<string, number>;
  retained: string[];
  message: string;
  timestamp: string;
}

export interface SeedDataResult {
  success: boolean;
  projectId: string;
  projectName: string;
  targetsCreated: number;
  testRunId: string;
  findingsCreated: number;
  evidenceCreated: number;
  policyId: string;
  releaseId?: string;
  message: string;
  timestamp: string;
}

export interface BackupMetadata {
  id: string;
  filename: string;
  createdAt: string;
  version: string;
  sizeBytes: number;
  sha256: string;
  counts: {
    tenants: number;
    projects: number;
    targets: number;
    environments: number;
    policies: number;
    testRuns: number;
    testExecutions: number;
    findings: number;
    evidenceRecords: number;
    metrics: number;
    releases: number;
  };
  description?: string;
}

export interface BackupPayload {
  metadata: {
    version: string;
    schemaVersion: string;
    createdAt: string;
    platform: string;
    counts: Record<string, number>;
    description?: string;
    sha256?: string;
  };
  data: {
    tenants: any[];
    projects: any[];
    targets: any[];
    environments: any[];
    policies: any[];
    testRuns: any[];
    testExecutions: any[];
    findings: any[];
    evidenceRecords: any[];
    metrics: any[];
    releases: any[];
  };
}

export const CreateBackupRequestSchema = z.object({
  description: z.string().max(255).optional(),
  includeExecutions: z.boolean().default(true),
});

export type CreateBackupRequest = z.infer<typeof CreateBackupRequestSchema>;

export const RestoreBackupRequestSchema = z.object({
  mode: z.enum(['replace', 'merge']).default('replace'),
  confirmation: z.string().optional(),
  backupId: z.string().optional(),
  backupData: z.record(z.string(), z.unknown()).optional(),
});

export type RestoreBackupRequest = z.infer<typeof RestoreBackupRequestSchema>;

export interface RestoreBackupResult {
  success: boolean;
  mode: 'replace' | 'merge';
  restoredCounts: Record<string, number>;
  message: string;
  timestamp: string;
}


import React, { useState, useRef } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Sliders,
  Database,
  Trash2,
  RefreshCw,
  HardDrive,
  Server,
  Cpu,
  Activity,
  Sparkles,
  ShieldAlert,
  CheckCircle2,
  AlertTriangle,
  Clock,
  Zap,
  Layers,
  Target,
  PlayCircle,
  AlertOctagon,
  Scale,
  FileText,
  Lock,
  X,
  Flame,
  Download,
  Upload,
  Archive,
  RotateCcw,
  Copy,
  Check,
  ShieldCheck,
} from 'lucide-react';
import { useAppStore } from '../store/useAppStore.js';
import { authFetch } from '../api/client.js';

export type PurgeMode = 'all' | 'executions' | 'findings' | 'artifacts' | 'jobs';

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
    environment?: string;
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

interface RestoreTargetModalState {
  isUploaded: boolean;
  backupId?: string;
  filename: string;
  backupData?: any;
  counts: Record<string, number>;
  createdAt: string;
  sha256?: string;
  description?: string;
}

interface PurgeTargetConfig {
  mode: PurgeMode;
  title: string;
  description: string;
  warning: string;
  badge: string;
  buttonLabel: string;
  requiresStrictConfirmation?: boolean;
}

const PURGE_OPTIONS: PurgeTargetConfig[] = [
  {
    mode: 'executions',
    title: 'Purge Test Executions & Findings',
    description: 'Clears all historical test runs, execution logs, findings, evidence, and metrics while preserving registered target scopes and security policies.',
    warning: 'All test run history, findings, and cryptographic evidence will be permanently deleted.',
    badge: 'Selective Purge',
    buttonLabel: 'Purge Executions & Findings',
  },
  {
    mode: 'artifacts',
    title: 'Purge Forensic Artifacts & Reports',
    description: 'Wipes all persisted SARIF, JUnit, and HTML report files from disk storage and removes artifact metadata records.',
    warning: 'All downloaded forensic test reports and cached disk files will be permanently purged.',
    badge: 'Storage Reclamation',
    buttonLabel: 'Purge Artifacts & Reports',
  },
  {
    mode: 'jobs',
    title: 'Clear Agent Jobs & Dispatch Queue',
    description: 'Flushes all queued, dispatched, stalled, and completed agent worker tasks along with dispatch audit logs.',
    warning: 'Any in-flight background worker tasks will lose their assigned job lease.',
    badge: 'Queue Maintenance',
    buttonLabel: 'Clear Worker Queues',
  },
  {
    mode: 'all',
    title: 'Factory Reset (Clear All Data)',
    description: 'Completely purges all data across all 19 database tables and forensic disk directories. Automatically re-initializes the default tenant and enterprise security baseline policy.',
    warning: 'Destructive operation: wipes all projects, target scopes, test runs, findings, artifacts, and agents. System will reset to factory baseline.',
    badge: 'Nuclear / Destructive',
    buttonLabel: 'Clear All Data (Factory Reset)',
    requiresStrictConfirmation: true,
  },
];

export const ManagementView: React.FC = () => {
  const { showToast } = useAppStore();
  const queryClient = useQueryClient();
  const apiUrl = import.meta.env.VITE_API_URL || 'http://localhost:4000';

  const fileInputRef = useRef<HTMLInputElement | null>(null);

  // Purge Modal State
  const [activeModalPurge, setActiveModalPurge] = useState<PurgeTargetConfig | null>(null);
  const [confirmationInput, setConfirmationInput] = useState('');

  // Backup Creation State
  const [backupDescription, setBackupDescription] = useState('');
  const [includeExecutions, setIncludeExecutions] = useState(true);

  // Restore Modal State
  const [restoreModalTarget, setRestoreModalTarget] = useState<RestoreTargetModalState | null>(null);
  const [restoreMode, setRestoreMode] = useState<'replace' | 'merge'>('replace');
  const [restoreConfirmation, setRestoreConfirmation] = useState('');

  // Clipboard Copied State
  const [copiedSha, setCopiedSha] = useState<string | null>(null);

  // 1. Fetch System Overview Stats
  const {
    data: overview,
    isLoading,
    isRefetching,
    refetch,
  } = useQuery<SystemOverviewStats>({
    queryKey: ['management-overview'],
    queryFn: async () => {
      const res = await authFetch(`${apiUrl}/api/v1/management/overview`);
      const json = await res.json();
      if (!res.ok || !json.success) {
        throw new Error(json.error?.message || 'Failed to fetch management diagnostics');
      }
      return json.data;
    },
    refetchInterval: 10000,
  });

  // 2. Fetch Stored Backups List
  const {
    data: backups = [],
    isLoading: isBackupsLoading,
    refetch: refetchBackups,
  } = useQuery<BackupMetadata[]>({
    queryKey: ['management-backups'],
    queryFn: async () => {
      const res = await authFetch(`${apiUrl}/api/v1/management/backups`);
      const json = await res.json();
      if (!res.ok || !json.success) {
        throw new Error(json.error?.message || 'Failed to fetch platform backups');
      }
      return json.data || [];
    },
    refetchInterval: 10000,
  });

  // 3. Fetch Recent Audit Events
  const { data: auditEvents = [] } = useQuery({
    queryKey: ['management-audit-events'],
    queryFn: async () => {
      const res = await authFetch(`${apiUrl}/api/v1/management/audit-events`);
      const json = await res.json();
      return json.data || [];
    },
    refetchInterval: 15000,
  });

  // 4. Purge Data Mutation
  const purgeMutation = useMutation({
    mutationFn: async ({ mode, confirmation }: { mode: PurgeMode; confirmation: string }) => {
      const res = await authFetch(`${apiUrl}/api/v1/management/purge`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode, confirmation }),
      });
      const json = await res.json();
      if (!res.ok || !json.success) {
        throw new Error(json.error?.message || 'Purge operation failed');
      }
      return json.data;
    },
    onSuccess: (data) => {
      showToast(data.message || 'Data purged successfully', 'success');
      setActiveModalPurge(null);
      setConfirmationInput('');
      queryClient.invalidateQueries();
    },
    onError: (err: Error) => {
      showToast(err.message, 'error');
    },
  });

  // 5. Seed Demo Data Mutation
  const seedMutation = useMutation({
    mutationFn: async (options?: { force?: boolean }) => {
      const res = await authFetch(`${apiUrl}/api/v1/management/seed`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ force: options?.force ?? true }),
      });
      const json = await res.json();
      if (!res.ok || !json.success) {
        throw new Error(json.message || json.error?.message || 'Seed operation failed');
      }
      return json.data;
    },
    onSuccess: (data) => {
      showToast(`Sample lab generated: ${data.projectName} (5 findings, 2 targets)`, 'success');
      queryClient.invalidateQueries();
    },
    onError: (err: Error) => {
      showToast(err.message, 'error');
    },
  });

  // 6. Reap Jobs Mutation
  const reapMutation = useMutation({
    mutationFn: async () => {
      const res = await authFetch(`${apiUrl}/api/v1/management/reap-jobs`, {
        method: 'POST',
      });
      const json = await res.json();
      if (!res.ok || !json.success) {
        throw new Error(json.error?.message || 'Reaper execution failed');
      }
      return json.data;
    },
    onSuccess: (data) => {
      showToast(`Agent Watchdog: Reaped ${data.reapedCount} expired job leases`, 'info');
      queryClient.invalidateQueries({ queryKey: ['management-overview'] });
    },
    onError: (err: Error) => {
      showToast(err.message, 'error');
    },
  });

  // 7. Create Backup Mutation
  const createBackupMutation = useMutation({
    mutationFn: async ({ description, includeExecutions }: { description?: string; includeExecutions: boolean }) => {
      const res = await authFetch(`${apiUrl}/api/v1/management/backups`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ description, includeExecutions }),
      });
      const json = await res.json();
      if (!res.ok || !json.success) {
        throw new Error(json.error?.message || 'Failed to create backup snapshot');
      }
      return json.data;
    },
    onSuccess: (data: BackupMetadata) => {
      showToast(`Snapshot created successfully: ${data.filename}`, 'success');
      setBackupDescription('');
      queryClient.invalidateQueries({ queryKey: ['management-backups'] });
      queryClient.invalidateQueries({ queryKey: ['management-overview'] });
    },
    onError: (err: Error) => {
      showToast(err.message, 'error');
    },
  });

  // 8. Delete Backup Mutation
  const deleteBackupMutation = useMutation({
    mutationFn: async (backupId: string) => {
      const res = await authFetch(`${apiUrl}/api/v1/management/backups/${backupId}`, {
        method: 'DELETE',
      });
      const json = await res.json();
      if (!res.ok || !json.success) {
        throw new Error(json.error?.message || 'Failed to delete backup file');
      }
      return json.data;
    },
    onSuccess: () => {
      showToast('Backup snapshot deleted', 'info');
      queryClient.invalidateQueries({ queryKey: ['management-backups'] });
    },
    onError: (err: Error) => {
      showToast(err.message, 'error');
    },
  });

  // 9. Restore Backup Mutation
  const restoreBackupMutation = useMutation({
    mutationFn: async ({
      mode,
      confirmation,
      backupId,
      backupData,
    }: {
      mode: 'replace' | 'merge';
      confirmation?: string;
      backupId?: string;
      backupData?: any;
    }) => {
      const res = await authFetch(`${apiUrl}/api/v1/management/backups/restore`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode, confirmation, backupId, backupData }),
      });
      const json = await res.json();
      if (!res.ok || !json.success) {
        throw new Error(json.error?.message || 'Failed to restore backup snapshot');
      }
      return json.data;
    },
    onSuccess: (data) => {
      showToast(data.message || 'Platform state successfully restored!', 'success');
      setRestoreModalTarget(null);
      setRestoreConfirmation('');
      queryClient.invalidateQueries();
    },
    onError: (err: Error) => {
      showToast(err.message, 'error');
    },
  });

  const handleDownloadBackup = async (backup: BackupMetadata) => {
    try {
      const res = await authFetch(`${apiUrl}/api/v1/management/backups/${backup.id}/download`);
      if (!res.ok) throw new Error('Failed to download backup snapshot');
      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = backup.filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);
      showToast(`Snapshot downloaded: ${backup.filename}`, 'success');
    } catch (err: any) {
      showToast(err.message || 'Download failed', 'error');
    }
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      try {
        const parsed = JSON.parse(event.target?.result as string);
        if (!parsed || (!parsed.data && !parsed.metadata)) {
          showToast('Invalid backup file: missing platform metadata and data payload', 'error');
          return;
        }
        const data = parsed.data || {};
        const metadata = parsed.metadata || {};
        const counts = metadata.counts || {
          tenants: (data.tenants || []).length,
          projects: (data.projects || []).length,
          targets: (data.targets || []).length,
          environments: (data.environments || []).length,
          policies: (data.policies || []).length,
          testRuns: (data.testRuns || []).length,
          testExecutions: (data.testExecutions || []).length,
          findings: (data.findings || []).length,
          evidenceRecords: (data.evidenceRecords || []).length,
          metrics: (data.metrics || []).length,
          releases: (data.releases || []).length,
        };

        setRestoreModalTarget({
          isUploaded: true,
          filename: file.name,
          backupData: parsed,
          counts,
          createdAt: metadata.createdAt || new Date().toISOString(),
          sha256: metadata.sha256,
          description: metadata.description || 'Imported backup file',
        });
        setRestoreMode('replace');
        setRestoreConfirmation('');
      } catch {
        showToast('Corrupted or unreadable JSON file format', 'error');
      }
    };
    reader.readAsText(file);
    e.target.value = '';
  };

  const copySha = (sha: string) => {
    navigator.clipboard.writeText(sha);
    setCopiedSha(sha);
    showToast('SHA-256 fingerprint copied to clipboard', 'info');
    setTimeout(() => setCopiedSha(null), 2500);
  };

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
  };

  const formatUptime = (seconds: number) => {
    const d = Math.floor(seconds / (3600 * 24));
    const h = Math.floor((seconds % (3600 * 24)) / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = Math.floor(seconds % 60);
    if (d > 0) return `${d}d ${h}h ${m}m`;
    if (h > 0) return `${h}h ${m}m ${s}s`;
    return `${m}m ${s}s`;
  };

  return (
    <div className="space-y-8 animate-fade-in pb-12">
      {/* Hidden File Input for Backup Upload */}
      <input
        type="file"
        ref={fileInputRef}
        onChange={handleFileUpload}
        accept=".json"
        className="hidden"
      />

      {/* Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-border/80 pb-6">
        <div>
          <div className="flex items-center space-x-3 mb-1">
            <div className="p-2 rounded-xl bg-blue-500/10 border border-blue-500/20 text-blue-400">
              <Sliders className="w-6 h-6" />
            </div>
            <h1 className="text-2xl font-bold tracking-tight text-foreground">
              Universal Platform Management
            </h1>
            <span className="px-2.5 py-0.5 text-xs font-semibold rounded-full bg-blue-500/10 text-blue-400 border border-blue-500/20">
              Admin Console
            </span>
          </div>
          <p className="text-sm text-muted-foreground max-w-2xl">
            Live infrastructure diagnostics, cryptographic backup & disaster recovery, agent watchdog queues, and universal data lifecycle maintenance.
          </p>
        </div>

        {/* Global Action Buttons */}
        <div className="flex flex-wrap items-center gap-2.5">
          <button
            type="button"
            onClick={() => {
              refetch();
              refetchBackups();
            }}
            disabled={isRefetching || isBackupsLoading}
            className="flex items-center space-x-2 px-3.5 py-2 text-xs font-medium rounded-lg bg-accent/60 hover:bg-accent text-foreground border border-border/70 transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isRefetching || isBackupsLoading ? 'animate-spin text-blue-400' : ''}`} />
            <span>Refresh Diagnostics</span>
          </button>

          <button
            type="button"
            onClick={() => fileInputRef.current?.click()}
            className="flex items-center space-x-2 px-3.5 py-2 text-xs font-medium rounded-lg bg-accent/60 hover:bg-accent text-foreground border border-border/70 transition-colors"
          >
            <Upload className="w-3.5 h-3.5 text-cyan-400" />
            <span>Upload & Restore</span>
          </button>

          <button
            type="button"
            onClick={() => reapMutation.mutate()}
            disabled={reapMutation.isPending}
            className="flex items-center space-x-2 px-3.5 py-2 text-xs font-medium rounded-lg bg-accent/60 hover:bg-accent text-foreground border border-border/70 transition-colors"
          >
            <Activity className="w-3.5 h-3.5 text-amber-400" />
            <span>Reap Leases</span>
          </button>

          <button
            type="button"
            onClick={() => seedMutation.mutate({ force: true })}
            disabled={seedMutation.isPending || overview?.system?.environment === 'production'}
            className={
              overview?.system?.environment === 'production'
                ? "flex items-center space-x-2 px-3.5 py-2 text-xs font-medium rounded-lg bg-muted/20 text-muted-foreground/40 border border-border/30 cursor-not-allowed"
                : "flex items-center space-x-2 px-3.5 py-2 text-xs font-medium rounded-lg bg-blue-600/20 hover:bg-blue-600/30 text-blue-400 border border-blue-500/30 transition-all hover:scale-[1.02]"
            }
            title={
              overview?.system?.environment === 'production'
                ? 'Demo data seeding is disabled in production environments'
                : 'Seed demonstration test suite with Nova Banking Core API'
            }
          >
            <Sparkles className="w-3.5 h-3.5" />
            <span>
              {overview?.system?.environment === 'production'
                ? 'Seeding Disabled (Prod)'
                : seedMutation.isPending
                  ? 'Generating Lab...'
                  : 'Seed Demo Data'}
            </span>
          </button>

          <button
            type="button"
            onClick={() => {
              setActiveModalPurge(PURGE_OPTIONS.find((o) => o.mode === 'all') || null);
              setConfirmationInput('');
            }}
            className="flex items-center space-x-2 px-3.5 py-2 text-xs font-semibold rounded-lg bg-rose-600 hover:bg-rose-500 text-white shadow-lg shadow-rose-950/50 hover:shadow-rose-900/60 transition-all hover:scale-[1.02]"
          >
            <Trash2 className="w-3.5 h-3.5" />
            <span>Clear All Data</span>
          </button>
        </div>
      </div>

      {/* Infrastructure & Platform Diagnostics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* PostgreSQL Database Health */}
        <div className="glass-card p-5 rounded-xl border border-border/80 flex flex-col justify-between">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
              Database Core
            </span>
            <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400">
              <Database className="w-4 h-4" />
            </div>
          </div>
          <div>
            <div className="flex items-baseline space-x-2">
              <span className="text-2xl font-bold font-mono text-foreground">
                {overview?.database.status === 'up' ? 'Online' : 'Degraded'}
              </span>
              <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                {overview?.database.pingMs ?? 0} ms
              </span>
            </div>
            <p className="text-xs text-muted-foreground mt-1">
              Pool Max: {overview?.database.poolMax ?? 20} conns • {overview?.database.databaseName ?? 'security_lab'}
            </p>
          </div>
        </div>

        {/* Forensic Storage Allocation */}
        <div className="glass-card p-5 rounded-xl border border-border/80 flex flex-col justify-between">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
              Forensic Storage
            </span>
            <div className="p-2 rounded-lg bg-blue-500/10 text-blue-400">
              <HardDrive className="w-4 h-4" />
            </div>
          </div>
          <div>
            <div className="flex items-baseline space-x-2">
              <span className="text-2xl font-bold font-mono text-foreground">
                {formatBytes(overview?.storage.totalDiskBytes ?? 0)}
              </span>
              <span className="text-xs text-muted-foreground">
                {(overview?.storage.evidenceFileCount ?? 0) +
                  (overview?.storage.reportsFileCount ?? 0) +
                  (overview?.storage.artifactsFileCount ?? 0)}{' '}
                files
              </span>
            </div>
            <p className="text-xs text-muted-foreground mt-1">
              Evidence: {formatBytes(overview?.storage.evidenceSizeBytes ?? 0)} • Reports:{' '}
              {formatBytes(overview?.storage.reportsSizeBytes ?? 0)}
            </p>
          </div>
        </div>

        {/* Runtime Controller Memory */}
        <div className="glass-card p-5 rounded-xl border border-border/80 flex flex-col justify-between">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
              Controller Memory
            </span>
            <div className="p-2 rounded-lg bg-purple-500/10 text-purple-400">
              <Cpu className="w-4 h-4" />
            </div>
          </div>
          <div>
            <div className="flex items-baseline space-x-2">
              <span className="text-2xl font-bold font-mono text-foreground">
                {overview?.system.memoryUsage.heapUsedMb ?? 0} MB
              </span>
              <span className="text-xs text-muted-foreground">
                / {overview?.system.memoryUsage.heapTotalMb ?? 0} MB
              </span>
            </div>
            <p className="text-xs text-muted-foreground mt-1">
              RSS: {overview?.system.memoryUsage.rssMb ?? 0} MB • PID: {overview?.system.pid ?? '--'}
            </p>
          </div>
        </div>

        {/* System Uptime & Platform */}
        <div className="glass-card p-5 rounded-xl border border-border/80 flex flex-col justify-between">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
              Host Environment
            </span>
            <div className="p-2 rounded-lg bg-amber-500/10 text-amber-400">
              <Server className="w-4 h-4" />
            </div>
          </div>
          <div>
            <div className="flex items-baseline space-x-2">
              <span className="text-2xl font-bold font-mono text-foreground">
                {formatUptime(overview?.system.uptimeSeconds ?? 0)}
              </span>
            </div>
            <p className="text-xs text-muted-foreground mt-1">
              Node {overview?.system.nodeVersion ?? '--'} • {overview?.system.platform ?? '--'}
            </p>
          </div>
        </div>
      </div>

      {/* Live Entity Inventory Grid */}
      <div className="glass-card p-6 rounded-xl border border-border/80 space-y-4">
        <div className="flex items-center justify-between border-b border-border/70 pb-3">
          <div className="flex items-center space-x-2">
            <Layers className="w-4 h-4 text-blue-400" />
            <h3 className="text-sm font-semibold text-foreground">Universal Database Entity Inventory</h3>
          </div>
          <span className="text-xs text-muted-foreground font-mono">
            {overview?.counts.tenants ?? 1} Registered Tenants
          </span>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6 gap-3">
          {/* Projects */}
          <div className="p-3.5 rounded-xl bg-card/60 border border-border/70 hover:border-blue-500/40 transition-colors">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs text-muted-foreground">Projects</span>
              <Target className="w-3.5 h-3.5 text-blue-400" />
            </div>
            <div className="text-2xl font-bold font-mono text-foreground">
              {isLoading ? '--' : overview?.counts.projects}
            </div>
          </div>

          {/* Targets */}
          <div className="p-3.5 rounded-xl bg-card/60 border border-border/70 hover:border-cyan-500/40 transition-colors">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs text-muted-foreground">Target Scopes</span>
              <Target className="w-3.5 h-3.5 text-cyan-400" />
            </div>
            <div className="text-2xl font-bold font-mono text-foreground">
              {isLoading ? '--' : overview?.counts.targets}
            </div>
          </div>

          {/* Test Runs */}
          <div className="p-3.5 rounded-xl bg-card/60 border border-border/70 hover:border-emerald-500/40 transition-colors">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs text-muted-foreground">Test Runs</span>
              <PlayCircle className="w-3.5 h-3.5 text-emerald-400" />
            </div>
            <div className="text-2xl font-bold font-mono text-foreground">
              {isLoading ? '--' : overview?.counts.testRuns}
            </div>
          </div>

          {/* Total Findings */}
          <div className="p-3.5 rounded-xl bg-card/60 border border-border/70 hover:border-rose-500/40 transition-colors">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs text-muted-foreground">Total Findings</span>
              <AlertOctagon className="w-3.5 h-3.5 text-rose-400" />
            </div>
            <div className="text-2xl font-bold font-mono text-rose-400">
              {isLoading ? '--' : overview?.counts.findings}
            </div>
          </div>

          {/* Evidence Records */}
          <div className="p-3.5 rounded-xl bg-card/60 border border-border/70 hover:border-amber-500/40 transition-colors">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs text-muted-foreground">Evidence Records</span>
              <Lock className="w-3.5 h-3.5 text-amber-400" />
            </div>
            <div className="text-2xl font-bold font-mono text-foreground">
              {isLoading ? '--' : overview?.counts.evidenceRecords}
            </div>
          </div>

          {/* Policies & Gates */}
          <div className="p-3.5 rounded-xl bg-card/60 border border-border/70 hover:border-purple-500/40 transition-colors">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs text-muted-foreground">Policies & Gates</span>
              <Scale className="w-3.5 h-3.5 text-purple-400" />
            </div>
            <div className="text-2xl font-bold font-mono text-foreground">
              {isLoading ? '--' : overview?.counts.policies}
            </div>
          </div>

          {/* Releases */}
          <div className="p-3.5 rounded-xl bg-card/60 border border-border/70 hover:border-blue-500/40 transition-colors">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs text-muted-foreground">Releases Evaluated</span>
              <CheckCircle2 className="w-3.5 h-3.5 text-blue-400" />
            </div>
            <div className="text-2xl font-bold font-mono text-foreground">
              {isLoading ? '--' : overview?.counts.releases}
            </div>
          </div>

          {/* Artifacts & Reports */}
          <div className="p-3.5 rounded-xl bg-card/60 border border-border/70 hover:border-cyan-500/40 transition-colors">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs text-muted-foreground">Artifacts / Reports</span>
              <FileText className="w-3.5 h-3.5 text-cyan-400" />
            </div>
            <div className="text-2xl font-bold font-mono text-foreground">
              {isLoading ? '--' : (overview?.counts.artifacts || 0) + (overview?.counts.reports || 0)}
            </div>
          </div>

          {/* Distributed Agents */}
          <div className="p-3.5 rounded-xl bg-card/60 border border-border/70 hover:border-indigo-500/40 transition-colors">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs text-muted-foreground">Agents Registered</span>
              <Zap className="w-3.5 h-3.5 text-indigo-400" />
            </div>
            <div className="text-2xl font-bold font-mono text-foreground">
              {isLoading ? '--' : overview?.counts.agents}
            </div>
          </div>

          {/* Queued Worker Jobs */}
          <div className="p-3.5 rounded-xl bg-card/60 border border-border/70 hover:border-yellow-500/40 transition-colors">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs text-muted-foreground">Worker Jobs</span>
              <Clock className="w-3.5 h-3.5 text-yellow-400" />
            </div>
            <div className="text-2xl font-bold font-mono text-foreground">
              {isLoading ? '--' : overview?.counts.agentJobs}
            </div>
          </div>

          {/* Critical Vulnerabilities */}
          <div className="p-3.5 rounded-xl bg-rose-950/20 border border-rose-500/30">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs text-rose-300 font-medium">Critical Findings</span>
              <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
            </div>
            <div className="text-2xl font-bold font-mono text-rose-400">
              {isLoading ? '--' : overview?.counts.criticalFindings}
            </div>
          </div>

          {/* High Vulnerabilities */}
          <div className="p-3.5 rounded-xl bg-amber-950/20 border border-amber-500/30">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs text-amber-300 font-medium">High Findings</span>
              <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
            </div>
            <div className="text-2xl font-bold font-mono text-amber-400">
              {isLoading ? '--' : overview?.counts.highFindings}
            </div>
          </div>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* Platform Backup & Disaster Recovery Vault                               */}
      {/* ========================================================================= */}
      <div className="space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center space-x-2.5">
            <div className="p-2 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
              <Archive className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-lg font-semibold text-foreground flex items-center space-x-2">
                <span>Backup & Disaster Recovery Vault</span>
                <span className="px-2 py-0.5 text-[10px] font-semibold rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                  SHA-256 Verified
                </span>
              </h2>
              <p className="text-xs text-muted-foreground">
                Export complete platform snapshots, verify integrity signatures, and restore system state.
              </p>
            </div>
          </div>

          <div className="flex items-center space-x-2">
            <button
              type="button"
              onClick={() => fileInputRef.current?.click()}
              className="flex items-center space-x-1.5 px-3 py-1.5 text-xs font-medium rounded-lg bg-accent/60 hover:bg-accent text-foreground border border-border/70 transition-colors"
            >
              <Upload className="w-3.5 h-3.5 text-cyan-400" />
              <span>Import JSON Backup</span>
            </button>
          </div>
        </div>

        {/* Snapshot Creation Control Card */}
        <div className="glass-card p-5 rounded-xl border border-border/80 space-y-4">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="flex-1 space-y-1">
              <h3 className="text-sm font-semibold text-foreground flex items-center space-x-2">
                <ShieldCheck className="w-4 h-4 text-emerald-400" />
                <span>Create Platform Snapshot</span>
              </h3>
              <p className="text-xs text-muted-foreground">
                Generates a JSON snapshot containing all core models (tenants, projects, scopes, policies, test runs, findings, evidence, releases) with a cryptographic SHA-256 fingerprint.
              </p>
            </div>

            <div className="flex flex-wrap items-center gap-3">
              <label className="flex items-center space-x-2 text-xs text-muted-foreground cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={includeExecutions}
                  onChange={(e) => setIncludeExecutions(e.target.checked)}
                  className="rounded border-border text-emerald-500 focus:ring-emerald-500/30"
                />
                <span>Include Execution Logs & Findings</span>
              </label>

              <button
                type="button"
                onClick={() =>
                  createBackupMutation.mutate({
                    description: backupDescription || undefined,
                    includeExecutions,
                  })
                }
                disabled={createBackupMutation.isPending}
                className="flex items-center space-x-2 px-4 py-2 text-xs font-semibold rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white shadow-lg shadow-emerald-950/50 hover:shadow-emerald-900/60 transition-all hover:scale-[1.02]"
              >
                {createBackupMutation.isPending ? (
                  <>
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    <span>Creating Snapshot...</span>
                  </>
                ) : (
                  <>
                    <Archive className="w-3.5 h-3.5" />
                    <span>Create Snapshot Now</span>
                  </>
                )}
              </button>
            </div>
          </div>

          <div className="flex items-center space-x-2">
            <input
              type="text"
              value={backupDescription}
              onChange={(e) => setBackupDescription(e.target.value)}
              placeholder="Optional snapshot note (e.g. Pre-production audit baseline, sprint 24 release)"
              className="flex-1 px-3.5 py-2 text-xs rounded-lg bg-background/80 border border-border focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500 text-foreground placeholder:text-muted-foreground/40 outline-none"
            />
          </div>
        </div>

        {/* Existing Snapshots Table */}
        <div className="glass-card rounded-xl border border-border/80 overflow-hidden">
          <div className="px-5 py-3.5 border-b border-border/70 flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <HardDrive className="w-4 h-4 text-emerald-400" />
              <h3 className="text-sm font-semibold text-foreground">Stored Platform Backups</h3>
            </div>
            <span className="text-xs text-muted-foreground font-mono">
              {backups.length} {backups.length === 1 ? 'Archive' : 'Archives'} on Disk
            </span>
          </div>

          {backups.length === 0 ? (
            <div className="p-10 text-center space-y-3">
              <div className="p-3 rounded-2xl bg-accent/40 text-muted-foreground inline-block">
                <Archive className="w-8 h-8 opacity-40 mx-auto" />
              </div>
              <div className="text-xs font-medium text-foreground">No Stored Backups Found</div>
              <p className="text-xs text-muted-foreground max-w-sm mx-auto">
                Generate a full platform snapshot above or import an external JSON backup file to initialize disaster recovery records.
              </p>
            </div>
          ) : (
            <div className="divide-y divide-border/40">
              {backups.map((b) => (
                <div
                  key={b.id}
                  className="p-4 flex flex-col lg:flex-row lg:items-center justify-between gap-4 hover:bg-accent/20 transition-colors"
                >
                  <div className="space-y-2 min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-mono text-xs font-semibold text-foreground">
                        {b.filename}
                      </span>
                      <span className="px-2 py-0.5 text-[10px] font-mono rounded bg-accent text-muted-foreground border border-border/60">
                        {formatBytes(b.sizeBytes)}
                      </span>
                      <span className="text-[11px] text-muted-foreground">
                        {new Date(b.createdAt).toLocaleString()}
                      </span>
                    </div>

                    {b.description && (
                      <p className="text-xs text-foreground/80 italic">{b.description}</p>
                    )}

                    {/* Checksum Pill */}
                    <div className="flex items-center space-x-2">
                      <div className="flex items-center space-x-1.5 font-mono text-[11px] text-muted-foreground bg-accent/40 px-2.5 py-1 rounded border border-border/50">
                        <span className="text-emerald-400 font-semibold">SHA-256:</span>
                        <span className="truncate max-w-[280px] sm:max-w-md">{b.sha256}</span>
                      </div>
                      <button
                        type="button"
                        onClick={() => copySha(b.sha256)}
                        title="Copy SHA-256 Fingerprint"
                        className="p-1 text-muted-foreground hover:text-foreground transition-colors"
                      >
                        {copiedSha === b.sha256 ? (
                          <Check className="w-3.5 h-3.5 text-emerald-400" />
                        ) : (
                          <Copy className="w-3.5 h-3.5" />
                        )}
                      </button>
                    </div>

                    {/* Breakdown Badges */}
                    <div className="flex flex-wrap items-center gap-1.5 pt-1 text-[10px] font-mono">
                      <span className="px-2 py-0.5 rounded bg-blue-500/10 text-blue-300 border border-blue-500/20">
                        {b.counts.projects} Projects
                      </span>
                      <span className="px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/20">
                        {b.counts.targets} Scopes
                      </span>
                      <span className="px-2 py-0.5 rounded bg-purple-500/10 text-purple-300 border border-purple-500/20">
                        {b.counts.policies} Policies
                      </span>
                      <span className="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-300 border border-emerald-500/20">
                        {b.counts.testRuns} Runs
                      </span>
                      <span className="px-2 py-0.5 rounded bg-rose-500/10 text-rose-300 border border-rose-500/20">
                        {b.counts.findings} Findings
                      </span>
                      <span className="px-2 py-0.5 rounded bg-amber-500/10 text-amber-300 border border-amber-500/20">
                        {b.counts.evidenceRecords} Evidence
                      </span>
                    </div>
                  </div>

                  {/* Actions */}
                  <div className="flex items-center space-x-2 shrink-0">
                    <button
                      type="button"
                      onClick={() => handleDownloadBackup(b)}
                      title="Download JSON Snapshot"
                      className="flex items-center space-x-1.5 px-3 py-1.5 text-xs font-medium rounded-lg bg-accent/60 hover:bg-accent text-foreground border border-border/70 transition-colors"
                    >
                      <Download className="w-3.5 h-3.5 text-blue-400" />
                      <span>Download</span>
                    </button>

                    <button
                      type="button"
                      onClick={() => {
                        setRestoreModalTarget({
                          isUploaded: false,
                          backupId: b.id,
                          filename: b.filename,
                          counts: b.counts,
                          createdAt: b.createdAt,
                          sha256: b.sha256,
                          description: b.description,
                        });
                        setRestoreMode('replace');
                        setRestoreConfirmation('');
                      }}
                      title="Restore Platform from this Backup"
                      className="flex items-center space-x-1.5 px-3 py-1.5 text-xs font-medium rounded-lg bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-300 border border-emerald-500/30 transition-colors"
                    >
                      <RotateCcw className="w-3.5 h-3.5 text-emerald-400" />
                      <span>Restore</span>
                    </button>

                    <button
                      type="button"
                      onClick={() => {
                        if (confirm(`Are you sure you want to permanently delete backup snapshot ${b.filename}?`)) {
                          deleteBackupMutation.mutate(b.id);
                        }
                      }}
                      title="Delete Backup File"
                      className="p-1.5 text-xs rounded-lg text-muted-foreground hover:text-rose-400 hover:bg-rose-500/10 transition-colors"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Universal Data Operations & Maintenance Center */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <Trash2 className="w-5 h-5 text-rose-400" />
            <h2 className="text-lg font-semibold text-foreground">Data Operations & Maintenance Hub</h2>
          </div>
          <span className="text-xs text-muted-foreground">
            Surgical data management and factory reset controls
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {PURGE_OPTIONS.map((option) => {
            const isAll = option.mode === 'all';
            return (
              <div
                key={option.mode}
                className={`p-5 rounded-xl flex flex-col justify-between transition-all ${
                  isAll
                    ? 'glass-card border-rose-500/40 bg-gradient-to-br from-rose-950/30 to-background glow-rose'
                    : 'glass-card border-border/80'
                }`}
              >
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span
                      className={`text-[11px] font-semibold px-2 py-0.5 rounded-full ${
                        isAll
                          ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                          : 'bg-accent text-muted-foreground border border-border/60'
                      }`}
                    >
                      {option.badge}
                    </span>
                    {isAll && <Flame className="w-4 h-4 text-rose-400 animate-pulse" />}
                  </div>

                  <div>
                    <h3 className={`text-base font-semibold ${isAll ? 'text-rose-200' : 'text-foreground'}`}>
                      {option.title}
                    </h3>
                    <p className="text-xs text-muted-foreground mt-1 leading-relaxed">
                      {option.description}
                    </p>
                  </div>

                  <div
                    className={`p-3 rounded-lg text-xs flex items-start space-x-2 ${
                      isAll
                        ? 'bg-rose-950/40 border border-rose-500/30 text-rose-300'
                        : 'bg-accent/40 border border-border/50 text-muted-foreground'
                    }`}
                  >
                    <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
                    <span>{option.warning}</span>
                  </div>
                </div>

                <div className="pt-4 mt-2">
                  <button
                    type="button"
                    onClick={() => {
                      setActiveModalPurge(option);
                      setConfirmationInput('');
                    }}
                    className={`w-full py-2.5 px-4 text-xs font-semibold rounded-lg flex items-center justify-center space-x-2 transition-all ${
                      isAll
                        ? 'bg-rose-600 hover:bg-rose-500 text-white shadow-lg shadow-rose-950/50 hover:shadow-rose-900/60'
                        : 'bg-accent hover:bg-accent/80 text-foreground border border-border/70 hover:border-border'
                    }`}
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                    <span>{option.buttonLabel}</span>
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Recent System Audit Events Feed */}
      <div className="glass-card rounded-xl border border-border/80 overflow-hidden">
        <div className="px-5 py-4 border-b border-border/70 flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <Activity className="w-4 h-4 text-blue-400" />
            <h3 className="text-sm font-semibold text-foreground">Recent Platform & Agent Audit Trail</h3>
          </div>
          <span className="text-xs text-muted-foreground">Showing last {auditEvents.length} events</span>
        </div>

        {auditEvents.length === 0 ? (
          <div className="p-8 text-center text-xs text-muted-foreground">
            No audit events recorded yet. Run a security test or enroll an agent to see real-time trail.
          </div>
        ) : (
          <div className="divide-y divide-border/40 max-h-72 overflow-y-auto font-mono text-xs">
            {auditEvents.map((evt: any) => (
              <div key={evt.id} className="p-3.5 flex items-center justify-between hover:bg-accent/20 transition-colors">
                <div className="flex items-center space-x-3">
                  <span className="px-2 py-0.5 rounded text-[10px] bg-blue-500/10 text-blue-400 border border-blue-500/20">
                    {evt.eventType}
                  </span>
                  <span className="text-foreground">{evt.actorType}: {evt.actorId?.slice(0, 16)}</span>
                  {evt.ipAddress && <span className="text-muted-foreground text-[11px]">({evt.ipAddress})</span>}
                </div>
                <span className="text-muted-foreground text-[11px]">
                  {new Date(evt.createdAt).toLocaleTimeString()}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* ========================================================================= */}
      {/* Safety Confirmation Modal: Purge Operations                              */}
      {/* ========================================================================= */}
      {activeModalPurge && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md animate-fade-in">
          <div className="relative w-full max-w-lg p-6 rounded-2xl bg-card border border-rose-500/40 shadow-2xl space-y-5">
            <div className="flex items-start justify-between">
              <div className="flex items-center space-x-3">
                <div className="p-2.5 rounded-xl bg-rose-500/20 border border-rose-500/30 text-rose-400">
                  <ShieldAlert className="w-6 h-6" />
                </div>
                <div>
                  <h3 className="text-lg font-bold text-foreground">
                    Confirm {activeModalPurge.title}
                  </h3>
                  <span className="text-xs text-rose-400 font-medium">
                    Permanent and Irreversible Operation
                  </span>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setActiveModalPurge(null)}
                className="p-1 rounded-lg text-muted-foreground hover:text-foreground hover:bg-accent"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="p-3.5 rounded-xl bg-rose-950/30 border border-rose-500/30 text-xs text-rose-200 leading-relaxed">
              {activeModalPurge.warning}
            </div>

            {/* Safety Phrase Verification */}
            <div className="space-y-2">
              <label className="block text-xs font-medium text-foreground">
                To confirm, type <span className="font-mono font-bold text-rose-400">CLEAR ALL DATA</span> below:
              </label>
              <input
                type="text"
                value={confirmationInput}
                onChange={(e) => setConfirmationInput(e.target.value)}
                placeholder="CLEAR ALL DATA"
                className="w-full px-3.5 py-2.5 rounded-lg bg-background border border-border focus:border-rose-500 focus:ring-1 focus:ring-rose-500 text-sm font-mono text-foreground placeholder:text-muted-foreground/40 outline-none"
                autoFocus
              />
            </div>

            <div className="flex items-center justify-end space-x-3 pt-2">
              <button
                type="button"
                onClick={() => setActiveModalPurge(null)}
                disabled={purgeMutation.isPending}
                className="px-4 py-2 text-xs font-medium rounded-lg bg-accent text-foreground hover:bg-accent/80 transition-colors"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={() =>
                  purgeMutation.mutate({
                    mode: activeModalPurge.mode,
                    confirmation: confirmationInput,
                  })
                }
                disabled={
                  purgeMutation.isPending ||
                  (confirmationInput.trim().toUpperCase() !== 'CLEAR ALL DATA' &&
                    confirmationInput.trim().toUpperCase() !== 'CONFIRM_PURGE')
                }
                className="px-4 py-2 text-xs font-semibold rounded-lg bg-rose-600 hover:bg-rose-500 disabled:opacity-40 disabled:pointer-events-none text-white shadow-lg shadow-rose-950/50 flex items-center space-x-2 transition-all"
              >
                {purgeMutation.isPending ? (
                  <>
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    <span>Executing Purge...</span>
                  </>
                ) : (
                  <>
                    <Trash2 className="w-3.5 h-3.5" />
                    <span>Execute Purge</span>
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* Backup Restoration Modal                                                 */}
      {/* ========================================================================= */}
      {restoreModalTarget && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md animate-fade-in">
          <div className="relative w-full max-w-xl p-6 rounded-2xl bg-card border border-emerald-500/40 shadow-2xl space-y-5">
            <div className="flex items-start justify-between">
              <div className="flex items-center space-x-3">
                <div className="p-2.5 rounded-xl bg-emerald-500/20 border border-emerald-500/30 text-emerald-400">
                  <RotateCcw className="w-6 h-6" />
                </div>
                <div>
                  <h3 className="text-lg font-bold text-foreground">
                    Restore Platform Snapshot
                  </h3>
                  <span className="text-xs text-muted-foreground font-mono">
                    {restoreModalTarget.filename}
                  </span>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setRestoreModalTarget(null)}
                className="p-1 rounded-lg text-muted-foreground hover:text-foreground hover:bg-accent"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Target Breakdown Card */}
            <div className="p-4 rounded-xl bg-accent/40 border border-border/60 space-y-3">
              <div className="flex items-center justify-between text-xs">
                <span className="text-muted-foreground">Snapshot Created:</span>
                <span className="font-mono text-foreground">
                  {new Date(restoreModalTarget.createdAt).toLocaleString()}
                </span>
              </div>
              {restoreModalTarget.sha256 && (
                <div className="flex items-center justify-between text-xs">
                  <span className="text-muted-foreground">SHA-256 Checksum:</span>
                  <span className="font-mono text-[11px] text-emerald-400 truncate max-w-[320px]">
                    {restoreModalTarget.sha256}
                  </span>
                </div>
              )}
              <div className="grid grid-cols-3 sm:grid-cols-6 gap-2 pt-1 text-center font-mono text-[11px]">
                <div className="p-1.5 rounded bg-background/60 border border-border/40">
                  <div className="font-bold text-foreground">{restoreModalTarget.counts.projects ?? 0}</div>
                  <div className="text-[10px] text-muted-foreground">Projects</div>
                </div>
                <div className="p-1.5 rounded bg-background/60 border border-border/40">
                  <div className="font-bold text-foreground">{restoreModalTarget.counts.targets ?? 0}</div>
                  <div className="text-[10px] text-muted-foreground">Targets</div>
                </div>
                <div className="p-1.5 rounded bg-background/60 border border-border/40">
                  <div className="font-bold text-foreground">{restoreModalTarget.counts.policies ?? 0}</div>
                  <div className="text-[10px] text-muted-foreground">Policies</div>
                </div>
                <div className="p-1.5 rounded bg-background/60 border border-border/40">
                  <div className="font-bold text-foreground">{restoreModalTarget.counts.testRuns ?? 0}</div>
                  <div className="text-[10px] text-muted-foreground">Runs</div>
                </div>
                <div className="p-1.5 rounded bg-background/60 border border-border/40">
                  <div className="font-bold text-rose-400">{restoreModalTarget.counts.findings ?? 0}</div>
                  <div className="text-[10px] text-muted-foreground">Findings</div>
                </div>
                <div className="p-1.5 rounded bg-background/60 border border-border/40">
                  <div className="font-bold text-amber-400">{restoreModalTarget.counts.evidenceRecords ?? 0}</div>
                  <div className="text-[10px] text-muted-foreground">Evidence</div>
                </div>
              </div>
            </div>

            {/* Mode Selection */}
            <div className="space-y-2">
              <label className="block text-xs font-semibold text-foreground uppercase tracking-wider">
                Restoration Mode
              </label>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div
                  onClick={() => setRestoreMode('replace')}
                  className={`p-3.5 rounded-xl border cursor-pointer transition-all ${
                    restoreMode === 'replace'
                      ? 'border-rose-500/50 bg-rose-950/20 ring-1 ring-rose-500/30'
                      : 'border-border/60 bg-accent/20 hover:bg-accent/40'
                  }`}
                >
                  <div className="flex items-center space-x-2 mb-1">
                    <input
                      type="radio"
                      checked={restoreMode === 'replace'}
                      onChange={() => setRestoreMode('replace')}
                      className="text-rose-500 focus:ring-rose-500/30"
                    />
                    <span className="text-xs font-bold text-foreground">Clean Wipe & Restore</span>
                  </div>
                  <p className="text-[11px] text-muted-foreground leading-normal pl-5">
                    Wipes current database tables before restoring snapshot state. Ensures clean 1:1 replica.
                  </p>
                </div>

                <div
                  onClick={() => setRestoreMode('merge')}
                  className={`p-3.5 rounded-xl border cursor-pointer transition-all ${
                    restoreMode === 'merge'
                      ? 'border-emerald-500/50 bg-emerald-950/20 ring-1 ring-emerald-500/30'
                      : 'border-border/60 bg-accent/20 hover:bg-accent/40'
                  }`}
                >
                  <div className="flex items-center space-x-2 mb-1">
                    <input
                      type="radio"
                      checked={restoreMode === 'merge'}
                      onChange={() => setRestoreMode('merge')}
                      className="text-emerald-500 focus:ring-emerald-500/30"
                    />
                    <span className="text-xs font-bold text-foreground">Merge & Upsert</span>
                  </div>
                  <p className="text-[11px] text-muted-foreground leading-normal pl-5">
                    Non-destructive: inserts missing snapshot records while retaining existing live data.
                  </p>
                </div>
              </div>
            </div>

            {/* Strict Safety Confirmation for Replace Mode */}
            {restoreMode === 'replace' && (
              <div className="space-y-2 p-3.5 rounded-xl bg-rose-950/20 border border-rose-500/30">
                <label className="block text-xs font-medium text-rose-200">
                  To confirm clean database overwrite, type{' '}
                  <span className="font-mono font-bold text-rose-400">CONFIRM_RESTORE</span> below:
                </label>
                <input
                  type="text"
                  value={restoreConfirmation}
                  onChange={(e) => setRestoreConfirmation(e.target.value)}
                  placeholder="CONFIRM_RESTORE"
                  className="w-full px-3.5 py-2 rounded-lg bg-background border border-rose-500/40 focus:border-rose-500 focus:ring-1 focus:ring-rose-500 text-sm font-mono text-foreground placeholder:text-muted-foreground/40 outline-none"
                  autoFocus
                />
              </div>
            )}

            <div className="flex items-center justify-end space-x-3 pt-2">
              <button
                type="button"
                onClick={() => setRestoreModalTarget(null)}
                disabled={restoreBackupMutation.isPending}
                className="px-4 py-2 text-xs font-medium rounded-lg bg-accent text-foreground hover:bg-accent/80 transition-colors"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={() =>
                  restoreBackupMutation.mutate({
                    mode: restoreMode,
                    confirmation: restoreConfirmation,
                    backupId: restoreModalTarget.backupId,
                    backupData: restoreModalTarget.backupData,
                  })
                }
                disabled={
                  restoreBackupMutation.isPending ||
                  (restoreMode === 'replace' &&
                    restoreConfirmation.trim().toUpperCase() !== 'CONFIRM_RESTORE' &&
                    restoreConfirmation.trim().toUpperCase() !== 'RESTORE_REPLACE')
                }
                className="px-4 py-2 text-xs font-semibold rounded-lg bg-emerald-600 hover:bg-emerald-500 disabled:opacity-40 disabled:pointer-events-none text-white shadow-lg shadow-emerald-950/50 flex items-center space-x-2 transition-all"
              >
                {restoreBackupMutation.isPending ? (
                  <>
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    <span>Restoring Platform State...</span>
                  </>
                ) : (
                  <>
                    <RotateCcw className="w-3.5 h-3.5" />
                    <span>Confirm Restoration</span>
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

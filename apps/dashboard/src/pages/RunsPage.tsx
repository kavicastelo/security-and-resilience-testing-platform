import React, { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import {
  RotateCw,
  Clock,
  CheckCircle2,
  XCircle,
  Activity,
  Search,
  Radio,
  Filter,
} from 'lucide-react';
import { LiveRunMonitor } from '../components/LiveRunMonitor.js';
import { Pagination } from '../components/Pagination.js';
import { authFetch } from '../api/client.js';

interface TestRunSummary {
  totalTests: number;
  passedTests: number;
  failedTests: number;
  errorTests: number;
  findingsCount: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
}

interface TestRun {
  id: string;
  projectId: string;
  targetId: string;
  profileId?: string;
  status: 'pending' | 'queued' | 'running' | 'completed' | 'failed' | 'cancelled';
  startedAt?: string;
  completedAt?: string;
  summary: TestRunSummary;
  createdAt: string;
}

export const RunsPage: React.FC = () => {
  const queryClient = useQueryClient();
  const apiUrl = import.meta.env.VITE_API_URL || 'http://localhost:4000';

  const [selectedRunId, setSelectedRunId] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [currentPage, setCurrentPage] = useState<number>(1);
  const [pageSize, setPageSize] = useState<number>(8);

  // Fetch test runs
  const { data: runs = [] } = useQuery<TestRun[]>({
    queryKey: ['test-runs'],
    queryFn: async () => {
      const res = await authFetch(`${apiUrl}/api/v1/test-runs`);
      if (!res.ok) throw new Error('Failed to fetch test runs');
      const json = await res.json();
      return (json.data || []).sort(
        (a: TestRun, b: TestRun) =>
          new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
      );
    },
    refetchInterval: 5000, // Poll fallback
  });

  // Selected run details
  const selectedRun = runs.find((r) => r.id === selectedRunId) || (runs.length > 0 ? runs[0] : null);

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'running':
        return (
          <span className="flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-blue-950/60 text-blue-400 border border-blue-800 animate-pulse">
            <span className="w-1.5 h-1.5 rounded-full bg-blue-400 animate-ping"></span>
            Running
          </span>
        );
      case 'completed':
        return (
          <span className="flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-950/60 text-emerald-400 border border-emerald-800">
            <CheckCircle2 className="w-3.5 h-3.5" />
            Completed
          </span>
        );
      case 'failed':
        return (
          <span className="flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-rose-950/60 text-rose-400 border border-rose-800">
            <XCircle className="w-3.5 h-3.5" />
            Failed
          </span>
        );
      case 'queued':
      case 'pending':
        return (
          <span className="flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-950/60 text-amber-400 border border-amber-800">
            <Clock className="w-3.5 h-3.5" />
            Queued
          </span>
        );
      default:
        return (
          <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-slate-800 text-slate-400 border border-slate-700">
            {status}
          </span>
        );
    }
  };

  const filteredRuns = runs.filter((r) => {
    const matchesStatus = statusFilter === 'all' || r.status === statusFilter;
    const matchesSearch =
      searchQuery === '' ||
      r.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (r.profileId && r.profileId.toLowerCase().includes(searchQuery.toLowerCase()));
    return matchesStatus && matchesSearch;
  });

  const paginatedRuns = filteredRuns.slice((currentPage - 1) * pageSize, currentPage * pageSize);

  return (
    <div className="space-y-6">
      {/* Page Title */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2">
            <Activity className="w-7 h-7 text-blue-500" />
            Live Run Operations Console
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Real-time SSE event streaming, execution progress, active engine stages, and telemetry logs.
          </p>
        </div>
        <button
          onClick={() => queryClient.invalidateQueries({ queryKey: ['test-runs'] })}
          className="flex items-center gap-2 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium rounded-lg border border-slate-700 transition-colors self-start sm:self-auto"
        >
          <RotateCw className="w-3.5 h-3.5" />
          Refresh
        </button>
      </div>

      {/* Selected Run Real-time SSE Monitor */}
      {selectedRun && (
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Radio className="w-4 h-4 text-emerald-400 animate-pulse" />
              <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-300">
                Active Execution Monitor: <span className="font-mono text-blue-400">{selectedRun.id.slice(0, 8)}…</span>
              </h2>
            </div>
            {getStatusBadge(selectedRun.status)}
          </div>
          <LiveRunMonitor
            runId={selectedRun.id}
            initialStatus={selectedRun.status}
            onComplete={() => {
              queryClient.invalidateQueries({ queryKey: ['test-runs'] });
              queryClient.invalidateQueries({ queryKey: ['findings'] });
            }}
          />
        </div>
      )}

      {/* Runs Filter and History Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
        <div className="p-4 border-b border-slate-800 bg-slate-950/60 flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="relative w-full sm:w-80">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search by run ID or profile..."
              value={searchQuery}
              onChange={(e) => {
                setSearchQuery(e.target.value);
                setCurrentPage(1);
              }}
              className="w-full bg-slate-900 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500"
            />
          </div>

          <div className="flex items-center gap-2 w-full sm:w-auto">
            <div className="flex items-center gap-1.5 bg-slate-900 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs">
              <Filter className="w-3.5 h-3.5 text-slate-400" />
              <select
                value={statusFilter}
                onChange={(e) => {
                  setStatusFilter(e.target.value);
                  setCurrentPage(1);
                }}
                className="bg-transparent text-slate-300 font-medium focus:outline-none cursor-pointer"
              >
                <option value="all">All Statuses</option>
                <option value="running">Running</option>
                <option value="completed">Completed</option>
                <option value="failed">Failed</option>
                <option value="queued">Queued</option>
              </select>
            </div>
          </div>
        </div>

        {/* Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-950/40 text-xs font-semibold text-slate-400 uppercase tracking-wider">
                <th className="py-3 px-4">Run ID</th>
                <th className="py-3 px-4">Profile</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">Findings Breakdown</th>
                <th className="py-3 px-4">Created</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-sm">
              {paginatedRuns.map((run) => (
                <tr
                  key={run.id}
                  onClick={() => setSelectedRunId(run.id)}
                  className={`cursor-pointer transition-colors ${
                    selectedRun?.id === run.id ? 'bg-blue-950/20' : 'hover:bg-slate-800/40'
                  }`}
                >
                  <td className="py-3 px-4 font-mono text-xs font-bold text-blue-400">
                    {run.id.slice(0, 8)}…
                  </td>
                  <td className="py-3 px-4 text-xs font-mono text-slate-300">
                    {run.profileId || 'custom-plan'}
                  </td>
                  <td className="py-3 px-4">{getStatusBadge(run.status)}</td>
                  <td className="py-3 px-4">
                    <div className="flex items-center gap-1.5 text-xs">
                      {run.summary?.findingsCount?.critical > 0 && (
                        <span className="px-1.5 py-0.5 rounded bg-purple-950/60 text-purple-400 border border-purple-800 font-mono font-bold">
                          {run.summary.findingsCount.critical} Crit
                        </span>
                      )}
                      {run.summary?.findingsCount?.high > 0 && (
                        <span className="px-1.5 py-0.5 rounded bg-rose-950/60 text-rose-400 border border-rose-800 font-mono font-bold">
                          {run.summary.findingsCount.high} High
                        </span>
                      )}
                      {run.summary?.findingsCount?.medium > 0 && (
                        <span className="px-1.5 py-0.5 rounded bg-amber-950/60 text-amber-400 border border-amber-800 font-mono font-bold">
                          {run.summary.findingsCount.medium} Med
                        </span>
                      )}
                      {!run.summary?.findingsCount?.critical &&
                        !run.summary?.findingsCount?.high &&
                        !run.summary?.findingsCount?.medium && (
                          <span className="text-xs text-slate-500">Clean</span>
                        )}
                    </div>
                  </td>
                  <td className="py-3 px-4 text-xs text-slate-400 whitespace-nowrap">
                    {new Date(run.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                  </td>
                  <td className="py-3 px-4 text-right">
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        setSelectedRunId(run.id);
                      }}
                      className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-xs border border-slate-700 transition-colors"
                    >
                      Inspect Stream
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Pagination Footer */}
        {filteredRuns.length > 0 && (
          <div className="p-4 border-t border-slate-800 bg-slate-950/40">
            <Pagination
              currentPage={currentPage}
              onPageChange={setCurrentPage}
              pageSize={pageSize}
              onPageSizeChange={setPageSize}
              totalItems={filteredRuns.length}
            />
          </div>
        )}
      </div>
    </div>
  );
};

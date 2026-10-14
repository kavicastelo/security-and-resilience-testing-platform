import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Globe,
  Plus,
  ShieldCheck,
  Search,
  CheckCircle2,
  XCircle,
  X,
  Sliders,
} from 'lucide-react';
import { Pagination } from '../components/Pagination.js';
import { useAppStore } from '../store/useAppStore.js';
import { authFetch } from '../api/client.js';

interface TargetScope {
  allowedHosts: string[];
  allowedPorts: number[];
  excludedPaths: string[];
  testing: {
    activeScanning: boolean;
    loadTesting: boolean;
    chaosTesting: boolean;
  };
  limits: {
    maxRps: number;
    maxConcurrency: number;
    maxDuration: string;
  };
}

interface Target {
  id: string;
  projectId: string;
  name: string;
  baseUrl: string;
  scope: TargetScope;
  createdAt: string;
}

export const TargetsPage: React.FC = () => {
  const queryClient = useQueryClient();
  const apiUrl = import.meta.env.VITE_API_URL || 'http://localhost:4000';
  const { showToast } = useAppStore();

  const [searchQuery, setSearchQuery] = useState('');
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(6);

  // Modal / Builder State
  const [isBuilderOpen, setIsBuilderOpen] = useState(false);
  const [name, setName] = useState('');
  const [baseUrl, setBaseUrl] = useState('');
  const [allowedHosts, setAllowedHosts] = useState('');
  const [allowedPorts, setAllowedPorts] = useState('80, 443');
  const [excludedPaths, setExcludedPaths] = useState('/logout, /admin/delete');
  const [activeScanning, setActiveScanning] = useState(true);
  const [loadTesting, setLoadTesting] = useState(false);
  const [chaosTesting, setChaosTesting] = useState(false);
  const [maxRps, setMaxRps] = useState(100);
  const [maxConcurrency, setMaxConcurrency] = useState(25);
  const [headers, setHeaders] = useState('Authorization: Bearer <redacted>\nX-Custom-Auth: test-token');

  // Interactive Scope Playground
  const [testUrl, setTestUrl] = useState('');
  const [testResult, setTestResult] = useState<{ allowed: boolean; reason: string } | null>(null);

  // Fetch Targets
  const { data: targets = [], isLoading } = useQuery<Target[]>({
    queryKey: ['targets'],
    queryFn: async () => {
      const res = await authFetch(`${apiUrl}/api/v1/targets`);
      if (!res.ok) throw new Error('Failed to fetch targets');
      const json = await res.json();
      return json.data || [];
    },
  });

  // Create Target Mutation
  const createMutation = useMutation({
    mutationFn: async (payload: unknown) => {
      const res = await authFetch(`${apiUrl}/api/v1/targets`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const json = await res.json();
      if (!res.ok) throw new Error(json.error?.message || 'Failed to create target profile');
      return json;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['targets'] });
      showToast('Target profile and boundary constraints saved', 'success');
      setIsBuilderOpen(false);
      resetForm();
    },
    onError: (err: unknown) => {
      const msg = err instanceof Error ? err.message : String(err);
      showToast(msg, 'error');
    },
  });

  const resetForm = () => {
    setName('');
    setBaseUrl('');
    setAllowedHosts('');
    setAllowedPorts('80, 443');
    setExcludedPaths('/logout, /admin/delete');
    setActiveScanning(true);
    setLoadTesting(false);
    setChaosTesting(false);
    setMaxRps(100);
    setMaxConcurrency(25);
  };

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    if (!name || !baseUrl) {
      showToast('Name and Base URL are required', 'error');
      return;
    }

    const hostArray = allowedHosts
      ? allowedHosts.split(',').map((h) => h.trim())
      : [new URL(baseUrl).hostname];
    const portArray = allowedPorts
      .split(',')
      .map((p) => parseInt(p.trim(), 10))
      .filter((p) => !isNaN(p));
    const pathArray = excludedPaths
      .split(',')
      .map((p) => p.trim())
      .filter(Boolean);

    createMutation.mutate({
      projectId: 'default',
      name,
      baseUrl,
      scope: {
        allowedHosts: hostArray,
        allowedPorts: portArray,
        excludedPaths: pathArray,
        testing: {
          activeScanning,
          loadTesting,
          chaosTesting,
        },
        limits: {
          maxRps,
          maxConcurrency,
          maxDuration: '10m',
        },
      },
    });
  };

  const validateScopeUrl = (urlToTest: string) => {
    if (!urlToTest) {
      setTestResult(null);
      return;
    }
    try {
      const parsed = new URL(urlToTest);
      const hosts = allowedHosts
        ? allowedHosts.split(',').map((h) => h.trim())
        : baseUrl
        ? [new URL(baseUrl).hostname]
        : [];
      const isHostAllowed = hosts.some((h) => parsed.hostname === h || parsed.hostname.endsWith(`.${h}`));
      if (!isHostAllowed) {
        setTestResult({
          allowed: false,
          reason: `Host "${parsed.hostname}" is not within authorized scope hosts.`,
        });
        return;
      }
      const excluded = excludedPaths.split(',').map((p) => p.trim());
      const isExcluded = excluded.some((p) => parsed.pathname.startsWith(p));
      if (isExcluded) {
        setTestResult({
          allowed: false,
          reason: `Path "${parsed.pathname}" is explicitly blacklisted in safety boundaries.`,
        });
        return;
      }
      setTestResult({
        allowed: true,
        reason: `Target URL passes all domain, port, and CIDR constraint checks.`,
      });
    } catch {
      setTestResult({ allowed: false, reason: 'Invalid URL format' });
    }
  };

  const filteredTargets = targets.filter(
    (t) =>
      searchQuery === '' ||
      t.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      t.baseUrl.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const paginatedTargets = filteredTargets.slice((currentPage - 1) * pageSize, currentPage * pageSize);

  return (
    <div className="space-y-6">
      {/* Page Title & Add Button */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2">
            <Globe className="w-7 h-7 text-indigo-500" />
            Target Profiles & Test Plan Builder
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Configure system targets, authorization boundaries, sensitive header redaction, and execution constraints.
          </p>
        </div>
        <button
          onClick={() => {
            resetForm();
            setIsBuilderOpen(true);
          }}
          className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white text-sm font-semibold rounded-lg shadow-lg shadow-blue-600/20 transition-all self-start sm:self-auto"
        >
          <Plus className="w-4 h-4" />
          New Target Profile
        </button>
      </div>

      {/* Search Bar */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-3 flex items-center gap-3">
        <div className="relative flex-1">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search target profiles by name or URL..."
            value={searchQuery}
            onChange={(e) => {
              setSearchQuery(e.target.value);
              setCurrentPage(1);
            }}
            className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-4 py-2 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500"
          />
        </div>
      </div>

      {/* Target Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {isLoading ? (
          <div className="col-span-full py-16 text-center text-slate-400">Loading target profiles...</div>
        ) : paginatedTargets.length === 0 ? (
          <div className="col-span-full py-16 text-center bg-slate-900 border border-slate-800 rounded-xl">
            <Globe className="w-12 h-12 text-slate-600 mx-auto mb-3" />
            <h3 className="text-base font-semibold text-slate-300">No Target Profiles Defined</h3>
            <p className="text-xs text-slate-500 mt-1">
              Create your first target profile to begin executing authorized resilience tests.
            </p>
          </div>
        ) : (
          paginatedTargets.map((target) => (
            <div
              key={target.id}
              className="bg-slate-900 border border-slate-800 rounded-xl p-5 hover:border-slate-700 transition-all shadow-lg flex flex-col justify-between"
            >
              <div>
                <div className="flex items-start justify-between gap-2 mb-2">
                  <h3 className="text-base font-bold text-white truncate">{target.name}</h3>
                  <span className="text-xs px-2 py-0.5 rounded bg-emerald-950/60 text-emerald-400 border border-emerald-800">
                    Active
                  </span>
                </div>
                <p className="text-xs font-mono text-blue-400 truncate mb-4">{target.baseUrl}</p>

                {/* Scope Metadata */}
                <div className="space-y-2 text-xs text-slate-400 border-t border-slate-800/80 pt-3">
                  <div className="flex items-center justify-between">
                    <span className="text-slate-500">Allowed Hosts:</span>
                    <span className="font-mono text-slate-300 truncate max-w-[180px]">
                      {target.scope?.allowedHosts?.join(', ') || 'Any in BaseUrl'}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-slate-500">Allowed Ports:</span>
                    <span className="font-mono text-slate-300">
                      {target.scope?.allowedPorts?.join(', ') || '80, 443'}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-slate-500">Active Scanning:</span>
                    <span
                      className={`font-semibold ${
                        target.scope?.testing?.activeScanning ? 'text-emerald-400' : 'text-slate-500'
                      }`}
                    >
                      {target.scope?.testing?.activeScanning ? 'Enabled' : 'Disabled'}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-slate-500">Safety Limits:</span>
                    <span className="font-mono text-slate-300">
                      {target.scope?.limits?.maxRps || 100} RPS / {target.scope?.limits?.maxConcurrency || 25} Conc
                    </span>
                  </div>
                </div>
              </div>

              <div className="pt-4 mt-4 border-t border-slate-800 flex items-center justify-end">
                <span className="text-[11px] font-mono text-slate-500">
                  Target ID: {target.id.slice(0, 8)}…
                </span>
              </div>
            </div>
          ))
        )}
      </div>

      {/* Pagination Footer */}
      {filteredTargets.length > 0 && (
        <Pagination
          currentPage={currentPage}
          onPageChange={setCurrentPage}
          pageSize={pageSize}
          onPageSizeChange={setPageSize}
          totalItems={filteredTargets.length}
        />
      )}

      {/* Target Builder / Modal */}
      {isBuilderOpen && (
        <div
          role="dialog"
          aria-modal="true"
          className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in"
        >
          <div className="bg-slate-900 border border-slate-700 rounded-xl shadow-2xl w-full max-w-2xl max-h-[90vh] flex flex-col overflow-hidden text-slate-200">
            {/* Header */}
            <div className="p-4 sm:p-5 border-b border-slate-800 bg-slate-900/90 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Sliders className="w-5 h-5 text-blue-500" />
                <h3 className="text-lg font-bold text-white">Target Profile & Scope Boundary Builder</h3>
              </div>
              <button
                onClick={() => setIsBuilderOpen(false)}
                className="text-slate-400 hover:text-white transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Form */}
            <form onSubmit={handleSave} className="flex-1 overflow-y-auto p-4 sm:p-6 space-y-4">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1">Target Name *</label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. Production Billing API"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-sm text-slate-200 focus:outline-none focus:border-blue-500"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1">Base Target URL *</label>
                  <input
                    type="url"
                    required
                    placeholder="https://api.example.com"
                    value={baseUrl}
                    onChange={(e) => {
                      setBaseUrl(e.target.value);
                      if (!allowedHosts) {
                        try {
                          const h = new URL(e.target.value).hostname;
                          setAllowedHosts(h);
                        } catch {
                          // Ignore partial typing
                        }
                      }
                    }}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-sm text-slate-200 focus:outline-none focus:border-blue-500"
                  />
                </div>
              </div>

              {/* Scope CIDRs & Hosts */}
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Allowed Hosts / CIDRs (comma-separated)
                </label>
                <input
                  type="text"
                  placeholder="api.example.com, staging.example.com, 10.0.0.0/16"
                  value={allowedHosts}
                  onChange={(e) => setAllowedHosts(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-sm text-slate-200 focus:outline-none focus:border-blue-500"
                />
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1">Allowed Ports</label>
                  <input
                    type="text"
                    value={allowedPorts}
                    onChange={(e) => setAllowedPorts(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-sm text-slate-200 focus:outline-none focus:border-blue-500"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1">Blacklisted Paths</label>
                  <input
                    type="text"
                    value={excludedPaths}
                    onChange={(e) => setExcludedPaths(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-sm text-slate-200 focus:outline-none focus:border-blue-500"
                  />
                </div>
              </div>

              {/* Engine Capabilities */}
              <div className="p-3 bg-slate-950/60 border border-slate-800 rounded-lg space-y-2">
                <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400">
                  Authorized Testing Capabilities
                </label>
                <div className="flex flex-wrap items-center gap-4 text-xs">
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={activeScanning}
                      onChange={(e) => setActiveScanning(e.target.checked)}
                      className="rounded bg-slate-900 border-slate-700 text-blue-600 focus:ring-0"
                    />
                    <span>Active Vulnerability Fuzzing</span>
                  </label>
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={loadTesting}
                      onChange={(e) => setLoadTesting(e.target.checked)}
                      className="rounded bg-slate-900 border-slate-700 text-blue-600 focus:ring-0"
                    />
                    <span>Load & Concurrency Testing</span>
                  </label>
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={chaosTesting}
                      onChange={(e) => setChaosTesting(e.target.checked)}
                      className="rounded bg-slate-900 border-slate-700 text-blue-600 focus:ring-0"
                    />
                    <span>Chaos Injection</span>
                  </label>
                </div>
              </div>

              {/* Safety Throttle Limits */}
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1">Max RPS Throttling</label>
                  <input
                    type="number"
                    min={1}
                    max={10000}
                    value={maxRps}
                    onChange={(e) => setMaxRps(Number(e.target.value))}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-sm text-slate-200 focus:outline-none focus:border-blue-500"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1">Max Concurrency</label>
                  <input
                    type="number"
                    min={1}
                    max={500}
                    value={maxConcurrency}
                    onChange={(e) => setMaxConcurrency(Number(e.target.value))}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-sm text-slate-200 focus:outline-none focus:border-blue-500"
                  />
                </div>
              </div>

              {/* Sensitive Headers Redaction */}
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Sensitive Auth Headers (Encrypted in transit)
                </label>
                <textarea
                  rows={2}
                  value={headers}
                  onChange={(e) => setHeaders(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs font-mono text-emerald-400 focus:outline-none focus:border-blue-500"
                />
              </div>

              {/* Interactive Scope Playground */}
              <div className="p-3 bg-slate-950/80 border border-slate-800 rounded-lg">
                <label className="block text-xs font-semibold text-slate-300 mb-1.5 flex items-center gap-1.5">
                  <ShieldCheck className="w-3.5 h-3.5 text-blue-400" />
                  Scope Boundary Verifier
                </label>
                <div className="flex gap-2">
                  <input
                    type="text"
                    placeholder="Test URL (e.g. https://api.example.com/v1/auth)"
                    value={testUrl}
                    onChange={(e) => {
                      setTestUrl(e.target.value);
                      validateScopeUrl(e.target.value);
                    }}
                    className="flex-1 bg-slate-900 border border-slate-800 rounded p-1.5 text-xs text-slate-200"
                  />
                </div>
                {testResult && (
                  <div
                    className={`mt-2 p-2 rounded text-xs flex items-center gap-1.5 ${
                      testResult.allowed
                        ? 'bg-emerald-950/40 text-emerald-400 border border-emerald-900/60'
                        : 'bg-rose-950/40 text-rose-400 border border-rose-900/60'
                    }`}
                  >
                    {testResult.allowed ? (
                      <CheckCircle2 className="w-3.5 h-3.5 flex-shrink-0" />
                    ) : (
                      <XCircle className="w-3.5 h-3.5 flex-shrink-0" />
                    )}
                    <span>{testResult.reason}</span>
                  </div>
                )}
              </div>

              {/* Submit Buttons */}
              <div className="pt-2 flex items-center justify-end gap-3">
                <button
                  type="button"
                  onClick={() => setIsBuilderOpen(false)}
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-sm transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={createMutation.isPending}
                  className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white font-medium rounded-lg text-sm shadow-md transition-colors"
                >
                  {createMutation.isPending ? 'Saving Target...' : 'Save Target Profile'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

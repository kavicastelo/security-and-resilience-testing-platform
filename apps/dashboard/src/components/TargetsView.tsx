import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  ShieldAlert,
  ShieldCheck,
  Plus,
  Lock,
  Globe,
  Pencil,
  Trash2,
  X,
  Search,
  Copy,
  Terminal,
  Filter,
  Clock,
  Sliders,
  AlertTriangle,
  Zap,
} from 'lucide-react';
import { Pagination } from './Pagination.js';
import { useAppStore } from '../store/useAppStore.js';
import { authFetch } from '../api/client.js';
import {
  targetsApi,
  Target,
  VerificationStatus,
} from '../api/targets.js';
import { TargetStudio } from './targets/TargetStudio.js';
import { OwnershipWizardModal } from './targets/OwnershipWizardModal.js';
import { ScopeSimulatorPlayground } from './targets/ScopeSimulatorPlayground.js';

export const TargetsView: React.FC = () => {
  const queryClient = useQueryClient();
  const apiUrl = import.meta.env.VITE_API_URL || 'http://localhost:4000';
  const { showToast } = useAppStore();

  // Target list query
  const { data: targets = [], isLoading } = useQuery<Target[]>({
    queryKey: ['targets'],
    queryFn: () => targetsApi.listTargets(),
  });

  // Filter & Pagination state
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<'all' | VerificationStatus>('all');
  const [capabilityFilter, setCapabilityFilter] = useState<'all' | 'activeScanning' | 'loadTesting'>('all');
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(6);

  // Active studio & ownership modal state
  const [studioTarget, setStudioTarget] = useState<Target | null>(null);
  const [verificationTarget, setVerificationTarget] = useState<Target | null>(null);
  const [selectedSimulatorTargetId, setSelectedSimulatorTargetId] = useState<string>('');

  // New target modal state
  const [isCreating, setIsCreating] = useState(false);
  const [newTargetName, setNewTargetName] = useState('');
  const [newTargetUrl, setNewTargetUrl] = useState('');
  const [newTargetHosts, setNewTargetHosts] = useState('');
  const [newTargetPorts, setNewTargetPorts] = useState('80, 443');
  const [newExcludedPaths, setNewExcludedPaths] = useState('');
  const [activeScanningOpt, setActiveScanningOpt] = useState(false);
  const [loadTestingOpt, setLoadTestingOpt] = useState(false);
  const [chaosTestingOpt, setChaosTestingOpt] = useState(false);
  const [newMaxRps, setNewMaxRps] = useState(100);
  const [newMaxConcurrency, setNewMaxConcurrency] = useState(20);
  const [allowPrivateIpsOpt, setAllowPrivateIpsOpt] = useState(false);
  const [creationError, setCreationError] = useState<string | null>(null);

  // Edit target modal state
  const [editingTarget, setEditingTarget] = useState<Target | null>(null);
  const [editTargetName, setEditTargetName] = useState('');
  const [editTargetUrl, setEditTargetUrl] = useState('');
  const [editTargetHosts, setEditTargetHosts] = useState('');
  const [editTargetPorts, setEditTargetPorts] = useState('80, 443');
  const [editExcludedPaths, setEditExcludedPaths] = useState('');
  const [editActiveScanning, setEditActiveScanning] = useState(false);
  const [editLoadTesting, setEditLoadTesting] = useState(false);
  const [editChaosTesting, setEditChaosTesting] = useState(false);
  const [editMaxRps, setEditMaxRps] = useState(100);
  const [editMaxConcurrency, setEditMaxConcurrency] = useState(20);
  const [editAllowPrivateIps, setEditAllowPrivateIps] = useState(false);
  const [editError, setEditError] = useState<string | null>(null);

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    showToast(`Copied ${label} to clipboard`, 'info');
  };

  const handleOpenEdit = (target: Target) => {
    setEditingTarget(target);
    setEditTargetName(target.name);
    setEditTargetUrl(target.baseUrl);
    setEditTargetHosts(target.scope?.allowedHosts?.join(', ') || '');
    setEditTargetPorts(target.scope?.allowedPorts?.join(', ') || '80, 443');
    setEditExcludedPaths(target.scope?.excludedPaths?.join(', ') || '');
    setEditActiveScanning(Boolean(target.scope?.testing?.activeScanning));
    setEditLoadTesting(Boolean(target.scope?.testing?.loadTesting));
    setEditChaosTesting(Boolean(target.scope?.testing?.chaosTesting));
    setEditMaxRps(target.scope?.limits?.maxRps ?? 100);
    setEditMaxConcurrency(target.scope?.limits?.maxConcurrency ?? 20);
    setEditAllowPrivateIps(Boolean(target.scope?.allowPrivateIps));
    setEditError(null);
  };

  // Target creation mutation
  const createTargetMutation = useMutation({
    mutationFn: async () => {
      setCreationError(null);
      // Fetch or create default project first
      const projRes = await authFetch(`${apiUrl}/api/v1/projects`);
      const projJson = await projRes.json();
      let projectId = projJson.data?.[0]?.id;

      if (!projectId) {
        const createProj = await authFetch(`${apiUrl}/api/v1/projects`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name: 'Default Enterprise Project' }),
        });
        const createdProjJson = await createProj.json();
        projectId = createdProjJson.data.id;
      }

      const hosts = newTargetHosts
        .split(',')
        .map((h) => h.trim())
        .filter(Boolean);

      if (hosts.length === 0 && newTargetUrl) {
        try {
          const parsedHost = new URL(newTargetUrl).hostname;
          if (parsedHost) hosts.push(parsedHost);
        } catch {
          // ignore
        }
      }

      const parsedPorts = newTargetPorts
        .split(',')
        .map((p) => parseInt(p.trim(), 10))
        .filter((p) => !isNaN(p) && p > 0 && p <= 65535);

      if (parsedPorts.length === 0 && newTargetUrl) {
        try {
          const parsed = new URL(newTargetUrl);
          if (parsed.port) {
            parsedPorts.push(parseInt(parsed.port, 10));
          } else if (parsed.protocol === 'https:') {
            parsedPorts.push(443);
          } else if (parsed.protocol === 'http:') {
            parsedPorts.push(80);
          }
        } catch {
          // ignore
        }
      }

      const ports = parsedPorts.length > 0 ? parsedPorts : [80, 443];
      const excluded = newExcludedPaths
        .split(',')
        .map((p) => p.trim())
        .filter(Boolean);

      return await targetsApi.createTarget(projectId, {
        name: newTargetName.trim(),
        baseUrl: newTargetUrl.trim(),
        allowedHosts: hosts,
        allowedPorts: ports,
        excludedPaths: excluded,
        testing: {
          activeScanning: activeScanningOpt,
          loadTesting: loadTestingOpt,
          chaosTesting: chaosTestingOpt,
        },
        limits: {
          maxRps: newMaxRps,
          maxConcurrency: newMaxConcurrency,
          maxDuration: '10m',
        },
        allowPrivateIps: allowPrivateIpsOpt,
      });
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['targets'] });
      setIsCreating(false);
      setNewTargetName('');
      setNewTargetUrl('');
      setNewTargetHosts('');
      setNewExcludedPaths('');
      setAllowPrivateIpsOpt(false);
      showToast(`Target "${data.name}" registered successfully`);
    },
    onError: (err: unknown) => {
      const msg = err instanceof Error ? err.message : String(err);
      setCreationError(msg);
      showToast(msg, 'error');
    },
  });

  // Target update mutation
  const updateTargetMutation = useMutation({
    mutationFn: async () => {
      if (!editingTarget) return;
      setEditError(null);

      const hosts = editTargetHosts
        .split(',')
        .map((h) => h.trim())
        .filter(Boolean);

      if (hosts.length === 0 && editTargetUrl) {
        try {
          const parsedHost = new URL(editTargetUrl).hostname;
          if (parsedHost) hosts.push(parsedHost);
        } catch {
          // ignore
        }
      }

      const parsedPorts = editTargetPorts
        .split(',')
        .map((p) => parseInt(p.trim(), 10))
        .filter((p) => !isNaN(p) && p > 0 && p <= 65535);

      const ports = parsedPorts.length > 0 ? parsedPorts : [80, 443];
      const excluded = editExcludedPaths
        .split(',')
        .map((p) => p.trim())
        .filter(Boolean);

      return await targetsApi.updateTarget(editingTarget.id, {
        name: editTargetName.trim(),
        baseUrl: editTargetUrl.trim(),
        allowedHosts: hosts,
        allowedPorts: ports,
        excludedPaths: excluded,
        testing: {
          activeScanning: editActiveScanning,
          loadTesting: editLoadTesting,
          chaosTesting: editChaosTesting,
        },
        limits: {
          maxRps: editMaxRps,
          maxConcurrency: editMaxConcurrency,
          maxDuration: editingTarget.scope?.limits?.maxDuration || '10m',
        },
        scope: {
          allowedHosts: hosts,
          allowedPorts: ports,
          excludedPaths: excluded,
          testing: {
            activeScanning: editActiveScanning,
            loadTesting: editLoadTesting,
            chaosTesting: editChaosTesting,
          },
          limits: {
            maxRps: editMaxRps,
            maxConcurrency: editMaxConcurrency,
            maxDuration: editingTarget.scope?.limits?.maxDuration || '10m',
          },
          allowPrivateIps: editAllowPrivateIps,
        },
      });
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['targets'] });
      setEditingTarget(null);
      showToast(`Target "${data?.name || 'Target'}" updated successfully`);
    },
    onError: (err: unknown) => {
      const msg = err instanceof Error ? err.message : String(err);
      setEditError(msg);
      showToast(msg, 'error');
    },
  });

  // Target delete mutation
  const deleteTargetMutation = useMutation({
    mutationFn: async (targetId: string) => {
      return await targetsApi.deleteTarget(targetId);
    },
    onSuccess: (_, deletedId) => {
      queryClient.invalidateQueries({ queryKey: ['targets'] });
      queryClient.invalidateQueries({ queryKey: ['test-runs'] });
      queryClient.invalidateQueries({ queryKey: ['findings'] });
      if (selectedSimulatorTargetId === deletedId) {
        setSelectedSimulatorTargetId('');
      }
      showToast('Target deleted successfully', 'info');
    },
    onError: (err: unknown) => {
      const msg = err instanceof Error ? err.message : String(err);
      showToast(msg, 'error');
    },
  });

  // Filtered targets
  const filteredTargets = targets.filter((target) => {
    // Status filter
    if (statusFilter !== 'all') {
      const targetStatus = target.verificationStatus || 'PENDING';
      if (targetStatus !== statusFilter) return false;
    }

    // Capability filter
    if (capabilityFilter === 'activeScanning' && !target.scope?.testing?.activeScanning) {
      return false;
    }
    if (capabilityFilter === 'loadTesting' && !target.scope?.testing?.loadTesting) {
      return false;
    }

    // Search query
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchName = target.name.toLowerCase().includes(q);
      const matchUrl = target.baseUrl.toLowerCase().includes(q);
      const matchHost = target.scope?.allowedHosts?.some((h) => h.toLowerCase().includes(q));
      if (!matchName && !matchUrl && !matchHost) return false;
    }
    return true;
  });

  // Paged targets
  const paginatedTargets = filteredTargets.slice(
    (currentPage - 1) * pageSize,
    currentPage * pageSize,
  );

  // Aggregated Stats
  const totalCount = targets.length;
  const verifiedCount = targets.filter((t) => t.verificationStatus === 'VERIFIED').length;
  const pendingCount = targets.filter(
    (t) => !t.verificationStatus || t.verificationStatus === 'PENDING',
  ).length;
  const activeScanningCount = targets.filter((t) => t.scope?.testing?.activeScanning).length;

  return (
    <div className="space-y-8 animate-fade-in">
      {/* Top Header Section */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-foreground flex items-center space-x-2">
            <Lock className="w-5 h-5 text-blue-500" />
            <span>Target Studio & Scope Verifier</span>
          </h2>
          <p className="text-sm text-muted-foreground">
            Cryptographic domain ownership verification, pre-socket DNS pinning, anti-SSRF protections, and safety budgets.
          </p>
        </div>
        <button
          onClick={() => setIsCreating(true)}
          className="inline-flex items-center space-x-2 px-4 py-2 rounded-lg bg-primary hover:bg-primary/90 text-white text-xs font-semibold shadow-md transition-all duration-150 self-start md:self-auto hover:glow-blue"
        >
          <Plus className="w-4 h-4" />
          <span>Register New Target</span>
        </button>
      </div>

      {/* Security Invariants & Metrics Strip */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="p-4 rounded-xl bg-card border border-border/80 space-y-1">
          <span className="text-[10px] uppercase font-mono text-muted-foreground tracking-wider">
            Total Targets
          </span>
          <div className="text-2xl font-bold font-mono text-foreground">{totalCount}</div>
        </div>
        <div
          onClick={() => setStatusFilter(statusFilter === 'VERIFIED' ? 'all' : 'VERIFIED')}
          className="p-4 rounded-xl bg-card border border-emerald-800/40 space-y-1 cursor-pointer hover:border-emerald-600 transition-colors"
        >
          <span className="text-[10px] uppercase font-mono text-emerald-400 tracking-wider flex items-center gap-1">
            <ShieldCheck className="w-3 h-3" />
            <span>Verified Domains</span>
          </span>
          <div className="text-2xl font-bold font-mono text-emerald-400">{verifiedCount}</div>
        </div>
        <div
          onClick={() => setStatusFilter(statusFilter === 'PENDING' ? 'all' : 'PENDING')}
          className="p-4 rounded-xl bg-card border border-amber-800/40 space-y-1 cursor-pointer hover:border-amber-600 transition-colors"
        >
          <span className="text-[10px] uppercase font-mono text-amber-400 tracking-wider flex items-center gap-1">
            <Clock className="w-3 h-3" />
            <span>Pending Proof</span>
          </span>
          <div className="text-2xl font-bold font-mono text-amber-400">{pendingCount}</div>
        </div>
        <div className="p-4 rounded-xl bg-card border border-primary/40 space-y-1">
          <span className="text-[10px] uppercase font-mono text-primary tracking-wider flex items-center gap-1">
            <Zap className="w-3 h-3" />
            <span>Active Scan Authorized</span>
          </span>
          <div className="text-2xl font-bold font-mono text-primary">{activeScanningCount}</div>
        </div>
      </div>

      {/* Target Registration Form Modal */}
      {isCreating && (
        <div className="p-6 rounded-2xl border border-primary/40 bg-card/95 backdrop-blur-md space-y-4 shadow-xl animate-fade-in">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-foreground flex items-center gap-2">
              <Plus className="w-4 h-4 text-primary" />
              <span>Register Authorized Target & Security Boundary</span>
            </h3>
            <button
              onClick={() => setIsCreating(false)}
              className="text-xs text-muted-foreground hover:text-foreground p-1"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          {creationError && (
            <div className="p-3 text-xs bg-red-950/40 border border-red-800/40 text-red-400 rounded-lg">
              {creationError}
            </div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
            <div>
              <label className="block text-muted-foreground mb-1">Target Name</label>
              <input
                type="text"
                placeholder="e.g. Staging Customer API"
                value={newTargetName}
                onChange={(e) => setNewTargetName(e.target.value)}
                className="w-full px-3 py-2 rounded-md bg-accent border border-border text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
              />
            </div>
            <div>
              <label className="block text-muted-foreground mb-1">Base URL</label>
              <input
                type="text"
                placeholder="https://staging.example.com"
                value={newTargetUrl}
                onChange={(e) => setNewTargetUrl(e.target.value)}
                className="w-full px-3 py-2 rounded-md bg-accent border border-border text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
              />
            </div>
            <div>
              <label className="block text-muted-foreground mb-1">Allowed Hosts (comma-separated)</label>
              <input
                type="text"
                placeholder="staging.example.com, api-staging.example.com"
                value={newTargetHosts}
                onChange={(e) => setNewTargetHosts(e.target.value)}
                className="w-full px-3 py-2 rounded-md bg-accent border border-border text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
              />
            </div>
            <div>
              <label className="block text-muted-foreground mb-1">Allowed Ports</label>
              <input
                type="text"
                value={newTargetPorts}
                onChange={(e) => setNewTargetPorts(e.target.value)}
                className="w-full px-3 py-2 rounded-md bg-accent border border-border text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
              />
            </div>
            <div>
              <label className="block text-muted-foreground mb-1">Excluded Paths (e.g. /logout, /admin/delete)</label>
              <input
                type="text"
                placeholder="/logout, /delete-account, /admin/reboot"
                value={newExcludedPaths}
                onChange={(e) => setNewExcludedPaths(e.target.value)}
                className="w-full px-3 py-2 rounded-md bg-accent border border-border text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
              />
            </div>
            <div className="grid grid-cols-2 gap-2">
              <div>
                <label className="block text-muted-foreground mb-1">Max RPS Limit</label>
                <input
                  type="number"
                  min={1}
                  max={5000}
                  value={newMaxRps}
                  onChange={(e) => setNewMaxRps(parseInt(e.target.value, 10) || 50)}
                  className="w-full px-3 py-2 rounded-md bg-accent border border-border text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
                />
              </div>
              <div>
                <label className="block text-muted-foreground mb-1">Max Concurrency (VUs)</label>
                <input
                  type="number"
                  min={1}
                  max={1000}
                  value={newMaxConcurrency}
                  onChange={(e) => setNewMaxConcurrency(parseInt(e.target.value, 10) || 20)}
                  className="w-full px-3 py-2 rounded-md bg-accent border border-border text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
                />
              </div>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-6 pt-2 text-xs">
            <label className="flex items-center space-x-2 cursor-pointer">
              <input
                type="checkbox"
                checked={activeScanningOpt}
                onChange={(e) => setActiveScanningOpt(e.target.checked)}
                className="rounded border-border text-primary"
              />
              <span className="text-foreground">Authorize Active Vulnerability Scanning</span>
            </label>
            <label className="flex items-center space-x-2 cursor-pointer">
              <input
                type="checkbox"
                checked={loadTestingOpt}
                onChange={(e) => setLoadTestingOpt(e.target.checked)}
                className="rounded border-border text-primary"
              />
              <span className="text-foreground">Authorize Load/Resilience Testing</span>
            </label>
            <label className="flex items-center space-x-2 cursor-pointer">
              <input
                type="checkbox"
                checked={chaosTestingOpt}
                onChange={(e) => setChaosTestingOpt(e.target.checked)}
                className="rounded border-border text-primary"
              />
              <span className="text-foreground">Authorize Chaos Injection</span>
            </label>
            <label className="flex items-center space-x-2 cursor-pointer">
              <input
                type="checkbox"
                checked={allowPrivateIpsOpt}
                onChange={(e) => setAllowPrivateIpsOpt(e.target.checked)}
                className="rounded border-border text-amber-500"
              />
              <span className="text-amber-400">Allow Private RFC-1918 IPs (Requires Intranet Scoping)</span>
            </label>
          </div>

          <div className="flex justify-end space-x-3 pt-2">
            <button
              onClick={() => setIsCreating(false)}
              className="px-3 py-1.5 rounded text-xs text-muted-foreground hover:bg-accent"
            >
              Cancel
            </button>
            <button
              onClick={() => createTargetMutation.mutate()}
              disabled={createTargetMutation.isPending || !newTargetName || !newTargetUrl || !newTargetHosts}
              className="px-4 py-1.5 rounded text-xs bg-primary text-white font-medium hover:bg-primary/90 disabled:opacity-50"
            >
              {createTargetMutation.isPending ? 'Registering...' : 'Register Target'}
            </button>
          </div>
        </div>
      )}

      {/* Target Edit Form Modal */}
      {editingTarget && (
        <div className="p-6 rounded-2xl border border-amber-500/40 bg-card/95 backdrop-blur-md space-y-4 shadow-xl animate-fade-in">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <Pencil className="w-4 h-4 text-amber-400" />
              <h3 className="text-sm font-semibold text-foreground">
                Edit Target Scope: {editingTarget.name}
              </h3>
            </div>
            <button
              onClick={() => setEditingTarget(null)}
              className="text-xs text-muted-foreground hover:text-foreground p-1"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          {editError && (
            <div className="p-3 text-xs bg-red-950/40 border border-red-800/40 text-red-400 rounded-lg">
              {editError}
            </div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
            <div>
              <label className="block text-muted-foreground mb-1">Target Name</label>
              <input
                type="text"
                value={editTargetName}
                onChange={(e) => setEditTargetName(e.target.value)}
                className="w-full px-3 py-2 rounded-md bg-accent border border-border text-foreground focus:outline-none focus:ring-1 focus:ring-amber-500"
              />
            </div>
            <div>
              <label className="block text-muted-foreground mb-1">Base URL</label>
              <input
                type="text"
                value={editTargetUrl}
                onChange={(e) => setEditTargetUrl(e.target.value)}
                className="w-full px-3 py-2 rounded-md bg-accent border border-border text-foreground focus:outline-none focus:ring-1 focus:ring-amber-500"
              />
            </div>
            <div>
              <label className="block text-muted-foreground mb-1">Allowed Hosts (comma-separated)</label>
              <input
                type="text"
                value={editTargetHosts}
                onChange={(e) => setEditTargetHosts(e.target.value)}
                className="w-full px-3 py-2 rounded-md bg-accent border border-border text-foreground focus:outline-none focus:ring-1 focus:ring-amber-500"
              />
            </div>
            <div>
              <label className="block text-muted-foreground mb-1">Allowed Ports</label>
              <input
                type="text"
                value={editTargetPorts}
                onChange={(e) => setEditTargetPorts(e.target.value)}
                className="w-full px-3 py-2 rounded-md bg-accent border border-border text-foreground focus:outline-none focus:ring-1 focus:ring-amber-500"
              />
            </div>
            <div>
              <label className="block text-muted-foreground mb-1">Excluded Paths</label>
              <input
                type="text"
                value={editExcludedPaths}
                onChange={(e) => setEditExcludedPaths(e.target.value)}
                className="w-full px-3 py-2 rounded-md bg-accent border border-border text-foreground focus:outline-none focus:ring-1 focus:ring-amber-500"
              />
            </div>
            <div className="grid grid-cols-2 gap-2">
              <div>
                <label className="block text-muted-foreground mb-1">Max RPS Limit</label>
                <input
                  type="number"
                  min={1}
                  max={5000}
                  value={editMaxRps}
                  onChange={(e) => setEditMaxRps(parseInt(e.target.value, 10) || 50)}
                  className="w-full px-3 py-2 rounded-md bg-accent border border-border text-foreground focus:outline-none focus:ring-1 focus:ring-amber-500"
                />
              </div>
              <div>
                <label className="block text-muted-foreground mb-1">Max Concurrency (VUs)</label>
                <input
                  type="number"
                  min={1}
                  max={1000}
                  value={editMaxConcurrency}
                  onChange={(e) => setEditMaxConcurrency(parseInt(e.target.value, 10) || 20)}
                  className="w-full px-3 py-2 rounded-md bg-accent border border-border text-foreground focus:outline-none focus:ring-1 focus:ring-amber-500"
                />
              </div>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-6 pt-2 text-xs">
            <label className="flex items-center space-x-2 cursor-pointer">
              <input
                type="checkbox"
                checked={editActiveScanning}
                onChange={(e) => setEditActiveScanning(e.target.checked)}
                className="rounded border-border text-amber-500"
              />
              <span className="text-foreground">Authorize Active Scanning</span>
            </label>
            <label className="flex items-center space-x-2 cursor-pointer">
              <input
                type="checkbox"
                checked={editLoadTesting}
                onChange={(e) => setEditLoadTesting(e.target.checked)}
                className="rounded border-border text-amber-500"
              />
              <span className="text-foreground">Authorize Load/Resilience Testing</span>
            </label>
            <label className="flex items-center space-x-2 cursor-pointer">
              <input
                type="checkbox"
                checked={editChaosTesting}
                onChange={(e) => setEditChaosTesting(e.target.checked)}
                className="rounded border-border text-amber-500"
              />
              <span className="text-foreground">Authorize Chaos Injection</span>
            </label>
            <label className="flex items-center space-x-2 cursor-pointer">
              <input
                type="checkbox"
                checked={editAllowPrivateIps}
                onChange={(e) => setEditAllowPrivateIps(e.target.checked)}
                className="rounded border-border text-amber-500"
              />
              <span className="text-amber-400">Allow Private RFC-1918 IPs</span>
            </label>
          </div>

          <div className="flex justify-end space-x-3 pt-2">
            <button
              onClick={() => setEditingTarget(null)}
              className="px-3 py-1.5 rounded text-xs text-muted-foreground hover:bg-accent"
            >
              Cancel
            </button>
            <button
              onClick={() => updateTargetMutation.mutate()}
              disabled={updateTargetMutation.isPending || !editTargetName || !editTargetUrl || !editTargetHosts}
              className="px-4 py-1.5 rounded text-xs bg-amber-600 text-white font-medium hover:bg-amber-500 disabled:opacity-50"
            >
              {updateTargetMutation.isPending ? 'Saving...' : 'Save Changes'}
            </button>
          </div>
        </div>
      )}

      {/* Filter and Search Bar */}
      <div className="flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3">
        <div className="relative flex-1 max-w-md">
          <Search className="w-4 h-4 text-muted-foreground absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search targets by name, host, or URL..."
            value={searchQuery}
            onChange={(e) => {
              setSearchQuery(e.target.value);
              setCurrentPage(1);
            }}
            className="w-full pl-9 pr-4 py-2 bg-background border border-border rounded-lg text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-blue-500 placeholder:text-muted-foreground/60"
          />
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {/* Status Tabs */}
          <div className="flex bg-accent/40 p-1 rounded-lg border border-border text-xs">
            <button
              type="button"
              onClick={() => {
                setStatusFilter('all');
                setCurrentPage(1);
              }}
              className={`px-2.5 py-1 rounded-md transition-colors ${
                statusFilter === 'all'
                  ? 'bg-primary text-white font-medium shadow-sm'
                  : 'text-muted-foreground hover:text-foreground'
              }`}
            >
              All ({totalCount})
            </button>
            <button
              type="button"
              onClick={() => {
                setStatusFilter('VERIFIED');
                setCurrentPage(1);
              }}
              className={`px-2.5 py-1 rounded-md transition-colors ${
                statusFilter === 'VERIFIED'
                  ? 'bg-emerald-600 text-white font-medium shadow-sm'
                  : 'text-muted-foreground hover:text-foreground'
              }`}
            >
              Verified ({verifiedCount})
            </button>
            <button
              type="button"
              onClick={() => {
                setStatusFilter('PENDING');
                setCurrentPage(1);
              }}
              className={`px-2.5 py-1 rounded-md transition-colors ${
                statusFilter === 'PENDING'
                  ? 'bg-amber-600 text-white font-medium shadow-sm'
                  : 'text-muted-foreground hover:text-foreground'
              }`}
            >
              Pending ({pendingCount})
            </button>
          </div>

          {/* Capability Filter Dropdown */}
          <div className="flex items-center gap-1.5">
            <Filter className="w-4 h-4 text-muted-foreground shrink-0" />
            <select
              value={capabilityFilter}
              onChange={(e) => {
                setCapabilityFilter(e.target.value as typeof capabilityFilter);
                setCurrentPage(1);
              }}
              className="px-3 py-2 bg-background border border-border rounded-lg text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-blue-500 cursor-pointer"
            >
              <option value="all">All Capabilities</option>
              <option value="activeScanning">Active Scanning Authorized</option>
              <option value="loadTesting">Load Testing Authorized</option>
            </select>
          </div>
        </div>
      </div>

      {/* Target Scope Cards Grid */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground">
            Registered Targets ({filteredTargets.length})
          </h3>
          <span className="text-xs font-mono text-muted-foreground">
            CLI: <code className="text-blue-400">security-lab target list</code>
          </span>
        </div>

        {isLoading ? (
          <div className="p-8 text-center text-xs text-muted-foreground">Loading targets...</div>
        ) : filteredTargets.length === 0 ? (
          <div className="p-8 border border-dashed border-border rounded-xl text-center text-xs text-muted-foreground space-y-2">
            <p>No target scopes match the filter criteria.</p>
            <p>Register your target above or run: <code>security-lab target create</code></p>
          </div>
        ) : (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {paginatedTargets.map((target) => {
              const isVerified = target.verificationStatus === 'VERIFIED';
              const isFailed = target.verificationStatus === 'FAILED';

              return (
                <div
                  key={target.id}
                  className={`p-5 rounded-2xl border bg-card/70 backdrop-blur-sm space-y-4 transition-all duration-200 shadow-sm hover:shadow-md ${
                    isVerified
                      ? 'border-border hover:border-emerald-500/50'
                      : 'border-amber-900/30 hover:border-amber-500/50'
                  }`}
                >
                  {/* Card Header */}
                  <div className="flex items-start justify-between gap-2">
                    <div className="space-y-1">
                      <div className="flex items-center space-x-2">
                        <h4 className="font-semibold text-foreground text-sm">{target.name}</h4>
                        <button
                          type="button"
                          onClick={() => copyToClipboard(target.id, 'Target ID')}
                          title="Copy Target ID"
                          className="text-[10px] font-mono bg-accent/70 hover:bg-accent px-1.5 py-0.5 rounded text-muted-foreground flex items-center gap-1 transition-colors"
                        >
                          <span>{target.id.slice(0, 8)}...</span>
                          <Copy className="w-2.5 h-2.5" />
                        </button>

                        {/* Verification Status Badge */}
                        <button
                          type="button"
                          onClick={() => setVerificationTarget(target)}
                          className={`text-[10px] font-mono uppercase px-2 py-0.5 rounded-full border flex items-center gap-1 cursor-pointer transition-colors ${
                            isVerified
                              ? 'bg-emerald-950/60 text-emerald-400 border-emerald-800/60 hover:bg-emerald-950/80'
                              : isFailed
                              ? 'bg-red-950/60 text-red-400 border-red-800/60 hover:bg-red-950/80'
                              : 'bg-amber-950/60 text-amber-400 border-amber-800/60 hover:bg-amber-950/80'
                          }`}
                        >
                          {isVerified ? (
                            <>
                              <ShieldCheck className="w-3 h-3 text-emerald-400" />
                              <span>Verified</span>
                            </>
                          ) : isFailed ? (
                            <>
                              <ShieldAlert className="w-3 h-3 text-red-400" />
                              <span>Failed Proof</span>
                            </>
                          ) : (
                            <>
                              <Clock className="w-3 h-3 text-amber-400" />
                              <span>Pending Proof</span>
                            </>
                          )}
                        </button>
                      </div>

                      <div className="flex items-center space-x-1.5 text-xs text-primary font-mono">
                        <Globe className="w-3.5 h-3.5 shrink-0" />
                        <button
                          type="button"
                          onClick={() => copyToClipboard(target.baseUrl, 'Base URL')}
                          title="Copy Base URL"
                          className="hover:underline text-left truncate"
                        >
                          {target.baseUrl}
                        </button>
                      </div>
                    </div>

                    {/* Card Actions */}
                    <div className="flex items-center space-x-1.5 shrink-0">
                      <button
                        onClick={() => setStudioTarget(target)}
                        title="Open Target Studio"
                        className="text-[11px] font-medium text-primary hover:text-primary/80 bg-primary/10 border border-primary/30 px-2.5 py-1 rounded-md transition-colors flex items-center gap-1"
                      >
                        <Sliders className="w-3 h-3" />
                        <span>Studio</span>
                      </button>

                      <button
                        onClick={() => {
                          setSelectedSimulatorTargetId(target.id);
                          const element = document.getElementById('scope-simulator-section');
                          if (element) element.scrollIntoView({ behavior: 'smooth' });
                        }}
                        title="Test Scope Boundary"
                        className="text-[11px] font-medium text-blue-400 hover:text-blue-300 bg-blue-950/30 border border-blue-800/40 px-2.5 py-1 rounded-md transition-colors"
                      >
                        Simulate
                      </button>

                      <button
                        onClick={() => handleOpenEdit(target)}
                        title="Edit Target Scope"
                        className="text-[11px] font-medium text-amber-400 hover:text-amber-300 bg-amber-950/30 border border-amber-800/40 p-1.5 rounded-md hover:bg-amber-950/50 transition-colors"
                      >
                        <Pencil className="w-3.5 h-3.5" />
                      </button>

                      <button
                        onClick={() => {
                          if (window.confirm(`Are you sure you want to delete target "${target.name}"? This will also remove all associated test runs and findings.`)) {
                            deleteTargetMutation.mutate(target.id);
                          }
                        }}
                        disabled={deleteTargetMutation.isPending}
                        title="Delete Target"
                        className="text-[11px] font-medium text-rose-400 hover:text-rose-300 bg-rose-950/30 border border-rose-800/40 p-1.5 rounded-md hover:bg-rose-950/50 transition-colors disabled:opacity-50"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </div>

                  {/* Warning Strip for Unverified Targets */}
                  {!isVerified && (
                    <div className="flex items-center justify-between p-2 rounded-lg bg-amber-950/20 border border-amber-800/40 text-[11px]">
                      <div className="flex items-center space-x-1.5 text-amber-400">
                        <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                        <span>Domain unverified: Active vulnerability scanning is blocked.</span>
                      </div>
                      <button
                        type="button"
                        onClick={() => setVerificationTarget(target)}
                        className="text-amber-300 hover:text-amber-200 font-semibold underline shrink-0 ml-2"
                      >
                        Verify Domain
                      </button>
                    </div>
                  )}

                  {/* Boundaries */}
                  <div className="space-y-2 text-xs">
                    <div>
                      <span className="text-muted-foreground block text-[11px] uppercase tracking-wider mb-1">
                        Allowed Hosts:
                      </span>
                      <div className="flex flex-wrap gap-1.5">
                        {target.scope.allowedHosts.map((h) => (
                          <span
                            key={h}
                            className="font-mono text-[11px] bg-accent/80 px-2 py-0.5 rounded text-foreground border border-border"
                          >
                            {h}
                          </span>
                        ))}
                      </div>
                    </div>

                    <div className="flex flex-wrap items-center gap-4 pt-1 text-muted-foreground">
                      <div>
                        <span className="text-[11px]">Ports: </span>
                        <span className="font-mono text-foreground">
                          {target.scope.allowedPorts?.join(', ') || '80, 443'}
                        </span>
                      </div>
                      <div>
                        <span className="text-[11px]">Max RPS: </span>
                        <span className="font-mono text-foreground font-semibold">
                          {target.scope.limits?.maxRps ?? 100}
                        </span>
                      </div>
                      <div>
                        <span className="text-[11px]">Max Concurrency: </span>
                        <span className="font-mono text-cyan-400 font-semibold">
                          {target.scope.limits?.maxConcurrency ?? 20} VUs
                        </span>
                      </div>
                      <div>
                        <span className="text-[11px]">Private Subnets: </span>
                        <span
                          className={`font-mono font-semibold ${
                            target.scope.allowPrivateIps ? 'text-amber-400' : 'text-muted-foreground'
                          }`}
                        >
                          {target.scope.allowPrivateIps ? 'Allowed' : 'Blocked'}
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Capability Badges & CLI Hint */}
                  <div className="flex flex-wrap items-center justify-between gap-2 pt-2 border-t border-border/40 text-[11px]">
                    <div className="flex items-center space-x-2">
                      <span className="text-muted-foreground">Capabilities:</span>
                      <span
                        className={`px-2 py-0.5 rounded-full font-medium ${
                          target.scope.testing?.activeScanning
                            ? 'bg-emerald-950/40 text-emerald-400 border border-emerald-800/40'
                            : 'bg-muted text-muted-foreground'
                        }`}
                      >
                        Active Scan: {target.scope.testing?.activeScanning ? 'ON' : 'OFF'}
                      </span>
                      <span
                        className={`px-2 py-0.5 rounded-full font-medium ${
                          target.scope.testing?.loadTesting
                            ? 'bg-indigo-950/40 text-indigo-400 border border-indigo-800/40'
                            : 'bg-muted text-muted-foreground'
                        }`}
                      >
                        Load Test: {target.scope.testing?.loadTesting ? 'ON' : 'OFF'}
                      </span>
                    </div>

                    <button
                      type="button"
                      onClick={() => copyToClipboard(`security-lab test run --target ${target.id}`, 'Run CLI Command')}
                      title="Copy CLI run command"
                      className="flex items-center gap-1 font-mono text-[10px] text-muted-foreground hover:text-blue-400"
                    >
                      <Terminal className="w-3 h-3 text-blue-400" />
                      <span>Run via CLI</span>
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        )}

        {/* Pagination component */}
        <Pagination
          currentPage={currentPage}
          totalItems={filteredTargets.length}
          pageSize={pageSize}
          onPageChange={setCurrentPage}
          onPageSizeChange={setPageSize}
          pageSizeOptions={[2, 4, 6, 12]}
        />
      </div>

      {/* Interactive Scope Boundary Simulator Section */}
      <div id="scope-simulator-section">
        <ScopeSimulatorPlayground
          targets={targets}
          selectedTargetId={selectedSimulatorTargetId}
          onSelectTargetId={setSelectedSimulatorTargetId}
        />
      </div>

      {/* Target Studio Modal */}
      {studioTarget && (
        <TargetStudio
          target={studioTarget}
          allTargets={targets}
          isOpen={Boolean(studioTarget)}
          onClose={() => setStudioTarget(null)}
          onEdit={(t) => handleOpenEdit(t)}
        />
      )}

      {/* Ownership Wizard Modal */}
      {verificationTarget && (
        <OwnershipWizardModal
          target={verificationTarget}
          isOpen={Boolean(verificationTarget)}
          onClose={() => setVerificationTarget(null)}
          onVerified={() => {
            queryClient.invalidateQueries({ queryKey: ['targets'] });
          }}
        />
      )}
    </div>
  );
};

import React, { useState, useEffect, useMemo } from 'react';
import {
  Radio,
  Server,
  Plus,
  RefreshCw,
  Search,
  Activity,
  Cpu,
  ShieldCheck,
  Zap,
} from 'lucide-react';
import {
  AgentFleetNode,
  AgentFleetSummary,
  fetchAgentFleet,
  drainAgent,
  revokeAgent,
} from '../../api/agents.js';
import { AgentNodeCard } from './AgentNodeCard.js';
import { AgentEnrollmentModal } from './AgentEnrollmentModal.js';
import { AgentJobLeaseDrawer } from './AgentJobLeaseDrawer.js';

export const AgentFleetView: React.FC = () => {
  const [agents, setAgents] = useState<AgentFleetNode[]>([]);
  const [summary, setSummary] = useState<AgentFleetSummary | null>(null);
  const [statusFilter, setStatusFilter] = useState<'all' | 'online' | 'busy' | 'draining' | 'offline'>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedTag, setSelectedTag] = useState<string>('all');
  const [isLoading, setIsLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [isEnrollModalOpen, setIsEnrollModalOpen] = useState(false);
  const [drawerNode, setDrawerNode] = useState<AgentFleetNode | null>(null);

  const loadFleet = async (silent = false) => {
    if (!silent) setIsLoading(true);
    else setIsRefreshing(true);

    const data = await fetchAgentFleet();
    setAgents(data.agents);
    setSummary(data.summary);

    if (!silent) setIsLoading(false);
    else setIsRefreshing(false);
  };

  useEffect(() => {
    loadFleet();
    // Auto-refresh telemetry every 5 seconds per Architecture & UX Invariant
    const timer = setInterval(() => {
      loadFleet(true);
    }, 5000);
    return () => clearInterval(timer);
  }, []);

  // Collect all unique capability tags across fleet
  const allTags = useMemo(() => {
    const set = new Set<string>();
    agents.forEach((a) => {
      a.tags.forEach((t) => set.add(t));
      a.capabilities.forEach((c) => set.add(c));
    });
    return Array.from(set);
  }, [agents]);

  // Filter nodes by status, search, and tag
  const filteredNodes = useMemo(() => {
    return agents.filter((node) => {
      const matchesStatus =
        statusFilter === 'all' ||
        (statusFilter === 'online' && node.status === 'online') ||
        (statusFilter === 'busy' && node.status === 'busy') ||
        (statusFilter === 'draining' && node.status === 'draining') ||
        (statusFilter === 'offline' && node.status === 'offline');

      const query = searchQuery.trim().toLowerCase();
      const matchesQuery =
        query === '' ||
        node.name.toLowerCase().includes(query) ||
        node.ipAddress.toLowerCase().includes(query) ||
        node.region.toLowerCase().includes(query) ||
        node.environment.toLowerCase().includes(query);

      const matchesTag =
        selectedTag === 'all' ||
        node.tags.includes(selectedTag) ||
        node.capabilities.includes(selectedTag);

      return matchesStatus && matchesQuery && matchesTag;
    });
  }, [agents, statusFilter, searchQuery, selectedTag]);

  const handleDrain = async (node: AgentFleetNode) => {
    await drainAgent(node.id);
    setAgents((prev) =>
      prev.map((a) => (a.id === node.id ? { ...a, status: 'draining' } : a))
    );
  };

  const handleRevoke = async (node: AgentFleetNode) => {
    if (confirm(`Are you sure you want to revoke agent node "${node.name}"? Its mTLS identity will be invalidated.`)) {
      await revokeAgent(node.id);
      setAgents((prev) => prev.filter((a) => a.id !== node.id));
    }
  };

  if (isLoading || !summary) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[400px] space-y-3">
        <Activity className="w-8 h-8 text-blue-400 animate-spin" />
        <p className="text-sm font-mono text-muted-foreground">
          Scanning Enterprise Agent Fleet Radar & mTLS Attestations...
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Console Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-5 rounded-2xl bg-card/60 border border-border/60 shadow-xl backdrop-blur-md">
        <div className="space-y-1">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-xl bg-blue-500/10 text-blue-400 border border-blue-500/20">
              <Radio className="w-6 h-6 animate-pulse" />
            </div>
            <div>
              <h1 className="text-xl font-bold tracking-tight text-foreground flex items-center gap-2">
                Agent Fleet Command Console
                <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20 font-normal">
                  Phase UI-12
                </span>
              </h1>
              <div className="flex items-center gap-3 text-xs text-muted-foreground font-mono mt-0.5">
                <span>Distributed Worker Radar</span>
                <span>•</span>
                <span>mTLS & Ed25519 Cryptographic Attestation</span>
              </div>
            </div>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => loadFleet(true)}
            disabled={isRefreshing}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-medium bg-background/80 hover:bg-background text-foreground border border-border/60 transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 text-muted-foreground ${isRefreshing ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>

          <button
            type="button"
            onClick={() => setIsEnrollModalOpen(true)}
            className="flex items-center gap-1.5 px-4 py-1.5 rounded-xl text-xs font-semibold bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white shadow-lg shadow-blue-500/20 transition-all"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Enroll New Agent</span>
          </button>
        </div>
      </div>

      {/* Top Executive Summary Scorecards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {/* Total & Online Nodes */}
        <div className="p-4 rounded-2xl bg-card/60 border border-border/60 shadow-lg space-y-1">
          <div className="flex items-center justify-between text-xs text-muted-foreground">
            <span>Fleet Nodes</span>
            <Server className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-emerald-400">
            {summary.onlineCount + summary.busyCount}{' '}
            <span className="text-xs font-normal text-muted-foreground">/ {summary.totalAgents} Online</span>
          </div>
          <p className="text-[11px] text-muted-foreground font-mono">
            {summary.busyCount} busy, {summary.drainingCount} draining, {summary.offlineCount} offline
          </p>
        </div>

        {/* Total Compute Pool */}
        <div className="p-4 rounded-2xl bg-card/60 border border-border/60 shadow-lg space-y-1">
          <div className="flex items-center justify-between text-xs text-muted-foreground">
            <span>Fleet Compute Pool</span>
            <Cpu className="w-4 h-4 text-blue-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-blue-400">
            {summary.totalCpuCores}{' '}
            <span className="text-xs font-normal text-muted-foreground">vCPUs</span>
          </div>
          <p className="text-[11px] text-muted-foreground font-mono">
            {summary.totalMemoryGb} GB RAM ({summary.clusterUtilizationPercent}% avg load)
          </p>
        </div>

        {/* Active Job Leases */}
        <div className="p-4 rounded-2xl bg-card/60 border border-border/60 shadow-lg space-y-1">
          <div className="flex items-center justify-between text-xs text-muted-foreground">
            <span>Active Job Leases</span>
            <Zap className="w-4 h-4 text-purple-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-purple-400">
            {summary.activeJobsCount}{' '}
            <span className="text-xs font-normal text-muted-foreground">Leases Active</span>
          </div>
          <p className="text-[11px] text-muted-foreground font-mono">
            Across distributed customer VPC runners
          </p>
        </div>

        {/* Fleet mTLS Compliance */}
        <div className="p-4 rounded-2xl bg-card/60 border border-border/60 shadow-lg space-y-1">
          <div className="flex items-center justify-between text-xs text-muted-foreground">
            <span>mTLS Attestation</span>
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-emerald-400">
            100%{' '}
            <span className="text-xs font-normal text-muted-foreground">Verified</span>
          </div>
          <p className="text-[11px] text-muted-foreground font-mono">
            Ed25519 & X.509 mutual authentication
          </p>
        </div>
      </div>

      {/* Search & Status Filters */}
      <div className="p-4 rounded-2xl bg-card/60 border border-border/60 shadow-lg flex flex-col md:flex-row md:items-center justify-between gap-3 text-xs">
        {/* Status Filter Tabs */}
        <div className="flex items-center gap-1 bg-background/80 p-1 rounded-xl border border-border/50 font-mono text-[11px] overflow-x-auto">
          <button
            type="button"
            onClick={() => setStatusFilter('all')}
            className={`px-3 py-1 rounded-lg transition-colors shrink-0 ${
              statusFilter === 'all' ? 'bg-muted text-foreground font-bold' : 'text-muted-foreground'
            }`}
          >
            All Nodes ({summary.totalAgents})
          </button>
          <button
            type="button"
            onClick={() => setStatusFilter('online')}
            className={`px-3 py-1 rounded-lg transition-colors shrink-0 ${
              statusFilter === 'online' ? 'bg-emerald-500/20 text-emerald-300 font-bold' : 'text-muted-foreground'
            }`}
          >
            Online ({summary.onlineCount})
          </button>
          <button
            type="button"
            onClick={() => setStatusFilter('busy')}
            className={`px-3 py-1 rounded-lg transition-colors shrink-0 ${
              statusFilter === 'busy' ? 'bg-blue-500/20 text-blue-300 font-bold' : 'text-muted-foreground'
            }`}
          >
            Busy ({summary.busyCount})
          </button>
          <button
            type="button"
            onClick={() => setStatusFilter('draining')}
            className={`px-3 py-1 rounded-lg transition-colors shrink-0 ${
              statusFilter === 'draining' ? 'bg-amber-500/20 text-amber-300 font-bold' : 'text-muted-foreground'
            }`}
          >
            Draining ({summary.drainingCount})
          </button>
          <button
            type="button"
            onClick={() => setStatusFilter('offline')}
            className={`px-3 py-1 rounded-lg transition-colors shrink-0 ${
              statusFilter === 'offline' ? 'bg-muted text-foreground font-bold' : 'text-muted-foreground'
            }`}
          >
            Offline ({summary.offlineCount})
          </button>
        </div>

        {/* Search & Tag Filter */}
        <div className="flex items-center gap-2">
          <div className="relative w-full sm:w-64">
            <Search className="w-3.5 h-3.5 text-muted-foreground absolute left-3 top-2.5" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search node, IP, VPC region..."
              className="w-full text-xs font-mono bg-background/80 border border-border/60 rounded-xl pl-8 pr-3 py-1.5 text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-blue-500"
            />
          </div>

          <select
            value={selectedTag}
            onChange={(e) => setSelectedTag(e.target.value)}
            className="text-xs font-mono bg-background/80 border border-border/60 rounded-xl px-2.5 py-1.5 text-foreground focus:outline-none cursor-pointer"
          >
            <option value="all">All Tags & Caps</option>
            {allTags.map((tag) => (
              <option key={tag} value={tag}>
                {tag}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Nodes Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {filteredNodes.length === 0 ? (
          <div className="col-span-full p-12 text-center text-muted-foreground text-xs font-mono border border-border/40 rounded-2xl bg-card/40">
            No agent nodes match the selected filter criteria.
          </div>
        ) : (
          filteredNodes.map((node) => (
            <AgentNodeCard
              key={node.id}
              node={node}
              onViewLeases={(n) => setDrawerNode(n)}
              onDrain={handleDrain}
              onRevoke={handleRevoke}
            />
          ))
        )}
      </div>

      {/* Modals and Drawers */}
      <AgentEnrollmentModal
        isOpen={isEnrollModalOpen}
        onClose={() => {
          setIsEnrollModalOpen(false);
          loadFleet(true);
        }}
      />

      <AgentJobLeaseDrawer
        node={drawerNode}
        isOpen={drawerNode !== null}
        onClose={() => setDrawerNode(null)}
      />
    </div>
  );
};

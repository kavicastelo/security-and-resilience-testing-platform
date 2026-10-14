import React, { useState, useMemo } from 'react';
import {
  Search,
  AlertTriangle,
  Lock,
  CheckCircle2,
} from 'lucide-react';
import {
  AuthzMatrixDataset,
  MatrixCell,
  AuthzViolationEvidence,
} from '../../api/authz.js';

interface MatrixGridTableProps {
  dataset: AuthzMatrixDataset;
  onSelectEvidence: (evidence: AuthzViolationEvidence) => void;
}

export const MatrixGridTable: React.FC<MatrixGridTableProps> = ({
  dataset,
  onSelectEvidence,
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedFilter, setSelectedFilter] = useState<string>('all');
  const [selectedCategory, setSelectedCategory] = useState<string>('all');

  // Distinct categories
  const categories = useMemo(() => {
    const set = new Set<string>();
    dataset.routes.forEach((r) => set.add(r.category));
    return ['all', ...Array.from(set)];
  }, [dataset.routes]);

  // Filter routes
  const filteredRoutes = useMemo(() => {
    return dataset.routes.filter((route) => {
      // Category filter
      if (selectedCategory !== 'all' && route.category !== selectedCategory) {
        return false;
      }

      // Search query
      if (searchQuery) {
        const query = searchQuery.toLowerCase();
        const matchesPath = route.path.toLowerCase().includes(query);
        const matchesMethod = route.method.toLowerCase().includes(query);
        const matchesDesc = (route.description || '').toLowerCase().includes(query);
        if (!matchesPath && !matchesMethod && !matchesDesc) {
          return false;
        }
      }

      // Status filter
      if (selectedFilter !== 'all') {
        const routeCells = dataset.cells.filter(
          (c) => c.endpoint === route.path && c.method === route.method,
        );

        if (selectedFilter === 'violations') {
          return routeCells.some((c) => c.status.startsWith('VIOLATION'));
        }
        if (selectedFilter === 'bola') {
          return routeCells.some((c) => c.status === 'VIOLATION_BOLA');
        }
        if (selectedFilter === 'bfla') {
          return routeCells.some((c) => c.status === 'VIOLATION_BFLA');
        }
        if (selectedFilter === 'allowed') {
          return routeCells.some((c) => c.status === 'ALLOWED');
        }
      }

      return true;
    });
  }, [dataset, searchQuery, selectedFilter, selectedCategory]);

  const getMethodBadgeClass = (method: string) => {
    switch (method) {
      case 'GET':
        return 'bg-blue-500/15 text-blue-400 border-blue-500/30';
      case 'POST':
        return 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30';
      case 'PUT':
      case 'PATCH':
        return 'bg-amber-500/15 text-amber-400 border-amber-500/30';
      case 'DELETE':
        return 'bg-red-500/15 text-red-400 border-red-500/30';
      default:
        return 'bg-zinc-500/15 text-zinc-400 border-zinc-500/30';
    }
  };

  const renderCellContent = (cell: MatrixCell | undefined) => {
    if (!cell) {
      return (
        <div className="py-2.5 px-3 text-center text-xs text-muted-foreground font-mono">
          -
        </div>
      );
    }

    const isClickable = Boolean(cell.findingId && dataset.evidenceMap[cell.findingId]);

    const handleClick = () => {
      if (cell.findingId && dataset.evidenceMap[cell.findingId]) {
        onSelectEvidence(dataset.evidenceMap[cell.findingId]);
      }
    };

    switch (cell.status) {
      case 'VIOLATION_BOLA':
        return (
          <div
            onClick={handleClick}
            className={`group relative p-2.5 text-center transition-all ${
              isClickable ? 'cursor-pointer hover:scale-[1.02]' : ''
            }`}
          >
            <div className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[11px] font-mono font-bold bg-red-500/20 text-red-300 border border-red-500/50 shadow-sm shadow-red-500/20 group-hover:border-red-400">
              <span className="w-1.5 h-1.5 rounded-full bg-red-400 animate-ping" />
              <span>🚨 BOLA ({cell.httpStatus})</span>
            </div>
            <div className="text-[10px] text-red-400/80 font-mono mt-0.5">
              {cell.latencyMs}ms • IDOR Breach
            </div>
          </div>
        );

      case 'VIOLATION_BFLA':
        return (
          <div
            onClick={handleClick}
            className={`group relative p-2.5 text-center transition-all ${
              isClickable ? 'cursor-pointer hover:scale-[1.02]' : ''
            }`}
          >
            <div className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[11px] font-mono font-bold bg-purple-500/20 text-purple-300 border border-purple-500/50 shadow-sm shadow-purple-500/20 group-hover:border-purple-400">
              <span className="w-1.5 h-1.5 rounded-full bg-purple-400 animate-ping" />
              <span>🚨 BFLA ({cell.httpStatus})</span>
            </div>
            <div className="text-[10px] text-purple-400/80 font-mono mt-0.5">
              {cell.latencyMs}ms • Vertical Escalation
            </div>
          </div>
        );

      case 'VIOLATION_MISSING_AUTH':
        return (
          <div
            onClick={handleClick}
            className={`group relative p-2.5 text-center transition-all ${
              isClickable ? 'cursor-pointer hover:scale-[1.02]' : ''
            }`}
          >
            <div className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[11px] font-mono font-bold bg-amber-500/20 text-amber-300 border border-amber-500/50 group-hover:border-amber-400">
              <AlertTriangle className="w-3 h-3 text-amber-400" />
              <span>⚠️ NO AUTH ({cell.httpStatus})</span>
            </div>
            <div className="text-[10px] text-amber-400/80 font-mono mt-0.5">
              {cell.latencyMs}ms • Public Leak
            </div>
          </div>
        );

      case 'ALLOWED':
        return (
          <div className="p-2.5 text-center">
            <div className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-[11px] font-mono font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              <CheckCircle2 className="w-3 h-3" />
              <span>Allowed ({cell.httpStatus})</span>
            </div>
            <div className="text-[10px] text-muted-foreground font-mono mt-0.5">{cell.latencyMs}ms</div>
          </div>
        );

      case 'DENIED':
        return (
          <div className="p-2.5 text-center">
            <div className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-[11px] font-mono text-zinc-400 bg-zinc-800/40 border border-zinc-700/40">
              <Lock className="w-3 h-3 text-zinc-400" />
              <span>Denied ({cell.httpStatus})</span>
            </div>
            <div className="text-[10px] text-muted-foreground font-mono mt-0.5">{cell.latencyMs}ms</div>
          </div>
        );

      default:
        return (
          <div className="p-2.5 text-center text-xs font-mono text-muted-foreground">
            {cell.httpStatus}
          </div>
        );
    }
  };

  return (
    <div className="space-y-4">
      {/* Filter and Search Bar */}
      <div className="flex flex-col md:flex-row gap-3 items-stretch md:items-center justify-between p-4 rounded-xl bg-card border border-border/70 shadow-sm">
        {/* Search */}
        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search endpoint path, method, or description..."
            className="w-full pl-9 pr-4 py-2 text-xs rounded-lg bg-background border border-border/80 text-foreground focus:outline-none focus:ring-1 focus:ring-blue-500"
          />
        </div>

        {/* Filters */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Status filter */}
          <div className="flex items-center rounded-lg border border-border/70 p-0.5 bg-muted/30 text-xs">
            <button
              type="button"
              onClick={() => setSelectedFilter('all')}
              className={`px-2.5 py-1 rounded-md text-xs font-medium transition-colors ${
                selectedFilter === 'all'
                  ? 'bg-blue-600 text-white'
                  : 'text-muted-foreground hover:text-foreground'
              }`}
            >
              All Decisions
            </button>
            <button
              type="button"
              onClick={() => setSelectedFilter('violations')}
              className={`px-2.5 py-1 rounded-md text-xs font-medium transition-colors ${
                selectedFilter === 'violations'
                  ? 'bg-red-600 text-white'
                  : 'text-muted-foreground hover:text-foreground'
              }`}
            >
              Violations Only
            </button>
            <button
              type="button"
              onClick={() => setSelectedFilter('bola')}
              className={`px-2.5 py-1 rounded-md text-xs font-medium transition-colors ${
                selectedFilter === 'bola'
                  ? 'bg-rose-600 text-white'
                  : 'text-muted-foreground hover:text-foreground'
              }`}
            >
              BOLA
            </button>
            <button
              type="button"
              onClick={() => setSelectedFilter('bfla')}
              className={`px-2.5 py-1 rounded-md text-xs font-medium transition-colors ${
                selectedFilter === 'bfla'
                  ? 'bg-purple-600 text-white'
                  : 'text-muted-foreground hover:text-foreground'
              }`}
            >
              BFLA
            </button>
          </div>

          {/* Category filter */}
          {categories.length > 2 && (
            <select
              value={selectedCategory}
              onChange={(e) => setSelectedCategory(e.target.value)}
              className="px-3 py-1.5 text-xs rounded-lg bg-background border border-border/80 text-foreground focus:outline-none"
            >
              {categories.map((cat) => (
                <option key={cat} value={cat}>
                  {cat === 'all' ? 'All Categories' : cat}
                </option>
              ))}
            </select>
          )}
        </div>
      </div>

      {/* 2D Grid Table */}
      <div className="overflow-x-auto rounded-xl border border-border/70 bg-card shadow-lg">
        <table className="w-full text-left border-collapse">
          {/* Header Row: Personas / Identities */}
          <thead>
            <tr className="bg-muted/40 border-b border-border/80 text-xs font-mono">
              <th className="py-3 px-4 w-72 text-muted-foreground font-semibold uppercase tracking-wider">
                API Route & Parameter
              </th>
              {dataset.personas.map((persona) => (
                <th
                  key={persona.id}
                  className="py-3 px-3 text-center min-w-[160px] border-l border-border/50"
                >
                  <div className="text-xs font-bold text-foreground">{persona.badge}</div>
                  <div className="text-[10px] text-muted-foreground font-sans font-normal truncate">
                    {persona.name}
                  </div>
                  {persona.tenantId && (
                    <div className="text-[9px] text-cyan-400 font-mono mt-0.5">
                      {persona.tenantId}
                    </div>
                  )}
                </th>
              ))}
            </tr>
          </thead>

          {/* Body Rows: Routes */}
          <tbody className="divide-y divide-border/40 text-xs">
            {filteredRoutes.length === 0 ? (
              <tr>
                <td
                  colSpan={dataset.personas.length + 1}
                  className="py-12 text-center text-muted-foreground font-mono"
                >
                  No endpoints matched the active search or violation filters.
                </td>
              </tr>
            ) : (
              filteredRoutes.map((route) => {
                return (
                  <tr
                    key={route.id}
                    className="hover:bg-muted/20 transition-colors group"
                  >
                    {/* Endpoint info column */}
                    <td className="py-3 px-4 align-middle">
                      <div className="flex items-center gap-2">
                        <span
                          className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border uppercase shrink-0 ${getMethodBadgeClass(
                            route.method,
                          )}`}
                        >
                          {route.method}
                        </span>
                        <span className="font-mono text-xs font-semibold text-foreground break-all">
                          {route.path}
                        </span>
                      </div>
                      <div className="flex items-center gap-2 mt-1">
                        <span className="text-[10px] font-mono text-muted-foreground">
                          {route.category}
                        </span>
                        {route.isPrivileged && (
                          <span className="text-[9px] font-mono px-1.5 py-0.2 rounded bg-purple-500/10 text-purple-300 border border-purple-500/30">
                            Privileged
                          </span>
                        )}
                        {route.hasParams && (
                          <span className="text-[9px] font-mono px-1.5 py-0.2 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/30">
                            :{route.paramName}
                          </span>
                        )}
                      </div>
                      {route.description && (
                        <p className="text-[11px] text-muted-foreground mt-1 line-clamp-1">
                          {route.description}
                        </p>
                      )}
                    </td>

                    {/* Persona decision cells */}
                    {dataset.personas.map((persona) => {
                      const cell = dataset.cells.find(
                        (c) =>
                          c.endpoint === route.path &&
                          c.method === route.method &&
                          c.personaId === persona.id,
                      );
                      return (
                        <td
                          key={persona.id}
                          className="p-0 border-l border-border/40 align-middle"
                        >
                          {renderCellContent(cell)}
                        </td>
                      );
                    })}
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Legend & Guidance Footer */}
      <div className="flex flex-wrap items-center justify-between gap-4 p-4 rounded-xl bg-muted/20 border border-border/60 text-xs font-mono text-muted-foreground">
        <div className="flex flex-wrap items-center gap-4">
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-400" />
            <span>Allowed (Expected)</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-zinc-500" />
            <span>Denied (Expected 401/403)</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-red-500 animate-pulse" />
            <span className="text-red-400 font-semibold">BOLA Violation (Critical IDOR)</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-purple-500 animate-pulse" />
            <span className="text-purple-400 font-semibold">BFLA Escalation (Admin Leak)</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-amber-500" />
            <span className="text-amber-400">Missing Auth</span>
          </div>
        </div>

        <div className="text-[11px] text-muted-foreground">
          Tip: Click any <span className="text-red-400 font-bold">BOLA / BFLA</span> cell to inspect side-by-side HTTP payload evidence and trigger automated retests.
        </div>
      </div>
    </div>
  );
};

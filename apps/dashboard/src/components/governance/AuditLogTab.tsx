import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  FileText,
  Search,
  RefreshCw,
  User,
  Code,
  X,
  Copy,
  Check,
} from 'lucide-react';
import { governanceApi, WorkspaceAuditRecord } from '../../api/governance.js';
import { useAppStore } from '../../store/useAppStore.js';

export const AuditLogTab: React.FC = () => {
  const { currentWorkspaceId, showToast } = useAppStore();
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedActionFilter, setSelectedActionFilter] = useState('ALL');
  const [inspectEvent, setInspectEvent] = useState<WorkspaceAuditRecord | null>(null);
  const [hasCopied, setHasCopied] = useState(false);

  const { data: auditEvents = [], isLoading, refetch, isFetching } = useQuery<WorkspaceAuditRecord[]>({
    queryKey: ['workspace-audit-events', currentWorkspaceId],
    queryFn: () => governanceApi.getAuditEvents(currentWorkspaceId),
    enabled: !!currentWorkspaceId,
    refetchInterval: 15000,
  });

  const filteredEvents = auditEvents.filter((ev) => {
    const q = searchQuery.toLowerCase().trim();
    const matchesQuery =
      !q ||
      ev.action.toLowerCase().includes(q) ||
      ev.actorId.toLowerCase().includes(q) ||
      (ev.entityType && ev.entityType.toLowerCase().includes(q)) ||
      (ev.ipAddress && ev.ipAddress.toLowerCase().includes(q));

    const matchesFilter =
      selectedActionFilter === 'ALL' ||
      ev.action.toUpperCase().startsWith(selectedActionFilter);

    return matchesQuery && matchesFilter;
  });

  const handleCopyJson = (obj: unknown) => {
    navigator.clipboard.writeText(JSON.stringify(obj, null, 2));
    setHasCopied(true);
    showToast('Copied payload to clipboard', 'info');
    setTimeout(() => setHasCopied(false), 2000);
  };

  return (
    <div className="space-y-6 animate-fade-in max-w-5xl">
      {/* Top Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-4 rounded-xl bg-card border border-border/70 glass-card">
        <div>
          <h2 className="text-sm font-semibold text-foreground flex items-center space-x-2">
            <FileText className="w-4 h-4 text-blue-400" />
            <span>Immutable Governance Audit Trail</span>
          </h2>
          <p className="text-xs text-muted-foreground mt-0.5">
            Append-only record of security mutations, authentication events, and target modifications.
          </p>
        </div>

        <div className="flex items-center space-x-2">
          <button
            type="button"
            onClick={() => refetch()}
            disabled={isFetching}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-accent hover:bg-accent/80 text-muted-foreground hover:text-foreground text-xs font-medium transition-colors border border-border"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isFetching ? 'animate-spin text-blue-400' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center gap-3">
        <div className="relative flex-1">
          <Search className="w-4 h-4 text-muted-foreground absolute left-3 top-2.5" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search by action, actor ID, or IP..."
            className="w-full pl-9 pr-4 py-2 rounded-xl bg-card border border-border/80 text-xs text-foreground placeholder-muted-foreground focus:outline-none focus:ring-1 focus:ring-blue-500"
          />
        </div>

        <div className="flex items-center space-x-1.5 overflow-x-auto pb-1 sm:pb-0">
          {['ALL', 'TARGET', 'RUN', 'AUTH', 'POLICY', 'MEMBER'].map((cat) => (
            <button
              key={cat}
              type="button"
              onClick={() => setSelectedActionFilter(cat)}
              className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-colors border ${
                selectedActionFilter === cat
                  ? 'bg-primary/20 text-blue-300 border-primary/40'
                  : 'bg-card text-muted-foreground border-border hover:bg-accent'
              }`}
            >
              {cat}
            </button>
          ))}
        </div>
      </div>

      {/* Audit Log Table */}
      <div className="rounded-xl border border-border/70 bg-card overflow-hidden glass-panel">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-accent/40 border-b border-border text-muted-foreground uppercase text-[10px] font-semibold tracking-wider">
              <tr>
                <th className="px-4 py-3">Timestamp</th>
                <th className="px-4 py-3">Action</th>
                <th className="px-4 py-3">Actor</th>
                <th className="px-4 py-3">Entity</th>
                <th className="px-4 py-3">IP Address</th>
                <th className="px-4 py-3 text-right">Payload</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/40 font-mono">
              {isLoading ? (
                <tr>
                  <td colSpan={6} className="px-4 py-8 text-center text-muted-foreground font-sans">
                    Loading immutable audit trail...
                  </td>
                </tr>
              ) : filteredEvents.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-4 py-8 text-center text-muted-foreground font-sans">
                    <FileText className="w-8 h-8 mx-auto mb-2 opacity-40 text-blue-400" />
                    <p className="text-sm font-medium">No audit events match your criteria</p>
                    <p className="text-xs text-muted-foreground/70 mt-1">
                      System records all configuration changes and test executions automatically.
                    </p>
                  </td>
                </tr>
              ) : (
                filteredEvents.map((ev) => (
                  <tr key={ev.id} className="hover:bg-accent/30 transition-colors">
                    <td className="px-4 py-3 text-muted-foreground whitespace-nowrap text-[11px]">
                      {new Date(ev.createdAt).toLocaleString()}
                    </td>
                    <td className="px-4 py-3">
                      <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-blue-500/10 text-blue-300 border border-blue-500/25">
                        {ev.action}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-foreground font-sans text-xs">
                      <div className="flex items-center space-x-1.5">
                        <User className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
                        <span className="truncate max-w-[140px] font-mono text-[11px]">{ev.actorId}</span>
                      </div>
                    </td>
                    <td className="px-4 py-3 text-muted-foreground text-[11px]">
                      {ev.entityType ? `${ev.entityType}:${ev.entityId?.slice(0, 8) || ''}` : '-'}
                    </td>
                    <td className="px-4 py-3 text-muted-foreground text-[11px]">
                      {ev.ipAddress || '127.0.0.1'}
                    </td>
                    <td className="px-4 py-3 text-right">
                      <button
                        type="button"
                        onClick={() => setInspectEvent(ev)}
                        className="px-2 py-1 rounded bg-accent hover:bg-accent/80 text-blue-400 font-sans text-[11px] transition-colors"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Event Details Inspection Modal */}
      {inspectEvent && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 animate-fade-in">
          <div className="fixed inset-0 bg-black/80 backdrop-blur-sm" onClick={() => setInspectEvent(null)} />
          <div className="relative w-full max-w-lg bg-card border border-border/80 rounded-2xl p-6 glass-panel glow-blue z-10 space-y-4 max-h-[85vh] flex flex-col">
            <div className="flex items-center justify-between pb-3 border-b border-border">
              <div className="flex items-center space-x-2">
                <Code className="w-4 h-4 text-blue-400" />
                <h3 className="font-semibold text-sm text-foreground">Audit Event Details</h3>
              </div>
              <button
                type="button"
                onClick={() => setInspectEvent(null)}
                className="text-muted-foreground hover:text-foreground p-1"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-2 text-xs">
              <div className="flex justify-between py-1 border-b border-border/50">
                <span className="text-muted-foreground">Action:</span>
                <span className="font-mono text-blue-300 font-bold">{inspectEvent.action}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-border/50">
                <span className="text-muted-foreground">Actor ID:</span>
                <span className="font-mono text-foreground">{inspectEvent.actorId}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-border/50">
                <span className="text-muted-foreground">Timestamp:</span>
                <span className="font-mono text-foreground">{new Date(inspectEvent.createdAt).toISOString()}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-border/50">
                <span className="text-muted-foreground">IP Address:</span>
                <span className="font-mono text-foreground">{inspectEvent.ipAddress || '127.0.0.1'}</span>
              </div>
            </div>

            {/* JSON Payload Viewer */}
            <div className="flex-1 flex flex-col min-h-0 space-y-2 pt-2">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-semibold text-muted-foreground uppercase tracking-wider">
                  Event Payload (JSON)
                </span>
                <button
                  type="button"
                  onClick={() => handleCopyJson(inspectEvent)}
                  className="flex items-center space-x-1 text-[11px] text-blue-400 hover:text-blue-300"
                >
                  {hasCopied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{hasCopied ? 'Copied' : 'Copy'}</span>
                </button>
              </div>
              <pre className="flex-1 overflow-y-auto p-3 rounded-xl bg-accent/60 border border-border text-[11px] font-mono text-foreground select-all max-h-56">
                {JSON.stringify(inspectEvent, null, 2)}
              </pre>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

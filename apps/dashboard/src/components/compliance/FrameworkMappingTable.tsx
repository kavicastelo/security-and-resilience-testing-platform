import React, { useState } from 'react';
import {
  CategoryComplianceScore,
  ControlDemonstrationLevel,
  COMPLIANCE_DISCLAIMER,
} from '../../api/reports.js';
import {
  ShieldCheck,
  ShieldAlert,
  Search,
  ChevronDown,
  ChevronRight,
  ExternalLink,
  Info,
  SlidersHorizontal,
  FileCode2,
} from 'lucide-react';
import { useAppStore } from '../../store/useAppStore.js';

interface FrameworkMappingTableProps {
  categories: CategoryComplianceScore[];
  selectedCategoryId?: string;
  onSelectCategory?: (id: string) => void;
  frameworkTitle: string;
}

export const FrameworkMappingTable: React.FC<FrameworkMappingTableProps> = ({
  categories,
  selectedCategoryId,
  onSelectCategory,
  frameworkTitle,
}) => {
  const { setActiveTab } = useAppStore();
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<'ALL' | 'COMPLIANT' | 'NON_COMPLIANT'>('ALL');
  const [levelFilter, setLevelFilter] = useState<string>('ALL');
  const [expandedRows, setExpandedRows] = useState<Record<string, boolean>>({});

  const toggleRow = (catId: string) => {
    setExpandedRows((prev) => ({ ...prev, [catId]: !prev[catId] }));
    onSelectCategory?.(catId);
  };

  // Filter categories
  const filteredCategories = categories.filter((cat) => {
    // Search filter
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchId = cat.id.toLowerCase().includes(q);
      const matchName = cat.name.toLowerCase().includes(q);
      const matchCwe = cat.cweList.some((cwe) => cwe.toLowerCase().includes(q));
      const matchFindings = cat.sampleFindings.some(
        (f) =>
          f.title.toLowerCase().includes(q) ||
          (f.endpoint && f.endpoint.toLowerCase().includes(q)) ||
          (f.ruleId && f.ruleId.toLowerCase().includes(q))
      );
      if (!matchId && !matchName && !matchCwe && !matchFindings) return false;
    }

    // Status filter
    if (statusFilter !== 'ALL' && cat.status !== statusFilter) {
      return false;
    }

    // Level filter
    if (levelFilter !== 'ALL' && cat.demonstrationLevel !== levelFilter) {
      return false;
    }

    return true;
  });

  const getDemonstrationBadge = (level: ControlDemonstrationLevel) => {
    switch (level) {
      case 'DIRECT':
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
            Direct Demonstration
          </span>
        );
      case 'SUPPORTING':
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-medium bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
            Supporting Evidence
          </span>
        );
      case 'RELATED':
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-medium bg-purple-500/10 text-purple-400 border border-purple-500/30">
            Related Context
          </span>
        );
    }
  };

  const getSeverityBadge = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return 'bg-rose-500/20 text-rose-400 border-rose-500/30';
      case 'high':
        return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
      case 'medium':
        return 'bg-amber-500/20 text-amber-400 border-amber-500/30';
      case 'low':
        return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
      default:
        return 'bg-slate-500/20 text-slate-400 border-slate-500/30';
    }
  };

  return (
    <div className="space-y-4">
      {/* Controls & Search Toolbar */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 bg-card border border-border p-3 rounded-xl">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <input
            type="text"
            placeholder="Search by Control ID, title, CWE (e.g. CWE-639), or endpoint..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-4 py-1.5 text-xs bg-muted/40 border border-border rounded-lg text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary"
          />
        </div>

        <div className="flex items-center gap-2">
          {/* Status Filter */}
          <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
            <SlidersHorizontal className="w-3.5 h-3.5" />
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value as 'ALL' | 'COMPLIANT' | 'NON_COMPLIANT')}
              aria-label="Filter by Compliance Status"
              className="px-2.5 py-1.5 text-xs bg-muted/40 border border-border rounded-lg text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
            >
              <option value="ALL">All Statuses</option>
              <option value="COMPLIANT">Compliant Only</option>
              <option value="NON_COMPLIANT">Violations Only</option>
            </select>
          </div>

          {/* Evidence Level Filter */}
          <select
            value={levelFilter}
            onChange={(e) => setLevelFilter(e.target.value)}
            aria-label="Filter by Demonstration Level"
            className="px-2.5 py-1.5 text-xs bg-muted/40 border border-border rounded-lg text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
          >
            <option value="ALL">All Evidence Levels</option>
            <option value="DIRECT">Direct Demonstration</option>
            <option value="SUPPORTING">Supporting Evidence</option>
            <option value="RELATED">Related Context</option>
          </select>
        </div>
      </div>

      {/* Table Container */}
      <div className="border border-border rounded-xl bg-card overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-muted/30 border-b border-border text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
              <tr>
                <th className="py-3 px-4 w-12 text-center"></th>
                <th className="py-3 px-4">Control & Standard</th>
                <th className="py-3 px-4">Demonstration Level</th>
                <th className="py-3 px-4">Mapped CWEs</th>
                <th className="py-3 px-4 text-center">Status</th>
                <th className="py-3 px-4 text-center">Violations</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {filteredCategories.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-muted-foreground">
                    <Info className="w-6 h-6 mx-auto mb-2 opacity-50" />
                    No control mappings match the selected filter criteria.
                  </td>
                </tr>
              ) : (
                filteredCategories.map((cat) => {
                  const isExpanded = Boolean(expandedRows[cat.id]);
                  const isSelected = selectedCategoryId === cat.id;

                  return (
                    <React.Fragment key={cat.id}>
                      <tr
                        onClick={() => toggleRow(cat.id)}
                        className={`cursor-pointer transition-colors group ${
                          isSelected
                            ? 'bg-cyan-500/10'
                            : isExpanded
                            ? 'bg-muted/40'
                            : 'hover:bg-muted/20'
                        }`}
                      >
                        {/* Expand toggle */}
                        <td className="py-3.5 px-4 text-center text-muted-foreground">
                          {cat.findingsCount > 0 ? (
                            isExpanded ? (
                              <ChevronDown className="w-4 h-4 mx-auto text-primary" />
                            ) : (
                              <ChevronRight className="w-4 h-4 mx-auto group-hover:text-foreground" />
                            )
                          ) : (
                            <span className="w-4 h-4 inline-block text-slate-600">&bull;</span>
                          )}
                        </td>

                        {/* Control ID & Title */}
                        <td className="py-3.5 px-4">
                          <div className="flex items-center gap-2">
                            <span className="font-mono font-bold text-primary px-1.5 py-0.5 rounded bg-primary/10 border border-primary/20 text-[11px]">
                              {cat.id}
                            </span>
                            <span className="font-semibold text-foreground">{cat.name}</span>
                          </div>
                        </td>

                        {/* Demonstration Level */}
                        <td className="py-3.5 px-4 whitespace-nowrap">
                          {getDemonstrationBadge(cat.demonstrationLevel)}
                        </td>

                        {/* Mapped CWEs */}
                        <td className="py-3.5 px-4">
                          <div className="flex flex-wrap gap-1 max-w-xs">
                            {cat.cweList.slice(0, 3).map((cwe) => (
                              <span
                                key={cwe}
                                className="px-1.5 py-0.5 text-[10px] font-mono rounded bg-slate-800 text-slate-300 border border-slate-700"
                              >
                                {cwe}
                              </span>
                            ))}
                            {cat.cweList.length > 3 && (
                              <span className="text-[10px] text-muted-foreground self-center">
                                +{cat.cweList.length - 3} more
                              </span>
                            )}
                          </div>
                        </td>

                        {/* Status */}
                        <td className="py-3.5 px-4 text-center whitespace-nowrap">
                          {cat.status === 'COMPLIANT' ? (
                            <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-[11px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                              <ShieldCheck className="w-3.5 h-3.5" />
                              COMPLIANT
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-[11px] font-bold bg-rose-500/10 text-rose-400 border border-rose-500/30">
                              <ShieldAlert className="w-3.5 h-3.5" />
                              VIOLATION
                            </span>
                          )}
                        </td>

                        {/* Violations Count & Breakdown */}
                        <td className="py-3.5 px-4 text-center">
                          {cat.findingsCount > 0 ? (
                            <div className="flex items-center justify-center gap-1.5">
                              {cat.criticalCount > 0 && (
                                <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-rose-500/20 text-rose-400 border border-rose-500/30">
                                  {cat.criticalCount} Crit
                                </span>
                              )}
                              {cat.highCount > 0 && (
                                <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-orange-500/20 text-orange-400 border border-orange-500/30">
                                  {cat.highCount} High
                                </span>
                              )}
                              {cat.mediumCount > 0 && (
                                <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-amber-500/20 text-amber-400 border border-amber-500/30">
                                  {cat.mediumCount} Med
                                </span>
                              )}
                              {cat.lowCount > 0 && (
                                <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-blue-500/20 text-blue-400 border border-blue-500/30">
                                  {cat.lowCount} Low
                                </span>
                              )}
                            </div>
                          ) : (
                            <span className="text-muted-foreground text-[11px]">0 active</span>
                          )}
                        </td>

                        {/* Action Drilldown */}
                        <td className="py-3.5 px-4 text-right">
                          <button
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation();
                              toggleRow(cat.id);
                            }}
                            className="px-2.5 py-1 rounded-md text-[11px] font-medium text-primary hover:text-primary-foreground hover:bg-primary/20 transition-colors"
                          >
                            {isExpanded ? 'Hide Details' : 'View Details'}
                          </button>
                        </td>
                      </tr>

                      {/* Expandable finding drill-down row */}
                      {isExpanded && (
                        <tr className="bg-muted/15 border-b border-border">
                          <td colSpan={7} className="p-4 sm:p-5">
                            <div className="space-y-3">
                              <div className="flex items-center justify-between">
                                <h4 className="text-xs font-semibold text-foreground flex items-center gap-2">
                                  <FileCode2 className="w-4 h-4 text-primary" />
                                  Active Verification Findings for {cat.id} ({cat.findingsCount})
                                </h4>
                                <span className="text-[11px] text-muted-foreground font-mono">
                                  Framework: {frameworkTitle}
                                </span>
                              </div>

                              {cat.sampleFindings.length === 0 ? (
                                <div className="p-4 rounded-lg bg-emerald-500/5 border border-emerald-500/20 text-emerald-400 text-xs flex items-center gap-2">
                                  <ShieldCheck className="w-4 h-4" />
                                  No active vulnerabilities or compliance gaps detected in this control scope. Control operates within verified baselines.
                                </div>
                              ) : (
                                <div className="space-y-2">
                                  {cat.sampleFindings.map((finding) => (
                                    <div
                                      key={finding.id}
                                      className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 p-3 rounded-lg bg-card border border-border hover:border-slate-700 transition-colors"
                                    >
                                      <div className="space-y-1">
                                        <div className="flex items-center gap-2">
                                          <span
                                            className={`px-1.5 py-0.5 rounded text-[10px] font-bold uppercase border ${getSeverityBadge(
                                              finding.severity
                                            )}`}
                                          >
                                            {finding.severity}
                                          </span>
                                          <span className="font-semibold text-slate-100 text-xs">
                                            {finding.title}
                                          </span>
                                        </div>
                                        <div className="flex items-center gap-3 text-[11px] text-muted-foreground font-mono">
                                          {finding.endpoint && (
                                            <span>
                                              Endpoint: <strong className="text-slate-300">{finding.endpoint}</strong>
                                            </span>
                                          )}
                                          {finding.cwe && (
                                            <span>
                                              CWE: <strong className="text-slate-300">{finding.cwe}</strong>
                                            </span>
                                          )}
                                          {finding.ruleId && (
                                            <span>
                                              Rule: <strong className="text-slate-300">{finding.ruleId}</strong>
                                            </span>
                                          )}
                                        </div>
                                      </div>

                                      <button
                                        type="button"
                                        onClick={() => setActiveTab('findings')}
                                        className="inline-flex items-center gap-1 px-2.5 py-1 text-[11px] font-medium text-cyan-400 hover:text-cyan-300 bg-cyan-950/40 border border-cyan-800/60 rounded-md transition-colors whitespace-nowrap"
                                      >
                                        Triage Finding <ExternalLink className="w-3 h-3" />
                                      </button>
                                    </div>
                                  ))}
                                </div>
                              )}
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Product Requirement 24.4 Truthful Auditing Invariant Disclaimer */}
      <div className="flex items-start gap-3 p-3.5 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-300 text-xs">
        <Info className="w-5 h-5 flex-shrink-0 mt-0.5 text-amber-400" />
        <div className="space-y-1">
          <strong className="block font-semibold text-amber-200">
            Compliance Invariant & Legal Disclaimer (Product Requirement 24.4):
          </strong>
          <p className="text-amber-300/90 leading-relaxed">
            {COMPLIANCE_DISCLAIMER} Results reflect automated security scans, fuzzing campaigns, and test plan evaluations mapped to standards taxonomies. Controls marked as &ldquo;Compliant&rdquo; signify the absence of detected critical vulnerabilities within the automated test scope, not formal regulatory sign-off.
          </p>
        </div>
      </div>
    </div>
  );
};

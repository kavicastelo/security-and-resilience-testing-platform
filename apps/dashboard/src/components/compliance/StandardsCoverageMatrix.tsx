import React, { useState, useMemo } from 'react';
import {
  OverallComplianceReport,
  FrameworkId,
  ControlDemonstrationLevel,
} from '../../api/reports.js';
import {
  ShieldAlert,
  Search,
  CheckCircle2,
} from 'lucide-react';

interface StandardsCoverageMatrixProps {
  report: OverallComplianceReport | null;
  onSelectCategory?: (framework: FrameworkId, categoryId: string) => void;
}

export const StandardsCoverageMatrix: React.FC<StandardsCoverageMatrixProps> = ({
  report,
  onSelectCategory,
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [levelFilter, setLevelFilter] = useState<'ALL' | ControlDemonstrationLevel>('ALL');
  const [statusFilter, setStatusFilter] = useState<'ALL' | 'COMPLIANT' | 'NON_COMPLIANT'>('ALL');

  const frameworks: Array<{ id: FrameworkId; label: string }> = [
    { id: 'OWASP_TOP_10_2021', label: 'OWASP Top 10' },
    { id: 'OWASP_API_2023', label: 'OWASP API' },
    { id: 'OWASP_ASVS_4_0', label: 'ASVS 4.0' },
    { id: 'PCI_DSS_4_0', label: 'PCI-DSS 4.0' },
  ];

  const rows = useMemo(() => {
    if (!report) return [];

    const result: Array<{
      frameworkId: FrameworkId;
      frameworkLabel: string;
      categoryId: string;
      name: string;
      demonstrationLevel: ControlDemonstrationLevel;
      status: 'COMPLIANT' | 'NON_COMPLIANT';
      findingsCount: number;
      criticalCount: number;
      highCount: number;
      cweList: string[];
    }> = [];

    for (const fw of frameworks) {
      const assessment = report.frameworks[fw.id];
      if (!assessment) continue;

      for (const cat of assessment.categories) {
        result.push({
          frameworkId: fw.id,
          frameworkLabel: fw.label,
          categoryId: cat.id,
          name: cat.name,
          demonstrationLevel: cat.demonstrationLevel,
          status: cat.status,
          findingsCount: cat.findingsCount,
          criticalCount: cat.criticalCount,
          highCount: cat.highCount,
          cweList: cat.cweList,
        });
      }
    }

    return result;
  }, [report]);

  const filteredRows = useMemo(() => {
    return rows.filter((row) => {
      const matchesSearch =
        !searchQuery ||
        row.categoryId.toLowerCase().includes(searchQuery.toLowerCase()) ||
        row.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
        row.cweList.some((c) => c.toLowerCase().includes(searchQuery.toLowerCase()));

      const matchesLevel = levelFilter === 'ALL' || row.demonstrationLevel === levelFilter;
      const matchesStatus = statusFilter === 'ALL' || row.status === statusFilter;

      return matchesSearch && matchesLevel && matchesStatus;
    });
  }, [rows, searchQuery, levelFilter, statusFilter]);

  if (!report) {
    return (
      <div className="p-8 text-center bg-card border border-border rounded-xl text-muted-foreground text-xs">
        No report data available to display matrix.
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Matrix Controls */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 bg-card border border-border p-3 rounded-xl">
        <div className="relative flex-1">
          <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Filter matrix by standard control, name, or CWE..."
            className="w-full pl-9 pr-3 py-1.5 bg-muted/30 border border-border rounded-lg text-xs text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary"
          />
        </div>

        <div className="flex items-center gap-2">
          <select
            value={levelFilter}
            onChange={(e) => setLevelFilter(e.target.value as typeof levelFilter)}
            className="bg-card border border-border px-2.5 py-1.5 rounded-lg text-xs text-foreground focus:outline-none"
            aria-label="Filter by Evidence Level"
          >
            <option value="ALL">All Evidence Levels</option>
            <option value="DIRECT">DIRECT</option>
            <option value="SUPPORTING">SUPPORTING</option>
            <option value="RELATED">RELATED</option>
          </select>

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value as typeof statusFilter)}
            className="bg-card border border-border px-2.5 py-1.5 rounded-lg text-xs text-foreground focus:outline-none"
            aria-label="Filter by Status"
          >
            <option value="ALL">All Statuses</option>
            <option value="COMPLIANT">COMPLIANT (0 defects)</option>
            <option value="NON_COMPLIANT">NON-COMPLIANT</option>
          </select>
        </div>
      </div>

      {/* Matrix Table */}
      <div className="border border-border rounded-xl bg-card overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-muted/40 border-b border-border text-muted-foreground uppercase text-[10px] font-semibold">
              <tr>
                <th className="py-2.5 px-3">Standard</th>
                <th className="py-2.5 px-3">Control ID</th>
                <th className="py-2.5 px-3">Title</th>
                <th className="py-2.5 px-3">Evidence Level</th>
                <th className="py-2.5 px-3">Status</th>
                <th className="py-2.5 px-3">Active Violations</th>
                <th className="py-2.5 px-3">Mapped CWEs</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/60">
              {filteredRows.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-muted-foreground">
                    No control mappings matched the current filter criteria.
                  </td>
                </tr>
              ) : (
                filteredRows.map((row) => {
                  const isCompliant = row.status === 'COMPLIANT';
                  return (
                    <tr
                      key={`${row.frameworkId}-${row.categoryId}`}
                      onClick={() => onSelectCategory?.(row.frameworkId, row.categoryId)}
                      className="hover:bg-muted/30 transition-colors cursor-pointer"
                    >
                      <td className="py-2.5 px-3 font-semibold text-foreground whitespace-nowrap">
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-muted border border-border">
                          {row.frameworkLabel}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 font-mono font-bold text-primary whitespace-nowrap">
                        {row.categoryId}
                      </td>
                      <td className="py-2.5 px-3 font-medium text-foreground max-w-xs truncate">
                        {row.name}
                      </td>
                      <td className="py-2.5 px-3 whitespace-nowrap">
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                          {row.demonstrationLevel}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 whitespace-nowrap">
                        {isCompliant ? (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                            <CheckCircle2 className="w-3 h-3" /> COMPLIANT
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold bg-rose-500/10 text-rose-400 border border-rose-500/30">
                            <ShieldAlert className="w-3 h-3" /> NON-COMPLIANT
                          </span>
                        )}
                      </td>
                      <td className="py-2.5 px-3 font-mono whitespace-nowrap">
                        {row.findingsCount === 0 ? (
                          <span className="text-emerald-400 font-bold">0</span>
                        ) : (
                          <span className="text-rose-400 font-bold">
                            {row.findingsCount} ({row.criticalCount} crit, {row.highCount} high)
                          </span>
                        )}
                      </td>
                      <td className="py-2.5 px-3 text-muted-foreground font-mono text-[11px] max-w-xs truncate">
                        {row.cweList.slice(0, 3).join(', ')}
                        {row.cweList.length > 3 ? ` +${row.cweList.length - 3}` : ''}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

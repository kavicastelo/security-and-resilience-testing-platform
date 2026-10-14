import React, { useState } from 'react';
import { GitCompare, ArrowUpRight, ArrowDownRight, CheckCircle2, AlertTriangle, Star, Check } from 'lucide-react';
import { BaselineComparison, HistoricalBaseline } from '../../api/performance.js';

export interface BaselineComparisonTableProps {
  comparisons: BaselineComparison[];
  historicalBaselines: HistoricalBaseline[];
  activeBaselineId: string;
  onSelectBaseline: (baselineId: string) => void;
  onPromoteGolden?: () => void;
  className?: string;
}

export const BaselineComparisonTable: React.FC<BaselineComparisonTableProps> = ({
  comparisons,
  historicalBaselines,
  activeBaselineId,
  onSelectBaseline,
  onPromoteGolden,
  className = '',
}) => {
  const [promotedSuccess, setPromotedSuccess] = useState(false);

  const activeBaseline =
    historicalBaselines.find((b) => b.id === activeBaselineId) ?? historicalBaselines[0];

  const hasCriticalRegressions = comparisons.some((c) => c.severity === 'critical');
  const hasWarningRegressions = comparisons.some((c) => c.severity === 'warning');
  const regressionGatePassed = !hasCriticalRegressions && !hasWarningRegressions;

  const handlePromote = () => {
    if (onPromoteGolden) onPromoteGolden();
    setPromotedSuccess(true);
    setTimeout(() => setPromotedSuccess(false), 3000);
  };

  return (
    <div className={`p-5 rounded-2xl bg-card/60 border border-border/60 shadow-xl space-y-4 ${className}`}>
      {/* Header & Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-border/40">
        <div>
          <div className="flex items-center gap-2">
            <GitCompare className="w-5 h-5 text-purple-400" />
            <h3 className="font-semibold text-foreground text-sm tracking-wide">
              Automated Performance Regression Baseline Comparison
            </h3>
            <span
              className={`text-[10px] font-mono uppercase px-2 py-0.5 rounded border ${
                regressionGatePassed
                  ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30'
                  : 'bg-rose-500/15 text-rose-400 border-rose-500/30'
              }`}
            >
              {regressionGatePassed ? 'Regression Gate Passed' : 'Regression Detected (>10%)'}
            </span>
          </div>
          <p className="text-xs text-muted-foreground mt-0.5">
            Evaluates current run against historical golden baselines to catch subtle tail-latency or throughput degradations.
          </p>
        </div>

        {/* Baseline Selector & Actions */}
        <div className="flex items-center gap-2">
          <select
            value={activeBaselineId}
            onChange={(e) => onSelectBaseline(e.target.value)}
            className="text-xs font-mono bg-background/80 border border-border/60 rounded-lg px-2.5 py-1.5 text-foreground focus:outline-none focus:ring-1 focus:ring-purple-500"
          >
            {historicalBaselines.map((b) => (
              <option key={b.id} value={b.id}>
                {b.isGolden ? '★ ' : ''}
                {b.name} ({b.runDate})
              </option>
            ))}
          </select>

          <button
            type="button"
            onClick={handlePromote}
            disabled={promotedSuccess}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-purple-500/10 hover:bg-purple-500/20 text-purple-300 border border-purple-500/30 transition-colors"
          >
            {promotedSuccess ? (
              <>
                <Check className="w-3.5 h-3.5 text-emerald-400" />
                <span className="text-emerald-400">Promoted!</span>
              </>
            ) : (
              <>
                <Star className="w-3.5 h-3.5" />
                <span>Set as Golden</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Comparison Table */}
      <div className="overflow-x-auto rounded-xl border border-border/40">
        <table className="w-full text-left text-xs font-mono">
          <thead className="bg-background/80 text-muted-foreground text-[11px] uppercase tracking-wider border-b border-border/40">
            <tr>
              <th className="py-2.5 px-4 font-medium">Metric Dimension</th>
              <th className="py-2.5 px-4 font-medium">Current Run</th>
              <th className="py-2.5 px-4 font-medium">
                Baseline ({activeBaseline?.name?.slice(0, 24)}...)
              </th>
              <th className="py-2.5 px-4 font-medium">Absolute Delta</th>
              <th className="py-2.5 px-4 font-medium">Variance (%)</th>
              <th className="py-2.5 px-4 font-medium text-right">Policy Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border/30">
            {comparisons.map((row) => {
              const isImproved = row.severity === 'improved';
              const isWarning = row.severity === 'warning';
              const isCritical = row.severity === 'critical';

              return (
                <tr
                  key={row.metric}
                  className={`hover:bg-muted/30 transition-colors ${
                    isCritical
                      ? 'bg-rose-500/5'
                      : isWarning
                      ? 'bg-amber-500/5'
                      : ''
                  }`}
                >
                  <td className="py-2.5 px-4 font-sans font-medium text-foreground">
                    {row.metric}
                  </td>

                  <td className="py-2.5 px-4 font-bold text-foreground">
                    {row.current.toLocaleString()} {row.unit}
                  </td>

                  <td className="py-2.5 px-4 text-muted-foreground">
                    {row.baseline.toLocaleString()} {row.unit}
                  </td>

                  <td className="py-2.5 px-4">
                    <span
                      className={`font-semibold ${
                        isCritical
                          ? 'text-rose-400'
                          : isWarning
                          ? 'text-amber-400'
                          : isImproved
                          ? 'text-emerald-400'
                          : 'text-muted-foreground'
                      }`}
                    >
                      {row.delta > 0 ? `+${row.delta}` : row.delta} {row.unit}
                    </span>
                  </td>

                  <td className="py-2.5 px-4">
                    <div className="flex items-center gap-1.5 font-bold">
                      {row.deltaPct > 0 ? (
                        <ArrowUpRight
                          className={`w-3.5 h-3.5 ${
                            row.isRegression ? 'text-rose-400' : 'text-emerald-400'
                          }`}
                        />
                      ) : row.deltaPct < 0 ? (
                        <ArrowDownRight
                          className={`w-3.5 h-3.5 ${
                            row.isRegression ? 'text-rose-400' : 'text-emerald-400'
                          }`}
                        />
                      ) : null}
                      <span
                        className={
                          isCritical
                            ? 'text-rose-400'
                            : isWarning
                            ? 'text-amber-400'
                            : isImproved
                            ? 'text-emerald-400'
                            : 'text-muted-foreground'
                        }
                      >
                        {row.deltaPct > 0 ? `+${row.deltaPct}%` : `${row.deltaPct}%`}
                      </span>
                    </div>
                  </td>

                  <td className="py-2.5 px-4 text-right">
                    <span
                      className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] uppercase font-bold border ${
                        isCritical
                          ? 'bg-rose-500/15 text-rose-400 border-rose-500/30'
                          : isWarning
                          ? 'bg-amber-500/15 text-amber-400 border-amber-500/30'
                          : isImproved
                          ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30'
                          : 'bg-muted/40 text-muted-foreground border-border/40'
                      }`}
                    >
                      {isCritical ? (
                        <>
                          <AlertTriangle className="w-3 h-3" />
                          Regression &gt;25%
                        </>
                      ) : isWarning ? (
                        <>
                          <AlertTriangle className="w-3 h-3" />
                          Regression &gt;10%
                        </>
                      ) : isImproved ? (
                        <>
                          <CheckCircle2 className="w-3 h-3" />
                          Improved
                        </>
                      ) : (
                        'Aligned'
                      )}
                    </span>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Regression Threshold Info Footer */}
      <div className="flex items-center justify-between text-[11px] text-muted-foreground pt-1">
        <span>
          Policy gate threshold: Any latency degradation exceeding <strong>+10.0%</strong> triggers a warning; exceeding{' '}
          <strong>+25.0%</strong> triggers a deployment blocker.
        </span>
        <span className="font-mono text-foreground font-semibold">
          {comparisons.filter((c) => c.isRegression).length} regressions detected
        </span>
      </div>
    </div>
  );
};

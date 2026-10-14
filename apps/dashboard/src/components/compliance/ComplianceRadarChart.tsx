import React, { useState } from 'react';
import { CategoryComplianceScore } from '../../api/reports.js';
import { ShieldCheck, ShieldAlert, Info } from 'lucide-react';

interface ComplianceRadarChartProps {
  categories: CategoryComplianceScore[];
  selectedCategoryId?: string;
  onSelectCategory?: (id: string) => void;
  className?: string;
}

export const ComplianceRadarChart: React.FC<ComplianceRadarChartProps> = ({
  categories,
  selectedCategoryId,
  onSelectCategory,
  className = '',
}) => {
  const [hoveredCat, setHoveredCat] = useState<CategoryComplianceScore | null>(null);

  if (!categories || categories.length === 0) {
    return (
      <div className="flex items-center justify-center h-72 text-muted-foreground text-sm">
        No compliance category data available for radar plot.
      </div>
    );
  }

  const size = 380;
  const center = size / 2;
  const radius = 130;
  const n = categories.length;

  // Calculates percentage score for category
  const getCategoryScore = (cat: CategoryComplianceScore): number => {
    if (cat.status === 'COMPLIANT' && cat.findingsCount === 0) return 100;
    const penalty = cat.criticalCount * 45 + cat.highCount * 25 + cat.mediumCount * 12 + cat.lowCount * 5;
    return Math.max(20, 100 - penalty);
  };

  // Concentric levels: 25%, 50%, 75%, 100%
  const levels = [0.25, 0.5, 0.75, 1.0];

  // Helper to calculate coordinates
  const getCoordinates = (index: number, factor: number) => {
    const angle = (Math.PI * 2 * index) / n - Math.PI / 2;
    return {
      x: center + radius * factor * Math.cos(angle),
      y: center + radius * factor * Math.sin(angle),
    };
  };

  // Generate radar polygon points
  const polygonPoints = categories
    .map((cat, i) => {
      const score = getCategoryScore(cat) / 100;
      const { x, y } = getCoordinates(i, score);
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(' ');

  // Compute overall average
  const avgScore = Math.round(
    categories.reduce((acc, cat) => acc + getCategoryScore(cat), 0) / (categories.length || 1)
  );

  return (
    <div className={`relative flex flex-col items-center justify-center ${className}`}>
      {/* SVG Radar */}
      <svg
        viewBox={`0 0 ${size} ${size}`}
        className="w-full max-w-[400px] h-auto overflow-visible select-none drop-shadow-md"
      >
        <defs>
          {/* Cyan / Blue Gradient for Radar Area */}
          <linearGradient id="radarFillGrad" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#06b6d4" stopOpacity="0.45" />
            <stop offset="100%" stopColor="#3b82f6" stopOpacity="0.15" />
          </linearGradient>
          <filter id="glowFilter" x="-20%" y="-20%" width="140%" height="140%">
            <feGaussianBlur stdDeviation="3" result="blur" />
            <feComposite in="SourceGraphic" in2="blur" operator="over" />
          </filter>
        </defs>

        {/* Concentric grid rings */}
        {levels.map((lvl) => {
          const ringPoints = categories
            .map((_, i) => {
              const { x, y } = getCoordinates(i, lvl);
              return `${x.toFixed(1)},${y.toFixed(1)}`;
            })
            .join(' ');

          return (
            <g key={`ring-${lvl}`}>
              <polygon
                points={ringPoints}
                className="fill-none stroke-slate-800/80 stroke-1 stroke-dasharray-[3,3]"
              />
              <text
                x={center + 4}
                y={center - radius * lvl + 10}
                className="text-[9px] fill-slate-500 font-mono font-medium pointer-events-none"
              >
                {Math.round(lvl * 100)}%
              </text>
            </g>
          );
        })}

        {/* Spokes */}
        {categories.map((_, i) => {
          const { x, y } = getCoordinates(i, 1.0);
          return (
            <line
              key={`spoke-${i}`}
              x1={center}
              y1={center}
              x2={x}
              y2={y}
              className="stroke-slate-800 stroke-[1.5]"
            />
          );
        })}

        {/* Shaded Area Polygon */}
        <polygon
          points={polygonPoints}
          fill="url(#radarFillGrad)"
          stroke="#06b6d4"
          strokeWidth="2.5"
          filter="url(#glowFilter)"
          className="transition-all duration-300 ease-out"
        />

        {/* Vertex Dots & Interactive Hotspots */}
        {categories.map((cat, i) => {
          const score = getCategoryScore(cat) / 100;
          const { x, y } = getCoordinates(i, score);
          const isSelected = selectedCategoryId === cat.id;
          const isCompliant = cat.status === 'COMPLIANT';

          return (
            <g
              key={`vertex-${cat.id}`}
              className="cursor-pointer group"
              onMouseEnter={() => setHoveredCat(cat)}
              onMouseLeave={() => setHoveredCat(null)}
              onClick={() => onSelectCategory?.(cat.id)}
            >
              {/* Outer pulse circle on selection */}
              {isSelected && (
                <circle
                  cx={x}
                  cy={y}
                  r="10"
                  className="fill-cyan-500/20 stroke-cyan-400 stroke-1 animate-ping"
                />
              )}

              {/* Point dot */}
              <circle
                cx={x}
                cy={y}
                r={isSelected ? 6 : 4.5}
                className={`transition-all duration-200 stroke-2 ${
                  isCompliant
                    ? 'fill-emerald-400 stroke-emerald-950 group-hover:r-6'
                    : 'fill-rose-500 stroke-rose-950 group-hover:r-6'
                } ${isSelected ? 'stroke-white stroke-[2.5]' : ''}`}
              />
            </g>
          );
        })}

        {/* Category Axis Labels */}
        {categories.map((cat, i) => {
          const { x, y } = getCoordinates(i, 1.22);
          const isSelected = selectedCategoryId === cat.id;
          const isCompliant = cat.status === 'COMPLIANT';

          return (
            <g
              key={`label-${cat.id}`}
              className="cursor-pointer group"
              onClick={() => onSelectCategory?.(cat.id)}
              onMouseEnter={() => setHoveredCat(cat)}
              onMouseLeave={() => setHoveredCat(null)}
            >
              <rect
                x={x - 24}
                y={y - 10}
                width="48"
                height="20"
                rx="4"
                className={`transition-all duration-150 ${
                  isSelected
                    ? 'fill-cyan-950/90 stroke-cyan-500 stroke-1'
                    : 'fill-slate-900/80 stroke-slate-800/80 stroke-1 group-hover:fill-slate-800'
                }`}
              />
              <circle
                cx={x - 16}
                cy={y}
                r="3"
                className={isCompliant ? 'fill-emerald-400' : 'fill-rose-500'}
              />
              <text
                x={x - 10}
                y={y + 3.5}
                className={`text-[10px] font-mono font-bold transition-colors ${
                  isSelected
                    ? 'fill-cyan-300'
                    : isCompliant
                    ? 'fill-slate-300 group-hover:fill-white'
                    : 'fill-rose-300 group-hover:fill-rose-200'
                }`}
              >
                {cat.id.length > 5 ? cat.id.slice(0, 5) : cat.id}
              </text>
            </g>
          );
        })}
      </svg>

      {/* Floating Center Summary Badge */}
      <div className="absolute top-2 left-2 flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900/90 border border-slate-800 text-xs backdrop-blur-sm shadow-sm">
        <span className="text-muted-foreground font-mono">Radar Index:</span>
        <span
          className={`font-mono font-bold text-sm ${
            avgScore >= 80 ? 'text-emerald-400' : avgScore >= 60 ? 'text-amber-400' : 'text-rose-400'
          }`}
        >
          {avgScore}%
        </span>
      </div>

      {/* Hover Tooltip Card */}
      {hoveredCat && (
        <div className="absolute bottom-2 left-1/2 -translate-x-1/2 z-20 w-80 p-3 rounded-xl bg-slate-900/95 border border-cyan-500/40 text-foreground shadow-2xl backdrop-blur-md pointer-events-none text-xs space-y-1.5 animate-in fade-in zoom-in-95 duration-150">
          <div className="flex items-center justify-between">
            <span className="font-mono font-bold text-cyan-400">{hoveredCat.id}</span>
            <span
              className={`px-2 py-0.5 rounded text-[10px] font-bold flex items-center gap-1 ${
                hoveredCat.status === 'COMPLIANT'
                  ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                  : 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
              }`}
            >
              {hoveredCat.status === 'COMPLIANT' ? (
                <ShieldCheck className="w-3 h-3" />
              ) : (
                <ShieldAlert className="w-3 h-3" />
              )}
              {hoveredCat.status}
            </span>
          </div>

          <div className="font-semibold text-slate-100 text-xs">{hoveredCat.name}</div>

          <div className="flex items-center justify-between text-[11px] pt-1 border-t border-slate-800 text-muted-foreground">
            <span>Score: <strong className="text-slate-200">{getCategoryScore(hoveredCat)}%</strong></span>
            <span>Violations: <strong className="text-rose-400">{hoveredCat.findingsCount}</strong></span>
            <span className="capitalize px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 font-mono text-[10px]">
              {hoveredCat.demonstrationLevel} Evidence
            </span>
          </div>
        </div>
      )}

      {/* Legend & Product Requirement 24.4 Prompt */}
      <div className="flex flex-wrap items-center justify-center gap-4 mt-2 text-[11px] text-muted-foreground">
        <div className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 inline-block" />
          <span>Compliant (100%)</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-rose-500 inline-block" />
          <span>Active Violations</span>
        </div>
        <div className="flex items-center gap-1 text-slate-500">
          <Info className="w-3 h-3" />
          <span>Click any node to focus controls</span>
        </div>
      </div>
    </div>
  );
};

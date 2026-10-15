import React, { useState, useEffect } from 'react';
import {
  Gauge,
  Play,
  RotateCcw,
  Download,
  Activity,
  BarChart3,
  GitCompare,
  Layers,
  Zap,
  CheckCircle2,
  AlertTriangle,
  Globe,
  Sliders,
} from 'lucide-react';
import {
  PerformanceStudioSnapshot,
  fetchMetricsStudioData,
  fetchHistoricalBaselines,
  promoteGoldenBaseline,
  executeLoadTest,
  PRESET_BENCHMARKS,
  HistoricalBaseline,
} from '../../api/performance.js';
import { targetsApi, Target } from '../../api/targets.js';
import { authFetch } from '../../api/client.js';
import { RpsThroughputChart } from './RpsThroughputChart.js';
import { PercentileHistogramChart } from './PercentileHistogramChart.js';
import { SaturationKneeCard } from './SaturationKneeCard.js';
import { BaselineComparisonTable } from './BaselineComparisonTable.js';

export const PerformanceStudioView: React.FC = () => {
  const [selectedTargetId, setSelectedTargetId] = useState<string>('');
  const [selectedRunId, setSelectedRunId] = useState<string>('');
  const [activePreset, setActivePreset] = useState<string>('');
  const [targets, setTargets] = useState<Target[]>([]);
  const [testRuns, setTestRuns] = useState<Array<{ id: string; status: string; createdAt: string; targetId?: string }>>([]);
  const [snapshot, setSnapshot] = useState<PerformanceStudioSnapshot | null>(null);
  const [baselines, setBaselines] = useState<HistoricalBaseline[]>([]);
  const [activeBaselineId, setActiveBaselineId] = useState<string>('');
  const [activeTab, setActiveTab] = useState<'waterfall' | 'distribution' | 'capacity' | 'baseline' | 'status'>('waterfall');
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [isSimulating, setIsSimulating] = useState<boolean>(false);
  const [simulationProgress, setSimulationProgress] = useState<number>(100);

  // Load targets and test runs on mount
  useEffect(() => {
    let mounted = true;
    targetsApi.listTargets().then((res) => {
      if (mounted && Array.isArray(res)) {
        setTargets(res);
        if (res.length > 0 && !selectedTargetId) {
          setSelectedTargetId(res[0].id);
        }
      }
    }).catch(() => {});

    authFetch('/api/v1/test-runs').then(async (res) => {
      if (res.ok) {
        const json = await res.json();
        if (mounted && Array.isArray(json.data)) {
          setTestRuns(json.data);
          if (json.data.length > 0) {
            setSelectedRunId(json.data[0].id);
          }
        }
      }
    }).catch(() => {});

    return () => {
      mounted = false;
    };
  }, []);

  // Load baselines whenever target changes
  useEffect(() => {
    let mounted = true;
    fetchHistoricalBaselines(selectedTargetId || undefined)
      .then((data) => {
        if (mounted) {
          setBaselines(data);
          if (data.length > 0) {
            const golden = data.find((b) => b.isGolden);
            setActiveBaselineId(golden ? golden.id : data[0].id);
          }
        }
      })
      .catch(() => {});
    return () => {
      mounted = false;
    };
  }, [selectedTargetId]);

  // Load snapshot whenever selectedRunId or activePreset changes
  useEffect(() => {
    let mounted = true;
    if (selectedRunId) {
      setIsLoading(true);
      fetchMetricsStudioData(selectedRunId)
        .then((data) => {
          if (mounted) {
            setSnapshot(data);
            setIsLoading(false);
          }
        })
        .catch(() => {
          if (mounted) {
            setSnapshot(null);
            setIsLoading(false);
          }
        });
    } else if (activePreset && PRESET_BENCHMARKS[activePreset]) {
      setSnapshot(PRESET_BENCHMARKS[activePreset].snapshot);
    } else {
      setSnapshot(null);
    }
    return () => {
      mounted = false;
    };
  }, [selectedRunId, activePreset]);

  // Simulate a live load test ramp or trigger native load
  const handleTriggerSimulation = async () => {
    if (isSimulating) return;
    setIsSimulating(true);
    setSimulationProgress(0);

    if (selectedTargetId) {
      try {
        const result = await executeLoadTest({
          targetId: selectedTargetId,
          concurrency: 20,
          duration: '10s',
          rpsTarget: 500,
        });
        if (result && result.testRunId) {
          setSelectedRunId(result.testRunId);
          setIsSimulating(false);
          setSimulationProgress(100);
          return;
        }
      } catch {
        // Fall back to client simulation progress
      }
    }

    const interval = setInterval(() => {
      setSimulationProgress((prev) => {
        if (prev >= 100) {
          clearInterval(interval);
          setIsSimulating(false);
          return 100;
        }
        return prev + 10;
      });
    }, 250);
  };

  const handlePromoteGolden = async () => {
    if (!snapshot) return;
    const promoted = await promoteGoldenBaseline({
      targetId: snapshot.targetId,
      testRunId: snapshot.runId,
      name: snapshot.profileName || `Baseline Run ${snapshot.runId.slice(0, 8)}`,
      isGolden: true,
    });
    if (promoted) {
      const updated = await fetchHistoricalBaselines(snapshot.targetId);
      setBaselines(updated);
      setActiveBaselineId(promoted.id);
    }
  };


  const handleExportReport = () => {
    if (!snapshot) return;
    const reportData = {
      title: 'Performance & Capacity Engineering Audit Report',
      timestamp: new Date().toISOString(),
      runId: snapshot.runId,
      target: snapshot.targetUrl,
      profile: snapshot.profileName,
      metrics: {
        peakRps: snapshot.peakRps,
        avgRps: snapshot.avgRps,
        errorRate: `${(snapshot.errorRate * 100).toFixed(2)}%`,
        p50: `${snapshot.percentiles.p50.toFixed(2)}ms`,
        p90: `${snapshot.percentiles.p90.toFixed(2)}ms`,
        p95: `${snapshot.percentiles.p95.toFixed(2)}ms`,
        p99: `${snapshot.percentiles.p99.toFixed(2)}ms`,
      },
      saturationAnalysis: snapshot.saturation,
      baselineComparison: snapshot.baselineComparison,
      statusDistribution: snapshot.statusDistribution,
      sloPassed: snapshot.sloPassed,
    };

    const blob = new Blob([JSON.stringify(reportData, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `perf-capacity-report-${snapshot.runId}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  if (isLoading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[400px] space-y-3">
        <Activity className="w-8 h-8 text-cyan-400 animate-spin" />
        <p className="text-sm font-mono text-muted-foreground">Loading Performance Studio telemetry...</p>
      </div>
    );
  }

  if (!snapshot) {
    return (
      <div className="space-y-6">
        {/* Studio Header */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-5 rounded-2xl bg-card/60 border border-border/60 shadow-xl backdrop-blur-md">
          <div className="space-y-1">
            <div className="flex items-center gap-2.5">
              <div className="p-2 rounded-xl bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                <Gauge className="w-6 h-6" />
              </div>
              <div>
                <h1 className="text-xl font-bold tracking-tight text-foreground flex items-center gap-2">
                  Performance & Capacity Studio
                  <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 font-normal">
                    Phase UI-10
                  </span>
                </h1>
                <p className="text-xs text-muted-foreground font-mono mt-0.5">
                  Native metric streaming, real latency percentiles, and historical baseline regression.
                </p>
              </div>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {/* Target Selector */}
            {targets.length > 0 && (
              <div className="flex items-center gap-1.5 bg-background/80 px-2 py-1 rounded-xl border border-border/60">
                <Globe className="w-3.5 h-3.5 text-muted-foreground" />
                <select
                  value={selectedTargetId}
                  onChange={(e) => setSelectedTargetId(e.target.value)}
                  className="text-xs font-mono bg-transparent text-foreground focus:outline-none cursor-pointer"
                >
                  {targets.map((t) => (
                    <option key={t.id} value={t.id} className="bg-popover text-popover-foreground">
                      {t.name} ({t.baseUrl})
                    </option>
                  ))}
                </select>
              </div>
            )}

            {/* Test Run Selector */}
            {testRuns.length > 0 && (
              <div className="flex items-center gap-1.5 bg-background/80 px-2 py-1 rounded-xl border border-border/60">
                <Activity className="w-3.5 h-3.5 text-muted-foreground" />
                <select
                  value={selectedRunId}
                  onChange={(e) => {
                    setSelectedRunId(e.target.value);
                    setActivePreset('');
                  }}
                  className="text-xs font-mono bg-transparent text-foreground focus:outline-none cursor-pointer"
                >
                  <option value="">-- Select Test Run --</option>
                  {testRuns.map((r) => (
                    <option key={r.id} value={r.id} className="bg-popover text-popover-foreground">
                      Run #{r.id.slice(0, 8)} ({r.status})
                    </option>
                  ))}
                </select>
              </div>
            )}

            {/* Load Sample Benchmark Scenario Dropdown */}
            <div className="flex items-center gap-1.5 bg-background/80 px-2 py-1 rounded-xl border border-border/60">
              <Sliders className="w-3.5 h-3.5 text-muted-foreground" />
              <select
                value={activePreset}
                onChange={(e) => {
                  setActivePreset(e.target.value);
                  setSelectedRunId('');
                }}
                className="text-xs font-mono bg-transparent text-foreground focus:outline-none cursor-pointer"
              >
                <option value="">Load Sample Benchmark Scenario...</option>
                {Object.entries(PRESET_BENCHMARKS).map(([id, p]) => (
                  <option key={id} value={id} className="bg-popover text-popover-foreground">
                    {p.name} (Simulation)
                  </option>
                ))}
              </select>
            </div>
          </div>
        </div>

        {/* Empty State Banner */}
        <div className="flex flex-col items-center justify-center p-12 rounded-2xl bg-card/40 border border-dashed border-border/80 text-center space-y-4">
          <div className="p-3 rounded-2xl bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
            <Gauge className="w-10 h-10" />
          </div>
          <div className="max-w-md space-y-1">
            <h3 className="text-base font-semibold text-foreground">No Performance Benchmark Selected</h3>
            <p className="text-xs text-muted-foreground">
              Run a live load test sweep against an authorized target, select a previous test run to analyze real recorded telemetry, or load a sample benchmark scenario for offline simulation.
            </p>
          </div>
          <div className="flex items-center gap-3 pt-2">
            <button
              type="button"
              onClick={handleTriggerSimulation}
              disabled={isSimulating}
              className="flex items-center gap-1.5 px-4 py-2 rounded-xl text-xs font-semibold bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white shadow-lg shadow-cyan-500/20 transition-all"
            >
              <Play className="w-4 h-4" />
              <span>Run Native Load Test</span>
            </button>
            <button
              type="button"
              onClick={() => {
                setActivePreset('api-gateway-standard');
                setSelectedRunId('');
              }}
              className="flex items-center gap-1.5 px-4 py-2 rounded-xl text-xs font-medium bg-background/80 hover:bg-background text-foreground border border-border/60 transition-colors"
            >
              <Sliders className="w-4 h-4 text-cyan-400" />
              <span>Load Sample Scenario</span>
            </button>
          </div>
        </div>
      </div>
    );
  }

  const isBreached = snapshot.percentiles.p95 > 500;

  return (
    <div className="space-y-6">
      {/* Studio Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-5 rounded-2xl bg-card/60 border border-border/60 shadow-xl backdrop-blur-md">
        <div className="space-y-1">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-xl bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
              <Gauge className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-xl font-bold tracking-tight text-foreground flex items-center gap-2">
                Performance & Capacity Studio
                <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 font-normal">
                  Phase UI-10
                </span>
              </h1>
              <div className="flex items-center gap-3 text-xs text-muted-foreground font-mono mt-0.5">
                <span className="flex items-center gap-1">
                  <Globe className="w-3.5 h-3.5 text-blue-400" />
                  {snapshot.targetUrl}
                </span>
                <span>•</span>
                <span>Run ID: {snapshot.runId}</span>
              </div>
            </div>
          </div>
        </div>

        {/* Controls: Target, Run, Sample Preset Switcher, Simulation, Export */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Target Selector */}
          {targets.length > 0 && (
            <div className="flex items-center gap-1.5 bg-background/80 px-2 py-1 rounded-xl border border-border/60">
              <Globe className="w-3.5 h-3.5 text-muted-foreground" />
              <select
                value={selectedTargetId}
                onChange={(e) => setSelectedTargetId(e.target.value)}
                className="text-xs font-mono bg-transparent text-foreground focus:outline-none cursor-pointer"
              >
                {targets.map((t) => (
                  <option key={t.id} value={t.id} className="bg-popover text-popover-foreground">
                    {t.name}
                  </option>
                ))}
              </select>
            </div>
          )}

          {/* Test Run Selector */}
          {testRuns.length > 0 && (
            <div className="flex items-center gap-1.5 bg-background/80 px-2 py-1 rounded-xl border border-border/60">
              <Activity className="w-3.5 h-3.5 text-muted-foreground" />
              <select
                value={selectedRunId}
                onChange={(e) => {
                  setSelectedRunId(e.target.value);
                  setActivePreset('');
                }}
                className="text-xs font-mono bg-transparent text-foreground focus:outline-none cursor-pointer"
              >
                <option value="">-- Active Runs --</option>
                {testRuns.map((r) => (
                  <option key={r.id} value={r.id} className="bg-popover text-popover-foreground">
                    Run #{r.id.slice(0, 8)}
                  </option>
                ))}
              </select>
            </div>
          )}

          {/* Sample Benchmark Scenario Dropdown */}
          <div className="flex items-center gap-1.5 bg-background/80 px-2 py-1 rounded-xl border border-border/60">
            <Sliders className="w-3.5 h-3.5 text-muted-foreground" />
            <select
              value={activePreset}
              onChange={(e) => {
                setActivePreset(e.target.value);
                if (e.target.value) {
                  setSelectedRunId('');
                }
              }}
              disabled={isSimulating}
              className="text-xs font-mono bg-transparent text-foreground focus:outline-none cursor-pointer"
            >
              <option value="">Load Sample Benchmark Scenario...</option>
              {Object.entries(PRESET_BENCHMARKS).map(([id, p]) => (
                <option key={id} value={id} className="bg-popover text-popover-foreground">
                  {p.name} (Simulation)
                </option>
              ))}
            </select>
          </div>


          {/* Trigger Load Test / Simulation */}
          <button
            type="button"
            onClick={handleTriggerSimulation}
            disabled={isSimulating}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold shadow-lg transition-all ${
              isSimulating
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 cursor-wait'
                : 'bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white shadow-cyan-500/20'
            }`}
          >
            {isSimulating ? (
              <>
                <RotateCcw className="w-3.5 h-3.5 animate-spin" />
                <span>Ramping ({simulationProgress}%)...</span>
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5" />
                <span>Run Capacity Sweep</span>
              </>
            )}
          </button>

          {/* Export Report */}
          <button
            type="button"
            onClick={handleExportReport}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-medium bg-background/80 hover:bg-background text-foreground border border-border/60 transition-colors"
          >
            <Download className="w-3.5 h-3.5 text-muted-foreground" />
            <span>Export Audit</span>
          </button>
        </div>
      </div>

      {/* Executive KPI Metric Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {/* Peak Throughput */}
        <div className="p-4 rounded-2xl bg-card/60 border border-border/60 shadow-lg space-y-1">
          <div className="flex items-center justify-between text-xs text-muted-foreground">
            <span>Peak Throughput</span>
            <Activity className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-cyan-400">
            {snapshot.peakRps.toLocaleString()}{' '}
            <span className="text-xs font-normal text-muted-foreground">RPS</span>
          </div>
          <p className="text-[11px] text-muted-foreground font-mono">
            Avg: {snapshot.avgRps.toLocaleString()} req/s across {snapshot.durationSec}s
          </p>
        </div>

        {/* P95 Latency SLA */}
        <div className="p-4 rounded-2xl bg-card/60 border border-border/60 shadow-lg space-y-1">
          <div className="flex items-center justify-between text-xs text-muted-foreground">
            <span>P95 SLA Latency</span>
            {isBreached ? (
              <AlertTriangle className="w-4 h-4 text-rose-400" />
            ) : (
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            )}
          </div>
          <div
            className={`text-2xl font-bold font-mono ${
              isBreached ? 'text-rose-400' : 'text-emerald-400'
            }`}
          >
            {snapshot.percentiles.p95.toFixed(2)}{' '}
            <span className="text-xs font-normal text-muted-foreground">ms</span>
          </div>
          <div className="flex items-center gap-1 text-[11px]">
            <span
              className={`font-semibold ${
                isBreached ? 'text-rose-400' : 'text-emerald-400'
              }`}
            >
              {isBreached ? 'SLA Breached (>500ms)' : 'SLA Met (≤500ms)'}
            </span>
          </div>
        </div>

        {/* Error Rate */}
        <div className="p-4 rounded-2xl bg-card/60 border border-border/60 shadow-lg space-y-1">
          <div className="flex items-center justify-between text-xs text-muted-foreground">
            <span>Error Rate</span>
            <Layers className="w-4 h-4 text-amber-400" />
          </div>
          <div
            className={`text-2xl font-bold font-mono ${
              snapshot.errorRate > 0.01 ? 'text-rose-400' : 'text-foreground'
            }`}
          >
            {(snapshot.errorRate * 100).toFixed(2)}{' '}
            <span className="text-xs font-normal text-muted-foreground">%</span>
          </div>
          <p className="text-[11px] text-muted-foreground font-mono">
            {(
              snapshot.statusDistribution.status4xx + snapshot.statusDistribution.status5xx
            ).toLocaleString()}{' '}
            failed requests
          </p>
        </div>

        {/* Saturation Knee Concurrency */}
        <div className="p-4 rounded-2xl bg-card/60 border border-border/60 shadow-lg space-y-1">
          <div className="flex items-center justify-between text-xs text-muted-foreground">
            <span>Capacity Knee Limit</span>
            <Zap className="w-4 h-4 text-purple-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-purple-400">
            {snapshot.saturation.kneeConcurrency}{' '}
            <span className="text-xs font-normal text-muted-foreground">VUs</span>
          </div>
          <p className="text-[11px] text-muted-foreground font-mono">
            At {snapshot.saturation.maxSustainedRps.toLocaleString()} sustained RPS
          </p>
        </div>
      </div>

      {/* Navigation Tab Bar */}
      <div className="flex items-center gap-2 border-b border-border/40 pb-2 text-xs font-medium">
        <button
          type="button"
          onClick={() => setActiveTab('waterfall')}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg transition-colors ${
            activeTab === 'waterfall'
              ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30'
              : 'text-muted-foreground hover:text-foreground'
          }`}
        >
          <Activity className="w-3.5 h-3.5" />
          <span>Throughput & Concurrency</span>
        </button>

        <button
          type="button"
          onClick={() => setActiveTab('distribution')}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg transition-colors ${
            activeTab === 'distribution'
              ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30'
              : 'text-muted-foreground hover:text-foreground'
          }`}
        >
          <BarChart3 className="w-3.5 h-3.5" />
          <span>Percentile Histogram</span>
        </button>

        <button
          type="button"
          onClick={() => setActiveTab('capacity')}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg transition-colors ${
            activeTab === 'capacity'
              ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30'
              : 'text-muted-foreground hover:text-foreground'
          }`}
        >
          <Zap className="w-3.5 h-3.5" />
          <span>Capacity & Saturation</span>
        </button>

        <button
          type="button"
          onClick={() => setActiveTab('baseline')}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg transition-colors ${
            activeTab === 'baseline'
              ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30'
              : 'text-muted-foreground hover:text-foreground'
          }`}
        >
          <GitCompare className="w-3.5 h-3.5" />
          <span>Baseline Regression</span>
        </button>

        <button
          type="button"
          onClick={() => setActiveTab('status')}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg transition-colors ${
            activeTab === 'status'
              ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30'
              : 'text-muted-foreground hover:text-foreground'
          }`}
        >
          <Layers className="w-3.5 h-3.5" />
          <span>Status Codes Breakdown</span>
        </button>
      </div>

      {/* Active Tab View Rendering */}
      {activeTab === 'waterfall' && (
        <div className="space-y-6">
          <RpsThroughputChart
            points={snapshot.timeSeries}
            saturation={snapshot.saturation}
          />
          <SaturationKneeCard
            saturation={snapshot.saturation}
            peakRps={snapshot.peakRps}
          />
        </div>
      )}

      {activeTab === 'distribution' && (
        <div className="space-y-6">
          <PercentileHistogramChart
            bins={snapshot.histogramBins}
            percentiles={snapshot.percentiles}
            totalRequests={snapshot.totalRequests}
            slaThresholdMs={500}
          />
        </div>
      )}

      {activeTab === 'capacity' && (
        <div className="space-y-6">
          <SaturationKneeCard
            saturation={snapshot.saturation}
            peakRps={snapshot.peakRps}
          />
          <RpsThroughputChart
            points={snapshot.timeSeries}
            saturation={snapshot.saturation}
          />
        </div>
      )}

      {activeTab === 'baseline' && (
        <div className="space-y-6">
          <BaselineComparisonTable
            comparisons={snapshot.baselineComparison}
            historicalBaselines={baselines}
            activeBaselineId={activeBaselineId}
            onSelectBaseline={(id) => setActiveBaselineId(id)}
            onPromoteGolden={handlePromoteGolden}
          />
        </div>
      )}

      {activeTab === 'status' && (
        <div className="p-5 rounded-2xl bg-card/60 border border-border/60 shadow-xl space-y-4">
          <div className="flex items-center gap-2 pb-3 border-b border-border/40">
            <Layers className="w-5 h-5 text-blue-400" />
            <div>
              <h3 className="font-semibold text-foreground text-sm tracking-wide">
                HTTP Status Code Distribution & Error Analysis
              </h3>
              <p className="text-xs text-muted-foreground">
                Breakdown of response classes under sustained concurrent workload.
              </p>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/20 space-y-1">
              <span className="text-xs text-emerald-400 uppercase font-mono font-medium">
                2xx Success Class
              </span>
              <div className="text-xl font-bold font-mono text-emerald-300">
                {snapshot.statusDistribution.status2xx.toLocaleString()}
              </div>
              <p className="text-[11px] text-muted-foreground">
                {(
                  (snapshot.statusDistribution.status2xx / snapshot.totalRequests) *
                  100
                ).toFixed(2)}
                % of total requests
              </p>
            </div>

            <div className="p-4 rounded-xl bg-amber-500/10 border border-amber-500/20 space-y-1">
              <span className="text-xs text-amber-400 uppercase font-mono font-medium">
                4xx Client Error Class
              </span>
              <div className="text-xl font-bold font-mono text-amber-300">
                {snapshot.statusDistribution.status4xx.toLocaleString()}
              </div>
              <p className="text-[11px] text-muted-foreground">
                {(
                  (snapshot.statusDistribution.status4xx / snapshot.totalRequests) *
                  100
                ).toFixed(2)}
                % (e.g. 429 Rate Limiting, 400 Bad Request)
              </p>
            </div>

            <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/20 space-y-1">
              <span className="text-xs text-rose-400 uppercase font-mono font-medium">
                5xx Server Error Class
              </span>
              <div className="text-xl font-bold font-mono text-rose-300">
                {snapshot.statusDistribution.status5xx.toLocaleString()}
              </div>
              <p className="text-[11px] text-muted-foreground">
                {(
                  (snapshot.statusDistribution.status5xx / snapshot.totalRequests) *
                  100
                ).toFixed(2)}
                % (e.g. 500 Internal, 504 Gateway Timeout)
              </p>
            </div>
          </div>

          {/* Granular HTTP Codes Table */}
          <div className="rounded-xl border border-border/40 overflow-hidden">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-background/80 text-muted-foreground text-[11px] uppercase border-b border-border/40">
                <tr>
                  <th className="py-2.5 px-4 font-medium">HTTP Status Code</th>
                  <th className="py-2.5 px-4 font-medium">Classification</th>
                  <th className="py-2.5 px-4 font-medium">Count</th>
                  <th className="py-2.5 px-4 font-medium text-right">Percentage</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/30">
                {Object.entries(snapshot.statusDistribution.codeCounts).map(([code, count]) => {
                  const numCode = parseInt(code, 10);
                  const isSuccess = numCode >= 200 && numCode < 300;
                  const isClient = numCode >= 400 && numCode < 500;
                  const isServer = numCode >= 500;

                  return (
                    <tr key={code} className="hover:bg-muted/20">
                      <td className="py-2.5 px-4 font-bold text-foreground">{code}</td>
                      <td className="py-2.5 px-4 font-sans text-muted-foreground">
                        {isSuccess
                          ? 'OK / Created'
                          : numCode === 429
                          ? 'Too Many Requests (Rate Limited)'
                          : isClient
                          ? 'Client Error'
                          : numCode === 504
                          ? 'Gateway Timeout'
                          : isServer
                          ? 'Internal Server Error'
                          : 'Unknown'}
                      </td>
                      <td className="py-2.5 px-4 text-foreground">{count.toLocaleString()}</td>
                      <td className="py-2.5 px-4 text-right">
                        <span
                          className={`font-bold ${
                            isSuccess
                              ? 'text-emerald-400'
                              : isClient
                              ? 'text-amber-400'
                              : 'text-rose-400'
                          }`}
                        >
                          {((count / snapshot.totalRequests) * 100).toFixed(2)}%
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};

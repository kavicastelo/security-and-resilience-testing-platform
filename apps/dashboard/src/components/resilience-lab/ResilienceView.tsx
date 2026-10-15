import React, { useState, useEffect } from 'react';
import {
  Zap,
  GitCommit,
  AlertOctagon,
  ShieldCheck,
  PlayCircle,
  FileCode,
} from 'lucide-react';
import { useAppStore } from '../../store/useAppStore.js';
import {
  ChaosInjectionConfig,
  RecoveryTimelinePoint,
  ChaosExecutionStats,
  StateMachineModel,
  RaceConditionBurstModel,
  PRESET_CHAOS_PROFILES,
  SAMPLE_RECOVERY_TIMELINE,
  SAMPLE_STATE_MACHINE_MODEL,
  SAMPLE_RACE_CONDITION_MODEL,
  executeChaosSimulation,
  getStateMachineModel,
  getRaceConditionBurstModel,
} from '../../api/resilience.js';
import { ChaosControlPanel } from './ChaosControlPanel.js';
import { RecoveryTimelineChart } from './RecoveryTimelineChart.js';
import { StateMachineGraph } from './StateMachineGraph.js';
import { RaceConditionInspector } from './RaceConditionInspector.js';

export const ResilienceView: React.FC = () => {
  const { showToast, setActiveTab } = useAppStore();

  // Tab state
  const [activeTab, setActiveCurrentTab] = useState<'chaos' | 'stateMachine' | 'raceCondition'>('chaos');

  // Chaos injection state
  const [chaosConfig, setChaosConfig] = useState<ChaosInjectionConfig>(
    PRESET_CHAOS_PROFILES.db_brownout,
  );
  const [isInjecting, setIsInjecting] = useState<boolean>(false);
  const [timelineData, setTimelineData] = useState<RecoveryTimelinePoint[]>(SAMPLE_RECOVERY_TIMELINE);
  const [executionStats, setExecutionStats] = useState<ChaosExecutionStats>({
    status: 'idle',
    totalRequests: 100,
    faultsInjected: 40,
    unrecoveredErrors: 15,
    rtoSeconds: 2.8,
    circuitBreakerState: 'CLOSED',
    resilienceScore: 78,
  });

  // State machine & race condition states
  const [stateMachineModel, setStateMachineModel] = useState<StateMachineModel>(SAMPLE_STATE_MACHINE_MODEL);
  const [raceConditionModel, setRaceConditionModel] = useState<RaceConditionBurstModel>(SAMPLE_RACE_CONDITION_MODEL);

  useEffect(() => {
    const loadModels = async () => {
      try {
        const sm = await getStateMachineModel();
        if (sm && sm.states.length > 0) {
          setStateMachineModel(sm);
        }
        const rc = await getRaceConditionBurstModel();
        if (rc && rc.requests.length > 0) {
          setRaceConditionModel(rc);
        }
      } catch {
        // preserve initial states
      }
    };

    loadModels();
  }, []);

  const handleStartChaos = async () => {
    setIsInjecting(true);
    showToast('Chaos fault injection started on proxy interface', 'info');

    try {
      const result = await executeChaosSimulation(chaosConfig);
      setExecutionStats(result.stats);
      if (result.timeline && result.timeline.length > 0) {
        setTimelineData(result.timeline);
      }
      showToast(result.message, result.success ? 'success' : 'error');
    } catch (err: any) {
      showToast(err.message || 'Simulation error', 'error');
    } finally {
      setIsInjecting(false);
    }
  };

  const handleStopChaos = () => {
    setIsInjecting(false);
    showToast('Chaos injection halted. Proxy returned to pass-through mode.', 'info');
  };

  const handleLoadExamplePresets = () => {
    setStateMachineModel(SAMPLE_STATE_MACHINE_MODEL);
    setRaceConditionModel(SAMPLE_RACE_CONDITION_MODEL);
    setTimelineData(SAMPLE_RECOVERY_TIMELINE);
    showToast('Loaded example resilience models & state machine presets', 'info');
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-300">
      {/* View Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-2 border-b border-border/60">
        <div>
          <div className="flex items-center gap-2">
            <span className="p-2 rounded-xl bg-amber-500/10 border border-amber-500/20 text-amber-400">
              <Zap className="w-5 h-5" />
            </span>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-xl font-bold tracking-tight text-foreground">
                  Resilience, Chaos & Business Logic Workbench
                </h1>
                <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-amber-500/15 text-amber-400 border border-amber-500/30">
                  Resilience Lab v1.0
                </span>
              </div>
              <p className="text-xs text-muted-foreground mt-0.5">
                Simulate network faults, measure recovery time objective (RTO), and verify state transition invariants.
              </p>
            </div>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={handleLoadExamplePresets}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg bg-card border border-border/80 text-foreground hover:bg-accent transition-colors"
          >
            <FileCode className="w-3.5 h-3.5 text-purple-400" />
            <span>Load Example Presets</span>
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('runs')}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg bg-amber-600 hover:bg-amber-500 text-white transition-colors"
          >
            <PlayCircle className="w-3.5 h-3.5" />
            <span>Launch Engine in Test Plan</span>
          </button>
        </div>
      </div>

      {/* Safety Circuit Breaker Invariant Banner */}
      <div className="p-4 rounded-xl bg-emerald-950/20 border border-emerald-500/30 flex items-start sm:items-center justify-between gap-4">
        <div className="flex items-start sm:items-center gap-3">
          <div className="p-1.5 rounded-lg bg-emerald-500/20 text-emerald-400 shrink-0">
            <ShieldCheck className="w-4 h-4" />
          </div>
          <div className="text-xs">
            <span className="font-bold text-emerald-300">Safety Circuit Breakers Active: </span>
            <span className="text-emerald-200/80">
              Fault injection is rate-limited and capped. Automatic circuit breaker trip triggers on consecutive failures to protect upstream server stability.
            </span>
          </div>
        </div>
        <span className="hidden sm:inline-block text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 shrink-0">
          Rule 13 Enforced
        </span>
      </div>

      {/* Tab Switcher */}
      <div className="flex items-center gap-2 border-b border-border/60 pb-1">
        <button
          type="button"
          onClick={() => setActiveCurrentTab('chaos')}
          className={`flex items-center gap-2 px-4 py-2 text-xs font-semibold rounded-lg transition-colors ${
            activeTab === 'chaos'
              ? 'bg-amber-600 text-white shadow-sm'
              : 'text-muted-foreground hover:text-foreground hover:bg-accent'
          }`}
        >
          <Zap className="w-4 h-4" />
          <span>Chaos MITM & Recovery (RTO)</span>
        </button>

        <button
          type="button"
          onClick={() => setActiveCurrentTab('stateMachine')}
          className={`flex items-center gap-2 px-4 py-2 text-xs font-semibold rounded-lg transition-colors ${
            activeTab === 'stateMachine'
              ? 'bg-amber-600 text-white shadow-sm'
              : 'text-muted-foreground hover:text-foreground hover:bg-accent'
          }`}
        >
          <GitCommit className="w-4 h-4" />
          <span>Business Logic State Machine</span>
          {stateMachineModel.bypassExploits.length > 0 && (
            <span className="px-1.5 py-0.2 rounded-full text-[10px] bg-red-500 text-white font-mono">
              {stateMachineModel.bypassExploits.length}
            </span>
          )}
        </button>

        <button
          type="button"
          onClick={() => setActiveCurrentTab('raceCondition')}
          className={`flex items-center gap-2 px-4 py-2 text-xs font-semibold rounded-lg transition-colors ${
            activeTab === 'raceCondition'
              ? 'bg-amber-600 text-white shadow-sm'
              : 'text-muted-foreground hover:text-foreground hover:bg-accent'
          }`}
        >
          <AlertOctagon className="w-4 h-4" />
          <span>Race Condition Burst Lab</span>
          {raceConditionModel.isVulnerable && (
            <span className="px-1.5 py-0.2 rounded-full text-[10px] bg-red-500 text-white font-mono">
              EXPLOIT
            </span>
          )}
        </button>
      </div>

      {/* Tab 1: Chaos & Recovery */}
      {activeTab === 'chaos' && (
        <div className="space-y-6">
          <ChaosControlPanel
            config={chaosConfig}
            onChangeConfig={setChaosConfig}
            isRunning={isInjecting}
            onStartInjection={handleStartChaos}
            onStopInjection={handleStopChaos}
            isProductionTarget={false}
          />
          <RecoveryTimelineChart
            timeline={timelineData}
            stats={executionStats}
          />
        </div>
      )}

      {/* Tab 2: State Machine Flow */}
      {activeTab === 'stateMachine' && (
        <StateMachineGraph model={stateMachineModel} />
      )}

      {/* Tab 3: Race Condition Burst */}
      {activeTab === 'raceCondition' && (
        <RaceConditionInspector model={raceConditionModel} />
      )}
    </div>
  );
};

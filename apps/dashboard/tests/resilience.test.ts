import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  PRESET_CHAOS_PROFILES,
  SAMPLE_RECOVERY_TIMELINE,
  SAMPLE_STATE_MACHINE_MODEL,
  SAMPLE_RACE_CONDITION_MODEL,
  EMPTY_STATE_MACHINE_MODEL,
  EMPTY_RACE_CONDITION_MODEL,
  EXAMPLE_STATE_MACHINE_MODEL,
  EXAMPLE_RACE_CONDITION_MODEL,
  getChaosPresetConfig,
  getStateMachineModel,
  getRaceConditionBurstModel,
  executeChaosSimulation,
  auditStateMachine,
  executeRaceConditionBurst,
} from '../src/api/resilience.js';

describe('Phase UI-09 & PR-04: Business Logic State Machine, Race Conditions & Chaos Workbench', () => {
  const originalFetch = globalThis.fetch;

  beforeEach(() => {
    globalThis.fetch = vi.fn().mockImplementation(async (url: string, options?: any) => {
      const urlStr = String(url);

      if (urlStr.includes('/api/v1/resilience/chaos/execute')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            success: true,
            stats: {
              status: 'completed',
              totalRequests: 100,
              faultsInjected: 35,
              unrecoveredErrors: 10,
              rtoSeconds: 2.4,
              circuitBreakerState: 'CLOSED',
              resilienceScore: 82,
            },
            timeline: SAMPLE_RECOVERY_TIMELINE,
            message: 'Chaos resilience simulation completed successfully across proxy pipeline.',
          }),
        };
      }

      if (urlStr.includes('/api/v1/resilience/business-logic/state-machine')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            success: true,
            data: SAMPLE_STATE_MACHINE_MODEL,
          }),
        };
      }

      if (urlStr.includes('/api/v1/resilience/business-logic/race-condition')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            success: true,
            data: SAMPLE_RACE_CONDITION_MODEL,
          }),
        };
      }

      return {
        ok: true,
        status: 200,
        json: async () => ({ success: true, data: {} }),
      };
    });
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  describe('Chaos Injection Profiles & Parameter Constraints', () => {
    it('provides all 4 core resilience simulation presets with valid parameters', () => {
      const presets = Object.keys(PRESET_CHAOS_PROFILES);
      expect(presets).toContain('slow_3g');
      expect(presets).toContain('db_brownout');
      expect(presets).toContain('dependency_outage');
      expect(presets).toContain('packet_loss');

      // Verify packet drop rate stays within safety limits (<= 50%)
      for (const key of presets) {
        const config = PRESET_CHAOS_PROFILES[key];
        expect(config.packetDropRate).toBeLessThanOrEqual(50);
        expect(config.packetDropRate).toBeGreaterThanOrEqual(0);
        expect(config.latencyMs).toBeGreaterThanOrEqual(0);
        expect([429, 500, 502, 503, 504]).toContain(config.errorStatusCode);
      }
    });

    it('enforces safety circuit breaker on high-severity brownout and outage profiles', () => {
      const brownout = PRESET_CHAOS_PROFILES.db_brownout;
      expect(brownout.circuitBreakerEnabled).toBe(true);
      expect(brownout.circuitBreakerThreshold).toBeGreaterThanOrEqual(3);

      const outage = PRESET_CHAOS_PROFILES.dependency_outage;
      expect(outage.circuitBreakerEnabled).toBe(true);
    });

    it('retrieves default preset config through getChaosPresetConfig', () => {
      const config = getChaosPresetConfig('slow_3g');
      expect(config.activePreset).toBe('slow_3g');
      expect(config.latencyMs).toBe(1800);
      expect(config.jitterMs).toBe(400);
    });
  });

  describe('Recovery Time Objective (RTO) & Degradation Timeline', () => {
    it('contains sequential timeline phases from baseline to healthy recovery', () => {
      expect(SAMPLE_RECOVERY_TIMELINE.length).toBeGreaterThanOrEqual(10);

      const phases = SAMPLE_RECOVERY_TIMELINE.map((p) => p.phase);
      expect(phases).toContain('baseline');
      expect(phases).toContain('injection');
      expect(phases).toContain('tripped');
      expect(phases).toContain('recovering');
      expect(phases).toContain('healthy');
    });

    it('models error rate spike during injection and subsequent recovery', () => {
      const baseline = SAMPLE_RECOVERY_TIMELINE.find((p) => p.phase === 'baseline');
      const injection = SAMPLE_RECOVERY_TIMELINE.find((p) => p.phase === 'injection');
      const healthy = SAMPLE_RECOVERY_TIMELINE.find((p) => p.phase === 'healthy');

      expect(baseline?.errorRate).toBeLessThan(5);
      expect(injection?.errorRate).toBeGreaterThan(30);
      expect(healthy?.errorRate).toBeLessThan(5);
    });
  });

  describe('Business Logic State Machine & Step-Skipping Invariants', () => {
    it('defines clean empty baseline when no workflow is audited', () => {
      expect(EMPTY_STATE_MACHINE_MODEL.workflowId).toBe('');
      expect(EMPTY_STATE_MACHINE_MODEL.states.length).toBe(0);
      expect(EMPTY_STATE_MACHINE_MODEL.transitions.length).toBe(0);
      expect(EMPTY_STATE_MACHINE_MODEL.bypassExploits.length).toBe(0);
    });

    it('returns empty model baseline when controller returns 404 or connection error', async () => {
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 404,
        json: async () => ({ success: false }),
      });

      const model = await getStateMachineModel('non-existent');
      expect(model.workflowId).toBe('');
      expect(model.states.length).toBe(0);
      expect(model.transitions.length).toBe(0);
    });

    it('models multi-step e-commerce checkout workflow with designated payment guard', async () => {
      const model = await getStateMachineModel();
      expect(model.states.length).toBe(5);
      expect(model.initialStepId).toBe('step-cart-init');
      expect(model.terminalStepIds).toContain('step-order-fulfill');

      const paymentStep = model.states.find((s) => s.id === 'step-payment');
      expect(paymentStep).toBeDefined();
      expect(paymentStep?.isPaymentOrTerminal).toBe(true);
    });

    it('identifies critical step-skipping exploit bypassing payment to fulfill order', async () => {
      const model = await getStateMachineModel();
      expect(model.bypassExploits.length).toBeGreaterThan(0);

      const paymentBypass = model.bypassExploits.find((e) => e.id === 'fnd-bypass-skip-pay');
      expect(paymentBypass).toBeDefined();
      expect(paymentBypass?.severity).toBe('CRITICAL');
      expect(paymentBypass?.skippedSteps).toContain('step-payment');
      expect(paymentBypass?.targetEndpoint).toBe('/api/cart/fulfill');
      expect(paymentBypass?.actualStatus).toBe(200);
      expect(paymentBypass?.expectedStatus).toBe(400);
    });

    it('flags illegal transitions in state graph transition matrix', async () => {
      const model = await getStateMachineModel();
      const illegalTransition = model.transitions.find(
        (t) => t.fromStepId === 'step-add-item' && t.toStepId === 'step-order-fulfill',
      );

      expect(illegalTransition).toBeDefined();
      expect(illegalTransition?.isAllowed).toBe(false);
      expect(illegalTransition?.isBypass).toBe(true);
      expect(illegalTransition?.observedStatus).toBe(200);
    });

    it('audits state machine via POST /api/v1/resilience/business-logic/state-machine', async () => {
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ success: true, data: EXAMPLE_STATE_MACHINE_MODEL }),
      });

      const result = await auditStateMachine({
        workflowName: 'Test Checkout Workflow',
        states: EXAMPLE_STATE_MACHINE_MODEL.states,
        transitions: EXAMPLE_STATE_MACHINE_MODEL.transitions,
      });

      expect(result.workflowId).toBe(EXAMPLE_STATE_MACHINE_MODEL.workflowId);
      expect(globalThis.fetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/v1/resilience/business-logic/state-machine'),
        expect.objectContaining({ method: 'POST' }),
      );
    });
  });

  describe('Synchronized Socket Burst & Race Condition Detection', () => {
    it('defines clean empty baseline when no race condition burst has run', () => {
      expect(EMPTY_RACE_CONDITION_MODEL.testId).toBe('');
      expect(EMPTY_RACE_CONDITION_MODEL.concurrency).toBe(0);
      expect(EMPTY_RACE_CONDITION_MODEL.requests.length).toBe(0);
      expect(EMPTY_RACE_CONDITION_MODEL.isVulnerable).toBe(false);
    });

    it('returns empty burst model baseline when controller returns empty or connection error', async () => {
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 404,
        json: async () => ({ success: false }),
      });

      const model = await getRaceConditionBurstModel();
      expect(model.testId).toBe('');
      expect(model.concurrency).toBe(0);
      expect(model.isVulnerable).toBe(false);
    });

    it('models high-concurrency synchronized burst with sub-millisecond jitter', async () => {
      const model = await getRaceConditionBurstModel();
      expect(model.concurrency).toBe(20);
      expect(model.barrierReleaseJitterMs).toBeLessThan(1.0); // Sub-millisecond precision
      expect(model.maxAllowedSuccess).toBe(1);
      expect(model.requests.length).toBe(20);
    });

    it('detects multiple duplicate redemption exploits in race condition burst', async () => {
      const model = await getRaceConditionBurstModel();
      expect(model.isVulnerable).toBe(true);
      expect(model.actualSuccessCount).toBeGreaterThan(model.maxAllowedSuccess);

      const anomalies = model.requests.filter((r) => r.isAnomaly);
      expect(anomalies.length).toBe(5); // 6 total successes minus 1 allowed = 5 anomalies
      expect(anomalies.every((a) => a.statusCode === 200)).toBe(true);
    });

    it('provides atomic lock and optimistic locking remediation strategy', async () => {
      const model = await getRaceConditionBurstModel();
      expect(model.remediation).toBeDefined();
      expect(model.remediation.toLowerCase()).toContain('lock');
    });

    it('executes race condition burst via POST /api/v1/resilience/business-logic/race-condition', async () => {
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ success: true, data: EXAMPLE_RACE_CONDITION_MODEL }),
      });

      const result = await executeRaceConditionBurst({
        endpoint: '/api/v1/coupons/redeem',
        concurrency: 10,
      });

      expect(result.isVulnerable).toBe(true);
      expect(globalThis.fetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/v1/resilience/business-logic/race-condition'),
        expect.objectContaining({ method: 'POST' }),
      );
    });
  });

  describe('Chaos Simulation Execution Service', () => {
    it('executes simulated fault injection and receives live metrics from controller', async () => {
      const config = getChaosPresetConfig('db_brownout');
      const result = await executeChaosSimulation(config);

      expect(result.success).toBe(true);
      expect(result.stats).toBeDefined();
      expect(result.stats.totalRequests).toBe(100);
      expect(result.stats.faultsInjected).toBe(35);
      expect(result.stats.rtoSeconds).toBeGreaterThan(0);
      expect(result.stats.resilienceScore).toBeGreaterThanOrEqual(0);
      expect(result.stats.resilienceScore).toBeLessThanOrEqual(100);
      expect(globalThis.fetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/v1/resilience/chaos/execute'),
        expect.objectContaining({ method: 'POST' }),
      );
    });

    it('strictly throws error and never fabricates fake stats when controller execution fails', async () => {
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 500,
        json: async () => ({
          success: false,
          error: { message: 'Target unreachable during chaos injection' },
        }),
      });

      const config = getChaosPresetConfig('slow_3g');
      await expect(executeChaosSimulation(config)).rejects.toThrow(
        'Target unreachable during chaos injection',
      );
    });
  });
});

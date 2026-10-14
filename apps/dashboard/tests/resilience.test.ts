import { describe, it, expect } from 'vitest';
import {
  PRESET_CHAOS_PROFILES,
  SAMPLE_RECOVERY_TIMELINE,
  SAMPLE_STATE_MACHINE_MODEL,
  SAMPLE_RACE_CONDITION_MODEL,
  getChaosPresetConfig,
  getStateMachineModel,
  getRaceConditionBurstModel,
  executeChaosSimulation,
} from '../src/api/resilience.js';

describe('Phase UI-09: Business Logic State Machine, Race Conditions & Chaos Workbench', () => {
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
  });

  describe('Synchronized Socket Burst & Race Condition Detection', () => {
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
  });

  describe('Chaos Simulation Execution Service', () => {
    it('executes simulated fault injection and calculates resilience score and RTO', async () => {
      const config = getChaosPresetConfig('db_brownout');
      const result = await executeChaosSimulation(config);

      expect(result.success).toBe(true);
      expect(result.stats).toBeDefined();
      expect(result.stats.totalRequests).toBeGreaterThan(0);
      expect(result.stats.faultsInjected).toBeGreaterThan(0);
      expect(result.stats.rtoSeconds).toBeGreaterThan(0);
      expect(result.stats.resilienceScore).toBeGreaterThanOrEqual(0);
      expect(result.stats.resilienceScore).toBeLessThanOrEqual(100);
    });
  });
});

import { describe, it, expect, beforeEach } from 'vitest';
import {
  usePlanStudioStore,
  REGISTERED_ENGINES,
  CURATED_PRESETS,
} from '../src/store/usePlanStudioStore.js';

describe('Phase UI-04: Test Plan Studio, Engine Pipeline Sequencer & Scenario Composer', () => {
  beforeEach(() => {
    usePlanStudioStore.getState().resetPlan();
  });

  it('exposes comprehensive registered engine catalog across all categories', () => {
    expect(REGISTERED_ENGINES.length).toBeGreaterThanOrEqual(15);

    const categories = new Set(REGISTERED_ENGINES.map((e) => e.category));
    expect(categories.has('web')).toBe(true);
    expect(categories.has('api')).toBe(true);
    expect(categories.has('auth')).toBe(true);
    expect(categories.has('resilience')).toBe(true);
    expect(categories.has('infra')).toBe(true);

    // Verify key engines exist
    const engineIds = REGISTERED_ENGINES.map((e) => e.id);
    expect(engineIds).toContain('engine-native-headers');
    expect(engineIds).toContain('engine-native-fuzzer');
    expect(engineIds).toContain('engine-native-graphql');
    expect(engineIds).toContain('engine-worker-k6');
    expect(engineIds).toContain('engine-native-chaos');
    expect(engineIds).toContain('engine-native-smuggling');
    expect(engineIds).toContain('engine-sbom-supply-chain');
    expect(engineIds).toContain('engine-k8s-infra');
  });

  it('provides all 5 curated testing presets with correct engine mappings', () => {
    expect(CURATED_PRESETS).toHaveLength(5);
    const presetIds = CURATED_PRESETS.map((p) => p.id);
    expect(presetIds).toContain('quick-web');
    expect(presetIds).toContain('api-bola');
    expect(presetIds).toContain('resilience-chaos');
    expect(presetIds).toContain('supply-chain-infra');
    expect(presetIds).toContain('production-safe');

    // Quick Web should not be disruptive
    const quickWeb = CURATED_PRESETS.find((p) => p.id === 'quick-web')!;
    expect(quickWeb.disruptive).toBe(false);

    // Resilience & Chaos must be flagged as disruptive
    const chaosPreset = CURATED_PRESETS.find((p) => p.id === 'resilience-chaos')!;
    expect(chaosPreset.disruptive).toBe(true);
    expect(chaosPreset.engineIds).toContain('engine-native-chaos');
    expect(chaosPreset.engineIds).toContain('engine-worker-k6');
  });

  it('applies presets and updates pipeline sequence stages', () => {
    const store = usePlanStudioStore.getState();

    // Apply Resilience & Chaos preset
    store.applyPreset('resilience-chaos');
    const updatedState = usePlanStudioStore.getState();

    expect(updatedState.planName).toBe('Resilience & Chaos Laboratory');
    expect(updatedState.steps.length).toBe(4);
    expect(updatedState.steps.some((s) => s.engineId === 'engine-worker-k6')).toBe(true);
    expect(updatedState.steps.some((s) => s.engineId === 'engine-native-chaos')).toBe(true);

    // Add a new step
    store.addStep('engine-native-headers');
    expect(usePlanStudioStore.getState().steps).toHaveLength(5);

    // Reorder step
    store.reorderStep(0, 1);
    expect(usePlanStudioStore.getState().steps[1].engineId).toBe('engine-worker-k6');
  });

  it('allows fine-grained customization of engine parameters', () => {
    const store = usePlanStudioStore.getState();
    store.applyPreset('resilience-chaos');

    const k6Step = usePlanStudioStore.getState().steps.find((s) => s.engineId === 'engine-worker-k6')!;
    expect(k6Step).toBeDefined();

    // Update VUs and duration
    store.updateStepOptions(k6Step.id, { vus: 25, durationSec: 30, maxP95Ms: 400 });

    const updatedK6Step = usePlanStudioStore.getState().steps.find((s) => s.id === k6Step.id)!;
    expect(updatedK6Step.options.vus).toBe(25);
    expect(updatedK6Step.options.durationSec).toBe(30);
    expect(updatedK6Step.options.maxP95Ms).toBe(400);
  });

  it('exports structured DSL V2 YAML representation matching plan specification', () => {
    const store = usePlanStudioStore.getState();
    store.setPlanName('Custom API Security Suite');
    store.setSelectedTargetId('11111111-2222-3333-4444-555555555555');
    store.setTargetEndpoint('/api/v2');
    store.applyPreset('api-bola');

    const yaml = store.exportToYaml();

    expect(yaml).toContain("version: '2.0'");
    expect(yaml).toContain("name: 'Full API, GraphQL & BOLA Penetration'");
    expect(yaml).toContain("targetId: '11111111-2222-3333-4444-555555555555'");
    expect(yaml).toContain("endpoint: '/api/v2'");
    expect(yaml).toContain('pipeline:');
    expect(yaml).toContain('engine-native-graphql');
    expect(yaml).toContain('engine-native-authz-matrix');
    expect(yaml).toContain('engine-native-fuzzer');
  });
});

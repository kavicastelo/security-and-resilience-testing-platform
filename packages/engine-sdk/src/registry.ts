import {
  engineRegistry,
  EngineRegistry,
  TestEngine,
} from '@security-lab/test-sdk';

export { engineRegistry, EngineRegistry };

/**
 * Secondary dynamic registry for isolated/custom worker engines.
 */
class DynamicWorkerEngineRegistry {
  private readonly customEngines = new Map<string, TestEngine>();

  register(engine: TestEngine): void {
    this.customEngines.set(engine.id, engine);
    // Also register into global engine registry if available
    try {
      engineRegistry.register(engine);
    } catch {
      // Ignore if already registered
    }
  }

  get(engineId: string): TestEngine | undefined {
    return this.customEngines.get(engineId) || engineRegistry.get(engineId);
  }

  has(engineId: string): boolean {
    return this.customEngines.has(engineId) || engineRegistry.has(engineId);
  }

  clear(): void {
    this.customEngines.clear();
  }
}

export const dynamicWorkerEngineRegistry = new DynamicWorkerEngineRegistry();

import { TestEngine, EngineExecutionClass } from './engine.js';
import { TestCapability, CapabilityCategory } from './capability.js';
import { HeadersSecurityEngine } from './engines/headers.engine.js';
import { CorsSecurityEngine } from './engines/cors.engine.js';
import { TlsSecurityEngine } from './engines/tls.engine.js';
import { DeclarativeTestEngine } from './engines/declarative.engine.js';
import { RateLimitResilienceEngine } from './engines/rate-limit.engine.js';
import { ZapScannerEngine } from './engines/zap.engine.js';
import { TrivyScannerEngine } from './engines/trivy.engine.js';
import { K6ResilienceEngine } from './engines/k6.engine.js';

export interface EngineRegistrationMetadata {
  executionClass?: EngineExecutionClass;
  enabled?: boolean;
}

export interface RegisteredEngineEntry {
  engine: TestEngine;
  executionClass: EngineExecutionClass;
  registeredAt: Date;
}

/**
 * Pluggable EngineRegistry for dynamic discovery, inspection, and execution dispatch
 * across Class A native analyzers, Class B container scanners, and Class C workers.
 */
export class EngineRegistry {
  private readonly engines = new Map<string, RegisteredEngineEntry>();

  /**
   * Registers a test engine into the dynamic registry.
   */
  register(engine: TestEngine, metadata?: EngineRegistrationMetadata): this {
    if (!engine || !engine.id) {
      throw new Error('Cannot register an engine without a valid id');
    }

    const executionClass: EngineExecutionClass =
      metadata?.executionClass ||
      engine.executionClass ||
      (engine.id.startsWith('engine-worker-')
        ? 'class_c_worker'
        : engine.id.startsWith('engine-container-')
          ? 'class_b_container'
          : 'class_a_native');

    this.engines.set(engine.id, {
      engine,
      executionClass,
      registeredAt: new Date(),
    });

    return this;
  }

  /**
   * Unregisters an engine by ID. Returns true if removed, false otherwise.
   */
  unregister(engineId: string): boolean {
    return this.engines.delete(engineId);
  }

  /**
   * Gets an engine instance by ID.
   */
  get(engineId: string): TestEngine | undefined {
    return this.engines.get(engineId)?.engine;
  }

  /**
   * Gets full registration metadata including executionClass.
   */
  getEntry(engineId: string): RegisteredEngineEntry | undefined {
    return this.engines.get(engineId);
  }

  /**
   * Checks if an engine ID is registered.
   */
  has(engineId: string): boolean {
    return this.engines.has(engineId);
  }

  /**
   * Returns all registered engine instances.
   */
  getAll(): TestEngine[] {
    return Array.from(this.engines.values()).map((entry) => entry.engine);
  }

  /**
   * Finds all engines exposing a specific capability ID (e.g. 'headers_audit', 'zap_baseline').
   */
  findByCapability(capabilityId: string): TestEngine[] {
    return this.getAll().filter((engine) =>
      engine.capabilities().some((cap) => cap.id === capabilityId),
    );
  }

  /**
   * Finds all engines belonging to a specific capability category.
   */
  findByCategory(category: CapabilityCategory): TestEngine[] {
    return this.getAll().filter((engine) =>
      engine.capabilities().some((cap) => cap.category === category),
    );
  }

  /**
   * Finds all engines matching a given execution class ('class_a_native', 'class_b_container', 'class_c_worker').
   */
  findByExecutionClass(executionClass: EngineExecutionClass): TestEngine[] {
    return Array.from(this.engines.values())
      .filter((entry) => entry.executionClass === executionClass)
      .map((entry) => entry.engine);
  }

  /**
   * Lists all capabilities provided across all registered engines.
   */
  listCapabilities(): { engineId: string; capability: TestCapability }[] {
    const list: { engineId: string; capability: TestCapability }[] = [];
    for (const [engineId, entry] of this.engines) {
      for (const cap of entry.engine.capabilities()) {
        list.push({ engineId, capability: cap });
      }
    }
    return list;
  }

  /**
   * Initializes all registered engines that implement the optional init() hook.
   */
  async initAll(): Promise<void> {
    for (const entry of this.engines.values()) {
      if (typeof entry.engine.init === 'function') {
        await entry.engine.init();
      }
    }
  }

  /**
   * Runs health checks across all registered engines that implement healthCheck().
   * Engines without a custom hook default to healthy (true).
   */
  async healthCheckAll(): Promise<Record<string, boolean>> {
    const results: Record<string, boolean> = {};
    for (const [id, entry] of this.engines) {
      if (typeof entry.engine.healthCheck === 'function') {
        try {
          results[id] = await entry.engine.healthCheck();
        } catch {
          results[id] = false;
        }
      } else {
        results[id] = true;
      }
    }
    return results;
  }

  /**
   * Gracefully tears down all registered engines that implement the cleanup() hook.
   */
  async cleanupAll(): Promise<void> {
    for (const entry of this.engines.values()) {
      if (typeof entry.engine.cleanup === 'function') {
        try {
          await entry.engine.cleanup();
        } catch {
          // Continue cleanup for remaining engines
        }
      }
    }
  }
}

/**
 * Factory function creating a pre-populated EngineRegistry with all standard Security Lab engines.
 */
export function createDefaultEngineRegistry(): EngineRegistry {
  const registry = new EngineRegistry();
  registry.register(new HeadersSecurityEngine());
  registry.register(new CorsSecurityEngine());
  registry.register(new TlsSecurityEngine());
  registry.register(new DeclarativeTestEngine());
  registry.register(new RateLimitResilienceEngine());
  registry.register(new ZapScannerEngine());
  registry.register(new TrivyScannerEngine());
  registry.register(new K6ResilienceEngine());
  return registry;
}

/**
 * Default global singleton EngineRegistry.
 */
export const engineRegistry = createDefaultEngineRegistry();

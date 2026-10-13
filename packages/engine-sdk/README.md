# Engine SDK & Worker Sandboxing (`@security-lab/engine-sdk`)

The Engine SDK package provides runtime sandboxing, lifecycle management, and isolated worker thread execution for native security testing engines within the Security & Resilience Testing Platform.

---

## 1. Architectural Mission

Third-party security test engines, complex fuzzers, or untrusted DSL definitions may inadvertently contain infinite loops, memory leaks, or unhandled exceptions. In an un-sandboxed environment, executing these engines on the main Node.js event loop risks freezing or crashing the entire agent daemon or CLI runner process.

The Engine SDK solves this by executing native engines inside dedicated Node.js `worker_threads` with:
- **Hard Execution Timeouts**: Terminating runaway threads within 100ms using `worker.terminate()`.
- **Memory Ceilings**: Enforcing V8 heap boundaries via `resourceLimits: { maxOldGenerationSizeMb }`.
- **Safe Bi-Directional IPC**: Streaming progress, logs, metrics, and findings cleanly back to the parent process without shared-state mutation.
- **Graceful In-Process Fallback**: Seamless fallback to main-thread execution in resource-constrained or single-threaded debug environments.

---

## 2. Usage Example

```typescript
import { workerRunner, TestEngine } from '@security-lab/engine-sdk';
import { dynamicWorkerEngineRegistry } from '@security-lab/engine-sdk';

// 1. Register engine
dynamicWorkerEngineRegistry.register(myCustomEngine);

// 2. Execute within isolated worker thread
const result = await workerRunner.execute(
  'my-custom-engine',
  {
    targetUrl: 'https://example.com',
    timeoutMs: 10000,
  },
  context,
  {
    enabled: true,
    timeoutMs: 10000,
    maxOldGenerationSizeMb: 512, // 512MB heap limit
    fallbackToInProcess: true,
  },
);

if (result.success) {
  console.log('Engine completed successfully:', result.findings);
} else {
  console.warn('Engine failed or terminated:', result.error);
}
```

---

## 3. Worker Protocol & IPC Architecture

- `EXECUTE`: Dispatched from parent thread with input parameters and serialized context.
- `PROGRESS`: Pushed from worker to update parent runner on phase progression.
- `LOG`: Forwarded from worker thread to parent logger with level preservation.
- `RESULT`: Emitted on successful test engine completion with duration and memory metrics.
- `ERROR`: Transmitted on handled exceptions, timeout termination, or OOM crashes.

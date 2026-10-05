# Controller Test Execution Workers

## Responsibility
Orchestrates asynchronous test execution dispatch, worker queues, and runner lifecycles.

### What belongs here:
* Queue processors and dispatcher logic that launches Class A native tests in-process or delegates Class B / Class C jobs to Docker runners.
* Heartbeat and timeout monitors for running executions.

### What does NOT belong here:
* Synchronous HTTP request handlers.
* Hardcoded scanner attack payloads.

### Future Phase Implementation:
* **Phase 2**: Asynchronous execution dispatcher and container lifecycle manager.

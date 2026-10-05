# ADR 0001: Modular Monolith Architecture for Controller

## Status
Accepted

## Context
When architecting an enterprise application security testing platform, a common temptation is premature decomposition into microservices (e.g., separate services for target management, scheduling, reporting, findings, and notifications). 

However, during early phases and local developer testing:
* Microservices introduce heavy deployment friction, network latency, distributed transaction complexity, and excessive container overhead.
* Developers running security QA locally need to spin up the entire laboratory with minimal RAM and CPU consumption.

## Decision
We adopt a **Modular Monolith** architecture for the central controller application:
* The controller runs as a single Fastify Node.js application.
* Internally, code is strictly divided into cohesive domain modules (projects, targets, test-runs, findings, policies).
* All internal module communication occurs in-process via strongly typed interfaces and domain contracts.
* Test execution isolation is handled via containerized runners rather than microservice daemons.

## Consequences
### Positive
* Single process to start, test, and debug locally.
* Low memory footprint (< 100MB idle).
* Simple transactional consistency using single-database transactions.
* Smooth pathway to extract individual services in the future if specific scaling bottlenecks emerge.

### Negative
* Requires engineering discipline to avoid tight coupling between internal controller modules.

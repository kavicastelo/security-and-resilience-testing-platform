# Security Boundaries & Defensive Controls

## 1. Operating Principle

Security Lab is designed exclusively for authorized testing of systems owned or operated under legal authority. To enforce this principle, the architecture places multiple defensive layers between user input and network dispatch.

---

## 2. Target Scope Model as a Hard Security Boundary

The system does **not** permit arbitrary URLs to be passed on the fly without a verified target registration. Every target record defines strict network and capability boundaries:

### 2.1 Host and Port Allow-Listing
* **Allowed Hosts**: Outbound requests are strictly limited to domains and IP addresses in the `allowedHosts` list.
* **Allowed Ports**: Only authorized ports (e.g. 80, 443, 8080) are permitted. Outbound calls to internal services (e.g. 5432, 6379, metadata IP `169.254.169.254`) are blocked by default.

### 2.2 Excluded Paths
Targets can specify sensitive or destructive URL paths (`excludedPaths`) such as `/admin/reset-db` or `/billing/charge`. The execution dispatcher intercepts and rejects requests targeting these paths before transmission.

### 2.3 Explicit Capability Opt-In
Testing capabilities are segregated into passive and active/disruptive:
* `testing.activeScanning: boolean` (must be explicitly true to run active probes)
* `testing.loadTesting: boolean` (must be explicitly true to run stress tests)
* `testing.chaosTesting: boolean` (must be explicitly true to simulate failures)

Any attempt to run active or stress tests against a target with `activeScanning: false` or `loadTesting: false` fails with a deterministic scope authorization error.

### 2.4 Safety Clamps & Rate Limits
* `limits.maxRps`: Hard clamp on outbound request rate.
* `limits.maxConcurrency`: Maximum simultaneous in-flight connections.
* `limits.maxDuration`: Hard execution timeout after which tests are aborted.

---

## 3. Container Sandboxing & Least Privilege

External scanner tools (Class B) and load generators (Class C) run in ephemeral Docker containers:
* Containers run with unprivileged user IDs (`USER 10001:10001` or `nobody`).
* Containers have no access to host Docker sockets or filesystem directories.
* Containers are connected to isolated bridge networks.
* CPU and memory limits are enforced via Docker run parameters (`--memory="1g" --cpus="1.0"`).
* Containers are destroyed (`--rm`) immediately upon test completion.

# Example Target Definitions

## Responsibility
Contains declarative YAML target specifications demonstrating how operators define security scopes and boundaries.

### Key Concepts:
* **Allowed Hosts & Ports**: Prevents unauthorized traffic or accidental third-party scans.
* **Testing Capabilities Flags**: Requires explicit opt-in for `activeScanning`, `loadTesting`, or `chaosTesting`.
* **Limits**: Enforces safety clamps (`maxRps`, `maxConcurrency`, `maxDuration`).

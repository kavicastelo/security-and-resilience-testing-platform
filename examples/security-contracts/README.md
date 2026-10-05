# Example Security Contracts

## Responsibility
Contains declarative security contracts representing binding security commitments for microservices and APIs.

### Purpose:
* Shift security left by validating API contracts in CI pipelines before deployment.
* Prevent regression of critical controls (e.g. accidental removal of HSTS or leaking framework versions in response headers).

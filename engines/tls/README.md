# Engine: TLS & Cryptography (Class A Native)

## Responsibility
In-process native engine for inspecting transport layer security configurations, cipher suites, certificate validity, and protocol versions.

### What belongs here:
* TestEngine inspecting TLS handshake parameters using Node.js `tls` socket APIs.
* Enforcing TLS 1.2+ minimum version requirements.
* Checking certificate expiration, issuer trust, and hostname matching.
* Deprecated cipher suite detection (e.g. RC4, 3DES, CBC mode ciphers).

### What does NOT belong here:
* Man-in-the-middle proxy interception or CA private key operations.

### Execution Class:
* **Class A (Native In-Process)**: Direct TLS handshake socket inspections.

### Implementation Status:
* **Status**: SCAFFOLDED (Interface boundary defined in `@security-lab/test-sdk`)
* **Planned Phase**: Phase 2 (Native Test Engines & Scanners)

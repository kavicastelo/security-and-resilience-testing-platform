# Security & Defensive Architecture

## 1. Authorization & Legal Notice

> [!IMPORTANT]
> **Authorized Testing Notice**:
> Security Lab is engineered strictly for authorized security QA and resilience validation of applications, APIs, and infrastructure owned or explicitly authorized by the operator.
> Testing systems without prior mutual written consent is illegal and strictly prohibited. The platform enforces strict target scope boundaries and defensive safety controls.

---

## 2. Defensive Controls Architecture

To ensure the platform operates within safe, authorized boundaries, Security Lab implements multi-layer defense-in-depth:

1. **Target Scope Verification**: Outbound HTTP traffic is restricted strictly to pre-registered targets and allowed domains. Probing private RFC 1918 subnets, cloud metadata (`169.254.169.254`), or loopback addresses is blocked by default.
2. **Explicit Opt-in for Active Testing**: Destructive probes, heavy fuzzing, and load generation cannot execute unless explicitly enabled on target configurations.
3. **Forensic Evidence Immutability**: All evidence collected during testing is serialized using RFC 8785 canonical JSON and sealed with SHA-256 digests.
4. **Least-Privilege Container Sandboxing**: External scanner containers (OWASP ZAP, Aqua Trivy, Grafana k6) execute without root privileges (`--user 10001:10001`), with dropped capabilities (`--cap-drop=ALL`), read-only root filesystems, and temporary scratch directory mounts.

---

## 3. Security Documentation Library

| Specification | Document Path | Focus Area |
| :--- | :--- | :--- |
| **Security Boundaries & Defensive Controls** | [security-boundary.md](security-boundary.md) | Multi-layer SSRF shielding, IP canonicalization, DNS rebinding prevention, redirect interception, and container sandboxing flags. |
| **Security Model & Trust Architecture** | [security-model.md](security-model.md) | Trust boundary matrix (TB-01 to TB-11), two-tier key hierarchy (TEK), tenant isolation, result attestation signatures, and Docker host security. |
| **Platform Threat Model** | [threat-model.md](threat-model.md) | Comprehensive STRIDE threat model evaluating 18 critical attack scenarios (T1–T18) across the control plane and distributed agents. |

---

## 4. Responsible Disclosure

If you discover a security vulnerability within Security Lab itself, please report it via our responsible disclosure process:
* **Email**: `security@securitylab.internal` (or submit a confidential vulnerability report on GitHub).
* **PGP Key**: Encrypt reports containing proof-of-concept exploits.
* **SLA**: Our security team acknowledges all reports within 24 business hours and aims to issue remediations within 72 hours for critical vulnerabilities.

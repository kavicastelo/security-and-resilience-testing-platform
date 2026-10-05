# Security Policy & Defensive Engineering

## 1. Authorization & Legal Notice

> **IMPORTANT**: This project is designed for authorized security testing of applications and infrastructure owned or explicitly authorized by the operator.
> Testing systems without prior mutual written consent is illegal and strictly prohibited.

---

## 2. Defensive Controls Architecture

To ensure the platform operates within safe, authorized boundaries:
1. **Target Scope Verification**: Outbound HTTP traffic is restricted to pre-registered targets and allowed domains.
2. **Explicit Opt-in for Active Scanning**: Destructive probes or fuzzing cannot execute unless explicitly enabled on target configurations.
3. **Forensic Evidence Immutability**: All evidence collected during testing is sealed with SHA-256 hashes to prevent post-incident tampering.
4. **Least-Privilege Containers**: External runner containers execute without root privileges or host system access.

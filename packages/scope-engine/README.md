# Scope Engine (`@security-lab/scope-engine`)

The Scope Engine provides deterministic pre-socket DNS pinning, anti-SSRF verification, CIDR boundary validation, and target scope enforcement for the Security & Resilience Testing Platform.

---

## 1. Architectural Mission

When executing automated security scans, fuzzing, and resilience testing, the platform must never be manipulated into scanning unauthorized targets or attacking internal cloud infrastructure.

### The Threat: TOCTOU DNS Rebinding
In a Time-of-Check to Time-of-Use (TOCTOU) DNS rebinding attack:
1. An attacker registers `malicious.example.com` resolving to a benign public IP (e.g. `203.0.113.10`).
2. The initial scope validation passes because `203.0.113.10` is an authorized public IP.
3. During execution, the attacker updates their authoritative DNS server to resolve `malicious.example.com` to `169.254.169.254` (cloud metadata service) or `10.0.0.1` (internal database).
4. Standard HTTP clients re-resolve the domain at connect time, causing the scanner to exfiltrate cloud credentials or attack internal VPC infrastructure.

---

## 2. Pre-Socket DNS Pinning Defense

The Scope Engine defeats DNS rebinding via:
1. **Immediate Pre-Socket Resolution**: Hooks directly into the Node.js networking layer (`net.Socket`, `http.Agent`, `https.Agent`).
2. **Strict Range Filtering**:
   - Cloud metadata (`169.254.169.254`, `fd00:ec2::254`, `metadata.google.internal`) is unconditionally prohibited.
   - Link-local (`169.254.0.0/16`, `fe80::/10`) is unconditionally prohibited.
   - Loopback (`127.0.0.0/8`, `::1`) is rejected unless `localhost` / `127.0.0.1` is explicitly authorized.
   - Private RFC 1918 subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`) are blocked unless `allowPrivateIps: true` is explicitly opted into.
3. **Session-Scoped IP Pinning**: The first verified IP is pinned in `DnsPinningCache`. Subsequent socket connections reuse the verified IP directly, completely isolating the test engine from DNS modifications.
4. **Pre-Socket Abort**: If any resolved IP belongs to a prohibited range, the connection is aborted immediately before the TCP SYN packet is transmitted.

---

## 3. Usage Example

```typescript
import { createSecureHttpAgent, createSecureHttpsAgent, TargetScope } from '@security-lab/scope-engine';
import http from 'node:http';

const scope: TargetScope = {
  allowedHosts: ['api.example.com'],
  allowedPorts: [80, 443],
  excludedPaths: ['/billing'],
  testing: { activeScanning: true, loadTesting: false, chaosTesting: false },
  limits: { maxRps: 50, maxConcurrency: 5, maxDuration: '5m' },
  allowPrivateIps: false,
};

// Create hardened HTTP agents hooked with DNS pinning
const httpAgent = createSecureHttpAgent(scope);
const httpsAgent = createSecureHttpsAgent(scope);

const req = http.request('http://api.example.com/health', { agent: httpAgent }, (res) => {
  console.log('Connected to verified, pinned target:', res.statusCode);
});

req.on('error', (err) => {
  if (err.name === 'DnsPinningError') {
    console.error('DNS Rebinding or SSRF attempt blocked before socket connection:', err.message);
  }
});

req.end();
```

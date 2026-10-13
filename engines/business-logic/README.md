# @security-lab/business-logic

## Overview
The `engine-business-logic` is a Class A Native execution engine conforming to `@security-lab/engine-sdk`. It automates the discovery and verification of complex application business logic vulnerabilities that cannot be identified through traditional static analysis or generic injection fuzzing.

Specifically, it provides:
1. **Workflow State Machine Modeling & Step-Skipping Detection**: Validates multi-step business pipelines (such as e-commerce checkout, KYC onboarding, multi-stage approval) by systematically generating non-linear and illegal state transitions, identifying endpoints that allow skipping mandatory intermediate steps (e.g. bypassing payment to fulfill orders).
2. **Synchronized HTTP/1.1 Socket Burst (Single-Packet Concurrency Testing)**: Pre-warms 10–30 raw TCP/TLS sockets to the target, transmits all HTTP headers while holding back the final payload byte, and releases the final byte simultaneously at a millisecond barrier to exploit Time-of-Check to Time-of-Use (TOCTOU) race conditions (such as double-spending gift cards, replaying one-time coupons, or bypassing transfer rate limits).
3. **Financial Parameter Tampering & Negative Value Fuzzing**: Fuzzes numerical, quantity, discount, fee, and pricing parameters with zero, negative values (`-1`, `-999999`), integer overflows (`2147483648`, `9223372036854775807`), and fractional amounts to identify accounting bypasses and negative balance generation.

---

## Architectural Guarantees & Safety Invariants
- **Local-First & In-Memory**: Operates purely within Node.js without requiring external proxy binaries (e.g., Turbo Intruder, Burp Suite, or mitmproxy).
- **Socket Safety Ceiling (Rule 13)**: Hard-caps concurrency to a maximum of 30 sockets per burst test to prevent accidental target Denial of Service.
- **Microsecond Jitter Observability**: Measures and logs the exact network arrival jitter spread across all socket responses.
- **Evidence Redaction (Rule 4)**: Automatically redacts all sensitive headers (`Authorization`, `Cookie`, `X-Api-Key`) in finding evidence payloads using `@security-lab/crypto`.
- **Worker Sandboxing (Phase 03)**: Fully compatible with isolated V8 worker thread execution with CPU, memory, and timeout constraints.

---

## Capabilities
- `business_logic_state_bypass`: Automated step-skipping and workflow state transition invariant evaluation.
- `race_condition_burst`: Synchronized socket burst and TOCTOU concurrency race condition testing.
- `parameter_tampering`: Financial parameter tampering and negative value logic fuzzing.

---

## Usage Example

```typescript
import { businessLogicEngine } from '@security-lab/business-logic';

const result = await businessLogicEngine.execute(
  {
    targetUrl: 'https://api.example.com',
    options: {
      raceConditions: [
        {
          id: 'coupon-race',
          name: 'Redeem Gift Card Concurrency Test',
          endpointPath: '/api/v1/giftcards/redeem',
          method: 'POST',
          body: { code: 'GIFT-2026' },
          concurrency: 20,
          expectedMaxSuccessCount: 1,
        },
      ],
      tamperTests: [
        {
          id: 'cart-tamper',
          name: 'Cart Item Negative Quantity Fuzzing',
          endpointPath: '/api/v1/cart/items',
          method: 'POST',
          baseBody: { itemId: 'sku-100', quantity: 1, unitPrice: 50 },
          parameters: [
            { fieldName: 'quantity', targetType: 'quantity', location: 'body' },
          ],
        },
      ],
    },
  },
  context,
);
```

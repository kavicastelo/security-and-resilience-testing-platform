import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import http from 'http';
import {
  businessLogicEngine,
  executeSynchronizedBurst,
  evaluateWorkflowStateBypass,
  evaluateParameterTampering,
  WorkflowDefinition,
  RaceConditionTest,
} from '../src/index.js';
import { executeSandboxedEngine } from '@security-lab/test-runner';
import { REDACTED_VALUE } from '@security-lab/crypto';

describe('BusinessLogicEngine & Race Condition Suite', () => {
  let server: http.Server;
  let serverPort: number;
  let serverBaseUrl: string;

  // Mock State
  let couponRedemptionCount = 0;
  const validCouponCode = 'PROMO-2026';
  const cartSessions = new Map<string, { paid: boolean; items: any[]; fulfilled: boolean }>();

  beforeAll(async () => {
    server = http.createServer(async (req, res) => {
      const url = new URL(req.url || '/', `http://127.0.0.1`);
      const method = req.method || 'GET';

      // Read request body
      let bodyText = '';
      for await (const chunk of req) {
        bodyText += chunk;
      }
      let body: any = {};
      try {
        if (bodyText) body = JSON.parse(bodyText);
      } catch {
        // Non-JSON
      }

      // 1. Race Condition Target: Vulnerable Coupon Redemption (TOCTOU Window)
      if (method === 'POST' && url.pathname === '/api/coupon/redeem-vulnerable') {
        const coupon = body?.couponCode;
        if (coupon !== validCouponCode) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Invalid coupon' }));
          return;
        }

        // Deliberate TOCTOU concurrency race window: Check before increment
        if (couponRedemptionCount === 0) {
          // Micro-delay simulating DB query latency
          await new Promise((resolve) => setTimeout(resolve, 15));
          couponRedemptionCount++;
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: true, reward: 100, count: couponRedemptionCount }));
          return;
        }

        res.writeHead(409, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Coupon already redeemed' }));
        return;
      }

      // 2. Race Condition Target: Safe Mutex Protected Coupon Redemption
      if (method === 'POST' && url.pathname === '/api/coupon/redeem-safe') {
        const coupon = body?.couponCode;
        if (coupon !== validCouponCode) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Invalid coupon' }));
          return;
        }

        // Atomic check and increment without window
        if (couponRedemptionCount === 0) {
          couponRedemptionCount++;
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: true, reward: 100 }));
          return;
        }

        res.writeHead(409, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Coupon already redeemed' }));
        return;
      }

      // 3. Workflow State Machine Target: E-Commerce Cart & Checkout
      if (method === 'POST' && url.pathname === '/api/cart/init') {
        const cartId = 'cart-' + Math.random().toString(36).substring(2, 9);
        cartSessions.set(cartId, { paid: false, items: [], fulfilled: false });
        res.writeHead(200, {
          'Content-Type': 'application/json',
          'Set-Cookie': `cart_id=${cartId}; Path=/`,
        });
        res.end(JSON.stringify({ cartId, status: 'initialized' }));
        return;
      }

      if (method === 'POST' && url.pathname === '/api/cart/items') {
        // Parameter Tampering test hook
        if (typeof body?.quantity === 'number' && body.quantity < 0) {
          // Vulnerable logic: accepts negative quantity and calculates negative invoice total!
          const unitPrice = body.unitPrice || 20;
          const total = body.quantity * unitPrice;
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: true, itemsCount: body.quantity, total }));
          return;
        }

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, itemsCount: body?.quantity || 1 }));
        return;
      }

      if (method === 'POST' && url.pathname === '/api/cart/coupon') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, discount: 20 }));
        return;
      }

      if (method === 'POST' && url.pathname === '/api/cart/pay') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ paymentId: 'pay-xyz-999', status: 'paid' }));
        return;
      }

      // Vulnerable Fulfillment: Fulfills order WITHOUT verifying payment step!
      if (method === 'POST' && url.pathname === '/api/cart/fulfill') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ orderId: 'ord-8888', status: 'shipped_free' }));
        return;
      }

      // Safe Parameter Validation Endpoint
      if (method === 'POST' && url.pathname === '/api/safe-billing/items') {
        const qty = body?.quantity;
        if (typeof qty !== 'number' || qty <= 0 || qty > 1000 || !Number.isInteger(qty)) {
          res.writeHead(422, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Quantity must be strictly positive integer <= 1000' }));
          return;
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true }));
        return;
      }

      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Route not found' }));
    });

    await new Promise<void>((resolve) => {
      server.listen(0, '127.0.0.1', () => {
        const addr = server.address() as any;
        serverPort = addr.port;
        serverBaseUrl = `http://127.0.0.1:${serverPort}`;
        resolve();
      });
    });
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it('declares valid engine metadata and capabilities', () => {
    expect(businessLogicEngine.id).toBe('engine-business-logic');
    expect(businessLogicEngine.version).toBe('1.0.0');
    expect(businessLogicEngine.executionClass).toBe('class_a_native');

    const capabilities = businessLogicEngine.capabilities();
    expect(capabilities.length).toBe(3);
    expect(capabilities.map((c) => c.id)).toContain('business_logic_state_bypass');
    expect(capabilities.map((c) => c.id)).toContain('race_condition_burst');
    expect(capabilities.map((c) => c.id)).toContain('parameter_tampering');
  });

  it('validates target URL protocol format', () => {
    const validRes = businessLogicEngine.validate({
      targetUrl: serverBaseUrl,
      options: {},
    });
    expect(validRes.valid).toBe(true);

    const invalidRes = businessLogicEngine.validate({
      targetUrl: 'ftp://not-supported',
      options: {},
    });
    expect(invalidRes.valid).toBe(false);
  });

  it('triggers and detects concurrency race condition on vulnerable endpoint using synchronized socket burst', async () => {
    couponRedemptionCount = 0;

    const testDef: RaceConditionTest = {
      id: 'race-coupon-test',
      name: 'Single-Packet Coupon Race Test',
      endpointPath: '/api/coupon/redeem-vulnerable',
      method: 'POST',
      body: { couponCode: validCouponCode },
      concurrency: 10,
      expectedMaxSuccessCount: 1,
    };

    const burstResult = await executeSynchronizedBurst(serverBaseUrl, testDef);

    expect(burstResult.testId).toBe('race-coupon-test');
    expect(burstResult.concurrency).toBe(10);
    // With deliberate TOCTOU window and single-packet barrier, multiple requests succeed
    expect(burstResult.successfulResponses).toBeGreaterThan(1);
    expect(burstResult.isVulnerable).toBe(true);
    expect(burstResult.details).toContain('Race condition detected');
    expect(typeof burstResult.jitterSpreadMs).toBe('number');
  });

  it('asserts zero false positives when endpoint correctly prevents race conditions', async () => {
    couponRedemptionCount = 0;

    const safeTestDef: RaceConditionTest = {
      id: 'safe-coupon-test',
      name: 'Safe Mutex Coupon Test',
      endpointPath: '/api/coupon/redeem-safe',
      method: 'POST',
      body: { couponCode: validCouponCode },
      concurrency: 8,
      expectedMaxSuccessCount: 1,
    };

    const burstResult = await executeSynchronizedBurst(serverBaseUrl, safeTestDef);
    expect(burstResult.successfulResponses).toBe(1);
    expect(burstResult.isVulnerable).toBe(false);
  });

  it('detects step-skipping state bypass in multi-step e-commerce workflow', async () => {
    const workflow: WorkflowDefinition = {
      id: 'wf-checkout-test',
      name: 'Test Checkout Flow',
      initialStepId: 'step-1',
      terminalStepIds: ['step-3'],
      steps: [
        {
          id: 'step-1',
          name: 'Init Cart',
          method: 'POST',
          path: '/api/cart/init',
          order: 1,
          expectedStatus: 200,
        },
        {
          id: 'step-2',
          name: 'Payment Step',
          method: 'POST',
          path: '/api/cart/pay',
          order: 2,
          isPaymentOrTerminal: true,
          expectedStatus: 200,
        },
        {
          id: 'step-3',
          name: 'Fulfill Order',
          method: 'POST',
          path: '/api/cart/fulfill',
          order: 3,
          isPaymentOrTerminal: true,
          expectedStatus: 200,
        },
      ],
    };

    const violations = await evaluateWorkflowStateBypass(serverBaseUrl, workflow);
    expect(violations.length).toBeGreaterThan(0);
    const v = violations[0]!;
    expect(v.isViolation).toBe(true);
    expect(v.fromStep.name).toBe('Init Cart');
    expect(v.toStep.name).toBe('Fulfill Order');
    expect(v.skippedSteps.map((s) => s.name)).toContain('Payment Step');
    expect(v.actualStatusCode).toBe(200);
  });

  it('identifies financial parameter tampering with negative quantities', async () => {
    const tamperViolations = await evaluateParameterTampering(serverBaseUrl, {
      id: 'tamper-test',
      name: 'Cart Tamper Test',
      endpointPath: '/api/cart/items',
      method: 'POST',
      baseBody: { productId: 'p1', quantity: 1, unitPrice: 20 },
      parameters: [{ fieldName: 'quantity', targetType: 'quantity', location: 'body' }],
    });

    expect(tamperViolations.length).toBeGreaterThan(0);
    const violation = tamperViolations[0]!;
    expect(violation.isViolation).toBe(true);
    expect(violation.parameterName).toBe('quantity');
    expect(violation.tamperedValue).toBe(-1);
    expect(violation.reason).toContain('negative balance/total calculation');
  });

  it('does not flag parameter tampering when server returns 422 Unprocessable Entity', async () => {
    const safeViolations = await evaluateParameterTampering(serverBaseUrl, {
      id: 'safe-tamper-test',
      name: 'Safe Tamper Test',
      endpointPath: '/api/safe-billing/items',
      method: 'POST',
      baseBody: { quantity: 1 },
      parameters: [{ fieldName: 'quantity', targetType: 'quantity', location: 'body' }],
    });

    expect(safeViolations.length).toBe(0);
  });

  it('runs complete engine execution and produces valid findings conforming to contracts', async () => {
    couponRedemptionCount = 0;

    const result = await businessLogicEngine.execute(
      {
        targetUrl: serverBaseUrl,
        options: {
          raceConditions: [
            {
              id: 'race-coupon',
              name: 'Coupon TOCTOU Test',
              endpointPath: '/api/coupon/redeem-vulnerable',
              method: 'POST',
              body: { couponCode: validCouponCode },
              concurrency: 6,
              expectedMaxSuccessCount: 1,
            },
          ],
          tamperTests: [
            {
              id: 'tamper-cart',
              name: 'Negative Quantity Test',
              endpointPath: '/api/cart/items',
              method: 'POST',
              baseBody: { productId: 'test-item', quantity: 1, unitPrice: 25 },
              parameters: [{ fieldName: 'quantity', targetType: 'quantity', location: 'body' }],
            },
          ],
        },
      },
      {
        runId: 'run-bl-1',
        engineId: 'engine-business-logic',
        target: {
          id: 'target-1',
          url: serverBaseUrl,
        },
      },
    );

    expect(result.success).toBe(true);
    expect(result.engineId).toBe('engine-business-logic');
    expect(result.findings.length).toBeGreaterThanOrEqual(2);

    const raceFinding = result.findings.find((f) => f.title.includes('Concurrency Race Condition'));
    expect(raceFinding).toBeDefined();
    expect(raceFinding?.severity).toBe('critical');

    const tamperFinding = result.findings.find((f) => f.title.includes('Parameter Tampering'));
    expect(tamperFinding).toBeDefined();
    expect(tamperFinding?.severity).toBe('high');

    // Rule 4: Verify sensitive headers in finding evidence are redacted
    for (const f of result.findings) {
      if (f.evidence?.request?.headers) {
        for (const [k, v] of Object.entries(f.evidence.request.headers)) {
          if (['authorization', 'cookie', 'x-api-key'].includes(k.toLowerCase())) {
            expect(v).toBe(REDACTED_VALUE);
          }
        }
      }
    }
  });

  it('executes cleanly in worker thread via executeSandboxedEngine', async () => {
    couponRedemptionCount = 0;

    const workerResult = await executeSandboxedEngine(
      'engine-business-logic',
      {
        targetUrl: serverBaseUrl,
        options: {
          autoDiscoverCommonPatterns: false,
          raceConditions: [
            {
              id: 'worker-race-test',
              name: 'Worker Race Test',
              endpointPath: '/api/coupon/redeem-vulnerable',
              method: 'POST',
              body: { couponCode: validCouponCode },
              concurrency: 5,
              expectedMaxSuccessCount: 1,
            },
          ],
        },
      },
      {
        runId: 'run-worker-bl',
        engineId: 'engine-business-logic',
        target: {
          id: 'target-worker-bl',
          url: serverBaseUrl,
        },
      },
      {
        timeoutMs: 15000,
      },
    );

    expect(workerResult.success).toBe(true);
    expect(workerResult.engineId).toBe('engine-business-logic');
    expect(workerResult.findings.length).toBeGreaterThan(0);
  });
});

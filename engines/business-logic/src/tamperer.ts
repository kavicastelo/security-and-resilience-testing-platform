import { URL } from 'url';
import { safeFetch } from '@security-lab/engine-sdk';
import { TargetScope } from '@security-lab/domain';
import { createLogger } from '@security-lab/logger';
import {
  ParameterTamperTest,
  TamperViolation,
} from './types.js';

const logger = createLogger({ name: 'engine-tamperer' });

export const NUMERIC_TAMPER_PAYLOADS = [
  { value: -1, label: 'Negative Unit (-1)' },
  { value: -100, label: 'Large Negative Value (-100)' },
  { value: -999999, label: 'Extreme Negative Value (-999999)' },
  { value: 0, label: 'Zero Quantity/Price (0)' },
  { value: 2147483648, label: '32-Bit Integer Overflow (2147483648)' },
  { value: Number.MAX_SAFE_INTEGER, label: 'Max Safe Integer (9007199254740991)' },
  { value: 0.000001, label: 'Sub-Cent Fractional Rounding (0.000001)' },
];

export const DEFAULT_TAMPER_TESTS: ParameterTamperTest[] = [
  {
    id: 'tamper-cart-item-quantity',
    name: 'Cart Item Quantity Tampering',
    endpointPath: '/api/cart/items',
    method: 'POST',
    baseBody: { productId: 'item-prod-1', quantity: 1, unitPrice: 20 },
    parameters: [
      { fieldName: 'quantity', targetType: 'quantity', location: 'body' },
      { fieldName: 'unitPrice', targetType: 'price', location: 'body' },
    ],
  },
  {
    id: 'tamper-order-discount',
    name: 'Order Discount & Fee Tampering',
    endpointPath: '/api/cart/apply-coupon',
    method: 'POST',
    baseBody: { couponCode: 'DISCOUNT', discountAmount: 10 },
    parameters: [
      { fieldName: 'discountAmount', targetType: 'discount', location: 'body' },
    ],
  },
];

export async function evaluateParameterTampering(
  targetBaseUrl: string,
  test: ParameterTamperTest,
  scope?: TargetScope,
  timeoutMs: number = 10000,
): Promise<TamperViolation[]> {
  const violations: TamperViolation[] = [];
  const fullUrl = new URL(test.endpointPath, targetBaseUrl).toString();

  for (const param of test.parameters) {
    const payloads = param.payloadValues
      ? param.payloadValues.map((v) => ({ value: v, label: `Custom Value (${v})` }))
      : NUMERIC_TAMPER_PAYLOADS;

    for (const payloadItem of payloads) {
      const tamperedBody = { ...test.baseBody };
      let tamperedUrl = fullUrl;

      if (param.location === 'body') {
        tamperedBody[param.fieldName] = payloadItem.value;
      } else if (param.location === 'query') {
        const u = new URL(fullUrl);
        u.searchParams.set(param.fieldName, String(payloadItem.value));
        tamperedUrl = u.toString();
      }

      const reqHeaders: Record<string, string> = {
        'Content-Type': 'application/json',
        Accept: 'application/json',
        ...(test.headers || {}),
      };

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);

      try {
        const res = await safeFetch(tamperedUrl, {
          method: test.method,
          headers: reqHeaders,
          body: JSON.stringify(tamperedBody),
          scope,
          signal: controller.signal,
        });
        clearTimeout(timer);

        const respHeaders: Record<string, string> = {};
        res.headers.forEach((v, k) => {
          respHeaders[k.toLowerCase()] = v;
        });
        const bodyText = await res.text().catch(() => '');

        // Check if server accepted the unhandled negative/overflow value
        // If HTTP status is 200, 201, 204 or body indicates success/order calculation without 4xx
        if (res.status >= 200 && res.status < 300) {
          let hasNegativeCalculation = false;
          try {
            const parsed = JSON.parse(bodyText);
            const total = parsed.total ?? parsed.totalAmount ?? parsed.price ?? parsed.amount;
            if (typeof total === 'number' && total < 0) {
              hasNegativeCalculation = true;
            }
          } catch {
            // Non-JSON
          }

          const isNegative = typeof payloadItem.value === 'number' && payloadItem.value < 0;
          const violationDetail = hasNegativeCalculation
            ? `Parameter "${param.fieldName}" tampered with ${payloadItem.label} resulted in negative balance/total calculation in response.`
            : `Endpoint accepted tampered parameter "${param.fieldName}" with ${payloadItem.label} returning HTTP ${res.status} OK instead of client validation error (400/422).`;

          logger.warn(
            {
              testId: test.id,
              parameter: param.fieldName,
              value: payloadItem.value,
              status: res.status,
            },
            'Parameter tampering vulnerability detected!',
          );

          violations.push({
            testId: test.id,
            testName: test.name,
            endpoint: test.endpointPath,
            method: test.method,
            parameterName: param.fieldName,
            tamperedValue: payloadItem.value,
            actualStatusCode: res.status,
            responseBody: bodyText,
            responseHeaders: respHeaders,
            requestPayload: tamperedBody,
            isViolation: true,
            reason: violationDetail,
          });

          // Break to next parameter to avoid overwhelming with redundant findings for the same param
          if (isNegative) break;
        }
      } catch (_err: any) {
        clearTimeout(timer);
        // Connection error or fetch rejected
      }
    }
  }

  return violations;
}

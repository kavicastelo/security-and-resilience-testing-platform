import { URL } from 'url';
import { safeFetch } from '@security-lab/engine-sdk';
import { TargetScope } from '@security-lab/domain';
import { createLogger } from '@security-lab/logger';
import {
  WorkflowDefinition,
  WorkflowStep,
  StateTransitionViolation,
} from './types.js';

const logger = createLogger({ name: 'engine-state-graph' });

export const DEFAULT_CHECKOUT_WORKFLOW: WorkflowDefinition = {
  id: 'workflow-checkout-ecommerce',
  name: 'Standard E-Commerce Order & Payment Workflow',
  description: 'Multi-step cart creation, item addition, payment, and fulfillment pipeline',
  initialStepId: 'step-cart-init',
  terminalStepIds: ['step-order-fulfill'],
  steps: [
    {
      id: 'step-cart-init',
      name: 'Initialize Cart Session',
      method: 'POST',
      path: '/api/cart/init',
      order: 1,
      expectedStatus: 200,
      isPrivileged: false,
      isPaymentOrTerminal: false,
      extractVariables: [{ name: 'cartId', path: 'cartId' }],
    },
    {
      id: 'step-add-item',
      name: 'Add Item to Cart',
      method: 'POST',
      path: '/api/cart/items',
      body: { productId: 'item-101', quantity: 1, unitPrice: 25 },
      order: 2,
      expectedStatus: 200,
      isPrivileged: false,
      isPaymentOrTerminal: false,
    },
    {
      id: 'step-apply-coupon',
      name: 'Apply Promo Coupon',
      method: 'POST',
      path: '/api/cart/coupon',
      body: { couponCode: 'SAVE20' },
      order: 3,
      expectedStatus: 200,
      isPrivileged: false,
      isPaymentOrTerminal: false,
    },
    {
      id: 'step-payment',
      name: 'Process Order Payment',
      method: 'POST',
      path: '/api/cart/pay',
      body: { paymentMethod: 'card_nonce_test', amount: 20 },
      isPrivileged: false,
      isPaymentOrTerminal: true,
      order: 4,
      expectedStatus: 200,
      extractVariables: [{ name: 'paymentId', path: 'paymentId' }],
    },
    {
      id: 'step-order-fulfill',
      name: 'Fulfill & Dispatch Order',
      method: 'POST',
      path: '/api/cart/fulfill',
      body: { deliveryAddress: '123 Security Blvd' },
      isPrivileged: false,
      isPaymentOrTerminal: true,
      order: 5,
      expectedStatus: 200,
    },
  ],
};

export interface WorkflowExecutionContext {
  variables: Record<string, string>;
  cookies: Record<string, string>;
  headers: Record<string, string>;
}

export function substituteVariables(
  template: string,
  variables: Record<string, string>,
): string {
  let result = template;
  for (const [key, val] of Object.entries(variables)) {
    result = result.replaceAll(`{${key}}`, String(val));
    result = result.replaceAll(`:${key}`, String(val));
  }
  return result;
}

export function extractVariableFromData(data: any, path: string): string | undefined {
  if (!data) return undefined;
  if (typeof data !== 'object') return String(data);

  // Direct key lookup
  if (data[path] !== undefined) return String(data[path]);

  // Nested dot navigation
  const parts = path.split('.');
  let current = data;
  for (const p of parts) {
    if (current && typeof current === 'object' && p in current) {
      current = current[p];
    } else {
      return undefined;
    }
  }
  return current !== undefined ? String(current) : undefined;
}

/**
 * Executes a single workflow step against target URL with variable substitution & cookie persistence.
 */
export async function executeWorkflowStep(
  targetBaseUrl: string,
  step: WorkflowStep,
  ctx: WorkflowExecutionContext,
  scope?: TargetScope,
  timeoutMs: number = 10000,
): Promise<{
  statusCode: number;
  body: string;
  headers: Record<string, string>;
  parsedJson?: any;
}> {
  const resolvedPath = substituteVariables(step.path, ctx.variables);
  const targetUrl = new URL(resolvedPath, targetBaseUrl).toString();

  const reqHeaders: Record<string, string> = {
    Accept: 'application/json',
    'Content-Type': 'application/json',
    ...(step.headers || {}),
    ...ctx.headers,
  };

  // Add cookies
  const cookieEntries = Object.entries(ctx.cookies);
  if (cookieEntries.length > 0) {
    reqHeaders['Cookie'] = cookieEntries.map(([k, v]) => `${k}=${v}`).join('; ');
  }

  let bodyStr: string | undefined = undefined;
  if (step.body !== undefined) {
    if (typeof step.body === 'string') {
      bodyStr = substituteVariables(step.body, ctx.variables);
    } else {
      bodyStr = substituteVariables(JSON.stringify(step.body), ctx.variables);
    }
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await safeFetch(targetUrl, {
      method: step.method,
      headers: reqHeaders,
      body: bodyStr,
      scope,
      signal: controller.signal,
    });
    clearTimeout(timer);

    const respHeaders: Record<string, string> = {};
    res.headers.forEach((v, k) => {
      respHeaders[k.toLowerCase()] = v;
    });

    // Capture cookies
    const setCookie = respHeaders['set-cookie'];
    if (setCookie) {
      const parts = setCookie.split(';')[0];
      if (parts) {
        const [cName, cVal] = parts.split('=');
        if (cName && cVal) ctx.cookies[cName.trim()] = cVal.trim();
      }
    }

    const bodyText = await res.text().catch(() => '');
    let parsedJson: any = undefined;
    try {
      parsedJson = JSON.parse(bodyText);
    } catch {
      // Non-json response
    }

    // Variable extraction
    if (step.extractVariables && parsedJson) {
      for (const ev of step.extractVariables) {
        const extracted = extractVariableFromData(parsedJson, ev.path);
        if (extracted) {
          ctx.variables[ev.name] = extracted;
        }
      }
    }

    return {
      statusCode: res.status,
      body: bodyText,
      headers: respHeaders,
      parsedJson,
    };
  } catch (err: any) {
    clearTimeout(timer);
    return {
      statusCode: 0,
      body: err.message || 'Fetch error',
      headers: {},
    };
  }
}

/**
 * Analyzes workflow state graph and generates test executions targeting illegal state transitions and step skipping.
 */
export async function evaluateWorkflowStateBypass(
  targetBaseUrl: string,
  workflow: WorkflowDefinition,
  scope?: TargetScope,
  timeoutMs: number = 10000,
): Promise<StateTransitionViolation[]> {
  const violations: StateTransitionViolation[] = [];
  const sortedSteps = [...workflow.steps].sort((a, b) => a.order - b.order);

  if (sortedSteps.length < 2) {
    return violations;
  }

  // 1. Identify step-skipping candidate pairs:
  // From step A (order i) to step B (order j) where j > i + 1.
  // Skipping intermediate steps: [i + 1 ... j - 1].
  for (let i = 0; i < sortedSteps.length; i++) {
    for (let j = i + 2; j < sortedSteps.length; j++) {
      const fromStep = sortedSteps[i];
      const toStep = sortedSteps[j];
      if (!fromStep || !toStep) continue;

      const skippedSteps = sortedSteps.slice(i + 1, j);

      // Check if this transition was explicitly allowed
      if (workflow.transitions) {
        const explicit = workflow.transitions.find(
          (t) => t.fromStepId === fromStep.id && t.toStepId === toStep.id,
        );
        if (explicit?.allowed) {
          continue; // Allowed transition, skip testing as violation
        }
      }

      logger.info(
        {
          workflow: workflow.name,
          from: fromStep.name,
          to: toStep.name,
          skipped: skippedSteps.map((s) => s.name),
        },
        'Testing illegal workflow state transition (step-skipping)',
      );

      // Create isolated execution context
      const ctx: WorkflowExecutionContext = {
        variables: {},
        cookies: {},
        headers: {},
      };

      // Execute prior steps up to fromStep
      let setupSuccess = true;
      for (let s = 0; s <= i; s++) {
        const currentSetupStep = sortedSteps[s];
        if (!currentSetupStep) continue;
        const res = await executeWorkflowStep(targetBaseUrl, currentSetupStep, ctx, scope, timeoutMs);
        if (res.statusCode < 200 || res.statusCode >= 300) {
          setupSuccess = false;
          break;
        }
      }

      if (!setupSuccess) {
        // Could not establish prerequisite state, cannot reliably test skip
        continue;
      }

      // Now ATTEMPT TO JUMP directly to toStep (skipping skippedSteps)
      const skipAttemptRes = await executeWorkflowStep(targetBaseUrl, toStep, ctx, scope, timeoutMs);

      // Check if server completed the illegal transition
      // If server returns 200, 201, 204 without 400/403/409/422, it allowed step-skipping!
      const isSuccess =
        skipAttemptRes.statusCode >= 200 && skipAttemptRes.statusCode < 300;

      const fullUrl = new URL(substituteVariables(toStep.path, ctx.variables), targetBaseUrl).toString();

      if (isSuccess) {
        const skippedNames = skippedSteps.map((s) => `"${s.name}"`).join(', ');
        const reason = `Step-skipping bypass detected in workflow "${workflow.name}": Step "${toStep.name}" succeeded with HTTP ${skipAttemptRes.statusCode} without executing mandatory prerequisite steps [${skippedNames}].`;

        logger.warn(
          {
            workflowId: workflow.id,
            fromStep: fromStep.name,
            toStep: toStep.name,
            statusCode: skipAttemptRes.statusCode,
          },
          'Workflow state machine bypass detected!',
        );

        violations.push({
          workflowId: workflow.id,
          workflowName: workflow.name,
          fromStep,
          toStep,
          skippedSteps,
          actualStatusCode: skipAttemptRes.statusCode,
          responseBody: skipAttemptRes.body,
          responseHeaders: skipAttemptRes.headers,
          requestUrl: fullUrl,
          requestMethod: toStep.method,
          isViolation: true,
          reason,
        });
      }
    }
  }

  return violations;
}

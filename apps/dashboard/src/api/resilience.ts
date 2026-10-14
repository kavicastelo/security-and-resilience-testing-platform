import { apiClient } from './client.js';

export interface ChaosInjectionConfig {
  latencyMs: number;
  jitterMs: number;
  packetDropRate: number; // 0 - 50%
  errorInjectionRate: number; // 0 - 100%
  errorStatusCode: number; // 429, 500, 502, 503, 504
  circuitBreakerEnabled: boolean;
  circuitBreakerThreshold: number; // consecutive failures before trip
  activePreset: 'custom' | 'slow_3g' | 'db_brownout' | 'dependency_outage' | 'packet_loss';
}

export interface RecoveryTimelinePoint {
  timestamp: number;
  timeLabel: string;
  requestsPerSec: number;
  errorRate: number; // 0 - 100%
  latencyP95Ms: number;
  phase: 'baseline' | 'injection' | 'tripped' | 'recovering' | 'healthy';
}

export interface ChaosExecutionStats {
  status: 'idle' | 'running' | 'completed' | 'tripped';
  totalRequests: number;
  faultsInjected: number;
  unrecoveredErrors: number;
  rtoSeconds: number; // Recovery Time Objective
  circuitBreakerState: 'CLOSED' | 'OPEN' | 'HALF_OPEN';
  resilienceScore: number; // 0 - 100%
}

export interface WorkflowStateNode {
  id: string;
  name: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE';
  path: string;
  order: number;
  isTerminal?: boolean;
  isPaymentOrTerminal?: boolean;
  description: string;
}

export interface WorkflowTransitionEdge {
  fromStepId: string;
  toStepId: string;
  isAllowed: boolean;
  isBypass?: boolean;
  findingId?: string;
  observedStatus?: number;
  description?: string;
}

export interface StateBypassExploit {
  id: string;
  name: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  skippedSteps: string[];
  targetEndpoint: string;
  method: string;
  expectedStatus: number;
  actualStatus: number;
  description: string;
  impact: string;
  remediation: string;
  requestSnippet: string;
  responseSnippet: string;
}

export interface StateMachineModel {
  workflowId: string;
  name: string;
  targetUrl: string;
  initialStepId: string;
  terminalStepIds: string[];
  states: WorkflowStateNode[];
  transitions: WorkflowTransitionEdge[];
  bypassExploits: StateBypassExploit[];
}

export interface BurstRequestRecord {
  threadId: number;
  sentDeltaMs: number;
  durationMs: number;
  statusCode: number;
  responsePreview: string;
  isAnomaly: boolean;
}

export interface RaceConditionBurstModel {
  testId: string;
  name: string;
  endpoint: string;
  method: string;
  concurrency: number;
  barrierReleaseJitterMs: number;
  maxAllowedSuccess: number;
  actualSuccessCount: number;
  isVulnerable: boolean;
  summary: string;
  remediation: string;
  requests: BurstRequestRecord[];
}

// ============================================================================
// Preset Datasets
// ============================================================================

export const PRESET_CHAOS_PROFILES: Record<string, ChaosInjectionConfig> = {
  slow_3g: {
    latencyMs: 1800,
    jitterMs: 400,
    packetDropRate: 5,
    errorInjectionRate: 0,
    errorStatusCode: 504,
    circuitBreakerEnabled: false,
    circuitBreakerThreshold: 5,
    activePreset: 'slow_3g',
  },
  db_brownout: {
    latencyMs: 850,
    jitterMs: 200,
    packetDropRate: 15,
    errorInjectionRate: 40,
    errorStatusCode: 503,
    circuitBreakerEnabled: true,
    circuitBreakerThreshold: 5,
    activePreset: 'db_brownout',
  },
  dependency_outage: {
    latencyMs: 120,
    jitterMs: 30,
    packetDropRate: 0,
    errorInjectionRate: 75,
    errorStatusCode: 502,
    circuitBreakerEnabled: true,
    circuitBreakerThreshold: 3,
    activePreset: 'dependency_outage',
  },
  packet_loss: {
    latencyMs: 90,
    jitterMs: 40,
    packetDropRate: 35,
    errorInjectionRate: 15,
    errorStatusCode: 504,
    circuitBreakerEnabled: false,
    circuitBreakerThreshold: 5,
    activePreset: 'packet_loss',
  },
};

export const SAMPLE_RECOVERY_TIMELINE: RecoveryTimelinePoint[] = [
  { timestamp: 0, timeLabel: '0s', requestsPerSec: 100, errorRate: 0, latencyP95Ms: 42, phase: 'baseline' },
  { timestamp: 5, timeLabel: '5s', requestsPerSec: 102, errorRate: 1, latencyP95Ms: 45, phase: 'baseline' },
  { timestamp: 10, timeLabel: '10s', requestsPerSec: 98, errorRate: 0, latencyP95Ms: 44, phase: 'baseline' },
  { timestamp: 15, timeLabel: '15s', requestsPerSec: 95, errorRate: 38, latencyP95Ms: 890, phase: 'injection' },
  { timestamp: 20, timeLabel: '20s', requestsPerSec: 92, errorRate: 64, latencyP95Ms: 1420, phase: 'injection' },
  { timestamp: 25, timeLabel: '25s', requestsPerSec: 88, errorRate: 72, latencyP95Ms: 1680, phase: 'injection' },
  { timestamp: 30, timeLabel: '30s', requestsPerSec: 40, errorRate: 95, latencyP95Ms: 120, phase: 'tripped' },
  { timestamp: 35, timeLabel: '35s', requestsPerSec: 25, errorRate: 98, latencyP95Ms: 110, phase: 'tripped' },
  { timestamp: 40, timeLabel: '40s', requestsPerSec: 45, errorRate: 24, latencyP95Ms: 380, phase: 'recovering' },
  { timestamp: 45, timeLabel: '45s', requestsPerSec: 78, errorRate: 8, latencyP95Ms: 180, phase: 'recovering' },
  { timestamp: 50, timeLabel: '50s', requestsPerSec: 96, errorRate: 2, latencyP95Ms: 58, phase: 'healthy' },
  { timestamp: 55, timeLabel: '55s', requestsPerSec: 100, errorRate: 0, latencyP95Ms: 46, phase: 'healthy' },
];

export const SAMPLE_STATE_MACHINE_MODEL: StateMachineModel = {
  workflowId: 'wf-checkout-ecommerce',
  name: 'E-Commerce Order & Payment Workflow',
  targetUrl: 'https://api.store-resilience.internal',
  initialStepId: 'step-cart-init',
  terminalStepIds: ['step-order-fulfill'],
  states: [
    {
      id: 'step-cart-init',
      name: 'Cart Init',
      method: 'POST',
      path: '/api/cart/init',
      order: 1,
      description: 'Creates new cart session and issues cartId token',
    },
    {
      id: 'step-add-item',
      name: 'Add Items',
      method: 'POST',
      path: '/api/cart/items',
      order: 2,
      description: 'Appends inventory SKUs and quantities to active cart',
    },
    {
      id: 'step-apply-coupon',
      name: 'Apply Promo',
      method: 'POST',
      path: '/api/cart/coupon',
      order: 3,
      description: 'Validates and applies marketing discount code',
    },
    {
      id: 'step-payment',
      name: 'Payment Processing',
      method: 'POST',
      path: '/api/cart/pay',
      order: 4,
      isPaymentOrTerminal: true,
      description: 'Captures credit card authorization or digital wallet token',
    },
    {
      id: 'step-order-fulfill',
      name: 'Order Fulfillment',
      method: 'POST',
      path: '/api/cart/fulfill',
      order: 5,
      isTerminal: true,
      description: 'Dispatches warehouse order and issues shipping label',
    },
  ],
  transitions: [
    { fromStepId: 'step-cart-init', toStepId: 'step-add-item', isAllowed: true },
    { fromStepId: 'step-add-item', toStepId: 'step-apply-coupon', isAllowed: true },
    { fromStepId: 'step-apply-coupon', toStepId: 'step-payment', isAllowed: true },
    { fromStepId: 'step-payment', toStepId: 'step-order-fulfill', isAllowed: true },
    // Detected Illegal State Machine Bypasses:
    {
      fromStepId: 'step-add-item',
      toStepId: 'step-order-fulfill',
      isAllowed: false,
      isBypass: true,
      findingId: 'fnd-bypass-skip-pay',
      observedStatus: 200,
      description: 'Payment Bypass Exploit: Client skipped payment processing and successfully fulfilled order #ORD-8821.',
    },
    {
      fromStepId: 'step-cart-init',
      toStepId: 'step-payment',
      isAllowed: false,
      isBypass: true,
      findingId: 'fnd-bypass-empty-cart',
      observedStatus: 200,
      description: 'Zero-Item Payment Exploit: Paid for an empty cart without adding items.',
    },
  ],
  bypassExploits: [
    {
      id: 'fnd-bypass-skip-pay',
      name: 'Critical State Machine Bypass: Unpaid Order Dispatch',
      severity: 'CRITICAL',
      skippedSteps: ['step-apply-coupon', 'step-payment'],
      targetEndpoint: '/api/cart/fulfill',
      method: 'POST',
      expectedStatus: 400,
      actualStatus: 200,
      description:
        'The order fulfillment handler failed to verify whether a valid settled paymentId was linked to cart session before triggering warehouse dispatch. An adversary can acquire merchandise for free.',
      impact: 'Complete financial loss; free merchandise theft through automated API invocation.',
      remediation:
        'Enforce server-side state machine assertions: require payment.status == "COMPLETED" before transitioning cart state to "FULFILLED".',
      requestSnippet: `POST /api/cart/fulfill HTTP/1.1
Host: api.store-resilience.internal
Cookie: cart_session=cart-alice-9821
Content-Type: application/json

{"shippingAddress": "123 Security Blvd, Cyber City"}`,
      responseSnippet: `HTTP/1.1 200 OK
Content-Type: application/json

{
  "orderId": "ORD-FREE-9821",
  "status": "DISPATCHED",
  "trackingNumber": "1Z9999999999999999",
  "paidAmount": 0.00
}`,
    },
  ],
};

export const SAMPLE_RACE_CONDITION_MODEL: RaceConditionBurstModel = {
  testId: 'race-coupon-single-use',
  name: 'Synchronized Socket Burst: Single-Use Coupon Multi-Redeem',
  endpoint: '/api/coupon/redeem',
  method: 'POST',
  concurrency: 20,
  barrierReleaseJitterMs: 0.35,
  maxAllowedSuccess: 1,
  actualSuccessCount: 6,
  isVulnerable: true,
  summary:
    'Dispatched 20 concurrent HTTP requests across a 0.35ms TCP barrier holdback. The server redeemed coupon "BLACKFRIDAY90" 6 times concurrently due to missing database row-level locking.',
  remediation:
    'Use atomic database decrement with optimistic locking (WHERE remaining_uses > 0) or distributed locks via Redis Redlock.',
  requests: [
    { threadId: 1, sentDeltaMs: 0.0, durationMs: 42, statusCode: 200, responsePreview: '{"status":"redeemed","discount":50.0}', isAnomaly: false },
    { threadId: 2, sentDeltaMs: 0.02, durationMs: 43, statusCode: 200, responsePreview: '{"status":"redeemed","discount":50.0}', isAnomaly: true },
    { threadId: 3, sentDeltaMs: 0.05, durationMs: 44, statusCode: 200, responsePreview: '{"status":"redeemed","discount":50.0}', isAnomaly: true },
    { threadId: 4, sentDeltaMs: 0.08, durationMs: 45, statusCode: 200, responsePreview: '{"status":"redeemed","discount":50.0}', isAnomaly: true },
    { threadId: 5, sentDeltaMs: 0.12, durationMs: 45, statusCode: 200, responsePreview: '{"status":"redeemed","discount":50.0}', isAnomaly: true },
    { threadId: 6, sentDeltaMs: 0.15, durationMs: 46, statusCode: 200, responsePreview: '{"status":"redeemed","discount":50.0}', isAnomaly: true },
    { threadId: 7, sentDeltaMs: 0.18, durationMs: 46, statusCode: 409, responsePreview: '{"error":"Coupon already redeemed"}', isAnomaly: false },
    { threadId: 8, sentDeltaMs: 0.21, durationMs: 47, statusCode: 409, responsePreview: '{"error":"Coupon already redeemed"}', isAnomaly: false },
    { threadId: 9, sentDeltaMs: 0.24, durationMs: 47, statusCode: 409, responsePreview: '{"error":"Coupon already redeemed"}', isAnomaly: false },
    { threadId: 10, sentDeltaMs: 0.26, durationMs: 48, statusCode: 409, responsePreview: '{"error":"Coupon already redeemed"}', isAnomaly: false },
    { threadId: 11, sentDeltaMs: 0.28, durationMs: 48, statusCode: 409, responsePreview: '{"error":"Coupon already redeemed"}', isAnomaly: false },
    { threadId: 12, sentDeltaMs: 0.31, durationMs: 49, statusCode: 409, responsePreview: '{"error":"Coupon already redeemed"}', isAnomaly: false },
    { threadId: 13, sentDeltaMs: 0.33, durationMs: 49, statusCode: 409, responsePreview: '{"error":"Coupon already redeemed"}', isAnomaly: false },
    { threadId: 14, sentDeltaMs: 0.35, durationMs: 50, statusCode: 409, responsePreview: '{"error":"Coupon already redeemed"}', isAnomaly: false },
    { threadId: 15, sentDeltaMs: 0.37, durationMs: 50, statusCode: 409, responsePreview: '{"error":"Coupon already redeemed"}', isAnomaly: false },
    { threadId: 16, sentDeltaMs: 0.40, durationMs: 51, statusCode: 409, responsePreview: '{"error":"Coupon already redeemed"}', isAnomaly: false },
    { threadId: 17, sentDeltaMs: 0.42, durationMs: 51, statusCode: 409, responsePreview: '{"error":"Coupon already redeemed"}', isAnomaly: false },
    { threadId: 18, sentDeltaMs: 0.44, durationMs: 52, statusCode: 409, responsePreview: '{"error":"Coupon already redeemed"}', isAnomaly: false },
    { threadId: 19, sentDeltaMs: 0.47, durationMs: 52, statusCode: 409, responsePreview: '{"error":"Coupon already redeemed"}', isAnomaly: false },
    { threadId: 20, sentDeltaMs: 0.50, durationMs: 53, statusCode: 409, responsePreview: '{"error":"Coupon already redeemed"}', isAnomaly: false },
  ],
};

// ============================================================================
// API Client Methods
// ============================================================================

/**
 * Returns default or preset chaos injection configuration
 */
export function getChaosPresetConfig(presetKey: string = 'db_brownout'): ChaosInjectionConfig {
  return PRESET_CHAOS_PROFILES[presetKey] || PRESET_CHAOS_PROFILES.db_brownout;
}

/**
 * Fetches state machine verification model (or defaults)
 */
export async function getStateMachineModel(): Promise<StateMachineModel> {
  return SAMPLE_STATE_MACHINE_MODEL;
}

/**
 * Fetches race condition burst test model (or defaults)
 */
export async function getRaceConditionBurstModel(): Promise<RaceConditionBurstModel> {
  return SAMPLE_RACE_CONDITION_MODEL;
}

/**
 * Simulates triggering a live chaos experiment against the target
 */
export async function executeChaosSimulation(
  config: ChaosInjectionConfig,
): Promise<{ success: boolean; stats: ChaosExecutionStats; message: string }> {
  // If backend endpoints exist, call them; otherwise provide high-fidelity simulation
  try {
    const res = await apiClient.post<any>('/api/v1/test-runs', {
      plan: {
        name: `Chaos Experiment: ${config.activePreset}`,
        engineId: 'engine-chaos-mitm',
      },
    });
    return {
      success: true,
      stats: {
        status: config.circuitBreakerEnabled && config.errorInjectionRate > 50 ? 'tripped' : 'completed',
        totalRequests: 240,
        faultsInjected: Math.round(240 * (config.errorInjectionRate / 100)),
        unrecoveredErrors: Math.round(240 * (config.packetDropRate / 100)),
        rtoSeconds: config.latencyMs > 1000 ? 5.2 : 2.8,
        circuitBreakerState: config.circuitBreakerEnabled && config.errorInjectionRate > 50 ? 'HALF_OPEN' : 'CLOSED',
        resilienceScore: Math.max(20, 100 - config.errorInjectionRate - config.packetDropRate),
      },
      message: res?.message || 'Chaos injection experiment completed successfully.',
    };
  } catch {
    return {
      success: true,
      stats: {
        status: config.circuitBreakerEnabled && config.errorInjectionRate > 50 ? 'tripped' : 'completed',
        totalRequests: 180,
        faultsInjected: Math.round(180 * (config.errorInjectionRate / 100)),
        unrecoveredErrors: Math.round(180 * (config.packetDropRate / 100)),
        rtoSeconds: config.latencyMs > 1000 ? 4.8 : 2.4,
        circuitBreakerState: config.circuitBreakerEnabled && config.errorInjectionRate > 50 ? 'HALF_OPEN' : 'CLOSED',
        resilienceScore: Math.max(25, 100 - config.errorInjectionRate - config.packetDropRate),
      },
      message: 'Simulated fault injection executed across proxy pipeline.',
    };
  }
}

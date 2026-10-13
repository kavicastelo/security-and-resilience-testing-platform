import crypto from 'node:crypto';
import { safeFetch, RawEngineFinding, ExecutionContext } from '@security-lab/engine-sdk';

export async function testBatchAmplification(
  endpointUrl: string,
  batchSize = 50,
  customHeaders: Record<string, string> = {},
  context: ExecutionContext,
): Promise<{ batchingSupported: boolean; processedCount: number; finding?: RawEngineFinding }> {
  // Cap at safe limit (max 50) as required by Section 13
  const safeBatchSize = Math.min(50, Math.max(2, batchSize));

  // Build JSON array of operations
  const batchPayload = Array.from({ length: safeBatchSize }, (_, i) => ({
    query: `{ __typename }`,
    operationName: `Op${i}`,
  }));

  const startTime = Date.now();
  const headers = {
    'Content-Type': 'application/json',
    Accept: 'application/json',
    ...customHeaders,
  };

  try {
    const res = await safeFetch(endpointUrl, {
      method: 'POST',
      headers,
      body: JSON.stringify(batchPayload),
      signal: context.abortSignal,
      scope: context.target?.scope,
    });

    const responseTimeMs = Date.now() - startTime;
    const json = (await res.json()) as any;

    if (Array.isArray(json) && json.length >= 2) {
      const processedCount = json.length;

      const evidencePayload = {
        request: {
          method: 'POST',
          url: endpointUrl,
          headers,
          body: `[Array of ${safeBatchSize} GraphQL operations in single HTTP request]`,
        },
        response: {
          statusCode: res.status,
          headers: { 'content-type': res.headers.get('content-type') || 'application/json' },
          body: JSON.stringify({
            receivedResponsesCount: processedCount,
            sampleResult: json[0],
          }),
          responseTimeMs,
        },
        expected: 'GraphQL server rejects batch query arrays with HTTP 400 or limits batch size to 1-5',
        actual: `Server processed array of ${processedCount} operations in a single HTTP roundtrip`,
      };

      const sha256 = crypto
        .createHash('sha256')
        .update(JSON.stringify(evidencePayload))
        .digest('hex');

      const finding: RawEngineFinding = {
        title: 'GraphQL Batch Query Amplification Allowed',
        category: 'protocol_audit',
        severity: 'medium',
        description: `The GraphQL server processed ${processedCount} operations submitted as a JSON array in a single HTTP POST. Attackers can abuse batching to bypass HTTP-level rate limiting, amplify brute-force attacks against login mutations, or perform resource exhaustion.`,
        recommendation:
          'Disable batch query arrays in your GraphQL server or restrict maximum batch operations via gateway rate limiting.',
        evidence: {
          ...evidencePayload,
          immutableHash: sha256,
        },
      };

      return { batchingSupported: true, processedCount, finding };
    }
  } catch {
    // Non-batch or error
  }

  return { batchingSupported: false, processedCount: 0 };
}

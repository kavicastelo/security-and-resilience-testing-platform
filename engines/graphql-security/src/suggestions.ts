import crypto from 'node:crypto';
import { safeFetch, RawEngineFinding, ExecutionContext } from '@security-lab/engine-sdk';

export async function testFieldSuggestions(
  endpointUrl: string,
  customHeaders: Record<string, string> = {},
  context: ExecutionContext,
): Promise<{ suggestionsEnabled: boolean; leakedFields: string[]; finding?: RawEngineFinding }> {
  // Probes with deliberate misspellings designed to trigger standard GraphQL "Did you mean ...?" suggestions
  const candidateProbes = [
    { query: '{ __schem { typ } }', misspelled: '__schem' },
    { query: '{ usr { passwrd, emal } }', misspelled: 'passwrd' },
    { query: '{ user { passwrd } }', misspelled: 'passwrd' },
    { query: '{ authen { tkn } }', misspelled: 'authen' },
  ];

  const startTime = Date.now();
  const headers = {
    'Content-Type': 'application/json',
    Accept: 'application/json',
    ...customHeaders,
  };

  const leakedFields: string[] = [];
  let sampleEvidence: any = null;

  for (const probe of candidateProbes) {
    if (context.abortSignal?.aborted) break;

    try {
      const res = await safeFetch(endpointUrl, {
        method: 'POST',
        headers,
        body: JSON.stringify({ query: probe.query }),
        signal: context.abortSignal,
        scope: context.target?.scope,
      });

      const responseTimeMs = Date.now() - startTime;
      const json = (await res.json()) as any;

      const errors = json?.errors || [];
      for (const err of errors) {
        const msg = err.message || '';
        // Match standard GraphQL-JS suggestion format: Cannot query field "x". Did you mean "y"?
        const match = /did you mean\s+(["'][^"']+["']|\S+)/i.exec(msg);
        if (match && match[1]) {
          const suggested = match[1].replace(/["']/g, '');
          if (!leakedFields.includes(suggested)) {
            leakedFields.push(suggested);
          }

          if (!sampleEvidence) {
            sampleEvidence = {
              request: {
                method: 'POST',
                url: endpointUrl,
                headers,
                body: JSON.stringify({ query: probe.query }),
              },
              response: {
                statusCode: res.status,
                headers: { 'content-type': res.headers.get('content-type') || 'application/json' },
                body: JSON.stringify({ error: msg }),
                responseTimeMs,
              },
              expected: 'Error message does not reveal hidden or private schema fields via suggestions',
              actual: `Server leaked field suggestion in error: "${msg}"`,
            };
          }
        }
      }
    } catch {
      // Ignore network errors on individual probe
    }
  }

  if (leakedFields.length > 0 && sampleEvidence) {
    const sha256 = crypto
      .createHash('sha256')
      .update(JSON.stringify(sampleEvidence))
      .digest('hex');

    const finding: RawEngineFinding = {
      title: 'GraphQL Field Suggestions Enabled (Schema Reconstruction Risk)',
      category: 'information_disclosure',
      severity: 'low',
      description: `The GraphQL server returns field suggestions in validation error messages (e.g. "Did you mean '${leakedFields.join("', '")}'?"). Even with introspection disabled, automated dictionary fuzzers can reconstruct the complete private schema by analyzing suggestion feedback.`,
      recommendation:
        'Disable field suggestions in production (e.g. using graphql-disable-suggestions or mask error details in validation rules).',
      evidence: {
        ...sampleEvidence,
        immutableHash: sha256,
      },
    };

    return { suggestionsEnabled: true, leakedFields, finding };
  }

  return { suggestionsEnabled: false, leakedFields: [] };
}

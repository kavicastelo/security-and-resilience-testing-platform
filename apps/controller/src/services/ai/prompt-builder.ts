import { Finding, Target } from '@security-lab/domain';

export interface PromptBuilderOptions {
  sourceCodeSnippet?: string;
  filePath?: string;
  framework?: string;
}

export interface BuiltPrompt {
  systemPrompt: string;
  userPrompt: string;
  sanitizedMetadata: {
    findingId: string;
    title: string;
    severity: string;
    redactedHeaderCount: number;
    hasSourceCode: boolean;
  };
}

const SENSITIVE_HEADER_KEYS = new Set([
  'authorization',
  'cookie',
  'set-cookie',
  'x-api-key',
  'api-key',
  'x-auth-token',
  'proxy-authorization',
  'token',
  'secret',
  'private-key',
]);

const SENSITIVE_PATTERNS = [
  /Bearer\s+[A-Za-z0-9._~+/-]+=*/gi,
  /ey[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{4,}/g, // JWT
  /(password|passwd|secret|api_key|apikey|token)["']?\s*[:=]\s*["']?[^"'&,\s]+/gi,
];

/**
 * Scrubs sensitive data (passwords, JWTs, API tokens) from arbitrary text.
 */
export function sanitizeText(text: string): string {
  if (!text) return '';
  let sanitized = text;
  for (const pattern of SENSITIVE_PATTERNS) {
    sanitized = sanitized.replace(pattern, '[REDACTED_SECRET]');
  }
  return sanitized;
}

/**
 * Scrubs sensitive headers and values from HTTP header dictionaries.
 */
export function sanitizeHeaders(
  headers?: Record<string, string | string[] | undefined>,
): Record<string, string> {
  if (!headers) return {};
  const cleaned: Record<string, string> = {};

  for (const [key, val] of Object.entries(headers)) {
    if (!val) continue;
    const lowerKey = key.toLowerCase();
    const strVal = Array.isArray(val) ? val.join(', ') : String(val);

    if (SENSITIVE_HEADER_KEYS.has(lowerKey)) {
      cleaned[key] = '[REDACTED]';
    } else {
      cleaned[key] = sanitizeText(strVal);
    }
  }

  return cleaned;
}

export class RemediationPromptBuilder {
  /**
   * Constructs an AI remediation prompt from a security finding, target, and optional source code.
   */
  buildPrompt(
    finding: Finding,
    target?: Target | null,
    options?: PromptBuilderOptions,
  ): BuiltPrompt {
    const rawEvidence = ((finding as unknown as { evidence?: unknown }).evidence ||
      finding.metadata?.evidence ||
      {}) as {
      request?: {
        method?: string;
        url?: string;
        headers?: Record<string, string>;
        body?: unknown;
      };
      response?: {
        statusCode?: number;
        headers?: Record<string, string>;
        body?: unknown;
      };
    };

    let redactedHeaderCount = 0;
    const reqHeaders = rawEvidence.request?.headers
      ? sanitizeHeaders(rawEvidence.request.headers)
      : {};
    const resHeaders = rawEvidence.response?.headers
      ? sanitizeHeaders(rawEvidence.response.headers)
      : {};

    for (const v of Object.values(reqHeaders)) {
      if (v === '[REDACTED]') redactedHeaderCount++;
    }
    for (const v of Object.values(resHeaders)) {
      if (v === '[REDACTED]') redactedHeaderCount++;
    }

    const reqBodyStr = rawEvidence.request?.body
      ? sanitizeText(
          typeof rawEvidence.request.body === 'string'
            ? rawEvidence.request.body
            : JSON.stringify(rawEvidence.request.body, null, 2),
        )
      : '';

    const resBodyStr = rawEvidence.response?.body
      ? sanitizeText(
          typeof rawEvidence.response.body === 'string'
            ? rawEvidence.response.body
            : JSON.stringify(rawEvidence.response.body, null, 2),
        )
      : '';

    const fileLocation = (finding as any).location || (finding.metadata?.location as string);
    const filePath = options?.filePath || fileLocation || 'src/server.ts';
    const sourceCode = options?.sourceCodeSnippet
      ? sanitizeText(options.sourceCodeSnippet)
      : '';

    const systemPrompt = `You are a Principal Application Security Researcher and Senior Software Engineer.
Your task is to analyze a verified security finding from the platform and generate:
1. A clear, jargon-free root cause explanation of the vulnerability and how an attacker could exploit it.
2. A defensive, minimal, production-grade code patch in valid unified git diff format.
3. Concrete verification guidance explaining how the patch mitigates the flaw without breaking legitimate functionality.

Guidelines:
- Always format the code patch inside a single unified git diff block starting with \`diff --git a/${filePath} b/${filePath}\`.
- Ensure standard diff headers (\`--- a/${filePath}\`, \`+++ b/${filePath}\`, and \`@@ ... @@\`).
- Write secure, idiomatic, and robust code. Do not introduce regressions or disable security protections.
- Use temperature 0.1 precision: avoid extraneous narrative inside code blocks.`;

    const userPrompt = `### Vulnerability Finding Context
- **Title**: ${finding.title}
- **Severity**: ${finding.severity.toUpperCase()}
- **Category**: ${finding.category}
- **Description**: ${sanitizeText(finding.description)}
- **Target URL**: ${target?.baseUrl || 'http://localhost'}
- **Location / Route**: ${fileLocation || 'N/A'}
- **CWE / Rule**: ${finding.metadata?.cwe || finding.metadata?.ruleId || 'N/A'}

### HTTP Request Evidence
- **Method**: ${rawEvidence.request?.method || 'GET'}
- **URL**: ${rawEvidence.request?.url || target?.baseUrl || '/'}
- **Headers**:
\`\`\`json
${JSON.stringify(reqHeaders, null, 2)}
\`\`\`
${reqBodyStr ? `- **Body**:\n\`\`\`\n${reqBodyStr.slice(0, 1000)}\n\`\`\`\n` : ''}

### HTTP Response Evidence
- **Status Code**: ${rawEvidence.response?.statusCode || 200}
- **Headers**:
\`\`\`json
${JSON.stringify(resHeaders, null, 2)}
\`\`\`
${resBodyStr ? `- **Body Snippet**:\n\`\`\`\n${resBodyStr.slice(0, 1000)}\n\`\`\`\n` : ''}

${
  sourceCode
    ? `### Relevant Source Code (${filePath})\n\`\`\`typescript\n${sourceCode}\n\`\`\`\n`
    : `### Target File\nFile path to patch: \`${filePath}\`\n`
}

Please provide:
### 1. Root Cause & Exploit Explanation
Explain the vulnerability, why the observed evidence proves the flaw, and the attacker risk.

### 2. Unified Git Diff Patch
Provide the precise git patch. Must strictly start with \`diff --git a/${filePath} b/${filePath}\`.

### 3. Verification & Safety Considerations
Explain why this fix is safe and what retesting step confirms it.`;

    return {
      systemPrompt,
      userPrompt,
      sanitizedMetadata: {
        findingId: finding.id,
        title: finding.title,
        severity: finding.severity,
        redactedHeaderCount,
        hasSourceCode: Boolean(sourceCode),
      },
    };
  }
}

export const remediationPromptBuilder = new RemediationPromptBuilder();

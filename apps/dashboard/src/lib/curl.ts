export interface RequestEvidenceLike {
  method?: string;
  url?: string;
  headers?: Record<string, string>;
  body?: string;
}

/**
 * Escapes characters for safe inclusion inside a Bash single-quoted string.
 */
export function escapeBashSingleQuote(str: string): string {
  return str.replace(/'/g, "'\\''");
}

/**
 * Generates an executable, multiline copy-pasteable `curl` reproduction snippet.
 */
export function generateCurlSnippet(request?: RequestEvidenceLike | null, fallbackUrl?: string): string {
  if (!request?.url && !fallbackUrl) {
    return 'curl -X GET "https://target-endpoint.local"';
  }

  const url = request?.url || fallbackUrl || '';
  const method = (request?.method || 'GET').toUpperCase();

  const parts: string[] = [`curl -i -X ${method} '${escapeBashSingleQuote(url)}'`];

  if (request?.headers && typeof request.headers === 'object') {
    for (const [key, value] of Object.entries(request.headers)) {
      if (value !== undefined && value !== null && value !== '') {
        const headerStr = `${key}: ${String(value)}`;
        parts.push(`  -H '${escapeBashSingleQuote(headerStr)}'`);
      }
    }
  }

  if (request?.body !== undefined && request?.body !== null) {
    const bodyStr = typeof request.body === 'string' ? request.body : JSON.stringify(request.body);
    if (bodyStr.length > 0) {
      parts.push(`  --data-raw '${escapeBashSingleQuote(bodyStr)}'`);
    }
  }

  return parts.join(' \\\n');
}

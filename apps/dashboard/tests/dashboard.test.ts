import { describe, it, expect } from 'vitest';
import { generateCurlSnippet, escapeBashSingleQuote } from '../src/lib/curl.js';

describe('Phase 18: Dashboard Operations Console & Evidence Inspection Utilities', () => {
  it('escapes single quotes inside bash strings safely to prevent CLI injection', () => {
    const raw = "user's input with 'quotes'";
    const escaped = escapeBashSingleQuote(raw);
    expect(escaped).toBe("user'\\''s input with '\\''quotes'\\''");
  });

  it('generates standard curl reproduction snippets with headers and payloads', () => {
    const snippet = generateCurlSnippet({
      method: 'POST',
      url: 'https://api.internal.target/v1/auth',
      headers: {
        'Content-Type': 'application/json',
        Authorization: 'Bearer secret-token-123',
      },
      body: JSON.stringify({ username: "admin' OR 1=1--" }),
    });

    expect(snippet).toContain("curl -i -X POST 'https://api.internal.target/v1/auth'");
    expect(snippet).toContain("-H 'Content-Type: application/json'");
    expect(snippet).toContain("-H 'Authorization: Bearer secret-token-123'");
    expect(snippet).toContain("--data-raw");
    expect(snippet).toContain("admin'\\'' OR 1=1--");
  });

  it('generates a clean default curl snippet when evidence request is empty', () => {
    const snippet = generateCurlSnippet(null, 'https://fallback.local/health');
    expect(snippet).toBe("curl -i -X GET 'https://fallback.local/health'");
  });
});

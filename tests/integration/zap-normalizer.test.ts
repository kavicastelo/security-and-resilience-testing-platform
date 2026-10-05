import { describe, it, expect } from 'vitest';
import { normalizeZapAlerts } from '@security-lab/domain';

describe('OWASP ZAP Alert Normalizer', () => {
  it('normalizes full ZAP site report into unified platform findings', () => {
    const rawZapReport = {
      '@programName': 'ZAP',
      '@version': '2.14.0',
      site: [
        {
          '@name': 'https://api.example.com',
          alerts: [
            {
              pluginid: '40018',
              alert: 'SQL Injection',
              name: 'SQL Injection',
              riskcode: '3',
              confidence: '3',
              riskdesc: 'High (High)',
              desc: '<p>A SQL injection vulnerability was detected in user input.</p>',
              solution: '<p>Use <b>parameterized queries</b> and ORM abstractions.</p>',
              reference: '<p>https://owasp.org/www-community/attacks/SQL_Injection</p>',
              cweid: '89',
              wascid: '19',
              instances: [
                {
                  uri: 'https://api.example.com/api/v1/users',
                  method: 'GET',
                  param: 'id',
                  attack: "' OR 1=1 --",
                  evidence: 'syntax error near unexpected token',
                },
              ],
            },
            {
              pluginid: '10038',
              alert: 'Content Security Policy (CSP) Header Not Set',
              riskcode: '2',
              confidence: '2',
              desc: 'Content Security Policy (CSP) is an added layer of defense.',
              solution: 'Configure CSP header on web server.',
              cweid: '693',
              instances: [
                {
                  uri: 'https://api.example.com/',
                  method: 'GET',
                },
              ],
            },
            {
              pluginid: '10021',
              alert: 'X-Content-Type-Options Header Missing',
              riskcode: '1',
              confidence: '1',
              desc: 'Anti-MIME-Sniffing header missing.',
              solution: 'Set X-Content-Type-Options: nosniff.',
              cweid: '693',
            },
          ],
        },
      ],
    };

    const findings = normalizeZapAlerts(rawZapReport);
    expect(findings).toHaveLength(3);

    // 1. Critical SQL Injection Finding
    const sqli = findings.find((f) => f.title === 'SQL Injection');
    expect(sqli).toBeDefined();
    expect(sqli?.severity).toBe('critical'); // Elevated to critical due to SQLi pattern
    expect(sqli?.confidence).toBe('certain');
    expect(sqli?.cweId).toBe('CWE-89');
    expect(sqli?.wascId).toBe('WASC-19');
    expect(sqli?.description).not.toContain('<p>');
    expect(sqli?.recommendation).toContain('parameterized queries');
    expect(sqli?.evidence?.request?.url).toBe('https://api.example.com/api/v1/users');
    expect(sqli?.evidence?.actual).toContain('syntax error');

    // 2. Medium CSP Finding
    const csp = findings.find((f) => f.title.includes('Content Security Policy'));
    expect(csp).toBeDefined();
    expect(csp?.severity).toBe('medium');
    expect(csp?.confidence).toBe('firm');

    // 3. Low MIME-Sniffing Finding
    const nosniff = findings.find((f) => f.title.includes('X-Content-Type-Options'));
    expect(nosniff).toBeDefined();
    expect(nosniff?.severity).toBe('low');
    expect(nosniff?.confidence).toBe('tentative');
  });

  it('handles empty, invalid, or flat array ZAP inputs gracefully', () => {
    expect(normalizeZapAlerts(null)).toHaveLength(0);
    expect(normalizeZapAlerts({})).toHaveLength(0);
    expect(normalizeZapAlerts({ alerts: [] })).toHaveLength(0);

    const flatAlerts = [
      {
        alert: 'Server Leaks Version',
        riskcode: '0',
        confidence: '2',
        desc: 'Server header reveals Apache version',
      },
    ];

    const findings = normalizeZapAlerts(flatAlerts);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('info');
    expect(findings[0]?.confidence).toBe('firm');
  });
});

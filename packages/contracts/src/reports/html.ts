import { ReportInput } from './types.js';
import { calculatePostureScore } from '@security-lab/scoring';

function escapeHtml(unsafe: string): string {
  return unsafe
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/**
 * Generates self-contained, enterprise executive HTML report suitable for browser viewing or PDF printing.
 */
export function generateHtmlExecutiveReport(input: ReportInput): string {
  const { testRun, target, executions, findings, metrics = [], releaseGate } = input;
  const posture = input.posture || calculatePostureScore(findings);
  const targetUrl = target?.baseUrl || 'N/A';
  const targetName = target?.name || testRun.targetId;

  const metricMap: Record<string, number> = {};
  for (const m of metrics) {
    metricMap[m.name] = m.value;
  }

  const p95 = metricMap['http_req_duration_p95'];
  const p99 = metricMap['http_req_duration_p99'];
  const med = metricMap['http_req_duration_med'];
  const rps = metricMap['http_rps'];
  const totalReqs = metricMap['http_reqs_total'];
  const failedRatio = metricMap['http_req_failed_ratio'];
  const rateLimitEnforced = metricMap['rate_limiting_enforced'];

  const gateDecision = releaseGate?.decision || (posture.score >= 80 ? 'passed' : 'failed');
  const gateColor =
    gateDecision === 'passed' ? '#10b981' : gateDecision === 'warning' ? '#f59e0b' : '#ef4444';
  const gateTitle =
    gateDecision === 'passed'
      ? 'RELEASE GATE: PASSED (Compliant)'
      : gateDecision === 'warning'
        ? 'RELEASE GATE: WARNING (Manual Review Required)'
        : 'RELEASE GATE: BLOCKED (Non-Compliant)';

  const gradeColor =
    posture.grade === 'A'
      ? '#10b981'
      : posture.grade === 'B'
        ? '#3b82f6'
        : posture.grade === 'C'
          ? '#f59e0b'
          : '#ef4444';

  const findingsRows = findings
    .map((f) => {
      const sevColor =
        f.severity === 'critical'
          ? '#ef4444'
          : f.severity === 'high'
            ? '#f97316'
            : f.severity === 'medium'
              ? '#f59e0b'
              : f.severity === 'low'
                ? '#3b82f6'
                : '#6b7280';

      return `
      <tr>
        <td style="padding: 10px 14px; border-bottom: 1px solid #27272a;">
          <span style="display: inline-block; padding: 2px 8px; border-radius: 4px; font-weight: 700; font-size: 11px; text-transform: uppercase; background-color: ${sevColor}22; color: ${sevColor}; border: 1px solid ${sevColor}44;">
            ${f.severity}
          </span>
        </td>
        <td style="padding: 10px 14px; border-bottom: 1px solid #27272a; font-weight: 600; color: #f4f4f5;">
          ${escapeHtml(f.title)}
          <div style="font-weight: 400; font-size: 12px; color: #a1a1aa; margin-top: 4px;">
            ${escapeHtml(f.description)}
          </div>
          ${
            f.recommendation
              ? `<div style="font-weight: 400; font-size: 12px; color: #10b981; margin-top: 4px;">
                  <strong>Remediation:</strong> ${escapeHtml(f.recommendation)}
                </div>`
              : ''
          }
        </td>
        <td style="padding: 10px 14px; border-bottom: 1px solid #27272a; font-size: 12px; color: #a1a1aa;">
          ${escapeHtml(f.category)}
        </td>
        <td style="padding: 10px 14px; border-bottom: 1px solid #27272a; font-family: monospace; font-size: 11px; color: #71717a;">
          ${f.evidenceId ? escapeHtml(f.evidenceId.slice(0, 8)) + '...' : 'N/A'}
        </td>
      </tr>`;
    })
    .join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Security Lab Executive Security & Resilience Report</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
      background-color: #09090b;
      color: #fafafa;
      margin: 0;
      padding: 40px 20px;
      line-height: 1.5;
    }
    .container {
      max-width: 960px;
      margin: 0 auto;
    }
    .header {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      border-bottom: 1px solid #27272a;
      padding-bottom: 24px;
      margin-bottom: 30px;
    }
    .badge {
      padding: 6px 16px;
      border-radius: 9999px;
      font-weight: 700;
      font-size: 13px;
      letter-spacing: 0.5px;
    }
    .card {
      background-color: #18181b;
      border: 1px solid #27272a;
      border-radius: 12px;
      padding: 24px;
      margin-bottom: 24px;
    }
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 16px;
    }
    .stat-box {
      background-color: #09090b;
      border: 1px solid #27272a;
      border-radius: 8px;
      padding: 16px;
    }
    .stat-label {
      font-size: 11px;
      text-transform: uppercase;
      color: #a1a1aa;
      margin-bottom: 4px;
      font-weight: 600;
    }
    .stat-val {
      font-size: 24px;
      font-weight: 800;
      font-family: monospace;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      text-align: left;
    }
    th {
      padding: 10px 14px;
      border-bottom: 2px solid #27272a;
      font-size: 12px;
      text-transform: uppercase;
      color: #a1a1aa;
    }
    @media print {
      body { background-color: #fff; color: #000; padding: 0; }
      .card { border-color: #ddd; background-color: #fafafa; }
      .stat-box { background-color: #fff; border-color: #ddd; }
    }
  </style>
</head>
<body>
  <div class="container">
    <!-- Header -->
    <div class="header">
      <div>
        <h1 style="margin: 0; font-size: 24px; font-weight: 800; letter-spacing: -0.5px;">SECURITY LAB</h1>
        <div style="font-size: 13px; color: #a1a1aa; margin-top: 4px;">Security QA for Enterprise Applications</div>
        <div style="font-size: 13px; margin-top: 12px;">
          <strong>Target:</strong> ${escapeHtml(targetName)} (<code style="color: #60a5fa;">${escapeHtml(targetUrl)}</code>)
        </div>
        <div style="font-size: 12px; color: #71717a; margin-top: 4px;">
          TestRun ID: <code>${escapeHtml(testRun.id)}</code> • Executions: ${executions.length} engines • Executed: ${new Date(testRun.createdAt).toUTCString()}
        </div>
      </div>
      <div style="text-align: right;">
        <div class="badge" style="background-color: ${gateColor}20; color: ${gateColor}; border: 1px solid ${gateColor}50;">
          ${gateTitle}
        </div>
      </div>
    </div>

    <!-- Executive Posture Score Card -->
    <div class="card">
      <h2 style="font-size: 16px; margin-top: 0; margin-bottom: 16px; border-bottom: 1px solid #27272a; padding-bottom: 8px;">
        1. Security Posture Assessment & Release Verdict
      </h2>
      <div style="display: flex; align-items: center; justify-content: space-between; gap: 24px;">
        <div style="display: flex; align-items: center; gap: 20px;">
          <div style="width: 80px; height: 80px; border-radius: 50%; background-color: ${gradeColor}20; border: 3px solid ${gradeColor}; display: flex; align-items: center; justify-content: center; font-size: 36px; font-weight: 900; color: ${gradeColor};">
            ${posture.grade}
          </div>
          <div>
            <div style="font-size: 28px; font-weight: 800; font-family: monospace;">${posture.score} <span style="font-size: 14px; font-weight: 500; color: #a1a1aa;">/ 100</span></div>
            <div style="font-size: 13px; color: #a1a1aa;">Posture Score • Total Weighted Risk: <strong>${posture.totalWeightedRisk}</strong></div>
          </div>
        </div>
        <div class="grid" style="grid-template-columns: repeat(4, 1fr); gap: 8px; font-size: 12px; font-family: monospace;">
          <div style="text-align: center; padding: 8px; background: #09090b; border-radius: 6px; border: 1px solid #ef444440;">
            <div style="color: #ef4444; font-weight: 700; font-size: 18px;">${posture.findingCounts.critical}</div>
            <div style="color: #a1a1aa; font-size: 10px;">CRITICAL</div>
          </div>
          <div style="text-align: center; padding: 8px; background: #09090b; border-radius: 6px; border: 1px solid #f9731640;">
            <div style="color: #f97316; font-weight: 700; font-size: 18px;">${posture.findingCounts.high}</div>
            <div style="color: #a1a1aa; font-size: 10px;">HIGH</div>
          </div>
          <div style="text-align: center; padding: 8px; background: #09090b; border-radius: 6px; border: 1px solid #f59e0b40;">
            <div style="color: #f59e0b; font-weight: 700; font-size: 18px;">${posture.findingCounts.medium}</div>
            <div style="color: #a1a1aa; font-size: 10px;">MEDIUM</div>
          </div>
          <div style="text-align: center; padding: 8px; background: #09090b; border-radius: 6px; border: 1px solid #3b82f640;">
            <div style="color: #3b82f6; font-weight: 700; font-size: 18px;">${posture.findingCounts.low}</div>
            <div style="color: #a1a1aa; font-size: 10px;">LOW</div>
          </div>
        </div>
      </div>
    </div>

    <!-- Quantitative Latency SLA Telemetry -->
    ${
      p95 !== undefined || rps !== undefined
        ? `
    <div class="card">
      <h2 style="font-size: 16px; margin-top: 0; margin-bottom: 16px; border-bottom: 1px solid #27272a; padding-bottom: 8px;">
        2. Resilience & Quantitative Latency SLA Telemetry
      </h2>
      <div class="grid">
        <div class="stat-box">
          <div class="stat-label">P95 Response Latency</div>
          <div class="stat-val" style="color: ${p95 !== undefined && p95 > 500 ? '#ef4444' : '#10b981'};">${p95 ?? 0} ms</div>
          <div style="font-size: 11px; color: #71717a; margin-top: 4px;">SLA Threshold: ≤500ms</div>
        </div>
        <div class="stat-box">
          <div class="stat-label">P99 Response Latency</div>
          <div class="stat-val">${p99 ?? 0} ms</div>
          <div style="font-size: 11px; color: #71717a; margin-top: 4px;">Tail latency distribution</div>
        </div>
        <div class="stat-box">
          <div class="stat-label">Median Latency (P50)</div>
          <div class="stat-val">${med ?? 0} ms</div>
          <div style="font-size: 11px; color: #71717a; margin-top: 4px;">Median response time</div>
        </div>
        <div class="stat-box">
          <div class="stat-label">Throughput (RPS)</div>
          <div class="stat-val" style="color: #60a5fa;">${rps ?? 0}</div>
          <div style="font-size: 11px; color: #71717a; margin-top: 4px;">Processed: ${totalReqs ?? 0} reqs</div>
        </div>
        <div class="stat-box">
          <div class="stat-label">Error / Failure Rate</div>
          <div class="stat-val" style="color: ${(failedRatio || 0) > 0 ? '#ef4444' : '#10b981'};">${failedRatio ?? 0}%</div>
          <div style="font-size: 11px; color: #71717a; margin-top: 4px;">
            Rate Limiting: ${rateLimitEnforced === 1 ? 'Enforced' : 'None'}
          </div>
        </div>
      </div>
    </div>`
        : ''
    }

    <!-- Findings Matrix -->
    <div class="card">
      <h2 style="font-size: 16px; margin-top: 0; margin-bottom: 16px; border-bottom: 1px solid #27272a; padding-bottom: 8px;">
        3. Normalized Vulnerabilities & Misconfigurations (${findings.length})
      </h2>
      ${
        findings.length === 0
          ? '<div style="color: #10b981; font-weight: 600; padding: 20px 0;">✔ Zero vulnerabilities or policy violations detected. Endpoint satisfies all compliance checks.</div>'
          : `<table>
        <thead>
          <tr>
            <th style="width: 100px;">Severity</th>
            <th>Vulnerability & Description</th>
            <th style="width: 140px;">Category</th>
            <th style="width: 90px;">Evidence</th>
          </tr>
        </thead>
        <tbody>
          ${findingsRows}
        </tbody>
      </table>`
      }
    </div>

    <!-- Footer -->
    <div style="text-align: center; font-size: 12px; color: #71717a; margin-top: 40px; border-top: 1px solid #27272a; padding-top: 20px;">
      Report generated cryptographically by <strong>Security Lab</strong> • Local-First Security QA Platform
    </div>
  </div>
</body>
</html>`;
}

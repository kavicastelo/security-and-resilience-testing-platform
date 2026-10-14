import { ReportInput } from '@security-lab/contracts';
import { calculatePostureScore } from '@security-lab/scoring';
import { assessCompliance } from './compliance/index.js';

function escapeHtml(unsafe: string): string {
  if (!unsafe) return '';
  return unsafe
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/**
 * Generates a 100% self-contained, interactive enterprise compliance HTML report.
 * Zero external CDN calls, embedded SVG graphics, client-side filtering, and sanitized evidence.
 */
export function generateStandaloneComplianceHtmlReport(input: ReportInput): string {
  const { testRun, target, findings, releaseGate } = input;
  const posture = input.posture || calculatePostureScore(findings);
  const targetUrl = target?.baseUrl || 'N/A';
  const targetName = target?.name || testRun.targetId;

  const compliance = assessCompliance(findings, testRun.id, targetUrl);
  const counts = compliance.countsBySeverity;

  // Grade color
  const gradeColor =
    posture.grade === 'A'
      ? '#10b981'
      : posture.grade === 'B'
        ? '#3b82f6'
        : posture.grade === 'C'
          ? '#f59e0b'
          : posture.grade === 'D'
            ? '#f97316'
            : '#ef4444';

  const gateDecision = releaseGate?.decision || (posture.score >= 80 ? 'passed' : 'failed');
  const gateBadgeColor =
    gateDecision === 'passed' ? '#10b981' : gateDecision === 'warning' ? '#f59e0b' : '#ef4444';

  // Calculate SVG donut chart slices
  const totalFindings = findings.length;
  const circumference = 2 * Math.PI * 40; // r=40 -> ~251.32

  const criticalAngle = totalFindings > 0 ? (counts.critical / totalFindings) * circumference : 0;
  const highAngle = totalFindings > 0 ? (counts.high / totalFindings) * circumference : 0;
  const mediumAngle = totalFindings > 0 ? (counts.medium / totalFindings) * circumference : 0;
  const lowAngle = totalFindings > 0 ? (counts.low / totalFindings) * circumference : 0;
  const infoAngle = totalFindings > 0 ? (counts.info / totalFindings) * circumference : 0;

  const cOffset = 0;
  const hOffset = cOffset + criticalAngle;
  const mOffset = hOffset + highAngle;
  const lOffset = mOffset + mediumAngle;
  const iOffset = lOffset + lowAngle;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Executive Compliance & Security Report - ${escapeHtml(targetName)}</title>
  <style>
    :root {
      --bg: #0f172a;
      --card-bg: #1e293b;
      --card-border: #334155;
      --text: #f8fafc;
      --text-muted: #94a3b8;
      --primary: #3b82f6;
      --critical: #ef4444;
      --high: #f97316;
      --medium: #f59e0b;
      --low: #3b82f6;
      --info: #64748b;
      --success: #10b981;
    }
    body.light-theme {
      --bg: #f8fafc;
      --card-bg: #ffffff;
      --card-border: #e2e8f0;
      --text: #0f172a;
      --text-muted: #64748b;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.5;
      padding: 24px;
      transition: background 0.2s, color 0.2s;
    }
    .container { max-width: 1200px; margin: 0 auto; }
    .header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding-bottom: 24px;
      border-bottom: 1px solid var(--card-border);
      margin-bottom: 24px;
    }
    .header-title h1 { font-size: 24px; font-weight: 700; }
    .header-title p { color: var(--text-muted); font-size: 14px; margin-top: 4px; }
    .header-actions { display: flex; gap: 12px; align-items: center; }
    .btn {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      color: var(--text);
      padding: 8px 16px;
      border-radius: 6px;
      cursor: pointer;
      font-size: 13px;
      font-weight: 500;
    }
    .btn:hover { background: var(--card-border); }
    .badge {
      display: inline-block;
      padding: 4px 10px;
      border-radius: 9999px;
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 20px; margin-bottom: 24px; }
    .card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 10px;
      padding: 20px;
    }
    .card-title {
      font-size: 14px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      color: var(--text-muted);
      margin-bottom: 12px;
      font-weight: 600;
    }
    .posture-score {
      font-size: 48px;
      font-weight: 800;
      line-height: 1;
      display: flex;
      align-items: baseline;
      gap: 8px;
    }
    .posture-score .grade {
      font-size: 28px;
      padding: 2px 10px;
      border-radius: 6px;
      background: rgba(255,255,255,0.08);
    }
    .chart-container { display: flex; align-items: center; gap: 20px; }
    .chart-legend { display: flex; flex-direction: column; gap: 6px; font-size: 12px; }
    .legend-item { display: flex; align-items: center; gap: 8px; }
    .legend-dot { width: 10px; height: 10px; border-radius: 50%; }
    .compliance-bar {
      margin-top: 10px;
      margin-bottom: 16px;
    }
    .bar-label { display: flex; justify-content: space-between; font-size: 12px; margin-bottom: 4px; }
    .bar-bg { background: rgba(255,255,255,0.1); border-radius: 4px; height: 8px; overflow: hidden; }
    .bar-fill { height: 100%; border-radius: 4px; transition: width 0.3s; }
    .filters {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      margin-bottom: 20px;
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      padding: 12px;
      border-radius: 8px;
    }
    .filter-btn {
      background: transparent;
      border: 1px solid var(--card-border);
      color: var(--text);
      padding: 6px 12px;
      border-radius: 6px;
      font-size: 12px;
      cursor: pointer;
    }
    .filter-btn.active {
      background: var(--primary);
      border-color: var(--primary);
      color: #fff;
    }
    .search-box {
      flex: 1;
      min-width: 200px;
      background: var(--bg);
      border: 1px solid var(--card-border);
      color: var(--text);
      padding: 6px 12px;
      border-radius: 6px;
      font-size: 12px;
    }
    .finding-card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 8px;
      padding: 16px;
      margin-bottom: 12px;
    }
    .finding-header {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 12px;
    }
    .finding-title { font-size: 15px; font-weight: 600; margin-bottom: 4px; }
    .finding-badges { display: flex; flex-wrap: wrap; gap: 6px; margin: 8px 0; }
    .compliance-tag {
      background: rgba(59, 130, 246, 0.15);
      color: #60a5fa;
      border: 1px solid rgba(59, 130, 246, 0.3);
      padding: 2px 6px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 600;
    }
    .finding-desc { font-size: 13px; color: var(--text-muted); margin-bottom: 12px; }
    .finding-remediation {
      background: rgba(16, 185, 129, 0.1);
      border-left: 3px solid var(--success);
      padding: 10px 12px;
      border-radius: 0 4px 4px 0;
      font-size: 12px;
    }
    .finding-remediation strong { color: #34d399; }
    .code-block {
      background: #000;
      color: #38bdf8;
      padding: 8px 12px;
      border-radius: 4px;
      font-family: monospace;
      font-size: 11px;
      overflow-x: auto;
      margin-top: 8px;
    }
  </style>
</head>
<body data-theme="dark">
  <div class="container">
    <!-- Header -->
    <header class="header">
      <div class="header-title">
        <div style="font-size: 11px; font-weight: 700; letter-spacing: 1.5px; color: var(--accent); margin-bottom: 4px;">SECURITY LAB &bull; Security QA for Enterprise Applications</div>
        <h1>Executive Security & Resilience Report &bull; Compliance Assessment</h1>
        <p>Target: <strong>${escapeHtml(targetName)}</strong> (${escapeHtml(targetUrl)}) &bull; TestRun: <code>${escapeHtml(testRun.id)}</code></p>
      </div>
      <div class="header-actions">
        <span class="badge" style="background: ${gateBadgeColor}; color: #fff;">
          RELEASE GATE: ${escapeHtml(gateDecision.toUpperCase())}
        </span>
        <button class="btn theme-toggle" onclick="toggleTheme()">Toggle Theme</button>
        <button class="btn" onclick="window.print()">Print / PDF</button>
      </div>
    </header>

    <!-- Top Grid: Posture, Distribution, Compliance Overview -->
    <div class="grid">
      <!-- 1. Posture Score Card -->
      <div class="card">
        <div class="card-title">Security Posture Score</div>
        <div class="posture-score" style="color: ${gradeColor};">
          ${posture.score}<span style="font-size: 20px; color: var(--text-muted);">/100</span>
          <span class="grade" style="color: ${gradeColor};">${posture.grade}</span>
        </div>
        <p style="margin-top: 10px; font-size: 13px; color: var(--text-muted);">
          Risk Assessment: <strong style="color: ${gradeColor};">${((posture as any).riskLevel || (posture.score >= 80 ? 'LOW' : posture.score >= 50 ? 'MEDIUM' : 'HIGH')).toUpperCase()}</strong>
        </p>
        <p style="font-size: 12px; color: var(--text-muted); margin-top: 4px;">
          Generated: ${new Date().toUTCString()}
        </p>
      </div>

      <!-- 2. Severity Breakdown (SVG Donut Chart) -->
      <div class="card">
        <div class="card-title">Vulnerability Severity Distribution</div>
        <div class="chart-container">
          <svg width="100" height="100" viewBox="0 0 100 100" class="donut-chart" style="transform: rotate(-90deg);">
            <circle cx="50" cy="50" r="40" fill="transparent" stroke="#334155" stroke-width="14" />
            <!-- Critical -->
            <circle cx="50" cy="50" r="40" fill="transparent" stroke="#ef4444" stroke-width="14"
              stroke-dasharray="${criticalAngle} ${circumference}" stroke-dashoffset="0" />
            <!-- High -->
            <circle cx="50" cy="50" r="40" fill="transparent" stroke="#f97316" stroke-width="14"
              stroke-dasharray="${highAngle} ${circumference}" stroke-dashoffset="-${hOffset}" />
            <!-- Medium -->
            <circle cx="50" cy="50" r="40" fill="transparent" stroke="#f59e0b" stroke-width="14"
              stroke-dasharray="${mediumAngle} ${circumference}" stroke-dashoffset="-${mOffset}" />
            <!-- Low -->
            <circle cx="50" cy="50" r="40" fill="transparent" stroke="#3b82f6" stroke-width="14"
              stroke-dasharray="${lowAngle} ${circumference}" stroke-dashoffset="-${lOffset}" />
            <!-- Info -->
            <circle cx="50" cy="50" r="40" fill="transparent" stroke="#64748b" stroke-width="14"
              stroke-dasharray="${infoAngle} ${circumference}" stroke-dashoffset="-${iOffset}" />
          </svg>
          <div class="chart-legend">
            <div class="legend-item"><div class="legend-dot" style="background: #ef4444;"></div>Critical: ${counts.critical}</div>
            <div class="legend-item"><div class="legend-dot" style="background: #f97316;"></div>High: ${counts.high}</div>
            <div class="legend-item"><div class="legend-dot" style="background: #f59e0b;"></div>Medium: ${counts.medium}</div>
            <div class="legend-item"><div class="legend-dot" style="background: #3b82f6;"></div>Low: ${counts.low}</div>
            <div class="legend-item"><div class="legend-dot" style="background: #64748b;"></div>Info: ${counts.info}</div>
          </div>
        </div>
      </div>

      <!-- 3. Compliance Frameworks Scorecard -->
      <div class="card">
        <div class="card-title">Regulatory Compliance Scorecard</div>
        <div class="compliance-bar">
          <div class="bar-label">
            <span>OWASP Top 10 (2021)</span>
            <span><strong>${compliance.owaspTop10.compliancePercentage}%</strong> (${compliance.owaspTop10.overallStatus})</span>
          </div>
          <div class="bar-bg">
            <div class="bar-fill" style="width: ${compliance.owaspTop10.compliancePercentage}%; background: ${compliance.owaspTop10.compliancePercentage >= 80 ? '#10b981' : '#ef4444'};"></div>
          </div>
        </div>

        <div class="compliance-bar">
          <div class="bar-label">
            <span>OWASP ASVS 4.0</span>
            <span><strong>${compliance.asvs.compliancePercentage}%</strong> (${compliance.asvs.overallStatus})</span>
          </div>
          <div class="bar-bg">
            <div class="bar-fill" style="width: ${compliance.asvs.compliancePercentage}%; background: ${compliance.asvs.compliancePercentage >= 80 ? '#10b981' : '#ef4444'};"></div>
          </div>
        </div>

        <div class="compliance-bar">
          <div class="bar-label">
            <span>PCI-DSS v4.0 (Req 6)</span>
            <span><strong>${compliance.pciDss.compliancePercentage}%</strong> (${compliance.pciDss.overallStatus})</span>
          </div>
          <div class="bar-bg">
            <div class="bar-fill" style="width: ${compliance.pciDss.compliancePercentage}%; background: ${compliance.pciDss.compliancePercentage >= 80 ? '#10b981' : '#ef4444'};"></div>
          </div>
        </div>
      </div>
    </div>

    <!-- Interactive Filters -->
    <div class="filters">
      <button class="filter-btn active" onclick="setFilter('severity', 'all', this)">All Severities</button>
      <button class="filter-btn" onclick="setFilter('severity', 'critical', this)">Critical (${counts.critical})</button>
      <button class="filter-btn" onclick="setFilter('severity', 'high', this)">High (${counts.high})</button>
      <button class="filter-btn" onclick="setFilter('severity', 'medium', this)">Medium (${counts.medium})</button>
      <button class="filter-btn" onclick="setFilter('severity', 'low', this)">Low (${counts.low})</button>
      <input type="text" id="searchInput" class="search-box search-input" placeholder="Filter findings by rule, CWE, or title..." oninput="handleSearch()">
    </div>

    <!-- Findings Section -->
    <div id="findingsContainer">
      ${
        compliance.findings.length === 0
          ? '<div class="card" style="text-align: center; padding: 40px; color: var(--text-muted);">Zero vulnerabilities detected. Application passed all automated audits.</div>'
          : compliance.findings
              .map((f) => {
                const sColor =
                  f.severity === 'critical'
                    ? '#ef4444'
                    : f.severity === 'high'
                      ? '#f97316'
                      : f.severity === 'medium'
                        ? '#f59e0b'
                        : f.severity === 'low'
                          ? '#3b82f6'
                          : '#64748b';

                return `
        <div class="finding-card" data-severity="${f.severity}" data-title="${escapeHtml(f.title.toLowerCase())}" data-category="${escapeHtml(f.category.toLowerCase())}" data-cwe="${escapeHtml(f.compliance.cwe.toLowerCase())}">
          <div class="finding-header">
            <div>
              <div class="finding-title">${escapeHtml(f.title)}</div>
              <div class="finding-badges">
                <span class="badge" style="background: ${sColor}; color: #fff;">${f.severity}</span>
                <span class="compliance-tag">OWASP ${escapeHtml(f.compliance.owaspTop10.id)}</span>
                <span class="compliance-tag">ASVS ${escapeHtml(f.compliance.asvs.requirementId)}</span>
                <span class="compliance-tag">PCI-DSS ${escapeHtml(f.compliance.pciDss.requirementId)}</span>
                <span class="compliance-tag">${escapeHtml(f.compliance.cwe)}</span>
                <span class="badge" style="background: rgba(255,255,255,0.1); color: var(--text-muted);">${escapeHtml(f.status)}</span>
              </div>
            </div>
            <div style="font-size: 11px; color: var(--text-muted);">
              ID: <code>${escapeHtml(f.id.slice(0, 8))}</code>
            </div>
          </div>
          <div class="finding-desc">${escapeHtml(f.description)}</div>
          ${
            f.recommendation
              ? `
          <div class="finding-remediation">
            <strong>Remediation Guidance:</strong> ${escapeHtml(f.recommendation)}
          </div>
          `
              : ''
          }
        </div>
        `;
              })
              .join('\n')
      }
    </div>
  </div>

  <script>
    let activeSeverity = 'all';
    let searchQuery = '';

    function toggleTheme() {
      document.body.classList.toggle('light-theme');
    }

    function setFilter(type, value, btn) {
      if (type === 'severity') {
        activeSeverity = value;
        document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
      }
      applyFilters();
    }

    function handleSearch() {
      searchQuery = document.getElementById('searchInput').value.toLowerCase().trim();
      applyFilters();
    }

    function applyFilters() {
      const cards = document.querySelectorAll('.finding-card');
      cards.forEach(card => {
        const severity = card.getAttribute('data-severity');
        const title = card.getAttribute('data-title');
        const category = card.getAttribute('data-category');
        const cwe = card.getAttribute('data-cwe');

        const matchesSeverity = (activeSeverity === 'all' || severity === activeSeverity);
        const matchesSearch = !searchQuery ||
          title.includes(searchQuery) ||
          category.includes(searchQuery) ||
          cwe.includes(searchQuery);

        if (matchesSeverity && matchesSearch) {
          card.style.display = 'block';
        } else {
          card.style.display = 'none';
        }
      });
    }
  </script>
</body>
</html>`;
}

export { generateStandaloneComplianceHtmlReport as generateHtmlExecutiveReport };


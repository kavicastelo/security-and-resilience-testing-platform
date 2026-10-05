import { FindingSeverity, FindingConfidence } from '../finding/index.js';

export interface ZapAlertInstance {
  uri?: string;
  method?: string;
  param?: string;
  attack?: string;
  evidence?: string;
}

export interface ZapAlertRaw {
  pluginid?: string;
  alertRef?: string;
  alert?: string;
  name?: string;
  riskcode?: string | number;
  confidence?: string | number;
  riskdesc?: string;
  desc?: string;
  instances?: ZapAlertInstance[];
  count?: string | number;
  solution?: string;
  reference?: string;
  cweid?: string | number;
  wascid?: string | number;
  sourceid?: string;
}

export interface ZapReportSite {
  '@name'?: string;
  '@host'?: string;
  '@port'?: string;
  '@ssl'?: string;
  alerts?: ZapAlertRaw[];
}

export interface ZapReportRoot {
  site?: ZapReportSite[] | ZapReportSite;
  alerts?: ZapAlertRaw[];
}

export interface NormalizedFinding {
  title: string;
  category: string;
  severity: FindingSeverity;
  confidence: FindingConfidence;
  description: string;
  recommendation?: string;
  cweId?: string;
  wascId?: string;
  evidence?: {
    request?: {
      method: string;
      url: string;
      headers: Record<string, string>;
      body?: string;
    };
    response?: {
      statusCode: number;
      headers: Record<string, string>;
      body?: string;
    };
    expected?: string;
    actual?: string;
  };
  metadata?: Record<string, unknown>;
}

function stripHtml(text?: string): string {
  if (!text) return '';
  return text
    .replace(/<[^>]*>?/gm, '')
    .replace(/&quot;/g, '"')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .trim();
}

function mapZapRiskToSeverity(riskcode?: string | number, alertName?: string): FindingSeverity {
  const code = String(riskcode ?? '').trim();
  switch (code) {
    case '3':
      // Elevate critical if high-severity RCE/SQLi
      if (alertName && /sql injection|command injection|remote code|path traversal/i.test(alertName)) {
        return 'critical';
      }
      return 'high';
    case '2':
      return 'medium';
    case '1':
      return 'low';
    case '0':
    default:
      return 'info';
  }
}

function mapZapConfidence(confidence?: string | number): FindingConfidence {
  const conf = String(confidence ?? '').trim();
  switch (conf) {
    case '3':
      return 'certain';
    case '2':
      return 'firm';
    case '1':
    default:
      return 'tentative';
  }
}

/**
 * Normalizes raw OWASP ZAP alert objects into standard Security Lab findings.
 */
export function normalizeZapAlerts(rawReport: unknown): NormalizedFinding[] {
  if (!rawReport || typeof rawReport !== 'object') {
    return [];
  }

  const alerts: ZapAlertRaw[] = [];

  // Handle case: raw report is an array of alerts
  if (Array.isArray(rawReport)) {
    alerts.push(...(rawReport as ZapAlertRaw[]));
  } else {
    const reportObj = rawReport as ZapReportRoot;

    // Handle case: reportObj.alerts array
    if (Array.isArray(reportObj.alerts)) {
      alerts.push(...reportObj.alerts);
    }

    // Handle case: reportObj.site array or single site object
    if (reportObj.site) {
      const sites = Array.isArray(reportObj.site) ? reportObj.site : [reportObj.site];
      for (const site of sites) {
        if (Array.isArray(site.alerts)) {
          alerts.push(...site.alerts);
        }
      }
    }
  }

  const normalized: NormalizedFinding[] = [];

  for (const alert of alerts) {
    const title = alert.name || alert.alert || 'Unknown ZAP Alert';
    const severity = mapZapRiskToSeverity(alert.riskcode, title);
    const confidence = mapZapConfidence(alert.confidence);
    const description = stripHtml(alert.desc) || 'No detailed description provided by scanner.';
    const recommendation = stripHtml(alert.solution) || undefined;
    const cweId = alert.cweid ? `CWE-${alert.cweid}` : undefined;
    const wascId = alert.wascid ? `WASC-${alert.wascid}` : undefined;

    const firstInstance = alert.instances?.[0];
    const instanceUrl = firstInstance?.uri || 'unknown';
    const instanceMethod = firstInstance?.method || 'GET';

    normalized.push({
      title,
      category: 'web_application_security',
      severity,
      confidence,
      description,
      recommendation,
      cweId,
      wascId,
      evidence: firstInstance
        ? {
            request: {
              method: instanceMethod,
              url: instanceUrl,
              headers: {},
              body: firstInstance.attack || undefined,
            },
            expected: 'No vulnerability detected by security scanner',
            actual: firstInstance.evidence || firstInstance.attack || `Alert ${title} detected at ${instanceUrl}`,
          }
        : undefined,
      metadata: {
        pluginId: alert.pluginid,
        alertRef: alert.alertRef,
        cweId,
        wascId,
        param: firstInstance?.param,
        count: alert.count,
        source: 'owasp_zap',
        reference: stripHtml(alert.reference),
      },
    });
  }

  return normalized;
}

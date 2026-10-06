import {
  Finding,
  Metric,
  Policy,
  PolicyWaiver,
  ReleaseGateDecision,
} from '@security-lab/domain';

export interface PolicyViolation {
  ruleId: string;
  ruleName: string;
  action: 'block_release' | 'warn' | 'require_approval';
  reason: string;
  evidenceRef?: string;
  category?:
    | 'severity'
    | 'count'
    | 'category'
    | 'latency'
    | 'error_rate'
    | 'required_profile'
    | 'endpoint_sla'
    | 'waiver';
}

export interface WaivedFindingRecord {
  findingId: string;
  fingerprint: string;
  title: string;
  reason: string;
  approvedBy: string;
  expiresAt: Date;
}

export interface ExpiredWaiverRecord {
  fingerprint: string;
  reason: string;
  approvedBy: string;
  expiresAt: Date;
}

export interface PolicyEvaluationContext {
  executedProfiles?: string[];
  executedEngines?: string[];
  now?: Date;
}

export interface PolicyEvaluationResult {
  decision: ReleaseGateDecision;
  passed: boolean;
  violations: PolicyViolation[];
  waivedFindings: WaivedFindingRecord[];
  expiredWaivers: ExpiredWaiverRecord[];
  evaluatedRulesCount: number;
  timestamp: Date;
}

/**
 * Evaluates target findings and metrics against a defined security gate policy (v2).
 * Supports:
 * - Severity & count constraints
 * - Disallowed vulnerability categories
 * - Global latency & error rate SLAs
 * - Per-endpoint SLA thresholds
 * - Mandatory test profile enforcement
 * - Temporary finding waivers with expiration validation
 */
export function evaluatePolicy(
  policy: Policy,
  findings: Finding[],
  metrics: Metric[] = [],
  context?: PolicyEvaluationContext,
): PolicyEvaluationResult {
  const violations: PolicyViolation[] = [];
  const waivedFindings: WaivedFindingRecord[] = [];
  const expiredWaivers: ExpiredWaiverRecord[] = [];

  const now = context?.now ?? new Date();
  const waivers: PolicyWaiver[] = policy.waivers || [];

  // Map unexpired waivers by fingerprint for fast lookup
  const waiverByFingerprint = new Map<string, PolicyWaiver>();
  for (const w of waivers) {
    const expiresAt = w.expiresAt instanceof Date ? w.expiresAt : new Date(w.expiresAt);
    if (expiresAt.getTime() >= now.getTime()) {
      waiverByFingerprint.set(w.fingerprint, { ...w, expiresAt });
    } else {
      // Waiver has expired!
      expiredWaivers.push({
        fingerprint: w.fingerprint,
        reason: w.reason,
        approvedBy: w.approvedBy,
        expiresAt,
      });

      violations.push({
        ruleId: 'waiver-expired',
        ruleName: 'Expired Finding Waiver',
        action: 'block_release',
        reason: `Finding waiver for fingerprint "${w.fingerprint}" approved by "${w.approvedBy}" expired on ${expiresAt.toISOString()}. Temporary security exemption has lapsed.`,
        category: 'waiver',
      });
    }
  }

  // 1. Separate findings into active vs waived
  const activeFindings: Finding[] = [];
  for (const finding of findings) {
    const activeWaiver = waiverByFingerprint.get(finding.fingerprint);
    if (activeWaiver) {
      waivedFindings.push({
        findingId: finding.id,
        fingerprint: finding.fingerprint,
        title: finding.title,
        reason: activeWaiver.reason,
        approvedBy: activeWaiver.approvedBy,
        expiresAt: activeWaiver.expiresAt as Date,
      });
    } else {
      activeFindings.push(finding);
    }
  }

  // 2. Validate top-level required profiles
  const executed = new Set([
    ...(context?.executedProfiles || []),
    ...(context?.executedEngines || []),
  ]);

  if (policy.requiredProfiles && policy.requiredProfiles.length > 0) {
    for (const reqProfile of policy.requiredProfiles) {
      if (!executed.has(reqProfile)) {
        violations.push({
          ruleId: 'required-profile-missing',
          ruleName: 'Mandatory Test Profile Enforcement',
          action: 'block_release',
          reason: `Mandatory test profile "${reqProfile}" was not executed during test run`,
          category: 'required_profile',
        });
      }
    }
  }

  // 3. Evaluate each rule in policy
  for (const rule of policy.rules) {
    const { condition, action } = rule;

    // A. Rule-level required profiles
    if (condition.requiredProfiles && condition.requiredProfiles.length > 0) {
      for (const reqProfile of condition.requiredProfiles) {
        if (!executed.has(reqProfile)) {
          violations.push({
            ruleId: rule.id,
            ruleName: rule.name,
            action,
            reason: `Mandatory test profile "${reqProfile}" was not executed during test run`,
            category: 'required_profile',
          });
        }
      }
    }

    // B. Check maximum severity restriction on active findings
    if (condition.maxAllowedSeverity) {
      const severityRanks = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
      const maxAllowedRank = severityRanks[condition.maxAllowedSeverity];

      for (const finding of activeFindings) {
        if (severityRanks[finding.severity] > maxAllowedRank) {
          violations.push({
            ruleId: rule.id,
            ruleName: rule.name,
            action,
            reason: `Finding "${finding.title}" has severity "${finding.severity}" which exceeds maximum allowed "${condition.maxAllowedSeverity}"`,
            evidenceRef: finding.id,
            category: 'severity',
          });
        }
      }
    }

    // C. Check max counts by severity on active findings
    if (condition.maxCountBySeverity) {
      for (const [severityStr, maxCount] of Object.entries(condition.maxCountBySeverity)) {
        const matchingFindings = activeFindings.filter((f) => f.severity === severityStr);
        if (matchingFindings.length > maxCount) {
          violations.push({
            ruleId: rule.id,
            ruleName: rule.name,
            action,
            reason: `Found ${matchingFindings.length} findings with severity "${severityStr}", exceeding limit of ${maxCount}`,
            category: 'count',
          });
        }
      }
    }

    // D. Check disallowed categories on active findings
    if (condition.disallowCategories && condition.disallowCategories.length > 0) {
      for (const finding of activeFindings) {
        if (condition.disallowCategories.includes(finding.category)) {
          violations.push({
            ruleId: rule.id,
            ruleName: rule.name,
            action,
            reason: `Finding category "${finding.category}" is strictly disallowed by policy`,
            evidenceRef: finding.id,
            category: 'category',
          });
        }
      }
    }

    // E. Check maximum allowable P95 latency SLA
    if (condition.maxP95LatencyMs !== undefined && metrics.length > 0) {
      const p95Metric = metrics.find((m) => m.name === 'http_req_duration_p95');
      if (p95Metric && p95Metric.value > condition.maxP95LatencyMs) {
        violations.push({
          ruleId: rule.id,
          ruleName: rule.name,
          action,
          reason: `P95 latency of ${Math.round(p95Metric.value)}ms exceeds maximum allowed policy threshold of ${condition.maxP95LatencyMs}ms`,
          category: 'latency',
        });
      }
    }

    // F. Check maximum allowable error rate percentage
    if (condition.maxErrorRatePercent !== undefined && metrics.length > 0) {
      const errorMetric = metrics.find((m) => m.name === 'http_req_failed_ratio');
      if (errorMetric && errorMetric.value > condition.maxErrorRatePercent) {
        violations.push({
          ruleId: rule.id,
          ruleName: rule.name,
          action,
          reason: `Request failure rate of ${errorMetric.value}% exceeds maximum allowed policy threshold of ${condition.maxErrorRatePercent}%`,
          category: 'error_rate',
        });
      }
    }

    // G. Check Per-Endpoint SLAs
    if (condition.endpointSlas && condition.endpointSlas.length > 0 && metrics.length > 0) {
      for (const sla of condition.endpointSlas) {
        // Find metrics for this endpoint
        const endpointMetrics = metrics.filter((m) => {
          const pathTag = (m.tags as Record<string, unknown>)?.path || (m.tags as Record<string, unknown>)?.endpoint;
          return pathTag === sla.path || m.name.includes(sla.path);
        });

        const epP95 = endpointMetrics.find((m) => m.name.includes('duration_p95') || m.name === 'http_req_duration_p95');
        if (epP95 && epP95.value > sla.maxP95LatencyMs) {
          violations.push({
            ruleId: rule.id,
            ruleName: rule.name,
            action,
            reason: `Endpoint "${sla.path}" P95 latency of ${Math.round(epP95.value)}ms exceeds endpoint SLA threshold of ${sla.maxP95LatencyMs}ms`,
            category: 'endpoint_sla',
          });
        }

        if (sla.maxErrorRatePercent !== undefined) {
          const epErr = endpointMetrics.find((m) => m.name.includes('failed_ratio') || m.name === 'http_req_failed_ratio');
          if (epErr && epErr.value > sla.maxErrorRatePercent) {
            violations.push({
              ruleId: rule.id,
              ruleName: rule.name,
              action,
              reason: `Endpoint "${sla.path}" failure rate of ${epErr.value}% exceeds endpoint SLA threshold of ${sla.maxErrorRatePercent}%`,
              category: 'endpoint_sla',
            });
          }
        }
      }
    }
  }

  const hasBlocking = violations.some((v) => v.action === 'block_release');
  const hasWarnings = violations.some((v) => v.action === 'warn' || v.action === 'require_approval');

  let decision: ReleaseGateDecision = 'passed';
  if (hasBlocking) {
    decision = 'failed';
  } else if (hasWarnings) {
    decision = 'warning';
  }

  return {
    decision,
    passed: decision === 'passed',
    violations,
    waivedFindings,
    expiredWaivers,
    evaluatedRulesCount: policy.rules.length,
    timestamp: now,
  };
}


import { Finding, Metric, Policy, ReleaseGateDecision } from '@security-lab/domain';

export interface PolicyViolation {
  ruleId: string;
  ruleName: string;
  action: 'block_release' | 'warn' | 'require_approval';
  reason: string;
  evidenceRef?: string;
}

export interface PolicyEvaluationResult {
  decision: ReleaseGateDecision;
  passed: boolean;
  violations: PolicyViolation[];
  evaluatedRulesCount: number;
  timestamp: Date;
}

/**
 * Evaluates target findings and metrics against a defined security gate policy.
 */
export function evaluatePolicy(
  policy: Policy,
  findings: Finding[],
  _metrics: Metric[] = [],
): PolicyEvaluationResult {
  const violations: PolicyViolation[] = [];

  for (const rule of policy.rules) {
    const { condition, action } = rule;

    // Check maximum severity restriction
    if (condition.maxAllowedSeverity) {
      const severityRanks = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
      const maxAllowedRank = severityRanks[condition.maxAllowedSeverity];

      for (const finding of findings) {
        if (severityRanks[finding.severity] > maxAllowedRank) {
          violations.push({
            ruleId: rule.id,
            ruleName: rule.name,
            action,
            reason: `Finding "${finding.title}" has severity "${finding.severity}" which exceeds maximum allowed "${condition.maxAllowedSeverity}"`,
            evidenceRef: finding.id,
          });
        }
      }
    }

    // Check max counts by severity
    if (condition.maxCountBySeverity) {
      for (const [severityStr, maxCount] of Object.entries(condition.maxCountBySeverity)) {
        const matchingFindings = findings.filter((f) => f.severity === severityStr);
        if (matchingFindings.length > maxCount) {
          violations.push({
            ruleId: rule.id,
            ruleName: rule.name,
            action,
            reason: `Found ${matchingFindings.length} findings with severity "${severityStr}", exceeding limit of ${maxCount}`,
          });
        }
      }
    }

    // Check disallowed categories
    if (condition.disallowCategories && condition.disallowCategories.length > 0) {
      for (const finding of findings) {
        if (condition.disallowCategories.includes(finding.category)) {
          violations.push({
            ruleId: rule.id,
            ruleName: rule.name,
            action,
            reason: `Finding category "${finding.category}" is strictly disallowed by policy`,
            evidenceRef: finding.id,
          });
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
    evaluatedRulesCount: policy.rules.length,
    timestamp: new Date(),
  };
}

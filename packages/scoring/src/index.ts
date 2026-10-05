import { Finding, FindingSeverity } from '@security-lab/domain';

export const SEVERITY_WEIGHTS: Record<FindingSeverity, number> = {
  critical: 10.0,
  high: 7.5,
  medium: 5.0,
  low: 2.0,
  info: 0.1,
};

export interface PostureScoreResult {
  score: number; // 0 to 100 (100 = flawless)
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
  totalWeightedRisk: number;
  findingCounts: Record<FindingSeverity, number>;
}

/**
 * Calculates security posture score (0 - 100) based on findings and predefined weights.
 */
export function calculatePostureScore(findings: Finding[]): PostureScoreResult {
  const counts: Record<FindingSeverity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };

  let totalWeightedRisk = 0;

  for (const finding of findings) {
    counts[finding.severity] += 1;
    totalWeightedRisk += SEVERITY_WEIGHTS[finding.severity];
  }

  // Initial score is 100; subtract weighted risk penalties
  const rawScore = 100 - totalWeightedRisk;
  const score = Math.max(0, Math.min(100, Math.round(rawScore * 10) / 10));

  let grade: 'A' | 'B' | 'C' | 'D' | 'F' = 'A';
  if (counts.critical > 0 || score < 60) {
    grade = 'F';
  } else if (counts.high > 0 || score < 75) {
    grade = 'D';
  } else if (score < 85) {
    grade = 'C';
  } else if (score < 95) {
    grade = 'B';
  }

  return {
    score,
    grade,
    totalWeightedRisk,
    findingCounts: counts,
  };
}

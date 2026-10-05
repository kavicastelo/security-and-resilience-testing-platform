import { Command } from 'commander';
import pc from 'picocolors';
import { apiClient } from '../api/client.js';
import { ReleaseGateDecision, Policy } from '@security-lab/domain';

interface PolicyViolation {
  ruleId: string;
  ruleName: string;
  action: 'block_release' | 'warn' | 'require_approval';
  reason: string;
  evidenceRef?: string;
}

interface ReleaseGateEvaluationResponse {
  decision: ReleaseGateDecision;
  passed: boolean;
  score: {
    score: number;
    grade: 'A' | 'B' | 'C' | 'D' | 'F';
    totalWeightedRisk: number;
    findingCounts: Record<string, number>;
  };
  gateResult: {
    decision: ReleaseGateDecision;
    passed: boolean;
    violations: PolicyViolation[];
    evaluatedRulesCount: number;
    timestamp: string;
  };
  policy: Policy;
}

export const gateCommand = new Command('gate')
  .description('Enforce CI/CD security release gates against enterprise compliance policies');

gateCommand
  .command('evaluate')
  .description('Evaluate a TestRun against security and resilience gate policy')
  .requiredOption('-r, --run <testRunId>', 'TestRun ID to evaluate')
  .option('-p, --policy <policyId>', 'Policy ID (defaults to enterprise baseline)')
  .option('--name <releaseName>', 'Release name for audit trail')
  .option('--version <semver>', 'Release version tag (e.g. v1.2.0)')
  .option('--fail-on <decision>', 'Fail threshold: failed or warning', 'failed')
  .action(async (options) => {
    try {
      // eslint-disable-next-line no-console
      console.log(
        pc.cyan(
          `\nEvaluating Release Gate policy for TestRun ${pc.bold(options.run)}...`,
        ),
      );

      const response = await apiClient.post<ReleaseGateEvaluationResponse>(
        '/api/v1/releases/evaluate',
        {
          testRunId: options.run,
          policyId: options.policy,
          name: options.name,
          version: options.version,
        },
      );

      const { decision, score, gateResult, policy } = response;

      // Header summary
      // eslint-disable-next-line no-console
      console.log(pc.bold(pc.cyan('\nSecurity Posture & Policy Evaluation:')));
      // eslint-disable-next-line no-console
      console.log(`  Policy Name:      ${pc.bold(policy.name)}`);
      // eslint-disable-next-line no-console
      console.log(`  Rules Evaluated:  ${gateResult.evaluatedRulesCount} rules`);

      const gradeColor =
        score.grade === 'A'
          ? pc.green
          : score.grade === 'B'
            ? pc.blue
            : score.grade === 'C'
              ? pc.yellow
              : pc.red;

      // eslint-disable-next-line no-console
      console.log(
        `  Posture Score:    ${pc.bold(score.score)} / 100 [Grade: ${gradeColor(pc.bold(score.grade))}] (Weighted Risk: ${score.totalWeightedRisk})`,
      );

      const counts = score.findingCounts;
      // eslint-disable-next-line no-console
      console.log(
        `  Findings:         Critical: ${pc.red(counts['critical'] || 0)} | High: ${pc.red(counts['high'] || 0)} | Medium: ${pc.yellow(counts['medium'] || 0)} | Low: ${pc.blue(counts['low'] || 0)}`,
      );

      // Decision Badge
      const decisionBadge =
        decision === 'passed'
          ? pc.bgGreen(pc.white(pc.bold(' PASSED ')))
          : decision === 'warning'
            ? pc.bgYellow(pc.black(pc.bold(' WARNING ')))
            : pc.bgRed(pc.white(pc.bold(' BLOCKED ')));

      // eslint-disable-next-line no-console
      console.log(`\n  Release Decision: ${decisionBadge}\n`);

      // Violations list
      if (gateResult.violations.length > 0) {
        // eslint-disable-next-line no-console
        console.log(pc.bold(pc.red('Policy Violations:')));
        for (const v of gateResult.violations) {
          const actionBadge =
            v.action === 'block_release'
              ? pc.red('BLOCK')
              : v.action === 'warn'
                ? pc.yellow('WARN')
                : pc.blue('APPROVAL');
          // eslint-disable-next-line no-console
          console.log(`  ● [${actionBadge}] ${pc.bold(v.ruleName)}: ${v.reason}`);
          if (v.evidenceRef) {
            // eslint-disable-next-line no-console
            console.log(`    Ref: ${pc.dim(v.evidenceRef)}`);
          }
        }
      } else {
        // eslint-disable-next-line no-console
        console.log(pc.green('✔ Zero policy violations detected. Endpoint satisfies all gate criteria.'));
      }

      // Exit Code evaluation
      const failThreshold = options.failOn.toLowerCase();
      let shouldFail = false;
      if (failThreshold === 'warning') {
        shouldFail = decision === 'failed' || decision === 'warning';
      } else {
        shouldFail = decision === 'failed';
      }

      if (shouldFail) {
        console.error(pc.red(`\n✖ Pipeline execution halted: Release gate failed criteria (${decision.toUpperCase()}).`));
        process.exit(1);
      } else {
        // eslint-disable-next-line no-console
        console.log(pc.green('\n✔ Release gate passed criteria. Proceeding with deployment.'));
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(pc.red(`✖ Release gate evaluation failed: ${msg}`));
      process.exit(1);
    }
  });

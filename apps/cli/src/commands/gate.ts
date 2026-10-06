import fs from 'node:fs';
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
  category?: string;
}

interface WaivedFinding {
  findingId: string;
  fingerprint: string;
  title: string;
  reason: string;
  approvedBy: string;
  expiresAt: string;
}

interface ExpiredWaiver {
  fingerprint: string;
  reason: string;
  approvedBy: string;
  expiresAt: string;
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
    waivedFindings?: WaivedFinding[];
    expiredWaivers?: ExpiredWaiver[];
    evaluatedRulesCount: number;
    timestamp: string;
  };
  policy: Policy;
  evaluatorHash?: string;
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
  .option('--json', 'Output machine-readable JSON to stdout')
  .action(async (options) => {
    try {
      if (!options.json) {
        // eslint-disable-next-line no-console
        console.log(
          pc.cyan(
            `\nEvaluating Release Gate policy for TestRun ${pc.bold(options.run)}...`,
          ),
        );
      }

      const response = await apiClient.post<ReleaseGateEvaluationResponse>(
        '/api/v1/releases/evaluate',
        {
          testRunId: options.run,
          policyId: options.policy,
          name: options.name,
          version: options.version,
        },
      );

      const { decision, score, gateResult, policy, evaluatorHash } = response;
      const waivedFindings = gateResult.waivedFindings || [];
      const expiredWaivers = gateResult.expiredWaivers || [];

      if (options.json) {
        // Machine-readable output
        // eslint-disable-next-line no-console
        console.log(JSON.stringify(response, null, 2));
      } else {
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

        if (evaluatorHash) {
          // eslint-disable-next-line no-console
          console.log(`  Audit Seal Hash:  ${pc.dim(evaluatorHash)}`);
        }

        // Decision Badge
        const decisionBadge =
          decision === 'passed'
            ? pc.bgGreen(pc.white(pc.bold(' PASSED ')))
            : decision === 'warning'
              ? pc.bgYellow(pc.black(pc.bold(' WARNING ')))
              : pc.bgRed(pc.white(pc.bold(' BLOCKED ')));

        // eslint-disable-next-line no-console
        console.log(`\n  Release Decision: ${decisionBadge}\n`);

        // Waived Findings
        if (waivedFindings.length > 0) {
          // eslint-disable-next-line no-console
          console.log(pc.bold(pc.yellow('Approved Finding Waivers (Exemptions):')));
          for (const w of waivedFindings) {
            // eslint-disable-next-line no-console
            console.log(
              pc.yellow(
                `  ⚡ [WAIVED] ${pc.bold(w.title)} (Approver: ${w.approvedBy}, Reason: "${w.reason}", Expires: ${w.expiresAt})`,
              ),
            );
          }
        }

        // Expired Waivers
        if (expiredWaivers.length > 0) {
          // eslint-disable-next-line no-console
          console.log(pc.bold(pc.red('Expired Finding Waivers:')));
          for (const w of expiredWaivers) {
            // eslint-disable-next-line no-console
            console.log(
              pc.red(
                `  ✖ [EXPIRED] Fingerprint: ${pc.dim(w.fingerprint)} (Approver: ${w.approvedBy}, Reason: "${w.reason}", Expired on: ${w.expiresAt})`,
              ),
            );
          }
        }

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
      }

      // Generate GitHub Actions Step Summary if $GITHUB_STEP_SUMMARY is set
      const summaryFile = process.env.GITHUB_STEP_SUMMARY;
      if (summaryFile) {
        try {
          const decisionEmoji = decision === 'passed' ? '✅' : decision === 'warning' ? '⚠️' : '❌';
          let summaryMarkdown = `## ${decisionEmoji} Security Lab — Release Gate Evaluation Summary\n\n`;
          summaryMarkdown += `| Attribute | Details |\n| :--- | :--- |\n`;
          summaryMarkdown += `| **Release Decision** | **${decision.toUpperCase()}** |\n`;
          summaryMarkdown += `| **Policy Evaluated** | ${policy.name} |\n`;
          summaryMarkdown += `| **Security Posture Score** | ${score.score} / 100 (Grade: ${score.grade}) |\n`;
          summaryMarkdown += `| **Rules Evaluated** | ${gateResult.evaluatedRulesCount} |\n`;
          summaryMarkdown += `| **Policy Violations** | ${gateResult.violations.length} |\n`;
          summaryMarkdown += `| **Approved Waivers** | ${waivedFindings.length} |\n`;
          summaryMarkdown += `| **Expired Waivers** | ${expiredWaivers.length} |\n`;
          if (evaluatorHash) {
            summaryMarkdown += `| **Cryptographic Seal** | \`${evaluatorHash}\` |\n`;
          }
          summaryMarkdown += `\n`;

          if (gateResult.violations.length > 0) {
            summaryMarkdown += `### ❌ Policy Violations\n\n`;
            summaryMarkdown += `| Severity | Rule Name | Reason |\n| :--- | :--- | :--- |\n`;
            for (const v of gateResult.violations) {
              summaryMarkdown += `| \`${v.action}\` | **${v.ruleName}** | ${v.reason} |\n`;
            }
            summaryMarkdown += `\n`;
          }

          if (waivedFindings.length > 0) {
            summaryMarkdown += `### ⚡ Approved Finding Waivers\n\n`;
            summaryMarkdown += `| Finding | Approver | Reason | Expires At |\n| :--- | :--- | :--- | :--- |\n`;
            for (const w of waivedFindings) {
              summaryMarkdown += `| ${w.title} | ${w.approvedBy} | ${w.reason} | ${w.expiresAt} |\n`;
            }
            summaryMarkdown += `\n`;
          }

          fs.appendFileSync(summaryFile, summaryMarkdown, 'utf8');
        } catch (summaryErr) {
          console.error(pc.yellow(`Warning: Failed to write to GITHUB_STEP_SUMMARY: ${String(summaryErr)}`));
        }
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
        if (!options.json) {
          // eslint-disable-next-line no-console
          console.log(pc.green('\n✔ Release gate passed criteria. Proceeding with deployment.'));
        }
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(pc.red(`✖ Release gate evaluation failed: ${msg}`));
      process.exit(1);
    }
  });


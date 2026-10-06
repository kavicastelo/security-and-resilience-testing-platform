import fs from 'node:fs';
import path from 'node:path';
import { Command } from 'commander';
import pc from 'picocolors';
import { apiClient } from '../api/client.js';
import { parseOpenApiSpec, evaluateOpenApiContractRules } from '@security-lab/domain';

interface ContractVerificationFinding {
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  category: string;
  recommendation?: string;
  metadata?: Record<string, unknown>;
  evidence?: {
    expected?: string;
    actual?: string;
  };
}

interface ContractVerificationMetric {
  name: string;
  value: number;
  unit: string;
}

interface ContractVerificationResult {
  engineId: string;
  durationMs: number;
  success: boolean;
  findings: ContractVerificationFinding[];
  metrics: ContractVerificationMetric[];
  error?: string;
  rawOutput?: {
    title: string;
    version: string;
    endpointsCount: number;
    contractViolations: number;
    fuzzServerErrors: number;
  };
}

function formatSeverity(sev: string): string {
  switch (sev.toLowerCase()) {
    case 'critical':
      return pc.bgRed(pc.white(pc.bold(' CRITICAL ')));
    case 'high':
      return pc.red(pc.bold(' HIGH '));
    case 'medium':
      return pc.yellow(pc.bold(' MEDIUM '));
    case 'low':
      return pc.blue(pc.bold(' LOW '));
    default:
      return pc.dim(' INFO ');
  }
}

const SEVERITY_LEVELS: Record<string, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export const contractCommand = new Command('contract')
  .description('Audit OpenAPI specifications, verify security contracts, and fuzz schemas');

contractCommand
  .command('verify')
  .description('Verify security contracts and fuzz request bodies against an OpenAPI specification')
  .requiredOption('-s, --spec <pathOrUrl>', 'Path to local OpenAPI YAML/JSON file or remote URL')
  .option('-t, --target <targetUrl>', 'Target base URL for runtime verification and schema fuzzing')
  .option('--no-fuzz', 'Disable active negative schema fuzzing (perform static contract audit only)')
  .option('--fail-on <severity>', 'Fail exit code threshold (critical, high, medium, low)', 'high')
  .action(async (options) => {
    // eslint-disable-next-line no-console
    console.log(pc.bold(pc.cyan('\n🛡️ Security Lab — OpenAPI Security Contract Verification')));
    // eslint-disable-next-line no-console
    console.log(pc.dim('─'.repeat(65)));
    // eslint-disable-next-line no-console
    console.log(`Spec Source : ${pc.bold(options.spec)}`);
    if (options.target) {
      // eslint-disable-next-line no-console
      console.log(`Target URL  : ${pc.bold(options.target)}`);
    } else {
      // eslint-disable-next-line no-console
      console.log(`Target URL  : ${pc.dim('[None provided — static contract audit mode]')}`);
    }
    // eslint-disable-next-line no-console
    console.log(pc.dim('─'.repeat(65)) + '\n');

    const isUrl = options.spec.startsWith('http://') || options.spec.startsWith('https://');
    let specContent: string | undefined;

    if (!isUrl) {
      const resolvedPath = path.resolve(process.cwd(), options.spec);
      if (!fs.existsSync(resolvedPath)) {
        console.error(pc.red(`✖ Specification file not found: ${resolvedPath}`));
        process.exit(1);
      }
      try {
        specContent = fs.readFileSync(resolvedPath, 'utf-8');
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        console.error(pc.red(`✖ Failed to read specification file: ${msg}`));
        process.exit(1);
      }
    }

    let result: ContractVerificationResult;

    try {
      result = await apiClient.post<ContractVerificationResult>('/api/v1/contracts/verify', {
        spec: specContent,
        specUrl: isUrl ? options.spec : undefined,
        targetUrl: options.target,
        options: {
          fuzzing: options.fuzz !== false,
        },
      });
    } catch {
      // Local in-process fallback using @security-lab/domain
      if (!specContent && isUrl) {
        try {
          const fetchRes = await fetch(options.spec);
          specContent = await fetchRes.text();
        } catch (err: unknown) {
          const msg = err instanceof Error ? err.message : String(err);
          console.error(pc.red(`✖ Failed to fetch OpenAPI spec from ${options.spec}: ${msg}`));
          process.exit(1);
        }
      }

      if (!specContent) {
        console.error(pc.red('✖ No specification content available to verify'));
        process.exit(1);
      }

      const startTime = Date.now();
      try {
        const inventory = parseOpenApiSpec(specContent);
        const violations = evaluateOpenApiContractRules(inventory);
        const durationMs = Date.now() - startTime;

        result = {
          engineId: 'engine-native-contract',
          durationMs,
          success: true,
          findings: violations.map((v) => ({
            title: v.title,
            description: v.description,
            severity: v.severity,
            category: 'compliance',
            recommendation: v.recommendation,
          })),
          metrics: [
            { name: 'openapi_endpoints_count', value: inventory.endpoints.length, unit: 'endpoints' },
            { name: 'contract_violations_count', value: violations.length, unit: 'violations' },
          ],
          rawOutput: {
            title: inventory.title,
            version: inventory.version,
            endpointsCount: inventory.endpoints.length,
            contractViolations: violations.length,
            fuzzServerErrors: 0,
          },
        };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        console.error(pc.red(`\n✖ Contract verification failed: ${msg}`));
        process.exit(1);
      }
    }

    if (!result.success) {
      console.error(pc.red(`\n✖ Contract verification failed: ${result.error || 'Unknown error'}`));
      process.exit(1);
    }

    // eslint-disable-next-line no-console
    console.log(pc.bold(pc.green(`✔ Verification finished in ${result.durationMs}ms`)));

    // Print Metrics
    if (result.metrics && result.metrics.length > 0) {
      // eslint-disable-next-line no-console
      console.log(pc.bold(pc.cyan('\nAudit Metrics:')));
      for (const m of result.metrics) {
        // eslint-disable-next-line no-console
        console.log(`  ● ${m.name}: ${pc.bold(String(m.value))} ${pc.dim(m.unit)}`);
      }
    }

    // Print Findings
    const findings = result.findings || [];
    if (findings.length === 0) {
      // eslint-disable-next-line no-console
      console.log(pc.bold(pc.green('\n✔ All API security contracts verified! Zero violations detected.\n')));
      process.exit(0);
    }

    // eslint-disable-next-line no-console
    console.log(pc.bold(pc.yellow(`\nContract Violations & Findings (${findings.length}):`)));

    for (const f of findings) {
      // eslint-disable-next-line no-console
      console.log(`\n  ${formatSeverity(f.severity)} ${pc.bold(f.title)}`);
      // eslint-disable-next-line no-console
      console.log(`    ${pc.dim(f.description)}`);
      if (f.recommendation) {
        // eslint-disable-next-line no-console
        console.log(`    ${pc.cyan('Fix:')} ${f.recommendation}`);
      }
    }

    // Threshold evaluation
    const thresholdLevel = SEVERITY_LEVELS[options.failOn.toLowerCase()] ?? 3;
    const hasThresholdBreach = findings.some(
      (f) => (SEVERITY_LEVELS[f.severity.toLowerCase()] ?? 0) >= thresholdLevel,
    );

    // eslint-disable-next-line no-console
    console.log('');
    if (hasThresholdBreach) {
      console.error(
        pc.bold(
          pc.red(
            `✖ Contract verification failed threshold: Found findings matching or exceeding [${options.failOn.toUpperCase()}].`,
          ),
        ),
      );
      process.exit(1);
    } else {
      // eslint-disable-next-line no-console
      console.log(pc.green(`✔ No findings exceeded failure threshold [${options.failOn.toUpperCase()}].`));
      process.exit(0);
    }
  });

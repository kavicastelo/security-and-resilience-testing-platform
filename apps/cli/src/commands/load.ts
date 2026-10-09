import { Command } from 'commander';
import pc from 'picocolors';
import { apiClient } from '../api/client.js';
import { formatCliError } from '../output/formatters.js';
import { TestRun, Finding, FindingSeverity, Metric } from '@security-lab/domain';

interface TestRunExecutionResponse {
  testRun: TestRun;
  executions: {
    id: string;
    engineId: string;
    status: string;
    durationMs?: number;
    error?: string;
  }[];
  findings: Finding[];
}

function formatSeverityBadge(severity: FindingSeverity): string {
  switch (severity) {
    case 'critical':
      return pc.bgRed(pc.white(pc.bold(' CRITICAL ')));
    case 'high':
      return pc.red(pc.bold(' HIGH '));
    case 'medium':
      return pc.yellow(pc.bold(' MEDIUM '));
    case 'low':
      return pc.blue(pc.bold(' LOW '));
    case 'info':
      return pc.cyan(' INFO ');
    default:
      return severity;
  }
}

export const loadCommand = new Command('load')
  .description('Class C Resilience & Load Testing (Grafana k6 SLA audits & Rate Limiting)');

// Subcommand: run (Grafana k6 load & latency SLA audit)
loadCommand
  .command('run')
  .description('Dispatch Class C concurrent load test and verify latency SLAs (p95/p99)')
  .requiredOption('-p, --project <projectId>', 'Project ID')
  .requiredOption('-t, --target <targetId>', 'Target ID')
  .option('--vus <number>', 'Number of concurrent virtual users (VUs)', '5')
  .option('--duration <seconds>', 'Test duration in seconds', '3')
  .option('--sla-p95 <ms>', 'P95 response latency SLA threshold in milliseconds', '500')
  .option('--fail-on-sla', 'Exit with non-zero code if latency SLA is breached', false)
  .action(async (options) => {
    try {
      const vus = parseInt(options.vus, 10);
      const durationSec = parseInt(options.duration, 10);
      const maxP95Ms = parseInt(options.slaP95, 10);

      // eslint-disable-next-line no-console
      console.log(
        pc.cyan(
          `\nInitiating Class C Load & Latency SLA test for target ${pc.bold(options.target)}...`,
        ),
      );
      // eslint-disable-next-line no-console
      console.log(
        `Configured workload: ${pc.bold(vus)} VUs | Duration: ${pc.bold(durationSec)}s | P95 SLA: ≤${pc.bold(maxP95Ms)}ms`,
      );

      // 1. Create TestRun
      const run = await apiClient.post<TestRun>('/api/v1/test-runs', {
        projectId: options.project,
        targetId: options.target,
        profileId: 'k6',
        triggeredBy: 'manual',
        metadata: {
          vus,
          durationSec,
          maxP95Ms,
        },
      });

      // eslint-disable-next-line no-console
      console.log(`TestRun created [ID: ${pc.dim(run.id)}] - Spawning Class C worker...`);

      // 2. Execute (synchronous wait mode)
      const result = await apiClient.post<TestRunExecutionResponse>(`/api/v1/test-runs/${run.id}/execute?wait=true`, {
        engineIds: ['engine-worker-k6'],
        options: {
          vus,
          durationSec,
          maxP95Ms,
        },
      });

      const { testRun, executions, findings } = result;

      // 3. Fetch quantitative metrics
      const metrics = await apiClient.get<Metric[]>(`/api/v1/test-runs/${run.id}/metrics`);
      const metricMap: Record<string, number> = {};
      for (const m of metrics) {
        metricMap[m.name] = m.value;
      }

      // eslint-disable-next-line no-console
      console.log(pc.bold(pc.cyan('\nWorker Execution Summary:')));
      for (const exec of executions) {
        const statusBadge =
          exec.status === 'completed'
            ? pc.green('PASSED')
            : exec.status === 'failed'
              ? pc.red('FAILED')
              : pc.yellow(exec.status);
        // eslint-disable-next-line no-console
        console.log(`  ● [${statusBadge}] ${pc.bold(exec.engineId)} (${exec.durationMs ?? 0}ms)`);
        if (exec.error) {
          // eslint-disable-next-line no-console
          console.log(`    ${pc.red(`Error: ${exec.error}`)}`);
        }
      }

      // eslint-disable-next-line no-console
      console.log(pc.bold(pc.cyan('\nQuantitative Latency & Performance SLA Metrics:')));
      const p95 = metricMap['http_req_duration_p95'] ?? 0;
      const p99 = metricMap['http_req_duration_p99'] ?? 0;
      const med = metricMap['http_req_duration_med'] ?? 0;
      const avg = metricMap['http_req_duration_avg'] ?? 0;
      const max = metricMap['http_req_duration_max'] ?? 0;
      const rps = metricMap['http_rps'] ?? 0;
      const totalReqs = metricMap['http_reqs_total'] ?? 0;
      const failedRatio = metricMap['http_req_failed_ratio'] ?? 0;

      // eslint-disable-next-line no-console
      console.log(`  Requests Processed:  ${pc.bold(totalReqs)} requests (${pc.bold(rps)} req/sec)`);
      // eslint-disable-next-line no-console
      console.log(`  Failed Requests:     ${failedRatio > 0 ? pc.red(`${failedRatio}%`) : pc.green('0%')}`);
      // eslint-disable-next-line no-console
      console.log(`  Median (p50):        ${med} ms`);
      // eslint-disable-next-line no-console
      console.log(`  Average:             ${avg} ms`);
      // eslint-disable-next-line no-console
      console.log(
        `  P95 Latency:         ${p95 > maxP95Ms ? pc.red(pc.bold(`${p95} ms`)) : pc.green(pc.bold(`${p95} ms`))} (SLA: ≤${maxP95Ms} ms)`,
      );
      // eslint-disable-next-line no-console
      console.log(`  P99 Latency:         ${p99} ms`);
      // eslint-disable-next-line no-console
      console.log(`  Max Latency:         ${max} ms`);

      const slaBreached = p95 > maxP95Ms;
      // eslint-disable-next-line no-console
      console.log('\nSLA Compliance Verdict:');
      if (slaBreached) {
        // eslint-disable-next-line no-console
        console.log(
          pc.red(
            pc.bold(`  ✖ SLA BREACH: P95 latency (${p95}ms) exceeded SLA threshold of ${maxP95Ms}ms.`),
          ),
        );
      } else {
        // eslint-disable-next-line no-console
        console.log(
          pc.green(
            pc.bold(`  ✔ SLA SATISFIED: P95 latency (${p95}ms) met SLA threshold of ≤${maxP95Ms}ms.`),
          ),
        );
      }

      if (findings.length > 0) {
        // eslint-disable-next-line no-console
        console.log(pc.bold(pc.cyan('\nResilience & Performance Findings:')));
        for (const f of findings) {
          // eslint-disable-next-line no-console
          console.log(`\n  ${formatSeverityBadge(f.severity)} ${pc.bold(f.title)}`);
          // eslint-disable-next-line no-console
          console.log(`    Category:       ${pc.dim(f.category)}`);
          // eslint-disable-next-line no-console
          console.log(`    Description:    ${f.description}`);
          if (f.recommendation) {
            // eslint-disable-next-line no-console
            console.log(`    Remediation:    ${pc.green(f.recommendation)}`);
          }
        }
      }

      if ((options.failOnSla && slaBreached) || testRun.status === 'failed') {
        process.exit(1);
      }
    } catch (err: unknown) {
      console.error(formatCliError(err, 'Load test execution failed'));
      process.exit(1);
    }
  });

// Subcommand: rate-limit (Native resilience burst audit)
loadCommand
  .command('rate-limit')
  .description('Audit endpoint throttling defenses against rapid burst requests')
  .requiredOption('-p, --project <projectId>', 'Project ID')
  .requiredOption('-t, --target <targetId>', 'Target ID')
  .option('--fail-on-missing', 'Fail exit code if rate limiting headers/throttling are absent', false)
  .action(async (options) => {
    try {
      // eslint-disable-next-line no-console
      console.log(
        pc.cyan(
          `\nInitiating API Rate Limiting & Throttling audit for target ${pc.bold(options.target)}...`,
        ),
      );

      // 1. Create TestRun
      const run = await apiClient.post<TestRun>('/api/v1/test-runs', {
        projectId: options.project,
        targetId: options.target,
        profileId: 'rate-limit',
        triggeredBy: 'manual',
      });

      // 2. Execute (synchronous wait mode)
      const result = await apiClient.post<TestRunExecutionResponse>(`/api/v1/test-runs/${run.id}/execute?wait=true`, {
        engineIds: ['engine-native-resilience'],
      });

      const { testRun, findings } = result;

      // 3. Fetch quantitative metrics
      const metrics = await apiClient.get<Metric[]>(`/api/v1/test-runs/${run.id}/metrics`);
      const metricMap: Record<string, number> = {};
      for (const m of metrics) {
        metricMap[m.name] = m.value;
      }

      const rateLimitEnforced = (metricMap['rate_limiting_enforced'] ?? 0) === 1;
      const burstTotal = metricMap['burst_requests_evaluated'] ?? 0;

      // eslint-disable-next-line no-console
      console.log(pc.bold(pc.cyan('\nRate Limit Audit Summary:')));
      // eslint-disable-next-line no-console
      console.log(`  Burst Requests Evaluated: ${burstTotal}`);
      // eslint-disable-next-line no-console
      console.log(
        `  Rate Limiting Enforced:   ${
          rateLimitEnforced ? pc.green(pc.bold('YES (429 or X-RateLimit headers)')) : pc.yellow(pc.bold('NO (Missing rate limits)'))
        }`,
      );

      if (findings.length > 0) {
        // eslint-disable-next-line no-console
        console.log(pc.bold(pc.cyan('\nFindings:')));
        for (const f of findings) {
          // eslint-disable-next-line no-console
          console.log(`\n  ${formatSeverityBadge(f.severity)} ${pc.bold(f.title)}`);
          // eslint-disable-next-line no-console
          console.log(`    Category:       ${pc.dim(f.category)}`);
          // eslint-disable-next-line no-console
          console.log(`    Description:    ${f.description}`);
          if (f.recommendation) {
            // eslint-disable-next-line no-console
            console.log(`    Remediation:    ${pc.green(f.recommendation)}`);
          }
        }
      }

      if ((options.failOnMissing && !rateLimitEnforced) || testRun.status === 'failed') {
        process.exit(1);
      }
    } catch (err: unknown) {
      console.error(formatCliError(err, 'Rate limit audit failed'));
      process.exit(1);
    }
  });

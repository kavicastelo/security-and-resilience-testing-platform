import crypto from 'node:crypto';
import http from 'node:http';
import https from 'node:https';
import dns from 'node:dns/promises';
import { Command } from 'commander';
import pc from 'picocolors';
import { apiClient } from '../api/client.js';
import { createSpinner } from '../output/spinner.js';
import { renderSummaryBox } from '../output/table.js';
import { formatSuccess, formatError } from '../output/formatters.js';

export interface VerifyOptions {
  target?: string;
  url?: string;
  method?: 'http-token' | 'dns-txt';
  token?: string;
  pollInterval?: string;
  maxAttempts?: string;
  offline?: boolean;
}

export const verifyCommand = new Command('verify')
  .description('Verify ownership and authorization proof for a target scope (DNS TXT or HTTP token challenge)')
  .option('-t, --target <targetId>', 'Target ID in Security Lab Controller')
  .option('-u, --url <url>', 'Target base URL to verify', 'http://localhost:3000')
  .option('-m, --method <method>', 'Verification proof method: http-token or dns-txt', 'http-token')
  .option('--token <token>', 'Verification challenge token (auto-generated if omitted)')
  .option('--poll-interval <ms>', 'Polling interval in milliseconds', '1500')
  .option('--max-attempts <n>', 'Maximum polling attempts before timeout', '5')
  .option('--offline', 'Verify locally via direct HTTP/DNS probe without contacting controller', false)
  .action(async (options: VerifyOptions) => {
    try {
      const method = options.method === 'dns-txt' ? 'dns-txt' : 'http-token';
      const targetUrl = options.url || 'http://localhost:3000';
      const parsedUrl = new URL(targetUrl);
      const token = options.token || `sec-lab-proof-${crypto.randomBytes(8).toString('hex')}`;
      const pollInterval = parseInt(options.pollInterval || '1500', 10);
      const maxAttempts = parseInt(options.maxAttempts || '5', 10);

      // eslint-disable-next-line no-console
      console.log(pc.bold(pc.cyan('\n🛡️  Security Lab — Target Scope Verification Wizard\n')));

      // eslint-disable-next-line no-console
      console.log(
        renderSummaryBox('Target Ownership Challenge', [
          { label: 'Target URL', value: targetUrl },
          { label: 'Domain / Host', value: parsedUrl.hostname },
          { label: 'Verification Method', value: method === 'dns-txt' ? 'DNS TXT Record' : 'HTTP Well-Known Token' },
          { label: 'Challenge Token', value: token },
        ]),
      );

      // Print step-by-step instructions
      // eslint-disable-next-line no-console
      console.log(pc.bold('\nVerification Instructions:'));
      if (method === 'http-token') {
        const challengePath = `${targetUrl.replace(/\/$/, '')}/.well-known/security-lab-challenge`;
        // eslint-disable-next-line no-console
        console.log(`  1. Expose an HTTP endpoint on your application:`);
        // eslint-disable-next-line no-console
        console.log(`     ${pc.cyan('GET')} ${pc.bold(challengePath)}`);
        // eslint-disable-next-line no-console
        console.log(`  2. Return the challenge token in the response body:`);
        // eslint-disable-next-line no-console
        console.log(`     ${pc.green(token)}`);
      } else {
        const txtRecordName = `_security-lab-challenge.${parsedUrl.hostname}`;
        // eslint-disable-next-line no-console
        console.log(`  1. Add a DNS TXT record in your DNS provider:`);
        // eslint-disable-next-line no-console
        console.log(`     Name:  ${pc.bold(pc.cyan(txtRecordName))}`);
        // eslint-disable-next-line no-console
        console.log(`     Value: ${pc.green(token)}`);
      }

      // eslint-disable-next-line no-console
      console.log('');
      const spinner = createSpinner('Starting target ownership verification polling...').start();

      let verified = false;
      let lastError = '';

      for (let attempt = 1; attempt <= maxAttempts; attempt++) {
        spinner.update(`Polling verification proof (attempt ${attempt}/${maxAttempts})...`);

        if (options.target && !options.offline) {
          try {
            interface TargetVerifyResponse {
              verified: boolean;
              method: string;
              message?: string;
            }
            const res = await apiClient.post<TargetVerifyResponse>(
              `/api/v1/targets/${options.target}/verify-proof`,
              { method, token },
            );
            if (res.verified) {
              verified = true;
              break;
            }
            lastError = res.message || 'Proof not found';
          } catch (apiErr: unknown) {
            lastError = apiErr instanceof Error ? apiErr.message : String(apiErr);
          }
        } else {
          // Direct local probe
          if (method === 'http-token') {
            const checkUrl = `${targetUrl.replace(/\/$/, '')}/.well-known/security-lab-challenge`;
            try {
              const client = parsedUrl.protocol === 'https:' ? https : http;
              const result = await new Promise<{ status: number; body: string }>((resolve, reject) => {
                const req = client.get(checkUrl, { timeout: 3000 }, (res) => {
                  let data = '';
                  res.on('data', (chunk) => {
                    data += chunk;
                  });
                  res.on('end', () => resolve({ status: res.statusCode || 0, body: data }));
                });
                req.on('error', reject);
                req.on('timeout', () => {
                  req.destroy();
                  reject(new Error('Connection timed out'));
                });
              });

              if (result.status === 200 && result.body.includes(token)) {
                verified = true;
                break;
              } else {
                lastError = `HTTP ${result.status}: Token mismatch or endpoint not ready`;
              }
            } catch (err: unknown) {
              lastError = err instanceof Error ? err.message : String(err);
            }
          } else {
            // DNS TXT Probe
            try {
              const txtRecords = await dns.resolveTxt(`_security-lab-challenge.${parsedUrl.hostname}`);
              const flatRecords = txtRecords.flat();
              if (flatRecords.some((rec) => rec.includes(token))) {
                verified = true;
                break;
              } else {
                lastError = `DNS record did not contain token "${token}"`;
              }
            } catch (err: unknown) {
              lastError = err instanceof Error ? err.message : String(err);
            }
          }
        }

        if (attempt < maxAttempts) {
          await new Promise((resolve) => setTimeout(resolve, pollInterval));
        }
      }

      if (verified) {
        spinner.succeed(`Target ownership verified successfully! Scope authorized.`);
        // eslint-disable-next-line no-console
        console.log(`\n${formatSuccess(`Ownership confirmed for: ${pc.bold(targetUrl)}`)}`);
        // eslint-disable-next-line no-console
        console.log(`  Security and resilience tests may now be executed against this scope.\n`);
        process.exit(0);
      } else {
        spinner.fail(`Target ownership verification timed out after ${maxAttempts} attempts.`);
        // eslint-disable-next-line no-console
        console.log(`\n${formatError(`Verification failed: ${lastError}`)}`);
        // eslint-disable-next-line no-console
        console.log(`  Please ensure your endpoint or DNS record is properly configured and accessible.\n`);
        process.exit(1);
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(formatError(`Target verification encountered an unexpected error: ${msg}`));
      process.exit(2);
    }
  });

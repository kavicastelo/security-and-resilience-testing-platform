import crypto from 'node:crypto';
import {
  TestEngine,
  TestCapability,
  ExecutionContext,
  TestInput,
  TestResult,
  ValidationResult,
  RawEngineFinding,
  RawEngineMetric,
  dynamicWorkerEngineRegistry,
} from '@security-lab/engine-sdk';
import { validateUrlAgainstScope } from '@security-lab/domain';
import { createLogger } from '@security-lab/logger';
import {
  SmugglingEngineOptions,
  SmugglingEngineOptionsSchema,
  RawSocketEvidence,
  SmugglingExecutionSummary,
} from './types.js';
import { rawSocketSender, formatHexDump } from './socket-sender.js';
import {
  buildClTeTimingPayload,
  buildClTeDualPayloads,
  buildTeClTimingPayload,
  buildTeClDualPayloads,
  buildTeTeVariants,
  buildHostPoisoningPayload,
  buildHopByHopPayload,
} from './payloads.js';

export * from './types.js';
export * from './socket-sender.js';
export * from './payloads.js';

const logger = createLogger({ name: 'engine-http-smuggling' });

export class HttpSmugglingEngine implements TestEngine {
  readonly id = 'engine-http-smuggling';
  readonly version = '1.0.0';
  readonly executionClass = 'class_a_native' as const;

  capabilities(): TestCapability[] {
    return [
      {
        id: 'http_smuggling_cl_te',
        name: 'HTTP Request Smuggling (CL.TE) Detection',
        category: 'protocol_audit',
        description:
          'Verifies whether front-end proxy uses Content-Length and back-end uses Transfer-Encoding, permitting request smuggling and prefix hijacking.',
        isDisruptive: false,
      },
      {
        id: 'http_smuggling_te_cl',
        name: 'HTTP Request Smuggling (TE.CL) Detection',
        category: 'protocol_audit',
        description:
          'Verifies whether front-end proxy uses Transfer-Encoding and back-end uses Content-Length, permitting request desynchronization.',
        isDisruptive: false,
      },
      {
        id: 'http_smuggling_te_te',
        name: 'HTTP Request Smuggling (TE.TE) Obfuscation Verification',
        category: 'protocol_audit',
        description:
          'Fuzzes malformed Transfer-Encoding header variants to determine if either proxy or server mishandles obfuscated headers.',
        isDisruptive: false,
      },
      {
        id: 'reverse_proxy_host_poisoning',
        name: 'Reverse Proxy Host & Forwarded Header Poisoning',
        category: 'protocol_audit',
        description:
          'Detects whether upstream reverse proxies reflect unvalidated Host or X-Forwarded-Host headers into cacheable redirects or HTML base tags.',
        isDisruptive: false,
      },
      {
        id: 'hop_by_hop_header_manipulation',
        name: 'Hop-by-Hop Header Stripping & Bypass',
        category: 'protocol_audit',
        description:
          'Tests whether custom headers listed in Connection header are stripped by intermediate proxies, potentially bypassing access controls.',
        isDisruptive: false,
      },
    ];
  }

  validate(input: TestInput): ValidationResult {
    try {
      const url = new URL(input.targetUrl);
      if (url.protocol !== 'http:' && url.protocol !== 'https:') {
        return {
          valid: false,
          errors: [{ path: 'targetUrl', message: 'Target URL must use http: or https: protocol' }],
        };
      }
      return { valid: true };
    } catch {
      return {
        valid: false,
        errors: [{ path: 'targetUrl', message: 'Invalid target URL format' }],
      };
    }
  }

  async execute(input: TestInput, context: ExecutionContext): Promise<TestResult> {
    const startTime = Date.now();
    const findings: RawEngineFinding[] = [];
    const metrics: RawEngineMetric[] = [];
    const evidenceList: RawSocketEvidence[] = [];

    // Parse and validate target URL
    const targetUrlObj = new URL(input.targetUrl);
    const host = targetUrlObj.hostname;
    const useTls = targetUrlObj.protocol === 'https:';
    const port = targetUrlObj.port ? parseInt(targetUrlObj.port, 10) : useTls ? 443 : 80;
    const basePath = targetUrlObj.pathname && targetUrlObj.pathname !== '' ? targetUrlObj.pathname : '/';

    // Target Scope Verification (Rule 2 Compliance)
    if (context.target?.scope) {
      const scopeResult = validateUrlAgainstScope(input.targetUrl, context.target.scope as any);
      if (!scopeResult.valid) {
        logger.warn(
          { targetUrl: input.targetUrl, violations: scopeResult.violations },
          'Target URL is outside authorized scope. Halting HTTP smuggling execution.',
        );
        return {
          engineId: this.id,
          success: false,
          durationMs: Date.now() - startTime,
          findings: [],
          metrics: [],
          error: `Execution prohibited: Target URL "${input.targetUrl}" is not within authorized scope. Violations: ${scopeResult.violations.join(', ')}`,
        };
      }
    }

    const optionsParsed = SmugglingEngineOptionsSchema.safeParse(input.options || {});
    const options: SmugglingEngineOptions = optionsParsed.success
      ? optionsParsed.data
      : SmugglingEngineOptionsSchema.parse({});

    const canaryPath = options.canaryPath || '/robots.txt';
    const normalPath = options.normalPath || basePath;
    const poisonCanaryHost = options.poisonCanaryHost || 'canary.internal.testing';
    const timingThreshold = options.timingDelayThresholdMs || 1500;
    const timeoutMs = options.timeoutMs || 5000;
    const techniques =
      options.techniques && options.techniques.length > 0
        ? options.techniques
        : ['CL_TE', 'TE_CL', 'TE_TE', 'HOST_POISONING', 'HOP_BY_HOP'];

    let probesDispatched = 0;
    let variantsTestedCount = 0;
    const variantsTested: string[] = [];
    const latencies: number[] = [];

    logger.info(
      { host, port, useTls, normalPath, canaryPath },
      'Starting HTTP Request Smuggling and reverse proxy verification scan',
    );

    context.reportProgress?.(10, 'Establishing baseline socket connectivity');

    // Baseline connectivity probe
    const baselinePayload = `GET ${normalPath} HTTP/1.1\r\nHost: ${host}\r\nConnection: close\r\n\r\n`;
    probesDispatched++;
    const baselineResp = await rawSocketSender.sendRawPayload({
      host,
      port,
      useTls,
      payload: baselinePayload,
      timeoutMs,
      allowSelfSignedTls: options.allowSelfSignedTls,
    });
    latencies.push(baselineResp.latencyMs);

    // 1 & 2. CL.TE Smuggling Probes
    if (techniques.includes('CL_TE')) {
      context.reportProgress?.(25, 'Testing CL.TE dual-request desynchronization');
      variantsTested.push('CL_TE_DUAL_REQUEST');
      variantsTestedCount++;

      const clTeDual = buildClTeDualPayloads({
        host,
        port,
        path: normalPath,
        canaryPath,
      });

      probesDispatched += 2;
      const clTeDualResult = await rawSocketSender.sendDualPayloads({
        host,
        port,
        useTls,
        firstPayload: clTeDual.firstPayload,
        secondPayload: clTeDual.secondPayload,
        delayBetweenMs: 50,
        timeoutMs,
        allowSelfSignedTls: options.allowSelfSignedTls,
      });
      latencies.push(clTeDualResult.latencyMs);

      const firstRawText = clTeDualResult.firstResponse?.rawBuffer.toString('utf-8') || '';
      const secondRawText = clTeDualResult.secondResponse?.rawBuffer.toString('utf-8') || '';
      const combinedResponses = `${firstRawText}\n${secondRawText}`;

      // Desynchronization indicator: Canary marker appears in subsequent response or 404 canary reflection
      const clTeDesync =
        combinedResponses.includes(clTeDual.canaryMarker) ||
        (clTeDualResult.firstResponse?.statusCode === 200 &&
          combinedResponses.includes(`X-Canary-Check: ${clTeDual.canaryMarker}`)) ||
        (secondRawText.includes('404') && !firstRawText.includes('404') && combinedResponses.includes('canary-'));

      if (clTeDesync) {
        const evidenceHash = crypto
          .createHash('sha256')
          .update(clTeDual.firstPayload)
          .update(clTeDualResult.firstResponse?.rawBuffer || Buffer.alloc(0))
          .digest('hex');

        evidenceList.push({
          technique: 'CL_TE',
          variantId: 'cl_te_prefix_desync',
          requestSent: clTeDual.firstPayload.toString('utf-8'),
          requestHexDump: formatHexDump(clTeDual.firstPayload),
          responseReceived: combinedResponses,
          responseHexDump: formatHexDump(clTeDualResult.firstResponse?.rawBuffer || Buffer.alloc(0)),
          statusCode: clTeDualResult.firstResponse?.statusCode,
          latencyMs: clTeDualResult.latencyMs,
          evidenceHash,
        });

        findings.push({
          title: 'Critical HTTP Request Smuggling Vulnerability (CL.TE)',
          description:
            'The front-end proxy prioritized Content-Length while the back-end application server prioritized Transfer-Encoding. An unauthenticated attacker can smuggle arbitrary HTTP requests, hijack other users sessions, and poison reverse proxy caches.',
          severity: 'critical',
          category: 'protocol_audit',
          recommendation:
            'Ensure both the front-end reverse proxy and back-end application servers parse HTTP/1.1 headers identically (disable Transfer-Encoding or normalize duplicate headers to RFC 7230 compliance), or mandate HTTP/2 end-to-end.',
          evidence: {
            request: {
              url: new URL(normalPath, input.targetUrl).toString(),
              method: 'POST',
              headers: {
                Host: host,
                'Transfer-Encoding': 'chunked',
                'Content-Length': String(Buffer.byteLength(clTeDual.firstPayload)),
              },
              body: clTeDual.firstPayload.toString('utf-8'),
            },
            response: {
              statusCode: clTeDualResult.firstResponse?.statusCode ?? 200,
              headers: clTeDualResult.firstResponse?.headers ?? {},
              body: combinedResponses,
              responseTimeMs: clTeDualResult.latencyMs,
            },
            immutableHash: evidenceHash,
            metadata: {
              technique: 'CL_TE',
              canaryMarker: clTeDual.canaryMarker,
              evidenceHash,
            },
          },
        });
      }

      // CL.TE Timing Probe
      context.reportProgress?.(40, 'Testing CL.TE differential timing probe');
      variantsTested.push('CL_TE_TIMING');
      variantsTestedCount++;

      const clTeTimingPayload = buildClTeTimingPayload({ host, port, path: normalPath, canaryPath });
      probesDispatched++;
      const clTeTimingResult = await rawSocketSender.sendRawPayload({
        host,
        port,
        useTls,
        payload: clTeTimingPayload,
        timeoutMs,
        allowSelfSignedTls: options.allowSelfSignedTls,
      });
      latencies.push(clTeTimingResult.latencyMs);

      if (
        clTeTimingResult.timedOut ||
        (clTeTimingResult.latencyMs > timingThreshold && baselineResp.latencyMs < timingThreshold / 2)
      ) {
        const evidenceHash = crypto
          .createHash('sha256')
          .update(clTeTimingPayload)
          .update(clTeTimingResult.rawBuffer)
          .digest('hex');

        findings.push({
          title: 'Potential HTTP Request Smuggling (CL.TE Timing Discrepancy)',
          description: `The target server exhibited significant timing delay (${clTeTimingResult.latencyMs}ms vs ${baselineResp.latencyMs}ms baseline) when presented with a CL.TE payload, indicating the back-end server stalled awaiting chunk data under Transfer-Encoding.`,
          severity: 'high',
          category: 'protocol_audit',
          recommendation:
            'Configure upstream load balancers to reject ambiguous requests containing both Content-Length and Transfer-Encoding headers.',
          evidence: {
            request: {
              url: new URL(normalPath, input.targetUrl).toString(),
              method: 'POST',
              headers: {
                Host: host,
                'Transfer-Encoding': 'chunked',
                'Content-Length': '4',
              },
              body: clTeTimingPayload.toString('utf-8'),
            },
            response: {
              statusCode: clTeTimingResult.statusCode ?? 0,
              headers: clTeTimingResult.headers,
              body: clTeTimingResult.rawHeaders,
              responseTimeMs: clTeTimingResult.latencyMs,
            },
            immutableHash: evidenceHash,
            metadata: {
              latencyMs: clTeTimingResult.latencyMs,
              baselineLatencyMs: baselineResp.latencyMs,
              timedOut: clTeTimingResult.timedOut,
              evidenceHash,
            },
          },
        });
      }
    }

    // 3 & 4. TE.CL Smuggling Probes
    if (techniques.includes('TE_CL')) {
      context.reportProgress?.(55, 'Testing TE.CL dual-request desynchronization');
      variantsTested.push('TE_CL_DUAL_REQUEST');
      variantsTestedCount++;

      const teClDual = buildTeClDualPayloads({
        host,
        port,
        path: normalPath,
        canaryPath,
      });

      probesDispatched += 2;
      const teClDualResult = await rawSocketSender.sendDualPayloads({
        host,
        port,
        useTls,
        firstPayload: teClDual.firstPayload,
        secondPayload: teClDual.secondPayload,
        delayBetweenMs: 50,
        timeoutMs,
        allowSelfSignedTls: options.allowSelfSignedTls,
      });
      latencies.push(teClDualResult.latencyMs);

      const teClCombined = `${teClDualResult.firstResponse?.rawBuffer.toString('utf-8') || ''}\n${
        teClDualResult.secondResponse?.rawBuffer.toString('utf-8') || ''
      }`;

      if (
        teClCombined.includes(teClDual.canaryMarker) ||
        teClCombined.includes(`X-Canary-Check: ${teClDual.canaryMarker}`)
      ) {
        const evidenceHash = crypto
          .createHash('sha256')
          .update(teClDual.firstPayload)
          .update(teClDualResult.firstResponse?.rawBuffer || Buffer.alloc(0))
          .digest('hex');

        findings.push({
          title: 'Critical HTTP Request Smuggling Vulnerability (TE.CL)',
          description:
            'The front-end proxy prioritized Transfer-Encoding while the back-end application server prioritized Content-Length. This asymmetry permits arbitrary request smuggling across shared persistent TCP connections.',
          severity: 'critical',
          category: 'protocol_audit',
          recommendation:
            'Ensure the front-end proxy strips conflicting Content-Length headers or normalizes chunked requests before forwarding to back-ends.',
          evidence: {
            request: {
              url: new URL(normalPath, input.targetUrl).toString(),
              method: 'POST',
              headers: {
                Host: host,
                'Transfer-Encoding': 'chunked',
                'Content-Length': '4',
              },
              body: teClDual.firstPayload.toString('utf-8'),
            },
            response: {
              statusCode: teClDualResult.firstResponse?.statusCode ?? 200,
              headers: teClDualResult.firstResponse?.headers ?? {},
              body: teClCombined,
              responseTimeMs: teClDualResult.latencyMs,
            },
            immutableHash: evidenceHash,
            metadata: {
              technique: 'TE_CL',
              canaryMarker: teClDual.canaryMarker,
              evidenceHash,
            },
          },
        });
      }

      // TE.CL Timing Probe
      context.reportProgress?.(70, 'Testing TE.CL differential timing probe');
      variantsTested.push('TE_CL_TIMING');
      variantsTestedCount++;

      const teClTimingPayload = buildTeClTimingPayload({ host, port, path: normalPath, canaryPath });
      probesDispatched++;
      const teClTimingResult = await rawSocketSender.sendRawPayload({
        host,
        port,
        useTls,
        payload: teClTimingPayload,
        timeoutMs,
        allowSelfSignedTls: options.allowSelfSignedTls,
      });
      latencies.push(teClTimingResult.latencyMs);

      if (
        teClTimingResult.timedOut ||
        (teClTimingResult.latencyMs > timingThreshold && baselineResp.latencyMs < timingThreshold / 2)
      ) {
        const evidenceHash = crypto
          .createHash('sha256')
          .update(teClTimingPayload)
          .update(teClTimingResult.rawBuffer)
          .digest('hex');

        findings.push({
          title: 'Potential HTTP Request Smuggling (TE.CL Timing Discrepancy)',
          description: `The target server exhibited prolonged timing delay (${teClTimingResult.latencyMs}ms vs ${baselineResp.latencyMs}ms baseline) when presented with a TE.CL payload, indicating back-end Content-Length starvation.`,
          severity: 'high',
          category: 'protocol_audit',
          recommendation:
            'Drop requests containing ambiguous Content-Length and Transfer-Encoding headers at the gateway/proxy boundary.',
          evidence: {
            request: {
              url: new URL(normalPath, input.targetUrl).toString(),
              method: 'POST',
              headers: {
                Host: host,
                'Transfer-Encoding': 'chunked',
                'Content-Length': '6',
              },
              body: teClTimingPayload.toString('utf-8'),
            },
            response: {
              statusCode: teClTimingResult.statusCode ?? 0,
              headers: teClTimingResult.headers,
              body: teClTimingResult.rawHeaders,
              responseTimeMs: teClTimingResult.latencyMs,
            },
            immutableHash: evidenceHash,
            metadata: {
              latencyMs: teClTimingResult.latencyMs,
              baselineLatencyMs: baselineResp.latencyMs,
              timedOut: teClTimingResult.timedOut,
              evidenceHash,
            },
          },
        });
      }
    }

    // 5. TE.TE Obfuscation Permutations
    if (techniques.includes('TE_TE')) {
      context.reportProgress?.(80, 'Testing TE.TE obfuscated Transfer-Encoding variations');
      const teTeVariants = buildTeTeVariants({ host, port, path: normalPath, canaryPath });

      for (const variant of teTeVariants) {
        variantsTested.push(variant.name);
        variantsTestedCount++;
        probesDispatched++;

        const resp = await rawSocketSender.sendRawPayload({
          host,
          port,
          useTls,
          payload: variant.payload,
          timeoutMs,
          allowSelfSignedTls: options.allowSelfSignedTls,
        });
        latencies.push(resp.latencyMs);

        if (resp.timedOut || (resp.latencyMs > timingThreshold && baselineResp.latencyMs < timingThreshold / 2)) {
          const evidenceHash = crypto
            .createHash('sha256')
            .update(variant.payload)
            .update(resp.rawBuffer)
            .digest('hex');

          findings.push({
            title: `HTTP Request Smuggling via Header Obfuscation (${variant.name})`,
            description: `The target system mishandled obfuscated Transfer-Encoding headers ("${variant.obfuscationHeader.replace(
              /\r?\n/g,
              ' ',
            )}"), leading to differential parsing between reverse proxy and back-end.`,
            severity: 'high',
            category: 'protocol_audit',
            recommendation:
              'Strictly enforce RFC 7230 token grammar for Transfer-Encoding headers. Reject requests containing malformed whitespace or multiple conflicting values.',
            evidence: {
              request: {
                url: new URL(normalPath, input.targetUrl).toString(),
                method: 'POST',
                headers: {
                  Host: host,
                  Obfuscation: variant.obfuscationHeader,
                },
                body: variant.payload.toString('utf-8'),
              },
              response: {
                statusCode: resp.statusCode ?? 0,
                headers: resp.headers,
                body: resp.rawHeaders,
                responseTimeMs: resp.latencyMs,
              },
              immutableHash: evidenceHash,
              metadata: {
                variant: variant.name,
                latencyMs: resp.latencyMs,
                evidenceHash,
              },
            },
          });
        }
      }
    }

    // 6. Reverse Proxy Host Header Poisoning Probe
    if (techniques.includes('HOST_POISONING')) {
      context.reportProgress?.(90, 'Testing reverse proxy Host and Forwarded header poisoning');
      variantsTested.push('HOST_HEADER_POISONING');
      variantsTestedCount++;

      const hostPoisonPayload = buildHostPoisoningPayload({
        host,
        port,
        path: normalPath,
        canaryPath,
        canaryHost: poisonCanaryHost,
      });
      probesDispatched++;
      const hostPoisonResp = await rawSocketSender.sendRawPayload({
        host,
        port,
        useTls,
        payload: hostPoisonPayload,
        timeoutMs,
        allowSelfSignedTls: options.allowSelfSignedTls,
      });
      latencies.push(hostPoisonResp.latencyMs);

      const locationHeader = hostPoisonResp.headers['location'] || '';
      const linkHeader = hostPoisonResp.headers['link'] || '';
      const bodyText = hostPoisonResp.body.toLowerCase();

      if (
        locationHeader.includes(poisonCanaryHost) ||
        linkHeader.includes(poisonCanaryHost) ||
        bodyText.includes(`<base href="http://${poisonCanaryHost}`) ||
        bodyText.includes(`<base href="https://${poisonCanaryHost}`)
      ) {
        const evidenceHash = crypto
          .createHash('sha256')
          .update(hostPoisonPayload)
          .update(hostPoisonResp.rawBuffer)
          .digest('hex');

        findings.push({
          title: 'Reverse Proxy Host Header Poisoning via X-Forwarded-Host',
          description: `The application or reverse proxy reflected the untrusted injected host ("${poisonCanaryHost}") in a redirect Location header or response body. This enables password-reset poisoning, cache poisoning, and web tracking manipulation.`,
          severity: 'high',
          category: 'protocol_audit',
          recommendation:
            'Configure the reverse proxy to overwrite X-Forwarded-Host with the trusted incoming Host header, and validate Host headers against an explicit server whitelist.',
          evidence: {
            request: {
              url: new URL(normalPath, input.targetUrl).toString(),
              method: 'GET',
              headers: {
                Host: host,
                'X-Forwarded-Host': poisonCanaryHost,
              },
              body: hostPoisonPayload.toString('utf-8'),
            },
            response: {
              statusCode: hostPoisonResp.statusCode ?? 302,
              headers: hostPoisonResp.headers,
              body: hostPoisonResp.rawHeaders,
              responseTimeMs: hostPoisonResp.latencyMs,
            },
            immutableHash: evidenceHash,
            metadata: {
              reflectedLocation: locationHeader,
              poisonCanaryHost,
              evidenceHash,
            },
          },
        });
      }
    }

    // 7. Hop-by-hop Header Manipulation Probe
    if (techniques.includes('HOP_BY_HOP')) {
      context.reportProgress?.(95, 'Testing hop-by-hop header stripping manipulation');
      variantsTested.push('HOP_BY_HOP_STRIPPING');
      variantsTestedCount++;

      const hopPayload = buildHopByHopPayload(
        { host, port, path: normalPath, canaryPath },
        ['X-Internal-Token', 'X-Forwarded-For'],
      );
      probesDispatched++;
      const hopResp = await rawSocketSender.sendRawPayload({
        host,
        port,
        useTls,
        payload: hopPayload,
        timeoutMs,
        allowSelfSignedTls: options.allowSelfSignedTls,
      });
      latencies.push(hopResp.latencyMs);

      // If reverse proxy reflected debug headers showing internal headers were stripped or altered
      if (
        hopResp.headers['x-hop-bypass-detected'] === 'true' ||
        hopResp.body.includes('hop-by-hop-stripped: true')
      ) {
        const evidenceHash = crypto
          .createHash('sha256')
          .update(hopPayload)
          .update(hopResp.rawBuffer)
          .digest('hex');

        findings.push({
          title: 'Hop-by-Hop Header Stripping Vulnerability',
          description:
            'The upstream proxy stripped security-critical custom headers specified in the Connection header before forwarding the request to the application backend.',
          severity: 'medium',
          category: 'protocol_audit',
          recommendation:
            'Configure intermediate proxies to prohibit client Connection header tokens from overriding security-critical upstream metadata.',
          evidence: {
            request: {
              url: new URL(normalPath, input.targetUrl).toString(),
              method: 'GET',
              headers: {
                Host: host,
                Connection: 'close, X-Internal-Token, X-Forwarded-For',
              },
              body: hopPayload.toString('utf-8'),
            },
            response: {
              statusCode: hopResp.statusCode ?? 200,
              headers: hopResp.headers,
              body: hopResp.rawHeaders,
              responseTimeMs: hopResp.latencyMs,
            },
            immutableHash: evidenceHash,
            metadata: {
              evidenceHash,
            },
          },
        });
      }
    }

    const durationMs = Date.now() - startTime;
    const avgLatency =
      latencies.length > 0 ? Math.round(latencies.reduce((a, b) => a + b, 0) / latencies.length) : 0;

    // Metrics
    metrics.push(
      { name: 'probes_dispatched', value: probesDispatched, unit: 'count' },
      { name: 'smuggling_variants_tested', value: variantsTestedCount, unit: 'count' },
      { name: 'vulnerabilities_detected', value: findings.length, unit: 'count' },
      { name: 'avg_socket_latency_ms', value: avgLatency, unit: 'ms' },
    );

    context.reportProgress?.(100, `Completed HTTP smuggling scan. Detected ${findings.length} issues.`);

    logger.info(
      {
        probesDispatched,
        variantsTestedCount,
        vulnerabilitiesDetected: findings.length,
        avgLatency,
        durationMs,
      },
      'HTTP smuggling scan completed',
    );

    const summary: SmugglingExecutionSummary = {
      targetHost: host,
      targetPort: port,
      useTls,
      probesDispatched,
      vulnerabilitiesDetected: findings.length,
      variantsTested,
      findings: evidenceList,
      durationMs,
    };

    return {
      engineId: this.id,
      success: true,
      durationMs,
      findings,
      metrics,
      rawOutput: JSON.stringify(summary, null, 2),
    };
  }
}

export const httpSmugglingEngine = new HttpSmugglingEngine();
dynamicWorkerEngineRegistry.register(httpSmugglingEngine);

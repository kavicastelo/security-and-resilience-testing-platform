import tls from 'node:tls';
import { validateUrlAgainstScope } from '@security-lab/domain';
import { TestEngine } from '../engine.js';
import { TestCapability } from '../capability.js';
import { ExecutionContext } from '../context.js';
import { TestInput, TestResult, ValidationResult, RawEngineFinding } from '../result.js';

export class TlsSecurityEngine implements TestEngine {
  readonly id = 'engine-native-tls';
  readonly version = '1.0.0';
  readonly executionClass = 'class_a_native' as const;

  capabilities(): TestCapability[] {
    return [
      {
        id: 'tls_audit',
        name: 'TLS / SSL Transport Security Audit',
        category: 'protocol_audit',
        description: 'Audits TLS protocol version, certificate validity, expiration, and cipher suites',
        isDisruptive: false,
      },
    ];
  }

  validate(input: TestInput): ValidationResult {
    try {
      new URL(input.targetUrl);
      return { valid: true };
    } catch {
      return {
        valid: false,
        errors: [{ path: 'targetUrl', message: `Invalid target URL: "${input.targetUrl}"` }],
      };
    }
  }

  async execute(input: TestInput, context: ExecutionContext): Promise<TestResult> {
    const startTime = Date.now();

    // Enforce security scope boundary before opening TLS socket
    if (context.target?.scope) {
      const scopeValidation = validateUrlAgainstScope(input.targetUrl, context.target.scope);
      if (!scopeValidation.valid) {
        return {
          engineId: this.id,
          durationMs: Date.now() - startTime,
          success: false,
          findings: [],
          metrics: [],
          error: `Target URL violates security boundary: ${scopeValidation.violations.join('; ')}`,
        };
      }
    }

    const url = new URL(input.targetUrl);
    const findings: RawEngineFinding[] = [];

    // 1. Check for unencrypted HTTP transport
    if (url.protocol === 'http:') {
      findings.push({
        title: 'Cleartext HTTP Transport in Use',
        category: 'tls_ssl',
        severity: 'high',
        description: `Target "${input.targetUrl}" uses unencrypted HTTP. All data in transit is vulnerable to passive eavesdropping and interception.`,
        recommendation: 'Enforce HTTPS for all target services and redirect HTTP traffic to HTTPS.',
        evidence: {
          request: { method: 'GET', url: input.targetUrl, headers: {} },
          expected: 'HTTPS protocol with valid TLS certificate',
          actual: 'Plain HTTP protocol without TLS',
        },
      });

      return {
        engineId: this.id,
        durationMs: Date.now() - startTime,
        success: true,
        findings,
        metrics: [{ name: 'tls_enabled', value: 0, unit: 'boolean' }],
      };
    }

    context.reportProgress(20, 'Establishing TLS socket connection to target host...');
    const hostname = url.hostname;
    const port = url.port ? parseInt(url.port, 10) : 443;

    try {
      const socketDetails = await new Promise<{
        protocol: string;
        cipherName: string;
        cert: tls.PeerCertificate;
      }>((resolve, reject) => {
        const timeout = setTimeout(() => {
          socket.destroy();
          reject(new Error(`TLS connection timed out after 5000ms connecting to ${hostname}:${port}`));
        }, 5000);

        const socket = tls.connect(
          {
            host: hostname,
            port,
            servername: hostname,
            rejectUnauthorized: false, // Audit mode: allows inspecting self-signed/expired certs
          },
          () => {
            clearTimeout(timeout);
            const protocol = socket.getProtocol() || 'unknown';
            const cipher = socket.getCipher();
            const cert = socket.getPeerCertificate();
            socket.end();
            resolve({
              protocol,
              cipherName: cipher?.name || 'unknown',
              cert,
            });
          },
        );

        socket.on('error', (err) => {
          clearTimeout(timeout);
          reject(err);
        });
      });

      context.reportProgress(70, 'Analyzing TLS handshake parameters and peer certificate...');
      const { protocol, cipherName, cert } = socketDetails;

      // 2. Protocol Version Check (TLS 1.0, 1.1, SSLv3 deprecated)
      if (['TLSv1', 'TLSv1.1', 'SSLv3', 'SSLv2'].includes(protocol)) {
        findings.push({
          title: `Deprecated TLS Protocol Version Negotiated (${protocol})`,
          category: 'tls_ssl',
          severity: 'high',
          description: `Target negotiated ${protocol}, which is formally deprecated by RFC 8996 due to known cryptographic weaknesses.`,
          recommendation: 'Disable TLS 1.0 and TLS 1.1 in server configuration; require TLS 1.2 or TLS 1.3.',
          evidence: {
            actual: `Negotiated Protocol: ${protocol}`,
            expected: 'TLSv1.2 or TLSv1.3',
          },
        });
      }

      // 3. Certificate Expiration Check
      if (cert && cert.valid_to) {
        const expiryDate = new Date(cert.valid_to);
        const daysRemaining = Math.floor((expiryDate.getTime() - Date.now()) / (1000 * 60 * 60 * 24));

        if (daysRemaining < 0) {
          findings.push({
            title: 'TLS Certificate Expired',
            category: 'tls_ssl',
            severity: 'critical',
            description: `The certificate presented by ${hostname} expired ${Math.abs(daysRemaining)} days ago on ${cert.valid_to}.`,
            recommendation: 'Renew and replace the expired TLS certificate immediately.',
            evidence: {
              expected: 'Valid non-expired certificate',
              actual: `Expired on: ${cert.valid_to}`,
            },
          });
        } else if (daysRemaining <= 30) {
          findings.push({
            title: `TLS Certificate Expiring Soon (${daysRemaining} days remaining)`,
            category: 'tls_ssl',
            severity: 'low',
            description: `The TLS certificate for ${hostname} will expire in ${daysRemaining} days on ${cert.valid_to}.`,
            recommendation: 'Ensure certificate auto-renewal is operating correctly before expiration.',
          });
        }
      }

      // 4. Cipher Suite Weakness Check
      const weakCipherPatterns = [/RC4/i, /3DES/i, /DES/i, /MD5/i, /NULL/i, /EXPORT/i, /_CBC_/i];
      const isWeakCipher = weakCipherPatterns.some((p) => p.test(cipherName));
      if (isWeakCipher) {
        findings.push({
          title: `Weak or Deprecated Cipher Suite In Use (${cipherName})`,
          category: 'tls_ssl',
          severity: 'medium',
          description: `Target server negotiated cipher "${cipherName}", which utilizes weak cryptographic primitives.`,
          recommendation: 'Configure server to prefer modern AEAD ciphers (e.g. AES-GCM, CHACHA20-POLY1305).',
          evidence: {
            actual: `Cipher: ${cipherName}`,
            expected: 'Modern AEAD cipher suite',
          },
        });
      }

      context.reportProgress(100, `Completed TLS audit: ${findings.length} findings identified.`);

      return {
        engineId: this.id,
        durationMs: Date.now() - startTime,
        success: true,
        findings,
        metrics: [
          { name: 'tls_handshake_ms', value: Date.now() - startTime, unit: 'ms' },
          { name: 'cert_valid_days', value: cert?.valid_to ? Math.floor((new Date(cert.valid_to).getTime() - Date.now()) / 86400000) : 0, unit: 'days' },
        ],
        rawOutput: {
          protocol,
          cipherName,
          subject: cert?.subject,
          issuer: cert?.issuer,
          validFrom: cert?.valid_from,
          validTo: cert?.valid_to,
        },
      };
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      return {
        engineId: this.id,
        durationMs: Date.now() - startTime,
        success: false,
        findings: [],
        metrics: [],
        error: `TLS socket audit failed: ${msg}`,
      };
    }
  }
}

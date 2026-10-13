import https from 'node:https';
import tls from 'node:tls';

export interface MtlsClientConfig {
  enabled: boolean;
  caCert?: string;
  clientCert?: string;
  clientKey?: string;
  rejectUnauthorized?: boolean;
}

export interface MtlsServerConfig {
  enabled: boolean;
  caCert?: string;
  serverCert?: string;
  serverKey?: string;
  clientCertRequired?: boolean;
}

/**
 * Creates an HTTPS Agent configured for mutual TLS (mTLS) client connections.
 */
export function createMtlsHttpsAgent(config: MtlsClientConfig): https.Agent | undefined {
  if (!config.enabled) {
    return undefined;
  }

  const agentOptions: https.AgentOptions = {
    rejectUnauthorized: config.rejectUnauthorized ?? true,
  };

  if (config.caCert) {
    agentOptions.ca = config.caCert;
  }
  if (config.clientCert) {
    agentOptions.cert = config.clientCert;
  }
  if (config.clientKey) {
    agentOptions.key = config.clientKey;
  }

  return new https.Agent(agentOptions);
}

/**
 * Generates TLS server options for Fastify/Node HTTPS when mTLS is enabled.
 */
export function getMtlsServerOptions(config: MtlsServerConfig): tls.TlsOptions | undefined {
  if (!config.enabled || !config.serverCert || !config.serverKey) {
    return undefined;
  }

  const serverOptions: tls.TlsOptions = {
    cert: config.serverCert,
    key: config.serverKey,
    requestCert: config.clientCertRequired ?? true,
    rejectUnauthorized: config.clientCertRequired ?? true,
  };

  if (config.caCert) {
    serverOptions.ca = config.caCert;
  }

  return serverOptions;
}

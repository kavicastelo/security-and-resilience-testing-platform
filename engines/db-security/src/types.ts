import { DatabaseType } from '@security-lab/contracts';

export * from '@security-lab/contracts';

export interface DatabaseProbeTarget {
  host: string;
  port: number;
  protocol: string;
  databaseType: DatabaseType;
}

export interface RawProbeResult {
  success: boolean;
  tlsSupported: boolean;
  tlsMandated: boolean;
  unauthenticatedAccessAllowed: boolean;
  defaultCredentialsMatched: boolean;
  matchedCredentialUser?: string;
  serverVersion?: string;
  authMethod?: string;
  rawBannerHex?: string;
  error?: string;
  latencyMs: number;
  details?: Record<string, unknown>;
}

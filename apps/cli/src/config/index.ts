export interface CliConfig {
  apiUrl: string;
  apiKey?: string;
  format: 'table' | 'json' | 'yaml' | 'junit';
  verbose: boolean;
}

export function getCliConfig(overrides?: Partial<CliConfig>): CliConfig {
  return {
    apiUrl: overrides?.apiUrl || process.env.SECURITY_LAB_API_URL || 'http://localhost:4000',
    apiKey: overrides?.apiKey || process.env.SECURITY_LAB_API_KEY,
    format: overrides?.format || 'table',
    verbose: overrides?.verbose ?? false,
  };
}

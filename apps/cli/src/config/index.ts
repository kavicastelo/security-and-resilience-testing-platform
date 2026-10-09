import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

export interface CliConfig {
  apiUrl: string;
  apiKey?: string;
  format: 'table' | 'json' | 'yaml' | 'junit';
  verbose: boolean;
}

let activeOverrides: Partial<CliConfig> | undefined;

export function setCliConfig(overrides: Partial<CliConfig>): void {
  activeOverrides = { ...activeOverrides, ...overrides };
}

export function resetCliConfig(): void {
  activeOverrides = undefined;
}

export function getStoredConfigPath(): string {
  return path.join(os.homedir(), '.security-lab', 'config.json');
}

export function readStoredApiKey(): string | undefined {
  try {
    const configPath = getStoredConfigPath();
    if (fs.existsSync(configPath)) {
      const content = fs.readFileSync(configPath, 'utf-8');
      const data = JSON.parse(content) as { apiKey?: string };
      if (typeof data.apiKey === 'string' && data.apiKey.trim().length > 0) {
        return data.apiKey.trim();
      }
    }
  } catch {
    // Ignore read errors from home directory
  }
  return undefined;
}

export function saveStoredApiKey(apiKey: string): void {
  const configPath = getStoredConfigPath();
  const dir = path.dirname(configPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  fs.writeFileSync(configPath, JSON.stringify({ apiKey: apiKey.trim() }, null, 2), 'utf-8');
}

export function clearStoredApiKey(): void {
  try {
    const configPath = getStoredConfigPath();
    if (fs.existsSync(configPath)) {
      fs.unlinkSync(configPath);
    }
  } catch {
    // Ignore error
  }
}

export function getCliConfig(overrides?: Partial<CliConfig>): CliConfig {
  const apiKey =
    overrides?.apiKey ||
    activeOverrides?.apiKey ||
    process.env.SECURITY_LAB_API_KEY ||
    readStoredApiKey();

  return {
    apiUrl: overrides?.apiUrl || activeOverrides?.apiUrl || process.env.SECURITY_LAB_API_URL || 'http://localhost:4000',
    apiKey: apiKey && apiKey.trim().length > 0 ? apiKey.trim() : undefined,
    format: overrides?.format || activeOverrides?.format || 'table',
    verbose: overrides?.verbose ?? activeOverrides?.verbose ?? false,
  };
}

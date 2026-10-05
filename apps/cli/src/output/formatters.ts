import pc from 'picocolors';

export function formatJson(data: unknown): string {
  return JSON.stringify(data, null, 2);
}

export function formatSuccess(message: string): string {
  return `${pc.green('✔')} ${message}`;
}

export function formatError(message: string): string {
  return `${pc.red('✖')} ${message}`;
}

export function formatWarning(message: string): string {
  return `${pc.yellow('⚠')} ${message}`;
}

export function formatInfo(message: string): string {
  return `${pc.cyan('ℹ')} ${message}`;
}

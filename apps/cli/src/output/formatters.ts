import pc from 'picocolors';

export function formatJson(data: unknown): string {
  return JSON.stringify(data, null, 2);
}

export function formatSuccess(message: string): string {
  return `${pc.green('✔')} ${message}`;
}

export function formatError(message: string): string {
  if (message.includes('SECURITY_LAB_API_KEY is missing or invalid')) {
    return "Error: SECURITY_LAB_API_KEY is missing or invalid. Set it in your environment or run 'sec-lab login'.";
  }
  return `${pc.red('✖')} ${message}`;
}

export function formatCliError(err: unknown, fallbackPrefix?: string): string {
  if (err instanceof Error && (err.name === 'AuthenticationError' || err.message.includes('SECURITY_LAB_API_KEY is missing or invalid'))) {
    return "Error: SECURITY_LAB_API_KEY is missing or invalid. Set it in your environment or run 'sec-lab login'.";
  }
  const msg = err instanceof Error ? err.message : String(err);
  return pc.red(fallbackPrefix ? `✖ ${fallbackPrefix}: ${msg}` : `✖ ${msg}`);
}

export function formatWarning(message: string): string {
  return `${pc.yellow('⚠')} ${message}`;
}

export function formatInfo(message: string): string {
  return `${pc.cyan('ℹ')} ${message}`;
}

import pino, { Logger as PinoLogger, LoggerOptions } from 'pino';

export type LogLevel = 'fatal' | 'error' | 'warn' | 'info' | 'debug' | 'trace';

export interface LoggerInitOptions {
  name?: string;
  level?: LogLevel;
  pretty?: boolean;
}

export interface LoggerContext {
  correlationId?: string;
  testRunId?: string;
  executionId?: string;
  targetId?: string;
  [key: string]: unknown;
}

export type Logger = PinoLogger;

export function createLogger(options: LoggerInitOptions = {}): Logger {
  const level: LogLevel = options.level || (process.env.LOG_LEVEL as LogLevel) || 'info';
  const isPretty = options.pretty ?? (process.env.LOG_PRETTY === 'true');

  const pinoOptions: LoggerOptions = {
    name: options.name || 'security-lab',
    level,
    timestamp: pino.stdTimeFunctions.isoTime,
    formatters: {
      level(label: string) {
        return { level: label };
      },
    },
  };

  if (isPretty && process.env.NODE_ENV !== 'production') {
    // Basic structured formatted output for dev console
    return pino({
      ...pinoOptions,
      transport: {
        target: 'pino/file',
        options: { destination: 1 },
      },
    });
  }

  return pino(pinoOptions);
}

export const logger = createLogger();

export function withCorrelation(correlationId: string, baseLogger: Logger = logger): Logger {
  return baseLogger.child({ correlationId });
}

export function withTestRunContext(
  context: { testRunId: string; executionId?: string; targetId?: string },
  baseLogger: Logger = logger,
): Logger {
  return baseLogger.child(context);
}

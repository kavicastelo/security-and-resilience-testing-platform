import pc from 'picocolors';

export function isInteractiveTerminal(): boolean {
  return Boolean(
    process.stdout.isTTY &&
      !process.env.CI &&
      process.env.NODE_ENV !== 'test' &&
      !process.env.SECURITY_LAB_NON_INTERACTIVE,
  );
}

export interface SpinnerOptions {
  interval?: number;
  frames?: string[];
  stream?: NodeJS.WriteStream;
}

export class TerminalSpinner {
  private frames: string[];
  private interval: number;
  private currentFrameIndex = 0;
  private timer: NodeJS.Timeout | null = null;
  private message: string;
  private isSpinning = false;
  private interactive: boolean;
  private stream: NodeJS.WriteStream;

  constructor(message = '', options?: SpinnerOptions) {
    this.message = message;
    this.interval = options?.interval ?? 80;
    this.frames = options?.frames ?? ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
    this.interactive = isInteractiveTerminal();
    this.stream = options?.stream ?? process.stdout;
  }

  public start(message?: string): this {
    if (message !== undefined) {
      this.message = message;
    }

    if (this.isSpinning) {
      return this;
    }

    this.isSpinning = true;

    if (!this.interactive) {
      if (this.message) {
        this.stream.write(`${pc.cyan('ℹ')} ${this.message}\n`);
      }
      return this;
    }

    // Hide cursor in interactive TTY
    this.stream.write('\x1b[?25l');
    this.render();

    this.timer = setInterval(() => {
      this.currentFrameIndex = (this.currentFrameIndex + 1) % this.frames.length;
      this.render();
    }, this.interval);

    if (this.timer.unref) {
      this.timer.unref();
    }

    return this;
  }

  public update(message: string): this {
    this.message = message;
    if (this.interactive && this.isSpinning) {
      this.render();
    }
    return this;
  }

  public stop(): this {
    if (!this.isSpinning) {
      return this;
    }

    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }

    if (this.interactive) {
      this.clearLine();
      this.stream.write('\x1b[?25h'); // Restore cursor
    }

    this.isSpinning = false;
    return this;
  }

  public succeed(message?: string): this {
    return this.finish(pc.green('✔'), message ?? this.message);
  }

  public fail(message?: string): this {
    return this.finish(pc.red('✖'), message ?? this.message);
  }

  public warn(message?: string): this {
    return this.finish(pc.yellow('⚠'), message ?? this.message);
  }

  public info(message?: string): this {
    return this.finish(pc.cyan('ℹ'), message ?? this.message);
  }

  private finish(symbol: string, message: string): this {
    this.stop();
    this.stream.write(`${symbol} ${message}\n`);
    return this;
  }

  private render(): void {
    if (!this.interactive) return;
    const frame = pc.cyan(this.frames[this.currentFrameIndex] || '•');
    this.clearLine();
    this.stream.write(`${frame} ${this.message}`);
  }

  private clearLine(): void {
    if (this.stream.isTTY) {
      this.stream.write('\r\x1b[K');
    }
  }
}

export function createSpinner(message?: string, options?: SpinnerOptions): TerminalSpinner {
  return new TerminalSpinner(message, options);
}

export async function withSpinner<T>(
  message: string,
  task: (spinner: TerminalSpinner) => Promise<T>,
  options?: SpinnerOptions,
): Promise<T> {
  const spinner = createSpinner(message, options);
  spinner.start();
  try {
    const result = await task(spinner);
    return result;
  } catch (err) {
    spinner.fail(`${message} failed`);
    throw err;
  }
}

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

const LEVEL_ORDER: Record<LogLevel, number> = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
};

export interface LoggerContext {
  [key: string]: unknown;
}

export class Logger {
  constructor(
    private readonly minLevel: LogLevel = 'info',
    private readonly context: LoggerContext = {},
  ) {}

  child(extra: LoggerContext): Logger {
    return new Logger(this.minLevel, { ...this.context, ...extra });
  }

  private log(level: LogLevel, message: string, extra?: LoggerContext): void {
    if (LEVEL_ORDER[level] < LEVEL_ORDER[this.minLevel]) return;
    const entry = {
      level,
      message,
      timestamp: new Date().toISOString(),
      ...this.context,
      ...extra,
    };
    const out = level === 'error' ? console.error : level === 'warn' ? console.warn : console.log;
    out(JSON.stringify(entry));
  }

  debug(message: string, extra?: LoggerContext): void {
    this.log('debug', message, extra);
  }
  info(message: string, extra?: LoggerContext): void {
    this.log('info', message, extra);
  }
  warn(message: string, extra?: LoggerContext): void {
    this.log('warn', message, extra);
  }
  error(message: string, extra?: LoggerContext): void {
    this.log('error', message, extra);
  }
}

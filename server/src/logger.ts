/**
 * Structured JSON logs, one line per event. By design the logger only accepts
 * flat primitive fields, and the relay only ever passes room *tags* (short
 * hashes), sizes, counts and error codes - never blobs, headers, verifiers,
 * room ids or anything user-supplied.
 */

export type Level = 'debug' | 'info' | 'warn' | 'error';
export type LogFields = Record<string, string | number | boolean>;
export type LogSink = (line: string) => void;

export interface Logger {
  log(level: Level, evt: string, fields?: LogFields): void;
  info(evt: string, fields?: LogFields): void;
  warn(evt: string, fields?: LogFields): void;
  error(evt: string, fields?: LogFields): void;
}

/** Keys that must never reach a log line, even by mistake. */
const FORBIDDEN = new Set(['blob', 'header', 'box', 'verifier', 'rid', 'sig', 'nonce', 'key', 'payload', 'raw']);

export function createLogger(sink: LogSink = (l) => process.stdout.write(l + '\n')): Logger {
  const log = (level: Level, evt: string, fields: LogFields = {}): void => {
    const safe: LogFields = {};
    for (const [k, v] of Object.entries(fields)) {
      if (FORBIDDEN.has(k)) continue;
      // Strings are capped: legitimate fields are short tags/codes.
      safe[k] = typeof v === 'string' ? v.slice(0, 64) : v;
    }
    sink(JSON.stringify({ ts: new Date().toISOString(), level, evt, ...safe }));
  };
  return {
    log,
    info: (e, f) => log('info', e, f),
    warn: (e, f) => log('warn', e, f),
    error: (e, f) => log('error', e, f),
  };
}

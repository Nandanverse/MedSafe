/**
 * Structured logging, with no dependencies.
 *
 * One JSON object per line on stdout, which is what every log shipper — Loki,
 * CloudWatch, `docker logs | jq` — already knows how to read. A logging library
 * would add a dependency tree to solve a problem that is about forty lines of
 * code, and this project has to install cleanly on a college laptop.
 *
 * Three properties matter more than features here:
 *
 * 1. **Logging never throws.** A crash inside the logger would turn a handled
 *    error into an unhandled one, taking down a request that was about to return
 *    a perfectly good 400. Every path is wrapped, and a serialisation failure
 *    degrades to a minimal line rather than propagating.
 * 2. **Secrets are redacted by key name, not by hoping.** API keys, sensor HMACs
 *    and Authorization headers pass through this process constantly. Redaction is
 *    applied on the way out, so a future route that logs `req.headers` wholesale
 *    cannot leak a key. `X-API-Key` in a log file is a permanent credential leak:
 *    log files get pasted into bug reports and committed by accident.
 * 3. **Payloads are truncated.** `photo_base64` in a counterfeit report is
 *    megabytes of JPEG. Logging it once fills a disk and buries the line that
 *    mattered.
 *
 * This module deliberately reads `process.env` itself instead of importing
 * `config`. Configuration validation needs to *report* its own failures, so if
 * the logger depended on validated config, a bad `.env` would produce a silent
 * exit — the single most confusing failure a new contributor can hit.
 */

const LEVELS = Object.freeze({ debug: 10, info: 20, warn: 30, error: 40, silent: 100 });

/** Keys whose values never reach a log line, matched case-insensitively. */
const REDACT_KEYS = Object.freeze(
  new Set([
    'x-api-key',
    'api_key',
    'apikey',
    'authorization',
    'auth',
    'cookie',
    'set-cookie',
    'password',
    'passwd',
    'secret',
    'token',
    'access_token',
    'refresh_token',
    'private_key',
    'privatekey',
    'key_pem',
    'hmac',
    'signature',
    'shared_secret',
    'sensor_secret',
    'connection_string',
    'database_url',
    'redis_url',
    'reporter_contact',
  ]),
);

/**
 * Keys that are legitimately huge and are logged only as a size.
 * `raw_payload` is a TM1 string: useful to know it was present, useless at full
 * length, and it embeds a signature.
 */
const SIZE_ONLY_KEYS = Object.freeze(new Set(['photo_base64', 'photo', 'raw_payload', 'body']));

const REDACTED = '[redacted]';
const MAX_STRING = 512;
const MAX_DEPTH = 6;
const MAX_ARRAY = 50;

function parseLevel(raw) {
  const name = String(raw ?? '').trim().toLowerCase();
  if (name in LEVELS) return name;
  // An unrecognised LOG_LEVEL must not silence logging — that is how an
  // incident ends up with no evidence. Fall back to info and say so once.
  if (name) {
    process.stderr.write(
      `[truemed] LOG_LEVEL="${raw}" is not one of ${Object.keys(LEVELS).join(', ')}; using "info"\n`,
    );
  }
  return 'info';
}

function isPlainObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Serialise an Error, including our `code` and any `cause` chain. */
function serialiseError(err, includeStack) {
  const out = {
    name: err.name,
    message: err.message,
  };
  if (err.code !== undefined) out.code = err.code;
  if (err.status !== undefined) out.status = err.status;
  if (includeStack && typeof err.stack === 'string') {
    out.stack = err.stack.split('\n').slice(0, 12).join('\n');
  }
  if (err.cause instanceof Error) {
    out.cause = serialiseError(err.cause, includeStack);
  }
  return out;
}

/**
 * Copy a value into something safe to stringify: redacted, truncated, depth- and
 * cycle-bounded.
 */
function sanitise(value, includeStack, depth = 0, seen = new WeakSet()) {
  if (value === null || value === undefined) return value ?? null;

  if (typeof value === 'string') {
    return value.length > MAX_STRING
      ? `${value.slice(0, MAX_STRING)}…[${value.length} chars]`
      : value;
  }
  if (typeof value === 'number') return Number.isFinite(value) ? value : String(value);
  if (typeof value === 'boolean') return value;
  if (typeof value === 'bigint') return value.toString();
  if (typeof value === 'symbol') return value.toString();
  if (typeof value === 'function') return `[function ${value.name || 'anonymous'}]`;

  if (value instanceof Error) return serialiseError(value, includeStack);
  if (value instanceof Date) return value.toISOString();
  if (value instanceof Buffer) return `[${value.length} bytes]`;
  if (value instanceof Map) return sanitise(Object.fromEntries(value), includeStack, depth, seen);
  if (value instanceof Set) return sanitise([...value], includeStack, depth, seen);

  if (depth >= MAX_DEPTH) return '[depth limit]';

  // Cycles: an Express `req` object references itself through `req.res.req`, so
  // this is not a hypothetical.
  if (seen.has(value)) return '[circular]';
  seen.add(value);

  if (Array.isArray(value)) {
    const items = value.slice(0, MAX_ARRAY).map((v) => sanitise(v, includeStack, depth + 1, seen));
    if (value.length > MAX_ARRAY) items.push(`…[${value.length - MAX_ARRAY} more]`);
    return items;
  }

  if (isPlainObject(value) || typeof value === 'object') {
    const out = {};
    for (const [key, child] of Object.entries(value)) {
      const lower = key.toLowerCase();
      if (REDACT_KEYS.has(lower)) {
        out[key] = REDACTED;
      } else if (SIZE_ONLY_KEYS.has(lower)) {
        out[key] =
          typeof child === 'string'
            ? `[${child.length} chars]`
            : sanitise(child, includeStack, depth + 1, seen);
      } else {
        out[key] = sanitise(child, includeStack, depth + 1, seen);
      }
    }
    return out;
  }

  return String(value);
}

// ANSI escapes are built from the code point rather than typed literally. A raw
// ESC byte (0x1B) in a source file is invisible in a diff, and editors, shells
// and copy-paste all mangle it — this repository has already lost a file to that
// once.
const ESC = String.fromCharCode(27);
const COLOURS = Object.freeze({
  debug: `${ESC}[90m`,
  info: `${ESC}[36m`,
  warn: `${ESC}[33m`,
  error: `${ESC}[31m`,
  reset: `${ESC}[0m`,
});

function formatPretty(record) {
  const { ts, level, msg, ...rest } = record;
  const colour = COLOURS[level] ?? '';
  const time = ts.slice(11, 23);
  const tail = Object.keys(rest).length ? ` ${JSON.stringify(rest)}` : '';
  return `${colour}${time} ${level.toUpperCase().padEnd(5)}${COLOURS.reset} ${msg}${tail}\n`;
}

class Logger {
  /**
   * @param {object} [bound] fields added to every line from this logger
   * @param {object} [options]
   */
  constructor(bound = {}, options = {}) {
    const levelName = options.level ?? parseLevel(process.env.LOG_LEVEL ?? 'info');
    this.levelName = levelName;
    this.threshold = LEVELS[levelName];
    // Pretty output is opt-in and defaults on only outside production, so a
    // container never emits ANSI escapes into a log aggregator.
    this.pretty =
      options.pretty ??
      (process.env.LOG_PRETTY === '1' ||
        (process.env.LOG_PRETTY !== '0' && process.env.NODE_ENV !== 'production'));
    // Stack traces are noise in aggregate and useful in development. In
    // production they are still emitted for `error`, because an unexplained 500
    // with no stack is unfixable.
    this.includeStack = options.includeStack ?? true;
    this.bound = bound;
    this.stream = options.stream ?? process.stdout;
  }

  /** A logger that adds `fields` to every line — one per request, bound to its id. */
  child(fields = {}) {
    return new Logger(
      { ...this.bound, ...fields },
      {
        level: this.levelName,
        pretty: this.pretty,
        includeStack: this.includeStack,
        stream: this.stream,
      },
    );
  }

  isEnabled(level) {
    return LEVELS[level] >= this.threshold;
  }

  write(level, msg, fields) {
    if (!this.isEnabled(level)) return;
    try {
      const record = {
        ts: new Date().toISOString(),
        level,
        msg: typeof msg === 'string' ? msg : String(msg),
        ...sanitise({ ...this.bound, ...(fields ?? {}) }, this.includeStack),
      };
      this.stream.write(this.pretty ? formatPretty(record) : `${JSON.stringify(record)}\n`);
    } catch (err) {
      // Last resort. Losing one line is acceptable; throwing from a log call is
      // not, because callers log inside catch blocks and error handlers.
      try {
        this.stream.write(
          `${JSON.stringify({
            ts: new Date().toISOString(),
            level: 'error',
            msg: 'logger failed to serialise a record',
            logger_error: String(err && err.message),
            original_msg: String(msg),
          })}\n`,
        );
      } catch {
        /* stdout itself is gone; nothing useful remains to do */
      }
    }
  }

  debug(msg, fields) {
    this.write('debug', msg, fields);
  }

  info(msg, fields) {
    this.write('info', msg, fields);
  }

  warn(msg, fields) {
    this.write('warn', msg, fields);
  }

  error(msg, fields) {
    this.write('error', msg, fields);
  }
}

/** The process-wide logger. Routes should use `req.log` (a child) instead. */
export const logger = new Logger();

export { Logger, LEVELS, REDACT_KEYS, SIZE_ONLY_KEYS, sanitise };

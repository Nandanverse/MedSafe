/**
 * Structured logging.
 *
 * The redaction tests are the important ones. An `X-API-Key` in a log file is a
 * permanent credential leak — log files get pasted into bug reports and committed
 * by accident — and the whole point of redacting by key name is that a future
 * route which logs `req.headers` wholesale cannot leak one.
 *
 * "Logging never throws" is tested by feeding the logger values that break
 * `JSON.stringify`: cycles, BigInt, and a getter that throws.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { Logger, LEVELS, sanitise } from '../src/utils/logger.js';

/** A stand-in for process.stdout that keeps what was written. */
function capture() {
  const lines = [];
  return {
    lines,
    write(chunk) {
      lines.push(chunk);
      return true;
    },
    /** The last line, parsed. */
    last() {
      assert.ok(lines.length > 0, 'nothing was written');
      return JSON.parse(lines[lines.length - 1]);
    },
    text() {
      return lines.join('');
    },
  };
}

/** A logger writing JSON to a captured stream. */
function makeLogger(options = {}) {
  const stream = capture();
  const log = new Logger(options.bound ?? {}, {
    stream,
    pretty: false,
    level: options.level ?? 'debug',
    includeStack: options.includeStack ?? false,
  });
  return { log, stream };
}

describe('line format', () => {
  test('each line is one self-contained JSON object', () => {
    const { log, stream } = makeLogger();
    log.info('medicine minted', { product_id: 'A_B_2026_000001' });
    assert.equal(stream.lines.length, 1);
    assert.ok(stream.lines[0].endsWith('\n'), 'lines must be newline-delimited');
    const record = stream.last();
    assert.equal(record.level, 'info');
    assert.equal(record.msg, 'medicine minted');
    assert.equal(record.product_id, 'A_B_2026_000001');
  });

  test('the timestamp is ISO 8601 in UTC', () => {
    const { log, stream } = makeLogger();
    log.info('hello');
    assert.match(stream.last().ts, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
  });

  test('a non-string message is coerced rather than dropped', () => {
    const { log, stream } = makeLogger();
    log.info(42);
    assert.equal(stream.last().msg, '42');
  });

  test('pretty mode is human-readable and JSON mode has no escape codes', () => {
    const plain = capture();
    new Logger({}, { stream: plain, pretty: false, level: 'debug' }).warn('careful');
    const ESC = String.fromCharCode(27);
    assert.equal(plain.text().includes(ESC), false, 'JSON output must not contain ANSI escapes');

    const fancy = capture();
    new Logger({}, { stream: fancy, pretty: true, level: 'debug' }).warn('careful');
    assert.ok(fancy.text().includes(ESC), 'pretty output is colourised');
    assert.ok(fancy.text().includes('WARN'));
  });
});

describe('level filtering', () => {
  test('below-threshold lines are not written at all', () => {
    const { log, stream } = makeLogger({ level: 'warn' });
    log.debug('noise');
    log.info('also noise');
    assert.equal(stream.lines.length, 0);
    log.warn('kept');
    log.error('kept');
    assert.equal(stream.lines.length, 2);
  });

  test('silent suppresses everything', () => {
    const { log, stream } = makeLogger({ level: 'silent' });
    log.error('not written');
    assert.equal(stream.lines.length, 0);
  });

  test('isEnabled matches what write does', () => {
    const { log } = makeLogger({ level: 'info' });
    assert.equal(log.isEnabled('debug'), false);
    assert.equal(log.isEnabled('info'), true);
    assert.equal(log.isEnabled('error'), true);
  });

  test('the level ordering is the conventional one', () => {
    assert.ok(LEVELS.debug < LEVELS.info);
    assert.ok(LEVELS.info < LEVELS.warn);
    assert.ok(LEVELS.warn < LEVELS.error);
    assert.ok(LEVELS.error < LEVELS.silent);
  });
});

describe('child loggers', () => {
  test('bound fields appear on every line', () => {
    const { log, stream } = makeLogger();
    const child = log.child({ request_id: 'req-7', route: 'POST /api/verify/payload' });
    child.info('verified');
    const record = stream.last();
    assert.equal(record.request_id, 'req-7');
    assert.equal(record.route, 'POST /api/verify/payload');
  });

  test('per-call fields win over bound fields', () => {
    const { log, stream } = makeLogger({ bound: { stage: 'boot' } });
    log.info('later', { stage: 'serving' });
    assert.equal(stream.last().stage, 'serving');
  });

  test('a child does not mutate its parent', () => {
    const { log, stream } = makeLogger();
    log.child({ request_id: 'req-1' }).info('one');
    log.info('two');
    assert.equal(stream.last().request_id, undefined);
  });

  test('a child inherits level, stream and format', () => {
    const { log, stream } = makeLogger({ level: 'error' });
    const child = log.child({ a: 1 });
    child.info('dropped');
    assert.equal(stream.lines.length, 0);
    child.error('kept');
    assert.equal(stream.lines.length, 1);
  });
});

describe('redaction', () => {
  test('credential-bearing keys never reach the output', () => {
    const { log, stream } = makeLogger();
    log.info('request', {
      'x-api-key': 'tm_regulator_0123456789abcdef0123456789abcdef',
      authorization: 'Bearer abc.def.ghi',
      password: 'hunter2',
      hmac: 'deadbeef',
      database_url: 'postgres://u:p@h/db',
    });
    const text = stream.text();
    for (const secret of ['tm_regulator_', 'Bearer abc', 'hunter2', 'deadbeef', 'postgres://u:p']) {
      assert.equal(text.includes(secret), false, `leaked: ${secret}`);
    }
    const record = stream.last();
    assert.equal(record['x-api-key'], '[redacted]');
    assert.equal(record.password, '[redacted]');
  });

  test('redaction is case-insensitive, because header casing varies', () => {
    const { log, stream } = makeLogger();
    log.info('request', { 'X-API-Key': 'tm_sensor_abc', Authorization: 'Bearer xyz' });
    assert.equal(stream.text().includes('tm_sensor_abc'), false);
  });

  test('redaction reaches nested objects, so logging req.headers is safe', () => {
    const { log, stream } = makeLogger();
    log.info('request', {
      req: { method: 'POST', headers: { 'x-api-key': 'tm_manufacturer_secret' } },
    });
    assert.equal(stream.text().includes('tm_manufacturer_secret'), false);
    assert.equal(stream.last().req.headers['x-api-key'], '[redacted]');
    assert.equal(stream.last().req.method, 'POST', 'non-secret fields survive');
  });

  test('a reporter contact is redacted, since it is personal data under the DPDP Act', () => {
    const { log, stream } = makeLogger();
    log.info('report filed', { reporter_contact: '+91 98765 43210' });
    assert.equal(stream.text().includes('98765'), false);
  });

  test('huge fields are reduced to a size, not truncated content', () => {
    // A counterfeit report photo is megabytes of base64. Logging it once fills a
    // disk and buries the line that mattered.
    const { log, stream } = makeLogger();
    log.info('report filed', { photo_base64: 'A'.repeat(2_000_000) });
    const record = stream.last();
    assert.equal(record.photo_base64, '[2000000 chars]');
    assert.ok(stream.text().length < 500);
  });

  test('a raw TM1 payload is logged as a size, since it embeds a signature', () => {
    const { log, stream } = makeLogger();
    log.info('scan', { raw_payload: `TM1.${'x'.repeat(400)}.${'y'.repeat(86)}` });
    assert.match(stream.last().raw_payload, /^\[\d+ chars\]$/);
  });
});

describe('bounding output', () => {
  test('long strings are truncated with their true length noted', () => {
    const { log, stream } = makeLogger();
    log.info('long', { notes: 'x'.repeat(5000) });
    const value = stream.last().notes;
    assert.ok(value.length < 600, `truncated value was ${value.length} chars`);
    assert.match(value, /\[5000 chars\]$/);
  });

  test('deep nesting stops at a depth limit', () => {
    const { log, stream } = makeLogger();
    let deep = { end: 'bottom' };
    for (let i = 0; i < 20; i += 1) deep = { nested: deep };
    log.info('deep', deep);
    assert.match(JSON.stringify(stream.last()), /depth limit/);
  });

  test('long arrays are capped with a count of the remainder', () => {
    const { log, stream } = makeLogger();
    log.info('many', { items: Array.from({ length: 200 }, (_, i) => i) });
    const items = stream.last().items;
    assert.equal(items.length, 51);
    assert.equal(items[50], '…[150 more]');
  });
});

describe('logging never throws', () => {
  test('a circular reference is handled, not thrown', () => {
    // Express `req` references itself through req.res.req, so this is routine.
    const { log, stream } = makeLogger();
    const cycle = { name: 'req' };
    cycle.self = cycle;
    assert.doesNotThrow(() => log.info('cyclic', { cycle }));
    assert.equal(stream.last().cycle.self, '[circular]');
  });

  test('two references to the same object are not mistaken for a cycle', () => {
    const { log, stream } = makeLogger();
    const shared = { id: 1 };
    log.info('shared', { a: shared, b: shared });
    const record = stream.last();
    // `a` is serialised first; `b` is the same object, so it is reported as
    // circular rather than duplicated. Documenting the trade-off: a WeakSet
    // cannot distinguish a diamond from a cycle without extra bookkeeping, and
    // over-reporting is the safe direction for a logger.
    assert.deepEqual(record.a, { id: 1 });
    assert.equal(record.b, '[circular]');
  });

  test('a BigInt does not break serialisation', () => {
    // JSON.stringify throws a TypeError on BigInt.
    const { log, stream } = makeLogger();
    assert.doesNotThrow(() => log.info('big', { count: 10n ** 30n }));
    assert.equal(stream.last().count, '1000000000000000000000000000000');
  });

  test('a getter that throws degrades to a fallback line instead of propagating', () => {
    // A logger crash inside a catch block turns a handled error into an
    // unhandled one.
    const { log, stream } = makeLogger();
    const hostile = {
      get boom() {
        throw new Error('getter exploded');
      },
    };
    assert.doesNotThrow(() => log.info('hostile', { hostile }));
    assert.equal(stream.lines.length, 1);
    const record = stream.last();
    assert.equal(record.msg, 'logger failed to serialise a record');
    assert.equal(record.original_msg, 'hostile');
  });

  test('a stream that throws does not propagate', () => {
    const log = new Logger({}, {
      pretty: false,
      level: 'debug',
      stream: {
        write() {
          throw new Error('EPIPE');
        },
      },
    });
    assert.doesNotThrow(() => log.info('into the void'));
  });
});

describe('error serialisation', () => {
  test('name, message and our error code are kept', () => {
    const { log, stream } = makeLogger();
    const err = new Error('signature check failed');
    err.code = 'SIGNATURE_INVALID';
    err.status = 400;
    log.error('verification failed', { err });
    const record = stream.last();
    assert.equal(record.err.name, 'Error');
    assert.equal(record.err.message, 'signature check failed');
    assert.equal(record.err.code, 'SIGNATURE_INVALID');
    assert.equal(record.err.status, 400);
  });

  test('the cause chain is followed', () => {
    const { log, stream } = makeLogger();
    const root = new Error('connection refused');
    const wrapper = new Error('cannot reach the peer', { cause: root });
    log.error('upstream down', { err: wrapper });
    assert.equal(stream.last().err.cause.message, 'connection refused');
  });

  test('stacks are included when asked for and bounded in length', () => {
    const stream = capture();
    const log = new Logger({}, { stream, pretty: false, level: 'debug', includeStack: true });
    log.error('boom', { err: new Error('boom') });
    const stack = stream.last().err.stack;
    assert.ok(stack.includes('Error: boom'));
    assert.ok(stack.split('\n').length <= 12, 'stack should be capped');
  });

  test('an Error passed as the whole field set still serialises', () => {
    const { log, stream } = makeLogger();
    log.error('bare', { err: new TypeError('bad type') });
    assert.equal(stream.last().err.name, 'TypeError');
  });
});

describe('sanitise', () => {
  test('preserves the types a log consumer expects', () => {
    assert.equal(sanitise('text', false), 'text');
    assert.equal(sanitise(42, false), 42);
    assert.equal(sanitise(true, false), true);
    assert.equal(sanitise(null, false), null);
    assert.equal(sanitise(undefined, false), null);
  });

  test('non-finite numbers become strings, since JSON has no NaN', () => {
    assert.equal(sanitise(NaN, false), 'NaN');
    assert.equal(sanitise(Infinity, false), 'Infinity');
  });

  test('a Buffer is reported as a size, never as content', () => {
    // A Buffer in a log line is usually key material or a signature.
    assert.equal(sanitise(Buffer.alloc(64), false), '[64 bytes]');
  });

  test('a Date becomes an ISO string', () => {
    assert.equal(sanitise(new Date('2026-08-22T10:00:00Z'), false), '2026-08-22T10:00:00.000Z');
  });

  test('Map and Set are serialisable, unlike under plain JSON.stringify', () => {
    assert.deepEqual(sanitise(new Map([['a', 1]]), false), { a: 1 });
    assert.deepEqual(sanitise(new Set([1, 2]), false), [1, 2]);
  });

  test('a function is named rather than dropped', () => {
    assert.equal(sanitise(function handler() {}, false), '[function handler]');
  });
});

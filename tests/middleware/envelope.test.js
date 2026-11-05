/**
 * The response envelope middlewares, against DATA-CONTRACT.md §4.1.
 *
 * These two functions decide the shape of every byte the Flutter app parses, and
 * the app has exactly one generated model for it. So the cases here are mostly
 * about the *shape* — an extra key or a missing one is a breaking change to a
 * published contract, not a cosmetic difference, and it is the kind of drift that
 * gets noticed only when a patient's phone throws a null check.
 *
 * Express is not installed in this project's test environment, and it would add
 * nothing here: both middlewares are plain `(req, res, next)` functions, so a
 * pair of fakes exercises them honestly and the suite stays runnable with no
 * network. `res.json` round-trips the payload through JSON, which is what makes
 * the "undefined disappears" case below a real test rather than a hopeful one.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { makeEnvelope } from '../../src/middleware/envelope.js';
import { makeErrorHandler, notFoundHandler } from '../../src/middleware/error-handler.js';
import {
  CODES,
  TrueMedError,
  conflict,
  internalError,
  rateLimited,
  upstreamUnavailable,
  validationError,
} from '../../src/core/errors.js';
import { Logger } from '../../src/utils/logger.js';

/** A logger that keeps its lines as parsed objects instead of writing them out. */
function captureLogger() {
  const lines = [];
  const stream = {
    write(text) {
      lines.push(JSON.parse(text));
    },
  };
  const log = new Logger({}, { level: 'debug', pretty: false, stream });
  return { log, lines, last: () => lines.at(-1) };
}

function fakeReq({ method = 'GET', url = '/api/verify/PARA_1', headers = {} } = {}) {
  const lower = Object.fromEntries(
    Object.entries(headers).map(([key, value]) => [key.toLowerCase(), value]),
  );
  return {
    method,
    url,
    originalUrl: url,
    path: url.split('?')[0],
    headers: lower,
    get(name) {
      return lower[String(name).toLowerCase()];
    },
  };
}

function fakeRes() {
  const listeners = {};
  const res = {
    statusCode: 200,
    headersSent: false,
    headers: {},
    body: undefined,
    set(name, value) {
      res.headers[String(name).toLowerCase()] = value;
      return res;
    },
    get(name) {
      return res.headers[String(name).toLowerCase()];
    },
    status(code) {
      res.statusCode = code;
      return res;
    },
    json(payload) {
      res.headersSent = true;
      // Through JSON and back, exactly as the wire sees it: an `undefined` value
      // vanishes at this step, which is the failure `res.ok` guards against.
      res.body = JSON.parse(JSON.stringify(payload));
      for (const cb of listeners.finish ?? []) cb();
      return res;
    },
    on(event, cb) {
      (listeners[event] ??= []).push(cb);
      return res;
    },
  };
  return res;
}

/** Run the envelope middleware over a fresh req/res pair. */
function enveloped(reqOptions) {
  const { log, lines, last } = captureLogger();
  const req = fakeReq(reqOptions);
  const res = fakeRes();
  let nextCalls = 0;
  makeEnvelope(log)(req, res, () => {
    nextCalls += 1;
  });
  return { req, res, log, lines, last, nextCalls: () => nextCalls };
}

describe('the success envelope', () => {
  test('is exactly { ok, data, meta: { cached, took_ms } }', () => {
    const { res } = enveloped();
    res.ok({ verdict: 'GENUINE' });

    assert.deepEqual(Object.keys(res.body).sort(), ['data', 'meta', 'ok']);
    assert.equal(res.body.ok, true);
    assert.deepEqual(res.body.data, { verdict: 'GENUINE' });
    assert.deepEqual(Object.keys(res.body.meta).sort(), ['cached', 'took_ms']);
    assert.equal(res.statusCode, 200);
  });

  test('carries no request_id or took_ms at the top level', () => {
    // Both used to live in the body. They are not in §4.1, and a client model
    // generated from the contract rejects unknown fields.
    const { res } = enveloped();
    res.ok({ ok: 'this key inside data must not confuse anything' });

    assert.equal('request_id' in res.body, false);
    assert.equal('took_ms' in res.body, false);
    assert.equal('error' in res.body, false);
  });

  test('the request id travels as a header instead', () => {
    const { req, res } = enveloped();
    res.ok(null);
    assert.equal(res.get('X-Request-Id'), req.id);
    assert.ok(req.id.length >= 8);
  });

  test('meta.took_ms is a whole, non-negative number of milliseconds', () => {
    const { res } = enveloped();
    res.ok({});
    assert.ok(Number.isInteger(res.body.meta.took_ms), 'the body carries whole milliseconds');
    assert.ok(res.body.meta.took_ms >= 0, 'a monotonic clock cannot go backwards');
  });

  test('meta.cached defaults to false and can be set', () => {
    // §4.6 serves a terminal verdict from Redis for up to an hour. A pharmacist
    // reading a cold-chain number needs to know it might be an hour old, so this
    // flag is contract, not diagnostics.
    const plain = enveloped();
    plain.res.ok({});
    assert.equal(plain.res.body.meta.cached, false);

    const hit = enveloped();
    hit.res.ok({}, { cached: true });
    assert.equal(hit.res.body.meta.cached, true);
  });
});

describe('res.ok status handling', () => {
  test('a bare number is honoured as the status code', () => {
    // `res.ok(body, 201)` is the obvious thing to write for a create. If the
    // second argument were treated only as an options object this would silently
    // answer 200 — a wrong-but-plausible response nobody notices.
    const { res } = enveloped({ method: 'POST', url: '/api/medicine' });
    res.ok({ product_id: 'PARA_1' }, 201);
    assert.equal(res.statusCode, 201);
    assert.equal(res.body.ok, true);
    assert.deepEqual(Object.keys(res.body.meta).sort(), ['cached', 'took_ms']);
  });

  test('an options object can set the status too', () => {
    const { res } = enveloped({ method: 'POST', url: '/api/medicine' });
    res.ok({ product_id: 'PARA_1' }, { status: 201, cached: false });
    assert.equal(res.statusCode, 201);
  });

  test('extra meta is additive and cannot displace cached or took_ms', () => {
    // Pagination needs somewhere to put a bookmark, and §4.1 tolerates extra
    // meta; it does not tolerate a missing `cached`.
    const { res } = enveloped();
    res.ok([], { meta: { next_bookmark: 'g1AAAA', total: 42 } });
    assert.deepEqual(Object.keys(res.body.meta).sort(), [
      'cached',
      'next_bookmark',
      'took_ms',
      'total',
    ]);
    assert.equal(res.body.meta.cached, false);
    assert.equal(res.body.meta.next_bookmark, 'g1AAAA');
  });
});

describe('the data field is always present', () => {
  test('no argument still sends an explicit null', () => {
    const { res } = enveloped();
    res.ok();
    assert.equal('data' in res.body, true, 'JSON.stringify drops undefined; null survives');
    assert.equal(res.body.data, null);
  });

  test('falsy data is not rewritten to null', () => {
    // `?? null` and `|| null` differ exactly here, and a count of zero is a
    // perfectly good answer for a dashboard.
    for (const value of [0, false, '']) {
      const { res } = enveloped();
      res.ok(value);
      assert.equal(res.body.data, value, `${JSON.stringify(value)} must survive`);
    }
  });
});

describe('request identity', () => {
  test('a safe inbound X-Request-Id is reused so a trace spans the proxy hop', () => {
    const { req, res } = enveloped({ headers: { 'X-Request-Id': 'edge-7f3a9c21' } });
    assert.equal(req.id, 'edge-7f3a9c21');
    res.ok(null);
    assert.equal(res.get('X-Request-Id'), 'edge-7f3a9c21');
  });

  test('an unsafe inbound id is replaced rather than echoed', () => {
    // The value reaches a log line and a response header, so a newline in it is a
    // log-injection and header-splitting primitive.
    const hostile = [
      'short',
      `abcdefgh${String.fromCharCode(10)}injected`,
      'has spaces in it',
      'semi;colon;values',
      'x'.repeat(129),
    ];
    for (const value of hostile) {
      const { req } = enveloped({ headers: { 'X-Request-Id': value } });
      assert.notEqual(req.id, value, `${JSON.stringify(value)} must not be echoed`);
      assert.match(req.id, /^[\w.-]+$/);
    }
  });

  test('req.log is bound to the id, so one line ties to one response', () => {
    const { req, last } = enveloped();
    req.log.info('minting');
    assert.equal(last().request_id, req.id);
  });

  test('next() is called once so the request continues', () => {
    const { nextCalls } = enveloped();
    assert.equal(nextCalls(), 1);
  });
});

describe('the completion log line', () => {
  test('level tracks the status class', () => {
    const cases = [
      [200, 'info'],
      [201, 'info'],
      [404, 'warn'],
      [429, 'warn'],
      [500, 'error'],
      [503, 'error'],
    ];
    for (const [status, level] of cases) {
      const { res, last } = enveloped();
      res.ok(null, status);
      assert.equal(last().level, level, `status ${status} should log at ${level}`);
      assert.equal(last().status, status);
    }
  });

  test('it keeps sub-millisecond resolution the body does not', () => {
    // The body rounds to whole milliseconds because that is all a client can use;
    // percentile work on a fast cached path needs the finer number.
    const { res, last } = enveloped();
    res.ok(null);
    assert.equal(typeof last().took_ms, 'number');
    assert.ok(last().took_ms >= 0);
  });

  test('the caller role is logged when authenticated', () => {
    const { req, res, last } = enveloped({ method: 'POST', url: '/api/medicine' });
    req.auth = { role: 'manufacturer' };
    res.ok(null, 201);
    assert.equal(last().role, 'manufacturer');
  });
});

// ── error handler ────────────────────────────────────────────────────────────

/** Run the envelope middleware, then hand `err` to the error handler. */
function handled(err, reqOptions) {
  const ctx = enveloped(reqOptions);
  let forwarded;
  makeErrorHandler({ logger: ctx.log })(err, ctx.req, ctx.res, (e) => {
    forwarded = e;
  });
  return { ...ctx, forwarded: () => forwarded };
}

describe('the failure envelope', () => {
  test('is exactly { ok, error: { code, message } }', () => {
    const { res } = handled(conflict('PARA_1 is already on the ledger'));

    assert.deepEqual(Object.keys(res.body).sort(), ['error', 'ok']);
    assert.equal(res.body.ok, false);
    assert.deepEqual(Object.keys(res.body.error).sort(), ['code', 'message']);
    assert.equal(res.body.error.code, CODES.CONFLICT);
    assert.equal(res.statusCode, 409);
  });

  test('carries no meta, took_ms or request_id', () => {
    // §4.1's failure form has two keys. The id is in the header, where it is
    // available even for a failure that never reached a route.
    const { req, res } = handled(validationError('batch_no is required'));
    assert.equal('meta' in res.body, false);
    assert.equal('took_ms' in res.body, false);
    assert.equal('request_id' in res.body, false);
    assert.equal(res.get('X-Request-Id'), req.id);
  });

  test('details survive on an error the caller is allowed to read', () => {
    const { res } = handled(validationError('expiry_date is malformed', { field: 'expiry_date' }));
    assert.deepEqual(res.body.error.details, { field: 'expiry_date' });
    assert.equal(res.statusCode, 400);
  });

  test('the status comes from the code, so one condition answers one status', () => {
    for (const [err, status] of [
      [validationError('bad'), 400],
      [new TrueMedError(CODES.UNAUTHORIZED, 'no key'), 401],
      [new TrueMedError(CODES.FORBIDDEN, 'wrong role'), 403],
      [new TrueMedError(CODES.NOT_ON_CHAIN, 'absent'), 404],
      [conflict('dup'), 409],
      [upstreamUnavailable('the ledger'), 503],
      [internalError(new Error('boom')), 500],
    ]) {
      const { res } = handled(err);
      assert.equal(res.statusCode, status, `${err.code} should be ${status}`);
      assert.equal(res.body.error.code, err.code);
    }
  });
});

describe('what the client is not told', () => {
  test('an unexpected throwable never leaks its message', () => {
    // The single most valuable case in this file. A stack frame, a connection
    // string or a peer hostname in `err.message` ends up in a screenshot.
    const { res } = handled(new Error('connect ECONNREFUSED 10.0.3.7:5432 (db-primary.internal)'));

    assert.equal(res.statusCode, 500);
    assert.equal(res.body.error.code, CODES.INTERNAL_ERROR);
    assert.equal(res.body.error.message, 'an internal error occurred');
    assert.doesNotMatch(
      JSON.stringify(res.body),
      /ECONNREFUSED|10\.0\.3\.7|5432|db-primary/,
      'no host, port or driver text may reach the client',
    );
  });

  test('a non-exposed error loses its details as well as its message', () => {
    const leaky = new TrueMedError(CODES.INTERNAL_ERROR, 'postgres at db.internal:5432 refused', {
      details: { host: 'db.internal', port: 5432 },
    });
    assert.equal(leaky.expose, false, '5xx defaults to not exposed');

    const { res } = handled(leaky);
    assert.equal(res.body.error.message, 'an internal error occurred');
    assert.equal('details' in res.body.error, false, 'details can name internals too');
  });

  test('the generic message still tells a patient whether to retry', () => {
    // "a dependency is temporarily unavailable" and "an internal error occurred"
    // ask for different behaviour from the user; collapsing both to one string
    // would tell someone to give up on a fridge that is merely rebooting.
    const down = new TrueMedError(CODES.UPSTREAM_UNAVAILABLE, 'peer0.org1:7051 TLS handshake failed', {
      expose: false,
    });
    const { res } = handled(down);
    assert.equal(res.statusCode, 503);
    assert.equal(res.body.error.message, 'a dependency is temporarily unavailable');
    assert.doesNotMatch(res.body.error.message, /7051|peer0/);
  });

  test('but the log keeps the real message for whoever has to fix it', () => {
    const { lines } = handled(
      new TrueMedError(CODES.INTERNAL_ERROR, 'redis at cache.internal:6379 refused', {
        cause: new Error('ECONNREFUSED'),
      }),
    );
    const line = lines.find((l) => l.level === 'error' && /cache\.internal/.test(l.msg));
    assert.ok(line, 'the operator needs the detail the client was denied');
    assert.equal(line.code, CODES.INTERNAL_ERROR);
    assert.equal(line.cause, 'ECONNREFUSED');
  });

  test('a 4xx logs at warn, because the caller is at fault', () => {
    // A wall of error-level lines from clients sending bad JSON is how a real
    // incident gets missed.
    const { lines } = handled(validationError('batch_no is required'));
    const line = lines.find((l) => l.msg === 'batch_no is required');
    assert.ok(line);
    assert.equal(line.level, 'warn');
  });
});

describe('framework errors become contract envelopes', () => {
  test('malformed JSON from body-parser is a VALIDATION_ERROR', () => {
    const err = new SyntaxError('Unexpected token } in JSON at position 42');
    err.status = 400;
    err.body = '{"batch_no":}';

    const { res } = handled(err, { method: 'POST', url: '/api/medicine' });
    assert.equal(res.statusCode, 400);
    assert.equal(res.body.error.code, CODES.VALIDATION_ERROR);
    assert.equal(res.body.error.message, 'request body is not valid JSON');
  });

  test('an oversized body keeps 413 while reusing the code', () => {
    // A counterfeit report carries a photo, so this is the one clients hit in
    // practice. The status has to stay 413 for the app to know to recompress.
    const err = Object.assign(new Error('request entity too large'), {
      type: 'entity.too.large',
      status: 413,
    });
    const { res } = handled(err, { method: 'POST', url: '/api/report' });
    assert.equal(res.statusCode, 413);
    assert.equal(res.body.error.code, CODES.VALIDATION_ERROR);
  });

  test('an unsupported body encoding is a VALIDATION_ERROR', () => {
    const err = Object.assign(new Error('unsupported charset "UTF-9"'), {
      type: 'charset.unsupported',
    });
    const { res } = handled(err, { method: 'POST', url: '/api/temperature' });
    assert.equal(res.statusCode, 400);
    assert.equal(res.body.error.code, CODES.VALIDATION_ERROR);
  });

  test('one of our errors is never reinterpreted as a framework error', () => {
    // A TrueMedError that happens to carry 413 must keep its own message. The
    // framework translation only applies to what we did not raise ourselves.
    const ours = new TrueMedError(CODES.VALIDATION_ERROR, 'photo_base64 exceeds 2 MB', {
      status: 413,
      details: { limit_bytes: 2097152 },
    });
    const { res } = handled(ours, { method: 'POST', url: '/api/report' });
    assert.equal(res.statusCode, 413);
    assert.equal(res.body.error.message, 'photo_base64 exceeds 2 MB');
    assert.deepEqual(res.body.error.details, { limit_bytes: 2097152 });
  });

  test('an error-shaped plain object from another layer is normalised', () => {
    // The Fabric gateway builds errors across a module boundary; duck-typed ones
    // must not degrade to 500.
    const { res } = handled({ code: CODES.NOT_ON_CHAIN, status: 404, message: 'absent' });
    assert.equal(res.statusCode, 404);
    assert.equal(res.body.error.code, CODES.NOT_ON_CHAIN);
    assert.equal(res.body.error.message, 'absent');
  });
});

describe('headers the client acts on', () => {
  test('a rate-limited response sets Retry-After', () => {
    const { res } = handled(rateLimited(2.3));
    assert.equal(res.statusCode, 429);
    assert.equal(res.get('Retry-After'), '3', 'seconds, rounded up, never zero');
    assert.equal(res.body.error.code, CODES.RATE_LIMITED);
  });

  test('a response already sent is handed back rather than rewritten', () => {
    // Rewriting a committed response throws ERR_HTTP_HEADERS_SENT, turning a
    // delivered answer into a crash. Express's default handler closes the socket.
    const ctx = enveloped();
    ctx.res.ok({ verdict: 'GENUINE' });
    const delivered = ctx.res.body;

    let forwarded;
    const err = internalError(new Error('late failure'));
    makeErrorHandler({ logger: ctx.log })(err, ctx.req, ctx.res, (e) => {
      forwarded = e;
    });

    assert.equal(forwarded, err, 'the error is forwarded, not swallowed');
    assert.deepEqual(ctx.res.body, delivered, 'the good answer is left intact');
  });

  test('res.ok on a committed response is a no-op, not a throw', () => {
    const { res } = enveloped();
    res.ok({ first: true });
    const delivered = res.body;
    res.ok({ second: true });
    assert.deepEqual(res.body, delivered);
  });
});

describe('the terminal 404', () => {
  test('an unmatched path gets a contract envelope, not Express HTML', () => {
    const { req, res, lines } = enveloped({ method: 'GET', url: '/api/verifyy/PARA_1' });
    notFoundHandler(req, res);

    assert.equal(res.statusCode, 404);
    assert.deepEqual(Object.keys(res.body).sort(), ['error', 'ok']);
    assert.equal(res.body.ok, false);
    assert.equal(res.body.error.code, CODES.NOT_FOUND);
    assert.match(res.body.error.message, /GET \/api\/verifyy\/PARA_1/);
    assert.equal('request_id' in res.body, false);
    assert.equal(res.get('X-Request-Id'), req.id);
    assert.ok(
      lines.some((l) => l.level === 'warn' && /no route for/.test(l.msg)),
      'a burst of 404s on one path is a client shipping a bad URL; log it',
    );
  });

  test('it does not depend on an error handler being mounted after it', () => {
    // It answers directly instead of calling next(err). Delegating reads better
    // but makes the response depend on registration order, and mounting it last
    // by accident would hang the request until the client times out.
    const req = fakeReq({ method: 'DELETE', url: '/nope' });
    const res = fakeRes();
    notFoundHandler(req, res);
    assert.equal(res.statusCode, 404);
    assert.equal(res.body.error.code, CODES.NOT_FOUND);
  });
});

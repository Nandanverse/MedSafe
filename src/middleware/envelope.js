/**
 * Response envelope, request identity, and timing — one small middleware that
 * every response passes through.
 *
 * The whole API answers in the two shapes of DATA-CONTRACT.md §4.1, so the
 * Flutter client has exactly one parser:
 *
 *   success →  { "ok": true,  "data": <payload>, "meta": { "cached": false, "took_ms": 12 } }
 *   failure →  { "ok": false, "error": { "code", "message", "details"? } }
 *
 * `res.ok(data)` sends the success form; failures are `throw`n and shaped by the
 * error-handler. Both delegate to `core/envelope.js`, which is the only module
 * that decides what an envelope looks like — a middleware that assembled the
 * object literal itself is how the two shapes drifted apart the first time.
 *
 * **The request id is a header, not a body field.** `X-Request-Id` is set on
 * every response, including the ones that fail before any JSON exists, so it is
 * available for a bug report either way; putting it in the body as well would
 * add a field §4.1 does not have to every response in the system, and the app's
 * generated model would then reject the contract's own examples.
 *
 * A verify result is *data*, even when the verdict is COUNTERFEIT — that is a
 * successful answer to "is this genuine?", so it travels as `ok:true` with the
 * verdict inside `data`. Only protocol problems (bad input, auth, upstream down)
 * are `ok:false`. This split is the reason the whole system can treat HTTP status
 * and business verdict as independent axes.
 */

import { randomUUID } from 'node:crypto';

import { success } from '../core/envelope.js';

/** Round to 3 decimals — sub-microsecond noise is not worth logging. */
const round = (ms) => Math.round(ms * 1000) / 1000;

/**
 * @param {import('../utils/logger.js').Logger} logger
 * @returns {(req, res, next) => void}
 */
export function makeEnvelope(logger) {
  return function envelope(req, res, next) {
    const startNs = process.hrtime.bigint();
    // Honour an inbound request id (set by a proxy/load balancer) so a trace can
    // span the whole hop, but fall back to a fresh one.
    const inbound = req.get('X-Request-Id');
    const requestId = isSafeId(inbound) ? inbound : randomUUID();

    req.id = requestId;
    req.startNs = startNs;
    req.tookMs = () => round(Number(process.hrtime.bigint() - startNs) / 1e6);
    req.log = logger.child({ request_id: requestId });

    res.set('X-Request-Id', requestId);

    /**
     * Send a success envelope.
     *
     * The second argument takes a bare status code as well as an options object.
     * That is deliberate: `res.ok(body, 201)` is the obvious thing to write for a
     * create, and were it silently ignored the mint route would answer 200 for
     * the rest of the project's life — a wrong-but-plausible response is far
     * harder to notice than a thrown TypeError.
     *
     * `meta.cached` matters to more than curiosity: §4.6 lets a verdict be served
     * from Redis for up to an hour, and a pharmacist looking at a stale
     * cold-chain reading needs to know the number could be an hour old.
     *
     * @param {unknown} data
     * @param {number|{status?: number, cached?: boolean, meta?: object}} [opts]
     */
    res.ok = (data, opts = {}) => {
      // A response that has already begun streaming cannot be rewritten. Return
      // quietly so a late `res.ok` is a no-op rather than an ERR_HTTP_HEADERS_SENT
      // throw that turns a delivered answer into a crash.
      if (res.headersSent) return res;
      const { status = 200, cached = false, meta } =
        typeof opts === 'number' ? { status: opts } : opts;
      // `data ?? null` because JSON.stringify drops an undefined value: without
      // it, `res.ok()` emits an envelope with no `data` key at all, and a client
      // written against "data is always present" fails a null check on a phone.
      // `success()` rounds took_ms to whole milliseconds for the body; the log
      // line below keeps the finer resolution, which is what percentiles need.
      return res
        .status(status)
        .json(success(data ?? null, { cached, tookMs: req.tookMs(), extra: meta }));
    };

    // One structured line per completed request; level tracks the status class.
    res.on('finish', () => {
      const fields = {
        method: req.method,
        path: req.originalUrl ?? req.url,
        status: res.statusCode,
        took_ms: req.tookMs(),
      };
      if (req.auth?.role) fields.role = req.auth.role;
      if (res.statusCode >= 500) req.log.error('request failed', fields);
      else if (res.statusCode >= 400) req.log.warn('request rejected', fields);
      else req.log.info('request ok', fields);
    });

    next();
  };
}

/** Accept only a conservative id charset, so a header can't inject log/HTTP noise. */
function isSafeId(value) {
  return typeof value === 'string' && value.length >= 8 && value.length <= 128 && /^[\w.\-]+$/.test(value);
}

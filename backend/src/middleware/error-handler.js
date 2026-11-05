/**
 * The single error-shaping middleware. Every failure in the API — a thrown
 * TrueMedError, a body-parser rejection, or an unexpected crash — leaves through
 * here and becomes one contract-shaped envelope:
 *
 *   { "ok": false, "error": { "code", "message", "details"? } }
 *
 * That is DATA-CONTRACT.md §4.1 exactly, and the object is built by `failure()`
 * in `core/envelope.js` rather than assembled here, so success and failure
 * responses cannot drift apart. Notably there is no `meta` and no `request_id` on
 * a failure: the id travels in the `X-Request-Id` header, which is set on every
 * response including the ones that never reach a route.
 *
 * Three responsibilities beyond formatting:
 *
 * **It honours `expose`.** A TrueMedError marks whether its message is safe for
 * the client. 5xx messages routinely name peer hostnames, TLS paths or a stack;
 * for those we substitute a generic message before the envelope is built, and
 * drop `details` with it. The code is always safe — it is the frozen contract the
 * app switches on.
 *
 * **It normalises framework errors.** body-parser throws a JSON syntax error or
 * an "entity too large" before any route runs; left alone these become bare 400s
 * with an HTML body, breaking the client's one-shape assumption. We translate
 * them into VALIDATION_ERROR envelopes (the size case keeps a 413 status while
 * reusing the code) so there is never a response that isn't `{ ok, ... }`.
 *
 * **It decides who is at fault, and logs accordingly.** 5xx is ours and carries
 * the cause chain; 4xx is the caller's and stays at warn, because a wall of
 * error-level lines from clients sending bad JSON is how a real incident gets
 * missed.
 */

import { CODES, TrueMedError, isTrueMedError } from '../core/errors.js';
import { failure, toTrueMedError } from '../core/envelope.js';

/**
 * Generic, host-safe messages for errors we refuse to expose verbatim.
 *
 * Deliberately more specific than `failure()`'s own fallback: "a dependency is
 * temporarily unavailable" tells a patient to try again in a minute, where
 * "internal error" tells them to give up. Neither names a host.
 */
const SAFE_MESSAGE = Object.freeze({
  [CODES.INTERNAL_ERROR]: 'an internal error occurred',
  [CODES.UPSTREAM_UNAVAILABLE]: 'a dependency is temporarily unavailable',
});

/**
 * Recognise the framework errors that arrive before our routes and re-shape them.
 * @returns {TrueMedError|null}
 */
function fromFrameworkError(err) {
  // body-parser: payload above the configured limit.
  if (err?.type === 'entity.too.large' || err?.status === 413) {
    return new TrueMedError(
      CODES.VALIDATION_ERROR,
      'request body is larger than the server accepts',
      { status: 413 },
    );
  }
  // body-parser: malformed JSON (SyntaxError with a 400 and a `body` property).
  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
    return new TrueMedError(CODES.VALIDATION_ERROR, 'request body is not valid JSON');
  }
  // Unsupported/'415' content type from body-parser.
  if (err?.type === 'charset.unsupported' || err?.type === 'encoding.unsupported') {
    return new TrueMedError(CODES.VALIDATION_ERROR, 'unsupported request body encoding');
  }
  return null;
}

/**
 * Replace an unexposable message with a safe one, keeping the code and status.
 *
 * The substitution happens here rather than inside `failure()` so there is one
 * place that builds the envelope and one place that decides what a client may
 * read. `expose: true` on the replacement is not a loophole — the message is a
 * constant from this file, so it is safe by construction. `details` is dropped:
 * on a 5xx it is as likely to name internals as the message was.
 */
function clientSafe(te) {
  if (te.expose) return te;
  return new TrueMedError(te.code, SAFE_MESSAGE[te.code] ?? 'request failed', {
    status: te.status,
    expose: true,
  });
}

/**
 * @param {{logger?: import('../utils/logger.js').Logger}} [deps]
 * @returns {(err, req, res, next) => void}
 */
export function makeErrorHandler({ logger } = {}) {
  return function errorHandler(err, req, res, next) {
    // If the response has already begun streaming, we cannot rewrite it; hand
    // back to Express's default handler to close the socket.
    if (res.headersSent) return next(err);

    // A framework error is only reinterpreted when it isn't already one of ours:
    // a TrueMedError carrying status 413 must keep its own message, not be
    // mistaken for a body-parser rejection.
    const te = isTrueMedError(err)
      ? toTrueMedError(err)
      : (fromFrameworkError(err) ?? toTrueMedError(err));

    const log = req.log ?? logger;
    const logFields = {
      code: te.code,
      status: te.status,
      method: req.method,
      path: req.originalUrl ?? req.url,
    };
    // The log always gets the real message, even when the client does not.
    if (te.status >= 500) {
      log?.error?.(te.message, { ...logFields, cause: err?.cause?.message ?? err?.message });
    } else {
      log?.warn?.(te.message, logFields);
    }

    if (te.retryAfter) res.set('Retry-After', String(te.retryAfter));
    res.status(te.status).json(failure(clientSafe(te)));
  };
}

/**
 * Terminal 404 for any route that did not match. Registered after all routes so
 * an unknown path gets a contract envelope rather than Express's HTML default.
 *
 * It answers directly instead of delegating to the error handler with `next(err)`.
 * Delegating would read better but makes the response depend on registration
 * order: mount this last by accident and the request hangs until the client times
 * out. Both paths build the body with `failure()`, so the shape is shared anyway.
 */
export function notFoundHandler(req, res) {
  const err = new TrueMedError(CODES.NOT_FOUND, `no route for ${req.method} ${req.path}`);
  req.log?.warn?.(err.message, { code: err.code, status: err.status });
  res.status(err.status).json(failure(err));
}

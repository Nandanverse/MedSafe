/**
 * The response envelope from DATA-CONTRACT.md §4.1.
 *
 *   success: { ok: true,  data: {...}, meta: { cached, took_ms } }
 *   failure: { ok: false, error: { code, message } }
 *
 * `ok` is always present so a client branches on exactly one field. Building
 * the envelope in one module keeps a route from inventing its own shape — the
 * Flutter app parses these with a single generated model, and one route
 * returning a bare object would surface as a null-check crash on a patient's
 * phone rather than a compile error here.
 */

import { TrueMedError, CODES, isTrueMedError, internalError } from './errors.js';

/**
 * @param {unknown} data
 * @param {{cached?: boolean, tookMs?: number, extra?: object}} [meta]
 */
export function success(data, meta = {}) {
  const envelope = {
    ok: true,
    data,
    meta: {
      cached: meta.cached ?? false,
      took_ms: Math.max(0, Math.round(meta.tookMs ?? 0)),
    },
  };
  if (meta.extra && typeof meta.extra === 'object') {
    Object.assign(envelope.meta, meta.extra);
  }
  return envelope;
}

/**
 * Coerce anything thrown into the failure envelope.
 *
 * Unknown throwables become INTERNAL_ERROR with a fixed message. Echoing an
 * arbitrary `err.message` to the client is how stack frames, SQL fragments and
 * connection strings end up in a screenshot.
 */
export function failure(err) {
  if (isTrueMedError(err)) {
    const message = err.expose === false ? 'internal error' : err.message;
    const error = { code: err.code, message };
    if (err.details !== undefined) error.details = err.details;
    return { ok: false, error };
  }
  return {
    ok: false,
    error: { code: CODES.INTERNAL_ERROR, message: 'internal error' },
  };
}

/** Normalise any throwable into a TrueMedError, preserving ours untouched. */
export function toTrueMedError(err) {
  if (err instanceof TrueMedError) return err;
  if (isTrueMedError(err)) {
    const wrapped = new TrueMedError(err.code, err.message, {
      status: err.status,
      details: err.details,
      expose: err.expose,
    });
    return wrapped;
  }
  return internalError(err);
}

/**
 * Wall-clock milliseconds for `meta.took_ms`.
 *
 * `performance.now()` rather than `Date.now()`: it is monotonic, so an NTP step
 * mid-request cannot produce a negative duration.
 */
export const startTimer = () => {
  const t0 = performance.now();
  return () => performance.now() - t0;
};

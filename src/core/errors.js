/**
 * Typed errors carrying the machine-readable codes from DATA-CONTRACT.md §2.4.
 *
 * The app switches on `code`, never on prose, so these strings are part of the
 * frozen v1 contract. The HTTP status is derived from the code in one place
 * here rather than chosen at each throw site, because the same failure reached
 * from two routes must not answer 400 in one and 422 in the other — the Flutter
 * client would need two code paths for one condition.
 *
 * Mirrors qr-generator/truemed_qr/errors.py.
 */

/** Every code in §2.4, plus the internal catch-all. */
export const CODES = Object.freeze({
  QR_MALFORMED: 'QR_MALFORMED',
  QR_UNKNOWN_VERSION: 'QR_UNKNOWN_VERSION',
  PAYLOAD_INVALID: 'PAYLOAD_INVALID',
  SIGNATURE_INVALID: 'SIGNATURE_INVALID',
  SIGNATURE_KEY_UNKNOWN: 'SIGNATURE_KEY_UNKNOWN',
  EXPIRED: 'EXPIRED',
  NOT_ON_CHAIN: 'NOT_ON_CHAIN',
  RECALLED: 'RECALLED',
  COLD_CHAIN_BREACH: 'COLD_CHAIN_BREACH',
  CLONE_SUSPECTED: 'CLONE_SUSPECTED',
  UPSTREAM_UNAVAILABLE: 'UPSTREAM_UNAVAILABLE',
  RATE_LIMITED: 'RATE_LIMITED',
  UNAUTHORIZED: 'UNAUTHORIZED',
  FORBIDDEN: 'FORBIDDEN',
  VALIDATION_ERROR: 'VALIDATION_ERROR',
  NOT_FOUND: 'NOT_FOUND',
  CONFLICT: 'CONFLICT',
  INTERNAL_ERROR: 'INTERNAL_ERROR',
});

/**
 * Code → HTTP status.
 *
 * Note that a *verification* failure is not an HTTP failure. A counterfeit
 * medicine is a successful answer to "is this genuine?", so the verify routes
 * return 200 with a verdict body; only protocol-level problems map to 4xx.
 * Conflating the two would make every counterfeit look like a client bug in the
 * app's error handling and in any monitoring built on status codes.
 */
const STATUS = Object.freeze({
  [CODES.QR_MALFORMED]: 400,
  [CODES.QR_UNKNOWN_VERSION]: 400,
  [CODES.PAYLOAD_INVALID]: 400,
  [CODES.VALIDATION_ERROR]: 400,
  [CODES.SIGNATURE_INVALID]: 400,
  [CODES.SIGNATURE_KEY_UNKNOWN]: 400,
  [CODES.UNAUTHORIZED]: 401,
  [CODES.FORBIDDEN]: 403,
  [CODES.NOT_FOUND]: 404,
  [CODES.NOT_ON_CHAIN]: 404,
  [CODES.CONFLICT]: 409,
  [CODES.EXPIRED]: 200,
  [CODES.RECALLED]: 200,
  [CODES.COLD_CHAIN_BREACH]: 200,
  [CODES.CLONE_SUSPECTED]: 200,
  [CODES.RATE_LIMITED]: 429,
  [CODES.UPSTREAM_UNAVAILABLE]: 503,
  [CODES.INTERNAL_ERROR]: 500,
});

export class TrueMedError extends Error {
  /**
   * @param {string} code    one of CODES
   * @param {string} message human-readable, safe for a developer
   * @param {{status?: number, details?: unknown, cause?: unknown,
   *          expose?: boolean}} [opts]
   */
  constructor(code, message, opts = {}) {
    super(message, opts.cause ? { cause: opts.cause } : undefined);
    this.name = 'TrueMedError';
    this.code = CODES[code] ? code : CODES.INTERNAL_ERROR;
    this.status = opts.status ?? STATUS[this.code] ?? 500;
    if (opts.details !== undefined) this.details = opts.details;
    // `expose` decides whether `message` reaches the client. Default: yes for
    // 4xx (the caller can fix it), no for 5xx (it may name internal hosts).
    this.expose = opts.expose ?? this.status < 500;
  }

  toJSON() {
    const error = { code: this.code, message: this.message };
    if (this.details !== undefined) error.details = this.details;
    return { ok: false, error };
  }
}

export const httpStatusFor = (code) => STATUS[code] ?? 500;

// ── Constructors ─────────────────────────────────────────────────────────────
// Named helpers rather than subclasses: the code is the identity, and a
// subclass per code would be 18 near-empty classes that add nothing.

export const validationError = (message, details) =>
  new TrueMedError(CODES.VALIDATION_ERROR, message, { details });

export const unauthorized = (message = 'missing or invalid API key') =>
  new TrueMedError(CODES.UNAUTHORIZED, message);

export const forbidden = (message) => new TrueMedError(CODES.FORBIDDEN, message);

export const notFound = (message) => new TrueMedError(CODES.NOT_FOUND, message);

export const notOnChain = (productID) =>
  new TrueMedError(
    CODES.NOT_ON_CHAIN,
    `no medicine with product_id ${productID} exists on the blockchain`,
  );

export const conflict = (message) => new TrueMedError(CODES.CONFLICT, message);

export const rateLimited = (retryAfterSeconds) => {
  const err = new TrueMedError(
    CODES.RATE_LIMITED,
    'too many requests; slow down and retry shortly',
  );
  err.retryAfter = Math.max(1, Math.ceil(retryAfterSeconds));
  return err;
};

/**
 * Fabric, PostgreSQL or Redis is unreachable.
 *
 * `expose: false` because the underlying message routinely contains peer
 * hostnames, ports and TLS paths — a map of the deployment, handed to anyone
 * who can reach the public verify endpoint.
 */
export const upstreamUnavailable = (what, cause) =>
  new TrueMedError(
    CODES.UPSTREAM_UNAVAILABLE,
    `${what} is currently unreachable; the request was not applied`,
    { cause, expose: true, details: undefined },
  );

export const internalError = (cause) =>
  new TrueMedError(CODES.INTERNAL_ERROR, 'internal error', { cause });

/** True when `err` is one of ours and therefore already contract-shaped. */
export const isTrueMedError = (err) =>
  err instanceof TrueMedError ||
  (err !== null &&
    typeof err === 'object' &&
    typeof err.code === 'string' &&
    typeof err.status === 'number' &&
    CODES[err.code] !== undefined);

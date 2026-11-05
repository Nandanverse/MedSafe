/**
 * The trust bundle: which manufacturer public keys are legitimate.
 *
 * Port of the `TrustedKey` / `TrustBundle` half of
 * qr-generator/truemed_qr/crypto.py.
 *
 * Two levels of key, and the second one is the whole point:
 *
 * - **Manufacturer keys** sign individual QR payloads, one per manufacturing
 *   licence number.
 * - **A root key** (conceptually CDSCO's, kept offline) signs the bundle itself.
 *
 * Without the root signature there is a fatal hole. The mobile app has to learn
 * manufacturer public keys from somewhere, and if it trusts whatever
 * `GET /api/public-keys` returns, then anyone who can impersonate that endpoint —
 * a compromised server, a hostile network, a repackaged APK — inserts their own
 * key and mints QR codes that verify perfectly. Pinning one root public key in
 * the app binary and requiring the bundle to be root-signed means an attacker
 * must reach the offline root key, not merely this API.
 *
 * Which is why the bundle this module serves to the app is the **original bytes
 * as loaded from disk**, never a re-serialisation. See `rawJSON()`.
 */

import { TrueMedError, CODES } from './errors.js';
import { canonicalJSONBytes } from './canonical.js';
import { fingerprint, loadPublicKey, verify } from './ecdsa.js';
import { parseDate, dayOf } from './rules.js';

export const TRUST_BUNDLE_VERSION = 1;

export const KEY_STATUS = Object.freeze({ ACTIVE: 'active', REVOKED: 'revoked' });

const REQUIRED_KEY_FIELDS = Object.freeze([
  'mfg_licence_no',
  'manufacturer',
  'public_key_pem',
  'fingerprint',
  'valid_from',
  'valid_until',
]);

/**
 * A malformed or unsigned bundle is a server misconfiguration, not a client
 * error — it is detected at startup, from files the operator controls. So it maps
 * to INTERNAL_ERROR (500, message withheld from clients but logged in full)
 * rather than borrowing one of the client-facing verification codes.
 *
 * Python calls this `KEYSTORE_ERROR`, which is not one of the 15 codes in
 * DATA-CONTRACT.md §2.4 because it never reaches an HTTP response.
 */
const keyStoreError = (message) =>
  new TrueMedError(CODES.INTERNAL_ERROR, `trust bundle: ${message}`, {
    expose: false,
  });

const keyUnknown = (message) =>
  new TrueMedError(CODES.SIGNATURE_KEY_UNKNOWN, message);

/** One manufacturer signing key, as distributed to the app. */
export class TrustedKey {
  constructor(raw) {
    for (const field of REQUIRED_KEY_FIELDS) {
      if (typeof raw?.[field] !== 'string' || !raw[field]) {
        throw keyStoreError(
          `trusted key entry is missing or has a non-string '${field}'`,
        );
      }
    }
    this.mfgLicenceNo = raw.mfg_licence_no;
    this.manufacturer = raw.manufacturer;
    this.publicKeyPEM = raw.public_key_pem;
    this.fingerprint = raw.fingerprint;
    this.validFrom = raw.valid_from;
    this.validUntil = raw.valid_until;
    this.status = raw.status ?? KEY_STATUS.ACTIVE;

    // Validate the dates now rather than at verification time. A typo in
    // valid_until should stop the server starting, not silently make every strip
    // from one manufacturer unverifiable at 3am.
    parseDate('valid_from', this.validFrom);
    parseDate('valid_until', this.validUntil);

    this.publicKeyObject = null; // lazily loaded and cached by publicKey()
    Object.seal(this);
  }

  /**
   * The parsed key, cached.
   *
   * Python reloads the PEM on every lookup; here the bundle lives for the
   * process's lifetime and this runs on the hot path of every verification, so
   * the parse is done once. Behaviour is identical, including that a broken PEM
   * throws on first use.
   */
  publicKey() {
    if (this.publicKeyObject === null) {
      this.publicKeyObject = loadPublicKey(this.publicKeyPEM);
      const actual = fingerprint(this.publicKeyObject);
      if (actual !== this.fingerprint) {
        // Not a security control — an attacker editing the bundle would fix both
        // fields — but it catches a bundle assembled by hand or by a buggy script
        // before those keys silently fail to match anything.
        throw keyStoreError(
          `entry for licence ${this.mfgLicenceNo} claims fingerprint ` +
            `${this.fingerprint} but its PEM hashes to ${actual}`,
        );
      }
    }
    return this.publicKeyObject;
  }

  /** Active, and `when` falls inside the validity window (inclusive). */
  isValidOn(when) {
    if (this.status !== KEY_STATUS.ACTIVE) return false;
    const day = dayOf(when ?? new Date());
    return (
      parseDate('valid_from', this.validFrom) <= day &&
      day <= parseDate('valid_until', this.validUntil)
    );
  }

  /** Exactly the shape the root signature is computed over. */
  toDict() {
    return {
      mfg_licence_no: this.mfgLicenceNo,
      manufacturer: this.manufacturer,
      public_key_pem: this.publicKeyPEM,
      fingerprint: this.fingerprint,
      valid_from: this.validFrom,
      valid_until: this.validUntil,
      status: this.status,
    };
  }

  /** Public view for `GET /api/public-keys` listings. No PEM-only secrets exist. */
  toPublicDict() {
    return this.toDict();
  }
}

export class TrustBundle {
  /**
   * @param {TrustedKey[]} keys
   * @param {{issuedAt?: string, raw?: string, rootSignatureHex?: string,
   *          rootFingerprint?: string}} [meta]
   */
  constructor(keys, meta = {}) {
    this.keys = keys;
    this.issuedAt = meta.issuedAt ?? new Date().toISOString().slice(0, 19) + 'Z';
    this.raw = meta.raw ?? null;
    this.rootSignatureHex = meta.rootSignatureHex ?? null;
    this.rootFingerprint = meta.rootFingerprint ?? null;

    this.byLicence = new Map();
    for (const key of keys) {
      if (this.byLicence.has(key.mfgLicenceNo)) {
        throw keyStoreError(
          `duplicate manufacturing licence ${JSON.stringify(key.mfgLicenceNo)} — ` +
            'one licence maps to exactly one active signing key',
        );
      }
      this.byLicence.set(key.mfgLicenceNo, key);
    }
  }

  get size() {
    return this.keys.length;
  }

  has(mfgLicenceNo) {
    return this.byLicence.has(mfgLicenceNo);
  }

  entryFor(mfgLicenceNo) {
    return this.byLicence.get(mfgLicenceNo) ?? null;
  }

  /**
   * Resolve a licence number to its trusted public key.
   *
   * Throws SIGNATURE_KEY_UNKNOWN for both "no such licence" and "revoked or out
   * of window". The verifier turns that into UNVERIFIABLE (amber), never
   * COUNTERFEIT (red) — see the reasoning in verifier.js.
   *
   * @returns {import('node:crypto').KeyObject}
   */
  publicKeyFor(mfgLicenceNo, when) {
    const entry = this.byLicence.get(mfgLicenceNo);
    if (!entry) {
      throw keyUnknown(
        'no trusted signing key registered for manufacturing licence ' +
          `${JSON.stringify(mfgLicenceNo)}; either the trust bundle is stale or ` +
          'this QR was signed by an unregistered party',
      );
    }
    if (!entry.isValidOn(when)) {
      throw keyUnknown(
        `signing key for licence ${JSON.stringify(mfgLicenceNo)} is ` +
          `${entry.status} / outside its validity window ${entry.validFrom}..` +
          entry.validUntil,
      );
    }
    return entry.publicKey();
  }

  /** Canonical bytes covered by the root signature. */
  signableBytes() {
    return canonicalJSONBytes({
      version: TRUST_BUNDLE_VERSION,
      issued_at: this.issuedAt,
      keys: this.keys.map((k) => k.toDict()),
    });
  }

  /**
   * The bytes to serve from `GET /api/public-keys`.
   *
   * Verbatim as loaded, when we have them. This is not an optimisation. The app
   * verifies the root signature over the bundle's canonical form, and a
   * re-serialisation here — a different key order, `indent=2` versus none, an
   * `issued_at` we defaulted — produces different bytes and a signature that
   * fails on a perfectly genuine bundle. The API holds no root private key, so it
   * cannot re-sign what it changes. It must therefore change nothing.
   */
  rawJSON() {
    if (this.raw !== null) return this.raw;
    throw keyStoreError(
      'this bundle was built in memory rather than loaded from bytes, so it has ' +
        'no root signature to serve. Load it with TrustBundle.fromJSON().',
    );
  }

  /** Metadata for logs and the `/api/health` payload. */
  summary() {
    const active = this.keys.filter((k) => k.status === KEY_STATUS.ACTIVE).length;
    return {
      version: TRUST_BUNDLE_VERSION,
      issued_at: this.issuedAt,
      key_count: this.keys.length,
      active_key_count: active,
      root_fingerprint: this.rootFingerprint,
      signed: this.rootSignatureHex !== null,
    };
  }

  /**
   * Parse and (by default) verify a bundle.
   *
   * @param {string|Buffer} blob
   * @param {{rootPublicKey?: import('node:crypto').KeyObject|string,
   *          requireSignature?: boolean}} [opts]
   */
  static fromJSON(blob, opts = {}) {
    const { rootPublicKey = null, requireSignature = true } = opts;
    const text = typeof blob === 'string' ? blob : blob.toString('utf8');

    let raw;
    try {
      raw = JSON.parse(text);
    } catch (err) {
      throw keyStoreError(`not valid JSON: ${err.message}`);
    }
    if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
      throw keyStoreError('must be a JSON object');
    }
    if (raw.version !== TRUST_BUNDLE_VERSION) {
      throw keyStoreError(
        `unsupported version ${JSON.stringify(raw.version)}; this build ` +
          `understands version ${TRUST_BUNDLE_VERSION}`,
      );
    }
    if (!Array.isArray(raw.keys)) {
      throw keyStoreError("'keys' must be an array");
    }

    const bundle = new TrustBundle(
      raw.keys.map((entry) => new TrustedKey(entry)),
      {
        issuedAt: raw.issued_at,
        raw: text,
        rootSignatureHex: typeof raw.root_signature === 'string'
          ? raw.root_signature
          : null,
        rootFingerprint: typeof raw.root_fingerprint === 'string'
          ? raw.root_fingerprint
          : null,
      },
    );

    if (!requireSignature) return bundle;

    if (rootPublicKey === null) {
      throw keyStoreError(
        'signature required but no root public key was supplied; an unverified ' +
          'trust bundle is worthless — whoever can serve it can insert their own ' +
          'signing key',
      );
    }
    if (bundle.rootSignatureHex === null) {
      throw keyStoreError('bundle is unsigned and a signature is required');
    }
    if (!/^[0-9a-fA-F]*$/.test(bundle.rootSignatureHex) ||
        bundle.rootSignatureHex.length % 2 !== 0) {
      throw keyStoreError('root_signature is not valid hex');
    }

    const rootKey =
      typeof rootPublicKey === 'string' ? loadPublicKey(rootPublicKey) : rootPublicKey;
    const signature = Buffer.from(bundle.rootSignatureHex, 'hex');

    if (!verify(rootKey, bundle.signableBytes(), signature)) {
      throw new TrueMedError(
        CODES.SIGNATURE_INVALID,
        'trust bundle root signature is invalid — refusing to load. Either the ' +
          'bundle was tampered with in transit or it was signed by a key this ' +
          'build does not pin.',
        { expose: false },
      );
    }
    return bundle;
  }

  /** One-key bundle. For tests and single-manufacturer demos. */
  static single({
    mfgLicenceNo,
    manufacturer,
    publicKeyPEM,
    validFrom = '2020-01-01',
    validUntil = '2099-12-31',
  }) {
    return new TrustBundle([
      new TrustedKey({
        mfg_licence_no: mfgLicenceNo,
        manufacturer,
        public_key_pem: publicKeyPEM,
        fingerprint: fingerprint(publicKeyPEM),
        valid_from: validFrom,
        valid_until: validUntil,
        status: KEY_STATUS.ACTIVE,
      }),
    ]);
  }
}

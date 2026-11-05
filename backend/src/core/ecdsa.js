/**
 * ECDSA P-256 verification, and the key fingerprint scheme.
 *
 * Port of the signing half of qr-generator/truemed_qr/crypto.py. The backend
 * only ever *verifies*: signing lives on the manufacturer's host, and the API
 * never sees a manufacturer private key. There is deliberately no `sign()` here —
 * an unused signing path in a network-facing service is an invitation.
 *
 * Signature encoding is raw `r‖s`, 64 bytes, not the ASN.1 DER that most
 * libraries emit natively. DER is variable-length (70–72 bytes typically) and
 * carries redundant structure; raw is fixed-length and 8 bytes shorter, which
 * matters when the budget is a printed square centimetre. DER also has a long
 * history of parser-differential bugs, and a fixed-length format has no parser.
 *
 * Node calls this encoding `ieee-p1363`.
 */

import { createHash, createPublicKey, verify as cryptoVerify } from 'node:crypto';
import { TrueMedError, CODES } from './errors.js';

/** P-256 field size in bytes. Each of r and s occupies exactly this. */
export const COORD_LEN = 32;
export const SIGNATURE_LEN = COORD_LEN * 2;

/** What Node calls P-256 / secp256r1 in `asymmetricKeyDetails.namedCurve`. */
const P256_CURVE = 'prime256v1';
const HASH_ALGO = 'sha256';

/** Node's name for raw r‖s. Getting this wrong makes every check fail closed. */
const DSA_ENCODING = 'ieee-p1363';

const keyStoreError = (message) =>
  new TrueMedError(CODES.SIGNATURE_KEY_UNKNOWN, message);

/**
 * Load a P-256 public key from SubjectPublicKeyInfo PEM, rejecting anything else.
 *
 * The curve is pinned rather than inferred. Accepting whatever curve a key
 * happens to carry would let an attacker who can get a key into the bundle
 * downgrade to a weak curve — and the resulting signatures would verify
 * perfectly, so nothing downstream would notice. TrueMed v1 is P-256, full stop.
 *
 * @param {string|Buffer} pem
 * @returns {import('node:crypto').KeyObject}
 */
export function loadPublicKey(pem) {
  let key;
  try {
    key = createPublicKey({
      key: typeof pem === 'string' ? pem : pem.toString('utf8'),
      format: 'pem',
    });
  } catch (err) {
    throw keyStoreError(`could not load public key: ${err.message}`);
  }
  if (key.asymmetricKeyType !== 'ec') {
    throw keyStoreError(
      `expected an EC public key, got ${key.asymmetricKeyType}; TrueMed v1 ` +
        'verifies ECDSA P-256',
    );
  }
  const curve = key.asymmetricKeyDetails?.namedCurve;
  if (curve !== P256_CURVE) {
    throw keyStoreError(
      `public key is on curve ${curve}, but TrueMed v1 requires ${P256_CURVE} (P-256)`,
    );
  }
  return key;
}

/**
 * Short stable identifier: first 8 bytes of SHA-256 over the DER SPKI, hex.
 *
 * Used in logs, the trust bundle, and CLI output so a human can tell two keys
 * apart without comparing whole PEM blocks. Not a security boundary — the
 * signature check is. Byte-identical to `crypto.fingerprint()` in Python because
 * both hash the same DER encoding of the same key.
 *
 * @param {import('node:crypto').KeyObject|string|Buffer} key
 * @returns {string} 16 lowercase hex characters
 */
export function fingerprint(key) {
  const keyObject =
    typeof key === 'string' || Buffer.isBuffer(key) ? loadPublicKey(key) : key;
  const der = keyObject.export({ type: 'spki', format: 'der' });
  return createHash('sha256').update(der).digest('hex').slice(0, 16);
}

/**
 * Verify a raw 64-byte signature. Returns false rather than throwing.
 *
 * Every failure mode — wrong length, wrong key, tampered data, zero-valued r or
 * s, a malformed key — collapses to `false`. Callers decide what a failure
 * means; here it is uniformly "not authentic", so no exception type or message
 * distinguishes *why* a forgery failed.
 *
 * @param {import('node:crypto').KeyObject} publicKey
 * @param {Uint8Array|Buffer} data the bytes as received, never re-serialised
 * @param {Uint8Array|Buffer} signature raw r‖s
 * @returns {boolean}
 */
export function verify(publicKey, data, signature) {
  if (!(signature instanceof Uint8Array) || signature.length !== SIGNATURE_LEN) {
    return false;
  }
  if (!(data instanceof Uint8Array)) return false;

  // r = 0 or s = 0 is never a valid ECDSA signature, and naive verifiers have
  // historically accepted them. Checked explicitly so the guarantee does not
  // depend on an OpenSSL implementation detail.
  if (isAllZero(signature.subarray(0, COORD_LEN))) return false;
  if (isAllZero(signature.subarray(COORD_LEN))) return false;

  try {
    return cryptoVerify(
      HASH_ALGO,
      data,
      { key: publicKey, dsaEncoding: DSA_ENCODING },
      signature,
    );
  } catch {
    // A bad key object or an OpenSSL-level rejection is still just "not authentic".
    return false;
  }
}

function isAllZero(bytes) {
  for (const byte of bytes) if (byte !== 0) return false;
  return true;
}

/** Verify, throwing SIGNATURE_INVALID on failure. */
export function verifyOrThrow(publicKey, data, signature) {
  if (!verify(publicKey, data, signature)) {
    throw new TrueMedError(
      CODES.SIGNATURE_INVALID,
      'ECDSA signature does not match the payload under the trusted key for ' +
        'this manufacturing licence — treat this item as counterfeit',
    );
  }
}

/**
 * SHA-256 hex of an API key, as stored in PostgreSQL.
 *
 * A plain hash rather than bcrypt or argon2 is deliberate and correct *here*: an
 * API key is 128 bits of CSPRNG output, not a human-chosen password, so it has no
 * dictionary to attack and stretching buys nothing while costing latency on every
 * single request. The reasoning does not transfer to user passwords.
 */
export const hashAPIKey = (apiKey) =>
  createHash('sha256').update(apiKey, 'utf8').digest('hex');

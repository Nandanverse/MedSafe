/**
 * Authenticated encryption for the two secrets that cannot be hashed.
 *
 * Almost everything sensitive in TrueMed is stored as a SHA-256 hash, which is
 * strictly safer because a leak yields nothing usable. Two values cannot be
 * hashed, and it is worth being precise about why:
 *
 * - `sensors.secret_enc` — the HMAC shared secret. Verifying a reading means
 *   *recomputing* HMAC-SHA256 over `product_id|sensor_id|temperature|recorded_at|nonce`,
 *   which needs the key itself. A hash would make verification impossible.
 * - `counterfeit_reports.reporter_contact_enc` — a phone number a regulator may
 *   need to call while investigating. Hashing it would defeat its only purpose.
 *
 * So they are encrypted at rest with AES-256-GCM. The threat this addresses is
 * the one that actually happens: a leaked database dump, a stolen backup file, a
 * misconfigured replica. In each case the attacker gets rows but not the process
 * environment, and rows alone are useless.
 *
 * Two design points that are easy to get wrong:
 *
 * **Every ciphertext is bound to its row by AAD.** The associated data is a
 * caller-supplied context string such as `sensor:TM-SENSOR-001`. Without it, an
 * attacker with write access to the database could copy a known sensor's
 * encrypted secret into another sensor's row and then sign readings for that
 * second sensor with a secret they already know. GCM's tag covers the AAD, so a
 * moved ciphertext fails to decrypt rather than silently working.
 *
 * **The nonce is random per encryption, never a counter.** Reusing a
 * nonce-with-key pair under GCM is catastrophic — it leaks the XOR of the two
 * plaintexts and, worse, allows forging the authentication tag for arbitrary
 * messages. 96 random bits from `randomBytes` is the standard construction and
 * requires no state to be kept anywhere.
 *
 * Wire layout of the stored `bytea`:
 *
 *     byte 0        format version (0x01)
 *     bytes 1..12   96-bit random nonce
 *     bytes 13..28  128-bit GCM authentication tag
 *     bytes 29..    ciphertext
 *
 * The version byte comes first so a future migration to a different cipher can
 * be applied lazily: read both formats, write only the new one.
 */

import { createCipheriv, createDecipheriv, createHash, randomBytes, timingSafeEqual } from 'node:crypto';

const VERSION = 0x01;
const NONCE_BYTES = 12;
const TAG_BYTES = 16;
const HEADER_BYTES = 1 + NONCE_BYTES + TAG_BYTES;
const ALGORITHM = 'aes-256-gcm';

/**
 * Derive the 32-byte AES key from the configured key material.
 *
 * A plain SHA-256 rather than a KDF with a work factor, deliberately: the input
 * is required to be 32 bytes of CSPRNG output (`openssl rand -hex 32`), not a
 * human-chosen passphrase, so there is nothing for a slow KDF to defend. Adding
 * one would imply a guessability that does not exist and would slow every startup
 * for no gain. The hash is here only to accept the development label, which is
 * not 32 bytes, and to normalise hex input to raw bytes.
 *
 * @param {string} keyMaterial
 * @returns {Buffer} 32 bytes
 */
function deriveKey(keyMaterial) {
  if (typeof keyMaterial !== 'string' || keyMaterial.length === 0) {
    throw new TypeError('secret-box: key material must be a non-empty string');
  }
  if (/^[0-9a-f]{64}$/i.test(keyMaterial)) {
    return Buffer.from(keyMaterial, 'hex');
  }
  // Domain-separated so this key cannot collide with any other use of the same
  // secret elsewhere in the system.
  return createHash('sha256').update(`truemed/secret-box/v1\n${keyMaterial}`, 'utf8').digest();
}

export class SecretBox {
  /**
   * @param {string} keyMaterial 64 hex characters, or any string in development
   */
  constructor(keyMaterial) {
    // Held as a Buffer on the instance rather than re-derived per call. Not
    // frozen or hidden: JavaScript offers no way to keep a key out of a heap
    // dump, and pretending otherwise would be security theatre. The defence here
    // is at rest, not in memory.
    this.#key = deriveKey(keyMaterial);
  }

  #key;

  /**
   * Encrypt a UTF-8 string.
   *
   * @param {string} plaintext
   * @param {string} context identifies the row this ciphertext belongs to, e.g.
   *   `sensor:TM-SENSOR-001`. Must be supplied at decryption time too.
   * @returns {Buffer} the value to store in a `bytea` column
   */
  seal(plaintext, context) {
    if (typeof plaintext !== 'string') {
      throw new TypeError('secret-box: plaintext must be a string');
    }
    assertContext(context);

    const nonce = randomBytes(NONCE_BYTES);
    const cipher = createCipheriv(ALGORITHM, this.#key, nonce);
    cipher.setAAD(Buffer.from(context, 'utf8'));
    const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();

    return Buffer.concat([Buffer.from([VERSION]), nonce, tag, ciphertext]);
  }

  /**
   * Decrypt a value produced by `seal`.
   *
   * @param {Buffer|Uint8Array} sealed
   * @param {string} context must equal the context used to seal
   * @returns {string}
   * @throws {SecretBoxError} on a wrong key, a wrong context, or any tampering
   */
  open(sealed, context) {
    assertContext(context);
    const buf = Buffer.isBuffer(sealed) ? sealed : Buffer.from(sealed ?? []);

    if (buf.length < HEADER_BYTES) {
      throw new SecretBoxError(`sealed value is ${buf.length} bytes, shorter than the ${HEADER_BYTES}-byte header`);
    }
    if (buf[0] !== VERSION) {
      throw new SecretBoxError(`unsupported sealed-value version 0x${buf[0].toString(16).padStart(2, '0')}`);
    }

    const nonce = buf.subarray(1, 1 + NONCE_BYTES);
    const tag = buf.subarray(1 + NONCE_BYTES, HEADER_BYTES);
    const ciphertext = buf.subarray(HEADER_BYTES);

    try {
      const decipher = createDecipheriv(ALGORITHM, this.#key, nonce);
      decipher.setAAD(Buffer.from(context, 'utf8'));
      decipher.setAuthTag(tag);
      return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
    } catch (cause) {
      // Node throws "Unsupported state or unable to authenticate data" for a bad
      // key, a bad context and a flipped bit alike, and that is the right
      // behaviour to preserve: distinguishing them in the message would tell an
      // attacker which of the three they got wrong.
      throw new SecretBoxError('sealed value failed authentication (wrong key, wrong context, or tampered)', {
        cause,
      });
    }
  }

  /**
   * Decrypt, returning `null` instead of throwing when there is nothing to
   * decrypt.
   *
   * `reporter_contact_enc` is nullable — anonymous reporting must be possible —
   * so every read site would otherwise need the same null check.
   *
   * @param {Buffer|Uint8Array|null|undefined} sealed
   * @param {string} context
   * @returns {string|null}
   */
  openOrNull(sealed, context) {
    if (sealed === null || sealed === undefined) return null;
    const buf = Buffer.isBuffer(sealed) ? sealed : Buffer.from(sealed);
    if (buf.length === 0) return null;
    return this.open(buf, context);
  }

  /**
   * Constant-time comparison of a candidate secret against a sealed one.
   *
   * Used when verifying a sensor HMAC: the caller needs the secret to recompute a
   * MAC, but any place that compares secrets directly should not leak the length
   * of the matching prefix through timing.
   *
   * @param {Buffer|Uint8Array} sealed
   * @param {string} candidate
   * @param {string} context
   * @returns {boolean}
   */
  matches(sealed, candidate, context) {
    let actual;
    try {
      actual = this.open(sealed, context);
    } catch {
      return false;
    }
    const a = Buffer.from(actual, 'utf8');
    const b = Buffer.from(String(candidate), 'utf8');
    // timingSafeEqual throws on a length mismatch, which is itself a length
    // oracle. Hash both to a fixed width first so the comparison is always over
    // 32 bytes.
    const ha = createHash('sha256').update(a).digest();
    const hb = createHash('sha256').update(b).digest();
    return timingSafeEqual(ha, hb);
  }
}

export class SecretBoxError extends Error {
  constructor(message, opts) {
    super(message, opts);
    this.name = 'SecretBoxError';
  }
}

/**
 * A context is mandatory and must be non-empty.
 *
 * Defaulting it to `''` would be the easy thing to do and would silently remove
 * the row-binding property for every caller that forgot the argument, which is
 * exactly the kind of security regression that never shows up in a test.
 */
function assertContext(context) {
  if (typeof context !== 'string' || context.trim() === '') {
    throw new TypeError(
      'secret-box: a non-empty context string is required — it binds the ciphertext to its row',
    );
  }
}

/** Context string for a sensor's shared secret. */
export const sensorContext = (sensorID) => `sensor:${sensorID}`;

/** Context string for a reporter's contact detail. */
export const reportContext = (reportRef) => `report:${reportRef}`;

/**
 * Generate a sensor shared secret.
 *
 * 32 bytes of CSPRNG output, hex-encoded, because it has to be flashed into an
 * ESP32's firmware by a human and hex survives copy-paste into the Arduino IDE
 * without the base64 `+/=` characters becoming a debugging session.
 *
 * @returns {string} 64 hex characters
 */
export const generateSensorSecret = () => randomBytes(32).toString('hex');

export default SecretBox;

/**
 * The `TM1.<payload>.<signature>` wire format.
 *
 * Port of qr-generator/truemed_qr/codec.py, and the check order below is copied
 * deliberately rather than rewritten more naturally: the order determines which
 * error code a scan produces, and the Flutter app switches on that code to pick
 * between "this doesn't look like a TrueMed code" and "update the app". Reorder
 * these and the app shows the wrong message.
 *
 * `decode` returns the payload bytes exactly as they arrived. The verifier
 * signature-checks *those* bytes, never a re-serialisation of its own parse.
 * Re-serialising before verifying is a well-known signature-bypass pattern: any
 * disagreement between parser and serialiser — duplicate JSON keys, number
 * formatting, Unicode normalisation — lets an attacker craft input that verifies
 * under one reading and is acted on under another.
 */

import { TrueMedError, CODES } from './errors.js';
import { encodeB64u, decodeB64u } from './base64url.js';

export const WIRE_PREFIX = 'TM1';
export const SEPARATOR = '.';
export const CONTRACT_VERSION = 1;

/** Raw ECDSA P-256 signature length in bytes (r‖s, 32 each). */
export const SIG_LEN = 64;

/**
 * Refuse absurdly long input before doing any work. A QR v40 at ECC level L tops
 * out near 2953 bytes, so anything past this did not come from a QR code and is
 * more likely an attempt to make us allocate.
 */
export const MAX_WIRE_LEN = 4096;

const malformed = (message) => new TrueMedError(CODES.QR_MALFORMED, message);

/**
 * Assemble a wire string from canonical payload bytes and a raw signature.
 *
 * @param {Uint8Array|Buffer} payloadBytes
 * @param {Uint8Array|Buffer} signature 64 raw bytes
 * @returns {string}
 */
export function encode(payloadBytes, signature) {
  if (!(payloadBytes instanceof Uint8Array)) {
    throw new TypeError(`payloadBytes must be bytes, got ${typeof payloadBytes}`);
  }
  if (!(signature instanceof Uint8Array)) {
    throw new TypeError(`signature must be bytes, got ${typeof signature}`);
  }
  if (signature.length !== SIG_LEN) {
    throw new RangeError(
      `signature must be exactly ${SIG_LEN} raw bytes (r‖s), got ${signature.length}`,
    );
  }
  return [WIRE_PREFIX, encodeB64u(payloadBytes), encodeB64u(signature)].join(
    SEPARATOR,
  );
}

/**
 * @typedef {object} DecodedQR
 * @property {string} prefix
 * @property {Buffer} payloadBytes verbatim from the wire — never re-serialised
 * @property {Buffer} signature    64 raw bytes
 */

/**
 * Parse a scanned string into its three parts.
 *
 * Throws QR_MALFORMED for structural problems and QR_UNKNOWN_VERSION when the
 * prefix names a TrueMed format this build does not implement. That distinction
 * is the reason this function exists: a malformed string is probably not a
 * TrueMed code at all, whereas an unknown version means the app is out of date,
 * and telling a patient "this medicine is suspicious" when the real problem is
 * "your app needs updating" is both wrong and corrosive.
 *
 * @param {string} wire
 * @returns {DecodedQR}
 */
export function decode(wire) {
  if (typeof wire !== 'string') {
    throw malformed(`expected a string, got ${typeof wire}`);
  }

  // Scanners and clipboards routinely append newlines or surrounding spaces.
  const text = wire.trim();
  if (!text) throw malformed('scanned string is empty');
  if (text.length > MAX_WIRE_LEN) {
    throw malformed(
      `scanned string is ${text.length} characters, beyond any real QR code's ` +
        `capacity (${MAX_WIRE_LEN} accepted at most)`,
    );
  }

  const parts = text.split(SEPARATOR);

  // "Is this ours at all?" comes before structural validation. Checking the part
  // count first would answer a scanned UPI sticker with "expected 3
  // dot-separated parts" — a developer's message on a patient's screen.
  if (!parts[0].toUpperCase().startsWith('TM')) {
    throw malformed(
      `not a TrueMed QR code: expected prefix ${JSON.stringify(WIRE_PREFIX)}, ` +
        `found ${JSON.stringify(parts[0].slice(0, 16))}`,
    );
  }

  if (parts.length !== 3) {
    throw malformed(
      'expected 3 dot-separated parts (prefix.payload.signature), found ' +
        String(parts.length),
    );
  }

  const [prefix, payloadB64, sigB64] = parts;

  if (prefix !== WIRE_PREFIX) {
    throw new TrueMedError(
      CODES.QR_UNKNOWN_VERSION,
      `QR uses TrueMed format ${JSON.stringify(prefix)}; this build only ` +
        `implements ${WIRE_PREFIX}. Update the app to verify newer codes — it ` +
        'will not guess.',
    );
  }

  if (!payloadB64) throw malformed('payload part is empty');
  if (!sigB64) throw malformed('signature part is empty');

  const payloadBytes = decodeB64u(payloadB64, 'payload');
  const signature = decodeB64u(sigB64, 'signature');

  if (signature.length !== SIG_LEN) {
    throw malformed(
      `signature decodes to ${signature.length} bytes; a raw ECDSA P-256 ` +
        `signature is exactly ${SIG_LEN} (r‖s, 32 each)`,
    );
  }

  return { prefix, payloadBytes, signature };
}

/**
 * Cheap pre-filter for the scanner.
 *
 * The camera sees every QR in frame — WiFi codes, UPI codes, posters. It should
 * silently ignore anything that is not ours rather than flashing a counterfeit
 * warning at a payment sticker.
 */
export const looksLikeTrueMed = (text) =>
  typeof text === 'string' && text.trim().startsWith(WIRE_PREFIX + SEPARATOR);

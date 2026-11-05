/**
 * base64url (RFC 4648 §5) without padding, matching
 * qr-generator/truemed_qr/codec.py.
 *
 * The alphabet is checked explicitly before decoding, and that check is not
 * redundant with Node's own leniency — it is the point of this module.
 * `Buffer.from(s, 'base64')` ignores characters outside the alphabet entirely
 * and treats `-`/`_` and `+`/`/` as interchangeable. So `"A-AA"` and `"A+AA"`
 * decode to identical bytes, and so does `"A-A A"`.
 *
 * That is signature malleability. It forges nothing, but it means one payload
 * has many valid wire encodings, and the clone defence in DATA-CONTRACT.md §2.2
 * counts scans per distinct code. An attacker who can mint variant spellings of
 * one genuine QR gets unlimited free scans without ever tripping the duplicate
 * counter — quietly disabling the only control that catches a photocopied
 * strip. Hence: validate the alphabet, then decode.
 */

import { TrueMedError, CODES } from './errors.js';

/** Unpadded base64url alphabet. `=` is excluded: we strip padding on encode. */
const ALPHABET = /^[A-Za-z0-9_-]*$/;
const STRAY = /[^A-Za-z0-9_-]/;

/** @param {Uint8Array|Buffer} raw */
export function encodeB64u(raw) {
  return Buffer.from(raw).toString('base64url');
}

/**
 * Decode, rejecting anything outside the unpadded base64url alphabet.
 *
 * @param {string} text
 * @param {string} what label used in the error message
 * @returns {Buffer}
 */
export function decodeB64u(text, what = 'value') {
  if (typeof text !== 'string') {
    throw new TrueMedError(
      CODES.QR_MALFORMED,
      `${what} must be a string, got ${typeof text}`,
    );
  }
  const stray = STRAY.exec(text);
  if (stray) {
    throw new TrueMedError(
      CODES.QR_MALFORMED,
      `${what} contains ${JSON.stringify(stray[0])} at position ${stray.index}, ` +
        'which is not in the base64url alphabet (A-Z a-z 0-9 - _)',
    );
  }
  // A single leftover character cannot be the tail of any base64 group: 1 char
  // carries 6 bits, and no byte boundary falls there. Buffer would silently
  // drop it.
  if (text.length % 4 === 1) {
    throw new TrueMedError(
      CODES.QR_MALFORMED,
      `${what} is ${text.length} base64url characters, which is not a valid length`,
    );
  }
  const decoded = Buffer.from(text, 'base64url');
  // Round-trip check. Buffer.from is permissive about a final character whose
  // low bits are non-zero (e.g. "QQF" and "QQE" both decode to the same two
  // bytes), which is the same malleability problem as the alphabet above.
  if (decoded.toString('base64url') !== text) {
    throw new TrueMedError(
      CODES.QR_MALFORMED,
      `${what} is not canonically encoded unpadded base64url`,
    );
  }
  return decoded;
}

export const isB64u = (text) => typeof text === 'string' && ALPHABET.test(text);

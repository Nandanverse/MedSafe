/**
 * Canonical JSON, byte-identical to Python's
 * `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`.
 *
 * Needed because two things are signed across two languages: the QR payload
 * (Python signs, Node and Dart verify) and the trust bundle (Python signs, Node
 * serves, Dart verifies). A one-byte difference in serialisation is a signature
 * that fails on genuine data, so the rules are pinned here explicitly rather
 * than left to each language's defaults.
 *
 * Where the two languages already agree, and why:
 *
 * - `JSON.stringify` emits no whitespace by default, matching `separators`.
 * - Neither escapes non-ASCII once Python has `ensure_ascii=False`, so Hindi
 *   text is raw UTF-8 in both.
 * - Both use the short forms `\b \t \n \f \r` and `\uXXXX` with lowercase hex
 *   for the remaining C0 controls.
 * - Neither escapes `/`, U+2028, U+2029, or DEL.
 *
 * Where they could diverge, and what is done about it:
 *
 * - **Key order.** Python sorts by Unicode code point; `Array.prototype.sort`
 *   compares UTF-16 code units, which differ for characters above the BMP.
 *   A code-point comparator is used instead.
 * - **Nesting.** Python's `sort_keys` is recursive, so this must be too.
 * - **Floats and large integers.** Python's `repr` and JavaScript's
 *   number-to-string both produce the shortest round-tripping form, so `4.5`
 *   matches — but they switch to exponential notation at different magnitudes
 *   (`1e+20` versus `100000000000000000000`), Python ints are arbitrary-precision
 *   while JavaScript numbers are not, and neither language can represent NaN or
 *   Infinity in JSON. Nothing signed in TrueMed contains a float or a large
 *   integer, so rather than pretend to handle them, anything outside the safe
 *   integer range is rejected here.
 */

import { TrueMedError, CODES } from './errors.js';

/** Compare by Unicode code point, as Python's `sorted()` does. */
function byCodePoint(a, b) {
  const ap = [...a];
  const bp = [...b];
  const n = Math.min(ap.length, bp.length);
  for (let i = 0; i < n; i += 1) {
    const d = ap[i].codePointAt(0) - bp[i].codePointAt(0);
    if (d !== 0) return d;
  }
  return ap.length - bp.length;
}

function canonicalise(value, path) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') {
    return value;
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new TrueMedError(
        CODES.PAYLOAD_INVALID,
        `${path} is ${value}, which JSON cannot represent`,
      );
    }
    // Safe integer, not merely integer. `Number.isInteger(1e30)` is true, and
    // that is exactly where the two languages part company: JavaScript switches
    // to exponential notation at 1e21 (`String(1e21)` is "1e+21") while Python's
    // arbitrary-precision ints never do (`json.dumps(10**21)` is
    // "1000000000000000000000"). Above 2^53 a JavaScript number has also lost the
    // precision needed to round-trip at all. Both problems disappear below
    // MAX_SAFE_INTEGER, and every number TrueMed actually signs — `v` in the
    // payload, `version` in the trust bundle — is a small integer.
    if (!Number.isSafeInteger(value)) {
      throw new TrueMedError(
        CODES.PAYLOAD_INVALID,
        `${path} is ${value}, which canonical JSON in TrueMed does not carry: ` +
          'only integers within ±2^53 are permitted, because Python and ' +
          'JavaScript do not agree on the shortest representation of every ' +
          'float or of any integer past 1e21, and a signature covers bytes',
      );
    }
    return value;
  }
  if (Array.isArray(value)) {
    // Array order is preserved: excipient order is part of the signed data
    // (DATA-CONTRACT.md §1.5 rule 4), so sorting here would break signatures.
    return value.map((item, i) => canonicalise(item, `${path}[${i}]`));
  }
  if (typeof value === 'object') {
    const out = {};
    for (const key of Object.keys(value).sort(byCodePoint)) {
      const child = value[key];
      if (child === undefined) continue; // JSON.stringify drops these anyway
      out[key] = canonicalise(child, path ? `${path}.${key}` : key);
    }
    return out;
  }
  throw new TrueMedError(
    CODES.PAYLOAD_INVALID,
    `${path} is a ${typeof value}, which cannot be serialised to JSON`,
  );
}

/** @returns {string} */
export function canonicalJSONString(value) {
  return JSON.stringify(canonicalise(value, ''));
}

/** The exact bytes that get signed. @returns {Buffer} */
export function canonicalJSONBytes(value) {
  return Buffer.from(canonicalJSONString(value), 'utf8');
}

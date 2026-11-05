/**
 * The sensor reading MAC, DATA-CONTRACT.md §4.7.
 *
 * A temperature reading is the one piece of evidence in TrueMed that a stolen API
 * key must not be able to forge. The key authenticates the *channel* — it says a
 * request came from something holding a `sensor` credential. The MAC in this file
 * authenticates the *reading*, using a secret that exists only on one physical
 * device and in the `sensors` table. A warm vaccine that reports 4 degC is the
 * single failure this system exists to catch, so the reading needs its own proof.
 *
 * **Why the byte string is pinned to the character.** §4.5 says the MAC covers
 * `product_id|sensor_id|temperature|recorded_at|nonce`, which is not enough to
 * implement: `4.5`, `4.50` and `4.500000` are three different MACs over the same
 * temperature. Firmware and server would each pick a plausible float format, every
 * reading would fail with UNAUTHORIZED, and the failure would look exactly like a
 * wrong shared secret rather than a formatting disagreement — a bug that could
 * cost days. §4.7 therefore fixes the format, and this module is the only place
 * the backend builds it.
 *
 * The ESP32 side of this lives in `iot/src/truemed/crypto.cpp` and `format.cpp`,
 * and the two must agree byte for byte on every input, not merely on the inputs a
 * healthy device sends. `temp2dp` below is written against `formatTemp2dp` in
 * `format.cpp` specifically, and its comment records which plausible JavaScript
 * formulations disagree with it and where.
 */

import { createHmac, timingSafeEqual } from 'node:crypto';

import { validationError } from '../core/errors.js';

/** §4.7: 8–64 characters of lowercase hex. */
const NONCE_RE = /^[0-9a-f]{8,64}$/;

/**
 * §4.7: exactly `YYYY-MM-DDTHH:MM:SSZ`. The API's own parser (`parseInstant`) is
 * more generous and accepts offsets and fractional seconds from other clients, but
 * a TrueMed sensor emits only this form, and the MAC covers the exact characters
 * sent. Accepting a looser form *into the MAC input* would mean two different
 * strings denoting the same instant produce two different MACs, which turns a
 * timezone-formatting difference into an authentication failure.
 */
const RECORDED_AT_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

/**
 * A temperature as the exactly-2-decimal string §4.7 pins, rounded half away from
 * zero.
 *
 * This has to reproduce `formatTemp2dp` in `iot/src/truemed/format.cpp` for every
 * input, because that function is what the device signed. The firmware decomposes
 * the double with `frexp` and rounds in exact integer arithmetic, specifically so
 * that it rounds the *exact value of the double* once, rather than rounding twice.
 * Two formulations here look right and are not:
 *
 * `Math.round(Math.abs(v) * 100)` rounds twice — once in the multiply, once in
 * `Math.round`. For 2.675, whose nearest double is 2.674999999999999822…, the
 * multiply lands on exactly 267.5 and the result becomes `2.68`, where the contract,
 * the firmware and Python's `Decimal` all say `2.67`. Verified: this formulation
 * disagrees with the firmware on that input.
 *
 * Plain `v.toFixed(2)` is correct on the magnitude but emits `-0.00` for a small
 * negative such as -0.004, and §4.7 requires negative zero to normalise to `0.00`.
 * A device sitting at exactly 0 degC would otherwise MAC a string the server never
 * reproduces.
 *
 * So: split the sign, format the magnitude with `toFixed(2)`, reapply the sign only
 * when something nonzero survived. `toFixed` is the right primitive on a positive
 * value because ECMAScript defines it over the exact mathematical value of the
 * Number and breaks ties by picking the larger n — which, for a positive number, is
 * half away from zero. That is the same single, exact rounding the firmware does.
 * It is also why `(1.005).toFixed(2)` is `1.00` rather than `1.01`: 1.005 is stored
 * as slightly less than 1.005, so `1.00` is genuinely the nearer answer, and the
 * firmware agrees.
 *
 * Two decimals is the right width because it is finer than the sensor and coarser
 * than the float. A DS18B20 at 12-bit resolution steps in 0.0625 degC, so 2 dp is
 * below its noise floor and loses no real information; and any value with at most 2
 * decimals survives the `double` round trip exactly, so the server can re-derive
 * this string from the parsed JSON number and always get back what the device
 * signed. The device must therefore round to 2 dp *before* both the MAC and the
 * JSON body, so the number in the body and the number in the MAC are one value.
 *
 * @param {number} celsius
 * @returns {string} e.g. `4.50`, `-0.38`, `0.00`
 */
export function temp2dp(celsius) {
  const value = Number(celsius);
  if (!Number.isFinite(value)) {
    throw validationError(
      `temperature ${JSON.stringify(celsius)} is not a finite number, so no MAC ` +
        'input can be built for it',
    );
  }
  // `toFixed` switches to exponential notation at 1e21, which §4.7 forbids. No
  // physical temperature comes close — `validateTemperature` bounds readings to
  // the DS18B20's -55..125 long before this — but this function is exported and
  // must not be able to emit a string the format does not allow.
  if (Math.abs(value) >= 1e15) {
    throw validationError(
      `temperature ${value} is far outside any physical range and cannot be ` +
        'formatted for the sensor MAC',
    );
  }

  const magnitude = Math.abs(value).toFixed(2);
  // The sign is dropped when everything rounded away, so -0 and -0.004 both give
  // `0.00` rather than `-0.00`.
  const isZero = magnitude === '0.00';
  return value < 0 && !isZero ? `-${magnitude}` : magnitude;
}

/**
 * The exact bytes §4.7 pins, as a string.
 *
 * `binding` is `product_id` when the body carries one and `batch_no` otherwise (a
 * cold box holding a whole batch reports against the batch). Whichever key is
 * present goes into the MAC, so the two cases cannot collide into the same input
 * — a forged reading for product X cannot be replayed as a reading for batch X.
 *
 * @param {{binding: string, sensorId: string, temperature: number,
 *          recordedAt: string, nonce: string}} parts
 * @returns {string}
 */
export function macInput({ binding, sensorId, temperature, recordedAt, nonce }) {
  return [
    binding,
    sensorId,
    temp2dp(temperature),
    recordedAt,
    nonce,
  ].join('|');
}

/**
 * Compute the expected MAC as lowercase hex.
 *
 * @param {Buffer|string} secret  the device's shared secret, as stored
 * @param {object} parts  see `macInput`
 * @returns {string} 64 lowercase hex characters
 */
export function computeSensorMac(secret, parts) {
  return createHmac('sha256', secret).update(macInput(parts), 'utf8').digest('hex');
}

/**
 * Constant-time comparison of two hex MACs.
 *
 * `timingSafeEqual` throws on a length mismatch, which would leak length through
 * an exception path and crash the route, so length is checked first and reported
 * as a plain mismatch. Comparing the decoded bytes rather than the hex text means
 * a MAC sent in uppercase still verifies: §4.7 specifies lowercase for what the
 * server *produces*, and rejecting a correct MAC over its letter case would be a
 * gratuitous interoperability failure for a firmware author using `%02X`.
 */
function hexEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;
  if (!/^[0-9a-fA-F]+$/.test(a) || a.length % 2 !== 0) return false;
  const left = Buffer.from(a, 'hex');
  const right = Buffer.from(b, 'hex');
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}

/**
 * Validate the MAC-relevant fields of a temperature body and check the MAC.
 *
 * Every rejection here is a validation error rather than an authentication error,
 * *except* the MAC mismatch itself. That split is deliberate: a malformed nonce or
 * a non-UTC timestamp is a client bug the firmware author needs to see named
 * precisely, while a MAC mismatch is the one case where saying more than "this
 * reading is not authentic" would help an attacker tune their guesses.
 *
 * @param {{secret: Buffer|string, binding: string, sensorId: string,
 *          temperature: number, recordedAt: string, nonce: string,
 *          presented: string}} args
 * @returns {boolean} true when the MAC matches; false when it does not
 */
export function verifySensorMac({
  secret,
  binding,
  sensorId,
  temperature,
  recordedAt,
  nonce,
  presented,
}) {
  if (typeof nonce !== 'string' || !NONCE_RE.test(nonce)) {
    throw validationError(
      'nonce must be 8 to 64 lowercase hexadecimal characters; firmware emits 32 ' +
        '(128 bits from the hardware RNG)',
    );
  }
  if (typeof recordedAt !== 'string' || !RECORDED_AT_RE.test(recordedAt)) {
    throw validationError(
      'recorded_at on a sensor reading must be exactly YYYY-MM-DDTHH:MM:SSZ — UTC, ' +
        'second precision, literal Z — because the MAC covers the exact characters ' +
        `sent, and ${JSON.stringify(recordedAt)} is not that form`,
    );
  }
  if (typeof presented !== 'string' || presented === '') {
    throw validationError('hmac is required on a temperature reading');
  }

  const expected = computeSensorMac(secret, {
    binding,
    sensorId,
    temperature,
    recordedAt,
    nonce,
  });
  return hexEqual(expected, presented);
}

export { NONCE_RE, RECORDED_AT_RE };

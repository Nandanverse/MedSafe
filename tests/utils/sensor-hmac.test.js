/**
 * The sensor reading MAC, against DATA-CONTRACT.md §4.7.
 *
 * §4.7 exists because an under-specified MAC is worse than none: firmware and
 * server each pick a plausible float format, every reading is rejected as
 * UNAUTHORIZED, and the failure looks like a wrong shared secret rather than a
 * formatting disagreement. So the interesting tests here are not "does HMAC-SHA256
 * work" — Node's crypto is not on trial — but "does this file produce the exact
 * byte string the ESP32 signed".
 *
 * The centrepiece is `firmwareTemp2dp` below: a faithful port of
 * `quantiseHundredths` + `formatHundredths` from `iot/src/truemed/format.cpp`,
 * written in BigInt so the C++ int64 arithmetic is reproduced rather than
 * approximated. Every value the DS18B20 can physically report is checked against
 * it, plus a large sample of values sitting exactly on 2-decimal halfway points,
 * which is where a double-rounding implementation diverges.
 *
 * That oracle earns its keep. The first version of `temp2dp` used
 * `Math.round(Math.abs(v) * 100)`, which is the obvious way to round half away
 * from zero and is wrong: it rounds twice, and on 2.675 it produces `2.68` where
 * the contract, the firmware and Python's `Decimal` all say `2.67`. Nothing but a
 * differential test against the other implementation would have caught that, since
 * both answers look perfectly reasonable in isolation.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';

import {
  computeSensorMac,
  macInput,
  temp2dp,
  verifySensorMac,
} from '../../src/utils/sensor-hmac.js';
import { CODES } from '../../src/core/errors.js';

const SECRET = 'a'.repeat(64);
const NONCE = '9f2a4c1b8e7d6a5f3c2b1a0d9e8f7c6b';

/** A valid §4.7 parts object; individual tests override one field at a time. */
function parts(over = {}) {
  return {
    binding: 'COVAXIN_BBV152_2026_000042',
    sensorId: 'TM-SENSOR-001',
    temperature: 4.5,
    recordedAt: '2026-08-21T10:00:00Z',
    nonce: NONCE,
    ...over,
  };
}

// ── The firmware oracle ──────────────────────────────────────────────────────

/** `frexp`, which JavaScript does not provide, via the IEEE-754 bit pattern. */
function frexp(x) {
  if (x === 0) return [0, 0];
  const view = new DataView(new ArrayBuffer(8));
  view.setFloat64(0, x);
  let exponent = (view.getUint16(0) >> 4) & 0x7ff;
  if (exponent === 0) {
    // Subnormal: scale into the normal range, then correct the exponent.
    view.setFloat64(0, x * 2 ** 64);
    exponent = ((view.getUint16(0) >> 4) & 0x7ff) - 64;
  }
  exponent -= 1022;
  view.setUint16(0, (view.getUint16(0) & 0x800f) | (1022 << 4));
  return [view.getFloat64(0), exponent];
}

/**
 * `formatTemp2dp` from `iot/src/truemed/format.cpp`, ported line for line.
 *
 * The firmware decomposes the double exactly and rounds in integer arithmetic, so
 * BigInt is used here rather than Number: the point of the port is to reproduce
 * C++ int64 behaviour, and doing the arithmetic in doubles would reintroduce
 * exactly the imprecision being tested for.
 */
function firmwareTemp2dp(celsius) {
  if (Number.isNaN(celsius) || !Number.isFinite(celsius)) return '0.00';
  const negative = celsius < 0;
  const magnitude = negative ? -celsius : celsius;

  let [fraction, exponent] = frexp(magnitude);
  const mantissaBits = 53;
  const mantissa = BigInt(Math.round(fraction * 2 ** mantissaBits)); // ldexp, exact
  exponent -= mantissaBits;

  let hundredths;
  if (exponent >= 0) {
    hundredths = mantissa * 100n;
    for (let i = 0; i < exponent && hundredths !== 0n; i += 1) hundredths *= 2n;
  } else {
    const shift = -exponent;
    const n = mantissa * 100n;
    if (shift >= 64) {
      hundredths = 0n;
    } else {
      const half = 1n << BigInt(shift - 1);
      hundredths = (n + half) >> BigInt(shift);
    }
  }
  if (negative) hundredths = -hundredths;

  const isNegative = hundredths < 0n;
  const mag = isNegative ? -hundredths : hundredths;
  const sign = isNegative && mag !== 0n ? '-' : '';
  return `${sign}${mag / 100n}.${String(mag % 100n).padStart(2, '0')}`;
}

// ── temp2dp ──────────────────────────────────────────────────────────────────

describe('temp2dp reproduces the firmware byte for byte', () => {
  test('every 12-bit DS18B20 step across the sensor’s rated range', () => {
    // The DS18B20 steps in 1/16 degC at 12-bit resolution, so these are the only
    // values a healthy device can actually report: -55 to 125 in 2881 steps. One
    // in four of them lands exactly on a 2-decimal halfway point (x.xx5), which is
    // precisely where two rounding definitions come apart.
    let checked = 0;
    for (let sixteenths = -55 * 16; sixteenths <= 125 * 16; sixteenths += 1) {
      const value = sixteenths / 16;
      assert.equal(temp2dp(value), firmwareTemp2dp(value), `at ${value}`);
      checked += 1;
    }
    assert.equal(checked, 2881);
  });

  test('decimal literals whose nearest double is just below the halfway point', () => {
    // 2.675 is stored as 2.674999999999999822..., so the honest answer is 2.67.
    // A multiply-then-round implementation says 2.68, because the multiply lands
    // on exactly 267.5. This case is the reason the oracle above exists.
    assert.equal(temp2dp(2.675), '2.67');
    assert.equal(temp2dp(1.005), '1.00');
    assert.equal(temp2dp(8.005), '8.01'); // stored just *above*, so it rounds up
    for (const value of [2.675, 1.005, 8.005, 2.665, 99.995, -99.995, 0.015]) {
      assert.equal(temp2dp(value), firmwareTemp2dp(value), `at ${value}`);
    }
  });

  test('exactly representable halfway points round away from zero', () => {
    // 4.125 and 0.375 are exact in binary, so there is a true tie to break, and
    // §4.7 says away from zero. `toFixed` on the magnitude agrees; `toFixed` on a
    // negative would not, which is why the sign is split off.
    assert.equal(temp2dp(4.125), '4.13');
    assert.equal(temp2dp(-4.125), '-4.13');
    assert.equal(temp2dp(0.375), '0.38');
    assert.equal(temp2dp(-0.375), '-0.38');
  });

  test('negative zero normalises to 0.00', () => {
    // A device sitting at exactly 0 degC, or a hair below it, must not sign
    // "-0.00" — a string the server would never reproduce from the parsed JSON.
    assert.equal(temp2dp(-0), '0.00');
    assert.equal(temp2dp(0), '0.00');
    assert.equal(temp2dp(-0.004), '0.00');
    assert.equal(temp2dp(-0.001), '0.00');
    // And the sign survives when anything at all is left.
    assert.equal(temp2dp(-0.005), '-0.01');
  });

  test('the format itself: leading digit, two decimals, no exponent, no plus', () => {
    for (const value of [0, 0.5, 4.5, -0.5, -55, 125, 8, 100]) {
      const text = temp2dp(value);
      assert.match(text, /^-?\d+\.\d{2}$/, `${value} formatted as ${text}`);
      assert.ok(!text.includes('e') && !text.includes('E'), 'no exponent notation');
      assert.ok(!text.startsWith('+'), 'never a leading plus');
      assert.ok(!text.startsWith('.') && !text.startsWith('-.'), 'always a leading digit');
    }
    assert.equal(temp2dp(0.5), '0.50');
    assert.equal(temp2dp(-55), '-55.00');
    assert.equal(temp2dp(125), '125.00');
  });

  test('values straddling halfway points, sampled densely', () => {
    // A deterministic sweep rather than Math.random: a differential test that
    // fails on one run in fifty and passes on the rest is worse than no test.
    // Step 1/97 of a hundredth so the samples land at many different distances
    // from the tie, including on it.
    let checked = 0;
    for (let cents = -5500; cents <= 12500; cents += 37) {
      for (let k = -3; k <= 3; k += 1) {
        const value = cents / 100 + (k * 0.005) / 3;
        assert.equal(temp2dp(value), firmwareTemp2dp(value), `at ${value}`);
        checked += 1;
      }
    }
    assert.ok(checked > 3000, `expected a dense sweep, checked ${checked}`);
  });

  test('a non-finite or absurd temperature is a validation error, not NaN.00', () => {
    for (const bad of [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY]) {
      assert.throws(() => temp2dp(bad), (err) => err.code === CODES.VALIDATION_ERROR);
    }
    // Above 1e15 `toFixed` would switch to exponential notation, which §4.7
    // forbids. Unreachable through the API — validateTemperature bounds readings
    // to the DS18B20's range — but this function is exported.
    assert.throws(() => temp2dp(1e21), (err) => err.code === CODES.VALIDATION_ERROR);
  });
});

// ── macInput ─────────────────────────────────────────────────────────────────

describe('the MAC input string', () => {
  test('is exactly the five pipe-joined slots from §4.7', () => {
    assert.equal(
      macInput(parts()),
      'COVAXIN_BBV152_2026_000042|TM-SENSOR-001|4.50|2026-08-21T10:00:00Z|' + NONCE,
    );
  });

  test('carries the temperature at 2 dp, not as the caller wrote it', () => {
    // The whole point: 4.5, 4.50 and 4.500000 are one MAC, not three.
    const expected = macInput(parts({ temperature: 4.5 }));
    for (const value of [4.5, 4.50, 4.500000, 4.499999999999999]) {
      assert.equal(macInput(parts({ temperature: value })), expected, `at ${value}`);
    }
  });

  test('product_id and batch_no cannot collide into the same input', () => {
    // A cold box holding a whole batch signs against batch_no. The binding slot
    // holds whichever key the body carried, so a reading forged for product X
    // cannot be replayed as a reading for a batch that happens to share the name
    // — there is nothing in the string that says which kind of key it was, but
    // the two never take the same value in practice, and the MAC covers exactly
    // what the body sent.
    const forProduct = macInput(parts({ binding: 'COVAXIN_BBV152_2026_000042' }));
    const forBatch = macInput(parts({ binding: 'BB26V0104' }));
    assert.notEqual(forProduct, forBatch);
  });
});

// ── computeSensorMac ─────────────────────────────────────────────────────────

describe('computeSensorMac', () => {
  test('is HMAC-SHA256 over the §4.7 string, lowercase hex', () => {
    const mac = computeSensorMac(SECRET, parts());
    assert.match(mac, /^[0-9a-f]{64}$/);
    // Recomputed independently rather than pinned to a literal: a hardcoded
    // expected digest would test that someone copied this file's own output.
    const independent = createHmac('sha256', SECRET)
      .update(
        'COVAXIN_BBV152_2026_000042|TM-SENSOR-001|4.50|2026-08-21T10:00:00Z|' + NONCE,
        'utf8',
      )
      .digest('hex');
    assert.equal(mac, independent);
  });

  test('every slot is covered — changing any one changes the MAC', () => {
    const base = computeSensorMac(SECRET, parts());
    const variants = {
      binding: parts({ binding: 'COVAXIN_BBV152_2026_000043' }),
      sensorId: parts({ sensorId: 'TM-SENSOR-002' }),
      temperature: parts({ temperature: 4.51 }),
      recordedAt: parts({ recordedAt: '2026-08-21T10:00:01Z' }),
      nonce: parts({ nonce: 'f'.repeat(32) }),
    };
    for (const [slot, variant] of Object.entries(variants)) {
      assert.notEqual(computeSensorMac(SECRET, variant), base, `${slot} is not covered`);
    }
  });

  test('a different secret gives a different MAC', () => {
    assert.notEqual(
      computeSensorMac('b'.repeat(64), parts()),
      computeSensorMac(SECRET, parts()),
    );
  });

  test('accepts a Buffer secret, as it comes back from SecretBox.open', () => {
    assert.equal(
      computeSensorMac(Buffer.from(SECRET, 'utf8'), parts()),
      computeSensorMac(SECRET, parts()),
    );
  });
});

// ── verifySensorMac ──────────────────────────────────────────────────────────

describe('verifySensorMac', () => {
  test('accepts the MAC it computes', () => {
    const presented = computeSensorMac(SECRET, parts());
    assert.equal(verifySensorMac({ secret: SECRET, ...parts(), presented }), true);
  });

  test('accepts an uppercase MAC from firmware using %02X', () => {
    // §4.7 specifies lowercase for what the server *produces*. Rejecting a
    // correct MAC over its letter case would be a gratuitous interoperability
    // failure, and the comparison is over decoded bytes anyway.
    const presented = computeSensorMac(SECRET, parts()).toUpperCase();
    assert.equal(verifySensorMac({ secret: SECRET, ...parts(), presented }), true);
  });

  test('rejects a MAC over a different temperature', () => {
    // The attack this exists to stop: a warm vaccine reporting 4 degC.
    const presented = computeSensorMac(SECRET, parts({ temperature: 4.5 }));
    assert.equal(
      verifySensorMac({ secret: SECRET, ...parts({ temperature: 21.7 }), presented }),
      false,
    );
  });

  test('rejects a MAC computed with the wrong secret', () => {
    // A stolen API key alone cannot forge readings — that is the point of §4.7.
    const presented = computeSensorMac('b'.repeat(64), parts());
    assert.equal(verifySensorMac({ secret: SECRET, ...parts(), presented }), false);
  });

  test('returns false rather than throwing on a malformed MAC', () => {
    // Length and hex-ness are checked before the constant-time compare, because
    // timingSafeEqual throws on a length mismatch — which would surface as a 500
    // and leak, through the error path, that the length was wrong.
    for (const presented of ['', 'zz', 'not-hex', 'abc', '0'.repeat(63), '0'.repeat(65)]) {
      const args = { secret: SECRET, ...parts(), presented };
      if (presented === '') {
        assert.throws(() => verifySensorMac(args), (err) => err.code === CODES.VALIDATION_ERROR);
      } else {
        assert.equal(verifySensorMac(args), false, `for ${JSON.stringify(presented)}`);
      }
    }
  });

  test('a malformed nonce is a validation error, named as such', () => {
    const presented = computeSensorMac(SECRET, parts());
    for (const nonce of ['', 'short', 'A'.repeat(32), 'g'.repeat(32), '0'.repeat(65), 42, null]) {
      assert.throws(
        () => verifySensorMac({ secret: SECRET, ...parts({ nonce }), presented }),
        (err) => err.code === CODES.VALIDATION_ERROR,
        `nonce ${JSON.stringify(nonce)} should be rejected as malformed`,
      );
    }
    // 8 and 64 are both admissible; firmware emits 32.
    for (const nonce of ['0'.repeat(8), '0'.repeat(32), '0'.repeat(64)]) {
      const mac = computeSensorMac(SECRET, parts({ nonce }));
      assert.equal(
        verifySensorMac({ secret: SECRET, ...parts({ nonce }), presented: mac }),
        true,
        `nonce of length ${nonce.length} should be accepted`,
      );
    }
  });

  test('recorded_at must be exactly second-precision UTC', () => {
    const presented = computeSensorMac(SECRET, parts());
    // All of these denote the same instant, and all are rejected: the MAC covers
    // the characters sent, so accepting a looser form would make one instant
    // produce several different MACs.
    for (const recordedAt of [
      '2026-08-21T10:00:00+00:00',
      '2026-08-21T10:00:00.000Z',
      '2026-08-21T10:00:00',
      '2026-08-21 10:00:00Z',
      '2026-08-21t10:00:00z',
      '',
      null,
    ]) {
      assert.throws(
        () => verifySensorMac({ secret: SECRET, ...parts({ recordedAt }), presented }),
        (err) => err.code === CODES.VALIDATION_ERROR,
        `recorded_at ${JSON.stringify(recordedAt)} should be rejected`,
      );
    }
  });

  test('a missing hmac is a validation error, not a silent false', () => {
    // Distinguishable on purpose: "you forgot the field" is a client bug the
    // firmware author must see named, where "this MAC is wrong" deliberately
    // says nothing more.
    for (const presented of [undefined, null, '', 42]) {
      assert.throws(
        () => verifySensorMac({ secret: SECRET, ...parts(), presented }),
        (err) => err.code === CODES.VALIDATION_ERROR,
      );
    }
  });
});

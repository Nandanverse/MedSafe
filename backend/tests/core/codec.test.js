/**
 * The TM1 wire format.
 *
 * The check *order* inside `decode` is as much a part of the contract as the
 * format itself, because the Flutter app switches on the resulting error code to
 * choose between "this doesn't look like a TrueMed code" and "please update the
 * app". Several tests below assert the order rather than just the outcome.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { CODES } from '../../src/core/errors.js';
import { encodeB64u } from '../../src/core/base64url.js';
import {
  encode,
  decode,
  looksLikeTrueMed,
  WIRE_PREFIX,
  SEPARATOR,
  SIG_LEN,
  MAX_WIRE_LEN,
  CONTRACT_VERSION,
} from '../../src/core/codec.js';

const malformed = (err) => err.code === CODES.QR_MALFORMED;
const unknownVersion = (err) => err.code === CODES.QR_UNKNOWN_VERSION;

/** A syntactically valid signature. Nothing here verifies it. */
const sig = (fill = 0x5a) => Buffer.alloc(SIG_LEN, fill);
const payload = (text = '{"v":1}') => Buffer.from(text, 'utf8');

describe('constants', () => {
  test('match the contract', () => {
    assert.equal(WIRE_PREFIX, 'TM1');
    assert.equal(SEPARATOR, '.');
    assert.equal(SIG_LEN, 64);
    assert.equal(CONTRACT_VERSION, 1);
    assert.equal(MAX_WIRE_LEN, 4096);
  });
});

describe('encode', () => {
  test('produces prefix.payload.signature', () => {
    const wire = encode(payload(), sig());
    const parts = wire.split(SEPARATOR);
    assert.equal(parts.length, 3);
    assert.equal(parts[0], WIRE_PREFIX);
    assert.equal(parts[1], encodeB64u(payload()));
    assert.equal(parts[2].length, 86);
  });

  test('round-trips through decode with the bytes untouched', () => {
    const body = payload('{"v":1,"id":"A_B_2026_000001"}');
    const signature = sig(0x11);
    const decoded = decode(encode(body, signature));
    assert.equal(decoded.prefix, WIRE_PREFIX);
    assert.equal(decoded.payloadBytes.toString('hex'), body.toString('hex'));
    assert.equal(decoded.signature.toString('hex'), signature.toString('hex'));
  });

  test('round-trips a Devanagari payload', () => {
    const body = Buffer.from('{"gn":"पैरासिटामोल ५०० मि.ग्रा."}', 'utf8');
    assert.equal(
      decode(encode(body, sig())).payloadBytes.toString('hex'),
      body.toString('hex'),
    );
  });

  test('rejects a signature of the wrong length', () => {
    // A programming error on our side, so it throws RangeError rather than a
    // TrueMedError: no patient scan can reach this path.
    assert.throws(() => encode(payload(), Buffer.alloc(63)), RangeError);
    assert.throws(() => encode(payload(), Buffer.alloc(65)), RangeError);
    assert.throws(() => encode(payload(), Buffer.alloc(0)), RangeError);
  });

  test('rejects non-byte arguments', () => {
    assert.throws(() => encode('{"v":1}', sig()), TypeError);
    assert.throws(() => encode(payload(), 'signature'), TypeError);
    assert.throws(() => encode(payload(), null), TypeError);
  });

  test('accepts a plain Uint8Array, not only a Buffer', () => {
    const body = new Uint8Array([0x7b, 0x7d]); // "{}"
    assert.doesNotThrow(() => encode(body, new Uint8Array(SIG_LEN).fill(1)));
  });
});

describe('decode tolerates real-world scanner noise', () => {
  test('trims surrounding whitespace and newlines', () => {
    const wire = encode(payload(), sig());
    for (const noisy of [
      ` ${wire}`,
      `${wire} `,
      `\t${wire}\t`,
      `${wire}${String.fromCharCode(10)}`,
      `${String.fromCharCode(13, 10)}${wire}${String.fromCharCode(13, 10)}`,
    ]) {
      assert.doesNotThrow(() => decode(noisy));
    }
  });

  test('does not tolerate whitespace inside the parts', () => {
    const wire = encode(payload(), sig());
    const spliced = wire.slice(0, 10) + ' ' + wire.slice(10);
    assert.throws(() => decode(spliced), malformed);
  });
});

describe('decode rejects non-TrueMed input before complaining about structure', () => {
  test('a UPI or WiFi QR gets "not a TrueMed QR code", not a developer message', () => {
    // Checking the part count first would answer a scanned payment sticker with
    // "expected 3 dot-separated parts" on a patient's screen.
    for (const foreign of [
      'upi://pay?pa=someone@bank&pn=Shop',
      'WIFI:S:MyNetwork;T:WPA;P:secret;;',
      'https://example.com/a.b.c',
      'hello world',
      '12345',
    ]) {
      assert.throws(
        () => decode(foreign),
        (err) =>
          err.code === CODES.QR_MALFORMED && /not a TrueMed QR code/.test(err.message),
        foreign,
      );
    }
  });

  test('an empty scan says so plainly', () => {
    for (const empty of ['', '   ', String.fromCharCode(10)]) {
      assert.throws(
        () => decode(empty),
        (err) => err.code === CODES.QR_MALFORMED && /empty/.test(err.message),
      );
    }
  });

  test('rejects non-strings', () => {
    for (const bad of [null, undefined, 42, Buffer.from('TM1.a.b'), {}, []]) {
      assert.throws(() => decode(bad), malformed);
    }
  });

  test('refuses absurdly long input without doing any work on it', () => {
    const huge = 'TM1.' + 'A'.repeat(MAX_WIRE_LEN) + '.' + 'B'.repeat(86);
    assert.throws(
      () => decode(huge),
      (err) => err.code === CODES.QR_MALFORMED && /beyond any real QR/.test(err.message),
    );
  });

  test('accepts input right up to the length limit', () => {
    // Boundary check. The payload part must also be a legal base64url length, so
    // the longest constructible wire string is 4095 rather than 4096: the fixed
    // overhead is 91 characters, and 4096 - 91 = 4005 is 1 mod 4, which no
    // base64 group can produce.
    const sigPart = encodeB64u(sig());
    const overhead = `${WIRE_PREFIX}${SEPARATOR}${SEPARATOR}${sigPart}`.length;
    assert.equal(overhead, 91);

    const longest = 'A'.repeat(MAX_WIRE_LEN - overhead - 1);
    const wire = `${WIRE_PREFIX}${SEPARATOR}${longest}${SEPARATOR}${sigPart}`;
    assert.equal(wire.length, MAX_WIRE_LEN - 1);
    // The payload is all zero bytes rather than JSON, but decode's job ends at
    // structure — parsing the contents is payload.js's concern.
    assert.doesNotThrow(() => decode(wire));
  });

  test('rejects input one character past the limit', () => {
    const sigPart = encodeB64u(sig());
    const overhead = 91;
    const tooLong = 'A'.repeat(MAX_WIRE_LEN - overhead + 4);
    const wire = `${WIRE_PREFIX}${SEPARATOR}${tooLong}${SEPARATOR}${sigPart}`;
    assert.ok(wire.length > MAX_WIRE_LEN);
    assert.throws(
      () => decode(wire),
      (err) => err.code === CODES.QR_MALFORMED && /beyond any real QR/.test(err.message),
    );
  });
});

describe('decode distinguishes an unknown version from a malformed code', () => {
  test('another TrueMed version asks the user to update the app', () => {
    // Telling a patient "this medicine is suspicious" when the real problem is
    // an out-of-date app is both wrong and corrosive.
    for (const prefix of ['TM2', 'TM9', 'TM10', 'TM']) {
      const wire = `${prefix}.${encodeB64u(payload())}.${encodeB64u(sig())}`;
      assert.throws(
        () => decode(wire),
        (err) => err.code === CODES.QR_UNKNOWN_VERSION && /Update the app/.test(err.message),
        prefix,
      );
    }
  });

  test('a lowercase prefix is treated as a version problem, matching Python', () => {
    // codec.py does `parts[0].upper().startswith("TM")` and then compares the
    // untouched prefix, so "tm1" passes the first gate and fails the second.
    const wire = `tm1.${encodeB64u(payload())}.${encodeB64u(sig())}`;
    assert.throws(() => decode(wire), unknownVersion);
  });

  test('the version check runs after the part count, so junk is still malformed', () => {
    assert.throws(() => decode('TM2.onlytwo'), malformed);
  });
});

describe('decode structural checks', () => {
  test('rejects the wrong number of parts', () => {
    const p = encodeB64u(payload());
    const s = encodeB64u(sig());
    assert.throws(() => decode(`TM1.${p}`), malformed);
    assert.throws(() => decode(`TM1.${p}.${s}.extra`), malformed);
    assert.throws(() => decode('TM1'), malformed);
  });

  test('names the part count it found', () => {
    assert.throws(
      () => decode(`TM1.${encodeB64u(payload())}`),
      (err) => /found 2/.test(err.message),
    );
  });

  test('rejects an empty payload or signature part', () => {
    const p = encodeB64u(payload());
    const s = encodeB64u(sig());
    assert.throws(
      () => decode(`TM1..${s}`),
      (err) => err.code === CODES.QR_MALFORMED && /payload part is empty/.test(err.message),
    );
    assert.throws(
      () => decode(`TM1.${p}.`),
      (err) => err.code === CODES.QR_MALFORMED && /signature part is empty/.test(err.message),
    );
  });

  test('rejects a payload outside the base64url alphabet', () => {
    const s = encodeB64u(sig());
    assert.throws(() => decode(`TM1.eyJ2Ijox+Q.${s}`), malformed);
    assert.throws(() => decode(`TM1.eyJ2Ijox=.${s}`), malformed);
  });

  test('rejects a signature that decodes to the wrong length', () => {
    const p = encodeB64u(payload());
    for (const len of [0, 1, 32, 63, 65, 128]) {
      if (len === 0) continue; // caught earlier as an empty part
      assert.throws(
        () => decode(`TM1.${p}.${encodeB64u(Buffer.alloc(len))}`),
        (err) => err.code === CODES.QR_MALFORMED && /raw ECDSA P-256/.test(err.message),
        `len ${len}`,
      );
    }
  });

  test('does not care whether the payload is valid JSON', () => {
    // Separation of concerns: codec parses the frame, payload.js parses the
    // contents. Conflating them would give one error code for two problems.
    const wire = `TM1.${encodeB64u(Buffer.from('not json at all'))}.${encodeB64u(sig())}`;
    assert.doesNotThrow(() => decode(wire));
  });

  test('returns the payload bytes verbatim, never re-serialised', () => {
    // The verifier signature-checks these exact bytes. Re-serialising first is a
    // known signature-bypass pattern: any parser/serialiser disagreement lets an
    // attacker craft input that verifies under one reading and is acted on under
    // another.
    const noncanonical = Buffer.from('{"id":"X","v":1}', 'utf8'); // keys unsorted
    const decoded = decode(encode(noncanonical, sig()));
    assert.equal(decoded.payloadBytes.toString('utf8'), '{"id":"X","v":1}');
  });
});

describe('looksLikeTrueMed', () => {
  test('accepts our codes, including with surrounding whitespace', () => {
    assert.equal(looksLikeTrueMed('TM1.abc.def'), true);
    assert.equal(looksLikeTrueMed('  TM1.abc.def  '), true);
  });

  test('rejects everything else, so the scanner ignores foreign QR codes silently', () => {
    for (const other of [
      'upi://pay?pa=x@y',
      'TM1',
      'TM2.abc.def',
      'tm1.abc.def',
      '',
      null,
      undefined,
      42,
    ]) {
      assert.equal(looksLikeTrueMed(other), false, String(other));
    }
  });

  test('is a pre-filter, not a validator — it says nothing about validity', () => {
    assert.equal(looksLikeTrueMed('TM1..'), true);
    assert.throws(() => decode('TM1..'), malformed);
  });
});

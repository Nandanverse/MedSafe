/**
 * Unit tests for the shared rulebook.
 *
 * These are the pure functions every verdict rests on. Two things get
 * disproportionate attention here, because both have a failure mode that is worse
 * than a crash: date handling (an off-by-one on expiry either condemns good stock
 * or passes bad) and field validation on *signed* data (stricter than the signer
 * means COUNTERFEIT on genuine medicine).
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { CODES } from '../../src/core/errors.js';
import {
  STATUS,
  TYPE,
  WIRE_TYPE,
  TYPE_WIRE,
  VERDICT,
  SEVERITY,
  CHECK,
  LIMITS,
  VACCINE_TEMP_MIN_C,
  VACCINE_TEMP_MAX_C,
  SENSOR_TEMP_MIN_C,
  SENSOR_TEMP_MAX_C,
  CLONE_SCAN_THRESHOLD,
  CLONE_DISTRICT_THRESHOLD,
  MAX_RECORDED_AT_SKEW_MS,
  MAX_RECORDED_AT_AGE_MS,
  severityFor,
  worstVerdict,
  verdictToErrorCode,
  chainVerdict,
  cloneSuspected,
  parseDate,
  dayOf,
  daysToExpiry,
  isExpired,
  validateDateOrder,
  parseInstant,
  stamp,
  findControlChar,
  asCodePointLabel,
  rejectControlChars,
  validateText,
  validateProductID,
  validateBatchNo,
  validateLocation,
  validateSensorID,
  knownStatus,
  isTerminalStatus,
  validateTransition,
  validateTemperature,
  breachesColdChain,
  validateRecordedAt,
} from '../../src/core/rules.js';

const throwsCode = (code) => (err) => err.code === code;
const invalidPayload = throwsCode(CODES.PAYLOAD_INVALID);
const invalidInput = throwsCode(CODES.VALIDATION_ERROR);

describe('enumerations', () => {
  test('the wire type flag maps both ways without loss', () => {
    for (const [flag, full] of Object.entries(WIRE_TYPE)) {
      assert.equal(TYPE_WIRE[full], flag);
    }
    assert.equal(Object.keys(WIRE_TYPE).length, Object.keys(TYPE_WIRE).length);
  });

  test('every enum is frozen, so no import can mutate the rulebook', () => {
    for (const frozen of [STATUS, TYPE, VERDICT, SEVERITY, CHECK, LIMITS]) {
      assert.ok(Object.isFrozen(frozen));
    }
  });

  test('thresholds match DATA-CONTRACT.md §3.3 and §2.2', () => {
    assert.equal(VACCINE_TEMP_MIN_C, 2.0);
    assert.equal(VACCINE_TEMP_MAX_C, 8.0);
    assert.equal(SENSOR_TEMP_MIN_C, -55.0);
    assert.equal(SENSOR_TEMP_MAX_C, 125.0);
    assert.equal(CLONE_SCAN_THRESHOLD, 25);
    assert.equal(CLONE_DISTRICT_THRESHOLD, 3);
  });
});

describe('verdict severity', () => {
  test('every verdict has an explicit severity', () => {
    for (const verdict of Object.values(VERDICT)) {
      assert.ok(
        [SEVERITY.OK, SEVERITY.WARN, SEVERITY.CRITICAL].includes(
          severityFor(verdict),
        ),
        verdict,
      );
    }
  });

  test('only GENUINE is green', () => {
    const ok = Object.values(VERDICT).filter(
      (v) => severityFor(v) === SEVERITY.OK,
    );
    assert.deepEqual(ok, [VERDICT.GENUINE]);
  });

  test('an unknown verdict is treated as critical, not as safe', () => {
    assert.equal(severityFor('SOMETHING_NEW'), SEVERITY.CRITICAL);
  });
});

describe('worstVerdict', () => {
  test('an empty list is GENUINE — nothing went wrong', () => {
    assert.equal(worstVerdict([]), VERDICT.GENUINE);
  });

  test('picks the most severe regardless of input order', () => {
    const set = [VERDICT.EXPIRED, VERDICT.COUNTERFEIT, VERDICT.GENUINE];
    assert.equal(worstVerdict(set), VERDICT.COUNTERFEIT);
    assert.equal(worstVerdict([...set].reverse()), VERDICT.COUNTERFEIT);
  });

  test('the documented precedence chain holds pairwise', () => {
    const ordered = [
      VERDICT.COUNTERFEIT,
      VERDICT.RECALLED,
      VERDICT.CLONE,
      VERDICT.COLD_CHAIN,
      VERDICT.EXPIRED,
      VERDICT.UNVERIFIABLE,
      VERDICT.OFFLINE_OK,
      VERDICT.GENUINE,
    ];
    for (let i = 0; i < ordered.length; i += 1) {
      for (let j = i + 1; j < ordered.length; j += 1) {
        assert.equal(
          worstVerdict([ordered[j], ordered[i]]),
          ordered[i],
          `${ordered[i]} must outrank ${ordered[j]}`,
        );
      }
    }
  });

  test('every verdict is reachable — none is silently dropped', () => {
    for (const verdict of Object.values(VERDICT)) {
      assert.equal(worstVerdict([verdict]), verdict, verdict);
    }
  });

  test('an unrecognised verdict degrades to UNVERIFIABLE, not COUNTERFEIT', () => {
    // Asserting nothing beats accusing a pharmacist of selling fakes because the
    // app is older than the API.
    assert.equal(worstVerdict(['FUTURE_VERDICT']), VERDICT.UNVERIFIABLE);
  });

  test('a non-array is GENUINE rather than a crash', () => {
    assert.equal(worstVerdict(null), VERDICT.GENUINE);
    assert.equal(worstVerdict(undefined), VERDICT.GENUINE);
  });
});

describe('verdictToErrorCode', () => {
  test('failures carry a contract error code', () => {
    assert.equal(verdictToErrorCode(VERDICT.COUNTERFEIT), CODES.SIGNATURE_INVALID);
    assert.equal(verdictToErrorCode(VERDICT.RECALLED), CODES.RECALLED);
    assert.equal(verdictToErrorCode(VERDICT.CLONE), CODES.CLONE_SUSPECTED);
    assert.equal(verdictToErrorCode(VERDICT.COLD_CHAIN), CODES.COLD_CHAIN_BREACH);
    assert.equal(verdictToErrorCode(VERDICT.EXPIRED), CODES.EXPIRED);
    assert.equal(verdictToErrorCode(VERDICT.UNVERIFIABLE), CODES.PAYLOAD_INVALID);
  });

  test('passing verdicts carry none', () => {
    assert.equal(verdictToErrorCode(VERDICT.GENUINE), null);
    assert.equal(verdictToErrorCode(VERDICT.OFFLINE_OK), null);
  });
});

describe('chainVerdict', () => {
  test('a clean unit is GENUINE', () => {
    assert.equal(
      chainVerdict({ status: STATUS.AT_PHARMACY, expired: false }),
      VERDICT.GENUINE,
    );
  });

  test('recall beats every other on-chain finding', () => {
    assert.equal(
      chainVerdict({
        status: STATUS.RECALLED,
        expired: true,
        breached: true,
        cloneSuspected: true,
      }),
      VERDICT.RECALLED,
    );
  });

  test('clone beats a cold chain breach', () => {
    assert.equal(
      chainVerdict({
        status: STATUS.IN_TRANSIT,
        breached: true,
        cloneSuspected: true,
      }),
      VERDICT.CLONE,
    );
  });

  test('a breach beats expiry', () => {
    assert.equal(
      chainVerdict({ status: STATUS.IN_TRANSIT, expired: true, breached: true }),
      VERDICT.COLD_CHAIN,
    );
  });
});

describe('cloneSuspected', () => {
  test('the scan threshold is exclusive', () => {
    assert.equal(cloneSuspected(CLONE_SCAN_THRESHOLD, 1), false);
    assert.equal(cloneSuspected(CLONE_SCAN_THRESHOLD + 1, 1), true);
  });

  test('the district threshold is exclusive', () => {
    assert.equal(cloneSuspected(1, CLONE_DISTRICT_THRESHOLD), false);
    assert.equal(cloneSuspected(1, CLONE_DISTRICT_THRESHOLD + 1), true);
  });

  test('either signal alone is enough', () => {
    assert.equal(cloneSuspected(500, 1), true);
    assert.equal(cloneSuspected(2, 40), true);
  });

  test('a fresh unit is not suspected', () => {
    assert.equal(cloneSuspected(0, 0), false);
  });
});

describe('parseDate', () => {
  test('accepts a strict ISO date at UTC midnight', () => {
    assert.equal(parseDate('mfg_date', '2026-08-22'), Date.UTC(2026, 7, 22));
  });

  test('accepts a real leap day', () => {
    assert.doesNotThrow(() => parseDate('mfg_date', '2028-02-29'));
  });

  test('rejects a leap day that does not exist', () => {
    // Date.UTC would roll this to 1 March without complaint.
    assert.throws(() => parseDate('mfg_date', '2027-02-29'), invalidPayload);
  });

  test('rejects an impossible day of month', () => {
    assert.throws(() => parseDate('expiry_date', '2026-02-31'), invalidPayload);
    assert.throws(() => parseDate('expiry_date', '2026-04-31'), invalidPayload);
    assert.throws(() => parseDate('expiry_date', '2026-13-01'), invalidPayload);
    assert.throws(() => parseDate('expiry_date', '2026-00-10'), invalidPayload);
  });

  test('rejects the loose forms Date.parse would happily accept', () => {
    for (const bad of [
      '2026-3-15',
      '2026/03/15',
      'March 15 2026',
      '15-03-2026',
      '2026-03-15T00:00:00Z',
      ' 2026-03-15',
      '26-03-15',
    ]) {
      assert.throws(() => parseDate('mfg_date', bad), invalidPayload, bad);
    }
  });

  test('rejects non-strings', () => {
    for (const bad of [null, undefined, 20260315, {}, []]) {
      assert.throws(() => parseDate('mfg_date', bad), invalidPayload);
    }
  });
});

describe('expiry arithmetic', () => {
  const noon = new Date('2026-08-22T12:00:00Z');

  test('the expiry day itself is not expired', () => {
    // A pharmacist reading EXP 08/2026 dispenses on the 22nd without hesitation.
    assert.equal(daysToExpiry('2026-08-22', noon), 0);
    assert.equal(isExpired('2026-08-22', noon), false);
  });

  test('the day after is expired', () => {
    assert.equal(daysToExpiry('2026-08-21', noon), -1);
    assert.equal(isExpired('2026-08-21', noon), true);
  });

  test('tomorrow is one day out', () => {
    assert.equal(daysToExpiry('2026-08-23', noon), 1);
    assert.equal(isExpired('2026-08-23', noon), false);
  });

  test('the time of day never changes the answer', () => {
    // Rounding on a DST-free UTC basis; a 23:59 scan must agree with a 00:01 one.
    for (const hour of ['00:00:01', '06:30:00', '12:00:00', '23:59:59']) {
      const at = new Date(`2026-08-22T${hour}Z`);
      assert.equal(daysToExpiry('2026-08-22', at), 0, hour);
      assert.equal(isExpired('2026-08-22', at), false, hour);
    }
  });

  test('spans a leap day correctly', () => {
    const before = new Date('2028-02-28T00:00:00Z');
    assert.equal(daysToExpiry('2028-03-01', before), 2);
  });

  test('dayOf truncates to UTC midnight', () => {
    assert.equal(dayOf(new Date('2026-08-22T23:45:12Z')), Date.UTC(2026, 7, 22));
  });
});

describe('validateDateOrder', () => {
  test('accepts an expiry after manufacture', () => {
    assert.doesNotThrow(() => validateDateOrder('2026-01-10', '2028-01-09'));
  });

  test('rejects an expiry before manufacture', () => {
    assert.throws(
      () => validateDateOrder('2026-01-10', '2026-01-09'),
      invalidPayload,
    );
  });

  test('rejects a same-day expiry — a strip with no shelf life is not real', () => {
    assert.throws(
      () => validateDateOrder('2026-01-10', '2026-01-10'),
      invalidPayload,
    );
  });
});

describe('parseInstant and stamp', () => {
  test('accepts RFC 3339 with Z, offsets and fractional seconds', () => {
    const base = Date.parse('2026-08-22T10:00:00Z');
    assert.equal(parseInstant('recorded_at', '2026-08-22T10:00:00Z'), base);
    assert.equal(parseInstant('recorded_at', '2026-08-22T15:30:00+05:30'), base);
    assert.equal(parseInstant('recorded_at', '2026-08-22T10:00:00.250Z'), base + 250);
  });

  test('rejects a timestamp with no timezone', () => {
    // Without a zone the server would read it as local time and shift a
    // temperature reading by hours.
    for (const bad of [
      '2026-08-22T10:00:00',
      '2026-08-22 10:00:00Z',
      '2026-08-22',
      '2026-08-22T10:00Z',
      '',
    ]) {
      assert.throws(() => parseInstant('recorded_at', bad), invalidInput, bad);
    }
  });

  test('stamp round-trips through parseInstant', () => {
    const now = new Date('2026-08-22T10:00:00.999Z');
    const text = stamp(now);
    assert.equal(text, '2026-08-22T10:00:00Z');
    assert.equal(parseInstant('t', text), Date.parse('2026-08-22T10:00:00Z'));
  });
});

describe('control characters', () => {
  const NUL = String.fromCharCode(0);
  const LF = String.fromCharCode(10);
  const CR = String.fromCharCode(13);
  const DEL = String.fromCharCode(127);
  const NEL = String.fromCharCode(0x85);

  test('finds C0 controls', () => {
    for (const ch of [NUL, LF, CR, String.fromCharCode(0x1f)]) {
      assert.ok(findControlChar(`ok${ch}no`), `code point ${ch.charCodeAt(0)}`);
    }
  });

  test('finds DEL and C1 controls', () => {
    assert.ok(findControlChar(DEL));
    assert.ok(findControlChar(NEL));
    assert.ok(findControlChar(String.fromCharCode(0x9f)));
  });

  test('reports the position in code points', () => {
    const found = findControlChar(`ab${LF}c`);
    assert.equal(found.index, 2);
    assert.equal(found.codePoint, 10);
  });

  test('passes legitimate non-ASCII text', () => {
    for (const good of [
      'Paracetamol 500mg',
      'पैरासिटामोल ५०० मि.ग्रा.',
      'Sun–Pharma', // en dash
      'Café Pharma',
      '💊 emoji outside the BMP',
      'A0 is not a control',
    ]) {
      assert.equal(findControlChar(good), null, good);
      assert.doesNotThrow(() => rejectControlChars('generic_name', good), good);
    }
  });

  test('rejectControlChars names the offending code point', () => {
    assert.throws(
      () => rejectControlChars('notes', `line${LF}two`),
      (err) => err.code === CODES.VALIDATION_ERROR && /U\+000A/.test(err.message),
    );
  });

  test('asCodePointLabel pads to four hex digits', () => {
    assert.equal(asCodePointLabel(0), 'U+0000');
    assert.equal(asCodePointLabel(10), 'U+000A');
    assert.equal(asCodePointLabel(0x85), 'U+0085');
    assert.equal(asCodePointLabel(0x1f48a), 'U+1F48A');
  });
});

describe('validateText', () => {
  test('trims and returns the value', () => {
    assert.equal(validateText('generic_name', '  Paracetamol  ', 64), 'Paracetamol');
  });

  test('rejects empty and whitespace-only input', () => {
    assert.throws(() => validateText('generic_name', '', 64), invalidInput);
    assert.throws(() => validateText('generic_name', '   ', 64), invalidInput);
  });

  test('rejects non-strings', () => {
    for (const bad of [null, undefined, 42, {}, []]) {
      assert.throws(() => validateText('generic_name', bad, 64), invalidInput);
    }
  });

  test('counts length in code points, not UTF-16 units', () => {
    // Ten emoji are ten characters to a person and twenty units to JavaScript.
    const tenAstral = '💊'.repeat(10);
    assert.equal(validateText('quantity', tenAstral, 10), tenAstral);
    assert.throws(() => validateText('quantity', tenAstral, 9), invalidInput);
  });

  test('measures after trimming, so padding does not consume the budget', () => {
    assert.equal(validateText('quantity', `  ${'x'.repeat(32)}  `, 32).length, 32);
  });

  test('falls back to the LIMITS entry when no max is given', () => {
    assert.throws(
      () => validateText('mfg_licence_no', 'x'.repeat(LIMITS.mfg_licence_no + 1)),
      invalidInput,
    );
  });
});

describe('validateProductID', () => {
  test('accepts the documented shape', () => {
    for (const good of [
      'PARACETAMOL500MG_PARACIP500_2026_000001',
      'MEASLESRUBELLA_SURAKSHAMR_2026_000042',
      'A_B_2026_000001',
    ]) {
      assert.equal(validateProductID(good), good, good);
    }
  });

  test('accepts long segments and any 4-digit year, exactly as Python signs them', () => {
    // Being stricter than the signer here shows COUNTERFEIT on genuine medicine.
    assert.doesNotThrow(() => validateProductID('A'.repeat(50) + '_B_2100_000001'));
    assert.doesNotThrow(() => validateProductID('G_B_1999_000001'));
  });

  test('still bounds the whole string by LIMITS.product_id', () => {
    assert.throws(
      () => validateProductID('A'.repeat(LIMITS.product_id) + '_B_2026_000001'),
      invalidInput,
    );
  });

  test('rejects the wrong shape', () => {
    for (const bad of [
      'PARACETAMOL_2026_000001', // three segments
      'paracetamol_paracip_2026_000001', // lowercase
      'PARA_CIP_26_000001', // 2-digit year
      'PARA_CIP_2026_1', // short serial
      'PARA_CIP_2026_0000001', // long serial
      'PARA CIP_2026_000001', // space
      'PARA-CIP_CIP_2026_000001', // hyphen
      '_CIP_2026_000001', // empty segment
    ]) {
      assert.throws(() => validateProductID(bad), invalidInput, bad);
    }
  });
});

describe('validateBatchNo', () => {
  test('accepts manufacturer-defined formats, including punctuation and spaces', () => {
    // A recall that cannot be issued because a batch number has a space in it is
    // a recall that does not happen.
    for (const good of [
      'TM-2026-001',
      'B/2026/07',
      'LOT 42',
      'बैच-०१',
      'ABC.123',
    ]) {
      assert.equal(validateBatchNo(good), good, good);
    }
  });

  test('still enforces the length limit and the control-character rule', () => {
    assert.throws(
      () => validateBatchNo('x'.repeat(LIMITS.batch_no + 1)),
      invalidInput,
    );
    assert.throws(
      () => validateBatchNo(`TM${String.fromCharCode(9)}001`),
      invalidInput,
    );
  });
});

describe('validateLocation', () => {
  test('accepts the §5 form', () => {
    for (const good of [
      'FACTORY_PUNE_01',
      'WH_MUM_001',
      'PHARM_MUM_0142',
      'DIST-NORTH-7',
    ]) {
      assert.equal(validateLocation(good), good, good);
    }
  });

  test('rejects free text that would split one place across dashboard rows', () => {
    for (const bad of [
      'pharm_mum_0142',
      'Pharmacy Mumbai 142',
      '_WH_MUM_001',
      'W', // too short for the pattern
      'x'.repeat(33),
    ]) {
      assert.throws(() => validateLocation(bad), invalidInput, bad);
    }
  });
});

describe('validateSensorID', () => {
  test('accepts and upper-cases', () => {
    assert.equal(validateSensorID('tm-sensor-001'), 'TM-SENSOR-001');
    assert.equal(validateSensorID('TM-SENSOR-A1'), 'TM-SENSOR-A1');
  });

  test('rejects anything else', () => {
    for (const bad of ['SENSOR-001', 'TM-SENSOR-', 'TM-SENSOR-0', 'TM_SENSOR_001']) {
      assert.throws(() => validateSensorID(bad), invalidInput, bad);
    }
  });
});

describe('status transitions', () => {
  test('knownStatus covers exactly the contract statuses', () => {
    for (const status of Object.values(STATUS)) assert.ok(knownStatus(status));
    assert.equal(knownStatus('destroyed'), false);
  });

  test('dispensed and recalled are terminal', () => {
    assert.ok(isTerminalStatus(STATUS.DISPENSED));
    assert.ok(isTerminalStatus(STATUS.RECALLED));
    assert.equal(isTerminalStatus(STATUS.IN_TRANSIT), false);
  });

  test('allows every forward move', () => {
    const forward = [
      [STATUS.MANUFACTURED, STATUS.IN_TRANSIT],
      [STATUS.MANUFACTURED, STATUS.AT_PHARMACY],
      [STATUS.IN_TRANSIT, STATUS.AT_PHARMACY],
      [STATUS.AT_PHARMACY, STATUS.DISPENSED],
      [STATUS.IN_TRANSIT, STATUS.DISPENSED],
    ];
    for (const [from, to] of forward) {
      assert.equal(validateTransition(from, to), to, `${from} → ${to}`);
    }
  });

  test('in_transit may repeat for a further hop', () => {
    assert.equal(
      validateTransition(STATUS.IN_TRANSIT, STATUS.IN_TRANSIT),
      STATUS.IN_TRANSIT,
    );
  });

  test('no other status may repeat', () => {
    assert.throws(
      () => validateTransition(STATUS.AT_PHARMACY, STATUS.AT_PHARMACY),
      invalidInput,
    );
  });

  test('rejects backward moves — this is what stops resale of a dispensed unit', () => {
    for (const [from, to] of [
      [STATUS.AT_PHARMACY, STATUS.IN_TRANSIT],
      [STATUS.IN_TRANSIT, STATUS.MANUFACTURED],
    ]) {
      assert.throws(() => validateTransition(from, to), invalidInput, `${from}→${to}`);
    }
  });

  test('nothing moves out of a terminal status', () => {
    for (const from of [STATUS.DISPENSED, STATUS.RECALLED]) {
      assert.throws(
        () => validateTransition(from, STATUS.IN_TRANSIT),
        invalidInput,
        from,
      );
    }
  });

  test('recall is not reachable as a custody update', () => {
    assert.throws(
      () => validateTransition(STATUS.AT_PHARMACY, STATUS.RECALLED),
      (err) => err.code === CODES.VALIDATION_ERROR && /POST \/api\/recall/.test(err.message),
    );
  });

  test('rejects an unknown target and an unknown source', () => {
    assert.throws(
      () => validateTransition(STATUS.AT_PHARMACY, 'teleported'),
      invalidInput,
    );
    assert.throws(
      () => validateTransition('unheard_of', STATUS.DISPENSED),
      invalidInput,
    );
  });
});

describe('temperature', () => {
  test('accepts readings inside the sensor range', () => {
    for (const t of [SENSOR_TEMP_MIN_C, -10, 0, 4.5, 37, SENSOR_TEMP_MAX_C]) {
      assert.equal(validateTemperature(t), t, String(t));
    }
  });

  test('rejects readings outside it as a wiring fault', () => {
    // A disconnected one-wire bus reads -127 or +85; the former must not be
    // filed as the coldest cold-chain breach in history.
    for (const t of [-127, -55.1, 125.1, 1000]) {
      assert.throws(() => validateTemperature(t), invalidInput, String(t));
    }
  });

  test('rejects non-numbers and non-finite values', () => {
    for (const t of ['4.5', null, undefined, NaN, Infinity, -Infinity, {}]) {
      assert.throws(() => validateTemperature(t), invalidInput, String(t));
    }
  });

  test('the vaccine window is inclusive at both ends', () => {
    assert.equal(breachesColdChain(TYPE.VACCINE, VACCINE_TEMP_MIN_C), false);
    assert.equal(breachesColdChain(TYPE.VACCINE, VACCINE_TEMP_MAX_C), false);
    assert.equal(breachesColdChain(TYPE.VACCINE, 1.9), true);
    assert.equal(breachesColdChain(TYPE.VACCINE, 8.1), true);
  });

  test('a medicine has no cold chain to breach', () => {
    assert.equal(breachesColdChain(TYPE.MEDICINE, 45), false);
    assert.equal(breachesColdChain(TYPE.MEDICINE, -30), false);
  });
});

describe('validateRecordedAt', () => {
  const now = Date.parse('2026-08-22T12:00:00Z');
  const at = (ms) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z');

  test('accepts the present', () => {
    assert.equal(validateRecordedAt(at(now), now), now);
  });

  test('tolerates modest clock skew forward', () => {
    const skewed = now + MAX_RECORDED_AT_SKEW_MS - 1000;
    assert.equal(validateRecordedAt(at(skewed), now), skewed);
  });

  test('rejects a timestamp further ahead than the tolerance', () => {
    // Either a wrong clock or an alibi planted ahead of an excursion.
    assert.throws(
      () => validateRecordedAt(at(now + MAX_RECORDED_AT_SKEW_MS + 60000), now),
      invalidInput,
    );
  });

  test('accepts a backlog flushed after days offline', () => {
    const old = now - 20 * 86400000;
    assert.equal(validateRecordedAt(at(old), now), old);
  });

  test('rejects readings older than the backfill window', () => {
    assert.throws(
      () => validateRecordedAt(at(now - MAX_RECORDED_AT_AGE_MS - 86400000), now),
      invalidInput,
    );
  });

  test('rejects a malformed timestamp before any range check', () => {
    assert.throws(() => validateRecordedAt('yesterday', now), invalidInput);
  });
});

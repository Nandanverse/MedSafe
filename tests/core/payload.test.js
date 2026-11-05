/**
 * MedicineData: the signed data elements of one sellable unit.
 *
 * The governing rule under test here is the asymmetry stated at the top of
 * payload.js: **validation of a signed field must never be stricter than the
 * signer.** Several tests below deliberately assert that permissive inputs are
 * *accepted*, and they are not oversights — each one is a case where being
 * stricter than the Python signer would make genuine medicine read as
 * COUNTERFEIT.
 *
 * Demo values use real generic drug names with invented brand names, so no real
 * trademark appears anywhere in the repository.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { CODES } from '../../src/core/errors.js';
import { LIMITS, TYPE } from '../../src/core/rules.js';
import {
  MedicineData,
  makeProductID,
  CONTRACT_VERSION,
  MAX_PAYLOAD_BYTES,
  QR_MAX_BYTES_ECC_H,
  REQUIRED_WIRE_KEYS,
  REQUIRED_FULL_KEYS,
} from '../../src/core/payload.js';

const invalid = (err) => err.code === CODES.PAYLOAD_INVALID;

/** A minimal valid medicine. Override any field per test. */
const fields = (overrides = {}) => ({
  product_id: 'PARACETAMOL500MG_PARACIP500_2026_000001',
  generic_name: 'Paracetamol 500mg',
  brand_name: 'Paracip 500',
  manufacturer: 'Bharat Pharma Works Pvt Ltd, Pune',
  mfg_licence_no: 'MH-PUN-2019-0451',
  batch_no: 'TM-2026-001',
  mfg_date: '2026-01-15',
  expiry_date: '2028-01-14',
  quantity: '10 tablets',
  excipients: ['Starch', 'Magnesium stearate'],
  med_type: TYPE.MEDICINE,
  ...overrides,
});

const make = (overrides = {}) => new MedicineData(fields(overrides));

/**
 * Every field at its documented character maximum, with `n` maximum-length
 * excipients. Used to probe the byte budget, which the character limits alone do
 * not imply.
 */
const maxedFields = (n) => ({
  product_id: `${'A'.repeat(LIMITS.product_id - 15)}_B_2026_000001`,
  generic_name: 'g'.repeat(LIMITS.generic_name),
  brand_name: 'b'.repeat(LIMITS.brand_name),
  manufacturer: 'm'.repeat(LIMITS.manufacturer),
  mfg_licence_no: 'l'.repeat(LIMITS.mfg_licence_no),
  batch_no: 'n'.repeat(LIMITS.batch_no),
  quantity: 'q'.repeat(LIMITS.quantity),
  excipients: Array.from({ length: n }, () => 'x'.repeat(LIMITS.excipient)),
});

describe('capacity budget', () => {
  test('is derived from QR capacity, not guessed', () => {
    // ((1273 - 91) / 4) * 3 = 885
    assert.equal(QR_MAX_BYTES_ECC_H, 1273);
    assert.equal(MAX_PAYLOAD_BYTES, 885);
  });

  test('a realistic payload fits comfortably', () => {
    const size = make().canonicalJSON().length;
    assert.ok(size < MAX_PAYLOAD_BYTES, `payload is ${size} bytes`);
  });

  test('the per-field character limits do not add up to the byte budget', () => {
    // Measured, not assumed: every field at its documented maximum plus 12
    // maximum-length excipients encodes to 1030 bytes, which is 145 over budget.
    // So the character limits and the byte budget are two independent gates —
    // passing all of the former does not imply passing the latter. That is why
    // the budget check exists rather than being derivable from LIMITS.
    assert.throws(() => make(maxedFields(12)), (err) =>
      err.code === CODES.PAYLOAD_INVALID && /over the 885-byte budget/.test(err.message));
  });

  test('the budget boundary is where the measurement puts it', () => {
    // 8 maxed excipients on top of every other field maxed is 858 bytes; the
    // ninth pushes it to 901. Pinning both sides catches an off-by-one in the
    // comparison, which either rejects printable strips or accepts unprintable
    // ones.
    assert.equal(new MedicineData(fields(maxedFields(8))).canonicalJSON().length, 858);
    assert.throws(() => make(maxedFields(9)), invalid);
  });

  test('the byte budget bites before the character limits on Devanagari text', () => {
    // Each Devanagari character costs three UTF-8 bytes, so a payload well inside
    // every character limit can still be unprintable. Catching it at
    // construction means the failure lands on whoever typed the data rather than
    // stopping a production line at print time.
    const devanagari = {
      manufacturer: 'भारत फार्मा वर्क्स प्राइवेट लिमिटेड, पुणे, महाराष्ट्र',
      generic_name: 'पैरासिटामोल ५०० मिलीग्राम',
      brand_name: 'पैरासिप ५००',
      quantity: '१० गोलियाँ की पट्टी',
      excipients: [
        'स्टार्च', 'मैग्नीशियम स्टीयरेट', 'माइक्रोक्रिस्टलाइन सेलुलोज',
        'पोविडोन', 'टैल्क', 'सोडियम स्टार्च ग्लाइकोलेट',
        'हाइड्रोक्सीप्रोपाइल मेथिलसेलुलोज', 'टाइटेनियम डाइऑक्साइड',
        'पॉलीइथाइलीन ग्लाइकोल', 'क्रॉसकार्मेलोज सोडियम',
        'कोलाइडल सिलिकॉन डाइऑक्साइड', 'स्टीयरिक अम्ल',
      ],
    };

    // Establish the premise first: nothing here is over a character limit, so if
    // the byte budget did not exist this would be accepted and then fail at the
    // printer.
    for (const [field, value] of Object.entries(devanagari)) {
      if (field === 'excipients') {
        assert.ok(value.length <= LIMITS.excipients);
        for (const ex of value) assert.ok([...ex].length <= LIMITS.excipient, ex);
      } else {
        assert.ok([...value].length <= LIMITS[field], `${field} is within its limit`);
      }
    }

    assert.throws(
      () => make(devanagari),
      (err) => err.code === CODES.PAYLOAD_INVALID && /3 bytes per character/.test(err.message),
    );
  });

  test('the error reports the overflow so it can be acted on', () => {
    // A print-run operator needs to know how much to cut, not merely that it is
    // too long.
    assert.throws(
      () => make(maxedFields(12)),
      (err) => /overflow: 145 bytes/.test(err.message) && /Shorten the manufacturer/.test(err.message),
    );
  });
});

describe('required fields', () => {
  test('rejects a missing or empty value in every string field', () => {
    for (const field of [
      'product_id', 'generic_name', 'brand_name', 'manufacturer',
      'mfg_licence_no', 'batch_no', 'quantity',
    ]) {
      assert.throws(() => make({ [field]: undefined }), invalid, `${field} undefined`);
      assert.throws(() => make({ [field]: '' }), invalid, `${field} empty`);
      assert.throws(() => make({ [field]: '   ' }), invalid, `${field} blank`);
      assert.throws(() => make({ [field]: null }), invalid, `${field} null`);
      assert.throws(() => make({ [field]: 42 }), invalid, `${field} number`);
    }
  });

  test('trims surrounding whitespace', () => {
    assert.equal(make({ generic_name: '  Paracetamol 500mg  ' }).genericName, 'Paracetamol 500mg');
  });

  test('rejects control characters in signed fields', () => {
    const LF = String.fromCharCode(10);
    assert.throws(
      () => make({ brand_name: `Paracip${LF}500` }),
      (err) => err.code === CODES.PAYLOAD_INVALID && /U\+000A/.test(err.message),
    );
  });

  test('enforces the per-field character limits', () => {
    for (const [field, prop] of [
      ['generic_name', 'generic_name'],
      ['brand_name', 'brand_name'],
      ['manufacturer', 'manufacturer'],
      ['mfg_licence_no', 'mfg_licence_no'],
      ['batch_no', 'batch_no'],
      ['quantity', 'quantity'],
    ]) {
      assert.throws(
        () => make({ [prop]: 'x'.repeat(LIMITS[field] + 1) }),
        invalid,
        field,
      );
    }
  });

  test('constructing with no arguments fails rather than producing a blank unit', () => {
    assert.throws(() => new MedicineData(), invalid);
    assert.throws(() => new MedicineData({}), invalid);
  });
});

describe('product_id', () => {
  test('accepts the documented shape', () => {
    assert.doesNotThrow(() => make({ product_id: 'A_B_2026_000001' }));
  });

  test('accepts long segments and any 4-digit year, exactly as Python signs them', () => {
    // Stricter here than the signer means COUNTERFEIT on genuine medicine.
    assert.doesNotThrow(() => make({ product_id: `${'A'.repeat(50)}_B_2100_000001` }));
    assert.doesNotThrow(() => make({ product_id: 'G_B_1999_000001' }));
  });

  test('is still bounded overall by LIMITS.product_id', () => {
    assert.throws(
      () => make({ product_id: `${'A'.repeat(LIMITS.product_id)}_B_2026_000001` }),
      invalid,
    );
  });

  test('rejects the wrong shape', () => {
    for (const bad of [
      'PARACETAMOL_2026_000001',
      'paracetamol_paracip_2026_000001',
      'PARA_CIP_26_000001',
      'PARA_CIP_2026_1',
      'PARA CIP_2026_000001',
      'PARA-CIP_CIP_2026_000001',
    ]) {
      assert.throws(() => make({ product_id: bad }), invalid, bad);
    }
  });

  test('the error points at makeProductID rather than restating the regex', () => {
    assert.throws(
      () => make({ product_id: 'nope' }),
      (err) => /makeProductID\(\)/.test(err.message),
    );
  });
});

describe('dates', () => {
  test('rejects anything but strict ISO 8601', () => {
    for (const bad of ['15-01-2026', '2026/01/15', '2026-1-15', 'Jan 15 2026']) {
      assert.throws(() => make({ mfg_date: bad }), invalid, bad);
      assert.throws(() => make({ expiry_date: bad }), invalid, bad);
    }
  });

  test('rejects rollover dates that Date.UTC would silently accept', () => {
    assert.throws(() => make({ mfg_date: '2026-02-31' }), invalid);
    assert.throws(() => make({ expiry_date: '2027-02-29' }), invalid);
  });

  test('requires expiry strictly after manufacture', () => {
    assert.throws(
      () => make({ mfg_date: '2026-01-15', expiry_date: '2026-01-14' }),
      invalid,
    );
    assert.throws(
      () => make({ mfg_date: '2026-01-15', expiry_date: '2026-01-15' }),
      invalid,
    );
    assert.doesNotThrow(() =>
      make({ mfg_date: '2026-01-15', expiry_date: '2026-01-16' }),
    );
  });

  test('daysToExpiry and isExpired read the printed date as a pharmacist would', () => {
    const unit = make({ expiry_date: '2026-08-22' });
    const onExpiryDay = new Date('2026-08-22T23:00:00Z');
    assert.equal(unit.daysToExpiry(onExpiryDay), 0);
    assert.equal(unit.isExpired(onExpiryDay), false);
    assert.equal(unit.isExpired(new Date('2026-08-23T00:01:00Z')), true);
  });
});

describe('type flag', () => {
  test('medicine is the default', () => {
    assert.equal(make({ med_type: undefined }).medType, TYPE.MEDICINE);
    assert.equal(make({ med_type: undefined }).isVaccine, false);
  });

  test('vaccine sets isVaccine, which gates the whole cold chain', () => {
    const vaccine = make({ med_type: TYPE.VACCINE });
    assert.equal(vaccine.isVaccine, true);
    assert.equal(vaccine.toWireDict().tp, 'V');
  });

  test('rejects an unknown type', () => {
    for (const bad of ['syrup', 'M', 'V', '', null, 1]) {
      assert.throws(() => make({ med_type: bad }), invalid, String(bad));
    }
  });
});

describe('excipients', () => {
  test('accepts an empty list', () => {
    assert.deepEqual(make({ excipients: [] }).excipients, []);
  });

  test('defaults to an empty list', () => {
    assert.deepEqual(make({ excipients: undefined }).excipients, []);
  });

  test('rejects a comma-joined string, which is unparseable', () => {
    // Excipient names may themselves contain commas, so a joined string cannot
    // be split back apart reliably.
    assert.throws(
      () => make({ excipients: 'Starch, Magnesium stearate' }),
      (err) => err.code === CODES.PAYLOAD_INVALID && /JSON array of strings/.test(err.message),
    );
  });

  test('rejects non-string entries and over-long ones', () => {
    assert.throws(() => make({ excipients: ['Starch', 42] }), invalid);
    assert.throws(() => make({ excipients: ['Starch', null] }), invalid);
    assert.throws(() => make({ excipients: ['x'.repeat(LIMITS.excipient + 1)] }), invalid);
  });

  test('rejects more entries than the limit', () => {
    assert.throws(
      () => make({ excipients: Array.from({ length: 13 }, (_, i) => `E${i}`) }),
      (err) => err.code === CODES.PAYLOAD_INVALID && /declared inactive ingredients/.test(err.message),
    );
  });

  test('preserves order, because order is part of the signed bytes', () => {
    const order = ['Zinc oxide', 'Almond gum', 'Starch'];
    assert.deepEqual(make({ excipients: order }).excipients, order);
    assert.equal(
      make({ excipients: order }).canonicalJSONString().includes(
        '["Zinc oxide","Almond gum","Starch"]',
      ),
      true,
    );
  });
});

describe('immutability', () => {
  test('the instance is frozen after construction', () => {
    // A payload must not change between signing and encoding — precisely the
    // window in which a tampering bug hides.
    const unit = make();
    assert.ok(Object.isFrozen(unit));
    assert.throws(() => {
      unit.expiryDate = '2099-01-01';
    }, TypeError);
  });

  test('the excipient list is frozen too', () => {
    const unit = make();
    assert.ok(Object.isFrozen(unit.excipients));
    assert.throws(() => unit.excipients.push('Sneaky'), TypeError);
  });

  test('toDict and toWireDict hand out copies, not the internal array', () => {
    const unit = make();
    unit.toDict().excipients.push('Mutated');
    unit.toWireDict().ex.push('Mutated');
    assert.equal(unit.excipients.length, 2);
  });
});

describe('serialisation', () => {
  test('the wire form uses exactly the 12 short keys', () => {
    assert.deepEqual(Object.keys(make().toWireDict()).sort(), [...REQUIRED_WIRE_KEYS].sort());
  });

  test('the full form uses the documented long keys', () => {
    const keys = Object.keys(make().toDict());
    for (const required of REQUIRED_FULL_KEYS) {
      assert.ok(keys.includes(required), required);
    }
    assert.ok(keys.includes('contract_version'));
  });

  test('canonical JSON is sorted and whitespace-free', () => {
    const text = make().canonicalJSONString();
    assert.equal(/\s/.test(text.replace(/"[^"]*"/g, '')), false);
    assert.ok(text.startsWith('{"bn":'));
  });

  test('canonicalJSON is the UTF-8 encoding of canonicalJSONString', () => {
    const unit = make();
    assert.equal(
      unit.canonicalJSON().toString('hex'),
      Buffer.from(unit.canonicalJSONString(), 'utf8').toString('hex'),
    );
  });
});

describe('round trips', () => {
  test('wire dict → MedicineData → wire dict is stable', () => {
    const original = make({ med_type: TYPE.VACCINE });
    const rebuilt = MedicineData.fromWireDict(original.toWireDict());
    assert.deepEqual(rebuilt.toWireDict(), original.toWireDict());
    assert.equal(
      rebuilt.canonicalJSON().toString('hex'),
      original.canonicalJSON().toString('hex'),
    );
  });

  test('full dict → MedicineData → full dict is stable', () => {
    const original = make();
    const rebuilt = MedicineData.fromDict(original.toDict());
    assert.deepEqual(rebuilt.toDict(), original.toDict());
  });

  test('canonical bytes → MedicineData reproduces the same bytes', () => {
    const original = make();
    const rebuilt = MedicineData.fromCanonicalJSON(original.canonicalJSON());
    assert.equal(
      rebuilt.canonicalJSON().toString('hex'),
      original.canonicalJSON().toString('hex'),
    );
  });

  test('survives Devanagari intact', () => {
    const original = make({ generic_name: 'पैरासिटामोल ५०० मि.ग्रा.' });
    const rebuilt = MedicineData.fromCanonicalJSON(original.canonicalJSON());
    assert.equal(rebuilt.genericName, 'पैरासिटामोल ५०० मि.ग्रा.');
  });
});

describe('fromWireDict', () => {
  test('reports every missing key at once', () => {
    const partial = make().toWireDict();
    delete partial.ml;
    delete partial.bt;
    assert.throws(
      () => MedicineData.fromWireDict(partial),
      (err) => /missing required keys: .*ml.*bt|missing required keys: .*bt.*ml/.test(err.message),
    );
  });

  test('rejects a non-object', () => {
    for (const bad of [null, 'string', 42, [], undefined]) {
      assert.throws(() => MedicineData.fromWireDict(bad), invalid, String(bad));
    }
  });

  test('rejects a non-integer version', () => {
    // JSON has one number type, so 1.5 would otherwise slip past.
    for (const bad of [1.5, '1', true, null]) {
      assert.throws(
        () => MedicineData.fromWireDict({ ...make().toWireDict(), v: bad }),
        invalid,
        String(bad),
      );
    }
  });

  test('rejects a contract version this build does not implement', () => {
    assert.throws(
      () => MedicineData.fromWireDict({ ...make().toWireDict(), v: 2 }),
      (err) => err.code === CODES.PAYLOAD_INVALID && /TM1/.test(err.message),
    );
  });

  test('rejects an unknown type flag', () => {
    for (const bad of ['X', 'm', '', 1, null]) {
      assert.throws(
        () => MedicineData.fromWireDict({ ...make().toWireDict(), tp: bad }),
        invalid,
        String(bad),
      );
    }
  });
});

describe('fromCanonicalJSON', () => {
  test('accepts a non-canonically-ordered payload', () => {
    // Deliberate asymmetry with canonicalJSON(): verification signs over the
    // received bytes, so a correctly-signed payload with keys in another order is
    // still authentic. It just cannot have come from our generator.
    const wire = make().toWireDict();
    const reversed = Object.fromEntries(Object.entries(wire).reverse());
    assert.doesNotThrow(() =>
      MedicineData.fromCanonicalJSON(Buffer.from(JSON.stringify(reversed), 'utf8')),
    );
  });

  test('rejects invalid UTF-8 rather than substituting U+FFFD', () => {
    // Buffer.toString('utf8') replaces malformed sequences silently, which would
    // parse into different text than the bytes that were signed.
    const bad = Buffer.from([0x7b, 0x22, 0xff, 0xfe, 0x22, 0x7d]);
    assert.throws(
      () => MedicineData.fromCanonicalJSON(bad),
      (err) => err.code === CODES.PAYLOAD_INVALID && /not valid UTF-8/.test(err.message),
    );
  });

  test('rejects payloads that are not JSON', () => {
    assert.throws(
      () => MedicineData.fromCanonicalJSON(Buffer.from('not json', 'utf8')),
      (err) => err.code === CODES.PAYLOAD_INVALID && /not valid JSON/.test(err.message),
    );
  });

  test('rejects JSON that is not an object', () => {
    for (const bad of ['[]', '"text"', '42', 'null', 'true']) {
      assert.throws(
        () => MedicineData.fromCanonicalJSON(Buffer.from(bad, 'utf8')),
        invalid,
        bad,
      );
    }
  });
});

describe('fromDict', () => {
  test('reports missing fields', () => {
    const partial = make().toDict();
    delete partial.mfg_licence_no;
    assert.throws(
      () => MedicineData.fromDict(partial),
      (err) => /missing required fields: mfg_licence_no/.test(err.message),
    );
  });

  test('defaults contract_version when absent', () => {
    const dict = make().toDict();
    delete dict.contract_version;
    assert.equal(MedicineData.fromDict(dict).contractVersion, CONTRACT_VERSION);
  });

  test('rejects a non-object', () => {
    for (const bad of [null, [], 'x', 42]) {
      assert.throws(() => MedicineData.fromDict(bad), invalid, String(bad));
    }
  });
});

describe('makeProductID', () => {
  test('builds the documented form', () => {
    assert.equal(
      makeProductID('Paracetamol 500mg', 'Paracip 500', 2026, 1),
      'PARACETAMOL500MG_PARACIP500_2026_000001',
    );
  });

  test('removes non-alphanumerics rather than replacing them with underscores', () => {
    // Replacing would introduce a fifth segment and break parsing.
    assert.equal(
      makeProductID('Amoxicillin 500mg', 'Amoxi-Nova 500', 2026, 777),
      'AMOXICILLIN500MG_AMOXINOVA500_2026_000777',
    );
  });

  test('zero-pads the serial to six digits', () => {
    assert.ok(makeProductID('A', 'B', 2026, 1).endsWith('_000001'));
    assert.ok(makeProductID('A', 'B', 2026, 999999).endsWith('_999999'));
  });

  test('output always satisfies the constructor', () => {
    const id = makeProductID('Measles Rubella', 'Suraksha-MR', 2026, 42);
    assert.doesNotThrow(() => make({ product_id: id }));
  });

  test('rejects a serial outside 1..999999', () => {
    for (const bad of [0, -1, 1000000, 1.5, '1', null]) {
      assert.throws(() => makeProductID('A', 'B', 2026, bad), invalid, String(bad));
    }
  });

  test('rejects an implausible year', () => {
    for (const bad of [1899, 3000, 26, 2026.5, '2026']) {
      assert.throws(() => makeProductID('A', 'B', bad, 1), invalid, String(bad));
    }
  });

  test('rejects names with nothing alphanumeric to build from', () => {
    assert.throws(() => makeProductID('---', 'B', 2026, 1), invalid);
    assert.throws(() => makeProductID('पैरासिटामोल', 'B', 2026, 1), invalid);
  });

  test('rejects a result over the product_id limit', () => {
    assert.throws(
      () => makeProductID('A'.repeat(60), 'B'.repeat(60), 2026, 1),
      (err) => err.code === CODES.PAYLOAD_INVALID && /shorten/.test(err.message),
    );
  });
});

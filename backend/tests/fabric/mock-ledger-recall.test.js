/**
 * RecallBatch on the mock ledger.
 *
 * Recall is the most consequential operation in TrueMed: it is the mechanism by
 * which a regulator takes a dangerous batch out of circulation, it is terminal,
 * and it is the one write a patient's verdict depends on going through. So the
 * properties worth testing are not "does it set a field" but "can a recall ever
 * be prevented, and does calling it repeatedly finish".
 *
 * The mock is the executable reference for the Go chaincode, so these cases are
 * also the specification RecallBatch in contract.go has to satisfy. Where a case
 * asserts a field name it is asserting the API↔chaincode contract, not an
 * implementation detail: the service layer must not be able to tell the two
 * drivers apart, and a shape that differs between them is a bug that only shows
 * up in production, on the one path nobody can test locally.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { MockLedger, MSP } from '../../src/fabric/mock-ledger.js';
import {
  MAX_CUSTODY_EVENTS,
  MAX_CUSTODY_EVENTS_RECALL,
  MAX_RECALL_PER_TX,
  STATUS,
  TYPE,
} from '../../src/core/rules.js';
import { CODES } from '../../src/core/errors.js';

const MANUFACTURER = { mspId: MSP.MANUFACTURER };
const DISTRIBUTOR = { mspId: MSP.DISTRIBUTOR };
const REGULATOR = { mspId: MSP.REGULATOR };

/** A fixed clock, so every timestamp in a case is predictable. */
const FIXED_NOW = new Date('2026-06-01T10:00:00Z');

function ledger() {
  return new MockLedger({ clock: () => FIXED_NOW });
}

/**
 * A valid CreateMedicine body. Serial is the only thing that varies, because
 * product IDs must be unique and everything else is noise for these cases.
 */
function medicineInput(serial, overrides = {}) {
  return {
    product_id: `PARACETAMOL500MG_PARACIP500_2026_${String(serial).padStart(6, '0')}`,
    generic_name: 'Paracetamol 500mg',
    brand_name: 'Paracip 500',
    manufacturer: 'Sanjeevani Pharma Ltd, Plot 42 MIDC, Pune 411018',
    mfg_licence_no: 'MH/25D/2019/187',
    batch_no: 'SP26A0417',
    mfg_date: '2026-03-15',
    expiry_date: '2028-02-29',
    quantity: '10 tablets',
    excipients: ['Maize Starch', 'Povidone K30', 'Talc'],
    type: TYPE.MEDICINE,
    location: 'FACT_PUN_0001',
    ...overrides,
  };
}

/** Mint `count` units into one batch and return the ledger. */
async function withBatch(count, overrides = {}) {
  const led = ledger();
  for (let i = 1; i <= count; i += 1) {
    await led.createMedicine(medicineInput(i, overrides), MANUFACTURER);
  }
  return led;
}

const recall = (led, batchNo = 'SP26A0417', reason = 'NSQ: assay 78% of label claim') =>
  led.recallBatch({ batch_no: batchNo, reason }, REGULATOR);

describe('access control', () => {
  test('only the regulator may recall', async () => {
    const led = await withBatch(2);
    for (const ctx of [MANUFACTURER, DISTRIBUTOR, { mspId: '' }]) {
      await assert.rejects(
        () => led.recallBatch({ batch_no: 'SP26A0417', reason: 'because' }, ctx),
        (err) => err.code === CODES.FORBIDDEN,
        `${ctx.mspId || 'unauthenticated'} must not be able to recall`,
      );
    }
    // A refused recall must leave the batch untouched, not half-recalled.
    for (const record of led.state.values()) {
      assert.equal(record.status, STATUS.MANUFACTURED);
    }
  });

  test('a manufacturer cannot recall a competitor batch through the same call', async () => {
    // The concrete abuse the MSP check exists to stop: recall is destructive and
    // batch numbers are printed on every strip, so they are not a secret.
    const led = await withBatch(1);
    await assert.rejects(
      () => led.recallBatch({ batch_no: 'SP26A0417', reason: 'competitive mischief' }, MANUFACTURER),
      (err) => err.code === CODES.FORBIDDEN,
    );
  });
});

describe('the result shape matches the Go RecallResult', () => {
  test('every documented field is present, with the documented type', async () => {
    const led = await withBatch(3);
    const res = await recall(led);

    // `recalled` is a count and `product_ids` is the list. The mock once returned
    // `recalled` as the array and a separate `count`, which typechecks fine on
    // both sides and silently gives the dashboards a number where they expected a
    // list the moment FABRIC_MOCK flips to 0.
    assert.equal(typeof res.recalled, 'number', 'recalled is a count, not a list');
    assert.ok(Array.isArray(res.product_ids), 'product_ids is the list of units');
    assert.equal(res.recalled, 3);
    assert.equal(res.product_ids.length, 3);
    assert.equal(res.already_recalled, 0);
    assert.equal(res.more_remaining, false);
    assert.equal(res.batch_no, 'SP26A0417');
    assert.equal(res.recalled_at, '2026-06-01T10:00:00Z');
    assert.equal(res.actor_msp, MSP.REGULATOR);
    assert.deepEqual(
      Object.keys(res).sort(),
      [
        'actor_msp',
        'already_recalled',
        'batch_no',
        'more_remaining',
        'product_ids',
        'recalled',
        'recalled_at',
      ],
      'an extra or missing key here is a divergence from contract.go',
    );
  });

  test('product_ids names exactly the units this call changed', async () => {
    const led = await withBatch(2);
    const res = await recall(led);
    for (const productID of res.product_ids) {
      assert.equal(led.state.get(productID).status, STATUS.RECALLED);
    }
    assert.equal(res.product_ids.length, res.recalled);
  });

  test('the event payload matches the contract too', async () => {
    const led = await withBatch(2);
    await recall(led);
    assert.equal(led.lastEvent.name, 'BatchRecalled');
    assert.deepEqual(Object.keys(led.lastEvent.payload).sort(), [
      'actor_msp',
      'batch_no',
      'more_remaining',
      'reason',
      'recalled',
      'timestamp',
    ]);
    assert.equal(led.lastEvent.payload.recalled, 2, 'a count, as in contract.go');
  });
});

describe('what a recall writes to each unit', () => {
  test('status, reason, timestamp and a custody hop attributed to the regulator', async () => {
    const led = await withBatch(1);
    await recall(led, 'SP26A0417', 'NSQ: assay 78% of label claim');
    const record = [...led.state.values()][0];

    assert.equal(record.status, STATUS.RECALLED);
    assert.equal(record.recall_reason, 'NSQ: assay 78% of label claim');
    assert.equal(record.recalled_at, '2026-06-01T10:00:00Z');
    assert.equal(record.updated_at, '2026-06-01T10:00:00Z');

    const hop = record.custody_trail.at(-1);
    assert.equal(hop.status, STATUS.RECALLED);
    assert.equal(hop.actor_msp, MSP.REGULATOR, 'the audit trail must name who recalled');
    assert.equal(hop.timestamp, '2026-06-01T10:00:00Z');
  });

  test('a unit already dispensed to a patient is still recalled', async () => {
    // Dispensed is terminal for custody but not for safety: the point of a recall
    // is to reach medicine that is already in someone's hands.
    const led = await withBatch(1);
    const id = medicineInput(1).product_id;
    await led.updateLocation(
      { product_id: id, status: STATUS.IN_TRANSIT, location: 'WARE_PUN_0007' },
      DISTRIBUTOR,
    );
    await led.updateLocation(
      { product_id: id, status: STATUS.AT_PHARMACY, location: 'PHARM_MUM_0142' },
      DISTRIBUTOR,
    );
    const res = await recall(led);
    assert.equal(res.recalled, 1);
    assert.equal(led.state.get(id).status, STATUS.RECALLED);
  });

  test('units in other batches are untouched', async () => {
    const led = ledger();
    await led.createMedicine(medicineInput(1), MANUFACTURER);
    await led.createMedicine(
      medicineInput(2, { batch_no: 'SP26A0418' }),
      MANUFACTURER,
    );
    const res = await recall(led, 'SP26A0417');
    assert.equal(res.recalled, 1);
    assert.equal(led.state.get(medicineInput(2).product_id).status, STATUS.MANUFACTURED);
  });
});

describe('an unknown batch', () => {
  test('is NOT_ON_CHAIN rather than an empty success', async () => {
    // A regulator who mistypes a batch number must be told, not congratulated on
    // recalling nothing.
    const led = await withBatch(1);
    await assert.rejects(
      () => recall(led, 'SP26A9999'),
      (err) => err.code === CODES.NOT_ON_CHAIN,
    );
  });
});

describe('idempotence and forward progress', () => {
  test('recalling twice is idempotent, and the second call reports it', async () => {
    const led = await withBatch(3);
    const first = await recall(led);
    const second = await recall(led);

    assert.equal(first.recalled, 3);
    assert.equal(second.recalled, 0, 'nothing left to recall');
    assert.equal(second.already_recalled, 3, 'and it says so rather than reporting an error');
    assert.equal(second.more_remaining, false, 'so the caller stops');
    assert.deepEqual(second.product_ids, []);

    // The second call must not append a second recall hop to any unit.
    for (const record of led.state.values()) {
      const recallHops = record.custody_trail.filter((h) => h.status === STATUS.RECALLED);
      assert.equal(recallHops.length, 1, 'one recall hop per unit, however many calls');
    }
  });

  test('a batch larger than the write cap is recalled in full by repeated calls', async () => {
    // The regression this file exists for. The cap has to apply to the units a
    // call *writes*, not the index rows it *reads*. Capping the read means every
    // call sees the same prefix of the batch, so after the first call recalls
    // those units, each later call recalls nothing, still reports
    // `more_remaining: true`, and the units behind the prefix are unreachable
    // forever — a batch that can never be fully recalled, which in this system
    // means dangerous medicine that stays valid on every patient's scan.
    const total = MAX_RECALL_PER_TX + 7;
    const led = await withBatch(total);

    const first = await recall(led);
    assert.equal(first.recalled, MAX_RECALL_PER_TX, 'one call writes at most the cap');
    assert.equal(first.more_remaining, true, 'and admits there is more');

    const second = await recall(led);
    assert.equal(second.recalled, 7, 'the second call reaches the units the first left');
    assert.equal(second.more_remaining, false, 'and terminates the loop');

    for (const record of led.state.values()) {
      assert.equal(record.status, STATUS.RECALLED, `${record.product_id} was left behind`);
    }
  });

  test('the caller loop terminates, and each pass makes progress', async () => {
    // Stated as the property rather than as fixed counts: "repeat while
    // more_remaining" must be safe to write literally, with a bound low enough
    // that a non-progressing implementation fails instead of hanging the suite.
    const led = await withBatch(MAX_RECALL_PER_TX * 2 + 3);
    let calls = 0;
    let recalledTotal = 0;
    let more = true;
    while (more) {
      calls += 1;
      assert.ok(calls <= 5, 'the recall loop is not converging');
      const res = await recall(led);
      assert.ok(res.recalled > 0, `call ${calls} made no progress`);
      recalledTotal += res.recalled;
      more = res.more_remaining;
    }
    assert.equal(calls, 3);
    assert.equal(recalledTotal, MAX_RECALL_PER_TX * 2 + 3);
  });
});

describe('a full custody trail cannot veto a recall', () => {
  test('a unit at the normal custody cap is still recallable', async () => {
    // Without the reserved slot this is a denial-of-service on recall itself: a
    // distributor who loops UpdateLocation until the trail is full would make
    // every future recall of that batch fail, with no retry able to succeed.
    const led = await withBatch(1);
    const id = medicineInput(1).product_id;
    const record = led.state.get(id);

    // Fill the trail to the cap the location path enforces.
    while (record.custody_trail.length < MAX_CUSTODY_EVENTS) {
      record.custody_trail.push({
        status: STATUS.IN_TRANSIT,
        location: 'WARE_PUN_0007',
        timestamp: '2026-05-01T00:00:00Z',
        actor_msp: MSP.DISTRIBUTOR,
      });
    }
    assert.equal(record.custody_trail.length, MAX_CUSTODY_EVENTS);

    // The location path refuses, which is correct — that cap is what stops the
    // trail growing without bound in the first place.
    await assert.rejects(
      () =>
        led.updateLocation(
          { product_id: id, status: STATUS.IN_TRANSIT, location: 'WARE_PUN_0008' },
          DISTRIBUTOR,
        ),
      (err) => err.code === CODES.VALIDATION_ERROR,
    );

    // The recall path draws on the reserved slot and goes through.
    const res = await recall(led);
    assert.equal(res.recalled, 1);
    assert.equal(led.state.get(id).status, STATUS.RECALLED);
    assert.equal(led.state.get(id).custody_trail.length, MAX_CUSTODY_EVENTS_RECALL);
  });

  test('the reserved slot is one deep, so it cannot be used to grow the trail', async () => {
    // Recall is terminal, so the slot is claimable at most once per unit; a trail
    // already at the recall ceiling is a real anomaly and must be refused.
    const led = await withBatch(1);
    const record = led.state.get(medicineInput(1).product_id);
    while (record.custody_trail.length < MAX_CUSTODY_EVENTS_RECALL) {
      record.custody_trail.push({
        status: STATUS.IN_TRANSIT,
        location: 'WARE_PUN_0007',
        timestamp: '2026-05-01T00:00:00Z',
        actor_msp: MSP.DISTRIBUTOR,
      });
    }
    await assert.rejects(
      () => recall(led),
      (err) => err.code === CODES.VALIDATION_ERROR && /stuck integration/.test(err.message),
    );
  });
});

describe('input validation', () => {
  test('a missing or blank reason is refused', async () => {
    // The reason is what a pharmacist and a patient are shown. A recall with no
    // stated cause is not actionable by anyone.
    const led = await withBatch(1);
    for (const reason of [undefined, '', '   ']) {
      await assert.rejects(
        () => led.recallBatch({ batch_no: 'SP26A0417', reason }, REGULATOR),
        (err) => err.code === CODES.VALIDATION_ERROR,
        `reason ${JSON.stringify(reason)} must be refused`,
      );
    }
  });

  test('a control character in the reason is refused', async () => {
    // The reason reaches a log line, a Grafana panel and a patient's screen.
    const led = await withBatch(1);
    await assert.rejects(
      () =>
        led.recallBatch(
          { batch_no: 'SP26A0417', reason: `NSQ${String.fromCharCode(10)}injected` },
          REGULATOR,
        ),
      (err) => err.code === CODES.VALIDATION_ERROR,
    );
  });

  test('a blank batch number is refused before anything is written', async () => {
    const led = await withBatch(1);
    await assert.rejects(
      () => led.recallBatch({ batch_no: '  ', reason: 'NSQ' }, REGULATOR),
      (err) => err.code === CODES.VALIDATION_ERROR,
    );
    assert.equal([...led.state.values()][0].status, STATUS.MANUFACTURED);
  });
});

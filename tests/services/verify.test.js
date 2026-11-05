/**
 * The verification service — `GET /api/verify/:productID` and `POST /api/verify/payload`.
 *
 * This is the endpoint the whole project exists to serve: a patient holding a strip of
 * medicine, asking whether it is real. So these cases are written around the answers a
 * patient can receive rather than around the functions that produce them, and every
 * verdict boundary that could mislead someone is pinned here.
 *
 * Two properties matter more than the rest and are asserted repeatedly:
 *
 * **A verdict is not an HTTP failure.** EXPIRED and RECALLED are successful answers
 * carrying bad news, so they come back as a body with a verdict in it, never as a
 * thrown error. Only the absence of a record (NOT_ON_CHAIN) and genuine protocol
 * problems throw. If this ever inverts, the app's error path swallows the very
 * verdicts it most needs to show.
 *
 * **A cached verdict must never outlive the write that changed it.** §4.6 permits an
 * hour of caching, which means a recall that fails to invalidate leaves units reading
 * GENUINE for an hour after a regulator pulled them.
 *
 * The whole stack here is in-process — mock ledger, in-memory cache, the real signed
 * trust bundle from the fixtures — so these run with no database, no Redis, no Fabric
 * network and no Express.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import { MemoryCache } from '../../src/cache/memory.js';
import { MockLedger } from '../../src/fabric/mock-ledger.js';
import { TrustBundle } from '../../src/core/trust-bundle.js';
import { loadConfig } from '../../src/config/index.js';
import { makeTrustService } from '../../src/services/trust.js';
import { makeVerifyService } from '../../src/services/verify.js';
import { makeSupplyChainService } from '../../src/services/supply-chain.js';
import { verifyWire } from '../../src/core/verifier.js';
import { SecretBox } from '../../src/utils/secret-box.js';
import { MemoryStore } from '../../src/db/memory-store.js';
import { CODES } from '../../src/core/errors.js';
import { STATUS, TYPE, VERDICT, CHECK } from '../../src/core/rules.js';

const FIXTURES = JSON.parse(
  readFileSync(new URL('../fixtures/fixtures.json', import.meta.url), 'utf8'),
);

/** Fixed, so expiry arithmetic in every case is deterministic. */
const FIXED_NOW = new Date('2026-06-01T10:00:00Z');
const clock = () => FIXED_NOW;

const MANUFACTURER = { role: 'manufacturer' };
const REGULATOR = { role: 'regulator' };

function env(extra = {}) {
  return loadConfig({
    NODE_ENV: 'development',
    FABRIC_MOCK: '1',
    LOG_LEVEL: 'silent',
    TRUST_REQUIRE_SIGNATURE: '0',
    SENSOR_REQUIRE_HMAC: '0',
    ...extra,
  });
}

/** The whole verification stack over in-memory infrastructure. */
function stack() {
  const config = env();
  const cache = new MemoryCache(config.redis);
  const fabric = new MockLedger({ clock });
  const store = new MemoryStore({ clock });
  const bundle = TrustBundle.fromJSON(JSON.stringify(FIXTURES.trust_bundle_signed), {
    rootPublicKey: FIXTURES.root_public_key_pem,
    requireSignature: true,
  });
  const trust = makeTrustService({ config, bundle, clock });
  const verify = makeVerifyService({ cache, fabric, trust, clock });
  const supplyChain = makeSupplyChainService({
    cache,
    fabric,
    store,
    secrets: new SecretBox(config.secrets.encryptionKey),
    clock,
  });
  return { cache, fabric, store, trust, verify, supplyChain, config };
}

/**
 * A valid mint body. `mfg_licence_no` is the fixtures' active medicine licence, so the
 * unit belongs to a manufacturer the trust bundle actually knows.
 */
function medicineInput(serial, overrides = {}) {
  return {
    product_id: `PARACETAMOL500MG_PARACIP500_2026_${String(serial).padStart(6, '0')}`,
    generic_name: 'Paracetamol 500mg',
    brand_name: 'Paracip 500',
    manufacturer: 'Sanjeevani Pharma Ltd, Plot 42 MIDC, Pune 411018',
    mfg_licence_no: FIXTURES.licences.active_medicine,
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

/**
 * A real signed wire string from the fixtures, by case name.
 *
 * These are the only signed payloads available to the backend tests — the signing
 * keys live with the Python QR generator, and the backend holds no private key by
 * design (§5) — which makes them the only way to exercise a *successful* signature
 * check here.
 */
function wireFor(caseName) {
  const found = FIXTURES.cases.find((c) => c.name === caseName);
  assert.ok(found, `fixture case ${caseName} is missing`);
  return found.wire;
}

describe('verify.byProductID', () => {
  test('a genuine minted unit verifies as GENUINE', async () => {
    const s = stack();
    const input = medicineInput(1);
    await s.supplyChain.mint(input, MANUFACTURER);

    const { body, cached } = await s.verify.byProductID(input.product_id);

    assert.equal(body.verdict, VERDICT.GENUINE);
    assert.equal(cached, false);
    // §4.4 nests the signed fields under `medicine`; there is no top-level product_id.
    assert.equal(body.medicine.product_id, input.product_id);
    assert.equal(body.checks.signature, 'skipped_no_payload');
  });

  /**
   * Regression: the ledger record and the QR payload both carry a field named
   * `contract_version`, and they are different things — an int format version on the
   * payload (§1.3, always 1 for `TM1`) and the chaincode build string on the record
   * (§3, `"1.0.0"` from the Go contract). Reconstructing the medicine straight from
   * the record therefore fed a build string into a field validated as `=== 1`, and
   * *every* genuine unit answered PAYLOAD_INVALID with a 400. It is worth a named
   * case because the failure is maximally misleading: the medicine is real, the
   * record is intact, and the patient is told their code is malformed.
   */
  test('the chaincode build version is not mistaken for the payload format version', async () => {
    const s = stack();
    const input = medicineInput(2);
    await s.supplyChain.mint(input, MANUFACTURER);

    // The stored record really does carry a non-numeric contract_version; if this
    // stops being true the collision is gone and this test is proving nothing.
    const record = await s.fabric.getMedicine(input.product_id);
    assert.equal(
      typeof record.contract_version,
      'string',
      'the ledger stamps a build version string, per §3',
    );
    assert.notEqual(record.contract_version, 1);

    const { body } = await s.verify.byProductID(input.product_id);
    assert.equal(body.verdict, VERDICT.GENUINE, 'a real unit must not read as a bad payload');
  });

  test('an unknown product is NOT_ON_CHAIN and throws (absence, not a verdict)', async () => {
    const s = stack();
    await assert.rejects(
      () => s.verify.byProductID(medicineInput(3).product_id),
      (err) => {
        assert.equal(err.code, CODES.NOT_ON_CHAIN);
        assert.equal(err.status, 404);
        return true;
      },
    );
  });

  test('expired stock is a 200-with-verdict, not an error', async () => {
    const s = stack();
    const input = medicineInput(4, { mfg_date: '2024-01-10', expiry_date: '2025-01-31' });
    await s.supplyChain.mint(input, MANUFACTURER);

    const { body } = await s.verify.byProductID(input.product_id);

    assert.equal(body.verdict, VERDICT.EXPIRED);
    assert.ok(body.error, 'the reason is carried in the body for the patient to read');
  });

  test('a recalled unit reports RECALLED', async () => {
    const s = stack();
    const input = medicineInput(5);
    await s.supplyChain.mint(input, MANUFACTURER);
    await s.supplyChain.recall(
      { batch_no: input.batch_no, reason: 'failed dissolution testing' },
      REGULATOR,
    );

    const { body } = await s.verify.byProductID(input.product_id);
    assert.equal(body.verdict, VERDICT.RECALLED);
  });
});

describe('verify caching (§4.6)', () => {
  test('a repeat lookup is served from cache', async () => {
    const s = stack();
    const input = medicineInput(6);
    await s.supplyChain.mint(input, MANUFACTURER);

    const first = await s.verify.byProductID(input.product_id);
    const second = await s.verify.byProductID(input.product_id);

    assert.equal(first.cached, false);
    assert.equal(second.cached, true);
    assert.deepEqual(second.body.verdict, first.body.verdict);
  });

  test('a custody write drops the cached verdict', async () => {
    const s = stack();
    const input = medicineInput(7);
    await s.supplyChain.mint(input, MANUFACTURER);
    await s.verify.byProductID(input.product_id); // populate

    await s.supplyChain.recordLocation(
      { product_id: input.product_id, status: STATUS.IN_TRANSIT, location: 'WARE_PUN_0007' },
      { role: 'distributor' },
    );

    const after = await s.verify.byProductID(input.product_id);
    assert.equal(after.cached, false, 'a write must invalidate before it returns');
    assert.equal(after.body.medicine.status, STATUS.IN_TRANSIT);
  });

  /**
   * The one that would hurt most. A recall is the mechanism for pulling dangerous
   * stock, and a surviving cache entry keeps answering GENUINE for up to an hour
   * after it — long enough to dispense the whole batch.
   */
  test('a recall drops every cached verdict in the batch', async () => {
    const s = stack();
    const a = medicineInput(8);
    const b = medicineInput(9);
    await s.supplyChain.mint(a, MANUFACTURER);
    await s.supplyChain.mint(b, MANUFACTURER);
    await s.verify.byProductID(a.product_id);
    await s.verify.byProductID(b.product_id);

    await s.supplyChain.recall({ batch_no: a.batch_no, reason: 'contamination' }, REGULATOR);

    for (const unit of [a, b]) {
      const after = await s.verify.byProductID(unit.product_id);
      assert.equal(after.cached, false, `${unit.product_id} still had a cached verdict`);
      assert.equal(after.body.verdict, VERDICT.RECALLED);
    }
  });

  test('a recall still succeeds when the cache is unavailable', async () => {
    const s = stack();
    const input = medicineInput(10);
    await s.supplyChain.mint(input, MANUFACTURER);

    // A Redis outage must not be able to block a regulator's recall: the ledger write
    // is already committed and durable by the time invalidation is attempted.
    s.cache.del = async () => {
      throw new Error('redis is down');
    };

    const result = await s.supplyChain.recall(
      { batch_no: input.batch_no, reason: 'urgent safety recall' },
      REGULATOR,
    );
    assert.equal(result.recalled, 1);
  });
});

describe('verify.byPayload', () => {
  /**
   * The distinction this pins is easy to get backwards. A string that came off a
   * real scanner and did not verify is an *answer* — the patient scanned something,
   * and they are owed a verdict about it. A caller that sent no payload at all has
   * made a protocol mistake and there is nothing to answer about.
   */
  test('unreadable scanned text is answered with a verdict, not an exception', async () => {
    const s = stack();

    const { body } = await s.verify.byPayload({ raw_payload: 'definitely-not-a-tm1-payload' });

    assert.notEqual(body.verdict, VERDICT.GENUINE);
    assert.ok(
      [VERDICT.UNVERIFIABLE, VERDICT.COUNTERFEIT].includes(body.verdict),
      `unexpected verdict ${body.verdict}`,
    );
    assert.ok(body.error?.message, 'the patient is shown a reason');
  });

  test('a missing raw_payload is a validation failure', async () => {
    const s = stack();
    await assert.rejects(
      () => s.verify.byPayload({}),
      (err) => {
        assert.equal(err.code, CODES.VALIDATION_ERROR);
        return true;
      },
    );
  });

  /**
   * §7.1 (2026-08-22): only this endpoint records a patient scan, because only a
   * full signed payload is evidence a physical strip was present. Garbage must not
   * reach the ledger at all — otherwise a loop of fabricated payloads becomes a way
   * to drive writes, and clone telemetry becomes attacker-controlled.
   */
  test('a rejected payload never touches the ledger', async () => {
    const s = stack();
    let scans = 0;
    const realScan = s.fabric.recordPatientScan.bind(s.fabric);
    s.fabric.recordPatientScan = async (...args) => {
      scans += 1;
      return realScan(...args);
    };

    await s.verify.byPayload({ raw_payload: 'TM1:not-really-a-payload' });
    assert.equal(scans, 0);
  });

  /**
   * Regression, and the most expensive defect found in this backend so far: the
   * service was handing `verifyWire` the trust *service* where a trust *bundle* was
   * wanted. `verifyWire` calls exactly one member on it — `publicKeyFor` — which the
   * service does not have, so the call died with `TypeError: bundle.publicKeyFor is
   * not a function` and the route answered 500.
   *
   * What made it survive a green suite is the shape of the failure. The key is only
   * reached once a payload has decoded, parsed and produced a licence to look up, so
   * every malformed input — which is all the earlier cases in this file used — took
   * an earlier exit and passed. The endpoint was broken for precisely one class of
   * input: a real, correctly signed QR code off a real strip of medicine. Every
   * patient scan, and nothing else.
   *
   * `trust.liveView()` is the intended argument and exists for this (trust.js:222).
   */
  test('a genuine signed payload for a minted unit verifies as GENUINE', async () => {
    const s = stack();
    const wire = wireFor('genuine_medicine_offline');

    // Mint from the payload's own fields, so the ledger and the QR agree — which is
    // what a real mint does, since both come from the same manufacturing run.
    const { medicine } = verifyWire(wire, s.trust.liveView(), { today: FIXED_NOW });
    await s.supplyChain.mint({ ...medicine.toDict(), location: 'FACT_PUN_0001' }, MANUFACTURER);

    const { body } = await s.verify.byPayload({ raw_payload: wire, district: 'Pune' });

    assert.equal(body.verdict, VERDICT.GENUINE);
    // The one check `byProductID` can never make, and the reason this endpoint exists.
    assert.equal(body.checks.signature, CHECK.PASS);
    assert.equal(body.medicine.product_id, medicine.productID);
  });

  /**
   * §2.2, the other half of the same boundary: a valid signature is not sufficient.
   * A photocopied QR carries a perfectly good signature, so a payload that verifies
   * but names a unit no factory ever minted must not come back green.
   */
  test('a valid signature over a unit that was never minted is not GENUINE', async () => {
    const s = stack();

    const { body } = await s.verify.byPayload({ raw_payload: wireFor('genuine_medicine_offline') });

    assert.equal(body.checks.signature, CHECK.PASS, 'the signature really is valid');
    assert.notEqual(body.verdict, VERDICT.GENUINE);
    assert.equal(body.verdict, VERDICT.COUNTERFEIT);
  });

  /**
   * §7.1: this endpoint is the only one that records a patient scan, because a full
   * signed payload is the only evidence that a physical strip was present. The
   * counterpart to "a rejected payload never touches the ledger" above — an accepted
   * one must, or the clone-detection telemetry the CLONE_SUSPECTED verdict is built
   * from is never collected.
   */
  test('an accepted payload records the scan that clone detection is built from', async () => {
    const s = stack();
    const wire = wireFor('genuine_medicine_offline');
    const { medicine } = verifyWire(wire, s.trust.liveView(), { today: FIXED_NOW });
    await s.supplyChain.mint({ ...medicine.toDict(), location: 'FACT_PUN_0001' }, MANUFACTURER);

    await s.verify.byPayload({ raw_payload: wire, district: 'Pune' });

    const record = await s.fabric.getMedicine(medicine.productID);
    assert.equal(Number(record.scan_count), 1);
  });
});

/**
 * The ledger writes: mint, custody hop, temperature reading and recall.
 *
 * These are the operations that decide what the blockchain says, so the cases here
 * are organised around who is allowed to say what, and around the two ways a write
 * can be worse than useless: attributing it to the wrong organisation, or leaving a
 * stale answer cached behind it.
 *
 * The properties being pinned, rather than the code paths:
 *
 * **Accountability comes from the credential, never from the body.** `actor_msp` is
 * derived from the caller's role. A request that supplies its own is choosing who
 * gets blamed for a write, which is the one field that must not be attacker-chosen.
 *
 * **A role's write powers are narrower than its endpoint access.** A pharmacy key
 * reaches `/api/location` and may still only move a unit to `at_pharmacy` or
 * `dispensed` (§4.3). On the real network a pharmacy submits under DistributorMSP,
 * so the chaincode cannot catch this and the API is the only place it is enforced.
 *
 * **A device secret, not just an API key, authorises a temperature reading (§4.7).**
 * One key is realistically shared across a fleet, so without the per-device MAC a
 * key lifted from one cold box could write a comfortable 4 degrees over a vaccine
 * that has been left in the sun — and that reading is what a verdict is built from.
 *
 * Everything runs over the mock ledger, the in-memory store and the in-memory cache.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import { MemoryCache } from '../../src/cache/memory.js';
import { MemoryStore } from '../../src/db/memory-store.js';
import { MockLedger } from '../../src/fabric/mock-ledger.js';
import { TrustBundle } from '../../src/core/trust-bundle.js';
import { loadConfig } from '../../src/config/index.js';
import { makeTrustService } from '../../src/services/trust.js';
import { makeVerifyService } from '../../src/services/verify.js';
import { makeSupplyChainService } from '../../src/services/supply-chain.js';
import { SecretBox, sensorContext, generateSensorSecret } from '../../src/utils/secret-box.js';
import { computeSensorMac } from '../../src/utils/sensor-hmac.js';
import { CODES } from '../../src/core/errors.js';
import { MSP } from '../../src/fabric/mock-ledger.js';
import { STATUS, TYPE, VERDICT } from '../../src/core/rules.js';

const FIXTURES = JSON.parse(
  readFileSync(new URL('../fixtures/fixtures.json', import.meta.url), 'utf8'),
);

const FIXED_NOW = new Date('2026-06-01T10:00:00Z');
const clock = () => FIXED_NOW;

const AS = {
  manufacturer: { role: 'manufacturer' },
  distributor: { role: 'distributor' },
  pharmacy: { role: 'pharmacy' },
  regulator: { role: 'regulator' },
  /** The read-only analytics role, one letter from `pharmacy`. */
  pharma: { role: 'pharma' },
  sensor: { role: 'sensor' },
};

function stack() {
  const config = loadConfig({
    NODE_ENV: 'development',
    FABRIC_MOCK: '1',
    LOG_LEVEL: 'silent',
    TRUST_REQUIRE_SIGNATURE: '0',
  });
  const cache = new MemoryCache(config.redis);
  const store = new MemoryStore({ clock });
  const fabric = new MockLedger({ clock });
  const secrets = new SecretBox(config.secrets.encryptionKey);
  const bundle = TrustBundle.fromJSON(JSON.stringify(FIXTURES.trust_bundle_signed), {
    rootPublicKey: FIXTURES.root_public_key_pem,
    requireSignature: true,
  });
  const trust = makeTrustService({ config, bundle, clock });
  const supplyChain = makeSupplyChainService({ cache, fabric, store, secrets, clock });
  const verify = makeVerifyService({ cache, fabric, trust, clock });
  return { config, cache, store, fabric, secrets, supplyChain, verify };
}

let serial = 0;
/** A distinct valid unit per call, so no two cases collide on a product id. */
function medicineInput(overrides = {}) {
  serial += 1;
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

function vaccineInput(overrides = {}) {
  serial += 1;
  return medicineInput({
    product_id: `COVISHIELD_COVISHIELD_2026_${String(serial).padStart(6, '0')}`,
    generic_name: 'Covishield',
    brand_name: 'Covishield',
    mfg_licence_no: FIXTURES.licences.active_vaccine,
    batch_no: 'CV26B0088',
    type: TYPE.VACCINE,
    quantity: '5 ml vial',
    ...overrides,
  });
}

describe('supply chain: who may write', () => {
  test('the MSP is taken from the role, not from the body', async () => {
    const s = stack();
    const input = medicineInput();

    // A caller trying to pin the write on someone else.
    await s.supplyChain.mint({ ...input, actor_msp: 'RegulatorMSP' }, AS.manufacturer);

    const record = await s.fabric.getMedicine(input.product_id);
    const [first] = record.custody_trail;
    assert.equal(first.actor_msp, MSP.MANUFACTURER, 'the body must not choose the actor');
  });

  test('the read-only pharma role cannot write at all', async () => {
    const s = stack();
    await assert.rejects(
      () => s.supplyChain.mint(medicineInput(), AS.pharma),
      (err) => {
        assert.equal(err.code, CODES.FORBIDDEN);
        assert.match(err.message, /read-only/, 'the message must explain why, not just refuse');
        return true;
      },
    );
  });

  /**
   * §4.3, and the reason it is enforced here rather than left to the chaincode: a
   * pharmacy submits under DistributorMSP on the real network, so the ledger would
   * accept a rewind to `in_transit` as a legitimate distributor action. A chemist
   * could then reroute stock they had already received and the blockchain would
   * faithfully record the theft as normal logistics.
   */
  test('a pharmacy key cannot rewind a unit to in_transit', async () => {
    const s = stack();
    const input = medicineInput();
    await s.supplyChain.mint(input, AS.manufacturer);
    await s.supplyChain.recordLocation(
      { product_id: input.product_id, status: STATUS.AT_PHARMACY, location: 'PHAR_PUN_0042' },
      AS.pharmacy,
    );

    await assert.rejects(
      () =>
        s.supplyChain.recordLocation(
          { product_id: input.product_id, status: STATUS.IN_TRANSIT, location: 'WARE_PUN_0007' },
          AS.pharmacy,
        ),
      (err) => {
        assert.equal(err.code, CODES.FORBIDDEN);
        assert.match(err.message, /at_pharmacy|dispensed/, 'name what a pharmacy may record');
        return true;
      },
    );
  });

  test('a pharmacy key may record the two statuses it owns', async () => {
    const s = stack();
    const input = medicineInput();
    await s.supplyChain.mint(input, AS.manufacturer);

    for (const status of [STATUS.AT_PHARMACY, STATUS.DISPENSED]) {
      const body = await s.supplyChain.recordLocation(
        { product_id: input.product_id, status, location: 'PHAR_PUN_0042' },
        AS.pharmacy,
      );
      assert.equal(body.status, status);
    }
  });

  test('only a regulator may recall, and only with a stated reason', async () => {
    const s = stack();
    const input = medicineInput();
    await s.supplyChain.mint(input, AS.manufacturer);

    await assert.rejects(
      () => s.supplyChain.recall({ batch_no: input.batch_no, reason: 'mischief' }, AS.manufacturer),
      (err) => {
        assert.equal(err.code, CODES.FORBIDDEN);
        return true;
      },
    );
    await assert.rejects(
      () => s.supplyChain.recall({ batch_no: input.batch_no, reason: '   ' }, AS.regulator),
      (err) => {
        assert.equal(err.code, CODES.VALIDATION_ERROR);
        return true;
      },
    );
  });
});

describe('supply chain: write receipts (§4.5a)', () => {
  test('custody writes carry a tx_id and echo the attributed MSP', async () => {
    const s = stack();
    const input = medicineInput();

    const minted = await s.supplyChain.mint(input, AS.manufacturer);
    assert.equal(typeof minted.tx_id, 'string');
    assert.ok(minted.tx_id.length > 0);

    const hop = await s.supplyChain.recordLocation(
      { product_id: input.product_id, status: STATUS.IN_TRANSIT, location: 'WARE_PUN_0007' },
      AS.distributor,
    );
    assert.equal(typeof hop.tx_id, 'string');
    assert.equal(hop.actor_msp, MSP.DISTRIBUTOR);
  });

  /**
   * The contract shows `tx_id` on the three custody writes and omits it from
   * `RecallResult`, and the Dart client does not parse one. Asserted because the
   * obvious "be consistent, add it everywhere" instinct would put an unsanctioned
   * field on the wire; the id is still written to the log so a disputed recall can
   * be traced from the server's own records.
   */
  test('a recall response carries no tx_id', async () => {
    const s = stack();
    const input = medicineInput();
    await s.supplyChain.mint(input, AS.manufacturer);

    const result = await s.supplyChain.recall(
      { batch_no: input.batch_no, reason: 'failed dissolution testing' },
      AS.regulator,
    );

    assert.equal(result.tx_id, undefined);
    assert.equal(result.recalled, 1);
  });

  test('the custody timestamp is the ledger stamp, not the API clock', async () => {
    const s = stack();
    const input = medicineInput();
    const minted = await s.supplyChain.mint(input, AS.manufacturer);

    const record = await s.fabric.getMedicine(input.product_id);
    assert.equal(minted.timestamp, record.custody_trail[0].timestamp);
  });
});

describe('supply chain: cache invalidation (§4.6)', () => {
  /**
   * The subtle one. A patient who scans a strip before it has been minted caches a
   * NOT_ON_CHAIN for 30 seconds. If the mint does not clear that negative entry,
   * the first genuine unit off the line reports "not on the blockchain" — the exact
   * wording that tells a patient their real medicine is fake.
   */
  test('a mint clears a negative cache entry left by an earlier lookup', async () => {
    const s = stack();
    const input = medicineInput();

    await assert.rejects(() => s.verify.byProductID(input.product_id));
    await s.supplyChain.mint(input, AS.manufacturer);

    const { body, cached } = await s.verify.byProductID(input.product_id);
    assert.equal(cached, false);
    assert.equal(body.verdict, VERDICT.GENUINE);
  });

  test('a custody hop drops the cached verdict before responding', async () => {
    const s = stack();
    const input = medicineInput();
    await s.supplyChain.mint(input, AS.manufacturer);
    await s.verify.byProductID(input.product_id);

    // Recorded at the moment the service returns, so this proves the ordering:
    // the delete happens inside the call, not after the response is sent.
    await s.supplyChain.recordLocation(
      { product_id: input.product_id, status: STATUS.IN_TRANSIT, location: 'WARE_PUN_0007' },
      AS.distributor,
    );
    assert.equal(await s.cache.get(input.product_id), null);
  });
});

describe('supply chain: temperature readings (§4.7)', () => {
  const SENSOR_ID = 'TM-SENSOR-0001';
  const RECORDED_AT = '2026-06-01T09:55:00Z';

  /** Provision a device and return its plaintext secret. */
  async function provision(s, sensorId = SENSOR_ID) {
    const secret = generateSensorSecret();
    await s.store.insertSensor({
      sensorId,
      secretEnc: s.secrets.seal(secret, sensorContext(sensorId)),
      label: 'cold box 1',
    });
    return secret;
  }

  function reading(secret, { binding, keyName, temperature, nonce, sensorId = SENSOR_ID }) {
    return {
      [keyName]: binding,
      sensor_id: sensorId,
      temperature,
      recorded_at: RECORDED_AT,
      nonce,
      hmac: computeSensorMac(secret, {
        binding,
        sensorId,
        temperature,
        recordedAt: RECORDED_AT,
        nonce,
      }),
    };
  }

  test('a correctly signed reading is accepted', async () => {
    const s = stack();
    const secret = await provision(s);
    const input = vaccineInput();
    await s.supplyChain.mint(input, AS.manufacturer);

    const body = await s.supplyChain.recordTemperature(
      reading(secret, {
        binding: input.product_id,
        keyName: 'product_id',
        temperature: 4.5,
        nonce: 'a1b2c3d4',
      }),
      AS.sensor,
    );

    assert.equal(body.chain_ok, true);
    assert.equal(body.reading_count, 1);
    assert.equal(body.temperature, 4.5);
  });

  test('a reading outside 2-8 degC is recorded and reported as a breach', async () => {
    const s = stack();
    const secret = await provision(s);
    const input = vaccineInput();
    await s.supplyChain.mint(input, AS.manufacturer);

    const body = await s.supplyChain.recordTemperature(
      reading(secret, {
        binding: input.product_id,
        keyName: 'product_id',
        temperature: 14.25,
        nonce: 'b1b2c3d4',
      }),
      AS.sensor,
    );
    assert.equal(body.chain_ok, false, 'the reading itself is out of range');

    // And the verdict the patient sees must follow the ledger's sticky flag.
    const { body: verdict } = await s.verify.byProductID(input.product_id);
    assert.equal(verdict.verdict, VERDICT.COLD_CHAIN);
    assert.equal(verdict.cold_chain.breached, true);
  });

  test('a forged MAC is rejected even with a valid API key', async () => {
    const s = stack();
    await provision(s);
    const input = vaccineInput();
    await s.supplyChain.mint(input, AS.manufacturer);

    // Signed with a secret that is not the device's — the shared-API-key attacker.
    const wrong = reading(generateSensorSecret(), {
      binding: input.product_id,
      keyName: 'product_id',
      temperature: 4.0,
      nonce: 'c1b2c3d4',
    });

    await assert.rejects(
      () => s.supplyChain.recordTemperature(wrong, AS.sensor),
      (err) => {
        assert.equal(err.code, CODES.UNAUTHORIZED);
        return true;
      },
    );

    const record = await s.fabric.getMedicine(input.product_id);
    assert.equal(Number(record.temp_reading_count ?? 0), 0, 'nothing may reach the ledger');
  });

  test('a captured reading cannot be replayed', async () => {
    const s = stack();
    const secret = await provision(s);
    const input = vaccineInput();
    await s.supplyChain.mint(input, AS.manufacturer);
    const body = reading(secret, {
      binding: input.product_id,
      keyName: 'product_id',
      temperature: 4.5,
      nonce: 'd1b2c3d4',
    });

    await s.supplyChain.recordTemperature(body, AS.sensor);
    await assert.rejects(
      () => s.supplyChain.recordTemperature(body, AS.sensor),
      (err) => {
        assert.equal(err.code, CODES.UNAUTHORIZED);
        assert.match(err.message, /replay|already been used/i);
        return true;
      },
    );
  });

  /**
   * The nonce is burned only after the MAC verifies. Reserving first would let
   * anyone holding the API key spend a real device's nonces with garbage MACs, and
   * every genuine reading that followed would be rejected as a replay — a denial of
   * service on the cold chain mounted with no device secret at all.
   */
  test('a failed MAC does not burn the nonce', async () => {
    const s = stack();
    const secret = await provision(s);
    const input = vaccineInput();
    await s.supplyChain.mint(input, AS.manufacturer);
    const nonce = 'e1b2c3d4';

    await assert.rejects(() =>
      s.supplyChain.recordTemperature(
        reading(generateSensorSecret(), {
          binding: input.product_id,
          keyName: 'product_id',
          temperature: 4.0,
          nonce,
        }),
        AS.sensor,
      ),
    );

    // The real device now uses that nonce; it must still work.
    const body = await s.supplyChain.recordTemperature(
      reading(secret, {
        binding: input.product_id,
        keyName: 'product_id',
        temperature: 4.0,
        nonce,
      }),
      AS.sensor,
    );
    assert.equal(body.reading_count, 1);
  });

  test('an unprovisioned device is a 404, not an auth failure', async () => {
    const s = stack();
    const input = vaccineInput();
    await s.supplyChain.mint(input, AS.manufacturer);

    await assert.rejects(
      () =>
        s.supplyChain.recordTemperature(
          reading(generateSensorSecret(), {
            binding: input.product_id,
            keyName: 'product_id',
            temperature: 4.0,
            nonce: 'f1b2c3d4',
            sensorId: 'TM-SENSOR-9999',
          }),
          AS.sensor,
        ),
      (err) => {
        assert.equal(err.status, 404, 'the API key was valid; the device is not provisioned');
        return true;
      },
    );
  });

  test('a cold-box reading fans out across every unit in the batch', async () => {
    const s = stack();
    const secret = await provision(s);
    const a = vaccineInput();
    const b = vaccineInput();
    await s.supplyChain.mint(a, AS.manufacturer);
    await s.supplyChain.mint(b, AS.manufacturer);

    const body = await s.supplyChain.recordTemperature(
      reading(secret, {
        binding: a.batch_no,
        keyName: 'batch_no',
        temperature: 11.0,
        nonce: '0a1b2c3d',
      }),
      AS.sensor,
    );

    assert.equal(body.product_id, null, 'a batch reading has no single product');
    assert.equal(body.batch_no, a.batch_no);
    assert.equal(body.units_updated, 2);

    for (const unit of [a, b]) {
      const record = await s.fabric.getMedicine(unit.product_id);
      assert.equal(record.cold_chain_breached, true, `${unit.product_id} missed the breach`);
    }
  });

  test('a reading must bind to exactly one of product_id or batch_no', async () => {
    const s = stack();
    const secret = await provision(s);
    const input = vaccineInput();
    await s.supplyChain.mint(input, AS.manufacturer);

    const both = reading(secret, {
      binding: input.product_id,
      keyName: 'product_id',
      temperature: 4.0,
      nonce: '1a1b2c3d',
    });
    both.batch_no = input.batch_no;

    await assert.rejects(
      () => s.supplyChain.recordTemperature(both, AS.sensor),
      (err) => {
        assert.equal(err.code, CODES.VALIDATION_ERROR);
        return true;
      },
    );

    const neither = { ...both };
    delete neither.product_id;
    delete neither.batch_no;
    await assert.rejects(() => s.supplyChain.recordTemperature(neither, AS.sensor));
  });

  /**
   * §4.7 binds the MAC to whichever key was sent, so a MAC computed over a product
   * id cannot be resubmitted as a reading for the batch of the same name. Without
   * this the two cases would collide into one signed string.
   */
  test('a product-bound MAC cannot be replayed as a batch reading', async () => {
    const s = stack();
    const secret = await provision(s);
    const input = vaccineInput();
    await s.supplyChain.mint(input, AS.manufacturer);

    const signed = reading(secret, {
      binding: input.product_id,
      keyName: 'product_id',
      temperature: 4.0,
      nonce: '2a1b2c3d',
    });

    await assert.rejects(
      () =>
        s.supplyChain.recordTemperature(
          { ...signed, product_id: undefined, batch_no: input.batch_no },
          AS.sensor,
        ),
      (err) => {
        assert.equal(err.code, CODES.UNAUTHORIZED);
        return true;
      },
    );
  });
});

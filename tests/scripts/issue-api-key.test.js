/**
 * The key-issuing script.
 *
 * The thing worth testing here is not that a random string comes out. It is that the
 * credential this script prints is one the *real authenticator* accepts, with the
 * right role and the right scope attached — because the store keeps only a hash, so
 * a key that this script and `middleware/auth.js` disagree about is unrecoverable and
 * indistinguishable from a revoked one. Every happy-path case below therefore ends at
 * `makeAuth`, not at the store.
 *
 * The sensor half is tested the same way: a provisioning that produced a secret
 * `recordTemperature` would not accept is a device that reports a cold-chain breach
 * into a 401, which is exactly the failure nobody notices until the vaccines are
 * already spoiled.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { MemoryStore } from '../../src/db/memory-store.js';
import { MemoryCache } from '../../src/cache/memory.js';
import { MockLedger } from '../../src/fabric/mock-ledger.js';
import { loadConfig } from '../../src/config/index.js';
import { makeAuth, sha256hex } from '../../src/middleware/auth.js';
import { makeSupplyChainService } from '../../src/services/supply-chain.js';
import { SecretBox, sensorContext } from '../../src/utils/secret-box.js';
import { computeSensorMac } from '../../src/utils/sensor-hmac.js';
import { API_KEY_RE, ROLE, ROLES, TYPE } from '../../src/core/rules.js';
import { CODES } from '../../src/core/errors.js';
import {
  generateApiKey,
  issueApiKey,
  parseArgs,
  provisionSensor,
  revokeByHash,
  roleTable,
  validateRoleAndScope,
} from '../../scripts/issue-api-key.js';

const FIXED_NOW = new Date('2026-06-01T10:00:00Z');
const clock = () => FIXED_NOW;

const SCOPE = 'MH/25D/2019/187';

function stack() {
  const config = loadConfig({
    NODE_ENV: 'development',
    FABRIC_MOCK: '1',
    LOG_LEVEL: 'silent',
    TRUST_REQUIRE_SIGNATURE: '0',
  });
  const store = new MemoryStore({ clock });
  const cache = new MemoryCache(config.redis);
  const fabric = new MockLedger({ clock });
  const secrets = new SecretBox(config.secrets.encryptionKey);
  return {
    config,
    store,
    cache,
    fabric,
    secrets,
    supplyChain: makeSupplyChainService({ cache, fabric, store, secrets, clock }),
  };
}

/** Present a key to the real authenticator and report what it made of it. */
async function present(store, key) {
  const { authenticate } = makeAuth({ store });
  const req = { get: (header) => (header === 'X-API-Key' ? key : undefined) };
  let error = null;
  await authenticate(req, null, (err) => {
    error = err ?? null;
  });
  return { auth: req.auth ?? null, error };
}

const vaccine = (productID) => ({
  contract_version: 1,
  product_id: productID,
  generic_name: 'Measles-Rubella Vaccine',
  brand_name: 'Suraksha MR',
  manufacturer: 'Bharat Biologics Pvt Ltd, Plot 9 Peenya, Bengaluru 560058',
  mfg_licence_no: 'KA/25B/2021/044',
  batch_no: 'BB26MR014',
  mfg_date: '2026-05-01',
  expiry_date: '2027-04-30',
  quantity: '1 vial (5 doses)',
  excipients: ['Sorbitol'],
  type: TYPE.VACCINE,
  location: 'FACT_BLR_0007',
});

describe('issuing an API key', () => {
  /**
   * The load-bearing test. Six roles, each issued and then presented to the
   * authenticator the API actually runs — so a divergence between how this script
   * hashes a key and how a request is authenticated cannot pass.
   */
  test('every role gets a key the real authenticator accepts', async () => {
    const s = stack();

    for (const role of ROLES) {
      const scope = role === ROLE.PHARMA ? SCOPE : '';
      const { key, keyHash } = await issueApiKey({ store: s.store, role, scope });

      assert.match(key, API_KEY_RE, `key for ${role} does not match the §4.2 format`);
      assert.ok(key.startsWith(`tm_${role}_`), 'the role must be readable from the key');

      const { auth, error } = await present(s.store, key);
      assert.equal(error, null, `a freshly issued ${role} key was rejected`);
      assert.equal(auth.role, role);
      assert.equal(auth.keyHash, keyHash);
      // §4.4a: the scope the dashboard filters on comes from here and nowhere else.
      assert.equal(auth.scope, scope);
    }
  });

  test('the plaintext key exists nowhere in the stored row', async () => {
    const s = stack();
    const { key, keyHash, row } = await issueApiKey({
      store: s.store,
      role: ROLE.MANUFACTURER,
      label: 'Pune plant',
    });

    assert.equal(
      JSON.stringify(row).includes(key),
      false,
      'the plaintext key was stored, defeating the point of hashing it',
    );
    assert.equal(row.key_hash, keyHash);
    assert.equal(row.key_hash, sha256hex(key));

    // And the row really is the one the authenticator finds.
    const found = await s.store.findApiKey(sha256hex(key));
    assert.equal(found.id, row.id);
  });

  test('two keys for the same role are different keys', async () => {
    const s = stack();
    const a = await issueApiKey({ store: s.store, role: ROLE.DISTRIBUTOR });
    const b = await issueApiKey({ store: s.store, role: ROLE.DISTRIBUTOR });
    assert.notEqual(a.key, b.key);
    assert.notEqual(a.keyHash, b.keyHash);
  });

  /**
   * §4.4a. A blank scope would filter the pharma dashboard on '' and match nothing,
   * so the manufacturer sees an empty board and concludes they have no stock — the
   * misissued key never enters their mind. Refusing at issue time is the only place
   * this is cheap to notice.
   */
  test('a pharma key without a scope is refused', async () => {
    const s = stack();
    await assert.rejects(
      () => issueApiKey({ store: s.store, role: ROLE.PHARMA }),
      /scope/,
    );
    await assert.rejects(
      () => issueApiKey({ store: s.store, role: ROLE.PHARMA, scope: '   ' }),
      /scope/,
    );
  });

  /**
   * Nothing reads the scope of a non-pharma key, so accepting one would hand over a
   * credential the operator believes is confined to a licence and is not.
   */
  test('a scope on any other role is refused rather than ignored', async () => {
    const s = stack();
    for (const role of ROLES.filter((r) => r !== ROLE.PHARMA)) {
      await assert.rejects(
        () => issueApiKey({ store: s.store, role, scope: SCOPE }),
        /only meaningful for the pharma role/,
      );
    }
  });

  test('an unknown role is refused and the message lists the real ones', async () => {
    const s = stack();
    await assert.rejects(
      // The one-letter trap this project has already been bitten by.
      () => issueApiKey({ store: s.store, role: 'pharmacies' }),
      (err) => {
        assert.match(err.message, /unknown role/);
        for (const role of ROLES) assert.match(err.message, new RegExp(role));
        return true;
      },
    );
  });

  test('a generated key always satisfies the format the rest of the system matches', () => {
    for (const role of ROLES) {
      for (let i = 0; i < 25; i += 1) {
        const key = generateApiKey(role);
        assert.match(key, API_KEY_RE);
        assert.equal(key.length, `tm_${role}_`.length + 32);
      }
    }
  });

  test('validateRoleAndScope trims a scope and returns it', () => {
    assert.equal(validateRoleAndScope(ROLE.PHARMA, `  ${SCOPE}  `), SCOPE);
    assert.equal(validateRoleAndScope(ROLE.REGULATOR, ''), '');
  });

  test('every role is listed with what it is for', () => {
    const table = roleTable();
    assert.equal(table.length, ROLES.length);
    for (const entry of table) {
      assert.ok(ROLES.includes(entry.role));
      // `pharma` and `pharmacy` differ by one letter and by everything else, so a
      // tool that prints the list without the meanings is a tool that gets misread.
      assert.ok(entry.purpose && entry.purpose.length > 10, `${entry.role} has no purpose text`);
    }
  });
});

describe('revoking a key', () => {
  test('a revoked key stops authenticating', async () => {
    const s = stack();
    const { key, keyHash } = await issueApiKey({ store: s.store, role: ROLE.PHARMACY });

    assert.equal((await present(s.store, key)).error, null);

    assert.equal(await revokeByHash({ store: s.store, keyHash }), true);

    const after = await present(s.store, key);
    assert.ok(after.error, 'a revoked key still authenticated');
    assert.equal(after.error.code, CODES.UNAUTHORIZED);
  });

  test('revoking the same hash twice reports that nothing was live', async () => {
    const s = stack();
    const { keyHash } = await issueApiKey({ store: s.store, role: ROLE.PHARMACY });
    assert.equal(await revokeByHash({ store: s.store, keyHash }), true);
    assert.equal(await revokeByHash({ store: s.store, keyHash }), false);
  });

  /**
   * Revocation takes the hash precisely so that no credential is ever typed on a
   * command line, where `ps` and shell history can read it. Passing the key itself
   * must fail rather than quietly work, or the safe interface is optional.
   */
  test('revocation refuses a key where a hash belongs', async () => {
    const s = stack();
    const { key } = await issueApiKey({ store: s.store, role: ROLE.PHARMACY });
    await assert.rejects(() => revokeByHash({ store: s.store, keyHash: key }), /64 hex/);
  });

  test('an uppercase hash still revokes', async () => {
    const s = stack();
    const { keyHash } = await issueApiKey({ store: s.store, role: ROLE.REGULATOR });
    assert.equal(await revokeByHash({ store: s.store, keyHash: keyHash.toUpperCase() }), true);
  });
});

describe('provisioning a sensor', () => {
  /**
   * The end-to-end claim: a device flashed with what this script printed can post a
   * reading that §4.7 accepts. Everything in between — sealing, the AEAD context,
   * the MAC field order, the two-decimal temperature — has to line up for this to
   * pass, and each of those is a place where a plausible mistake produces a device
   * that authenticates and then has every reading rejected.
   */
  test('a reading built with the printed secret is accepted', async () => {
    const s = stack();
    const productID = 'MEASLESRUBELLA_SURAKSHAMR_2026_000101';
    await s.supplyChain.mint(vaccine(productID), { role: ROLE.MANUFACTURER });

    const sensor = await provisionSensor({
      store: s.store,
      secrets: s.secrets,
      sensorId: 'TM-SENSOR-PUN01',
      label: 'cold box',
    });

    const recordedAt = '2026-06-01T09:55:00Z';
    const parts = {
      binding: productID,
      sensorId: sensor.sensorId,
      temperature: 4.25,
      recordedAt,
      nonce: 'a1b2c3d4e5f60789',
    };
    const out = await s.supplyChain.recordTemperature(
      {
        product_id: productID,
        sensor_id: sensor.sensorId,
        temperature: parts.temperature,
        recorded_at: recordedAt,
        nonce: parts.nonce,
        hmac: computeSensorMac(sensor.secret, parts),
      },
      { role: ROLE.SENSOR },
    );

    assert.equal(out.sensor_id, sensor.sensorId);
    assert.equal(out.chain_ok, true);
    assert.equal(out.reading_count, 1);
  });

  test('the secret is sealed at rest and bound to its sensor id', async () => {
    const s = stack();
    const sensor = await provisionSensor({
      store: s.store,
      secrets: s.secrets,
      sensorId: 'TM-SENSOR-PUN01',
    });

    const row = await s.store.getSensor(sensor.sensorId);
    assert.ok(Buffer.isBuffer(row.secret_enc));
    assert.equal(
      row.secret_enc.includes(Buffer.from(sensor.secret, 'utf8')),
      false,
      'the sensor secret was stored in the clear',
    );
    assert.equal(s.secrets.open(row.secret_enc, sensorContext(sensor.sensorId)), sensor.secret);

    // A row copied onto another device's record must fail to open rather than
    // authenticate as that device.
    assert.throws(() => s.secrets.open(row.secret_enc, sensorContext('TM-SENSOR-PUN02')));
  });

  /**
   * `store.insertSensor` overwrites silently, so without this guard a mistyped
   * sensor id would rotate a deployed device's secret and every reading it sent
   * afterwards would be rejected as a bad MAC — indistinguishable, from the office,
   * from a hardware fault.
   */
  test('re-provisioning is refused unless rotation is explicit', async () => {
    const s = stack();
    const first = await provisionSensor({
      store: s.store,
      secrets: s.secrets,
      sensorId: 'TM-SENSOR-PUN01',
    });
    assert.equal(first.rotated, false);

    await assert.rejects(
      () => provisionSensor({ store: s.store, secrets: s.secrets, sensorId: 'TM-SENSOR-PUN01' }),
      /already provisioned/,
    );

    const rotated = await provisionSensor({
      store: s.store,
      secrets: s.secrets,
      sensorId: 'TM-SENSOR-PUN01',
      rotate: true,
    });
    assert.equal(rotated.rotated, true);
    assert.notEqual(rotated.secret, first.secret);
  });

  test('a malformed sensor id is refused', async () => {
    const s = stack();
    await assert.rejects(() =>
      provisionSensor({ store: s.store, secrets: s.secrets, sensorId: 'coldbox-1' }),
    );
  });
});

describe('argument parsing', () => {
  test('a flag and its value may be separated or joined', () => {
    const a = parseArgs(['--role', 'pharma', '--scope', SCOPE]);
    const b = parseArgs([`--role=pharma`, `--scope=${SCOPE}`]);
    assert.deepEqual(a, b);
    assert.equal(a.role, 'pharma');
    assert.equal(a.scope, SCOPE);
  });

  /**
   * A swallowed typo is the dangerous case: `--scoped MH/...` accepted and ignored
   * would issue an unconfined pharma key while the operator believed otherwise.
   */
  test('an unknown flag is an error, not something to ignore', () => {
    assert.throws(() => parseArgs(['--role', 'pharma', '--scoped', SCOPE]), /unknown option/);
  });

  test('a flag whose value is missing does not swallow the next flag', () => {
    assert.throws(() => parseArgs(['--role', '--json']), /needs a value/);
    assert.throws(() => parseArgs(['--revoke']), /needs a value/);
  });

  test('the boolean flags parse', () => {
    const args = parseArgs(['--list-roles', '--json', '--rotate-sensor']);
    assert.equal(args.listRoles, true);
    assert.equal(args.json, true);
    assert.equal(args.rotate, true);
    assert.equal(args.role, null);
  });

  test('nothing is a secret-bearing flag', () => {
    // The absence being asserted: there is no way to pass a key, a password or a
    // sensor secret in, because argv is readable by every local user via `ps`.
    for (const flag of ['--key', '--secret', '--password', '--api-key', '--sensor-secret']) {
      assert.throws(() => parseArgs([flag, 'anything']), /unknown option/, `${flag} was accepted`);
    }
  });

  test('a revoke hash is carried through', () => {
    const hash = 'a'.repeat(64);
    assert.equal(parseArgs(['--revoke', hash]).revoke, hash);
  });
});

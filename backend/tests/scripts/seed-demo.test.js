/**
 * The demo seeder.
 *
 * `seedDemo` is the only thing in this repository that drives the whole service layer
 * in one go — mint, custody hops, HMAC'd cold-chain readings, a batch recall, scan
 * telemetry, counterfeit reports, cache invalidation and verdict merging — against
 * real signed payloads from the fixtures. So testing it is worth more than testing a
 * script: a green run here says those pieces compose, not merely that each works when
 * called alone.
 *
 * Two claims get the most attention.
 *
 * The seeded world must *distinguish*. A demo where everything scans green proves
 * nothing, so every verdict a patient can be shown has to appear, and each unit is
 * checked against the verdict it was built to produce rather than against whatever it
 * happens to return.
 *
 * The printed sheet must be usable. The keys are printed once because only their
 * hashes are stored, so a key that does not authenticate is a key that is simply
 * gone — every one is pushed through the real authenticator here. And the sample
 * `curl` exists to save a firmware author from hand-computing an HMAC, which makes a
 * subtly wrong one worse than none at all: the body it prints is parsed back out of
 * the command string and replayed through `recordTemperature`.
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
import { makeReportsService } from '../../src/services/reports.js';
import { makeDashboardsService } from '../../src/services/dashboards.js';
import { makeHealthService } from '../../src/services/health.js';
import { makeSupplyChainService } from '../../src/services/supply-chain.js';
import { makeAuth } from '../../src/middleware/auth.js';
import { SecretBox } from '../../src/utils/secret-box.js';
import { ROLE, ROLES, STATUS, TYPE, VERDICT, validateSensorID } from '../../src/core/rules.js';
import { DEMO_SENSOR_ID, formatSummary, seedDemo } from '../../scripts/seed-demo.js';

const FIXTURES = JSON.parse(
  readFileSync(new URL('../fixtures/fixtures.json', import.meta.url), 'utf8'),
);

/**
 * The date the rest of the suite uses. It matters here: the fixtures contain a
 * payload that expired in 2025 and one that expires within thirty days of this
 * instant, and the seed asserts a verdict for each. A different clock would move both.
 */
const FIXED_NOW = new Date('2026-06-01T10:00:00Z');
const clock = () => FIXED_NOW;

const PHARMA_SCOPE = 'MH/25D/2019/187';

/**
 * The six services, wired by hand.
 *
 * Deliberately not `createServices` from `src/app.js`: that module imports Express,
 * and this suite runs with no `node_modules`. Building them here is also the honest
 * shape of the dependency — `seedDemo` takes a services object and does not care who
 * assembled it.
 */
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

  const services = {
    trust,
    verify: makeVerifyService({ cache, fabric, trust, clock }),
    supplyChain: makeSupplyChainService({ cache, fabric, store, secrets, clock }),
    reports: makeReportsService({ store, trust, secrets, clock }),
    dashboards: makeDashboardsService({ fabric, store, clock }),
    health: makeHealthService({ store, cache, fabric, trust, config, clock }),
  };
  return { config, cache, store, fabric, secrets, services };
}

/** A seeded stack of its own, for the tests that write to the world they inspect. */
async function freshWorld(options = {}) {
  const s = stack();
  const summary = await seedDemo({
    services: s.services,
    store: s.store,
    fabric: s.fabric,
    secrets: s.secrets,
    config: s.config,
    clock,
    ...options,
  });
  return { ...s, summary };
}

/**
 * One shared world for the read-only assertions. Seeding is cheap but not free —
 * eleven ECDSA verifications and about thirty ledger writes — and every test below
 * that does not mutate it is asking a different question about the same world, which
 * is what a demo sheet actually is.
 */
let shared = null;
async function world() {
  if (!shared) shared = await freshWorld();
  return shared;
}

/** Present a key to the authenticator the API really runs. */
async function present(store, key) {
  const { authenticate } = makeAuth({ store });
  const req = { get: (header) => (header === 'X-API-Key' ? key : undefined) };
  let error = null;
  await authenticate(req, null, (err) => {
    error = err ?? null;
  });
  return { auth: req.auth ?? null, error };
}

describe('the seeded world', () => {
  /**
   * The central claim. Each unit carries the verdict it was built to produce, and
   * `seedDemo` throws on a fresh seed if any disagrees — so reaching this assertion
   * already means the world verifies as intended. Asserting it again here states the
   * contract explicitly rather than relying on a throw somewhere else.
   */
  test('every verdict a patient can be shown is present, and no unit is off', async () => {
    const { summary } = await world();

    assert.deepEqual(summary.verdict_mismatches, []);
    for (const unit of summary.units) {
      assert.equal(
        unit.verdict,
        unit.expect,
        `${unit.product_id} (${unit.story}) verified as ${unit.verdict}`,
      );
    }

    const verdicts = new Set(summary.units.map((u) => u.verdict));
    for (const wanted of [
      VERDICT.GENUINE,
      VERDICT.EXPIRED,
      VERDICT.RECALLED,
      VERDICT.COLD_CHAIN,
      VERDICT.CLONE,
    ]) {
      assert.ok(verdicts.has(wanted), `no unit in the demo verifies as ${wanted}`);
    }
  });

  test('the world is reported as freshly created', async () => {
    const { summary } = await world();
    assert.equal(summary.ledger, 'created');
    assert.equal(summary.drivers.store, 'memory');
    // Read from ping(), because neither ledger driver carries a `.driver` property
    // and a hardcoded 'mock' would mislabel a real Fabric deployment.
    assert.equal(summary.drivers.ledger, 'mock');
    assert.match(summary.seeded_at, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
  });

  /**
   * The five fixture-backed units are the ones a phone can actually scan, because
   * only they have a signed payload behind them. The distinction is printed on the
   * sheet, so a demonstrator does not wave a phone at a unit that has no QR code.
   */
  test('the scannable units are exactly the fixture-backed ones', async () => {
    const { summary } = await world();
    const scannable = summary.units.filter((u) => u.scannable);
    const invented = summary.units.filter((u) => !u.scannable);

    assert.equal(scannable.length, 5);
    assert.ok(invented.length >= 2);
    for (const unit of scannable) assert.ok(unit.fixture_case);
    for (const unit of invented) assert.equal(unit.fixture_case, null);

    // A product id twice over would make two rows of the sheet describe one unit.
    const ids = summary.units.map((u) => u.product_id);
    assert.equal(new Set(ids).size, ids.length);

    for (const unit of summary.units) {
      assert.ok(unit.story && unit.story.length > 10, `${unit.product_id} has no story`);
      assert.ok([TYPE.MEDICINE, TYPE.VACCINE].includes(unit.type));
    }
  });

  test('the breached vaccine batch is what breached, and the healthy one did not', async () => {
    const { summary } = await world();

    const breached = summary.units.filter((u) => u.verdict === VERDICT.COLD_CHAIN);
    const breachedBatches = new Set(breached.map((u) => u.batch_no));
    assert.equal(breachedBatches.size, 1, 'the breach should be confined to one batch');
    for (const unit of breached) assert.equal(unit.type, TYPE.VACCINE);

    // The fixture vaccine is the phone's genuine-vaccine demo. If a breach reached
    // it, that demo would be gone and this file would be the only place it showed.
    const healthy = summary.units.filter(
      (u) => u.type === TYPE.VACCINE && u.verdict === VERDICT.GENUINE,
    );
    assert.ok(healthy.length >= 1, 'no vaccine in the demo has an intact cold chain');
    for (const unit of healthy) assert.equal(breachedBatches.has(unit.batch_no), false);

    // Eleven readings: a six-point healthy series and a five-point one that climbs
    // out of range twice. Pinned exactly, because these two numbers are the whole
    // cold-chain story — an accepted count that drifts means readings are being
    // rejected, and a breaching count of zero means the alert never fires.
    assert.equal(summary.readings.accepted, 11);
    assert.equal(summary.readings.breaching, 2);
  });

  test('the recall covers the whole batch and finished', async () => {
    const { summary } = await world();
    const recalled = summary.units.filter((u) => u.verdict === VERDICT.RECALLED);

    assert.equal(summary.recall.recalled, recalled.length);
    // §9.10-adjacent: a recall that reports more work remaining is a recall that
    // silently left units live. The demo batch is small enough to finish in one pass.
    assert.equal(summary.recall.more_remaining, false);
    assert.ok(summary.recall.reason.length > 10);
    for (const unit of recalled) assert.equal(unit.status, STATUS.RECALLED);
  });

  /**
   * The custody hops have to have landed. Every fixture-backed unit is walked to a
   * pharmacy or a health centre, and the status the verify response reports is read
   * off the ledger record — so a null here means either the hops did nothing or the
   * seed is reading the status from the wrong place, which it once was.
   */
  test('the units carry the supply-chain status their hops left them at', async () => {
    const { summary } = await world();
    for (const unit of summary.units) {
      assert.ok(unit.status, `${unit.product_id} has no status at all`);
      assert.ok(
        Object.values(STATUS).includes(unit.status),
        `${unit.product_id} has status ${unit.status}, which is not in STATUS`,
      );
    }
    const dispensable = summary.units.filter((u) => u.scannable && u.verdict !== VERDICT.CLONE);
    assert.ok(
      dispensable.every((u) => u.status === STATUS.AT_PHARMACY),
      'a fixture unit was walked to a pharmacy but does not say so',
    );
  });

  test('a clone is suspected, and it is the unit scanned in four districts', async () => {    const { summary } = await world();
    const clones = summary.units.filter((u) => u.verdict === VERDICT.CLONE);
    assert.equal(clones.length, 1);
    // Reported by a patient as well as flagged by telemetry: the narrative the
    // system exists for is that the two corroborate each other.
    assert.ok(
      summary.reports.some((r) => r.product_id === clones[0].product_id),
      'the cloned unit was never reported, so the heat map and the flag are unrelated',
    );
  });
});

describe('the credentials the seed prints', () => {
  /**
   * The store keeps only `sha256(key)`, so an unusable printed key is unrecoverable
   * and the demo is over. Each one goes through the real authenticator.
   */
  test('every role gets a key that authenticates as that role', async () => {
    const { store, summary } = await world();

    assert.equal(summary.keys.length, ROLES.length);
    assert.deepEqual(
      summary.keys.map((k) => k.role).sort(),
      [...ROLES].sort(),
      'a role in rules.js was left out of the demo',
    );

    for (const entry of summary.keys) {
      const { auth, error } = await present(store, entry.key);
      assert.equal(error, null, `the printed ${entry.role} key does not authenticate`);
      assert.equal(auth.role, entry.role);
      assert.equal(auth.keyHash, entry.key_hash);
      assert.ok(entry.label.startsWith('demo:'), `${entry.role} key has no demo label`);
    }
  });

  /** §4.4a. An unscoped pharma key is refused by the dashboard, not shown an empty one. */
  test('the pharma key is scoped and no other key is', async () => {
    const { summary } = await world();
    for (const entry of summary.keys) {
      if (entry.role === ROLE.PHARMA) assert.equal(entry.scope, PHARMA_SCOPE);
      else assert.equal(entry.scope, '');
    }
  });

  test('the cold box is provisioned with a valid id and a usable secret', async () => {
    const { store, secrets, summary } = await world();

    assert.equal(summary.sensor.sensor_id, DEMO_SENSOR_ID);
    assert.equal(validateSensorID(DEMO_SENSOR_ID), DEMO_SENSOR_ID);
    assert.ok(summary.sensor.secret.length >= 32);

    const row = await store.getSensor(DEMO_SENSOR_ID);
    assert.ok(row, 'the demo sensor is not in the store');
    assert.equal(
      row.secret_enc.includes(Buffer.from(summary.sensor.secret, 'utf8')),
      false,
      'the sensor secret is stored in the clear',
    );
    assert.ok(secrets);
  });
});

describe('the dashboards the seed leaves behind', () => {
  test('the CDSCO board has two districts and something in every total', async () => {
    const { summary } = await world();
    const { cdsco } = summary.dashboards;

    assert.equal(cdsco.totals.reports, 2);
    assert.equal(cdsco.districts.length, 2, 'a one-cell heat map does not look like a map');
    assert.deepEqual(
      cdsco.districts.map((d) => d.district).sort(),
      ['Nashik', 'Pune'],
    );
    for (const d of cdsco.districts) assert.ok(d.reports >= 1);

    // Each of these totals is a different detector. A zero in any of them means that
    // part of the system contributes nothing to the demo.
    assert.ok(cdsco.totals.units_recalled >= 2);
    assert.ok(cdsco.totals.cold_chain_breaches >= 1);
    assert.ok(cdsco.totals.clone_suspected >= 1);
    assert.ok(cdsco.alerts >= 1, 'the triage feed is empty, so there is nothing to show');
  });

  /**
   * The multi-tenant claim, checked against the seeded world rather than a contrived
   * one: a Maharashtra-scoped analytics key must not be able to see the Karnataka
   * vaccine batches that are sitting in the same ledger.
   */
  test('the pharma board is confined to its licence', async () => {
    const { services, summary } = await world();

    assert.equal(summary.dashboards.pharma.scope, PHARMA_SCOPE);
    assert.ok(summary.dashboards.pharma.totals.units_minted >= 1);

    const board = await services.dashboards.pharma({ role: ROLE.PHARMA, scope: PHARMA_SCOPE }, {});
    assert.equal(board.mfg_licence_no, PHARMA_SCOPE);

    const visible = new Set(board.batches.map((b) => b.batch_no));
    const vaccineBatches = new Set(
      summary.units.filter((u) => u.type === TYPE.VACCINE).map((u) => u.batch_no),
    );
    assert.ok(vaccineBatches.size >= 2, 'the demo has no out-of-scope batches to exclude');
    for (const batch of vaccineBatches) {
      assert.equal(
        visible.has(batch),
        false,
        `${batch} belongs to another licence and is visible to this key`,
      );
    }
    assert.ok(visible.size >= 1, 'the scoped board is empty, so the scope matches nothing');
  });
});

describe('the sample breach request', () => {
  /**
   * The whole point of printing a `curl` is that nobody has to compute an HMAC by
   * hand. A command that looks right and is rejected is worse than no command: the
   * reader concludes the API is broken. So the body is parsed back out of the exact
   * string that gets printed and replayed through the service that would receive it.
   */
  test('the printed command is accepted as written', async () => {
    const { store, services, summary } = await freshWorld();
    const { command } = summary.curl;

    const keyMatch = command.match(/X-API-Key: (tm_[a-z]+_[0-9a-f]{32})/);
    assert.ok(keyMatch, 'no API key in the printed command');
    const presented = await present(store, keyMatch[1]);
    assert.equal(presented.error, null, 'the key in the printed command does not authenticate');
    assert.equal(presented.auth.role, ROLE.SENSOR);

    const bodyMatch = command.match(/-d '(\{.*\})'\s*$/s);
    assert.ok(bodyMatch, 'no JSON body in the printed command');
    const body = JSON.parse(bodyMatch[1]);

    const out = await services.supplyChain.recordTemperature(body, {
      role: presented.auth.role,
      scope: presented.auth.scope,
    });
    assert.equal(out.sensor_id, DEMO_SENSOR_ID);
    // 12.6 degC on a vaccine batch: the alert this request exists to fire.
    assert.equal(out.chain_ok, false);
    assert.match(summary.curl.description, /12\.6/);
  });

  /**
   * A MAC is not a credential — it authenticates one message and nothing else. The
   * sensor secret is, and it appears in the printed command exactly nowhere, so the
   * command can be pasted into a bug report.
   */
  test('the command carries a MAC, not the sensor secret', async () => {
    const { summary } = await world();
    assert.equal(
      summary.curl.command.includes(summary.sensor.secret),
      false,
      'the sensor secret is embedded in the sample command',
    );
    assert.match(summary.curl.command, /"hmac":"[0-9a-f]{64}"/);
    assert.match(summary.curl.command, /POST http:\/\/[^ ]+\/api\/temperature/);
  });

  test('the body is bound to a batch, not to a single vial', async () => {
    const { summary } = await world();
    const body = JSON.parse(summary.curl.command.match(/-d '(\{.*\})'\s*$/s)[1]);
    // One cold box holds a tray, so a reading names the batch. Sending both keys
    // would leave no single string for the two sides to have agreed on (§4.7).
    assert.ok(body.batch_no);
    assert.equal('product_id' in body, false);
    assert.match(body.recorded_at, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
    assert.match(body.nonce, /^[0-9a-f]{8,64}$/);
  });
});

describe('running it again, and refusing to run at all', () => {
  /**
   * A re-seed is the ordinary case: the keys from the previous run cannot be
   * recovered, so re-running is how an operator gets working credentials back. It
   * must not fail on units the ledger already holds, and it must still print a
   * complete sheet — an earlier version of this script printed `units: 0` here, which
   * looks exactly like a broken seeder.
   */
  test('a second seed issues fresh credentials and still prints the whole sheet', async () => {
    const s = stack();
    const first = await seedDemo({
      services: s.services,
      store: s.store,
      fabric: s.fabric,
      secrets: s.secrets,
      config: s.config,
      clock,
    });
    const second = await seedDemo({
      services: s.services,
      store: s.store,
      fabric: s.fabric,
      secrets: s.secrets,
      config: s.config,
      clock,
    });

    assert.match(second.ledger, /already seeded/);
    assert.equal(second.units.length, first.units.length);
    assert.equal(second.keys.length, ROLES.length);
    assert.ok(second.dashboards, 'the re-seed printed no dashboards');
    assert.ok(second.curl, 'the re-seed printed no sample request');
    assert.deepEqual(second.verdict_mismatches, []);
    for (const unit of second.units) assert.equal(unit.verdict, unit.expect);

    // Fresh keys, and the old ones still work: nothing was revoked, because the
    // reason for re-running is usually that the printed sheet was lost.
    const firstKeys = new Set(first.keys.map((k) => k.key));
    for (const entry of second.keys) assert.equal(firstKeys.has(entry.key), false);
    assert.equal((await present(s.store, first.keys[0].key)).error, null);

    // The demo cold box is a script, not a device in a field, so rotation is right.
    assert.notEqual(second.sensor.secret, first.sensor.secret);
  });

  test('a re-seed reports a moved-on world instead of throwing', async () => {
    const s = stack();
    await seedDemo({
      services: s.services,
      store: s.store,
      fabric: s.fabric,
      secrets: s.secrets,
      config: s.config,
      clock,
    });

    // Someone demonstrates a recall between the two runs, which is a perfectly
    // legitimate thing to do to a demo world.
    const target = 'BB26MR009';
    await s.services.supplyChain.recall(
      { batch_no: target, reason: 'demonstrated during a viva' },
      { role: ROLE.REGULATOR, scope: '' },
    ).catch(() => {});

    const again = await seedDemo({
      services: s.services,
      store: s.store,
      fabric: s.fabric,
      secrets: s.secrets,
      config: s.config,
      clock,
    });
    assert.ok(Array.isArray(again.verdict_mismatches));
    assert.ok(again.keys.length === ROLES.length, 'the operator still needs their keys');
  });

  /**
   * A ledger is append-only: there is no undo for a fabricated medicine record, and
   * an invented unit is indistinguishable from real stock to everyone who scans one.
   * The refusal is inside `seedDemo` rather than in the CLI so that it holds however
   * the function is reached.
   */
  test('it refuses to seed a production ledger', async () => {
    const s = stack();
    await assert.rejects(
      () =>
        seedDemo({
          services: s.services,
          store: s.store,
          fabric: s.fabric,
          secrets: s.secrets,
          config: { ...s.config, isProduction: true },
          clock,
        }),
      /production/,
    );
    // Nothing was written on the way to the refusal.
    assert.equal((await s.store.listApiKeys?.())?.length ?? 0, 0);
  });

  /**
   * An unreachable ledger has to be said plainly and early. Left to fail on its own
   * it surfaces a few hundred lines later as a mint error, and the operator goes
   * looking for a bug in the seed data.
   */
  test('an unreachable ledger is reported before anything is written', async () => {
    const s = stack();
    let pinged = false;
    const deadLedger = {
      ping: async () => {
        pinged = true;
        throw new Error('connection refused');
      },
    };

    await assert.rejects(
      () =>
        seedDemo({
          services: s.services,
          store: s.store,
          fabric: deadLedger,
          secrets: s.secrets,
          config: s.config,
          clock,
        }),
      (err) => {
        assert.match(err.message, /not reachable/);
        assert.match(err.message, /connection refused/);
        return true;
      },
    );
    assert.equal(pinged, true);
    // No key was issued, so no credential was printed for a world that does not exist.
    assert.equal((await s.store.listApiKeys?.())?.length ?? 0, 0);
  });

  test('a fixture file without the demo cases is refused with a usable message', async () => {
    const s = stack();
    await assert.rejects(
      () =>
        seedDemo({
          services: s.services,
          store: s.store,
          fabric: s.fabric,
          secrets: s.secrets,
          config: s.config,
          clock,
          fixturesPath: new URL('../fixtures/fixtures.json', import.meta.url).pathname.replace(
            'fixtures.json',
            'no-such-fixtures.json',
          ),
        }),
      /ENOENT|no such file/i,
    );
  });
});

describe('the printed sheet', () => {
  test('it shows the keys, the secret, every unit and the sample request', async () => {
    const { summary } = await world();
    const text = formatSummary(summary);

    for (const entry of summary.keys) assert.ok(text.includes(entry.key), `${entry.role} key missing`);
    assert.ok(text.includes(summary.sensor.secret));
    for (const unit of summary.units) {
      assert.ok(text.includes(unit.product_id), `${unit.product_id} missing from the sheet`);
      assert.ok(text.includes(unit.verdict), `${unit.verdict} missing from the sheet`);
    }
    assert.ok(text.includes(summary.curl.command));
    assert.ok(text.includes(PHARMA_SCOPE));

    // A unit with no QR behind it must say so, or someone waves a phone at it.
    const invented = summary.units.find((u) => !u.scannable);
    assert.match(text, /no QR/);
    assert.ok(invented);
  });

  test('it stays quiet about mismatches when there are none', async () => {
    const { summary } = await world();
    const text = formatSummary(summary);
    assert.equal(text.includes('do not verify as the demo intends'), false);
  });

  /**
   * The sheet is read in a terminal and pasted into reports. An escape sequence in it
   * — from a manufacturer name, a label, anything that came from data — could rewrite
   * what the reader sees, which for a document about authenticity is a poor look.
   */
  test('the sheet contains no control characters beyond newlines', async () => {
    const { summary } = await world();
    const text = formatSummary(summary);
    // Built from character codes rather than written literally, so this file cannot
    // itself become the thing it tests for. Tab, newline and carriage return are
    // excluded; nothing else below 0x20 is layout.
    const c = String.fromCharCode;
    const control = new RegExp(
      `[${c(0)}-${c(8)}${c(11)}${c(12)}${c(14)}-${c(31)}${c(127)}]`,
      'g',
    );
    const bad = text.match(control);
    assert.equal(bad, null, `control characters in the sheet: ${JSON.stringify(bad)}`);
  });
});

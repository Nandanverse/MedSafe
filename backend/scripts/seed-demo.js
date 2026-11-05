/**
 * Seed a demonstrable TrueMed world: keys for every role, a provisioned cold box,
 * and units that answer every verdict a patient can be shown.
 *
 *     SEED_DEMO=1 npm start     # mock stack: the only way that works (see below)
 *     npm run seed              # a real PostgreSQL + Fabric deployment
 *     npm run seed -- --ephemeral   # exercise the seeder itself and throw it away
 *
 * ## What it builds, and why each piece is there
 *
 * A demo that only shows a green tick proves nothing: the interesting claim is that
 * the system *distinguishes*. So the seeded world contains one unit for each verdict
 * the app can render — GENUINE, EXPIRED, RECALLED, COLD_CHAIN_BREACH and
 * CLONE_SUSPECTED — plus a counterfeit report so the CDSCO heat map has a district
 * on it and the pharma dashboard has something to total.
 *
 * Five of those units are minted **from the signed payloads in the test fixtures**,
 * and that is the most important decision in this file. Those payloads were signed
 * by the fixture root, whose bundle is what `scripts/make-dev-keys.js` writes into
 * `keys/` and what `mobile/assets/trust_bundle.json` already ships. So the QR codes
 * printed from the fixtures scan as GENUINE (and EXPIRED, for the metformin) on a
 * real phone, offline, and again against this API online — one trust root end to
 * end. Minting invented product data instead would produce a world that the server
 * likes and every scan from the app rejects, which is an afternoon lost to a
 * mystery.
 *
 * The two things the fixtures cannot supply are minted synthetically: a second
 * vaccine batch to breach (breaching the fixture vaccine would break the phone's
 * genuine-vaccine demo) and a batch to recall. Neither needs a signature, because
 * `GET /api/verify/:product_id` reads the ledger and never checks one — signatures
 * are checked on the payload path, and only there.
 *
 * ## Why it verifies its own work
 *
 * Each unit declares the verdict it is supposed to produce, and the seed reads every
 * unit back through the real verify service and fails if any answer differs. That
 * makes this script an end-to-end check of the entire service layer — mint, custody,
 * HMAC'd readings, recall, scan telemetry, cache invalidation and verdict merging —
 * and it means the failure mode is a loud error here rather than a demo that shows
 * the wrong colour to an examiner.
 *
 * ## Why seeding the mock stack must happen inside the server
 *
 * With `FABRIC_MOCK=1` the ledger, the database and the cache are plain objects in
 * one process, and `MockLedger` has no file behind it. Anything this script writes as
 * a separate process disappears the moment it exits. There is no fixing that from
 * out here, so the CLI refuses in mock mode and points at `SEED_DEMO=1 npm start`,
 * where `server.js` calls `seedDemo` against the very stack it is about to serve.
 * `--ephemeral` exists for the one honest use of an out-of-process mock run:
 * exercising the seeder itself.
 *
 * ## Why the keys are printed
 *
 * The store keeps only `sha256(key)`, so a demo key that is not printed is a demo
 * key that is lost. They go to the returned summary and to stdout, never through the
 * logger — a credential in a log sink outlives every rotation policy. Everything
 * here is disposable by construction anyway: on the mock stack it lives and dies
 * with the process, and `seedDemo` refuses to run in production at all.
 */

import { randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { ROLE, ROLES, STATUS, TYPE, VERDICT } from '../src/core/rules.js';
import { computeSensorMac } from '../src/utils/sensor-hmac.js';
import { verifyWire } from '../src/core/verifier.js';
import { CODES } from '../src/core/errors.js';
import { issueApiKey, provisionSensor } from './issue-api-key.js';

const BACKEND_ROOT = fileURLToPath(new URL('../', import.meta.url));

export const DEFAULT_FIXTURES_PATH = path.join(
  BACKEND_ROOT,
  'tests',
  'fixtures',
  'fixtures.json',
);

/** The one cold box in the demo world. */
export const DEMO_SENSOR_ID = 'TM-SENSOR-DEMO01';

/**
 * What each demo key is for. Keyed by role and iterated from `ROLES`, so a role
 * added to `rules.js` still gets a key rather than being quietly left out of the
 * demo — the fallback label is deliberately obvious enough to notice.
 */
const KEY_LABELS = Object.freeze({
  [ROLE.MANUFACTURER]: 'demo: Sanjeevani Pharma, Pune plant',
  [ROLE.DISTRIBUTOR]: 'demo: Maharashtra Medical Distributors, Bhiwandi hub',
  [ROLE.PHARMACY]: 'demo: Shree Medical Stores, Kothrud',
  [ROLE.SENSOR]: `demo: cold box ${DEMO_SENSOR_ID}`,
  [ROLE.REGULATOR]: 'demo: CDSCO drug inspector, Pune division',
  [ROLE.PHARMA]: 'demo: Sanjeevani Pharma analytics',
});

/**
 * The licence a `pharma` key is scoped to (§4.4a). It is the fixture medicine
 * licence, so the scoped dashboard has the seeded Maharashtra stock on it and
 * demonstrably lacks the Karnataka vaccine.
 */
const PHARMA_SCOPE = 'MH/25D/2019/187';

const AUTH = Object.freeze({
  manufacturer: { role: ROLE.MANUFACTURER, scope: '' },
  distributor: { role: ROLE.DISTRIBUTOR, scope: '' },
  pharmacy: { role: ROLE.PHARMACY, scope: '' },
  sensor: { role: ROLE.SENSOR, scope: '' },
  regulator: { role: ROLE.REGULATOR, scope: '' },
});

/**
 * The five fixture-backed units. `expect` is the verdict the seeded world must
 * produce for each, and it is asserted rather than assumed.
 */
const FIXTURE_UNITS = Object.freeze([
  {
    fixtureCase: 'genuine_medicine_offline',
    mintLocation: 'FACT_PUN_0001',
    hops: [
      { location: 'WARE_BHI_0002', status: STATUS.IN_TRANSIT, as: 'distributor' },
      { location: 'PHAR_PUN_0011', status: STATUS.AT_PHARMACY, as: 'pharmacy' },
    ],
    // Two scans from one district. Deliberately one district: clone suspicion trips
    // on more than three, and the point of this unit is that it stays GENUINE.
    scanDistricts: ['Pune', 'Pune'],
    expect: VERDICT.GENUINE,
    story: 'the happy path: signed, in a pharmacy, scanned by a patient',
  },
  {
    fixtureCase: 'genuine_vaccine_offline',
    mintLocation: 'FACT_BLR_0007',
    hops: [
      { location: 'WARE_BLR_0003', status: STATUS.IN_TRANSIT, as: 'distributor' },
      { location: 'CHC_PUN_0031', status: STATUS.AT_PHARMACY, as: 'pharmacy' },
    ],
    scanDistricts: [],
    // Readings are sent against the batch, which is how a cold box actually
    // reports: one device holds a tray of vials, not one vial.
    coldChain: { series: [4.4, 4.1, 3.9, 4.6, 5.2, 4.8], breaching: false },
    expect: VERDICT.GENUINE,
    story: 'a vaccine whose cold chain held from Bengaluru to a Pune health centre',
  },
  {
    fixtureCase: 'expired_medicine',
    mintLocation: 'FACT_PUN_0001',
    hops: [{ location: 'PHAR_PUN_0011', status: STATUS.AT_PHARMACY, as: 'pharmacy' }],
    scanDistricts: [],
    expect: VERDICT.EXPIRED,
    story: 'genuinely manufactured, correctly signed, and years out of date',
  },
  {
    fixtureCase: 'expiring_within_30_days',
    mintLocation: 'FACT_PUN_0001',
    hops: [{ location: 'PHAR_PUN_0011', status: STATUS.AT_PHARMACY, as: 'pharmacy' }],
    scanDistricts: [],
    expect: VERDICT.GENUINE,
    story: 'still usable, close enough to expiry to warn a pharmacist',
  },
  {
    fixtureCase: 'genuine_unicode_offline',
    mintLocation: 'FACT_PUN_0001',
    hops: [{ location: 'PHAR_PUN_0011', status: STATUS.AT_PHARMACY, as: 'pharmacy' }],
    // Four districts in one afternoon. One strip cannot be in four places, so
    // either the QR was photographed and reprinted or the unit was cloned — which
    // is the entire reason scan telemetry is collected (§7.1).
    scanDistricts: ['Pune', 'Mumbai', 'Nagpur', 'Nashik'],
    expect: VERDICT.CLONE,
    story: 'one product id scanned in four districts: a copied QR code',
  },
]);

/** The vaccine batch that loses its cold chain. No fixture can supply this. */
const BREACHED_BATCH = Object.freeze({
  batch_no: 'BB26MR014',
  count: 3,
  mintLocation: 'FACT_BLR_0007',
  series: [4.5, 5.2, 7.9, 10.6, 11.4],
  expect: VERDICT.COLD_CHAIN,
  story: 'a cold box door left open on the Bengaluru-Pune leg',
  template: {
    generic_name: 'Measles-Rubella Vaccine',
    brand_name: 'Suraksha MR',
    manufacturer: 'Bharat Biologics Pvt Ltd, Plot 9 Peenya, Bengaluru 560058',
    mfg_licence_no: 'KA/25B/2021/044',
    mfg_date: '2026-06-18',
    expiry_date: '2027-06-17',
    quantity: '1 vial (5 doses)',
    excipients: ['Sorbitol', 'Hydrolysed Gelatin'],
    type: TYPE.VACCINE,
  },
  idPrefix: 'MEASLESRUBELLA_SURAKSHAMR_2026_',
  firstSerial: 101,
});

/** The batch a regulator withdraws. */
const RECALLED_BATCH = Object.freeze({
  batch_no: 'SP26D0512',
  count: 2,
  mintLocation: 'FACT_PUN_0001',
  reason: 'failed dissolution testing at the CDSCO laboratory, Mumbai',
  expect: VERDICT.RECALLED,
  story: 'a batch withdrawn by the regulator after a failed lab test',
  template: {
    generic_name: 'Ibuprofen 400mg',
    brand_name: 'Brufenova 400',
    manufacturer: 'Sanjeevani Pharma Ltd, Plot 42 MIDC, Pune 411018',
    mfg_licence_no: PHARMA_SCOPE,
    mfg_date: '2026-04-02',
    expiry_date: '2028-03-31',
    quantity: '15 tablets',
    excipients: ['Maize Starch', 'Croscarmellose Sodium'],
    type: TYPE.MEDICINE,
  },
  idPrefix: 'IBUPROFEN400_BRUFENOVA_2026_',
  firstSerial: 201,
});

/** `YYYY-MM-DDTHH:MM:SSZ` exactly, which is what §4.7 signs over. */
const isoSeconds = (d) => `${new Date(d).toISOString().slice(0, 19)}Z`;

/** 16 lowercase hex characters — inside the 8..64 the nonce rule allows. */
const freshNonce = () => randomBytes(8).toString('hex');

/**
 * A reading body a real device could have sent, MAC included.
 *
 * The MAC is computed with the project's own `computeSensorMac` over the project's
 * own field order, so a reading built here is accepted by `recordTemperature` for
 * exactly the reason a firmware-built one is. Rebuilding the MAC input by hand would
 * make the seed pass while telling us nothing about §4.7.
 */
function signedReading({ secret, sensorId, binding, isBatch, temperature, recordedAt, batteryPct }) {
  const parts = { binding, sensorId, temperature, recordedAt, nonce: freshNonce() };
  const body = {
    sensor_id: sensorId,
    temperature,
    recorded_at: recordedAt,
    nonce: parts.nonce,
    hmac: computeSensorMac(secret, parts),
  };
  // Exactly one of the two, because the MAC covers whichever key was sent and
  // sending both leaves no single string for the two sides to have agreed on.
  if (isBatch) body.batch_no = binding;
  else body.product_id = binding;
  if (batteryPct !== undefined) body.battery_pct = batteryPct;
  return body;
}

/** Was this world already seeded? */
async function alreadySeeded(fabric, productID, today) {
  const snapshot = await fabric.verifyMedicine(productID, today);
  return Boolean(snapshot?.found);
}

function unitIDs({ idPrefix, firstSerial, count }) {
  return Array.from(
    { length: count },
    (unused, i) => `${idPrefix}${String(firstSerial + i).padStart(6, '0')}`,
  );
}

/**
 * Build the demo world.
 *
 * Takes an already-constructed stack rather than building one, so the whole seed
 * runs against the in-process mock stack in a test — and so `server.js` can seed the
 * exact stack it is about to serve, which for the mock drivers is the only stack
 * that will ever exist.
 *
 * @param {{services: object, store: object, fabric: object, secrets: object,
 *          config: object, clock?: () => Date, fixturesPath?: string,
 *          force?: boolean}} deps
 * @returns {Promise<object>} the summary, including plaintext credentials
 */
export async function seedDemo({
  services,
  store,
  fabric,
  secrets,
  config,
  clock = () => new Date(),
  fixturesPath = DEFAULT_FIXTURES_PATH,
  force = false,
}) {
  if (config?.isProduction) {
    throw new Error(
      'refusing to seed with NODE_ENV=production. This writes fabricated medicine ' +
        'records to the ledger, and a ledger is append-only: there is no undo, and ' +
        'invented units would be indistinguishable from real stock to every ' +
        'pharmacist and patient who scans one.',
    );
  }

  const now = clock();
  const fixtures = JSON.parse(await readFile(fixturesPath, 'utf8'));
  const caseByName = new Map((fixtures.cases ?? []).map((c) => [c.name, c]));

  // Which drivers are actually behind this? Read from `ping()`, because neither
  // ledger driver carries a `driver` property — assuming one and defaulting to
  // 'mock' would print "ledger mock" on the demo sheet of a real Fabric deployment,
  // which is precisely the fact an examiner would want stated correctly. It doubles
  // as a pre-flight: if the ledger is unreachable, saying so here is far clearer
  // than a mint failing a few hundred lines later.
  let ledgerDriver;
  try {
    ledgerDriver = (await fabric.ping())?.driver ?? 'unknown';
  } catch (cause) {
    throw new Error(
      `the ledger is not reachable, so there is nothing to seed: ${cause?.message ?? cause}`,
    );
  }

  const summary = {
    seeded_at: isoSeconds(now),
    drivers: { store: store.driver ?? 'unknown', ledger: ledgerDriver },
    ledger: 'created',
    keys: [],
    sensor: null,
    units: [],
    readings: { accepted: 0, breaching: 0 },
    recall: null,
    reports: [],
    verdict_mismatches: [],
    dashboards: null,
    curl: null,
  };

  // ── Credentials ─────────────────────────────────────────────────────────────
  // Issued on every run, including a re-seed: only their hashes are stored, so a
  // key from a previous run cannot be recovered and reprinted.
  for (const role of ROLES) {
    const { key, keyHash, row } = await issueApiKey({
      store,
      role,
      scope: role === ROLE.PHARMA ? PHARMA_SCOPE : '',
      label: KEY_LABELS[role] ?? `demo: ${role} key`,
    });
    summary.keys.push({
      role: row.role,
      scope: row.scope,
      label: row.label,
      key,
      key_hash: keyHash,
    });
  }

  // `rotate: true` because a re-seed is expected to re-provision: the demo cold box
  // is a script, not a device in a field somewhere that would need reflashing.
  const sensor = await provisionSensor({
    store,
    secrets,
    sensorId: DEMO_SENSOR_ID,
    label: 'demo: vaccine cold box, Pune district vaccine store',
    rotate: true,
  });
  summary.sensor = { sensor_id: sensor.sensorId, secret: sensor.secret };

  // ── The unit plan ───────────────────────────────────────────────────────────
  // Resolved before anything is written, because both paths below need it: the
  // re-seed path skips every ledger write but still reads these units back, so a
  // second run prints a usable demo sheet instead of an empty one.
  //
  // Each fixture unit is resolved *through the verifier*, not by reading fields out
  // of the fixture file — the unit is minted from what a scanner would actually
  // recover from that QR code, which is what makes the printed code and the ledger
  // record agree by construction.
  const fixturePlans = FIXTURE_UNITS.map((plan) => {
    const fixture = caseByName.get(plan.fixtureCase);
    if (!fixture) {
      throw new Error(
        `the fixtures have no case named ${plan.fixtureCase}, so the demo unit it ` +
          'backs cannot be minted from a real signed payload',
      );
    }
    const { medicine, verdict: offlineVerdict } = verifyWire(
      fixture.wire,
      services.trust.liveView(),
      { today: now },
    );
    if (!medicine) {
      throw new Error(
        `fixture ${plan.fixtureCase} did not yield medicine data (offline verdict ` +
          `${offlineVerdict}); it cannot be used to mint a unit`,
      );
    }
    return { plan, wire: fixture.wire, data: medicine.toDict() };
  });

  for (const { plan, data } of fixturePlans) {
    summary.units.push({
      product_id: data.product_id,
      batch_no: data.batch_no,
      type: data.type,
      expect: plan.expect,
      verdict: null,
      status: null,
      scannable: true,
      fixture_case: plan.fixtureCase,
      story: plan.story,
    });
  }

  for (const batch of [BREACHED_BATCH, RECALLED_BATCH]) {
    for (const productID of unitIDs(batch)) {
      summary.units.push({
        product_id: productID,
        batch_no: batch.batch_no,
        type: batch.template.type,
        expect: batch.expect,
        verdict: null,
        status: null,
        // No signed payload exists for a unit invented here, so there is no QR to
        // scan. It is reachable through GET /api/verify/:product_id, which reads the
        // ledger and never checks a signature.
        scannable: false,
        fixture_case: null,
        story: batch.story,
      });
    }
  }

  // ── Is the ledger already seeded? ───────────────────────────────────────────
  // Checked against the first fixture unit. If it is there, every ledger write is
  // skipped rather than retried: the mint would be a CONFLICT and the custody hops
  // would try to walk a unit that has already arrived. Fresh keys and a fresh sensor
  // secret are still issued, because being unable to recover the previous run's
  // credentials is the usual reason for running this again.
  if (!force && (await alreadySeeded(fabric, fixturePlans[0].data.product_id, now))) {
    summary.ledger = 'already seeded; ledger left untouched';
    return finishSummary({ services, config, summary, sensor, now, strict: false });
  }

  // ── The five fixture-backed units ───────────────────────────────────────────
  const coldChainPlans = [];

  for (const { plan, wire, data } of fixturePlans) {
    await mintTolerantly(services, { ...data, location: plan.mintLocation }, AUTH.manufacturer);

    for (const hop of plan.hops) {
      await services.supplyChain.recordLocation(
        { product_id: data.product_id, location: hop.location, status: hop.status },
        AUTH[hop.as],
      );
    }

    // Recorded through the payload endpoint rather than by poking the ledger,
    // because that is the endpoint §7.1 made responsible for scan telemetry — so the
    // seeded counts are produced by the same code a phone drives.
    for (const district of plan.scanDistricts) {
      await services.verify.byPayload({ raw_payload: wire, district });
    }

    if (plan.coldChain) {
      coldChainPlans.push({
        binding: data.batch_no,
        isBatch: true,
        series: plan.coldChain.series,
      });
    }
  }

  // ── The breached vaccine batch ──────────────────────────────────────────────
  for (const productID of unitIDs(BREACHED_BATCH)) {
    await mintTolerantly(
      services,
      {
        ...BREACHED_BATCH.template,
        contract_version: 1,
        product_id: productID,
        batch_no: BREACHED_BATCH.batch_no,
        location: BREACHED_BATCH.mintLocation,
      },
      AUTH.manufacturer,
    );
  }
  coldChainPlans.push({
    binding: BREACHED_BATCH.batch_no,
    isBatch: true,
    series: BREACHED_BATCH.series,
  });

  // ── Cold-chain history ──────────────────────────────────────────────────────
  // After the units exist: a batch-bound reading fans out to the units in the
  // batch, so a reading sent before the mint would have nothing to attach to.
  for (const plan of coldChainPlans) {
    const readings = plan.series.length;
    for (let i = 0; i < readings; i += 1) {
      // Oldest first, five minutes apart, the newest five minutes ago — a plausible
      // history well inside the 30-day backfill window §3.6 allows.
      const at = new Date(now.getTime() - (readings - i) * 5 * 60 * 1000);
      const body = signedReading({
        secret: sensor.secret,
        sensorId: sensor.sensorId,
        binding: plan.binding,
        isBatch: plan.isBatch,
        temperature: plan.series[i],
        recordedAt: isoSeconds(at),
        batteryPct: 94 - i,
      });
      const out = await services.supplyChain.recordTemperature(body, AUTH.sensor);
      summary.readings.accepted += 1;
      if (out.chain_ok === false) summary.readings.breaching += 1;
    }
  }

  // ── The recalled batch ──────────────────────────────────────────────────────
  for (const productID of unitIDs(RECALLED_BATCH)) {
    await mintTolerantly(
      services,
      {
        ...RECALLED_BATCH.template,
        contract_version: 1,
        product_id: productID,
        batch_no: RECALLED_BATCH.batch_no,
        location: RECALLED_BATCH.mintLocation,
      },
      AUTH.manufacturer,
    );
  }

  const recall = await services.supplyChain.recall(
    { batch_no: RECALLED_BATCH.batch_no, reason: RECALLED_BATCH.reason },
    AUTH.regulator,
  );
  summary.recall = {
    batch_no: RECALLED_BATCH.batch_no,
    reason: RECALLED_BATCH.reason,
    recalled: Number(recall?.recalled ?? 0),
    more_remaining: Boolean(recall?.more_remaining),
  };

  // ── Counterfeit reports ─────────────────────────────────────────────────────
  // Two districts, so the CDSCO heat map has more than one cell and the district
  // roll-up is visibly a roll-up. The cloned unit is reported by name, which is the
  // narrative the whole system exists for: telemetry raised the suspicion, a patient
  // confirmed it.
  const cloneUnit = summary.units.find((u) => u.expect === VERDICT.CLONE);
  const expiredUnit = summary.units.find((u) => u.expect === VERDICT.EXPIRED);

  for (const report of [
    {
      product_id: cloneUnit?.product_id,
      pharmacy_name: 'Sai Krupa Medical Stores',
      district: 'Nashik',
      state: 'Maharashtra',
      notes: 'the foil print is blurred and the batch number is smudged',
      reporter_contact: '+91 98765 43210',
    },
    {
      product_id: expiredUnit?.product_id,
      pharmacy_name: 'Ganesh Chemists',
      district: 'Pune',
      state: 'Maharashtra',
      notes: 'sold to me last week and the strip expired in 2025',
    },
  ]) {
    if (!report.product_id) continue;
    const out = await services.reports.submit(report, { ip: '203.0.113.7' });
    summary.reports.push({
      report_id: out.report_id,
      product_id: report.product_id,
      district: report.district,
    });
  }

  return finishSummary({ services, config, summary, sensor, now, strict: true });
}

/**
 * Read every seeded unit back through the real verify service, then collect the
 * dashboards and the sample request.
 *
 * Shared by both paths so that a re-seed prints the same demo sheet as a first run.
 *
 * `strict` is the difference between them, and the distinction is deliberate. On a
 * fresh seed a wrong verdict means this script built the world incorrectly, and
 * handing over a demo that shows the wrong colour is worse than failing — so it
 * throws. On a re-seed the ledger state was created by an earlier run and may have
 * been moved on since, quite legitimately, by whoever was demonstrating; refusing to
 * print freshly issued keys because of that would be unhelpful, so the mismatch is
 * reported in the summary and the operator decides.
 */
async function finishSummary({ services, config, summary, sensor, now, strict }) {
  for (const unit of summary.units) {
    const { body } = await services.verify.byProductID(unit.product_id);
    unit.verdict = body.verdict;
    // `status` is a field of the ledger record, so it arrives nested under
    // `medicine` — there is no top-level `body.status`, and reading one gives a
    // column of nulls that looks like the supply chain never moved.
    unit.status = body.medicine?.status ?? null;
  }

  const wrong = summary.units.filter((u) => u.verdict !== u.expect);
  if (wrong.length > 0) {
    const detail = wrong
      .map((u) => `  ${u.product_id}  expected ${u.expect}, got ${u.verdict}`)
      .join('\n');
    if (strict) {
      throw new Error(
        'the seeded world does not verify as intended, so the demo would show the ' +
          `wrong verdict:\n${detail}`,
      );
    }
    summary.verdict_mismatches = wrong.map((u) => ({
      product_id: u.product_id,
      expected: u.expect,
      actual: u.verdict,
    }));
  }

  summary.dashboards = await readDashboards(services);
  summary.curl = breachCurl({ config, summary, sensor, now });

  return summary;
}

/**
 * Mint, treating "already on the ledger" as success.
 *
 * A ledger is append-only, so re-running against a real network must not fail on a
 * unit that a previous run already created. Only CONFLICT is swallowed: every other
 * failure is a real problem and is allowed to stop the seed.
 */
async function mintTolerantly(services, input, auth) {
  try {
    return await services.supplyChain.mint(input, auth);
  } catch (err) {
    if (err?.code === CODES.CONFLICT) return null;
    throw err;
  }
}

async function readDashboards(services) {
  const cdsco = await services.dashboards.cdsco({});
  const pharma = await services.dashboards.pharma({ role: ROLE.PHARMA, scope: PHARMA_SCOPE }, {});
  return {
    cdsco: {
      totals: cdsco.totals,
      districts: (cdsco.districts ?? []).map((d) => ({ district: d.district, reports: d.reports })),
      alerts: (cdsco.alerts ?? []).length,
    },
    pharma: { scope: PHARMA_SCOPE, totals: pharma.totals },
  };
}

/**
 * A ready-to-paste breach reading.
 *
 * The demo everyone asks to see is the alert firing, and reproducing it by hand
 * means computing an HMAC — which is exactly the step a firmware author gets wrong.
 * Handing over one correct request removes the guesswork, and it stays valid for the
 * whole 30-day backfill window because `recorded_at` is fixed and signed.
 *
 * It carries a MAC, not the sensor secret. The API key in it was already printed.
 */
function breachCurl({ config, summary, sensor, now }) {
  const key = summary.keys.find((k) => k.role === ROLE.SENSOR);
  if (!key) return null;

  const body = signedReading({
    secret: sensor.secret,
    sensorId: sensor.sensorId,
    binding: BREACHED_BATCH.batch_no,
    isBatch: true,
    temperature: 12.6,
    recordedAt: isoSeconds(now),
    batteryPct: 71,
  });

  const host = config?.server?.host === '0.0.0.0' ? '127.0.0.1' : config?.server?.host ?? '127.0.0.1';
  const url = `http://${host}:${config?.server?.port ?? 3000}/api/temperature`;

  return {
    description: `a 12.6 degC reading on batch ${BREACHED_BATCH.batch_no}`,
    command:
      `curl -sS -X POST ${url} \\\n` +
      `  -H 'Content-Type: application/json' \\\n` +
      `  -H 'X-API-Key: ${key.key}' \\\n` +
      `  -d '${JSON.stringify(body)}'`,
  };
}

/**
 * The summary as an operator-readable block.
 *
 * Separate from `seedDemo` so the seed can be driven by a test that inspects the
 * structure without a page of text arriving on stdout.
 */
export function formatSummary(summary) {
  const lines = [];
  const rule = '-'.repeat(78);

  lines.push(rule, 'TrueMed demo data', rule);
  lines.push(
    `store ${summary.drivers.store}, ledger ${summary.drivers.ledger}, ` +
      `seeded ${summary.seeded_at}`,
  );
  lines.push(`ledger: ${summary.ledger}`);

  lines.push('', 'API keys — shown once, only their hashes are stored');
  for (const k of summary.keys) {
    lines.push(`  ${k.role.padEnd(13)}${k.key}${k.scope ? `   scope ${k.scope}` : ''}`);
  }

  if (summary.sensor) {
    lines.push('', 'Cold-chain sensor');
    lines.push(`  ${summary.sensor.sensor_id}   secret ${summary.sensor.secret}`);
  }

  if (summary.units.length > 0) {
    lines.push('', 'Units');
    for (const u of summary.units) {
      lines.push(`  ${(u.verdict ?? u.expect).padEnd(20)}${u.product_id}`);
      lines.push(`  ${''.padEnd(20)}${u.story}${u.scannable ? '' : '  (no QR: minted without a signed payload)'}`);
    }
  }

  if (summary.readings.accepted > 0) {
    lines.push(
      '',
      `Temperature readings: ${summary.readings.accepted} accepted, ` +
        `${summary.readings.breaching} outside 2-8 degC`,
    );
  }

  if (summary.recall) {
    lines.push(
      '',
      `Recall: batch ${summary.recall.batch_no}, ${summary.recall.recalled} unit(s) — ` +
        summary.recall.reason,
    );
  }

  if (summary.reports.length > 0) {
    lines.push('', 'Counterfeit reports');
    for (const r of summary.reports) {
      lines.push(`  ${r.district.padEnd(12)}${r.product_id}   ${r.report_id}`);
    }
  }

  if (summary.verdict_mismatches.length > 0) {
    lines.push(
      '',
      'These units do not verify as the demo intends. The ledger was already seeded,',
      'so this state was created by an earlier run and may have been moved on since:',
    );
    for (const m of summary.verdict_mismatches) {
      lines.push(`  ${m.product_id}  expected ${m.expected}, got ${m.actual}`);
    }
  }

  if (summary.dashboards) {
    lines.push('', 'Dashboards');
    lines.push(`  CDSCO   ${JSON.stringify(summary.dashboards.cdsco.totals)}`);
    lines.push(`  pharma  ${JSON.stringify(summary.dashboards.pharma.totals)}`);
    lines.push(`          scoped to ${summary.dashboards.pharma.scope}`);
  }

  if (summary.curl) {
    lines.push('', `Fire a cold-chain breach — ${summary.curl.description}:`, '');
    lines.push(summary.curl.command);
  }

  lines.push(rule);
  return lines.join('\n');
}

// ── Command line ──────────────────────────────────────────────────────────────

const USAGE = `Seed a demonstrable TrueMed world.

  SEED_DEMO=1 npm start      seed the in-process mock stack and serve it
  npm run seed               seed a real PostgreSQL + Fabric deployment
  npm run seed -- --ephemeral  run the seeder against a throwaway mock stack

Options
  --ephemeral  build the whole world in this process and discard it on exit.
               Use it to check that the seeder works, not to prepare a demo.
  --force      seed the ledger again even if the demo units are already on it
  --json       emit the summary as JSON instead of a table
  --help       this text

Prints six API keys and a sensor secret. They are shown once — only hashes are
stored — and this script refuses to run with NODE_ENV=production.`;

async function main() {
  const argv = process.argv.slice(2);
  const known = new Set(['--ephemeral', '--force', '--json', '--help', '-h']);
  const unknown = argv.filter((a) => !known.has(a));
  if (unknown.length > 0) {
    process.stderr.write(`unknown option ${JSON.stringify(unknown[0])}\n\n${USAGE}\n`);
    process.exitCode = 2;
    return;
  }
  if (argv.includes('--help') || argv.includes('-h')) {
    process.stdout.write(`${USAGE}\n`);
    return;
  }

  const ephemeral = argv.includes('--ephemeral');
  const asJson = argv.includes('--json');

  let config;
  let assertRuntimePaths;
  try {
    ({ config, assertRuntimePaths } = await import('../src/config/index.js'));
  } catch (err) {
    process.stderr.write(`${err?.message ?? err}\n`);
    process.exitCode = 1;
    return;
  }

  if (config.fabric.mock && !ephemeral) {
    process.stderr.write(
      'refusing to seed the in-memory stack from a separate process.\n\n' +
        'FABRIC_MOCK=1 keeps the ledger, the database and the cache inside one\n' +
        'process, and the mock ledger has no file behind it — so everything this\n' +
        'script wrote would vanish the moment it exits, keys included.\n\n' +
        'Seed the mock stack from inside the server instead:\n' +
        '    SEED_DEMO=1 npm start\n\n' +
        'Or, to check that the seeder itself works and throw the result away:\n' +
        '    npm run seed -- --ephemeral\n',
    );
    process.exitCode = 1;
    return;
  }

  // Imported here rather than at the top of the file: `app.js` imports Express, and
  // a static import would make this module — and its tests — unloadable without the
  // production dependency tree installed.
  const [
    { createServices },
    { Logger },
    { createStore },
    { createCache },
    { createFabric },
    { loadTrustBundle },
    { SecretBox },
  ] = await Promise.all([
    import('../src/app.js'),
    import('../src/utils/logger.js'),
    import('../src/db/index.js'),
    import('../src/cache/index.js'),
    import('../src/fabric/index.js'),
    import('../src/services/trust.js'),
    import('../src/utils/secret-box.js'),
  ]);

  const logger = new Logger(
    { component: 'seed' },
    { level: config.log.level === 'debug' ? 'debug' : 'warn', pretty: config.log.pretty },
  );

  try {
    assertRuntimePaths(config);
  } catch (err) {
    process.stderr.write(
      `${err?.message ?? err}\n\nRun \`npm run dev-keys\` to write development ` +
        'trust keys into backend/keys/.\n',
    );
    process.exitCode = 1;
    return;
  }

  const store = createStore(config, logger);
  const cache = createCache(config, logger);
  const fabric = createFabric(config, logger);
  const opened = [];

  try {
    for (const driver of [store, cache, fabric]) {
      if (typeof driver.connect === 'function') {
        await driver.connect();
        opened.push(driver);
      }
    }

    const trustBundle = await loadTrustBundle(config.trust);
    const secrets = new SecretBox(config.secrets.encryptionKey);
    const services = createServices({
      config,
      logger,
      store,
      cache,
      fabric,
      trustBundle,
      secrets,
    });

    const summary = await seedDemo({
      services,
      store,
      fabric,
      secrets,
      config,
      force: argv.includes('--force'),
    });

    process.stdout.write(asJson ? `${JSON.stringify(summary, null, 2)}\n` : `${formatSummary(summary)}\n`);
    if (ephemeral) {
      process.stderr.write(
        '\nThis was an --ephemeral run: everything above lived in this process and ' +
          'is gone now. None of those keys will authenticate.\n',
      );
    }
  } catch (err) {
    process.stderr.write(`${err?.message ?? String(err)}\n`);
    process.exitCode = 1;
  } finally {
    for (const driver of opened.reverse()) {
      if (typeof driver.close === 'function') await driver.close().catch(() => {});
    }
  }
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  await main();
}

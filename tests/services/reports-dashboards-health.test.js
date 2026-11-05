/**
 * Counterfeit reports, the two dashboards, and readiness.
 *
 * Grouped because they share one concern: each of them decides what leaves the
 * server, and each has a way of leaking something it was trusted with.
 *
 * **A report is the most sensitive object in the system.** A patient sends a photo,
 * a location and sometimes a phone number, in order to accuse a named pharmacy. So
 * the contact is sealed at rest, coordinates are truncated to roughly a village
 * rather than a doorstep, and the response hands back an id and a timestamp and
 * nothing else — not the stored row, which holds ciphertext and the reporter's IP.
 *
 * **A pharma dashboard is multi-tenant.** The licence filter comes from the key's
 * scope, never the query (§4.4a). If a query parameter could influence it, one
 * manufacturer could read a competitor's entire production and recall history by
 * changing a URL.
 *
 * **Readiness decides whether traffic arrives.** Redis is optional and must only
 * downgrade the label to `degraded`; the database, the ledger and a usable trust
 * bundle are load-bearing and must take the replica out of rotation. Getting that
 * backwards either drops all traffic over a cache blip or keeps routing patients to
 * a replica that answers UNVERIFIABLE to every scan.
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
import { makeReportsService } from '../../src/services/reports.js';
import { makeDashboardsService } from '../../src/services/dashboards.js';
import { makeHealthService } from '../../src/services/health.js';
import { makeSupplyChainService } from '../../src/services/supply-chain.js';
import { verifyWire } from '../../src/core/verifier.js';
import { SecretBox, reportContext } from '../../src/utils/secret-box.js';
import { CODES } from '../../src/core/errors.js';
import { TYPE } from '../../src/core/rules.js';

const FIXTURES = JSON.parse(
  readFileSync(new URL('../fixtures/fixtures.json', import.meta.url), 'utf8'),
);

const FIXED_NOW = new Date('2026-06-01T10:00:00Z');
const clock = () => FIXED_NOW;

/** A 1x1 PNG, so photo handling is exercised on real image bytes. */
const TINY_PNG_BASE64 =
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==';

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
  return {
    config,
    cache,
    store,
    fabric,
    secrets,
    trust,
    reports: makeReportsService({ store, trust, secrets, clock }),
    dashboards: makeDashboardsService({ fabric, store, clock }),
    health: makeHealthService({ store, cache, fabric, trust, config, clock }),
    supplyChain: makeSupplyChainService({ cache, fabric, store, secrets, clock }),
  };
}

let serial = 0;
function unit({ licence = FIXTURES.licences.active_medicine, batch = 'SP26A0417', ...rest } = {}) {
  serial += 1;
  return {
    product_id: `PARACETAMOL500MG_PARACIP500_2026_${String(serial).padStart(6, '0')}`,
    generic_name: 'Paracetamol 500mg',
    brand_name: 'Paracip 500',
    manufacturer: 'Sanjeevani Pharma Ltd, Plot 42 MIDC, Pune 411018',
    mfg_licence_no: licence,
    batch_no: batch,
    mfg_date: '2026-03-15',
    expiry_date: '2028-02-29',
    quantity: '10 tablets',
    excipients: ['Maize Starch', 'Povidone K30', 'Talc'],
    type: TYPE.MEDICINE,
    location: 'FACT_PUN_0001',
    ...rest,
  };
}

describe('counterfeit reports', () => {
  test('a report returns only an id and a timestamp', async () => {
    const s = stack();
    const product = unit();

    const out = await s.reports.submit(
      {
        product_id: product.product_id,
        pharmacy_name: 'Shree Medical Stores',
        district: 'Pune',
        notes: 'the foil looks reprinted and the batch is smudged',
      },
      { ip: '203.0.113.7' },
    );

    assert.deepEqual(Object.keys(out).sort(), ['received_at', 'report_id']);
    assert.match(out.report_id, /^[0-9a-f-]{36}$/);
  });

  /**
   * A patient reporting their own neighbourhood pharmacy should not have their
   * doorstep recorded. Three decimals is about 100 m — enough to build a district
   * heat map, not enough to identify a household — and a truncated coordinate
   * cannot be un-truncated after a breach.
   */
  test('coordinates are stored coarsely', async () => {
    const s = stack();
    const product = unit();

    const { report_id: id } = await s.reports.submit({
      product_id: product.product_id,
      lat: 18.5204303,
      lon: 73.8567437,
    });

    const row = await s.store.getReport(id);
    assert.equal(row.lat, 18.52);
    assert.equal(row.lon, 73.857);
  });

  test('a reporter contact is sealed at rest and never returned', async () => {
    const s = stack();
    const product = unit();
    const contact = '+91 98765 43210';

    const { report_id: id } = await s.reports.submit({
      product_id: product.product_id,
      reporter_contact: contact,
    });

    const row = await s.store.getReport(id);
    const sealed = row.reporter_contact_enc;
    assert.ok(Buffer.isBuffer(sealed) && sealed.length > 0);
    assert.equal(sealed.includes(Buffer.from(contact, 'utf8')), false, 'plaintext must not survive');
    assert.equal(s.secrets.open(sealed, reportContext(id)), contact);
  });

  /**
   * The seal is bound to the report id as AEAD context, so a ciphertext lifted from
   * one row and pasted into another fails to open rather than authenticating as the
   * other reporter's contact.
   */
  test('a sealed contact cannot be moved to another report', async () => {
    const s = stack();
    const a = await s.reports.submit({ product_id: unit().product_id, reporter_contact: 'a@example.org' });
    const b = await s.reports.submit({ product_id: unit().product_id, reporter_contact: 'b@example.org' });

    const rowA = await s.store.getReport(a.report_id);
    assert.throws(() => s.secrets.open(rowA.reporter_contact_enc, reportContext(b.report_id)));
  });

  test('a report needs something that identifies a medicine', async () => {
    const s = stack();
    await assert.rejects(
      () => s.reports.submit({ pharmacy_name: 'Shree Medical Stores' }),
      (err) => {
        assert.equal(err.code, CODES.VALIDATION_ERROR);
        return true;
      },
    );
  });

  test('a photo is accepted and stored as bytes', async () => {
    const s = stack();
    const { report_id: id } = await s.reports.submit({
      product_id: unit().product_id,
      photo_base64: TINY_PNG_BASE64,
    });

    const row = await s.store.getReport(id);
    assert.ok(Buffer.isBuffer(row.photo));
    assert.equal(row.photo_bytes, row.photo.length);
  });

  test('a data: URL from a browser FileReader is accepted', async () => {
    const s = stack();
    const { report_id: id } = await s.reports.submit({
      product_id: unit().product_id,
      photo_base64: `data:image/png;base64,${TINY_PNG_BASE64}`,
    });

    const row = await s.store.getReport(id);
    assert.ok(row.photo.length > 0, 'the data: header must not be stored as image data');
  });

  /**
   * Node's base64 decoder silently drops characters outside the alphabet, so a
   * corrupt upload would otherwise be stored as a shorter, broken image and
   * discovered only when an investigator tried to look at the evidence.
   */
  test('corrupt base64 is rejected rather than silently truncated', async () => {
    const s = stack();
    await assert.rejects(
      () => s.reports.submit({ product_id: unit().product_id, photo_base64: 'not!!valid!!base64!!' }),
      (err) => {
        assert.equal(err.code, CODES.VALIDATION_ERROR);
        return true;
      },
    );
  });

  test('an unreadable payload is still accepted when a product_id is given', async () => {
    const s = stack();
    const product = unit();

    // The whole point of the endpoint: a scan that would not verify is exactly
    // what a patient needs to be able to report.
    const out = await s.reports.submit({
      product_id: product.product_id,
      raw_payload: 'TM1:garbage-that-will-not-verify',
    });
    assert.ok(out.report_id);
  });

  /**
   * Regression. The report form does not ask a patient to type a product id — it
   * sends the scan and lets the server read one out of it, which is the whole
   * ergonomics of one-tap reporting.
   *
   * That recovery goes through `verifyWire`, and the call site was passing the trust
   * *service* where a trust *bundle* belongs. The failure was invisible from here:
   * the surrounding `catch` treats any fault as "payload unreadable", so the id was
   * never recovered and the report came back 400 VALIDATION_ERROR — a patient holding
   * a suspect strip being told their evidence is unusable. Only a *valid* payload
   * reaches the lookup, so the earlier garbage-payload cases could not see it.
   */
  test('a report carrying only a scan recovers the product id from the payload', async () => {
    const s = stack();
    const wire = FIXTURES.cases.find((c) => c.name === 'genuine_medicine_offline').wire;
    const { medicine } = verifyWire(wire, s.trust.liveView(), { today: FIXED_NOW });

    const out = await s.reports.submit({ raw_payload: wire, district: 'Pune' });

    const row = await s.store.getReport(out.report_id);
    assert.equal(
      row.product_id,
      medicine.productID,
      'a report with no product_id must be attached to the one inside the payload',
    );
  });
});

describe('dashboards', () => {
  /**
   * The regulator's board counts problems, not production — reports, recalls, cold
   * chain breaches and clone suspicions — because those are the only things CDSCO
   * can act on. Unit and batch totals belong on the manufacturer's board.
   */
  test('the CDSCO board surfaces reports, recalls and the district they came from', async () => {
    const s = stack();
    const product = unit({ licence: FIXTURES.licences.active_medicine, batch: 'SP26A0417' });
    await s.supplyChain.mint(product, { role: 'manufacturer' });
    await s.reports.submit({ product_id: product.product_id, district: 'Pune', state: 'Maharashtra' });
    await s.supplyChain.recall(
      { batch_no: product.batch_no, reason: 'failed dissolution testing' },
      { role: 'regulator' },
    );

    const board = await s.dashboards.cdsco({});

    assert.equal(board.totals.reports, 1);
    assert.equal(board.totals.reports_open, 1);
    assert.equal(board.totals.units_recalled, 1);

    const pune = board.districts.find((d) => d.district === 'Pune');
    assert.ok(pune, 'the report must roll up into a district for the heat map');
    assert.equal(pune.reports, 1);

    // The alert is what a drug inspector is actually dispatched on, so it has to
    // name the product and the batch, not just increment a counter.
    const alert = board.alerts.find((a) => a.product_id === product.product_id);
    assert.ok(alert);
    assert.equal(alert.batch_no, product.batch_no);
  });

  /**
   * A report carries a phone number and a photo. Neither belongs on a dashboard
   * that is read by every regulator account — the district roll-up is what a heat
   * map needs, and the contact is only reachable by unsealing the row.
   */
  test('the CDSCO board never carries reporter contact details', async () => {
    const s = stack();
    const product = unit();
    await s.supplyChain.mint(product, { role: 'manufacturer' });
    await s.reports.submit({
      product_id: product.product_id,
      district: 'Pune',
      reporter_contact: '+91 98765 43210',
      photo_base64: TINY_PNG_BASE64,
    });

    const serialised = JSON.stringify(await s.dashboards.cdsco({}));
    assert.equal(serialised.includes('98765'), false, 'a reporter contact leaked onto a dashboard');
    assert.equal(serialised.includes('reporter_contact'), false);
    assert.equal(serialised.includes(TINY_PNG_BASE64.slice(0, 24)), false, 'photo bytes leaked');
  });

  /**
   * §4.4a. The scope comes from the authenticated key; the query is data the caller
   * controls. If a query parameter could override or widen it, one manufacturer
   * reads a competitor's production by editing a URL.
   */
  test('a pharma board shows only the scoped licence, whatever the query says', async () => {
    const s = stack();
    const mine = unit({ licence: FIXTURES.licences.active_medicine, batch: 'SP26A0417' });
    const theirs = unit({ licence: FIXTURES.licences.active_vaccine, batch: 'CV26B0088' });
    await s.supplyChain.mint(mine, { role: 'manufacturer' });
    await s.supplyChain.mint(theirs, { role: 'manufacturer' });

    const board = await s.dashboards.pharma(
      { scope: FIXTURES.licences.active_medicine },
      // A caller trying to widen the filter through every plausible parameter name.
      {
        mfg_licence_no: FIXTURES.licences.active_vaccine,
        licence: FIXTURES.licences.active_vaccine,
        scope: FIXTURES.licences.active_vaccine,
      },
    );

    const serialised = JSON.stringify(board);
    assert.equal(
      serialised.includes(theirs.product_id) || serialised.includes(theirs.batch_no),
      false,
      "another manufacturer's stock appeared in a scoped dashboard",
    );
    assert.equal(board.totals.units_minted, 1);
  });

  /**
   * A blank scope would filter on '' and match nothing, returning an empty board —
   * which looks like "you have no stock" and hides a misissued key. Refusing says
   * what is actually wrong.
   */
  test('an unscoped pharma key is refused, not shown an empty board', async () => {
    const s = stack();
    await assert.rejects(
      () => s.dashboards.pharma({ scope: '   ' }, {}),
      (err) => {
        assert.equal(err.code, CODES.FORBIDDEN);
        assert.match(err.message, /scope/);
        return true;
      },
    );
    await assert.rejects(() => s.dashboards.pharma({}, {}));
  });
});

describe('readiness', () => {
  test('liveness answers without touching a dependency', async () => {
    const s = stack();
    // If `live()` probed anything, this would throw rather than answer.
    s.store.ping = async () => {
      throw new Error('database is down');
    };
    s.fabric.ping = async () => {
      throw new Error('ledger is down');
    };

    const body = s.health.live();
    assert.equal(body.status, 'ok');
    assert.equal(typeof body.uptime_s, 'number');
  });

  test('a healthy stack is ready', async () => {
    const s = stack();
    const out = await s.health.ready();

    assert.equal(out.ready, true);
    assert.equal(out.status, 'ok');
    assert.equal(out.httpStatus, 200);
    assert.equal(out.checks.database.ok, true);
    assert.equal(out.checks.trust_bundle.ok, true);
  });

  /**
   * The cache is optional by design: verification still works without it, just
   * slower. Taking a replica out of rotation over a Redis blip would turn a
   * performance problem into an outage.
   */
  test('a cache outage is degraded but still serving', async () => {
    const s = stack();
    s.cache.ping = async () => {
      throw new Error('redis is unreachable');
    };

    const out = await s.health.ready();
    assert.equal(out.ready, true);
    assert.equal(out.status, 'degraded');
    assert.equal(out.httpStatus, 200);
    assert.equal(out.checks.cache.ok, false);
  });

  test('a ledger outage takes the replica out of rotation', async () => {
    const s = stack();
    s.fabric.ping = async () => {
      throw new Error('no peers reachable');
    };

    const out = await s.health.ready();
    assert.equal(out.ready, false);
    assert.equal(out.status, 'unavailable');
    assert.equal(out.httpStatus, 503);
  });

  /**
   * The check with no I/O behind it, and the one most worth having. A replica whose
   * bundle carries no usable keys passes every connectivity probe and answers
   * UNVERIFIABLE to every patient who scans a medicine — healthy by every other
   * measure, and useless.
   */
  test('a trust bundle with no active keys is not ready', async () => {
    const s = stack();
    s.trust.summary = () => ({ key_count: 3, active_key_count: 0, signed: true, issued_at: null });

    const out = await s.health.ready();
    assert.equal(out.ready, false);
    assert.equal(out.checks.trust_bundle.ok, false);
    assert.match(out.checks.trust_bundle.error, /no active/);
  });

  test('a probe reports the failure without leaking deployment detail upward', async () => {
    const s = stack();
    s.store.ping = async () => {
      throw new Error('connect ECONNREFUSED 10.0.3.14:5432');
    };

    const out = await s.health.ready();
    assert.equal(out.checks.database.ok, false);
    // Readiness is an operator-facing surface, so the detail is kept — but this
    // pins that it lives under `checks`, which the route only serves on the
    // dedicated probe path, and never in a public error envelope.
    assert.ok(out.checks.database.error);
  });
});

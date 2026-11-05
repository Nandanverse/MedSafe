/**
 * The interface map (`docs/BACKEND-INTERFACES.md`) against the code it describes.
 *
 * A map of an interface is only worth having if it is true, and prose has no compiler.
 * `BACKEND-INTERFACES.md` exists so that a new module — the Flutter client, the seed
 * script, a route — can be written against these interfaces without reading every
 * file, which means a wrong line in it is worse than a missing one: it is acted on.
 *
 * So the document is treated as an assertion about the code, and checked four ways.
 *
 * **Completeness.** Every exported symbol in `src/` must be named in a code span in the
 * map. This is the check that will trip most often, and deliberately: adding an export
 * without documenting it makes a reader conclude the export does not exist, and they
 * will write a worse version of it. If this test fails, the fix is normally to document
 * the new symbol rather than to relax the test.
 *
 * **Attribution.** Every symbol the map files under a module must be exported by that
 * module. A symbol documented under the wrong file survives any amount of careful
 * re-reading and sends the reader to an import that does not resolve — four of the six
 * driver classes have filenames that differ from the class name, so this is a live
 * hazard rather than a theoretical one (§9.13).
 *
 * **Transcription.** The enums the map copies out are compared to the real objects
 * key-for-key and value-for-value, parsed back out of the document rather than
 * hardcoded here. Copying an enum by hand is how `VERDICT.COLD_CHAIN` becomes
 * `VERDICT.COLD_CHAIN_BREACH` in someone's memory, and a wrong enum key is `undefined`,
 * so `assert.equal(x, VERDICT.TYPO)` passes vacuously (§9.11).
 *
 * **Claims.** The response shapes and the traps in §9 are asserted against the live
 * mock stack. A shape described from memory is the most likely thing in the document to
 * be wrong, because it is the part that cannot be checked by reading a signature.
 *
 * The whole thing runs in-process over the mock ledger, the in-memory store and the
 * in-memory cache: no database, no Redis, no Fabric network, no Express.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

import { MemoryCache } from '../../src/cache/memory.js';
import { CACHE_STATE } from '../../src/cache/index.js';
import { MemoryStore } from '../../src/db/memory-store.js';
import { PostgresStore } from '../../src/db/postgres.js';
import { RedisCache } from '../../src/cache/redis.js';
import { MockLedger } from '../../src/fabric/mock-ledger.js';
import { FabricGatewayClient } from '../../src/fabric/gateway-client.js';
import { MSP, mspForRole } from '../../src/fabric/index.js';
import { TrustBundle } from '../../src/core/trust-bundle.js';
import { loadConfig } from '../../src/config/index.js';
import { makeTrustService } from '../../src/services/trust.js';
import { makeVerifyService } from '../../src/services/verify.js';
import { makeSupplyChainService } from '../../src/services/supply-chain.js';
import { makeReportsService } from '../../src/services/reports.js';
import { verifyWire } from '../../src/core/verifier.js';
import { SecretBox } from '../../src/utils/secret-box.js';
import { LEVELS } from '../../src/utils/logger.js';
import { CODES, rateLimited } from '../../src/core/errors.js';
import * as rules from '../../src/core/rules.js';

const SRC = fileURLToPath(new URL('../../src/', import.meta.url));
const DOC_PATH = fileURLToPath(new URL('../../../docs/BACKEND-INTERFACES.md', import.meta.url));
const DOC = readFileSync(DOC_PATH, 'utf8');

const FIXTURES = JSON.parse(
  readFileSync(new URL('../fixtures/fixtures.json', import.meta.url), 'utf8'),
);

const FIXED_NOW = new Date('2026-06-01T10:00:00Z');
const clock = () => FIXED_NOW;

/**
 * Every identifier the document mentions inside a code span or a fenced block.
 *
 * Prose is excluded on purpose. A symbol whose name happens to be an English word —
 * `sanitise`, `conflict`, `stamp` — would otherwise count as documented because the
 * word appears in a sentence somewhere, which is exactly the false pass that makes a
 * completeness check worthless.
 */
function documentedTokens() {
  const spans = [];
  for (const m of DOC.matchAll(/`([^`\n]+)`/g)) spans.push(m[1]);
  for (const m of DOC.matchAll(/```[a-z]*\n([\s\S]*?)```/g)) spans.push(m[1]);
  const tokens = new Set();
  for (const span of spans) {
    for (const t of span.match(/[A-Za-z_$][A-Za-z0-9_$]*/g) || []) tokens.add(t);
  }
  return tokens;
}

/** Source files under `src/`, as paths relative to it. */
function sourceFiles(dir = SRC, out = []) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) sourceFiles(full, out);
    else if (entry.name.endsWith('.js')) out.push(path.relative(SRC, full));
  }
  return out;
}

/**
 * The names one module exports.
 *
 * Read from the text rather than by importing, because importing every module to
 * enumerate its exports would pull in `pg` and `redis` — absent here, and the reason
 * this suite runs with no `node_modules` at all.
 */
function exportsOf(rel) {
  const src = readFileSync(path.join(SRC, rel), 'utf8');
  const names = new Set();
  const patterns = [
    /^export\s+(?:async\s+)?function\s+([A-Za-z_$][\w$]*)/gm,
    /^export\s+class\s+([A-Za-z_$][\w$]*)/gm,
    /^export\s+(?:const|let|var)\s+([A-Za-z_$][\w$]*)/gm,
  ];
  for (const re of patterns) for (const m of src.matchAll(re)) names.add(m[1]);
  for (const m of src.matchAll(/^export\s*\{([^}]*)\}/gm)) {
    for (const part of m[1].split(',')) {
      const name = part.split(/\s+as\s+/).pop().trim();
      if (name) names.add(name);
    }
  }
  return names;
}

/**
 * An object literal the document transcribes, parsed back out of it.
 *
 * Parsed rather than hardcoded: a copy of the enum written here would only prove that
 * this file and `rules.js` agree, and say nothing about the document — which is the
 * thing under test.
 */
function transcribedEnum(name) {
  const re = new RegExp(`${name}\\s*=\\s*\\{([^}]*)\\}`);
  const found = DOC.match(re);
  assert.ok(found, `the map no longer transcribes ${name}; update this test or the map`);
  const out = {};
  for (const m of found[1].matchAll(/([A-Za-z_$][\w$]*)\s*:\s*(?:'([^']*)'|"([^"]*)"|(-?\d+(?:\.\d+)?))/g)) {
    const [, key, single, double, num] = m;
    out[key] = num !== undefined ? Number(num) : (single ?? double);
  }
  assert.ok(Object.keys(out).length > 0, `${name} was found in the map but parsed as empty`);
  return out;
}

/** The whole stack, in process, as every other service test builds it. */
function stack() {
  const config = loadConfig({
    NODE_ENV: 'development',
    FABRIC_MOCK: '1',
    LOG_LEVEL: 'silent',
    TRUST_REQUIRE_SIGNATURE: '0',
    SENSOR_REQUIRE_HMAC: '0',
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
    trust,
    verify: makeVerifyService({ cache, fabric, trust, clock }),
    supplyChain: makeSupplyChainService({ cache, fabric, store, secrets, clock }),
    reports: makeReportsService({ store, trust, secrets, clock }),
  };
}

/** The one signed fixture wire these checks are built from, and its parsed medicine. */
function signedUnit(trust) {
  const found = FIXTURES.cases.find((c) => c.name === 'genuine_medicine_offline');
  assert.ok(found, 'fixture case genuine_medicine_offline is missing');
  const { medicine } = verifyWire(found.wire, trust.liveView(), { today: FIXED_NOW });
  return { wire: found.wire, medicine };
}

describe('the interface map is complete', () => {
  /**
   * Fails when an export is added without being documented. That is the intended
   * behaviour: the map claims to name every export, and a map with a silent gap is
   * how a second implementation of an existing helper gets written.
   */
  test('every exported symbol in src/ is named in a code span', () => {
    const documented = documentedTokens();
    const missing = [];
    for (const rel of sourceFiles()) {
      for (const name of exportsOf(rel)) {
        if (!documented.has(name)) missing.push(`${rel} exports ${name}`);
      }
    }
    assert.deepEqual(
      missing,
      [],
      'these exports are not named in docs/BACKEND-INTERFACES.md — document them there',
    );
  });

  test('the module table attributes every symbol to the module that exports it', () => {
    const rows = [...DOC.matchAll(/^\| `((?:core|utils)\/[\w-]+\.js)` \| (.+) \|$/gm)];
    assert.ok(rows.length >= 10, 'the module table has shrunk; it listed ten modules');

    const wrong = [];
    for (const [, file, cell] of rows) {
      const real = exportsOf(file);
      for (const m of cell.matchAll(/`([A-Za-z_$][\w$]*)/g)) {
        if (!real.has(m[1])) wrong.push(`${file} does not export ${m[1]}`);
      }
    }
    assert.deepEqual(wrong, [], 'a symbol is documented under the wrong module');
  });
});

describe('the interface map transcribes the enums correctly', () => {
  test('the six shared enums match key-for-key and value-for-value', () => {
    assert.deepEqual(transcribedEnum('STATUS'), { ...rules.STATUS });
    assert.deepEqual(transcribedEnum('TYPE'), { ...rules.TYPE });
    assert.deepEqual(transcribedEnum('VERDICT'), { ...rules.VERDICT });
    assert.deepEqual(transcribedEnum('SEVERITY'), { ...rules.SEVERITY });
    assert.deepEqual(transcribedEnum('CHECK'), { ...rules.CHECK });
    assert.deepEqual(transcribedEnum('CACHE_STATE'), { ...CACHE_STATE });
  });

  test('MSP and the log levels match', () => {
    assert.deepEqual(transcribedEnum('MSP'), { ...MSP });
    assert.deepEqual(transcribedEnum('LEVELS'), { ...LEVELS });
  });

  test('the role list, the pharmacy statuses and the API key pattern match', () => {
    const roleBlock = DOC.match(/ROLE\s*=\s*\{([^}]*)\}/);
    assert.ok(roleBlock, 'the map no longer lists ROLE');
    const documentedRoles = roleBlock[1].split(',').map((s) => s.trim()).filter(Boolean);
    assert.deepEqual(documentedRoles.sort(), Object.keys(rules.ROLE).sort());

    const statuses = DOC.match(/PHARMACY_STATUSES\s*=\s*\[([^\]]*)\]/);
    assert.ok(statuses, 'the map no longer lists PHARMACY_STATUSES');
    assert.deepEqual(
      statuses[1].split(',').map((s) => s.trim().replace(/'/g, '')),
      [...rules.PHARMACY_STATUSES],
    );

    const pattern = DOC.match(/API_KEY_RE\s*=\s*\/(.+)\/\s*$/m);
    assert.ok(pattern, 'the map no longer quotes API_KEY_RE');
    assert.equal(pattern[1], rules.API_KEY_RE.source);
  });

  /**
   * §3.1 publishes the error vocabulary as a list, and the middleware maps each code to
   * a status. A code missing from the map is one a client will not know to handle.
   */
  test('every error code is listed in §3.1', () => {
    const section = DOC.match(/CODES\s+\/\/[^\n]*\n([\s\S]*?)\n\n/);
    assert.ok(section, 'the map no longer lists CODES');
    for (const code of Object.keys(CODES)) {
      assert.ok(section[1].includes(code), `${code} is missing from the map's CODES list`);
    }
  });
});

describe('the interface map describes the real driver interfaces', () => {
  const STORE_METHODS = [
    'insertApiKey', 'findApiKey', 'touchApiKey', 'revokeApiKey',
    'insertSensor', 'getSensor', 'revokeSensor',
    'insertReport', 'getReport', 'reportsForProduct', 'recentReports',
    'ping', 'close',
  ];
  const LEDGER_METHODS = [
    'medicineExists', 'getMedicine', 'verifyMedicine', 'allMedicines',
    'createMedicine', 'updateLocation', 'addTemperatureReading',
    'recordPatientScan', 'recallBatch', 'ping', 'close',
  ];
  const CACHE_METHODS = ['get', 'setVerify', 'del', 'reserveNonce', 'ping', 'close'];

  /**
   * The claim that makes `FABRIC_MOCK=1` possible: one method set per family, so
   * nothing above `createStore`/`createCache`/`createFabric` branches on the driver.
   * A method added to one half of a pair and not the other breaks mock mode or
   * production, and only one of those is exercised here.
   */
  test('the method sets the map documents are present on every driver', () => {
    for (const [label, proto, methods] of [
      ['MemoryStore', MemoryStore.prototype, STORE_METHODS],
      ['PostgresStore', PostgresStore.prototype, STORE_METHODS],
      ['MockLedger', MockLedger.prototype, LEDGER_METHODS],
      ['FabricGatewayClient', FabricGatewayClient.prototype, LEDGER_METHODS],
      ['MemoryCache', MemoryCache.prototype, CACHE_METHODS],
      ['RedisCache', RedisCache.prototype, CACHE_METHODS],
    ]) {
      for (const method of methods) {
        assert.equal(typeof proto[method], 'function', `${label} is missing ${method}()`);
      }
    }
  });

  test('the documented config paths exist with the documented values', () => {
    const { config } = stack();
    assert.equal(config.server.port, 8080);
    assert.equal(config.fabric.channel, 'truemed-channel');
    assert.equal(config.trust.reloadIntervalMs, 300000);
    assert.equal(config.sensor.nonceTtlS, 86400);
    assert.equal(config.rateLimit.reportPerHour, 10);
    assert.equal(config.redis.keyPrefix, 'verify:v1:');
    assert.equal(config.redis.ttl.terminalS, 3600);
    assert.equal(config.redis.ttl.activeS, 60);
    assert.equal(config.redis.ttl.negativeS, 30);
  });
});

describe('the interface map describes the real response shapes', () => {
  test('the on-chain record has exactly the keys the map lists', async () => {
    const s = stack();
    const { medicine } = signedUnit(s.trust);
    await s.supplyChain.mint(
      { ...medicine.toDict(), location: 'FACT_PUN_0001' },
      { role: 'manufacturer' },
    );

    const record = await s.fabric.getMedicine(medicine.productID);
    assert.deepEqual(Object.keys(record).sort(), [
      'batch_no', 'brand_name', 'cold_chain_breached', 'cold_chain_breached_at',
      'contract_version', 'created_at', 'created_by_msp', 'current_location',
      'custody_trail', 'distinct_scan_districts', 'doc_type', 'excipients',
      'expiry_date', 'first_scan_at', 'generic_name', 'last_scan_at', 'manufacturer',
      'mfg_date', 'mfg_licence_no', 'product_id', 'quantity', 'recall_reason',
      'recalled_at', 'scan_count', 'status', 'temp_max_c', 'temp_min_c',
      'temp_reading_count', 'temperature_history', 'type', 'updated_at',
    ]);
    assert.deepEqual(
      Object.keys(record.custody_trail[0]).sort(),
      ['actor_msp', 'location', 'status', 'timestamp'],
    );
  });

  test('MedicineData.toDict() is the mint body less its location', () => {
    const s = stack();
    const { medicine } = signedUnit(s.trust);
    assert.deepEqual(Object.keys(medicine.toDict()).sort(), [
      'batch_no', 'brand_name', 'contract_version', 'excipients', 'expiry_date',
      'generic_name', 'manufacturer', 'mfg_date', 'mfg_licence_no', 'product_id',
      'quantity', 'type',
    ]);
  });

  test('the three documented write responses have the documented keys', async () => {
    const s = stack();
    const { medicine } = signedUnit(s.trust);

    const mint = await s.supplyChain.mint(
      { ...medicine.toDict(), location: 'FACT_PUN_0001' },
      { role: 'manufacturer' },
    );
    assert.deepEqual(
      Object.keys(mint).sort(),
      ['location', 'product_id', 'status', 'timestamp', 'tx_id'],
    );

    const report = await s.reports.submit({ product_id: medicine.productID });
    assert.deepEqual(Object.keys(report).sort(), ['received_at', 'report_id']);

    const recall = await s.supplyChain.recall(
      { batch_no: medicine.batchNo, reason: 'failed dissolution testing' },
      { role: 'regulator' },
    );
    assert.deepEqual(Object.keys(recall).sort(), [
      'actor_msp', 'already_recalled', 'batch_no', 'more_remaining', 'product_ids',
      'recalled', 'recalled_at',
    ]);
  });

  test('the verify body is nested as §4.4 and the map describes it', async () => {
    const s = stack();
    const { wire, medicine } = signedUnit(s.trust);
    await s.supplyChain.mint(
      { ...medicine.toDict(), location: 'FACT_PUN_0001' },
      { role: 'manufacturer' },
    );

    const { body } = await s.verify.byPayload({ raw_payload: wire, district: 'Pune' });

    for (const key of ['verdict', 'severity', 'checks', 'medicine', 'cold_chain',
      'telemetry', 'custody_trail']) {
      assert.ok(key in body, `the verify body is missing ${key}`);
    }
    assert.deepEqual(
      Object.keys(body.checks).sort(),
      ['clone_telemetry', 'cold_chain', 'expiry', 'on_chain', 'signature'],
    );
    assert.deepEqual(
      Object.keys(body.cold_chain).sort(),
      ['applicable', 'breached', 'max_c', 'min_c', 'reading_count'],
    );
    assert.deepEqual(
      Object.keys(body.telemetry).sort(),
      ['distinct_districts', 'first_scan_at', 'scan_count'],
    );

    // §9.6: the signed fields are nested, and there is no top-level product_id.
    assert.equal('product_id' in body, false);
    assert.equal('status' in body, false);
    assert.equal(body.medicine.product_id, medicine.productID);
  });

  test('verifyWire returns exactly the keys the map lists', () => {
    const s = stack();
    const { wire } = signedUnit(s.trust);
    const result = verifyWire(wire, s.trust.liveView(), { today: FIXED_NOW });
    assert.deepEqual(Object.keys(result).sort(), [
      'checks', 'data', 'error', 'error_code', 'medicine', 'severity', 'valid',
      'verdict', 'warnings',
    ]);
  });
});

describe('the traps in §9 are real', () => {
  /** §9.1, the defect this section was written after. */
  test('verifyWire needs the bundle view, not the trust service', () => {
    const s = stack();
    const { wire } = signedUnit(s.trust);
    assert.throws(
      () => verifyWire(wire, s.trust, { today: FIXED_NOW }),
      /publicKeyFor is not a function/,
      'the service must not accidentally satisfy verifyWire',
    );
    assert.equal(typeof s.trust.liveView().publicKeyFor, 'function');
  });

  /** §9.2: the two fields named `contract_version` really are different things. */
  test('the ledger stamps a build string where the payload carries the int 1', async () => {
    const s = stack();
    const { medicine } = signedUnit(s.trust);
    await s.supplyChain.mint(
      { ...medicine.toDict(), location: 'FACT_PUN_0001' },
      { role: 'manufacturer' },
    );
    const record = await s.fabric.getMedicine(medicine.productID);
    assert.equal(typeof record.contract_version, 'string');
    assert.equal(medicine.toDict().contract_version, 1);
  });

  /** §9.7: a route reading `err.details.retry_after_s` would send no Retry-After. */
  test('a rate-limit error carries the delay on retryAfter', () => {
    const err = rateLimited(42);
    assert.equal(err.retryAfter, 42);
    assert.equal(err.details?.retry_after_s, undefined);
  });

  /** §9.9: the chaincode cannot tell a chemist from a distributor. */
  test('a pharmacy submits to Fabric as DistributorMSP', () => {
    assert.equal(mspForRole('pharmacy'), MSP.DISTRIBUTOR);
    assert.equal(mspForRole('pharmacy'), mspForRole('distributor'));
  });

  /** §9.11: a mistyped enum key is `undefined`, which compares equal to nothing real. */
  test('the verdict keys the map warns about do not exist', () => {
    assert.equal(rules.VERDICT.COLD_CHAIN_BREACH, undefined);
    assert.equal(rules.VERDICT.COLD_CHAIN, 'COLD_CHAIN_BREACH');
    assert.equal(rules.VERDICT.SIGNATURE_VALID_OFFLINE, undefined);
    assert.equal(rules.VERDICT.OFFLINE_OK, 'SIGNATURE_VALID_OFFLINE');
  });

  /** §9.12: the transaction id arrives through the context, not the return value. */
  test('a ledger write fills in the receipt it is handed', async () => {
    const s = stack();
    const { medicine } = signedUnit(s.trust);
    await s.supplyChain.mint(
      { ...medicine.toDict(), location: 'FACT_PUN_0001' },
      { role: 'manufacturer' },
    );

    const receipt = {};
    await s.fabric.recordPatientScan(
      { product_id: medicine.productID, district: 'Nagpur' },
      { receipt },
    );
    assert.match(String(receipt.tx_id), /^mock:/);
  });

  /** §9.13: four class names do not match their filenames. */
  test('the driver classes really live in the files the map names', () => {
    assert.ok(exportsOf('db/postgres.js').has('PostgresStore'));
    assert.ok(exportsOf('fabric/gateway-client.js').has('FabricGatewayClient'));
    assert.ok(exportsOf('cache/memory.js').has('MemoryCache'));
    assert.ok(exportsOf('cache/redis.js').has('RedisCache'));
    // And the trap itself: the vocabulary is split across two modules.
    assert.ok(exportsOf('fabric/index.js').has('mspForRole'));
    assert.equal(exportsOf('core/rules.js').has('mspForRole'), false);
  });

  /** §4: the report row has no verdict column, so the verdict is logged only. */
  test('a submitted payload verdict is not stored on the report', async () => {
    const s = stack();
    const { wire, medicine } = signedUnit(s.trust);
    const { report_id: id } = await s.reports.submit({ raw_payload: wire });
    const row = await s.store.getReport(id);
    assert.equal('payload_verdict' in row, false);
    assert.equal(row.product_id, medicine.productID);
  });
});

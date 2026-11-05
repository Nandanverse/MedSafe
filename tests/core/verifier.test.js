/**
 * Cross-language verification tests.
 *
 * Every wire string in fixtures.json was signed by the **Python** implementation
 * in qr-generator/, and every expectation was confirmed against the **Python**
 * verifier before this file existed. That ordering is the point: it makes these
 * tests a check that Node agrees with the reference implementation, rather than a
 * check that Node agrees with itself. A suite built from Node-signed data would
 * pass happily while the two languages disagreed about canonical JSON, base64url
 * or signature encoding — and the first symptom in production would be a patient
 * seeing COUNTERFEIT on genuine medicine.
 *
 * Regenerate with:
 *   python3 backend/tests/fixtures/generate-fixtures.py
 */

import { test, describe, before } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import { TrustBundle } from '../../src/core/trust-bundle.js';
import { MedicineData } from '../../src/core/payload.js';
import { verifyWire, mergeOnlineEvidence } from '../../src/core/verifier.js';
import { CODES } from '../../src/core/errors.js';
import { VERDICT, CHECK, STATUS } from '../../src/core/rules.js';

const fixtures = JSON.parse(
  readFileSync(new URL('../fixtures/fixtures.json', import.meta.url), 'utf8'),
);

/** Pinned so expiry expectations never drift with the wall clock. */
const TODAY = new Date(`${fixtures.reference_date}T00:00:00Z`);

let bundle;

before(() => {
  bundle = TrustBundle.fromJSON(JSON.stringify(fixtures.trust_bundle_signed), {
    rootPublicKey: fixtures.root_public_key_pem,
    requireSignature: true,
  });
});

describe('trust bundle', () => {
  test('loads the signed bundle and verifies the root signature', () => {
    assert.equal(bundle.size, fixtures.trust_bundle_signed.keys.length);
    assert.equal(bundle.rootFingerprint, fixtures.root_fingerprint);
    assert.equal(bundle.summary().signed, true);
  });

  test('every entry PEM hashes to the fingerprint it claims', () => {
    for (const entry of bundle.keys) {
      assert.doesNotThrow(() => entry.publicKey(), `licence ${entry.mfgLicenceNo}`);
    }
  });

  test('resolves the active manufacturer licences', () => {
    for (const licence of [
      fixtures.licences.active_medicine,
      fixtures.licences.active_vaccine,
    ]) {
      assert.ok(bundle.publicKeyFor(licence, TODAY), `licence ${licence}`);
    }
  });

  test('refuses a revoked licence with SIGNATURE_KEY_UNKNOWN', () => {
    assert.throws(
      () => bundle.publicKeyFor(fixtures.licences.revoked, TODAY),
      (err) => err.code === CODES.SIGNATURE_KEY_UNKNOWN,
    );
  });

  test('refuses a licence that is not in the bundle at all', () => {
    assert.throws(
      () => bundle.publicKeyFor(fixtures.licences.unregistered, TODAY),
      (err) => err.code === CODES.SIGNATURE_KEY_UNKNOWN,
    );
  });

  test('rejects an unsigned bundle when a signature is required', () => {
    assert.throws(() =>
      TrustBundle.fromJSON(JSON.stringify(fixtures.trust_bundle_unsigned), {
        rootPublicKey: fixtures.root_public_key_pem,
        requireSignature: true,
      }),
    );
  });

  test('accepts an unsigned bundle only when explicitly told to', () => {
    const dev = TrustBundle.fromJSON(
      JSON.stringify(fixtures.trust_bundle_unsigned),
      { requireSignature: false },
    );
    assert.equal(dev.summary().signed, false);
  });

  test('rejects a forged root signature', () => {
    assert.throws(
      () =>
        TrustBundle.fromJSON(
          JSON.stringify(fixtures.trust_bundle_forged_signature),
          { rootPublicKey: fixtures.root_public_key_pem, requireSignature: true },
        ),
      (err) => err.code === CODES.SIGNATURE_INVALID,
    );
  });

  /**
   * The attack the root signature exists to stop: an extra manufacturer key
   * spliced into an otherwise genuine bundle. If this ever passes, anyone who can
   * serve /api/public-keys can mint QR codes that verify perfectly.
   */
  test('rejects a bundle with an injected key', () => {
    assert.throws(
      () =>
        TrustBundle.fromJSON(JSON.stringify(fixtures.trust_bundle_injected_key), {
          rootPublicKey: fixtures.root_public_key_pem,
          requireSignature: true,
        }),
      (err) => err.code === CODES.SIGNATURE_INVALID,
    );
  });

  test('requires a root key rather than silently trusting the bundle', () => {
    assert.throws(() =>
      TrustBundle.fromJSON(JSON.stringify(fixtures.trust_bundle_signed), {
        requireSignature: true,
      }),
    );
  });
});

describe('canonical JSON matches Python byte for byte', () => {
  for (const sample of fixtures.canonical_json_samples) {
    test(sample.product_id, () => {
      const medicine = MedicineData.fromDict(sample.full_names);
      const bytes = medicine.canonicalJSON();
      assert.equal(
        bytes.toString('hex'),
        sample.canonical_json_utf8_hex,
        'Node canonical JSON differs from the bytes Python signed',
      );
      assert.equal(bytes.length, sample.byte_length);
    });
  }
});

describe('offline verification against Python-signed fixtures', () => {
  for (const testCase of fixtures.cases) {
    test(`${testCase.name} — ${testCase.note}`, () => {
      const got = verifyWire(testCase.wire, bundle, { today: TODAY });
      const want = testCase.expect;

      assert.equal(got.verdict, want.verdict, 'verdict');
      assert.equal(got.valid, want.valid, 'valid');
      assert.equal(got.severity, want.severity, 'severity');
      assert.equal(got.error_code, want.error_code, 'error_code');

      for (const [check, expected] of Object.entries(want.checks ?? {})) {
        assert.equal(got.checks[check], expected, `checks.${check}`);
      }

      if (want.product_id) {
        assert.equal(got.data?.product_id, want.product_id, 'data.product_id');
      }

      // A failing verdict must always carry a human-readable reason, and a
      // passing one must not invent an error.
      if (want.valid) {
        assert.equal(got.error, null, 'a valid result must have no error');
      } else {
        assert.ok(got.error, 'an invalid result must explain itself');
      }
    });
  }

  test('all 26 fixture cases ran', () => {
    assert.equal(fixtures.cases.length, 26);
  });
});

describe('offline verification never returns an unqualified GENUINE', () => {
  test('a perfect offline scan is SIGNATURE_VALID_OFFLINE at warn', () => {
    const genuine = fixtures.cases.find((c) => c.name === 'genuine_medicine_offline');
    const got = verifyWire(genuine.wire, bundle, { today: TODAY });
    assert.equal(got.verdict, VERDICT.OFFLINE_OK);
    assert.equal(got.severity, 'warn');
    assert.notEqual(got.verdict, VERDICT.GENUINE);
    assert.ok(
      got.warnings.some((w) => w.startsWith('Offline verification only')),
      'the offline caveat must be stated, not implied',
    );
  });

  test('checks 4 and 5 are reported as skipped, not as passing', () => {
    const genuine = fixtures.cases.find((c) => c.name === 'genuine_vaccine_offline');
    const got = verifyWire(genuine.wire, bundle, { today: TODAY });
    assert.equal(got.checks.on_chain, CHECK.SKIPPED_OFFLINE);
    assert.equal(got.checks.cold_chain, CHECK.SKIPPED_OFFLINE);
    assert.equal(got.checks.clone_telemetry, CHECK.SKIPPED_OFFLINE);
  });

  test('a code expiring soon warns without failing', () => {
    const soon = fixtures.cases.find((c) => c.name === 'expiring_within_30_days');
    const got = verifyWire(soon.wire, bundle, { today: TODAY });
    assert.equal(got.valid, true);
    assert.ok(
      got.warnings.some((w) => w.startsWith('Expires in')),
      'an imminent expiry must be surfaced',
    );
  });
});

describe('merging online evidence', () => {
  const offlineFor = (name) =>
    verifyWire(
      fixtures.cases.find((c) => c.name === name).wire,
      bundle,
      { today: TODAY },
    );

  test('a signed, on-chain, in-date medicine is GENUINE at ok', () => {
    const got = mergeOnlineEvidence(offlineFor('genuine_medicine_offline'), {
      onChain: true,
      status: STATUS.AT_PHARMACY,
      today: TODAY,
    });
    assert.equal(got.verdict, VERDICT.GENUINE);
    assert.equal(got.severity, 'ok');
    assert.equal(got.valid, true);
    assert.equal(got.error, null);
    assert.equal(got.checks.on_chain, CHECK.PASS);
    // A medicine has no cold chain to breach, which is different from passing one.
    assert.equal(got.checks.cold_chain, CHECK.NOT_APPLICABLE);
    assert.equal(
      got.warnings.some((w) => w.startsWith('Offline verification only')),
      false,
      'the offline caveat must be dropped once chain evidence exists',
    );
  });

  test('a valid signature that is absent from the chain is COUNTERFEIT', () => {
    const got = mergeOnlineEvidence(offlineFor('genuine_medicine_offline'), {
      onChain: false,
      today: TODAY,
    });
    assert.equal(got.verdict, VERDICT.COUNTERFEIT);
    assert.equal(got.severity, 'critical');
    assert.equal(got.checks.on_chain, CHECK.FAIL);
    assert.match(got.error, /leaked signing key/);
  });

  test('a recalled batch is RECALLED at critical', () => {
    const got = mergeOnlineEvidence(offlineFor('genuine_medicine_offline'), {
      onChain: true,
      status: STATUS.RECALLED,
      today: TODAY,
    });
    assert.equal(got.verdict, VERDICT.RECALLED);
    assert.equal(got.error_code, CODES.RECALLED);
  });

  test('a vaccine outside 2–8 °C is COLD_CHAIN_BREACH with the range named', () => {
    const got = mergeOnlineEvidence(offlineFor('genuine_vaccine_offline'), {
      onChain: true,
      status: STATUS.IN_TRANSIT,
      temperatureReadings: [
        { temperature: 4.2 },
        { temperature: 11.7 },
        { temperature: 5.0 },
      ],
      today: TODAY,
    });
    assert.equal(got.verdict, VERDICT.COLD_CHAIN);
    assert.equal(got.checks.cold_chain, CHECK.FAIL);
    assert.match(got.error, /4\.2°C to 11\.7°C/);
  });

  test('the chaincode breach flag outranks the readings we happen to have', () => {
    // The embedded readings are a bounded recent window; the flag was computed
    // over the whole history. A breach that has scrolled out of the window is
    // still a breach.
    const got = mergeOnlineEvidence(offlineFor('genuine_vaccine_offline'), {
      onChain: true,
      status: STATUS.AT_PHARMACY,
      temperatureReadings: [{ temperature: 4.0 }, { temperature: 5.0 }],
      coldChainBreached: true,
      today: TODAY,
    });
    assert.equal(got.verdict, VERDICT.COLD_CHAIN);
  });

  test('a vaccine with no readings is unconfirmed, not passed', () => {
    const got = mergeOnlineEvidence(offlineFor('genuine_vaccine_offline'), {
      onChain: true,
      status: STATUS.MANUFACTURED,
      temperatureReadings: [],
      today: TODAY,
    });
    assert.equal(got.checks.cold_chain, CHECK.SKIPPED_OFFLINE);
    assert.ok(got.warnings.some((w) => w.includes('unconfirmed')));
  });

  test('scan count over the threshold is CLONE_SUSPECTED', () => {
    const got = mergeOnlineEvidence(offlineFor('genuine_medicine_offline'), {
      onChain: true,
      status: STATUS.DISPENSED,
      scanCount: 412,
      distinctDistricts: 14,
      today: TODAY,
    });
    assert.equal(got.verdict, VERDICT.CLONE);
    assert.equal(got.checks.clone_telemetry, CHECK.FAIL);
    assert.match(got.error, /412 times across 14 districts/);
  });

  test('districts alone can trip clone detection', () => {
    // One physical pack cannot be in five districts, however few times it was
    // scanned in each.
    const got = mergeOnlineEvidence(offlineFor('genuine_medicine_offline'), {
      onChain: true,
      status: STATUS.AT_PHARMACY,
      scanCount: 5,
      distinctDistricts: 5,
      today: TODAY,
    });
    assert.equal(got.verdict, VERDICT.CLONE);
  });

  test('a handful of scans in one district is normal', () => {
    const got = mergeOnlineEvidence(offlineFor('genuine_medicine_offline'), {
      onChain: true,
      status: STATUS.AT_PHARMACY,
      scanCount: 4,
      distinctDistricts: 1,
      today: TODAY,
    });
    assert.equal(got.verdict, VERDICT.GENUINE);
    assert.equal(got.checks.clone_telemetry, CHECK.PASS);
  });

  test('precedence: a recall outranks a cold chain breach', () => {
    const got = mergeOnlineEvidence(offlineFor('genuine_vaccine_offline'), {
      onChain: true,
      status: STATUS.RECALLED,
      temperatureReadings: [{ temperature: 14.0 }],
      today: TODAY,
    });
    assert.equal(got.verdict, VERDICT.RECALLED);
    // Both failures are still reported, even though only one sets the verdict.
    assert.match(got.error, /recalled/);
    assert.match(got.error, /cold chain breach/);
  });

  test('precedence: not-on-chain outranks everything else', () => {
    const got = mergeOnlineEvidence(offlineFor('genuine_vaccine_offline'), {
      onChain: false,
      temperatureReadings: [{ temperature: 14.0 }],
      scanCount: 999,
      distinctDistricts: 20,
      today: TODAY,
    });
    assert.equal(got.verdict, VERDICT.COUNTERFEIT);
  });

  test('an expired medicine that is otherwise fine stays EXPIRED', () => {
    const got = mergeOnlineEvidence(offlineFor('expired_medicine'), {
      onChain: true,
      status: STATUS.AT_PHARMACY,
      today: TODAY,
    });
    assert.equal(got.verdict, VERDICT.EXPIRED);
    assert.equal(got.severity, 'warn');
    assert.match(got.error, /expired/);
  });

  test('chain data cannot rescue a forged signature', () => {
    const offline = offlineFor('tampered_signature');
    const got = mergeOnlineEvidence(offline, {
      onChain: true,
      status: STATUS.AT_PHARMACY,
      scanCount: 1,
      distinctDistricts: 1,
      today: TODAY,
    });
    assert.equal(got.verdict, VERDICT.COUNTERFEIT);
    assert.deepEqual(got, offline, 'the offline result must pass through untouched');
  });

  test('chain data cannot upgrade an unverifiable code', () => {
    const offline = offlineFor('signed_by_unregistered_key');
    const got = mergeOnlineEvidence(offline, {
      onChain: true,
      status: STATUS.AT_PHARMACY,
      today: TODAY,
    });
    assert.equal(got.verdict, VERDICT.UNVERIFIABLE);
    assert.deepEqual(got, offline);
  });

  test('the online result carries the chain fields the app displays', () => {
    const got = mergeOnlineEvidence(offlineFor('genuine_medicine_offline'), {
      onChain: true,
      status: STATUS.AT_PHARMACY,
      scanCount: 3,
      distinctDistricts: 1,
      today: TODAY,
    });
    assert.equal(got.data.status, STATUS.AT_PHARMACY);
    assert.equal(got.data.scan_count, 3);
    assert.equal(got.data.distinct_districts, 1);
    assert.equal(typeof got.data.signing_key_fingerprint, 'string');
    assert.equal(got.data.signing_key_fingerprint.length, 16);
  });
});

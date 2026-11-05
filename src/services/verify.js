/**
 * Verification: `GET /api/verify/:productID` and `POST /api/verify/payload`.
 *
 * This is the endpoint a patient's phone hits in a pharmacy, so it is the one
 * path in TrueMed where being wrong has a physical consequence. Everything here
 * is arranged around two rules from the contract.
 *
 * **A failed verification is a successful request.** EXPIRED, RECALLED,
 * COLD_CHAIN_BREACH and CLONE_SUSPECTED all return HTTP 200 with `ok: true` and
 * the verdict in the body (§2.4). Only a protocol problem — a malformed product
 * ID, a missing payload, an unreachable ledger — is an HTTP failure. Modelling a
 * recalled batch as a 4xx would be the obvious implementation and it would be
 * wrong: an app's error handler would show "request failed, try again" for the
 * one answer the patient most needs to read.
 *
 * **The verdict is computed in `core/verifier.js`, never here.** That module is a
 * port of `verifier.py`, which is the authoritative definition of "verified", and
 * the Dart client mirrors it check for check. A service that recomputed any part
 * of the precedence would give three implementations two chances to disagree. So
 * this file gathers evidence, hands it to `mergeOnlineEvidence`, and shapes the
 * §4.4 response around whatever comes back.
 *
 * The two endpoints differ in exactly one way that matters. A full signed `TM1`
 * string is evidence that a physical strip was scanned, so `POST /verify/payload`
 * submits `RecordPatientScan` and its result feeds clone detection. A bare product
 * ID in a URL is not such evidence, so `GET /verify/:productID` is a pure read —
 * otherwise anyone with a product ID and a loop could inflate another unit's scan
 * telemetry into a false CLONE_SUSPECTED and strand genuine stock (§7.1,
 * 2026-08-22).
 */

import { CACHE_STATE } from '../cache/index.js';
import { CODES, isTrueMedError, notOnChain, validationError } from '../core/errors.js';
import { MedicineData } from '../core/payload.js';
import { mergeOnlineEvidence, verifyWire } from '../core/verifier.js';
import { CHECK, STATUS, VERDICT, severityFor, validateProductID } from '../core/rules.js';

/** §4.6: `dispensed` and `recalled` are terminal, so their answers cache for an hour. */
const TERMINAL_STATUSES = new Set([STATUS.DISPENSED, STATUS.RECALLED]);

/**
 * What a negative cache entry looks like (§4.6, 30 s).
 *
 * A sentinel rather than a cached error envelope: the envelope carries a request
 * id and a `took_ms` that belong to the request that missed, and replaying those
 * to a later caller would put another request's identifiers in their logs.
 */
const NEGATIVE = { not_on_chain: true };

/**
 * The `cold_chain` block of §4.4.
 *
 * `min_c`/`max_c` are null — not 0 — when nothing has been recorded. Both the
 * chaincode and the mock initialise the aggregates to zero, and 0 °C is a
 * *plausible temperature that would itself be a breach*, so passing the raw field
 * through would show "0.0 °C recorded, out of range" for a vaccine that has never
 * been measured. `reading_count` is what distinguishes the two, and the client
 * relies on it: `ColdChainStatus.isUnmonitored` in `models.dart` is
 * `applicable && readingCount == 0`.
 */
function coldChainBlock(record, medicine) {
  if (!medicine?.isVaccine) {
    return { applicable: false, breached: false, min_c: null, max_c: null, reading_count: 0 };
  }
  const count = Number(record?.temp_reading_count ?? 0);
  const measured = Number.isFinite(count) && count > 0;
  return {
    applicable: true,
    breached: Boolean(record?.cold_chain_breached),
    min_c: measured ? Number(record.temp_min_c) : null,
    max_c: measured ? Number(record.temp_max_c) : null,
    reading_count: measured ? count : 0,
  };
}

/** The `telemetry` block of §4.4. */
function telemetryBlock(record) {
  const districts = Array.isArray(record?.distinct_scan_districts)
    ? record.distinct_scan_districts.length
    : 0;
  return {
    scan_count: Number(record?.scan_count ?? 0),
    distinct_districts: districts,
    // Empty string is how the ledger spells "never", but the client's field is
    // nullable and an empty timestamp would render as a blank date row.
    first_scan_at: record?.first_scan_at || null,
  };
}

/**
 * The `custody_trail` block of §4.4, projected to the four fields the contract
 * publishes rather than passed through.
 *
 * A ledger record may grow internal fields, and this array is what a pharmacist
 * and a patient see; forwarding whatever the chaincode happens to store would
 * leak the next such field into a public, unauthenticated response.
 */
function custodyTrailBlock(record) {
  const trail = Array.isArray(record?.custody_trail) ? record.custody_trail : [];
  return trail.map((event) => ({
    status: event?.status ?? null,
    location: event?.location ?? null,
    timestamp: event?.timestamp ?? null,
    actor_msp: event?.actor_msp ?? null,
  }));
}

/**
 * The `medicine` block of §4.4: the signed fields, plus the mutable chain state.
 *
 * The signed fields come from `MedicineData`, so what is shown is what was signed
 * — for `POST /verify/payload` that is the strip in the patient's hand, not the
 * ledger's copy of it. The two agree for genuine stock; when they do not, the
 * signature check has already failed and the verdict says so.
 */
function medicineBlock(record, medicine, today) {
  if (!medicine) return null;
  const block = medicine.toDict();
  block.status = record?.status ?? null;
  block.current_location = record?.current_location ?? null;
  block.days_to_expiry = medicine.daysToExpiry(today);
  return block;
}

/**
 * The `checks` block of §4.4: exactly the five keys the contract publishes.
 *
 * Projected rather than spread, for the same reason as `custody_trail`. The
 * verifier tracks a sixth check internally — `structure`, whether the `TM1`
 * framing decoded at all — and §4.4 does not list it. Spreading would publish it,
 * and an undocumented field in a public response is one the Dart client will
 * eventually depend on; three implementations of one rulebook only stay in step if
 * the wire shape is exactly what the contract says. Nothing is lost by omitting
 * it: a failed structure check always produces UNVERIFIABLE or COUNTERFEIT with
 * the reason spelled out in `error.message`.
 */
function checksBlock(checks) {
  const source = checks ?? {};
  const at = (key) => source[key] ?? CHECK.NOT_EVALUATED;
  return {
    signature: at('signature'),
    on_chain: at('on_chain'),
    expiry: at('expiry'),
    cold_chain: at('cold_chain'),
    clone_telemetry: at('clone_telemetry'),
  };
}

/**
 * Assemble the §4.4 `data` object.
 *
 * Deliberately not `verifier.toResponseBody()`. That function returns the flat
 * shape `verifier.py` produces for its own callers; §4.4 is a nested shape with
 * `medicine`, `cold_chain`, `telemetry` and `custody_trail`, and the client parses
 * exactly that. The verdict, severity and checks are taken verbatim from the
 * verification — this function shapes, it never decides.
 */
export function verifyBody(verification, record, today) {
  const medicine = verification.medicine ?? null;
  const body = {
    verdict: verification.verdict,
    severity: verification.severity ?? severityFor(verification.verdict),
    checks: checksBlock(verification.checks),
    medicine: medicineBlock(record, medicine, today),
    cold_chain: coldChainBlock(record, medicine),
    telemetry: telemetryBlock(record),
    custody_trail: custodyTrailBlock(record),
  };

  if (Array.isArray(verification.warnings) && verification.warnings.length) {
    body.warnings = [...verification.warnings];
  }

  // A failing verdict inside a 200 envelope carries its reason twice, because the
  // client reads both shapes (`models.dart`: `error_code` at the top level, or
  // `error.code`/`error.message` from the nested object). The nested object is the
  // only place a human-readable message can live, and that message is what the
  // patient is actually shown.
  if (verification.error_code) body.error_code = verification.error_code;
  if (verification.error) {
    body.error = {
      code: verification.error_code ?? CODES.INTERNAL_ERROR,
      message: verification.error,
    };
  }
  return body;
}

/**
 * Evidence for `mergeOnlineEvidence`, read off a ledger record.
 *
 * `coldChainBreached` is passed through from the record rather than recomputed
 * from `temperature_history`, because the record embeds only the most recent
 * window of readings (§3.7) while the chaincode's flag was computed over the
 * whole series and is sticky. Recomputing from the window would silently clear a
 * breach as soon as 48 good readings pushed the bad one out of view.
 */
function evidenceFrom(record, today) {
  return {
    onChain: Boolean(record),
    status: record?.status ?? null,
    temperatureReadings: Array.isArray(record?.temperature_history)
      ? record.temperature_history
      : [],
    coldChainBreached: record ? Boolean(record.cold_chain_breached) : null,
    scanCount: Number(record?.scan_count ?? 0),
    distinctDistricts: Array.isArray(record?.distinct_scan_districts)
      ? record.distinct_scan_districts.length
      : 0,
    today,
  };
}

/**
 * A stand-in offline result for the no-payload path.
 *
 * `GET /verify/:productID` has no signature to check, so `checks.signature` is
 * `skipped_no_payload` (§4.4) and the medicine is reconstructed from the ledger
 * record. Expiry is evaluated here because `mergeOnlineEvidence` does not perform
 * check 3 — it only honours an EXPIRED verdict that the offline pass already
 * reached — so leaving it unset would make expired stock read as GENUINE.
 */
function chainOnlyOffline(record, today) {
  // `contract_version` is deliberately dropped rather than passed through, because
  // the ledger record and the QR payload each have a field by that name and they
  // mean different things. On the payload it is the *wire format* version, an int
  // that §1.3 requires to be exactly 1 for a `TM1` prefix. On the chain record it is
  // the *chaincode build* that wrote the row — `"1.0.0"` from the Go contract, and
  // `"truemed-1.0"` from the mock ledger that mirrors it. Feeding the build string
  // into `MedicineData` makes it fail its own format check, so every genuine unit
  // would answer PAYLOAD_INVALID with a 400: the medicine is real, the record is
  // intact, and the patient is told the code is malformed. `fromDict` then applies
  // the payload default of 1, which is correct here — this object models what the
  // manufacturer signed, and the only signable version is 1.
  const { contract_version: _ledgerBuildVersion, ...payloadFields } = record;
  const medicine = MedicineData.fromDict(payloadFields);
  const checks = {
    signature: CHECK.SKIPPED_NO_PAYLOAD,
    expiry: CHECK.NOT_EVALUATED,
    on_chain: CHECK.NOT_EVALUATED,
    cold_chain: CHECK.NOT_EVALUATED,
    clone_telemetry: CHECK.NOT_EVALUATED,
  };

  const expired = medicine.isExpired(today);
  checks.expiry = expired ? CHECK.FAIL : CHECK.PASS;

  let verdict = VERDICT.GENUINE;
  let error = null;
  let errorCode = null;
  if (expired) {
    const days = -medicine.daysToExpiry(today);
    verdict = VERDICT.EXPIRED;
    error = `expired ${days} day${days === 1 ? '' : 's'} ago on ${medicine.expiryDate}`;
    errorCode = CODES.EXPIRED;
  }

  return {
    valid: !expired,
    verdict,
    severity: severityFor(verdict),
    error,
    error_code: errorCode,
    checks,
    warnings: [],
    data: null,
    medicine,
  };
}

/**
 * @param {{cache: object, fabric: object, trust: object,
 *          logger?: import('../utils/logger.js').Logger,
 *          clock?: () => Date}} deps
 */
export function makeVerifyService({ cache, fabric, trust, logger, clock = () => new Date() }) {
  /**
   * `GET /api/verify/:productID` — a pure read, cached per §4.6.
   *
   * @param {string} rawProductID
   * @returns {Promise<{body: object, cached: boolean}>}
   */
  async function byProductID(rawProductID) {
    // The shared validator, not a local copy: a product ID the Python signer
    // accepts but this rejects would show COUNTERFEIT on genuine medicine.
    const productID = validateProductID(rawProductID);

    const hit = await cache.get(productID);
    if (hit) {
      // A cached "not on chain" has to be re-thrown as the 404 it was, or a
      // negative entry would surface as a 200 with an empty body.
      if (hit.not_on_chain === true) throw notOnChain(productID);
      return { body: hit, cached: true };
    }

    const today = clock();
    const snapshot = await fabric.verifyMedicine(productID, today);
    if (!snapshot?.found || !snapshot.medicine) {
      await cache.setVerify(productID, NEGATIVE, CACHE_STATE.NEGATIVE);
      throw notOnChain(productID);
    }

    const record = snapshot.medicine;
    const verification = mergeOnlineEvidence(
      chainOnlyOffline(record, today),
      evidenceFrom(record, today),
    );
    const body = verifyBody(verification, record, today);

    await cache.setVerify(
      productID,
      body,
      TERMINAL_STATUSES.has(record.status) ? CACHE_STATE.TERMINAL : CACHE_STATE.ACTIVE,
    );
    return { body, cached: false };
  }

  /**
   * `POST /api/verify/payload` — signature plus chain, and the only endpoint that
   * records a patient scan (§7.1, 2026-08-22).
   *
   * @param {{raw_payload?: string, district?: string}} input
   * @returns {Promise<{body: object, cached: boolean}>}
   */
  async function byPayload(input) {
    const raw = input?.raw_payload;
    if (typeof raw !== 'string' || raw.trim() === '') {
      throw validationError(
        'raw_payload is required and must be the whole scanned string, exactly as ' +
          'the scanner read it',
      );
    }

    const today = clock();
    // Verified over the bytes as received (§1.5): no trimming beyond the outer
    // whitespace a scanner may add, no re-encoding. `decode` handles the framing.
    //
    // `trust.liveView()`, not `trust`: `verifyWire` wants something with a
    // `publicKeyFor`, and the trust *service* has no such member — passing it here
    // reads as harmless and fails only once a payload decodes far enough to need a
    // key, which is to say on every genuine QR code and on none of the malformed
    // ones. The view also tracks a bundle reload, which a captured bundle would not.
    const offline = verifyWire(raw, trust.liveView(), { today });

    // A forgery or an unreadable code cannot be rescued by chain data, and there
    // is no trustworthy product ID to look one up with — `mergeOnlineEvidence`
    // returns the offline result unchanged for both. Short-circuiting here also
    // means a stream of fabricated payloads cannot be used to drive ledger
    // queries, and records no scan against an ID we have no reason to believe.
    if (offline.verdict === VERDICT.COUNTERFEIT || offline.verdict === VERDICT.UNVERIFIABLE) {
      logger?.info?.('payload verification rejected offline', {
        verdict: offline.verdict,
        error_code: offline.error_code,
      });
      return { body: verifyBody(offline, null, today), cached: false };
    }

    const productID = offline.medicine.productID;

    // The scan is recorded before the evidence is read, and the write returns the
    // updated record — so the count the patient is shown includes their own scan,
    // in one round trip rather than a write followed by a read that could see a
    // different state.
    let record = null;
    try {
      record = await fabric.recordPatientScan(
        { product_id: productID, district: input?.district },
        {},
      );
    } catch (err) {
      // A valid signature over a unit that is not on the ledger is the leaked-key
      // case, and `mergeOnlineEvidence` turns `onChain: false` into COUNTERFEIT.
      // Any other failure is a real fault and must not be reported as a verdict.
      if (isTrueMedError(err) && err.code === CODES.NOT_ON_CHAIN) {
        record = null;
      } else {
        throw err;
      }
    }

    // §4.6 requires the cached verification to be dropped after a write to the
    // product. A scan is not in the section's list of three write endpoints, but
    // it does change `scan_count` and `distinct_districts`, and dropping the key
    // more often than required can only cost a cache hit — whereas serving stale
    // clone telemetry would hide the signal this endpoint exists to collect.
    if (record) await cache.del(productID);

    const verification = mergeOnlineEvidence(offline, evidenceFrom(record, today));
    return { body: verifyBody(verification, record, today), cached: false };
  }

  return { byProductID, byPayload };
}

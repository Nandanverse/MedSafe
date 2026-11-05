/**
 * Offline verification, and the fold of online evidence into a final verdict.
 *
 * Port of qr-generator/truemed_qr/verifier.py, which is the authoritative
 * definition of what "verified" means in TrueMed. The Dart implementation in
 * mobile/ mirrors it check for check, and this file is what the API's routes
 * call, so verdict precedence lives in one place per language rather than being
 * reimplemented per endpoint with three subtly different bugs.
 *
 * **What offline verification can and cannot prove.** A valid signature proves
 * the payload was produced by the holder of the private key registered to that
 * manufacturing licence. It does not prove the physical strip in the patient's
 * hand is genuine, because a counterfeiter can photograph one authentic strip and
 * reprint its perfectly-valid QR onto ten thousand fakes. Cloning is the standard
 * attack against every QR authentication scheme, and no amount of cryptography
 * applied to a static printed code prevents it.
 *
 * TrueMed's answer is on-chain scan telemetry — one sellable unit scanned four
 * hundred times across fourteen districts is almost certainly cloned — and that
 * signal only exists online. So a successful offline check yields
 * SIGNATURE_VALID_OFFLINE at severity `warn`, never GENUINE at `ok`. Rendering
 * offline success as an unqualified green tick would be a lie of omission in a
 * safety-critical interface.
 */

import { CODES, isTrueMedError } from './errors.js';
import { decode } from './codec.js';
import { MedicineData } from './payload.js';
import { fingerprint, verify } from './ecdsa.js';
import {
  CHECK,
  CLONE_DISTRICT_THRESHOLD,
  CLONE_SCAN_THRESHOLD,
  STATUS,
  VACCINE_TEMP_MAX_C,
  VACCINE_TEMP_MIN_C,
  VERDICT,
  severityFor,
  verdictToErrorCode,
  worstVerdict,
} from './rules.js';

const OFFLINE_CAVEAT =
  'Offline verification only. The signature is authentic, but duplicate-scan ' +
  'and cold-chain checks require an internet connection.';

/**
 * Build the `data` block of a verify response.
 *
 * @param {MedicineData|null} medicine
 */
function dataBlock(medicine, today, keyFingerprint) {
  if (!medicine) return null;
  const block = medicine.toDict();
  block.days_to_expiry = medicine.daysToExpiry(today);
  block.is_vaccine = medicine.isVaccine;
  if (keyFingerprint !== undefined && keyFingerprint !== null) {
    block.signing_key_fingerprint = keyFingerprint;
  }
  return block;
}

/**
 * @typedef {object} VerificationResult
 * @property {boolean} valid
 * @property {string} verdict
 * @property {string} severity
 * @property {string|null} error
 * @property {string|null} error_code
 * @property {Record<string,string>} checks
 * @property {string[]} warnings
 * @property {object|null} data
 * @property {MedicineData|null} medicine  not serialised; for internal callers
 */

function result({
  valid,
  verdict,
  error = null,
  errorCode = null,
  checks,
  warnings = [],
  data = null,
  medicine = null,
}) {
  return {
    valid,
    verdict,
    severity: severityFor(verdict),
    error,
    error_code: errorCode,
    checks,
    warnings,
    data,
    medicine,
  };
}

/** Every check starts as "not evaluated" and is only set once it actually runs. */
function freshChecks() {
  return {
    structure: CHECK.NOT_EVALUATED,
    signature: CHECK.NOT_EVALUATED,
    expiry: CHECK.NOT_EVALUATED,
    on_chain: CHECK.SKIPPED_OFFLINE,
    cold_chain: CHECK.SKIPPED_OFFLINE,
    clone_telemetry: CHECK.SKIPPED_OFFLINE,
  };
}

function failure(err, verdict, checks, medicine = null, today = undefined) {
  return result({
    valid: false,
    verdict,
    error: err.message,
    errorCode: err.code,
    checks,
    medicine,
    data: dataBlock(medicine, today),
  });
}

/**
 * Verify a scanned `TM1...` string offline: contract checks 1–3 (structure,
 * signature, expiry).
 *
 * Checks 4–5 (on-chain existence, cold chain) need the network; feed this result
 * to `mergeOnlineEvidence` once Fabric has answered.
 *
 * @param {string} wire
 * @param {import('./trust-bundle.js').TrustBundle} bundle
 * @param {{today?: Date}} [opts]
 * @returns {VerificationResult}
 */
export function verifyWire(wire, bundle, opts = {}) {
  const today = opts.today ?? new Date();
  const checks = freshChecks();

  // ── Check 1a: wire structure ──────────────────────────────────────────────
  let decoded;
  try {
    decoded = decode(wire);
  } catch (err) {
    if (!isTrueMedError(err)) throw err;
    // Both QR_MALFORMED and QR_UNKNOWN_VERSION land here as UNVERIFIABLE. An
    // unreadable code is not evidence of a counterfeit — it is far more often a
    // non-TrueMed QR or an app that predates the format.
    checks.structure = CHECK.FAIL;
    return failure(err, VERDICT.UNVERIFIABLE, checks);
  }

  // ── Check 1b: payload well-formedness ─────────────────────────────────────
  let medicine;
  try {
    medicine = MedicineData.fromCanonicalJSON(decoded.payloadBytes);
  } catch (err) {
    if (!isTrueMedError(err)) throw err;
    // A well-formed TM1 frame containing malformed data is not a misread. QR
    // error correction makes silent corruption that still parses as base64
    // vanishingly unlikely, so this is a fabrication attempt, not a bad scan.
    checks.structure = CHECK.FAIL;
    return failure(err, VERDICT.COUNTERFEIT, checks);
  }
  checks.structure = CHECK.PASS;

  // ── Check 2: signature ────────────────────────────────────────────────────
  let publicKey;
  try {
    publicKey = bundle.publicKeyFor(medicine.mfgLicenceNo, today);
  } catch (err) {
    if (!isTrueMedError(err) || err.code !== CODES.SIGNATURE_KEY_UNKNOWN) throw err;
    // Deliberately UNVERIFIABLE (amber), not COUNTERFEIT (red).
    //
    // A stale trust bundle is far more likely than a forgery here, and showing
    // red on genuine medicine because the app has not refreshed its keys would
    // destroy patient trust in the whole system — the failure mode that actually
    // kills adoption. Amber with "could not verify, update the app" is honest and
    // safe: nothing is asserted to be genuine.
    return failure(err, VERDICT.UNVERIFIABLE, checks, medicine, today);
  }

  const keyFingerprint = fingerprint(publicKey);

  // Verified over `decoded.payloadBytes` — the bytes as received. Never over
  // `medicine.canonicalJSON()`, which would be our re-serialisation of our own
  // parse and would let a parser/serialiser disagreement through.
  if (!verify(publicKey, decoded.payloadBytes, decoded.signature)) {
    checks.signature = CHECK.FAIL;
    return result({
      valid: false,
      verdict: VERDICT.COUNTERFEIT,
      error:
        'signature does not match this payload under the registered key for ' +
        `licence ${medicine.mfgLicenceNo} — treat as counterfeit`,
      errorCode: CODES.SIGNATURE_INVALID,
      checks,
      medicine,
      data: dataBlock(medicine, today),
    });
  }
  checks.signature = CHECK.PASS;

  // ── Check 3: expiry ───────────────────────────────────────────────────────
  if (medicine.isExpired(today)) {
    const days = -medicine.daysToExpiry(today);
    checks.expiry = CHECK.FAIL;
    return result({
      valid: false,
      verdict: VERDICT.EXPIRED,
      error: `expired ${days} day${days === 1 ? '' : 's'} ago on ${medicine.expiryDate}`,
      errorCode: CODES.EXPIRED,
      checks,
      medicine,
      data: dataBlock(medicine, today, keyFingerprint),
    });
  }
  checks.expiry = CHECK.PASS;

  // ── Offline path complete ─────────────────────────────────────────────────
  const warnings = [OFFLINE_CAVEAT];
  const daysLeft = medicine.daysToExpiry(today);
  if (daysLeft <= 30) {
    warnings.push(`Expires in ${daysLeft} days on ${medicine.expiryDate}.`);
  }

  return result({
    valid: true,
    verdict: VERDICT.OFFLINE_OK,
    checks,
    medicine,
    data: dataBlock(medicine, today, keyFingerprint),
    warnings,
  });
}

/**
 * Fold blockchain evidence into an offline result and recompute the verdict.
 *
 * @param {VerificationResult} offline result from `verifyWire`
 * @param {{
 *   onChain: boolean,
 *   status?: string|null,
 *   temperatureReadings?: Array<{temperature: number}>,
 *   coldChainBreached?: boolean|null,
 *   scanCount?: number,
 *   distinctDistricts?: number,
 *   today?: Date
 * }} evidence
 * @returns {VerificationResult}
 */
export function mergeOnlineEvidence(offline, evidence) {
  const {
    onChain,
    status = null,
    temperatureReadings = [],
    coldChainBreached = null,
    scanCount = 0,
    distinctDistricts = 0,
    today = new Date(),
  } = evidence;

  // A forged or unparseable code cannot be rescued by chain data.
  if (
    offline.verdict === VERDICT.COUNTERFEIT ||
    offline.verdict === VERDICT.UNVERIFIABLE
  ) {
    return offline;
  }

  const medicine = offline.medicine;
  const checks = { ...offline.checks };
  const verdicts = [];
  const errors = [];
  // The offline caveat no longer applies once we have chain evidence.
  const warnings = offline.warnings.filter((w) => !w.startsWith('Offline verification only'));

  if (offline.verdict === VERDICT.EXPIRED) {
    verdicts.push(VERDICT.EXPIRED);
    if (offline.error) errors.push(offline.error);
  }

  // ── Check 4: on chain, and not recalled ───────────────────────────────────
  if (!onChain) {
    checks.on_chain = CHECK.FAIL;
    verdicts.push(VERDICT.COUNTERFEIT);
    errors.push(
      'this product ID has a valid signature but does not exist on the ' +
        'blockchain, which should be impossible for genuine stock — most likely ' +
        'a QR minted with a leaked signing key',
    );
  } else {
    checks.on_chain = CHECK.PASS;
    if (status === STATUS.RECALLED) {
      verdicts.push(VERDICT.RECALLED);
      errors.push('this batch has been recalled by the regulator — do not use');
    }
  }

  // ── Check 5: cold chain (vaccines only) ───────────────────────────────────
  if (!medicine?.isVaccine) {
    checks.cold_chain = CHECK.NOT_APPLICABLE;
  } else {
    const temps = (temperatureReadings ?? [])
      .filter((r) => r && typeof r === 'object' && r.temperature !== undefined)
      .map((r) => Number(r.temperature))
      .filter((t) => Number.isFinite(t));

    // The chaincode's sticky breach flag is authoritative when supplied: it was
    // computed when the reading arrived, over the full history, and the embedded
    // readings we get back here are only the most recent window.
    const breached =
      coldChainBreached === null || coldChainBreached === undefined
        ? temps.some((t) => t < VACCINE_TEMP_MIN_C || t > VACCINE_TEMP_MAX_C)
        : Boolean(coldChainBreached);

    if (breached) {
      checks.cold_chain = CHECK.FAIL;
      verdicts.push(VERDICT.COLD_CHAIN);
      if (temps.length) {
        const lo = Math.min(...temps).toFixed(1);
        const hi = Math.max(...temps).toFixed(1);
        errors.push(
          `cold chain breach: readings ranged ${lo}°C to ${hi}°C, outside the ` +
            `required ${VACCINE_TEMP_MIN_C.toFixed(0)}–${VACCINE_TEMP_MAX_C.toFixed(0)}°C — ` +
            'this vaccine may have lost potency',
        );
      } else {
        errors.push(
          'cold chain breach recorded on the blockchain for this vaccine',
        );
      }
    } else if (!temps.length) {
      checks.cold_chain = CHECK.SKIPPED_OFFLINE;
      warnings.push(
        'No temperature readings recorded for this vaccine, so cold-chain ' +
          'integrity is unconfirmed.',
      );
    } else {
      checks.cold_chain = CHECK.PASS;
    }
  }

  // ── Clone telemetry ───────────────────────────────────────────────────────
  if (
    scanCount > CLONE_SCAN_THRESHOLD ||
    distinctDistricts > CLONE_DISTRICT_THRESHOLD
  ) {
    checks.clone_telemetry = CHECK.FAIL;
    verdicts.push(VERDICT.CLONE);
    errors.push(
      `this exact code has been scanned ${scanCount} times across ` +
        `${distinctDistricts} districts; one physical pack cannot be in that ` +
        'many places, so the QR has probably been copied onto counterfeit stock',
    );
  } else {
    checks.clone_telemetry = CHECK.PASS;
  }

  if (!verdicts.length) verdicts.push(VERDICT.GENUINE);

  const final = worstVerdict(verdicts);
  const keyFingerprint = offline.data?.signing_key_fingerprint ?? null;
  const data = dataBlock(medicine, today, keyFingerprint);
  if (data) {
    data.status = status;
    data.scan_count = scanCount;
    data.distinct_districts = distinctDistricts;
  }

  return result({
    valid: final === VERDICT.GENUINE,
    verdict: final,
    error: errors.length ? errors.join('; ') : null,
    errorCode: verdictToErrorCode(final),
    checks,
    medicine,
    data,
    warnings,
  });
}

/**
 * Response body for the verify endpoints: the result without the internal
 * `medicine` instance, which is a class and does not belong in JSON.
 */
export function toResponseBody(verification) {
  const { medicine: _ignored, ...body } = verification;
  return body;
}

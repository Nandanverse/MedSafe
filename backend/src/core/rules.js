/**
 * Shared rules, enums and limits.
 *
 * This is the Node mirror of `blockchain/chaincode/internal/rules/rules.go` and
 * of the constants in `qr-generator/truemed_qr/`. Three implementations of one
 * rulebook is a drift risk, so each language keeps its copy in exactly one file
 * and the values are cross-checked in tests rather than trusted.
 *
 * Nothing here touches the network, a database or Express, which is deliberate:
 * every rule a patient's verdict depends on is a pure function that can be
 * tested without any infrastructure at all.
 */

import { TrueMedError, CODES, validationError } from './errors.js';

// ── Enumerations ─────────────────────────────────────────────────────────────

/** Custody statuses. DATA-CONTRACT.md §3.1. */
export const STATUS = Object.freeze({
  MANUFACTURED: 'manufactured',
  IN_TRANSIT: 'in_transit',
  AT_PHARMACY: 'at_pharmacy',
  DISPENSED: 'dispensed',
  RECALLED: 'recalled',
});

export const TYPE = Object.freeze({ MEDICINE: 'medicine', VACCINE: 'vaccine' });

/**
 * API-key roles. DATA-CONTRACT.md §4.2.
 *
 * `PHARMA` and `PHARMACY` are different roles and the names are close enough to be
 * dangerous, which is why the contract spends a paragraph on them. `pharma` is a
 * manufacturer's read-only analytics key over its own batches; `pharmacy` is a
 * retail chemist's write key for exactly two custody transitions. Issuing the wrong
 * one either exposes a manufacturer's whole distribution picture to a shop, or lets
 * a manufacturer mark its own stock dispensed. Any tooling that prints this list
 * must print what each role means beside it.
 */
export const ROLE = Object.freeze({
  MANUFACTURER: 'manufacturer',
  DISTRIBUTOR: 'distributor',
  SENSOR: 'sensor',
  REGULATOR: 'regulator',
  PHARMA: 'pharma',
  PHARMACY: 'pharmacy',
});

/** What each role is for, so an operator issuing a key cannot confuse two of them. */
export const ROLE_PURPOSE = Object.freeze({
  [ROLE.MANUFACTURER]: 'mint units on chain and record custody hops',
  [ROLE.DISTRIBUTOR]: 'record custody hops and temperature readings in transit',
  [ROLE.SENSOR]: 'submit cold-box temperature readings (also needs a sensor secret)',
  [ROLE.REGULATOR]: 'recall batches and read the CDSCO dashboard',
  [ROLE.PHARMA]: "read-only analytics over ONE manufacturer's own batches",
  [ROLE.PHARMACY]: 'a retail chemist: record at_pharmacy and dispensed only',
});

export const ROLES = Object.freeze(Object.values(ROLE));

/**
 * Custody transitions a retail pharmacy may assert (§4.3).
 *
 * The role check on `POST /api/location` is not sufficient on its own: without this
 * list a chemist's key could rewind a unit to `in_transit` and reroute it. Role
 * gates the endpoint, this list gates the transition, and `validateTransition`
 * gates the direction. `rules.dart` carries the same list purely to produce a
 * faster error message; this copy is the one that is enforced.
 */
export const PHARMACY_STATUSES = Object.freeze([STATUS.AT_PHARMACY, STATUS.DISPENSED]);

/**
 * `tm_{role}_{32 hex}`, §4.2.
 *
 * The alternation lists `pharmacy` before `pharma`. The pattern is anchored at both
 * ends so either order matches correctly here, but a shorter-first alternation is a
 * trap for whoever next copies this regex somewhere without the anchors: `pharma`
 * would win against a pharmacy key and the role would be read as the manufacturer
 * analytics role. Longest-first costs nothing and removes the trap. `rules.dart`
 * orders it the same way for the same reason.
 */
export const API_KEY_RE =
  /^tm_(manufacturer|distributor|sensor|regulator|pharmacy|pharma)_[0-9a-f]{32}$/;

/** The role embedded in a well-formed API key, or null. */
export function roleOfApiKey(key) {
  if (typeof key !== 'string') return null;
  return API_KEY_RE.exec(key.trim())?.[1] ?? null;
}

/** Wire type flag → full name. `tp` in the QR payload. */
export const WIRE_TYPE = Object.freeze({ M: TYPE.MEDICINE, V: TYPE.VACCINE });
export const TYPE_WIRE = Object.freeze({
  [TYPE.MEDICINE]: 'M',
  [TYPE.VACCINE]: 'V',
});

export const VERDICT = Object.freeze({
  GENUINE: 'GENUINE',
  OFFLINE_OK: 'SIGNATURE_VALID_OFFLINE',
  EXPIRED: 'EXPIRED',
  COLD_CHAIN: 'COLD_CHAIN_BREACH',
  CLONE: 'CLONE_SUSPECTED',
  RECALLED: 'RECALLED',
  COUNTERFEIT: 'COUNTERFEIT',
  UNVERIFIABLE: 'UNVERIFIABLE',
});

export const SEVERITY = Object.freeze({
  OK: 'ok',
  WARN: 'warn',
  CRITICAL: 'critical',
});

/** DATA-CONTRACT.md §2.3. */
const SEVERITY_OF = Object.freeze({
  [VERDICT.GENUINE]: SEVERITY.OK,
  [VERDICT.OFFLINE_OK]: SEVERITY.WARN,
  [VERDICT.EXPIRED]: SEVERITY.WARN,
  [VERDICT.UNVERIFIABLE]: SEVERITY.WARN,
  [VERDICT.COLD_CHAIN]: SEVERITY.CRITICAL,
  [VERDICT.CLONE]: SEVERITY.CRITICAL,
  [VERDICT.RECALLED]: SEVERITY.CRITICAL,
  [VERDICT.COUNTERFEIT]: SEVERITY.CRITICAL,
});

/**
 * Most severe first. A bad signature makes every other field meaningless — the
 * batch number on a forged strip is whatever the forger typed — so it dominates.
 *
 * UNVERIFIABLE sits between EXPIRED and SIGNATURE_VALID_OFFLINE, matching
 * `_PRECEDENCE` in verifier.py. DATA-CONTRACT.md §2.3 originally listed only
 * seven verdicts here and left this one out; that omission is a bug, because a
 * list without UNVERIFIABLE sends `worstVerdict(['UNVERIFIABLE'])` to the
 * fallback below. Both are `warn`, so no colour changes — the ordering only
 * decides which message a patient reads. Contract updated to match (§7).
 */
const PRECEDENCE = Object.freeze([
  VERDICT.COUNTERFEIT,
  VERDICT.RECALLED,
  VERDICT.CLONE,
  VERDICT.COLD_CHAIN,
  VERDICT.EXPIRED,
  VERDICT.UNVERIFIABLE,
  VERDICT.OFFLINE_OK,
  VERDICT.GENUINE,
]);

/** Check outcomes reported in `data.checks`. */
export const CHECK = Object.freeze({
  PASS: 'pass',
  FAIL: 'fail',
  SKIPPED_OFFLINE: 'skipped_offline',
  NOT_APPLICABLE: 'not_applicable',
  NOT_EVALUATED: 'not_evaluated',
  SKIPPED_NO_PAYLOAD: 'skipped_no_payload',
});

// ── Thresholds ───────────────────────────────────────────────────────────────

/** WHO cold chain for routine vaccines. Inclusive at both ends. §3.3. */
export const VACCINE_TEMP_MIN_C = 2.0;
export const VACCINE_TEMP_MAX_C = 8.0;

/**
 * DS18B20 rated range. Outside it is a wiring fault, not a cold-chain event: a
 * disconnected one-wire bus reads -127 °C or +85 °C, and recording those as
 * breaches would bury real excursions under hardware noise.
 */
export const SENSOR_TEMP_MIN_C = -55.0;
export const SENSOR_TEMP_MAX_C = 125.0;

export const CLONE_SCAN_THRESHOLD = 25;
export const CLONE_DISTRICT_THRESHOLD = 3;

export const MAX_EMBEDDED_READINGS = 48;
export const MAX_CUSTODY_EVENTS = 64;

/**
 * The ceiling a recall may reach: one custody slot above the normal cap.
 *
 * Without the headroom the cap becomes a weapon. A distributor who fills a
 * unit's trail with 64 location hops would make every later recall of that batch
 * fail, and no retry could ever succeed — a stuck integration must not be able to
 * veto a safety recall. One slot suffices because recall is terminal: an
 * already-recalled unit is skipped, so this slot is claimed at most once per unit
 * and growth stays bounded. Mirrors `maxCustodyEventsRecall` in medicine.go.
 */
export const MAX_CUSTODY_EVENTS_RECALL = MAX_CUSTODY_EVENTS + 1;

export const MAX_DISTINCT_DISTRICTS = 32;
export const MAX_RECALL_PER_TX = 500;

/**
 * Index rows one recall reads, as opposed to the units it writes.
 *
 * Far larger than MAX_RECALL_PER_TX because the two bound different costs: the
 * write cap keeps a block a workable size, while this only stops one transaction
 * from reading an unbounded index. The scan must cover a whole realistic batch,
 * because a scan that stopped at the write cap would return the same prefix on
 * every call and never reach the units behind it. Mirrors `maxRecallScan` in
 * contract.go.
 */
export const MAX_RECALL_SCAN = 100000;

export const DEFAULT_PAGE_SIZE = 50;
export const MAX_PAGE_SIZE = 500;

/** Sensor clock tolerances, in milliseconds. §3.6. */
export const MAX_RECORDED_AT_SKEW_MS = 15 * 60 * 1000;
export const MAX_RECORDED_AT_AGE_MS = 30 * 24 * 60 * 60 * 1000;

/** Per-field character limits. Mirrors payload.py `_MAX_LEN` and rules.go. */
export const LIMITS = Object.freeze({
  product_id: 80,
  generic_name: 64,
  brand_name: 48,
  manufacturer: 120,
  mfg_licence_no: 32,
  batch_no: 24,
  quantity: 32,
  excipient: 40,
  excipients: 12,
  location: 32,
  sensor_id: 32,
  district: 48,
  state: 48,
  pharmacy_name: 120,
  reason: 200,
  notes: 500,
  reporter_contact: 120,
});

/**
 * Deliberately identical to `_PRODUCT_ID_RE` in payload.py, down to the
 * unbounded segments and the permissive 4-digit year.
 *
 * Validation of a *signed* field must never be stricter than the signer. If
 * Python will sign `AAAA…(50 chars)_BRAND_2100_000001` and Node rejects it, the
 * patient sees COUNTERFEIT on genuine medicine — the one failure mode that
 * destroys trust in the whole system. Overall length is bounded by
 * LIMITS.product_id instead, exactly as Python bounds it.
 */
const PRODUCT_ID_RE = /^[A-Z0-9]+_[A-Z0-9]+_\d{4}_\d{6}$/;
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const LOCATION_RE = /^[A-Z0-9][A-Z0-9_-]{1,31}$/;
const SENSOR_ID_RE = /^TM-SENSOR-[A-Z0-9]{2,12}$/;
const RFC3339_RE =
  /^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:[Zz]|[+-]\d{2}:\d{2})$/;

// ── Verdicts ─────────────────────────────────────────────────────────────────

export const severityFor = (verdict) => SEVERITY_OF[verdict] ?? SEVERITY.CRITICAL;

/**
 * The most severe verdict in the list.
 *
 * Falls back to UNVERIFIABLE for an unrecognised verdict, matching
 * `worst_verdict` in verifier.py. Two wrong answers were available and both are
 * worse: GENUINE would assert safety about something we do not understand, and
 * COUNTERFEIT would show a red counterfeit warning for what is most likely an
 * app that is simply older than the API. UNVERIFIABLE asserts nothing.
 */
export function worstVerdict(verdicts) {
  if (!Array.isArray(verdicts) || verdicts.length === 0) return VERDICT.GENUINE;
  for (const candidate of PRECEDENCE) {
    if (verdicts.includes(candidate)) return candidate;
  }
  return VERDICT.UNVERIFIABLE;
}

/** Verdict → `error.code`, or null when the verdict is not a failure. */
export function verdictToErrorCode(verdict) {
  switch (verdict) {
    case VERDICT.COUNTERFEIT:
      return CODES.SIGNATURE_INVALID;
    case VERDICT.RECALLED:
      return CODES.RECALLED;
    case VERDICT.CLONE:
      return CODES.CLONE_SUSPECTED;
    case VERDICT.COLD_CHAIN:
      return CODES.COLD_CHAIN_BREACH;
    case VERDICT.EXPIRED:
      return CODES.EXPIRED;
    case VERDICT.UNVERIFIABLE:
      return CODES.PAYLOAD_INVALID;
    default:
      return null;
  }
}

/** The on-chain-only fold, mirroring `rules.Verdict` in Go. §3.9. */
export function chainVerdict({ status, expired, breached, cloneSuspected: clone }) {
  if (status === STATUS.RECALLED) return VERDICT.RECALLED;
  if (clone) return VERDICT.CLONE;
  if (breached) return VERDICT.COLD_CHAIN;
  if (expired) return VERDICT.EXPIRED;
  return VERDICT.GENUINE;
}

export const cloneSuspected = (scanCount, distinctDistricts) =>
  Number(scanCount) > CLONE_SCAN_THRESHOLD ||
  Number(distinctDistricts) > CLONE_DISTRICT_THRESHOLD;

// ── Dates ────────────────────────────────────────────────────────────────────

/**
 * Parse a strict `YYYY-MM-DD` date to a UTC-midnight epoch millisecond value.
 *
 * The regex is not redundant with `Date.parse`, which accepts `2026-3-15`,
 * `March 15 2026`, and — depending on the engine — `2026-02-31`, rolling it
 * silently into 3 March. A date inside a signed payload must have exactly one
 * representation, and an expiry that rolls forward by two days is an expiry
 * check that can be gamed.
 *
 * @returns {number} epoch ms at UTC midnight
 */
export function parseDate(field, value) {
  if (typeof value !== 'string' || !DATE_RE.test(value)) {
    throw new TrueMedError(
      CODES.PAYLOAD_INVALID,
      `${field} must be exactly YYYY-MM-DD (got ${JSON.stringify(value)})`,
    );
  }
  const [y, m, d] = value.split('-').map(Number);
  const ms = Date.UTC(y, m - 1, d);
  const back = new Date(ms);
  // Reject 2026-02-31 and friends: Date.UTC rolls them over instead of failing.
  if (
    back.getUTCFullYear() !== y ||
    back.getUTCMonth() !== m - 1 ||
    back.getUTCDate() !== d
  ) {
    throw new TrueMedError(
      CODES.PAYLOAD_INVALID,
      `${field} is not a real calendar date: ${value}`,
    );
  }
  return ms;
}

/** UTC midnight of the day containing `when`. */
export function dayOf(when = new Date()) {
  const d = when instanceof Date ? when : new Date(when);
  return Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate());
}

const MS_PER_DAY = 86400000;

/** Whole days remaining; negative once expired, 0 on the expiry day itself. */
export function daysToExpiry(expiryDate, asOf = new Date()) {
  return Math.round(
    (parseDate('expiry_date', expiryDate) - dayOf(asOf)) / MS_PER_DAY,
  );
}

/**
 * True once the calendar date is past the printed expiry.
 *
 * The expiry day itself is still usable — a pharmacist reading `EXP 02/2028`
 * dispenses on 29 February 2028 without hesitation, and calling that unit
 * expired would be wrong in a way that undermines every other verdict.
 */
export const isExpired = (expiryDate, asOf = new Date()) =>
  daysToExpiry(expiryDate, asOf) < 0;

export function validateDateOrder(mfgDate, expiryDate) {
  const mfg = parseDate('mfg_date', mfgDate);
  const exp = parseDate('expiry_date', expiryDate);
  if (exp <= mfg) {
    throw new TrueMedError(
      CODES.PAYLOAD_INVALID,
      `expiry_date ${expiryDate} must be after mfg_date ${mfgDate}`,
    );
  }
}

/**
 * Parse an RFC 3339 instant to epoch ms.
 *
 * The regex pins the format before `Date.parse` sees it, for the same reason as
 * above: a sensor sending `2026-08-21 10:00` (space, no zone) would otherwise be
 * read in the *server's* local time, silently shifting a temperature reading by
 * hours and moving an excursion out of the window a regulator looks at.
 */
export function parseInstant(field, value) {
  if (typeof value !== 'string' || !RFC3339_RE.test(value)) {
    throw validationError(
      `${field} must be an RFC 3339 timestamp with a timezone, ` +
        `e.g. 2026-08-21T10:00:00Z (got ${JSON.stringify(value)})`,
    );
  }
  const ms = Date.parse(value);
  if (Number.isNaN(ms)) {
    throw validationError(`${field} is not a valid instant: ${value}`);
  }
  return ms;
}

/** RFC 3339 UTC, second precision — the format every timestamp uses on the wire. */
export function stamp(when = new Date()) {
  const d = when instanceof Date ? when : new Date(when);
  return `${d.toISOString().slice(0, 19)}Z`;
}

// ── Field validation ─────────────────────────────────────────────────────────

/**
 * Find the first C0/C1 control character, or return null.
 *
 * Split out from `rejectControlChars` so that payload.js can run the same scan
 * and report it as PAYLOAD_INVALID rather than VALIDATION_ERROR — the two carry
 * different meanings to the app (a bad QR versus a bad API request) and there
 * should still be only one implementation of the scan itself.
 *
 * @returns {{char: string, codePoint: number, index: number}|null}
 */
export function findControlChar(value) {
  let index = 0;
  for (const ch of value) {
    const cp = ch.codePointAt(0);
    const isC0 = cp < 0x20;
    const isDelOrC1 = cp >= 0x7f && cp <= 0x9f;
    if (isC0 || isDelOrC1) return { char: ch, codePoint: cp, index };
    index += 1;
  }
  return null;
}

/** Format a code point as `U+XXXX` for an error message. */
export const asCodePointLabel = (cp) =>
  `U+${cp.toString(16).padStart(4, '0').toUpperCase()}`;

/**
 * Reject C0/C1 control characters in a stored or signed field.
 *
 * A newline or NUL is how log injection and payload smuggling start, and no
 * legitimate excipient, pharmacy name or location ID contains one.
 *
 * Checked by code point rather than with a regex character range on purpose:
 * a range written as literal control bytes is invisible in a diff and easy for
 * an editor to mangle, and one written with escapes is easy to get subtly wrong.
 */
export function rejectControlChars(field, value) {
  const found = findControlChar(value);
  if (found) {
    throw validationError(
      `${field} contains a control character (${asCodePointLabel(found.codePoint)}); ` +
        'control characters are not permitted',
    );
  }
}

export function validateText(field, value, max) {
  if (typeof value !== 'string') {
    throw validationError(`${field} must be a string, got ${typeof value}`);
  }
  const trimmed = value.trim();
  if (!trimmed) throw validationError(`${field} must not be empty`);
  rejectControlChars(field, trimmed);
  const limit = max ?? LIMITS[field];
  // Counted in code points, not UTF-16 units, so a Devanagari name is measured
  // the way a person would count its characters.
  const length = [...trimmed].length;
  if (limit && length > limit) {
    throw validationError(
      `${field} is ${length} characters, over the ${limit}-character limit`,
    );
  }
  return trimmed;
}

export function validateProductID(value) {
  const text = validateText('product_id', value, LIMITS.product_id);
  if (!PRODUCT_ID_RE.test(text)) {
    throw validationError(
      `product_id ${JSON.stringify(text)} is not in the form ` +
        'GENERIC_BRAND_YEAR_SERIAL (e.g. PARACETAMOL500MG_PARACIP500_2026_000001)',
    );
  }
  return text;
}

/**
 * Batch numbers are manufacturer-defined (DATA-CONTRACT.md §5), so no character
 * set is imposed — only length and the control-character rule that every signed
 * field gets.
 *
 * An earlier version restricted these to `[A-Za-z0-9./-]`. That was wrong twice
 * over: `batch_no` is signed wire data, so anything the Python signer accepts
 * must verify here, and a regulator calling POST /api/recall has to be able to
 * name *any* batch that exists on chain. A recall that cannot be issued because
 * the manufacturer put a space in their batch number is a recall that does not
 * happen.
 */
export function validateBatchNo(value) {
  return validateText('batch_no', value, LIMITS.batch_no);
}

/**
 * Location IDs follow §5: `{TYPE}_{CITY}_{NNN}`.
 *
 * Enforced rather than accepted as free text because Grafana groups by this
 * value. `PHARM_MUM_0142`, `pharm mum 142` and `Pharmacy Mumbai 142` are one
 * place to a human and three rows on a dashboard, and a heat map that splits one
 * pharmacy across three rows is worse than no heat map.
 */
export function validateLocation(value) {
  const text = validateText('location', value, LIMITS.location);
  if (!LOCATION_RE.test(text)) {
    throw validationError(
      `location ${JSON.stringify(text)} must be uppercase in the form ` +
        'TYPE_CITY_NNN, e.g. FACTORY_PUNE_01, WH_MUM_001, PHARM_MUM_0142',
    );
  }
  return text;
}

export function validateSensorID(value) {
  const text = validateText('sensor_id', value, LIMITS.sensor_id).toUpperCase();
  if (!SENSOR_ID_RE.test(text)) {
    throw validationError(
      `sensor_id ${JSON.stringify(text)} must look like TM-SENSOR-001`,
    );
  }
  return text;
}

export const knownStatus = (status) => Object.values(STATUS).includes(status);

export const isTerminalStatus = (status) =>
  status === STATUS.DISPENSED || status === STATUS.RECALLED;

/** Forward-only ranking used by `validateTransition`. */
const STATUS_RANK = Object.freeze({
  [STATUS.MANUFACTURED]: 0,
  [STATUS.IN_TRANSIT]: 1,
  [STATUS.AT_PHARMACY]: 2,
  [STATUS.DISPENSED]: 3,
});

/**
 * Custody may move forward, or stay on `in_transit` for another hop. §3.1.
 *
 * Rejecting backward moves is what stops a unit already marked `dispensed` from
 * being rewound to `in_transit` and resold. The ledger would happily record it:
 * a ledger guarantees that history is not rewritten, not that new history makes
 * sense.
 */
export function validateTransition(from, to) {
  if (!knownStatus(to)) {
    throw validationError(
      `status ${JSON.stringify(to)} is not one of ${Object.values(STATUS).join(', ')}`,
    );
  }
  if (to === STATUS.RECALLED) {
    throw validationError(
      'a recall may only be applied through POST /api/recall by the regulator, ' +
        'never as a custody update',
    );
  }
  if (isTerminalStatus(from)) {
    throw validationError(`${from} is terminal; this unit cannot move to ${to}`);
  }
  const rankFrom = STATUS_RANK[from];
  const rankTo = STATUS_RANK[to];
  if (rankFrom === undefined) {
    throw validationError(
      `current status ${JSON.stringify(from)} is not recognised`,
    );
  }
  if (rankTo < rankFrom) {
    throw validationError(`cannot move backwards from ${from} to ${to}`);
  }
  if (rankTo === rankFrom && to !== STATUS.IN_TRANSIT) {
    throw validationError(
      `unit is already ${from}; only in_transit may repeat, for a further hop`,
    );
  }
  return to;
}

export function validateTemperature(value) {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    throw validationError(
      'temperature must be a finite number in degrees Celsius',
    );
  }
  if (value < SENSOR_TEMP_MIN_C || value > SENSOR_TEMP_MAX_C) {
    throw validationError(
      `temperature ${value} °C is outside the DS18B20 rated range ` +
        `${SENSOR_TEMP_MIN_C}..${SENSOR_TEMP_MAX_C} °C, so it is a sensor or ` +
        'wiring fault rather than a cold-chain reading',
    );
  }
  return value;
}

/** Only vaccines have a cold chain; medicines log temperature without breaching. */
export const breachesColdChain = (medType, temperature) =>
  medType === TYPE.VACCINE &&
  (temperature < VACCINE_TEMP_MIN_C || temperature > VACCINE_TEMP_MAX_C);

/**
 * Validate a sensor's own `recorded_at` against a reference instant.
 *
 * Generous backwards (a device offline for days flushes its buffer on reconnect,
 * and those readings are exactly the ones worth keeping), strict forwards: a
 * timestamp in the future is either a wrong clock or an attempt to plant an
 * alibi ahead of an excursion.
 */
export function validateRecordedAt(recordedAt, referenceMs = Date.now()) {
  const ms = parseInstant('recorded_at', recordedAt);
  if (ms - referenceMs > MAX_RECORDED_AT_SKEW_MS) {
    throw validationError(
      `recorded_at ${recordedAt} is more than ` +
        `${MAX_RECORDED_AT_SKEW_MS / 60000} minutes in the future`,
    );
  }
  if (referenceMs - ms > MAX_RECORDED_AT_AGE_MS) {
    throw validationError(
      `recorded_at ${recordedAt} is older than the ` +
        `${MAX_RECORDED_AT_AGE_MS / 86400000}-day backfill window`,
    );
  }
  return ms;
}

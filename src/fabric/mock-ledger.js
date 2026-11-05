/**
 * In-memory Fabric ledger — the mock driver behind FABRIC_MOCK=1.
 *
 * Two jobs, and the second is the one that earns its length:
 *
 * 1. It lets the API, the Flutter app and the Grafana dashboards be developed and
 *    demonstrated with no Hyperledger network running — no Docker, no 6 GB of
 *    peers and orderers on a college laptop.
 *
 * 2. It is the **executable reference** for `blockchain/chaincode`. The Go
 *    contract cannot be compiled or unit-tested in every environment this project
 *    is worked on, so the rules it must implement are pinned here in a language
 *    that always runs, and exercised by tests/fabric/mock-ledger.test.js. When the
 *    Go and this disagree, one of them has a bug; this file is the specification
 *    they are checked against.
 *
 * Because of job 2, this deliberately mirrors the on-chain model in
 * DATA-CONTRACT.md §3 field-for-field, enforces the §3.4 MSP rules itself rather
 * than assuming channel membership, keeps the sticky cold-chain breach of §3.3,
 * and takes its timestamps from an injected clock the way the chaincode must take
 * them from `GetTxTimestamp()` and never from `time.Now()` (§3.2). The one thing
 * it does not reproduce is distributed endorsement — a single process cannot — so
 * it is not a substitute for running the real network before shipping, and
 * `network.sh deploy` still runs the Go tests on nanda's machine.
 */

import {
  MedicineData,
  makeProductID as _makeProductID, // re-exported for scripts/seed
} from '../core/payload.js';
import {
  CHECK,
  MAX_CUSTODY_EVENTS,
  MAX_CUSTODY_EVENTS_RECALL,
  MAX_DISTINCT_DISTRICTS,
  MAX_EMBEDDED_READINGS,
  MAX_RECALL_PER_TX,
  MAX_RECALL_SCAN,
  STATUS,
  TYPE,
  breachesColdChain,
  chainVerdict,
  cloneSuspected,
  isExpired,
  stamp,
  validateBatchNo,
  validateLocation,
  validateRecordedAt,
  validateSensorID,
  validateTemperature,
  validateText,
  validateTransition,
} from '../core/rules.js';
import { LIMITS } from '../core/rules.js';
import { conflict, forbidden, notOnChain, validationError } from '../core/errors.js';

export const CONTRACT_VERSION = 'truemed-1.0';

/** MSP identifiers, matching configtx.yaml / crypto-config.yaml. */
export const MSP = Object.freeze({
  MANUFACTURER: 'ManufacturerMSP',
  DISTRIBUTOR: 'DistributorMSP',
  REGULATOR: 'RegulatorMSP',
});

/**
 * §3.4 access control, enforced in the contract rather than left to channel
 * membership: every member of a channel may submit any transaction, so without
 * this a distributor could mint. Endorsement policy is the complementary control
 * and cannot express "only the manufacturer may call this".
 */
const WRITERS = Object.freeze({
  createMedicine: new Set([MSP.MANUFACTURER]),
  updateLocation: new Set([MSP.MANUFACTURER, MSP.DISTRIBUTOR]),
  addTemperatureReading: new Set([MSP.MANUFACTURER, MSP.DISTRIBUTOR]),
  recallBatch: new Set([MSP.REGULATOR]),
  // recordPatientScan and the reads are open to any member.
});

const DOC_TYPE = Object.freeze({ MEDICINE: 'medicine', TEMPERATURE: 'temperature' });

/** Composite-key separator. Fabric uses U+0000; the mock only needs uniqueness. */
const SEP = String.fromCharCode(0);
const SEQ_BASE = 999999999999; // 12 digits; newest reading sorts first (§3.5)

const clone = (value) => JSON.parse(JSON.stringify(value));

/**
 * @param {string} op       one of the WRITERS keys
 * @param {string} mspId    submitting identity's MSP
 */
function assertWriter(op, mspId) {
  const allowed = WRITERS[op];
  if (!allowed) return; // open operation
  if (!mspId || !allowed.has(mspId)) {
    throw forbidden(
      `${op} may only be submitted by ${[...allowed].join(' or ')}; ` +
        `the caller's identity is ${mspId ? `in ${mspId}` : 'unauthenticated'}`,
    );
  }
}

export class MockLedger {
  /**
   * @param {{clock?: () => Date, logger?: import('../utils/logger.js').Logger}} [opts]
   */
  constructor(opts = {}) {
    this.mock = true;
    this.clock = opts.clock ?? (() => new Date());
    this.log = opts.logger ?? null;
    /** product_id → Medicine record */
    this.state = new Map();
    /** composite `batch~product` → product_id, for deterministic recall (§3.5/§3.8) */
    this.batchIndex = new Map();
    /** composite `temp~product` → TemperatureReading, the full series */
    this.tempSeries = new Map();
    /** per-product monotonically increasing reading counter, for the seq key */
    this.tempCounts = new Map();
    /** last event emitted, so tests can assert §3.8 without a real event hub */
    this.lastEvent = null;
    /** monotonic counter behind the synthetic transaction ids (see #receipt) */
    this.txSeq = 0;
  }

  /** RFC 3339 UTC ledger time — the deterministic stamp, like GetTxTimestamp. */
  #now() {
    return stamp(this.clock());
  }

  /**
   * Stamp the caller's receipt with this write's transaction id (§4.5a).
   *
   * The transaction id is transport metadata, not ledger data, so it deliberately
   * does not go into the returned record. `recallBatch`'s return value mirrors
   * `RecallResult` in contract.go field for field — a test asserts the exact key
   * set — and the four other writes return the record itself, where an extra
   * `tx_id` would imply the ledger stores one. So it travels out-of-band, in an
   * object the caller opts into by passing `ctx.receipt`.
   *
   * Opt-in matters: callers that pass a bare `{ mspId }` (every existing test,
   * which shares one frozen-by-convention ctx constant across many calls) are
   * never mutated. Only a caller that supplies a fresh receipt per request — the
   * service layer does — gets one back, so there is no cross-request bleed.
   *
   * The `mock:` prefix is load-bearing. A synthetic id shaped like a real Fabric
   * transaction id would let a demo screenshot pass for evidence, and §4.5a says
   * this is "the only field here that lets a dispute be settled". On the mock
   * driver no dispute can be settled, because there is no ledger to fetch the
   * transaction from, and the value says so.
   */
  #receipt(ctx) {
    const receipt = ctx?.receipt;
    if (!receipt || typeof receipt !== 'object') return;
    this.txSeq += 1;
    receipt.tx_id = `mock:${String(this.txSeq).padStart(16, '0')}`;
  }

  #emit(name, payload) {
    // §3.8: one event per transaction; SetEvent overwrites rather than appends.
    this.lastEvent = { name, payload: clone(payload) };
    this.log?.debug?.('ledger event', { event: name, ...payload });
  }

  async ping() {
    return { ok: true, driver: 'mock' };
  }

  async close() {
    /* nothing to release */
  }

  // ── Reads ───────────────────────────────────────────────────────────────────

  async medicineExists(productID) {
    return this.state.has(productID);
  }

  /** The full record, deep-cloned so a caller cannot mutate ledger state. */
  async getMedicine(productID) {
    const record = this.state.get(productID);
    return record ? clone(record) : null;
  }

  /**
   * VerifyMedicine (§3.9): the on-chain fold, which never returns COUNTERFEIT
   * because the chain cannot see the QR signature. An absent product ID is
   * NOT_ON_CHAIN, which the API promotes to COUNTERFEIT only after the signature
   * verifies.
   */
  async verifyMedicine(productID, when) {
    const record = this.state.get(productID);
    if (!record) {
      return { found: false, verdict: 'NOT_ON_CHAIN', medicine: null };
    }
    const asOf = when ?? this.clock();
    const verdict = chainVerdict({
      status: record.status,
      expired: isExpired(record.expiry_date, asOf),
      breached: record.cold_chain_breached,
      cloneSuspected: cloneSuspected(record.scan_count, record.distinct_scan_districts.length),
    });
    return { found: true, verdict, medicine: clone(record) };
  }

  // ── Writes ────────────────────────────────────────────────────────────────

  /**
   * CreateMedicine (ManufacturerMSP). Validates the signed data elements through
   * MedicineData so the mint endpoint refuses anything that could not have been a
   * real signed payload, then initialises the mutable custody/telemetry state.
   *
   * @param {object} input  full-name fields from POST /api/medicine (§4.5)
   * @param {{mspId: string}} ctx
   */
  async createMedicine(input, ctx) {
    assertWriter('createMedicine', ctx.mspId);

    // Reuse the payload validator: identical field rules to a signed QR, so a
    // product minted here is one the QR generator could have produced.
    const medicine = MedicineData.fromDict(input);
    const location = validateLocation(input.location);

    if (this.state.has(medicine.productID)) {
      throw conflict(
        `product_id ${medicine.productID} already exists on the ledger; ` +
          'each sellable unit is minted exactly once',
      );
    }

    const now = this.#now();
    const record = {
      doc_type: DOC_TYPE.MEDICINE,
      ...medicine.toDict(), // product_id, generic_name, …, excipients, type
      current_location: location,
      status: STATUS.MANUFACTURED,
      custody_trail: [
        { status: STATUS.MANUFACTURED, location, timestamp: now, actor_msp: ctx.mspId },
      ],
      temperature_history: [],
      temp_reading_count: 0,
      temp_min_c: 0,
      temp_max_c: 0,
      cold_chain_breached: false,
      cold_chain_breached_at: '',
      scan_count: 0,
      first_scan_at: '',
      last_scan_at: '',
      distinct_scan_districts: [],
      recall_reason: '',
      recalled_at: '',
      created_at: now,
      updated_at: now,
      created_by_msp: ctx.mspId,
      contract_version: CONTRACT_VERSION,
    };

    this.state.set(record.product_id, record);
    // §3.5: the batch index is written in the same transaction as the record, so
    // a recall can never miss a unit that was successfully created.
    this.batchIndex.set(`${record.batch_no}${SEP}${record.product_id}`, record.product_id);
    this.tempCounts.set(record.product_id, 0);

    this.#emit('MedicineCreated', {
      product_id: record.product_id,
      batch_no: record.batch_no,
      type: record.type,
    });
    this.#receipt(ctx);
    return clone(record);
  }

  /**
   * UpdateLocation (Manufacturer/Distributor): one custody hop. §3.1 forbids
   * backward transitions and rejects recalls submitted this way.
   */
  async updateLocation(input, ctx) {
    assertWriter('updateLocation', ctx.mspId);
    const record = this.#mustGet(input.product_id);
    const location = validateLocation(input.location);
    // Throws VALIDATION_ERROR on a backward or illegal move, and refuses a recall
    // dressed up as a custody update.
    const status = validateTransition(record.status, input.status);

    if (record.custody_trail.length >= MAX_CUSTODY_EVENTS) {
      throw validationError(
        `custody trail already holds ${MAX_CUSTODY_EVENTS} events, the cap that ` +
          'bounds record growth; this unit cannot accept another hop',
      );
    }

    const now = this.#now();
    record.status = status;
    record.current_location = location;
    record.custody_trail.push({ status, location, timestamp: now, actor_msp: ctx.mspId });
    record.updated_at = now;

    this.#emit('CustodyUpdated', { product_id: record.product_id, status, location });
    this.#receipt(ctx);
    return clone(record);
  }

  /**
   * AddTemperatureReading (Manufacturer/Distributor). Cold-chain breach is sticky
   * and vaccine-only (§3.3): a vaccine that got warm does not become safe again
   * when it cools, so the flag, once set, never clears. Medicines log temperature
   * but never breach.
   *
   * The full series is stored under its own composite key (§3.5); the record
   * embeds only the most recent MAX_EMBEDDED_READINGS as a display window (§3.7),
   * because a vial sampled every five minutes produces ~105 000 readings a year.
   */
  async addTemperatureReading(input, ctx) {
    assertWriter('addTemperatureReading', ctx.mspId);
    const record = this.#mustGet(input.product_id);

    const sensorID = validateSensorID(input.sensor_id);
    const temperature = validateTemperature(input.temperature);
    const ledgerMs = this.clock().getTime();
    // recorded_at is the sensor's own claim, validated against ledger time — never
    // wall-clock — with a forward-skew allowance and a backfill window (§3.6).
    validateRecordedAt(input.recorded_at, ledgerMs);

    const now = this.#now();
    const breach = breachesColdChain(record.type, temperature);
    const reading = {
      temperature,
      timestamp: now, // ledger time — trustworthy
      recorded_at: input.recorded_at, // sensor's claim
      location: record.current_location,
      sensor_id: sensorID,
      breach,
    };

    // Full series under temp~product, seq = SEQ_BASE - n so newest sorts first.
    const n = (this.tempCounts.get(record.product_id) ?? 0) + 1;
    this.tempCounts.set(record.product_id, n);
    const seq = String(SEQ_BASE - n).padStart(12, '0');
    this.tempSeries.set(`${record.product_id}${SEP}${seq}`, {
      doc_type: DOC_TYPE.TEMPERATURE,
      product_id: record.product_id,
      ...reading,
    });

    // Embedded rolling window: newest first, oldest dropped past the cap.
    record.temperature_history.unshift(reading);
    if (record.temperature_history.length > MAX_EMBEDDED_READINGS) {
      record.temperature_history.length = MAX_EMBEDDED_READINGS;
    }

    // Aggregates span the full history, not just the window.
    if (record.temp_reading_count === 0) {
      record.temp_min_c = temperature;
      record.temp_max_c = temperature;
    } else {
      record.temp_min_c = Math.min(record.temp_min_c, temperature);
      record.temp_max_c = Math.max(record.temp_max_c, temperature);
    }
    record.temp_reading_count += 1;

    if (breach && !record.cold_chain_breached) {
      record.cold_chain_breached = true;
      record.cold_chain_breached_at = now;
      this.#emit('ColdChainBreach', {
        product_id: record.product_id,
        temperature,
        sensor_id: sensorID,
      });
    } else {
      this.#emit('TemperatureRecorded', {
        product_id: record.product_id,
        temperature,
        breach,
      });
    }
    record.updated_at = now;
    this.#receipt(ctx);
    return clone(record);
  }

  /**
   * RecordPatientScan (any member). Increments scan telemetry and tracks the set
   * of districts, capped at MAX_DISTINCT_DISTRICTS (§3.7) — by the time the cap is
   * hit the verdict is already CLONE_SUSPECTED, so further districts add nothing.
   */
  async recordPatientScan(input, ctx = {}) {
    const record = this.#mustGet(input.product_id);
    const now = this.#now();

    record.scan_count += 1;
    if (!record.first_scan_at) record.first_scan_at = now;
    record.last_scan_at = now;

    if (input.district !== undefined && input.district !== null && input.district !== '') {
      const district = validateText('district', input.district, LIMITS.district);
      if (
        !record.distinct_scan_districts.includes(district) &&
        record.distinct_scan_districts.length < MAX_DISTINCT_DISTRICTS
      ) {
        record.distinct_scan_districts.push(district);
      }
    }
    record.updated_at = now;

    const clones = cloneSuspected(record.scan_count, record.distinct_scan_districts.length);
    if (clones) {
      this.#emit('CloneSuspected', {
        product_id: record.product_id,
        scan_count: record.scan_count,
        distinct_districts: record.distinct_scan_districts.length,
      });
    } else {
      this.#emit('PatientScanned', {
        product_id: record.product_id,
        scan_count: record.scan_count,
      });
    }
    this.#receipt(ctx);
    return clone(record);
  }

  /**
   * RecallBatch (RegulatorMSP). Walks the batch index (§3.5) rather than a rich
   * query — rich queries are illegal in a writing transaction because their
   * results cannot be re-derived deterministically at validation. Recall is
   * terminal and bounded to MAX_RECALL_PER_TX units per call (§3.7); the caller
   * repeats while `more_remaining` is true.
   *
   * The cap is on units *recalled*, not index rows scanned. Capping the scan
   * would hand back the same prefix of the batch on every call, so once those
   * units were recalled each further call would recall nothing while still
   * reporting `more_remaining: true`, and the units behind that prefix could
   * never be reached. This is the behaviour of `RecallBatch` in contract.go, down
   * to the field names it returns — the service layer must not be able to tell
   * the two drivers apart.
   */
  async recallBatch(input, ctx) {
    assertWriter('recallBatch', ctx.mspId);
    const batchNo = validateBatchNo(input.batch_no);
    const reason = validateText('reason', input.reason, LIMITS.reason);

    const prefix = `${batchNo}${SEP}`;
    const productIDs = [];
    let scanTruncated = false;
    for (const [key, productID] of this.batchIndex) {
      if (!key.startsWith(prefix)) continue;
      if (productIDs.length >= MAX_RECALL_SCAN) {
        scanTruncated = true;
        break;
      }
      productIDs.push(productID);
    }
    productIDs.sort(); // deterministic order, so pagination is stable across calls

    if (productIDs.length === 0) throw notOnChain(`batch ${batchNo}`);

    const now = this.#now();
    const recalledIDs = [];
    let alreadyRecalled = 0;
    let capReached = false;
    for (const productID of productIDs) {
      if (recalledIDs.length >= MAX_RECALL_PER_TX) {
        capReached = true;
        break;
      }
      const record = this.state.get(productID);
      if (!record) continue;
      if (record.status === STATUS.RECALLED) {
        alreadyRecalled += 1; // idempotent across pages
        continue;
      }
      if (record.custody_trail.length >= MAX_CUSTODY_EVENTS_RECALL) {
        throw validationError(
          `${productID} already has ${MAX_CUSTODY_EVENTS_RECALL} custody events, ` +
            'which is the maximum; a legitimate unit sees fewer than ten, so this ' +
            'looks like a stuck integration',
        );
      }
      record.status = STATUS.RECALLED;
      record.recall_reason = reason;
      record.recalled_at = now;
      record.custody_trail.push({
        status: STATUS.RECALLED,
        location: record.current_location,
        timestamp: now,
        actor_msp: ctx.mspId,
      });
      record.updated_at = now;
      recalledIDs.push(productID);
    }

    const moreRemaining = capReached || scanTruncated;

    // The one case repeated calls cannot resolve: a batch bigger than the scan
    // ceiling whose entire scanned prefix is already recalled. `more_remaining`
    // would stay true while no call could reach the units beyond the ceiling.
    if (scanTruncated && !capReached && recalledIDs.length === 0) {
      throw validationError(
        `batch ${batchNo} holds more than ${MAX_RECALL_SCAN} units and every unit ` +
          'examined is already recalled; a batch this large cannot be fully recalled ' +
          'by batch number — recall the remaining units individually, and split ' +
          'batches at manufacture',
      );
    }

    this.#emit('BatchRecalled', {
      batch_no: batchNo,
      reason,
      recalled: recalledIDs.length,
      more_remaining: moreRemaining,
      actor_msp: ctx.mspId,
      timestamp: now,
    });
    this.#receipt(ctx);
    return {
      batch_no: batchNo,
      recalled: recalledIDs.length,
      already_recalled: alreadyRecalled,
      more_remaining: moreRemaining,
      product_ids: recalledIDs,
      recalled_at: now,
      actor_msp: ctx.mspId,
    };
  }

  // ── Dashboard support (read-only aggregates) ─────────────────────────────────

  /**
   * Every medicine record, deep-cloned. The dashboards run over this; a real
   * deployment would page a CouchDB rich query, but a rich query in a read-only
   * evaluate is legal (the §3.5 prohibition is only on writing transactions).
   */
  async allMedicines() {
    return [...this.state.values()].map(clone);
  }

  #mustGet(productID) {
    const record = this.state.get(productID);
    if (!record) throw notOnChain(productID);
    return record;
  }
}

export { _makeProductID as makeProductID };

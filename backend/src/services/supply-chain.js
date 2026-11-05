/**
 * The ledger writes: `POST /api/medicine`, `/api/location`, `/api/temperature` and
 * `/api/recall`.
 *
 * The first three move a single unit through the supply chain, and each returns the
 * §4.5a shape — the object that landed, plus the chaincode's own timestamp and the
 * Fabric transaction id — rather than the whole ledger record. That projection is
 * the point: a client confirming a custody hop needs to know what was written and
 * how to cite it in a dispute, not to receive a copy of every temperature reading
 * attached to the unit.
 *
 * `POST /api/recall` is the odd one out and is kept here anyway, because it shares
 * every rule below: it writes to the ledger under the caller's MSP and it must drop
 * the cached verification of everything it touched. It differs in scope — it acts on
 * a whole batch, returns the chaincode's `RecallResult` rather than a custody
 * response, and completes across several calls (§3.7) rather than one.
 *
 * Three rules from the contract shape this file.
 *
 * **The submitting MSP comes from the caller's role, never from the request body.**
 * `mspForRole` does the mapping and §3.4 is enforced by the chaincode against the
 * identity that actually submitted. A body-supplied `actor_msp` would be an
 * attacker-chosen field on the one value that says who is accountable for a write.
 *
 * **A pharmacy key may only assert `at_pharmacy` and `dispensed` (§4.3).** The role
 * check gates the endpoint, this list gates the transition, and the chaincode's
 * forward-only ordering gates the direction. All three are needed: on the real
 * network a pharmacy submits under DistributorMSP (see `fabric/index.js`), so
 * without this check a chemist's key could rewind a unit to `in_transit` and
 * reroute it, and the ledger would faithfully record the theft.
 *
 * **Every write drops the cached verification for its product (§4.6).** A pharmacy
 * that keeps seeing a stale custody state is the failure §4.6 exists to prevent, so
 * the `del` happens before the response is built, not after it is sent.
 *
 * The sensor path additionally verifies a per-device HMAC (§4.7) and burns a nonce,
 * so a stolen API key alone cannot forge temperature readings — the reasoning is at
 * `recordTemperature` below.
 */

import { CODES, TrueMedError, forbidden, notFound, validationError } from '../core/errors.js';
import { MedicineData } from '../core/payload.js';
import {
  LIMITS,
  PHARMACY_STATUSES,
  ROLE,
  STATUS,
  breachesColdChain,
  validateBatchNo,
  validateLocation,
  validateProductID,
  validateSensorID,
  validateTemperature,
  validateText,
} from '../core/rules.js';
import { mspForRole } from '../fabric/index.js';
import { sensorContext } from '../utils/secret-box.js';
import { verifySensorMac } from '../utils/sensor-hmac.js';

/**
 * How long a sensor nonce stays spent, in seconds (§4.5: "replay-checked for 24 h").
 *
 * The window is a replay window, not a clock-skew allowance: §3.6 already bounds
 * `recorded_at` to a 30-day backfill and 15 minutes of forward skew. A nonce that
 * expired sooner than the backfill window would let a captured reading be replayed
 * once the entry lapsed, which is why this is not derived from either bound.
 */
const NONCE_TTL_SECONDS = 24 * 60 * 60;

/**
 * The MSP a role submits under, refusing roles that may not write at all.
 *
 * `pharma` is the trap this guards: it is a manufacturer's read-only analytics
 * role, one letter away from `pharmacy`, and `mspForRole` returns null for it. A
 * null flowing on unchecked would reach the mock ledger's `assertWriter` as
 * `undefined` and surface as a confusing chaincode error rather than the 403 it is.
 */
function submitterFor(role) {
  const mspId = mspForRole(role);
  if (!mspId) {
    throw forbidden(
      `role ${role} cannot write to the blockchain; it is a read-only role`,
    );
  }
  return mspId;
}

/**
 * §4.5a: `{product_id, status, location, timestamp, tx_id}` for a custody write.
 *
 * `timestamp` is read off the record the chaincode returned — its deterministic
 * transaction time (§3.2) — never the API's own clock. The contract spends a
 * paragraph on why: a server clock here would put a value in the client's custody
 * trail that disagrees with a later read of the same event, and nobody would notice
 * until an investigator compared a pharmacy's screenshot against the ledger.
 *
 * The timestamp is taken from the last custody event rather than `updated_at`
 * because a recall or a temperature reading also bumps `updated_at`; the custody
 * event is the write this response is describing.
 */
function custodyResponse(record, receipt) {
  const trail = Array.isArray(record?.custody_trail) ? record.custody_trail : [];
  const last = trail.length ? trail[trail.length - 1] : null;
  const body = {
    product_id: record?.product_id ?? null,
    status: record?.status ?? null,
    location: record?.current_location ?? null,
    timestamp: last?.timestamp ?? record?.updated_at ?? null,
  };
  if (receipt.tx_id) body.tx_id = receipt.tx_id;
  return body;
}

/**
 * @param {{cache: object, fabric: object, store: object, secrets: object,
 *          logger?: import('../utils/logger.js').Logger,
 *          clock?: () => Date}} deps
 */
export function makeSupplyChainService({ cache, fabric, store, secrets, logger, clock = () => new Date() }) {
  /**
   * `POST /api/medicine` — mint a unit (§4.5). Manufacturer only.
   *
   * @param {object} input  the §4.5 body
   * @param {{role: string}} auth
   * @returns {Promise<object>} the §4.5a mint response
   */
  async function mint(input, auth) {
    const mspId = submitterFor(auth.role);

    // Validated here as well as in the chaincode, so a malformed mint is a 400 from
    // the API rather than a round trip that fails at endorsement. `MedicineData`
    // applies exactly the rules the Python signer applies, so a unit accepted here
    // is one the QR generator could have produced — anything looser would mint
    // stock whose own QR could never verify.
    const medicine = MedicineData.fromDict(input);
    const location = validateLocation(input?.location);

    const receipt = {};
    const record = await fabric.createMedicine(
      { ...medicine.toDict(), location },
      { mspId, receipt },
    );

    // A mint cannot have a cached verification of its own — the product did not
    // exist a moment ago — but a negative entry from someone who looked it up
    // first would outlive the mint by up to 30 s (§4.6) and report NOT_ON_CHAIN
    // for a unit that is now on the ledger.
    await cache.del(medicine.productID);

    logger?.info?.('unit minted', {
      product_id: medicine.productID,
      batch_no: medicine.batchNo,
      location,
      actor_msp: mspId,
    });
    return custodyResponse(record, receipt);
  }

  /**
   * `POST /api/location` — a custody hop (§4.5). Manufacturer, distributor or
   * pharmacy.
   *
   * @param {object} input
   * @param {{role: string}} auth
   * @returns {Promise<object>} the §4.5a custody response, with `actor_msp`
   */
  async function recordLocation(input, auth) {
    const mspId = submitterFor(auth.role);
    const productID = validateProductID(input?.product_id);
    const location = validateLocation(input?.location);

    const status = input?.status;
    if (typeof status !== 'string' || status.trim() === '') {
      throw validationError(
        `status is required and must be one of ${Object.values(STATUS).join(', ')}`,
      );
    }

    // §4.3: the status restriction that makes the pharmacy role safe. Checked
    // before the ledger sees the request so a chemist gets a 403 naming the two
    // statuses they may assert, rather than a chaincode error about MSPs — the
    // pharmacy submits under DistributorMSP, so the chaincode could not catch this.
    if (auth.role === ROLE.PHARMACY && !PHARMACY_STATUSES.includes(status)) {
      throw forbidden(
        `a pharmacy key may only record ${PHARMACY_STATUSES.join(' or ')}; ` +
          `${status} must be recorded by the manufacturer or distributor`,
      );
    }

    const receipt = {};
    const record = await fabric.updateLocation(
      { product_id: productID, location, status },
      { mspId, receipt },
    );

    // Before the response, not after: §4.6 requires the key gone or a pharmacy
    // keeps reading stale custody data for up to a minute.
    await cache.del(productID);

    logger?.info?.('custody updated', {
      product_id: productID,
      status: record?.status ?? status,
      location,
      actor_msp: mspId,
    });

    const body = custodyResponse(record, receipt);
    // §4.5a: echoed so a client can tell which organisation the API attributed the
    // write to. A chemist whose key was mis-issued against the wrong MSP sees
    // writes succeed under someone else's org, which is otherwise invisible.
    body.actor_msp = mspId;
    return body;
  }

  /**
   * `POST /api/temperature` — an IoT cold-chain reading (§4.5). Sensor role.
   *
   * Two credentials are required and they answer different questions. The API key
   * says which *system* is talking; the §4.7 HMAC, keyed on a per-device secret
   * held sealed in the store, says which *device* produced this reading. A single
   * shared API key across a fleet is the realistic deployment, so without the MAC a
   * key lifted from one cold box would let an attacker write a comfortable 4 °C
   * over a vaccine that has been sitting in the sun.
   *
   * @param {object} input
   * @param {{role: string}} auth
   * @returns {Promise<object>} the §4.5a temperature response
   */
  async function recordTemperature(input, auth) {
    const mspId = submitterFor(auth.role);
    const sensorID = validateSensorID(input?.sensor_id);
    const temperature = validateTemperature(input?.temperature);

    // §4.7: the MAC binds to `product_id` when the body carries one, otherwise to
    // `batch_no` — a cold box holds a whole batch. Exactly one must be present, or
    // there is no single string for both sides to have signed.
    const hasProduct = input?.product_id !== undefined && input.product_id !== null && input.product_id !== '';
    const hasBatch = input?.batch_no !== undefined && input.batch_no !== null && input.batch_no !== '';
    if (hasProduct === hasBatch) {
      throw validationError(
        'exactly one of product_id or batch_no is required: a reading is either ' +
          'for one unit or for the batch in a cold box, and the HMAC covers ' +
          'whichever key was sent',
      );
    }
    const binding = hasProduct
      ? validateProductID(input.product_id)
      : validateBatchNo(input.batch_no);

    const sensor = await store.getSensor(sensorID);
    if (!sensor) {
      // Deliberately 404 and not 401: the API key was valid, so this is not an
      // authentication failure. It is a device that was never provisioned or has
      // been revoked, and an installer reading the message needs to be sent to
      // `scripts/issue-api-key.js`, not to their key.
      throw notFound(
        `sensor ${sensorID} is not provisioned or has been revoked; provision it ` +
          'before it can submit readings',
      );
    }

    // The secret is sealed at rest with the sensor id as AEAD context, so a row
    // moved between devices fails to open rather than authenticating as the other.
    let secret;
    try {
      secret = secrets.open(sensor.secret_enc, sensorContext(sensorID));
    } catch (cause) {
      throw new TrueMedError(
        CODES.INTERNAL_ERROR,
        `the stored secret for sensor ${sensorID} could not be decrypted; it was ` +
          'sealed with a different ENCRYPTION_KEY and the sensor must be re-provisioned',
        { cause, expose: false },
      );
    }

    // Throws VALIDATION_ERROR on a malformed nonce or timestamp — naming a client
    // bug the firmware author must see — and returns false only for a MAC that is
    // genuinely wrong, which says nothing more.
    const macOk = verifySensorMac({
      secret,
      binding,
      sensorId: sensorID,
      temperature,
      recordedAt: input?.recorded_at,
      nonce: input?.nonce,
      presented: input?.hmac,
    });
    if (!macOk) {
      logger?.warn?.('sensor reading rejected: bad HMAC', {
        sensor_id: sensorID,
        binding,
      });
      throw new TrueMedError(
        CODES.UNAUTHORIZED,
        'the reading HMAC does not match; check the sensor secret and that the ' +
          'MAC covers binding|sensor_id|temperature|recorded_at|nonce with the ' +
          'temperature at exactly two decimal places',
        { expose: true },
      );
    }

    // Burned only after the MAC verifies. Reserving first would let an attacker
    // spend a legitimate device's nonces with garbage MACs, and every real reading
    // that followed would be rejected as a replay — a denial of service on the
    // cold chain, mounted with no secret at all.
    const fresh = await cache.reserveNonce(sensorID, input.nonce, NONCE_TTL_SECONDS);
    if (!fresh) {
      throw new TrueMedError(
        CODES.UNAUTHORIZED,
        `nonce ${input.nonce} has already been used by sensor ${sensorID}; each ` +
          'reading must carry a fresh nonce, so this is a replay of an earlier one',
        { expose: true },
      );
    }

    const reading = {
      sensor_id: sensorID,
      temperature,
      recorded_at: input.recorded_at,
    };
    if (input?.battery_pct !== undefined && input.battery_pct !== null) {
      reading.battery_pct = batteryPct(input.battery_pct);
    }

    // A batch-bound reading applies to every unit in the batch, so it is fanned out
    // across them; a product-bound one touches a single unit. Both go through the
    // same chaincode call per unit, because the ledger's cold-chain flag is
    // per-unit — that is what makes a single vial's verdict answerable offline.
    const targets = hasProduct
      ? [binding]
      : await unitsInBatch(binding);

    const receipt = {};
    let last = null;
    for (const productID of targets) {
      last = await fabric.addTemperatureReading(
        { ...reading, product_id: productID },
        { mspId, receipt },
      );
      await cache.del(productID);
    }

    // `chain_ok` describes *this reading* against the range, not the batch's
    // history (§4.5a). The type comes from the record the ledger returned, because
    // only a vaccine has a cold chain to breach — a medicine logs temperature
    // without ever breaching.
    const chainOk = !breachesColdChain(last?.type, temperature);
    if (!chainOk) {
      logger?.warn?.('cold chain breach recorded', {
        sensor_id: sensorID,
        binding,
        temperature,
        units: targets.length,
      });
    }

    const body = {
      product_id: hasProduct ? binding : null,
      sensor_id: sensorID,
      temperature,
      recorded_at: input.recorded_at,
      chain_ok: chainOk,
      reading_count: Number(last?.temp_reading_count ?? 0),
    };
    if (!hasProduct) {
      // A batch reading has no single product_id, so the batch it applied to and
      // the number of units it touched replace it. Without these a cold box's
      // response would carry `product_id: null` and nothing to say what it did.
      body.batch_no = binding;
      body.units_updated = targets.length;
    }
    if (receipt.tx_id) body.tx_id = receipt.tx_id;
    return body;
  }

  /**
   * `POST /api/recall` — recall a batch (§4.5). Regulator only.
   *
   * Returns the chaincode's `RecallResult` **unchanged**, which is a deliberate
   * departure from the three writes above. Those project a few fields out of the
   * record they wrote; this one has a purpose-built return value of its own, and
   * §4.5a passes it straight through. Notably that shape carries no `tx_id`: the
   * contract shows the field on all three custody writes and omits it here, and the
   * client's `RecallResult` does not parse one. The id is still logged below, so a
   * dispute over a recall can be settled from the server's own records without
   * putting an unsanctioned field on the wire.
   *
   * A recall is the one write that completes across several calls. The chaincode
   * recalls at most `MAX_RECALL_PER_TX` units per transaction and reports
   * `more_remaining`, so the caller loops until it is false (§3.7). That is also why
   * `already_recalled` exists: repeating a call must report that there was nothing
   * left to do rather than failing, or a client's retry after a dropped response
   * would look like an error.
   *
   * @param {object} input  `{batch_no, reason}`
   * @param {{role: string}} auth
   * @returns {Promise<object>} the §4.5 `RecallResult`
   */
  async function recall(input, auth) {
    const mspId = submitterFor(auth.role);
    const batchNo = validateBatchNo(input?.batch_no);

    // Required and non-blank (§4.5). Checked ahead of `validateText` only to say
    // *why* it is required — the reason reaches a pharmacist deciding whether to
    // pull stock and a patient asking whether to keep taking the drug, and
    // "reason must be a string, got undefined" does not tell an integrator that.
    if (input?.reason === undefined || input?.reason === null || String(input.reason).trim() === '') {
      throw validationError(
        'reason is required and must not be blank: it is shown to the pharmacist ' +
          'and to the patient, and a recall with no stated cause is not actionable',
      );
    }
    const reason = validateText('reason', input.reason, LIMITS.reason);

    const receipt = {};
    const result = await fabric.recallBatch(
      { batch_no: batchNo, reason },
      { mspId, receipt },
    );

    // §4.6, and the most safety-critical invalidation in the API. A live unit's
    // GENUINE verdict is cached under the 60 s active TTL, so leaving these keys in
    // place would keep telling patients a recalled medicine is fine — for a minute,
    // from a cache, after a regulator has formally withdrawn it. Done before the
    // response is built, not after it is sent.
    await invalidateAll(result?.product_ids, batchNo);

    logger?.info?.('batch recalled', {
      batch_no: batchNo,
      recalled: Number(result?.recalled ?? 0),
      already_recalled: Number(result?.already_recalled ?? 0),
      more_remaining: Boolean(result?.more_remaining),
      actor_msp: mspId,
      // Kept in the log rather than the response, per the note above.
      tx_id: receipt.tx_id ?? null,
    });

    return result;
  }

  /**
   * Drop the cached verification of every unit a recall moved.
   *
   * Never throws, and deliberately so. The ledger write has already committed and is
   * durable; the recall genuinely happened. Rejecting here would report a successful
   * recall as a failure, sending a regulator into a retry loop that cannot fix a
   * Redis outage — while the residual staleness is bounded at the 60 s active TTL and
   * expires on its own. A loud error log is the right response to a condition an
   * operator must see but a caller cannot act on.
   *
   * The deletes are issued together rather than in sequence: a full page is up to
   * `MAX_RECALL_PER_TX` units, and 500 sequential round trips would add real latency
   * to the window in which those stale verdicts are still being served.
   *
   * Only `product_ids` is invalidated. Units counted in `already_recalled` were
   * recalled by an earlier call, which cleared their keys then, and anything cached
   * for them since already reads `RECALLED`.
   */
  async function invalidateAll(productIDs, batchNo) {
    const ids = Array.isArray(productIDs) ? productIDs : [];
    if (!ids.length) return;
    const settled = await Promise.allSettled(ids.map((id) => cache.del(id)));
    const failed = settled.filter((r) => r.status === 'rejected');
    if (failed.length) {
      logger?.error?.('cached verdicts survived a recall', {
        batch_no: batchNo,
        failed: failed.length,
        of: ids.length,
        error: failed[0].reason?.message ?? String(failed[0].reason),
        note: 'these units may verify as GENUINE until their cache entry expires',
      });
    }
  }

  /**
   * Product IDs in a batch, for a cold-box reading.
   *
   * Scanned from the ledger rather than tracked here: the batch index is the
   * chaincode's, and a second copy in the API would drift the moment a unit was
   * minted while the API was down.
   */
  async function unitsInBatch(batchNo) {
    const all = await fabric.allMedicines();
    const units = all
      .filter((record) => record?.batch_no === batchNo)
      .map((record) => record.product_id)
      .sort();
    if (!units.length) {
      throw notFound(
        `no units of batch ${batchNo} exist on the blockchain, so this cold-box ` +
          'reading has nothing to attach to',
      );
    }
    return units;
  }

  return { mint, recordLocation, recordTemperature, recall };
}

/**
 * Battery percentage, bounded to 0..100.
 *
 * Optional in §4.5 and not covered by the MAC, so it is treated as advisory: it
 * decides when someone is sent to change a battery and never touches a verdict.
 * Still validated, because an out-of-range value stored unchecked would make a
 * "battery below 20%" alert unreliable in the direction that matters.
 */
function batteryPct(value) {
  const pct = Number(value);
  if (!Number.isFinite(pct) || pct < 0 || pct > 100) {
    throw validationError('battery_pct must be a number between 0 and 100');
  }
  return Math.round(pct);
}

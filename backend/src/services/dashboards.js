/**
 * The two read-only dashboards: `GET /api/dashboard/cdsco` and `/api/dashboard/pharma`.
 *
 * Neither returns a verdict, so neither is on the verification path — §4.4a is
 * explicit that a dashboard which is stale, truncated or down degrades a
 * regulator's view and can never change what a patient is told. That single fact
 * licenses everything here: these aggregate over a full-ledger scan and a batch of
 * recent reports, work no verification endpoint could afford, precisely because
 * being a few seconds behind costs a triage screen nothing.
 *
 * The contract fixes the response *shapes* (the Dart client parses exact keys in
 * `models.dart`) but not the aggregation *policy*, and there is no reference
 * implementation to port — unlike the verifier. So the policy is defined here, and
 * the two dashboards deliberately treat the `?days=` window differently, because
 * they answer different questions:
 *
 * **CDSCO windows events.** "How many cold-chain breaches happened in the last 30
 * days" is the regulator's question, so every CDSCO count is bounded by the
 * timestamp of the thing it counts: reports by `created_at`, recalls by
 * `recalled_at`, breaches by `cold_chain_breached_at`, clone suspicion by the most
 * recent scan. A breach from six weeks ago is not this month's problem.
 *
 * **Pharma shows stock.** A manufacturer tracking batches needs current shelf
 * state, not "units minted in the last 30 days" — hiding a batch because it was
 * made five weeks ago but is still on shelves would defeat the screen. So pharma's
 * unit totals and status counts are a current snapshot; the window bounds only the
 * per-batch report counts. `expiring_soon` is its own forward-looking filter and is
 * never windowed.
 *
 * Both policies are stated in the code below at the point they apply, so a future
 * reader changing one number knows what question it was meant to answer.
 *
 * Two shared rules:
 *
 * **Severity is never invented — it is a verdict's severity.** A district's colour
 * and a batch's `worst_severity` come from `chainVerdict` + `severityFor`, the same
 * §2.3 mapping the patient's screen uses, so one palette drives the map, the alert
 * list and the verdict banner. A report against a product that is not on the ledger
 * is treated as CRITICAL, because an ID nobody minted is the counterfeit case.
 *
 * **A `pharma` key sees only its own manufacturer.** The `mfg_licence_no` comes
 * from the key's scope (§4.4a), never the query, so one manufacturer can never read
 * another's production. An unscoped `pharma` key is a provisioning mistake and is
 * refused rather than shown an empty or, worse, a blank-scoped everyone-else view.
 */

import { forbidden, validationError } from '../core/errors.js';
import {
  DEFAULT_PAGE_SIZE,
  MAX_PAGE_SIZE,
  SEVERITY,
  STATUS,
  TYPE,
  chainVerdict,
  cloneSuspected,
  daysToExpiry,
  isExpired,
  severityFor,
} from '../core/rules.js';

const DAY_MS = 24 * 60 * 60 * 1000;

/**
 * Separator for the composite `district${KEY_SEP}state` map key.
 *
 * A NUL can never appear in either half: both reach here through `validateText`,
 * which rejects every control character, so no real district or state can collide
 * with the delimiter (`"A" + "B\0C"` and `"A\0B" + "C"` cannot both occur). It is
 * built from a char code rather than written as a literal NUL, because a raw
 * control byte in a source file is invisible in review and corrupts the file for
 * any tool that treats it as binary — which is exactly how it slipped in the first
 * time.
 */
const KEY_SEP = String.fromCharCode(0);

/** The five §3.1 statuses, so `status_counts` always carries every key at zero. */
const ALL_STATUSES = [
  STATUS.MANUFACTURED,
  STATUS.IN_TRANSIT,
  STATUS.AT_PHARMACY,
  STATUS.DISPENSED,
  STATUS.RECALLED,
];

/** A report is "open" until it is resolved; confirmed and dismissed are terminal. */
const OPEN_REPORT_STATUSES = new Set(['new', 'triaged']);

/** `days_to_expiry <= EXPIRING_SOON_DAYS` with stock left is the pull-from-shelf list. */
const EXPIRING_SOON_DAYS = 90;

/** Rank for worst-first ordering; mirrors §2.3, most severe highest. */
const SEVERITY_RANK = { [SEVERITY.OK]: 0, [SEVERITY.WARN]: 1, [SEVERITY.CRITICAL]: 2 };

/** The more severe of two §2.3 severities. */
function worseSeverity(a, b) {
  return (SEVERITY_RANK[b] ?? 0) > (SEVERITY_RANK[a] ?? 0) ? b : a;
}

/** Distinct scan districts on a record, tolerating a missing or malformed field. */
function districtCount(record) {
  return Array.isArray(record?.distinct_scan_districts)
    ? record.distinct_scan_districts.length
    : 0;
}

/**
 * The §2.3 severity of a unit's current chain state, or CRITICAL when there is no
 * unit — a report whose product ID is not on the ledger is the counterfeit case,
 * and colouring it anything softer would bury the most serious signal the board
 * carries.
 */
function recordSeverity(record, today) {
  if (!record) return SEVERITY.CRITICAL;
  const verdict = chainVerdict({
    status: record.status,
    expired: isExpired(record.expiry_date, today),
    breached: Boolean(record.cold_chain_breached),
    cloneSuspected: cloneSuspected(Number(record.scan_count ?? 0), districtCount(record)),
  });
  return severityFor(verdict);
}

/** Parse a timestamp to epoch ms, or NaN for the ledger's empty-string "never". */
function tsMs(value) {
  if (typeof value !== 'string' || value === '') return NaN;
  return Date.parse(value);
}

/** True when `value` is a real timestamp inside `[fromMs, toMs]`. */
function inWindow(value, fromMs, toMs) {
  const t = tsMs(value);
  return Number.isFinite(t) && t >= fromMs && t <= toMs;
}

/**
 * `?days=` and `?limit=`, validated to the §4.4a ranges.
 *
 * Out of range is a 400 rather than a silent clamp, because a client asking for
 * `?days=9999` has a bug the operator should see, and a clamp would answer a
 * different question than the one asked without saying so.
 */
function readWindow(query, clock) {
  const days = intParam(query?.days, 'days', 1, 365, 30);
  const limit = intParam(query?.limit, 'limit', 1, MAX_PAGE_SIZE, DEFAULT_PAGE_SIZE);
  const toMs = clock().getTime();
  const fromMs = toMs - days * DAY_MS;
  return {
    days,
    limit,
    fromMs,
    toMs,
    window: {
      from: new Date(fromMs).toISOString(),
      to: new Date(toMs).toISOString(),
      days,
    },
  };
}

/** A bounded integer query param with a default when absent. */
function intParam(raw, name, min, max, dflt) {
  if (raw === undefined || raw === null || raw === '') return dflt;
  const value = Array.isArray(raw) ? raw[raw.length - 1] : raw;
  const n = Number(value);
  if (!Number.isInteger(n) || n < min || n > max) {
    throw validationError(`${name} must be an integer between ${min} and ${max}`);
  }
  return n;
}

/**
 * Order rows, keep `limit`, and report whether any were dropped.
 *
 * §4.4a chooses a single `truncated` flag over a cursor on purpose: these are
 * worst-first triage screens, and a regulator who needs the long tail needs an
 * export, not page two.
 */
function limitRows(rows, limit) {
  return { rows: rows.slice(0, limit), truncated: rows.length > limit };
}

/**
 * @param {{fabric: object, store: object,
 *          logger?: import('../utils/logger.js').Logger,
 *          clock?: () => Date}} deps
 */
export function makeDashboardsService({ fabric, store, logger, clock = () => new Date() }) {
  /**
   * A `product_id → record` index over the whole ledger, built once per request.
   *
   * Every aggregate here needs to look a reported product's batch and manufacturer
   * up, and re-scanning per report would be quadratic. The scan is already bounded
   * by the driver (the gateway pages and caps it; the mock holds an array).
   */
  async function ledgerIndex() {
    const records = await fabric.allMedicines();
    const byProduct = new Map();
    for (const record of records) {
      if (record?.product_id) byProduct.set(record.product_id, record);
    }
    return { records, byProduct };
  }

  /**
   * `GET /api/dashboard/cdsco` → 200. Regulator only (gated by the route).
   *
   * @param {object} query  the parsed query string (`days`, `limit`)
   * @returns {Promise<object>} the §4.4a CDSCO body
   */
  async function cdsco(query) {
    const { limit, fromMs, toMs, window } = readWindow(query, clock);
    const today = clock();
    const { records, byProduct } = await ledgerIndex();

    // Newest-first and bounded: this is a triage feed, and the most recent
    // MAX_PAGE_SIZE reports are what a heat map and an alert queue are built from.
    const reports = await store.recentReports({ limit: MAX_PAGE_SIZE });
    const windowReports = reports.filter((r) => inWindow(r.created_at, fromMs, toMs));

    // ── Totals: every count bounded by the window (CDSCO measures events) ──
    let reportsOpen = 0;
    for (const r of windowReports) {
      if (OPEN_REPORT_STATUSES.has(r.status ?? 'new')) reportsOpen += 1;
    }

    let unitsRecalled = 0;
    let coldChainBreaches = 0;
    let cloneCount = 0;
    for (const record of records) {
      if (record.status === STATUS.RECALLED && inWindow(record.recalled_at, fromMs, toMs)) {
        unitsRecalled += 1;
      }
      if (record.cold_chain_breached && inWindow(record.cold_chain_breached_at, fromMs, toMs)) {
        coldChainBreaches += 1;
      }
      if (
        cloneSuspected(Number(record.scan_count ?? 0), districtCount(record)) &&
        inWindow(record.last_scan_at || record.first_scan_at, fromMs, toMs)
      ) {
        cloneCount += 1;
      }
    }

    // ── Districts: the heat map, one row per (district, state) with reports ──
    const districts = new Map();
    for (const r of windowReports) {
      const district = (r.district ?? '').trim();
      // A report with no district cannot be placed on a district heat map. It still
      // counts in totals.reports above; it just has no point to plot.
      if (!district) continue;
      const state = (r.state ?? '').trim();
      const key = `${district}${KEY_SEP}${state}`;
      let row = districts.get(key);
      if (!row) {
        row = { district, state, reports: 0, batches: new Set(), severity: SEVERITY.OK };
        districts.set(key, row);
      }
      row.reports += 1;
      const record = byProduct.get(r.product_id) ?? null;
      if (record?.batch_no) row.batches.add(record.batch_no);
      row.severity = worseSeverity(row.severity, recordSeverity(record, today));
    }
    const districtRows = [...districts.values()]
      .map((row) => ({
        district: row.district,
        state: row.state,
        reports: row.reports,
        distinct_batches: row.batches.size,
        severity: row.severity,
      }))
      .sort((a, b) => b.reports - a.reports || a.district.localeCompare(b.district));

    // ── Alerts: worst-first triage feed drawn from four sources ──
    const alerts = [];

    for (const r of windowReports) {
      const record = byProduct.get(r.product_id) ?? null;
      const where = [r.pharmacy_name, r.district, r.state].map((s) => (s ?? '').trim()).filter(Boolean);
      alerts.push({
        kind: 'counterfeit_report',
        severity: worseSeverity(SEVERITY.WARN, recordSeverity(record, today)),
        product_id: r.product_id ?? null,
        batch_no: record?.batch_no ?? null,
        manufacturer: record?.manufacturer ?? null,
        detail: where.length ? `Reported at ${where.join(', ')}` : 'Counterfeit reported',
        at: r.created_at ?? null,
      });
    }

    // Batch-level bookkeeping for the recall_incomplete alert: a batch with some
    // units recalled and some still live is a recall that stopped early (§4.4a),
    // the only trace of a client that dropped the loop before `more_remaining`
    // went false.
    const batchState = new Map();

    for (const record of records) {
      const batch = record.batch_no;
      if (batch) {
        let bs = batchState.get(batch);
        if (!bs) {
          bs = { total: 0, recalled: 0, live: 0, manufacturer: record.manufacturer, latestRecall: '' };
          batchState.set(batch, bs);
        }
        bs.total += 1;
        if (record.status === STATUS.RECALLED) {
          bs.recalled += 1;
          if (tsMs(record.recalled_at) > (tsMs(bs.latestRecall) || 0)) bs.latestRecall = record.recalled_at;
        } else {
          bs.live += 1;
        }
      }

      if (record.cold_chain_breached && inWindow(record.cold_chain_breached_at, fromMs, toMs)) {
        alerts.push({
          kind: 'cold_chain_breach',
          severity: SEVERITY.CRITICAL,
          product_id: record.product_id,
          batch_no: record.batch_no ?? null,
          manufacturer: record.manufacturer ?? null,
          detail: coldRangeDetail(record),
          at: record.cold_chain_breached_at,
        });
      }

      if (
        cloneSuspected(Number(record.scan_count ?? 0), districtCount(record)) &&
        inWindow(record.last_scan_at || record.first_scan_at, fromMs, toMs)
      ) {
        alerts.push({
          kind: 'clone_suspected',
          severity: SEVERITY.CRITICAL,
          product_id: record.product_id,
          batch_no: record.batch_no ?? null,
          manufacturer: record.manufacturer ?? null,
          detail: `${Number(record.scan_count ?? 0)} scans across ${districtCount(record)} districts`,
          at: record.last_scan_at || record.first_scan_at || null,
        });
      }
    }

    for (const [batch, bs] of batchState) {
      // Incomplete only when the recall actually started, left units live, and did
      // so within the window — a batch never recalled is not an incomplete recall.
      if (bs.recalled > 0 && bs.live > 0 && inWindow(bs.latestRecall, fromMs, toMs)) {
        alerts.push({
          kind: 'recall_incomplete',
          severity: SEVERITY.CRITICAL,
          product_id: null,
          batch_no: batch,
          manufacturer: bs.manufacturer ?? null,
          detail: `${bs.recalled} of ${bs.total} units recalled; ${bs.live} still live on chain`,
          at: bs.latestRecall || null,
        });
      }
    }

    alerts.sort(
      (a, b) =>
        (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0) ||
        (tsMs(b.at) || 0) - (tsMs(a.at) || 0),
    );

    const districtsOut = limitRows(districtRows, limit);
    const alertsOut = limitRows(alerts, limit);

    return {
      window,
      totals: {
        reports: windowReports.length,
        reports_open: reportsOpen,
        units_recalled: unitsRecalled,
        cold_chain_breaches: coldChainBreaches,
        clone_suspected: cloneCount,
      },
      districts: districtsOut.rows,
      alerts: alertsOut.rows.map(stripNulls),
      truncated: districtsOut.truncated || alertsOut.truncated,
    };
  }

  /**
   * `GET /api/dashboard/pharma` → 200. Pharma role only (gated by the route).
   *
   * @param {{scope?: string}} auth  the authenticated key; `scope` is the mfg_licence_no
   * @param {object} query
   * @returns {Promise<object>} the §4.4a pharma body
   */
  async function pharma(auth, query) {
    const mfgLicenceNo = (auth?.scope ?? '').trim();
    if (!mfgLicenceNo) {
      // An unscoped pharma key would otherwise filter on '' and, since no real unit
      // carries a blank licence, silently return an empty dashboard — hiding a
      // misissued key instead of surfacing it.
      throw forbidden(
        'this pharma key has no manufacturer scope; re-issue it with ' +
          '`npm run issue-key -- --role pharma --scope <mfg_licence_no>`',
      );
    }

    const { limit, fromMs, toMs, window } = readWindow(query, clock);
    const today = clock();
    const { records } = await ledgerIndex();
    const mine = records.filter((r) => r.mfg_licence_no === mfgLicenceNo);

    // The window bounds reports, not stock: a manufacturer needs current shelf
    // state. So reports are filtered by created_at and indexed by product.
    const reports = await store.recentReports({ limit: MAX_PAGE_SIZE });
    const reportsByProduct = new Map();
    for (const r of reports) {
      if (!inWindow(r.created_at, fromMs, toMs)) continue;
      const list = reportsByProduct.get(r.product_id);
      if (list) list.push(r);
      else reportsByProduct.set(r.product_id, [r]);
    }

    // Current-state totals across every unit this manufacturer owns.
    let unitsMinted = 0;
    let unitsDispensed = 0;
    let unitsRecalled = 0;
    const batches = new Map();

    for (const record of mine) {
      unitsMinted += 1;
      if (record.status === STATUS.DISPENSED) unitsDispensed += 1;
      if (record.status === STATUS.RECALLED) unitsRecalled += 1;

      const batchNo = record.batch_no ?? '';
      let batch = batches.get(batchNo);
      if (!batch) {
        batch = {
          batch_no: batchNo,
          generic_name: record.generic_name ?? '',
          brand_name: record.brand_name ?? '',
          type: record.type ?? TYPE.MEDICINE,
          mfg_date: record.mfg_date ?? null,
          expiry_date: record.expiry_date ?? '',
          statusCounts: Object.fromEntries(ALL_STATUSES.map((s) => [s, 0])),
          unitCount: 0,
          breached: false,
          minC: null,
          maxC: null,
          readingCount: 0,
          severity: SEVERITY.OK,
          reportedProducts: new Set(),
        };
        batches.set(batchNo, batch);
      }

      batch.unitCount += 1;
      if (batch.statusCounts[record.status] !== undefined) batch.statusCounts[record.status] += 1;
      batch.severity = worseSeverity(batch.severity, recordSeverity(record, today));

      if (batch.type === TYPE.VACCINE) {
        if (record.cold_chain_breached) batch.breached = true;
        const count = Number(record.temp_reading_count ?? 0);
        if (count > 0) {
          batch.readingCount += count;
          const lo = Number(record.temp_min_c);
          const hi = Number(record.temp_max_c);
          if (Number.isFinite(lo)) batch.minC = batch.minC === null ? lo : Math.min(batch.minC, lo);
          if (Number.isFinite(hi)) batch.maxC = batch.maxC === null ? hi : Math.max(batch.maxC, hi);
        }
      }

      if (reportsByProduct.has(record.product_id)) batch.reportedProducts.add(record.product_id);
    }

    // §4.4a: the manufacturer name is read from the units themselves, so it is the
    // one on the signed records rather than anything the key or query supplied.
    const manufacturer = mine.length ? mine[0].manufacturer ?? '' : '';

    const batchRows = [...batches.values()]
      .map((batch) => {
        let reportCount = 0;
        for (const pid of batch.reportedProducts) reportCount += reportsByProduct.get(pid).length;
        // A batch carrying an open report is at least a WARN even if every unit
        // still reads GENUINE: a patient flagged it, and the board should show that.
        const severity = reportCount > 0 ? worseSeverity(batch.severity, SEVERITY.WARN) : batch.severity;
        return {
          batch_no: batch.batch_no,
          generic_name: batch.generic_name,
          brand_name: batch.brand_name,
          type: batch.type,
          mfg_date: batch.mfg_date,
          expiry_date: batch.expiry_date,
          days_to_expiry: daysToExpiry(batch.expiry_date, today),
          unit_count: batch.unitCount,
          status_counts: batch.statusCounts,
          cold_chain: {
            applicable: batch.type === TYPE.VACCINE,
            breached: batch.breached,
            min_c: batch.readingCount > 0 ? batch.minC : null,
            max_c: batch.readingCount > 0 ? batch.maxC : null,
            reading_count: batch.readingCount,
          },
          reports: reportCount,
          worst_severity: severity,
        };
      })
      .sort(
        (a, b) =>
          (SEVERITY_RANK[b.worst_severity] ?? 0) - (SEVERITY_RANK[a.worst_severity] ?? 0) ||
          a.days_to_expiry - b.days_to_expiry ||
          a.batch_no.localeCompare(b.batch_no),
      );

    // expiring_soon: forward-looking and never windowed. Units remaining are those
    // not yet dispensed or recalled — the number that decides whether to pull stock.
    const expiring = batchRows
      .map((batch) => {
        const remaining =
          batch.status_counts[STATUS.MANUFACTURED] +
          batch.status_counts[STATUS.IN_TRANSIT] +
          batch.status_counts[STATUS.AT_PHARMACY];
        return {
          batch_no: batch.batch_no,
          expiry_date: batch.expiry_date,
          days_to_expiry: batch.days_to_expiry,
          units_remaining: remaining,
        };
      })
      .filter((row) => row.days_to_expiry <= EXPIRING_SOON_DAYS && row.units_remaining > 0)
      .sort((a, b) => a.days_to_expiry - b.days_to_expiry || a.batch_no.localeCompare(b.batch_no));

    const batchesOut = limitRows(batchRows, limit);
    const expiringOut = limitRows(expiring, limit);

    if (batchesOut.truncated || expiringOut.truncated) {
      logger?.info?.('pharma dashboard truncated', {
        mfg_licence_no: mfgLicenceNo,
        batches: batchRows.length,
        limit,
      });
    }

    return {
      manufacturer,
      mfg_licence_no: mfgLicenceNo,
      window,
      totals: {
        units_minted: unitsMinted,
        units_dispensed: unitsDispensed,
        units_recalled: unitsRecalled,
        batches: batches.size,
      },
      batches: batchesOut.rows,
      expiring_soon: expiringOut.rows,
      truncated: batchesOut.truncated || expiringOut.truncated,
    };
  }

  return { cdsco, pharma };
}

/** A human line for a cold-chain breach alert, using whatever range was recorded. */
function coldRangeDetail(record) {
  const count = Number(record.temp_reading_count ?? 0);
  if (count <= 0) return 'Cold chain breach recorded';
  const lo = Number(record.temp_min_c);
  const hi = Number(record.temp_max_c);
  const parts = [];
  if (Number.isFinite(lo)) parts.push(`min ${lo.toFixed(1)}°C`);
  if (Number.isFinite(hi)) parts.push(`max ${hi.toFixed(1)}°C`);
  return parts.length ? `Temperature out of range (${parts.join(', ')})` : 'Cold chain breach recorded';
}

/**
 * Drop null-valued optional keys from an alert.
 *
 * §4.4a lists `product_id`, `batch_no`, `manufacturer` and `at` as present on the
 * alerts that have them; a batch-level `recall_incomplete` has no single product,
 * so emitting `product_id: null` would invite a client to render an empty field.
 * The Dart parser treats all four as optional, so omitting a null is compatible and
 * cleaner than sending it. `kind`, `severity` and `detail` are always kept.
 */
function stripNulls(alert) {
  const out = { kind: alert.kind, severity: alert.severity, detail: alert.detail };
  if (alert.product_id != null) out.product_id = alert.product_id;
  if (alert.batch_no != null) out.batch_no = alert.batch_no;
  if (alert.manufacturer != null) out.manufacturer = alert.manufacturer;
  if (alert.at != null) out.at = alert.at;
  return out;
}

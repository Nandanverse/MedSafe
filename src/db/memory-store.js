/**
 * In-memory persistence store — the driver behind the mock stack and the tests.
 *
 * It holds the three tables that live *off* the ledger, in ordinary Maps:
 *
 * - **api_keys** — the API's own auth. Keys are stored as SHA-256 hashes, never
 *   in the clear, so a dump of this table cannot be replayed as credentials.
 * - **sensors** — one shared HMAC secret per cold-box sensor, sealed with the
 *   app's encryption key (AES-256-GCM via SecretBox) so the secret is unreadable
 *   at rest.
 * - **counterfeit_reports** — patient submissions. The reporter's contact detail
 *   is sealed the same way; the photo and coarse location are stored as given.
 *
 * These are not on the blockchain on purpose: they are private operational data
 * (credentials, personal contact details, citizen reports), the opposite of the
 * public, immutable supply-chain facts the ledger is for. Postgres owns them in
 * production; this Map-backed twin lets the API and its tests run with no
 * database, and is the reference for what postgres.js and schema.sql must do.
 */

import { randomUUID } from 'node:crypto';

import { stamp } from '../core/rules.js';

const clone = (v) => (v == null ? v : JSON.parse(JSON.stringify(v)));

/** Copy a row for return, turning any Buffer field back into a real Buffer. */
function outRow(row) {
  if (!row) return null;
  const copy = { ...row };
  for (const k of ['secret_enc', 'reporter_contact_enc', 'photo']) {
    if (Buffer.isBuffer(row[k])) copy[k] = Buffer.from(row[k]);
  }
  return copy;
}

export class MemoryStore {
  /**
   * @param {{clock?: () => Date, logger?: import('../utils/logger.js').Logger}} [opts]
   */
  constructor(opts = {}) {
    this.driver = 'memory';
    this.clock = opts.clock ?? (() => new Date());
    this.log = opts.logger ?? null;
    /** key_hash → api_key row */
    this.apiKeys = new Map();
    /** sensor_id → sensor row */
    this.sensors = new Map();
    /** id → counterfeit_report row */
    this.reports = new Map();
  }

  #now() {
    return stamp(this.clock());
  }

  // ── API keys ────────────────────────────────────────────────────────────────

  /**
   * @param {{role: string, keyHash: string, label?: string, scope?: string}} rec
   *   `scope` carries the holder's mfg_licence_no for a `pharma` key and is the
   *   only thing confining that key to one manufacturer's batches (§4.4a).
   * @returns {Promise<object>} the stored row (without the plaintext key, which
   *   the store never sees)
   */
  async insertApiKey({ role, keyHash, label = '', scope = '' }) {
    if (this.apiKeys.has(keyHash)) {
      // A hash collision here means the same random key was generated twice —
      // astronomically unlikely, but surface it rather than overwrite.
      throw new Error('an API key with this hash already exists');
    }
    const row = {
      id: randomUUID(),
      role,
      key_hash: keyHash,
      label,
      scope,
      created_at: this.#now(),
      revoked_at: null,
      last_used_at: null,
    };
    this.apiKeys.set(keyHash, row);
    return clone(row);
  }

  /**
   * Look up a live (non-revoked) API key by its SHA-256 hash.
   * @returns {Promise<object|null>}
   */
  async findApiKey(keyHash) {
    const row = this.apiKeys.get(keyHash);
    if (!row || row.revoked_at) return null;
    return clone(row);
  }

  /** Best-effort last-used stamp; never fails a request if it can't record. */
  async touchApiKey(keyHash) {
    const row = this.apiKeys.get(keyHash);
    if (row) row.last_used_at = this.#now();
  }

  async revokeApiKey(keyHash) {
    const row = this.apiKeys.get(keyHash);
    if (!row || row.revoked_at) return false;
    row.revoked_at = this.#now();
    return true;
  }

  // ── Sensors ──────────────────────────────────────────────────────────────────

  /**
   * @param {{sensorId: string, secretEnc: Buffer, label?: string}} rec
   */
  async insertSensor({ sensorId, secretEnc, label = '' }) {
    if (!Buffer.isBuffer(secretEnc)) {
      throw new Error('secretEnc must be a Buffer (the sealed sensor secret)');
    }
    const row = {
      sensor_id: sensorId,
      secret_enc: Buffer.from(secretEnc),
      label,
      created_at: this.#now(),
      revoked_at: null,
    };
    this.sensors.set(sensorId, row);
    return outRow(row);
  }

  /** Live sensor by id, or null if unknown or revoked. */
  async getSensor(sensorId) {
    const row = this.sensors.get(sensorId);
    if (!row || row.revoked_at) return null;
    return outRow(row);
  }

  async revokeSensor(sensorId) {
    const row = this.sensors.get(sensorId);
    if (!row || row.revoked_at) return false;
    row.revoked_at = this.#now();
    return true;
  }

  // ── Counterfeit reports ───────────────────────────────────────────────────────

  /**
   * Store a patient counterfeit report. The reporter contact, if any, arrives
   * already sealed by the route (SecretBox + reportContext(id)); the store keeps
   * the ciphertext and never the plaintext.
   *
   * @param {object} r
   * @param {string} [r.id]                 report reference; generated if absent
   * @param {string} r.product_id
   * @param {string} [r.pharmacy_name]
   * @param {string} [r.district]
   * @param {string} [r.state]
   * @param {number|null} [r.lat]
   * @param {number|null} [r.lon]
   * @param {string} [r.notes]
   * @param {Buffer|null} [r.photo]
   * @param {number} [r.photo_bytes]
   * @param {Buffer|null} [r.reporter_contact_enc]
   * @param {string|null} [r.client_ip]
   * @returns {Promise<object>} the stored row
   */
  async insertReport(r) {
    const id = r.id ?? randomUUID();
    const row = {
      id,
      created_at: this.#now(),
      product_id: r.product_id,
      pharmacy_name: r.pharmacy_name ?? '',
      district: r.district ?? '',
      state: r.state ?? '',
      lat: r.lat ?? null,
      lon: r.lon ?? null,
      notes: r.notes ?? '',
      photo: Buffer.isBuffer(r.photo) ? Buffer.from(r.photo) : null,
      photo_bytes: r.photo_bytes ?? (Buffer.isBuffer(r.photo) ? r.photo.length : 0),
      reporter_contact_enc: Buffer.isBuffer(r.reporter_contact_enc)
        ? Buffer.from(r.reporter_contact_enc)
        : null,
      client_ip: r.client_ip ?? null,
      status: r.status ?? 'new',
    };
    this.reports.set(id, row);
    this.log?.info('counterfeit report stored', {
      report_id: id,
      product_id: row.product_id,
      has_photo: row.photo != null,
    });
    return outRow(row);
  }

  async getReport(id) {
    return outRow(this.reports.get(id));
  }

  /**
   * Reports for a product, newest first — the CDSCO dashboard's per-product view.
   * Contact ciphertext is omitted here; it is decrypted only on an explicit,
   * audited single-report fetch, not in a list.
   */
  async reportsForProduct(productID, { limit = 100 } = {}) {
    const out = [];
    for (const row of this.reports.values()) {
      if (row.product_id === productID) out.push(stripContact(outRow(row)));
    }
    out.sort((a, b) => (a.created_at < b.created_at ? 1 : -1));
    return out.slice(0, limit);
  }

  async recentReports({ limit = 100 } = {}) {
    const out = [...this.reports.values()].map((r) => stripContact(outRow(r)));
    out.sort((a, b) => (a.created_at < b.created_at ? 1 : -1));
    return out.slice(0, limit);
  }

  async ping() {
    return { ok: true, driver: 'memory' };
  }

  async close() {
    this.apiKeys.clear();
    this.sensors.clear();
    this.reports.clear();
  }
}

/** Drop the encrypted contact from a row bound for a list/dashboard view. */
function stripContact(row) {
  if (!row) return row;
  const { reporter_contact_enc, ...rest } = row;
  rest.has_contact = reporter_contact_enc != null;
  return rest;
}

/**
 * PostgreSQL persistence driver, used when FABRIC_MOCK=0.
 *
 * Identical interface to MemoryStore, so routes never branch on the driver. As
 * with the Fabric and Redis clients, the `pg` package is imported lazily inside
 * connect(): the mock/test path must load on a machine that never installed the
 * production dependencies, and a missing package should be an actionable startup
 * message rather than an import crash.
 *
 * Every timestamp is normalised to an ISO-8601 string on the way out, and every
 * BYTEA column comes back as a Node Buffer (node-postgres does this already), so
 * a row from Postgres is shaped exactly like a row from MemoryStore. Queries are
 * always parameterised — no SQL is ever built by string concatenation.
 */

import { randomUUID } from 'node:crypto';

import { CODES, TrueMedError } from '../core/errors.js';

/** TIMESTAMPTZ arrives as a JS Date; emit ISO strings for a stable shape. */
const iso = (v) => (v instanceof Date ? v.toISOString() : v ?? null);

function mapApiKey(row) {
  if (!row) return null;
  return {
    id: row.id,
    role: row.role,
    key_hash: row.key_hash,
    label: row.label,
    // Defaulted rather than passed through: a row read from a database that has
    // not had the 2026-08-24 ALTER applied yet has no such column, and `undefined`
    // reaching the pharma dashboard's scope check would read as "unscoped".
    scope: row.scope ?? '',
    created_at: iso(row.created_at),
    revoked_at: iso(row.revoked_at),
    last_used_at: iso(row.last_used_at),
  };
}

function mapSensor(row) {
  if (!row) return null;
  return {
    sensor_id: row.sensor_id,
    secret_enc: row.secret_enc, // Buffer from pg
    label: row.label,
    created_at: iso(row.created_at),
    revoked_at: iso(row.revoked_at),
  };
}

function mapReport(row) {
  if (!row) return null;
  return {
    id: row.id,
    created_at: iso(row.created_at),
    product_id: row.product_id,
    pharmacy_name: row.pharmacy_name,
    district: row.district,
    state: row.state,
    lat: row.lat,
    lon: row.lon,
    notes: row.notes,
    photo: row.photo ?? null,
    photo_bytes: row.photo_bytes,
    reporter_contact_enc: row.reporter_contact_enc ?? null,
    client_ip: row.client_ip,
    status: row.status,
  };
}

export class PostgresStore {
  /**
   * @param {object} dbCfg   config.db
   * @param {import('../utils/logger.js').Logger} logger
   */
  constructor(dbCfg, logger) {
    this.driver = 'postgres';
    this.cfg = dbCfg;
    this.log = logger;
    this.pool = null;
  }

  async connect() {
    if (this.pool) return;

    let Pool;
    try {
      ({ Pool } = await import('pg'));
    } catch (cause) {
      throw new TrueMedError(
        CODES.INTERNAL_ERROR,
        'FABRIC_MOCK=0 but the `pg` package is not installed. Run `npm ci` in ' +
          'backend/ so PostgreSQL support is available.',
        { cause, expose: false },
      );
    }

    this.pool = new Pool({
      connectionString: this.cfg.url,
      max: this.cfg.poolMax,
      connectionTimeoutMillis: this.cfg.connectTimeoutMs,
      statement_timeout: this.cfg.statementTimeoutMs,
      ssl: this.cfg.ssl || undefined,
    });
    // A pool 'error' fires for idle clients dropped by the server; log rather
    // than let it bubble as an unhandled rejection and take the process down.
    this.pool.on('error', (err) => {
      this.log?.warn('postgres idle client error', { error: err?.message });
    });

    // A fresh container often beats Postgres to readiness; retry a bounded number
    // of times so the first query doesn't crash-loop the service.
    let lastErr;
    for (let attempt = 1; attempt <= this.cfg.connectRetries; attempt += 1) {
      try {
        await this.pool.query('SELECT 1');
        this.log?.info('connected to postgres', { attempt });
        return;
      } catch (err) {
        lastErr = err;
        this.log?.warn('postgres not ready; will retry', {
          attempt,
          of: this.cfg.connectRetries,
          error: err?.message,
        });
        await delay(this.cfg.connectRetryDelayMs);
      }
    }
    throw new TrueMedError(
      CODES.UPSTREAM_UNAVAILABLE,
      'could not connect to PostgreSQL after retries',
      { cause: lastErr, expose: false },
    );
  }

  async #ensure() {
    if (!this.pool) await this.connect();
  }

  async #query(text, params) {
    await this.#ensure();
    return this.pool.query(text, params);
  }

  // ── API keys ────────────────────────────────────────────────────────────────

  async insertApiKey({ role, keyHash, label = '', scope = '' }) {
    const { rows } = await this.#query(
      `INSERT INTO api_keys (role, key_hash, label, scope)
       VALUES ($1, $2, $3, $4)
       RETURNING id, role, key_hash, label, scope, created_at, revoked_at, last_used_at`,
      [role, keyHash, label, scope],
    );
    return mapApiKey(rows[0]);
  }

  async findApiKey(keyHash) {
    const { rows } = await this.#query(
      `SELECT id, role, key_hash, label, scope, created_at, revoked_at, last_used_at
         FROM api_keys
        WHERE key_hash = $1 AND revoked_at IS NULL`,
      [keyHash],
    );
    return mapApiKey(rows[0]);
  }

  async touchApiKey(keyHash) {
    try {
      await this.#query(`UPDATE api_keys SET last_used_at = now() WHERE key_hash = $1`, [keyHash]);
    } catch (err) {
      // Best-effort telemetry; never fail a request because we couldn't stamp it.
      this.log?.debug('touchApiKey failed', { error: err?.message });
    }
  }

  async revokeApiKey(keyHash) {
    const { rowCount } = await this.#query(
      `UPDATE api_keys SET revoked_at = now() WHERE key_hash = $1 AND revoked_at IS NULL`,
      [keyHash],
    );
    return rowCount > 0;
  }

  // ── Sensors ──────────────────────────────────────────────────────────────────

  async insertSensor({ sensorId, secretEnc, label = '' }) {
    if (!Buffer.isBuffer(secretEnc)) {
      throw new Error('secretEnc must be a Buffer (the sealed sensor secret)');
    }
    const { rows } = await this.#query(
      `INSERT INTO sensors (sensor_id, secret_enc, label)
       VALUES ($1, $2, $3)
       RETURNING sensor_id, secret_enc, label, created_at, revoked_at`,
      [sensorId, secretEnc, label],
    );
    return mapSensor(rows[0]);
  }

  async getSensor(sensorId) {
    const { rows } = await this.#query(
      `SELECT sensor_id, secret_enc, label, created_at, revoked_at
         FROM sensors
        WHERE sensor_id = $1 AND revoked_at IS NULL`,
      [sensorId],
    );
    return mapSensor(rows[0]);
  }

  async revokeSensor(sensorId) {
    const { rowCount } = await this.#query(
      `UPDATE sensors SET revoked_at = now() WHERE sensor_id = $1 AND revoked_at IS NULL`,
      [sensorId],
    );
    return rowCount > 0;
  }

  // ── Counterfeit reports ───────────────────────────────────────────────────────

  async insertReport(r) {
    const id = r.id ?? randomUUID();
    const photo = Buffer.isBuffer(r.photo) ? r.photo : null;
    const { rows } = await this.#query(
      `INSERT INTO counterfeit_reports
         (id, product_id, pharmacy_name, district, state, lat, lon, notes,
          photo, photo_bytes, reporter_contact_enc, client_ip, status)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
       RETURNING id, created_at, product_id, pharmacy_name, district, state,
                 lat, lon, notes, photo, photo_bytes, reporter_contact_enc,
                 client_ip, status`,
      [
        id,
        r.product_id,
        r.pharmacy_name ?? '',
        r.district ?? '',
        r.state ?? '',
        r.lat ?? null,
        r.lon ?? null,
        r.notes ?? '',
        photo,
        r.photo_bytes ?? (photo ? photo.length : 0),
        Buffer.isBuffer(r.reporter_contact_enc) ? r.reporter_contact_enc : null,
        r.client_ip ?? null,
        r.status ?? 'new',
      ],
    );
    this.log?.info('counterfeit report stored', {
      report_id: id,
      product_id: r.product_id,
      has_photo: photo != null,
    });
    return mapReport(rows[0]);
  }

  async getReport(id) {
    const { rows } = await this.#query(
      `SELECT id, created_at, product_id, pharmacy_name, district, state,
              lat, lon, notes, photo, photo_bytes, reporter_contact_enc,
              client_ip, status
         FROM counterfeit_reports WHERE id = $1`,
      [id],
    );
    return mapReport(rows[0]);
  }

  async reportsForProduct(productID, { limit = 100 } = {}) {
    const { rows } = await this.#query(
      `SELECT id, created_at, product_id, pharmacy_name, district, state,
              lat, lon, notes, photo_bytes, client_ip, status,
              (reporter_contact_enc IS NOT NULL) AS has_contact
         FROM counterfeit_reports
        WHERE product_id = $1
        ORDER BY created_at DESC
        LIMIT $2`,
      [productID, limit],
    );
    return rows.map(listRow);
  }

  async recentReports({ limit = 100 } = {}) {
    const { rows } = await this.#query(
      `SELECT id, created_at, product_id, pharmacy_name, district, state,
              lat, lon, notes, photo_bytes, client_ip, status,
              (reporter_contact_enc IS NOT NULL) AS has_contact
         FROM counterfeit_reports
        ORDER BY created_at DESC
        LIMIT $1`,
      [limit],
    );
    return rows.map(listRow);
  }

  async ping() {
    await this.#query('SELECT 1');
    return { ok: true, driver: 'postgres' };
  }

  async close() {
    if (!this.pool) return;
    try {
      await this.pool.end();
    } finally {
      this.pool = null;
    }
  }
}

/** List-view row: ISO timestamp, no contact ciphertext, has_contact flag only. */
function listRow(row) {
  return {
    id: row.id,
    created_at: iso(row.created_at),
    product_id: row.product_id,
    pharmacy_name: row.pharmacy_name,
    district: row.district,
    state: row.state,
    lat: row.lat,
    lon: row.lon,
    notes: row.notes,
    photo_bytes: row.photo_bytes,
    client_ip: row.client_ip,
    status: row.status,
    has_contact: row.has_contact === true,
  };
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

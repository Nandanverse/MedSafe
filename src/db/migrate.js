/**
 * Apply src/db/schema.sql to the configured PostgreSQL database.
 *
 *   node src/db/migrate.js            # apply schema (idempotent)
 *   npm run migrate
 *
 * There is no migration framework here on purpose: for a project this size a
 * single idempotent schema file, versioned in git and re-runnable safely, is
 * clearer than a chain of up/down migrations. The schema uses CREATE ... IF NOT
 * EXISTS throughout, so running this repeatedly is a no-op after the first time.
 *
 * This talks to Postgres directly rather than through PostgresStore, because its
 * job is DDL, not the row queries the store wraps. It loads DATABASE_URL from the
 * same config the server uses, so "migrate then start" always target one database.
 */

import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { config } from '../config/index.js';
import { logger } from '../utils/logger.js';

const here = dirname(fileURLToPath(import.meta.url));

async function main() {
  const schemaPath = join(here, 'schema.sql');
  const sql = await readFile(schemaPath, 'utf8');

  let Pool;
  try {
    ({ Pool } = await import('pg'));
  } catch (cause) {
    logger.error('the `pg` package is not installed; run `npm ci` in backend/ first', {
      error: cause?.message,
    });
    process.exitCode = 1;
    return;
  }

  if (config.fabric.mock) {
    logger.warn(
      'FABRIC_MOCK=1: the mock stack uses the in-memory store and needs no ' +
        'database. Migrating anyway because migrate.js was run explicitly — set ' +
        'DATABASE_URL to the target database.',
    );
  }

  const pool = new Pool({
    connectionString: config.db.url,
    max: 1,
    connectionTimeoutMillis: config.db.connectTimeoutMs,
    ssl: config.db.ssl || undefined,
  });

  try {
    logger.info('applying schema', { file: schemaPath });
    await pool.query(sql);
    logger.info('schema applied successfully');
  } catch (err) {
    logger.error('migration failed', { error: err?.message });
    process.exitCode = 1;
  } finally {
    await pool.end();
  }
}

main().catch((err) => {
  logger.error('migration crashed', { error: err?.message });
  process.exitCode = 1;
});

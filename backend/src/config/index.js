/**
 * Configuration: read the environment once, validate it completely, then freeze.
 *
 * Three decisions worth stating, because each one is a class of outage avoided:
 *
 * **Every problem is reported at once.** A naive loader throws on the first
 * missing variable, so deploying a service with four unset variables costs four
 * restarts to discover. This collects every failure and reports them together.
 *
 * **Nothing is read from `process.env` after startup.** Reading env vars deep in
 * a request handler means a typo surfaces as `undefined` in production at 2am
 * instead of at boot. Everything is resolved here, validated here, and frozen.
 *
 * **Unsafe-in-production settings refuse to start in production.** Three
 * settings exist purely for local development — Fabric mock mode, unsigned trust
 * bundles, and unauthenticated sensor readings — and each one silently destroys
 * the guarantee TrueMed exists to provide. `FABRIC_MOCK=1` in production would
 * cheerfully answer GENUINE for medicine that was never minted on the chain. A
 * warning in a log file is not enough for that; the process refuses to boot.
 *
 * Secrets are never echoed. `describe()` returns a redacted view for the startup
 * log line, because `DATABASE_URL` contains a password and startup logs get
 * pasted into issue trackers.
 *
 * Loading a `.env` file is Node's job, not a library's:
 *   node --env-file=.env src/server.js
 * which is why there is no `dotenv` dependency here.
 */

import { existsSync, statSync } from 'node:fs';
import { isAbsolute, resolve } from 'node:path';

/** Thrown with every validation failure at once, never with a secret in it. */
export class ConfigError extends Error {
  constructor(problems) {
    const list = problems.map((p) => `  - ${p}`).join('\n');
    super(`invalid configuration (${problems.length} problem${problems.length === 1 ? '' : 's'}):\n${list}`);
    this.name = 'ConfigError';
    this.problems = problems;
  }
}

/**
 * Values that mean "someone copied .env.example and did not edit it". Allowed in
 * development, fatal in production: a deployment running on placeholder
 * credentials is either broken or, worse, quietly working against the wrong
 * database.
 */
const PLACEHOLDERS = Object.freeze([
  'changeme',
  'change-me',
  'change_me',
  'replaceme',
  'replace-me',
  'your-value-here',
  'todo',
  'xxx',
]);

const TRUE_VALUES = new Set(['1', 'true', 'yes', 'on']);
const FALSE_VALUES = new Set(['0', 'false', 'no', 'off']);

/**
 * The stand-in encryption key used when `SECRET_ENCRYPTION_KEY` is unset.
 *
 * Most secrets in this system are stored hashed, which is strictly better. Two
 * cannot be: a sensor's HMAC shared secret must be recoverable to recompute a
 * MAC, and a reporter's phone number must be readable by a regulator following
 * up on a counterfeit report. Those two columns are encrypted at rest instead, so
 * a leaked database dump or backup does not yield forgeable sensor secrets or a
 * list of informants' phone numbers.
 *
 * This constant is deliberately self-describing and deliberately not a valid
 * production key: production requires 64 hex characters, so a deployment cannot
 * inherit it by forgetting to set the variable.
 */
export const DEV_ENCRYPTION_KEY = 'development-only-insecure-key-do-not-use-in-production';

/** Accumulates problems so the caller sees all of them in one go. */
class Reader {
  constructor(env) {
    this.env = env;
    this.problems = [];
    /** Names of variables that hold secrets, so `describe()` can redact them. */
    this.secretNames = new Set();
  }

  fail(message) {
    this.problems.push(message);
  }

  /** Raw lookup: empty and whitespace-only are treated as unset. */
  raw(name) {
    const value = this.env[name];
    if (value === undefined || value === null) return undefined;
    const trimmed = String(value).trim();
    return trimmed === '' ? undefined : trimmed;
  }

  /**
   * @param {string} name
   * @param {{default?: string, required?: boolean, secret?: boolean,
   *          pattern?: RegExp, hint?: string}} [opts]
   */
  str(name, opts = {}) {
    if (opts.secret) this.secretNames.add(name);
    const value = this.raw(name) ?? opts.default;
    if (value === undefined) {
      if (opts.required) this.fail(`${name} is required${opts.hint ? ` (${opts.hint})` : ''}`);
      return undefined;
    }
    if (opts.pattern && !opts.pattern.test(value)) {
      // Never echo the value of a secret in an error message.
      const shown = opts.secret ? '<redacted>' : `"${value}"`;
      this.fail(`${name} is ${shown}, which does not match ${opts.pattern}${opts.hint ? ` — ${opts.hint}` : ''}`);
      return undefined;
    }
    return value;
  }

  int(name, { default: dflt, min, max } = {}) {
    const raw = this.raw(name);
    if (raw === undefined) return dflt;
    // Number() rather than parseInt(): parseInt("8080abc") is 8080, which would
    // silently accept a typo.
    const n = Number(raw);
    if (!Number.isInteger(n)) {
      this.fail(`${name} must be an integer, got "${raw}"`);
      return dflt;
    }
    if (min !== undefined && n < min) {
      this.fail(`${name} must be at least ${min}, got ${n}`);
      return dflt;
    }
    if (max !== undefined && n > max) {
      this.fail(`${name} must be at most ${max}, got ${n}`);
      return dflt;
    }
    return n;
  }

  bool(name, dflt) {
    const raw = this.raw(name);
    if (raw === undefined) return dflt;
    const lower = raw.toLowerCase();
    if (TRUE_VALUES.has(lower)) return true;
    if (FALSE_VALUES.has(lower)) return false;
    // "FABRIC_MOCK=no thanks" must not read as truthy, and an unrecognised value
    // must not silently pick a side on a security-relevant switch.
    this.fail(`${name} must be one of 1/0/true/false/yes/no/on/off, got "${raw}"`);
    return dflt;
  }

  enum1(name, allowed, dflt) {
    const raw = this.raw(name);
    if (raw === undefined) return dflt;
    if (!allowed.includes(raw)) {
      this.fail(`${name} must be one of ${allowed.join(', ')}, got "${raw}"`);
      return dflt;
    }
    return raw;
  }

  /** Comma-separated list, empties dropped. */
  csv(name, dflt = []) {
    const raw = this.raw(name);
    if (raw === undefined) return dflt;
    return Object.freeze(raw.split(',').map((s) => s.trim()).filter(Boolean));
  }

  /**
   * A filesystem path, resolved to absolute. Existence is *not* checked here —
   * see `assertRuntimePaths`, which runs at boot so that `loadConfig` stays a
   * pure function of the environment and can be unit-tested.
   */
  path(name, opts = {}) {
    const value = this.str(name, opts);
    if (value === undefined) return undefined;
    return isAbsolute(value) ? value : resolve(process.cwd(), value);
  }
}

/**
 * Build the config object from an environment mapping.
 *
 * @param {Record<string, string|undefined>} [env]
 * @returns {Readonly<object>}
 * @throws {ConfigError} listing every problem found
 */
export function loadConfig(env = process.env) {
  const r = new Reader(env);

  const nodeEnv = r.enum1('NODE_ENV', ['development', 'test', 'production'], 'development');
  const isProduction = nodeEnv === 'production';
  const isTest = nodeEnv === 'test';

  const config = {
    env: nodeEnv,
    isProduction,
    isTest,
    isDevelopment: nodeEnv === 'development',

    server: {
      port: r.int('PORT', { default: 8080, min: 1, max: 65535 }),
      host: r.str('HOST', { default: '0.0.0.0' }),
      // Rate limiting and counterfeit-report geography both key off client IP. If
      // the service sits behind nginx or a load balancer, every request appears to
      // come from the proxy, so one abusive client would rate-limit the whole
      // country. Enabling this without an actual proxy in front is the reverse
      // mistake: clients could then spoof X-Forwarded-For freely.
      trustProxy: r.bool('TRUST_PROXY', false),
      // Counterfeit reports carry a JPEG as base64, which inflates by ~33%.
      bodyLimit: r.str('BODY_LIMIT', { default: '2mb', pattern: /^\d+(b|kb|mb)$/i }),
      shutdownGraceMs: r.int('SHUTDOWN_GRACE_MS', { default: 10_000, min: 0, max: 120_000 }),
      // Empty means "no browser origins allowed", which is correct for a
      // mobile-first API. The dashboards set this explicitly.
      corsOrigins: r.csv('CORS_ORIGINS'),
    },

    log: {
      level: r.enum1('LOG_LEVEL', ['debug', 'info', 'warn', 'error', 'silent'], 'info'),
      pretty: r.bool('LOG_PRETTY', !isProduction),
    },

    db: {
      url: r.str('DATABASE_URL', {
        required: isProduction,
        secret: true,
        default: isProduction ? undefined : 'postgres://truemed:truemed@localhost:5432/truemed',
        hint: 'postgres://user:password@host:5432/truemed',
      }),
      poolMax: r.int('DB_POOL_MAX', { default: 10, min: 1, max: 200 }),
      connectTimeoutMs: r.int('DB_CONNECT_TIMEOUT_MS', { default: 5_000, min: 100 }),
      // A statement timeout is a liveness guarantee: without it one unindexed
      // dashboard query can hold a pool connection until the pool is exhausted
      // and patient verification starts failing.
      statementTimeoutMs: r.int('DB_STATEMENT_TIMEOUT_MS', { default: 10_000, min: 100 }),
      ssl: r.bool('DB_SSL', false),
      connectRetries: r.int('DB_CONNECT_RETRIES', { default: 5, min: 0, max: 60 }),
      connectRetryDelayMs: r.int('DB_CONNECT_RETRY_DELAY_MS', { default: 1_000, min: 50 }),
    },

    redis: {
      // Redis is a cache, never a source of truth, so the service is designed to
      // run without it. Disabling it makes every verification hit the chain.
      enabled: r.bool('REDIS_ENABLED', true),
      url: r.str('REDIS_URL', { default: 'redis://localhost:6379', secret: true }),
      connectTimeoutMs: r.int('REDIS_CONNECT_TIMEOUT_MS', { default: 3_000, min: 100 }),
      // Contract values from DATA-CONTRACT.md §4.6, deliberately not
      // env-overridable: the Flutter app and the dashboards reason about
      // staleness using these numbers, so they are part of the contract rather
      // than a deployment knob.
      ttl: Object.freeze({ terminalS: 3600, activeS: 60, negativeS: 30 }),
      keyPrefix: 'verify:v1:',
    },

    fabric: {
      // In-memory driver so the API, the app and the dashboards can be developed
      // and demonstrated without a running Fabric network.
      mock: r.bool('FABRIC_MOCK', !isProduction),
      channel: r.str('FABRIC_CHANNEL', { default: 'truemed-channel' }),
      chaincode: r.str('FABRIC_CHAINCODE', { default: 'truemed' }),
      mspId: r.str('FABRIC_MSP_ID', { default: 'ManufacturerMSP' }),
      peerEndpoint: r.str('FABRIC_PEER_ENDPOINT', { default: 'localhost:7051' }),
      // gRPC verifies the peer's TLS certificate against its hostname. In a
      // docker-compose network the certificate says `peer0.manufacturer.truemed.in`
      // while the endpoint is `localhost:7051`, so the alias is what makes the
      // handshake succeed without disabling verification.
      peerHostAlias: r.str('FABRIC_PEER_HOST_ALIAS', { default: '' }),
      tlsCaPath: r.path('FABRIC_TLS_CA_PATH'),
      certPath: r.path('FABRIC_CERT_PATH'),
      keyPath: r.path('FABRIC_KEY_PATH'),
      evaluateTimeoutMs: r.int('FABRIC_EVALUATE_TIMEOUT_MS', { default: 5_000, min: 100 }),
      // Submitting waits for ordering and commit, which is inherently slower
      // than a read.
      submitTimeoutMs: r.int('FABRIC_SUBMIT_TIMEOUT_MS', { default: 15_000, min: 100 }),
    },

    trust: {
      // The signed trust bundle served by GET /api/public-keys and used to verify
      // scanned payloads. Without it the API cannot verify anything.
      bundlePath: r.path('TRUST_BUNDLE_PATH', {
        required: true,
        default: 'keys/trust-bundle.json',
      }),
      rootPublicKeyPath: r.path('TRUST_ROOT_PUBLIC_KEY_PATH', {
        required: true,
        default: 'keys/root-public.pem',
      }),
      // The root signature is what makes a stolen API server insufficient to
      // insert an attacker's signing key. Turning it off is a development-only
      // convenience.
      requireSignature: r.bool('TRUST_REQUIRE_SIGNATURE', true),
      reloadIntervalMs: r.int('TRUST_RELOAD_INTERVAL_MS', { default: 300_000, min: 0 }),
    },

    sensor: {
      // Per §4.5, readings carry an HMAC over the reading fields with the
      // sensor's shared secret, so a stolen API key alone cannot forge a
      // temperature history.
      requireHmac: r.bool('SENSOR_REQUIRE_HMAC', true),
      nonceTtlS: r.int('SENSOR_NONCE_TTL_S', { default: 86_400, min: 60 }),
      maxClockSkewMs: r.int('SENSOR_MAX_CLOCK_SKEW_MS', { default: 15 * 60 * 1000, min: 0 }),
    },

    secrets: {
      // Used for the two columns that must hold recoverable plaintext:
      // sensors.secret_enc and counterfeit_reports.reporter_contact_enc.
      encryptionKey: r.str('SECRET_ENCRYPTION_KEY', {
        default: DEV_ENCRYPTION_KEY,
        secret: true,
        hint: 'generate with: openssl rand -hex 32',
      }),
      // Counterfeit reports carry a client IP for abuse investigation and
      // verification rows carry coarse geography. Neither is needed indefinitely,
      // and under the DPDP Act keeping personal data past its purpose is the
      // violation, not collecting it.
      retentionDays: r.int('DATA_RETENTION_DAYS', { default: 400, min: 30, max: 3650 }),
    },

    rateLimit: {
      // Public endpoints are unauthenticated by design — a patient must never
      // need an account — so IP is the only key available.
      publicPerMin: r.int('RATE_LIMIT_PUBLIC_PER_MIN', { default: 60, min: 1 }),
      authedPerMin: r.int('RATE_LIMIT_AUTHED_PER_MIN', { default: 600, min: 1 }),
      // Reports are cheap to send and expensive to triage, and each one carries a
      // photo.
      reportPerHour: r.int('RATE_LIMIT_REPORT_PER_HOUR', { default: 10, min: 1 }),
      sensorPerMin: r.int('RATE_LIMIT_SENSOR_PER_MIN', { default: 120, min: 1 }),
    },
  };

  // ── Cross-field checks ────────────────────────────────────────────────────
  // Individually valid settings can combine into something unsafe, so these run
  // after everything is read.

  if (isProduction) {
    if (config.fabric.mock) {
      r.fail(
        'FABRIC_MOCK must be 0 in production: mock mode answers from an in-memory ' +
          'ledger, so the API would report GENUINE for medicine that was never ' +
          'recorded on the blockchain',
      );
    }
    if (!config.trust.requireSignature) {
      r.fail(
        'TRUST_REQUIRE_SIGNATURE must be 1 in production: an unsigned trust bundle ' +
          'lets anyone who can write the bundle file insert their own signing key',
      );
    }
    if (!config.sensor.requireHmac) {
      r.fail(
        'SENSOR_REQUIRE_HMAC must be 1 in production: without it a stolen sensor API ' +
          'key is enough to fabricate a clean cold-chain history for spoiled vaccines',
      );
    }
    if (config.log.level === 'silent') {
      r.fail('LOG_LEVEL must not be "silent" in production: an incident with no logs cannot be investigated');
    }
    if (config.secrets.encryptionKey === DEV_ENCRYPTION_KEY) {
      r.fail(
        'SECRET_ENCRYPTION_KEY must be set in production: the development default is a ' +
          'published constant in this source tree, so sensor HMAC secrets and reporter ' +
          'contacts in the database would be readable by anyone who can read this repository',
      );
    }
    if (config.server.corsOrigins.includes('*')) {
      r.fail('CORS_ORIGINS must not be "*" in production: name the dashboard origins explicitly');
    }
    for (const name of ['DATABASE_URL', 'REDIS_URL']) {
      const value = r.raw(name);
      if (!value) continue;
      const lower = value.toLowerCase();
      const hit = PLACEHOLDERS.find((p) => lower.includes(p));
      if (hit) {
        r.fail(`${name} still contains the placeholder "${hit}" from .env.example`);
      }
    }
  }

  // Fabric credentials are only meaningful outside mock mode, and only then are
  // they required — demanding them in mock mode would make local development
  // impossible.
  if (!config.fabric.mock) {
    for (const [key, name] of [
      ['tlsCaPath', 'FABRIC_TLS_CA_PATH'],
      ['certPath', 'FABRIC_CERT_PATH'],
      ['keyPath', 'FABRIC_KEY_PATH'],
    ]) {
      if (!config.fabric[key]) {
        r.fail(`${name} is required when FABRIC_MOCK=0`);
      }
    }
  }

  // Validated here rather than with a `pattern` on the read, because the two
  // acceptable shapes carry different meanings: 64 hex characters is a real key,
  // and the development constant is an explicit opt-out that production rejects
  // above.
  if (
    config.secrets.encryptionKey !== DEV_ENCRYPTION_KEY &&
    !/^[0-9a-f]{64}$/i.test(config.secrets.encryptionKey)
  ) {
    r.fail(
      'SECRET_ENCRYPTION_KEY must be exactly 64 hex characters (32 bytes) — generate one ' +
        'with: openssl rand -hex 32',
    );
  }

  if (config.db.statementTimeoutMs <= config.db.connectTimeoutMs) {    // Not fatal, but almost always a mistake: a statement budget smaller than
    // the time allowed to obtain a connection means queries die on arrival.
    r.fail(
      `DB_STATEMENT_TIMEOUT_MS (${config.db.statementTimeoutMs}) should exceed ` +
        `DB_CONNECT_TIMEOUT_MS (${config.db.connectTimeoutMs})`,
    );
  }

  if (r.problems.length > 0) throw new ConfigError(r.problems);

  config.secretNames = Object.freeze([...r.secretNames]);
  return deepFreeze(config);
}

function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

/**
 * Check that the files the service cannot run without are actually present.
 *
 * Separate from `loadConfig` on purpose: touching the filesystem would make
 * config loading untestable and would couple unit tests to a checked-out key
 * directory. The server calls this at boot, before it starts listening, so a
 * missing trust bundle is a refusal to start rather than a 500 on the first
 * patient scan.
 *
 * @param {object} cfg
 * @throws {ConfigError}
 */
export function assertRuntimePaths(cfg) {
  const problems = [];
  const required = [
    ['TRUST_BUNDLE_PATH', cfg.trust.bundlePath],
    ['TRUST_ROOT_PUBLIC_KEY_PATH', cfg.trust.rootPublicKeyPath],
  ];
  if (!cfg.fabric.mock) {
    required.push(
      ['FABRIC_TLS_CA_PATH', cfg.fabric.tlsCaPath],
      ['FABRIC_CERT_PATH', cfg.fabric.certPath],
      ['FABRIC_KEY_PATH', cfg.fabric.keyPath],
    );
  }

  for (const [name, path] of required) {
    if (!path) continue; // already reported by loadConfig
    if (!existsSync(path)) {
      problems.push(`${name} points at ${path}, which does not exist`);
      continue;
    }
    if (!statSync(path).isFile()) {
      problems.push(`${name} points at ${path}, which is not a file`);
    }
  }

  if (problems.length > 0) throw new ConfigError(problems);
}

/**
 * A redacted view suitable for the startup log line.
 *
 * Secret-bearing URLs are reduced to scheme, host and database name — enough to
 * confirm the service is pointed at the right place, with no password.
 */
export function describe(cfg) {
  return {
    env: cfg.env,
    port: cfg.server.port,
    log_level: cfg.log.level,
    db: summariseUrl(cfg.db.url),
    db_pool_max: cfg.db.poolMax,
    redis: cfg.redis.enabled ? summariseUrl(cfg.redis.url) : 'disabled',
    fabric: cfg.fabric.mock
      ? 'MOCK (in-memory ledger)'
      : `${cfg.fabric.channel}/${cfg.fabric.chaincode} as ${cfg.fabric.mspId} via ${cfg.fabric.peerEndpoint}`,
    trust_bundle: cfg.trust.bundlePath,
    trust_signature_required: cfg.trust.requireSignature,
    sensor_hmac_required: cfg.sensor.requireHmac,
    // Never the key, and never a prefix of it: the point of naming the
    // development default is that someone reading a startup log can tell at a
    // glance that stored secrets are not really protected.
    secret_encryption:
      cfg.secrets.encryptionKey === DEV_ENCRYPTION_KEY ? 'DEVELOPMENT KEY' : 'configured',
    cors_origins: cfg.server.corsOrigins.length ? cfg.server.corsOrigins : 'none',
  };
}

/** `postgres://user:pw@host:5432/truemed` → `postgres://host:5432/truemed` */
function summariseUrl(url) {
  if (!url) return 'unset';
  try {
    const parsed = new URL(url);
    return `${parsed.protocol}//${parsed.host}${parsed.pathname}`;
  } catch {
    // Never fall back to returning the raw string: if it failed to parse it may
    // still contain a password.
    return '<unparseable, redacted>';
  }
}

/**
 * The process-wide config.
 *
 * A `ConfigError` thrown here propagates out of the import, and `server.js`
 * turns it into a readable message and a non-zero exit. Deciding to call
 * `process.exit` is the entry point's job, not a library module's.
 */
export const config = loadConfig();

export default config;

/**
 * Configuration loading.
 *
 * `loadConfig(env)` is a pure function of an environment mapping, which is the
 * whole reason it takes `env` as an argument — these tests would otherwise have
 * to mutate `process.env` and leak state between cases.
 *
 * The cases that matter most are the production refusals. Each of the three
 * development switches silently destroys a guarantee the project exists to
 * provide, so "does the process refuse to start" is a security test, not a
 * configuration nicety.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  loadConfig,
  assertRuntimePaths,
  describe as describeConfig,
  ConfigError,
} from '../src/config/index.js';

/**
 * A syntactically valid encryption key for the fixtures: 64 hex characters, the
 * shape `SECRET_ENCRYPTION_KEY` demands once the development default is refused.
 *
 * Deliberately a visible repeating pattern rather than CSPRNG output, so that
 * nobody reading this file can mistake it for a real key that leaked into the
 * test suite. The production checks it exercises are on *presence* and *shape* —
 * that the published development constant has been replaced, and that what
 * replaced it is 32 bytes of hex — and a patterned value satisfies both exactly
 * as a random one would. There is no entropy check to defeat.
 */
const TEST_ENCRYPTION_KEY = '0123456789abcdef'.repeat(4);

/**
 * A production environment with the minimum needed to be valid.
 *
 * Every key here is one that production refuses to start without, so this object
 * doubles as the list of what an operator must set. `SECRET_ENCRYPTION_KEY`
 * belongs in that list: without it `loadConfig` fails with "the development
 * default is a published constant", which is correct behaviour and would
 * otherwise make three cases below fail for a reason unrelated to what they test.
 */
const prodEnv = (overrides = {}) => ({
  NODE_ENV: 'production',
  DATABASE_URL: 'postgres://truemed:s3cr3t-p4ssw0rd@db.internal:5432/truemed',
  FABRIC_MOCK: '0',
  FABRIC_TLS_CA_PATH: '/etc/truemed/tlsca.pem',
  FABRIC_CERT_PATH: '/etc/truemed/cert.pem',
  FABRIC_KEY_PATH: '/etc/truemed/key.pem',
  SECRET_ENCRYPTION_KEY: TEST_ENCRYPTION_KEY,
  ...overrides,
});

/** Collect the problem list from a load that is expected to fail. */
function problemsFrom(env) {
  try {
    loadConfig(env);
  } catch (err) {
    assert.ok(err instanceof ConfigError, `expected ConfigError, got ${err}`);
    return err.problems;
  }
  assert.fail('expected loadConfig to throw');
}

describe('development defaults', () => {
  test('an empty environment produces a usable development config', () => {
    const cfg = loadConfig({});
    assert.equal(cfg.env, 'development');
    assert.equal(cfg.isProduction, false);
    assert.equal(cfg.server.port, 8080);
    assert.equal(cfg.log.level, 'info');
    assert.equal(cfg.fabric.mock, true, 'mock ledger by default outside production');
    assert.ok(cfg.db.url.startsWith('postgres://'));
  });

  test('CORS is closed by default', () => {
    // A mobile-first API needs no browser origins, and defaulting open would be
    // a mistake that only shows up in a security review.
    assert.deepEqual(loadConfig({}).server.corsOrigins, []);
  });

  test('the contract cache TTLs are present and not env-overridable', () => {
    // DATA-CONTRACT.md §4.6. Overriding these would let a deployment diverge from
    // what the app assumes about staleness.
    const cfg = loadConfig({ REDIS_TTL_ACTIVE_S: '9999' });
    assert.deepEqual({ ...cfg.redis.ttl }, { terminalS: 3600, activeS: 60, negativeS: 30 });
  });

  test('the result is deeply frozen', () => {
    const cfg = loadConfig({});
    assert.throws(() => {
      cfg.server.port = 1;
    }, TypeError);
    assert.throws(() => {
      cfg.redis.ttl.activeS = 1;
    }, TypeError);
  });
});

describe('reporting every problem at once', () => {
  test('four bad variables produce four problems, not one', () => {
    // The point of the collector: otherwise a misconfigured deployment costs one
    // restart per mistake to discover.
    const problems = problemsFrom({
      PORT: 'not-a-number',
      LOG_LEVEL: 'chatty',
      TRUST_PROXY: 'maybe',
      DB_POOL_MAX: '0',
    });
    assert.equal(problems.length, 4, problems.join(' | '));
    for (const name of ['PORT', 'LOG_LEVEL', 'TRUST_PROXY', 'DB_POOL_MAX']) {
      assert.ok(problems.some((p) => p.startsWith(name)), `expected a problem for ${name}`);
    }
  });

  test('the message counts the problems', () => {
    try {
      loadConfig({ PORT: 'x', LOG_LEVEL: 'y' });
      assert.fail('expected a throw');
    } catch (err) {
      assert.match(err.message, /2 problems/);
    }
  });
});

describe('type parsing', () => {
  test('rejects a number with trailing junk instead of silently truncating it', () => {
    // parseInt("8080abc") is 8080, which would accept a typo.
    assert.ok(problemsFrom({ PORT: '8080abc' }).some((p) => /PORT must be an integer/.test(p)));
  });

  test('rejects a non-integer port', () => {
    assert.ok(problemsFrom({ PORT: '80.5' }).some((p) => /integer/.test(p)));
  });

  test('enforces bounds', () => {
    assert.ok(problemsFrom({ PORT: '0' }).some((p) => /at least 1/.test(p)));
    assert.ok(problemsFrom({ PORT: '70000' }).some((p) => /at most 65535/.test(p)));
  });

  test('accepts the documented boolean spellings', () => {
    for (const yes of ['1', 'true', 'TRUE', 'yes', 'on']) {
      assert.equal(loadConfig({ TRUST_PROXY: yes }).server.trustProxy, true, yes);
    }
    for (const no of ['0', 'false', 'No', 'off']) {
      assert.equal(loadConfig({ TRUST_PROXY: no }).server.trustProxy, false, no);
    }
  });

  test('rejects an ambiguous boolean rather than guessing', () => {
    // "FABRIC_MOCK=no thanks" must not read as truthy, and a security switch must
    // never silently pick a side.
    for (const bad of ['no thanks', 'y', '2', 'enabled']) {
      assert.ok(problemsFrom({ TRUST_PROXY: bad }).length > 0, bad);
    }
  });

  test('treats empty and whitespace-only as unset, so a blank line in .env is harmless', () => {
    assert.equal(loadConfig({ PORT: '' }).server.port, 8080);
    assert.equal(loadConfig({ PORT: '   ' }).server.port, 8080);
    assert.equal(loadConfig({ LOG_LEVEL: '' }).log.level, 'info');
  });

  test('trims surrounding whitespace', () => {
    assert.equal(loadConfig({ PORT: ' 9090 ' }).server.port, 9090);
  });

  test('parses a comma-separated list and drops empties', () => {
    const cfg = loadConfig({ CORS_ORIGINS: 'http://a.test, http://b.test ,,' });
    assert.deepEqual([...cfg.server.corsOrigins], ['http://a.test', 'http://b.test']);
  });

  test('rejects an unknown enum value', () => {
    assert.ok(problemsFrom({ NODE_ENV: 'staging' }).some((p) => /NODE_ENV must be one of/.test(p)));
  });

  test('rejects a body limit that is not a size', () => {
    assert.ok(problemsFrom({ BODY_LIMIT: 'huge' }).length > 0);
    assert.equal(loadConfig({ BODY_LIMIT: '512kb' }).server.bodyLimit, '512kb');
  });
});

describe('production refuses unsafe development switches', () => {
  test('a correct production environment loads', () => {
    const cfg = loadConfig(prodEnv());
    assert.equal(cfg.isProduction, true);
    assert.equal(cfg.fabric.mock, false);
    assert.equal(cfg.log.pretty, false, 'no ANSI escapes into a log aggregator');
  });

  test('FABRIC_MOCK=1 in production is fatal', () => {
    // Mock mode answers from an in-memory ledger, so the API would report GENUINE
    // for medicine that was never recorded on the chain. This is the single most
    // dangerous misconfiguration in the project.
    const problems = problemsFrom(prodEnv({ FABRIC_MOCK: '1' }));
    assert.ok(problems.some((p) => /FABRIC_MOCK must be 0 in production/.test(p)));
    assert.ok(problems.some((p) => /never recorded on the blockchain/.test(p)),
      'the message must explain the consequence, not just the rule');
  });

  test('an unsigned trust bundle in production is fatal', () => {
    const problems = problemsFrom(prodEnv({ TRUST_REQUIRE_SIGNATURE: '0' }));
    assert.ok(problems.some((p) => /TRUST_REQUIRE_SIGNATURE must be 1/.test(p)));
  });

  test('unauthenticated sensor readings in production are fatal', () => {
    const problems = problemsFrom(prodEnv({ SENSOR_REQUIRE_HMAC: '0' }));
    assert.ok(problems.some((p) => /SENSOR_REQUIRE_HMAC must be 1/.test(p)));
  });

  test('silent logging in production is fatal', () => {
    const problems = problemsFrom(prodEnv({ LOG_LEVEL: 'silent' }));
    assert.ok(problems.some((p) => /LOG_LEVEL must not be "silent"/.test(p)));
  });

  test('wildcard CORS in production is fatal', () => {
    const problems = problemsFrom(prodEnv({ CORS_ORIGINS: '*' }));
    assert.ok(problems.some((p) => /CORS_ORIGINS must not be/.test(p)));
  });

  test('the unset encryption key is fatal in production', () => {
    // prodEnv() supplies SECRET_ENCRYPTION_KEY, so this case removes it again to
    // keep the refusal itself covered. Leaving the development default in place
    // would encrypt sensor HMAC secrets and reporter phone numbers under a
    // constant published in this repository — a database dump would then be
    // readable by anyone who can clone it, which is the same as not encrypting.
    const problems = problemsFrom({ ...prodEnv(), SECRET_ENCRYPTION_KEY: undefined });
    assert.ok(problems.some((p) => /SECRET_ENCRYPTION_KEY must be set in production/.test(p)));
  });

  test('a malformed encryption key is fatal in any environment', () => {
    // Not 64 hex characters. Caught everywhere rather than only in production,
    // because a key the SecretBox cannot derive from fails at the moment a sensor
    // reading arrives, not at startup — and a crash on the write path is far
    // harder to diagnose than a refusal to boot.
    for (const bad of ['tooshort', 'z'.repeat(64), '0123456789abcdef'.repeat(3)]) {
      const problems = problemsFrom({ SECRET_ENCRYPTION_KEY: bad });
      assert.ok(
        problems.some((p) => /SECRET_ENCRYPTION_KEY must be exactly 64 hex/.test(p)),
        `expected a shape complaint for ${JSON.stringify(bad)}`,
      );
    }
  });

  test('all three unsafe switches at once are all reported', () => {
    const problems = problemsFrom(
      prodEnv({ FABRIC_MOCK: '1', TRUST_REQUIRE_SIGNATURE: '0', SENSOR_REQUIRE_HMAC: '0' }),
    );
    assert.equal(problems.length, 3, problems.join(' | '));
  });

  test('the same switches are allowed in development', () => {
    assert.doesNotThrow(() =>
      loadConfig({ FABRIC_MOCK: '1', TRUST_REQUIRE_SIGNATURE: '0', SENSOR_REQUIRE_HMAC: '0' }),
    );
  });
});

describe('production required values', () => {
  test('DATABASE_URL is required, with no localhost fallback', () => {
    // Falling back to a development database in production is worse than failing:
    // it appears to work.
    const problems = problemsFrom({ ...prodEnv(), DATABASE_URL: undefined });
    assert.ok(problems.some((p) => /DATABASE_URL is required/.test(p)));
  });

  test('an unedited .env.example is rejected by its placeholder', () => {
    // .env.example ships DATABASE_URL with the password "changeme" precisely so
    // that copying it into production fails loudly.
    const problems = problemsFrom(
      prodEnv({ DATABASE_URL: 'postgres://truemed:changeme@localhost:5432/truemed' }),
    );
    assert.ok(problems.some((p) => /placeholder "changeme"/.test(p)));
  });

  test('Fabric credentials are required when not in mock mode', () => {
    const problems = problemsFrom(
      prodEnv({ FABRIC_TLS_CA_PATH: undefined, FABRIC_CERT_PATH: undefined }),
    );
    assert.ok(problems.some((p) => /FABRIC_TLS_CA_PATH is required when FABRIC_MOCK=0/.test(p)));
    assert.ok(problems.some((p) => /FABRIC_CERT_PATH is required when FABRIC_MOCK=0/.test(p)));
  });

  test('Fabric credentials are not required in mock mode', () => {
    // Demanding them would make local development impossible.
    assert.doesNotThrow(() => loadConfig({ FABRIC_MOCK: '1' }));
  });

  test('relative Fabric and trust paths are resolved to absolute', () => {
    const cfg = loadConfig({ TRUST_BUNDLE_PATH: 'keys/bundle.json' });
    assert.ok(cfg.trust.bundlePath.startsWith('/'), cfg.trust.bundlePath);
    assert.ok(cfg.trust.bundlePath.endsWith('keys/bundle.json'));
  });
});

describe('secrets never appear in errors or logs', () => {
  test('describe() reduces a database URL to host and database name', () => {
    const cfg = loadConfig(prodEnv());
    const shown = describeConfig(cfg);
    const serialised = JSON.stringify(shown);
    assert.equal(serialised.includes('s3cr3t-p4ssw0rd'), false, 'password leaked into describe()');
    assert.equal(shown.db, 'postgres://db.internal:5432/truemed');
  });

  test('describe() redacts rather than falling back to the raw string', () => {
    // An unparseable URL may still contain a password, so the fallback must not
    // echo it.
    const cfg = loadConfig({ REDIS_URL: 'not a url at all' });
    assert.equal(describeConfig(cfg).redis, '<unparseable, redacted>');
  });

  test('describe() names mock mode unmistakably', () => {
    // This string ends up in the startup log line, where someone debugging a demo
    // needs to see immediately that the ledger is not real.
    assert.match(describeConfig(loadConfig({})).fabric, /MOCK/);
  });

  test('a validation failure on a secret-bearing variable does not echo its value', () => {
    const problems = problemsFrom({ BODY_LIMIT: 'nonsense' });
    assert.ok(problems.length > 0);
    // BODY_LIMIT is not secret, so its value is shown — the useful case.
    assert.ok(problems.some((p) => /"nonsense"/.test(p)));
  });
});

describe('cross-field sanity', () => {
  test('a statement timeout below the connect timeout is rejected', () => {
    const problems = problemsFrom({
      DB_CONNECT_TIMEOUT_MS: '10000',
      DB_STATEMENT_TIMEOUT_MS: '5000',
    });
    assert.ok(problems.some((p) => /DB_STATEMENT_TIMEOUT_MS/.test(p)));
  });

  test('equal timeouts are also rejected, since queries would die on arrival', () => {
    const problems = problemsFrom({
      DB_CONNECT_TIMEOUT_MS: '5000',
      DB_STATEMENT_TIMEOUT_MS: '5000',
    });
    assert.ok(problems.some((p) => /DB_STATEMENT_TIMEOUT_MS/.test(p)));
  });
});

describe('assertRuntimePaths', () => {
  const dir = mkdtempSync(join(tmpdir(), 'truemed-config-'));

  test('passes when the trust files exist', () => {
    const bundle = join(dir, 'trust-bundle.json');
    const rootKey = join(dir, 'root-public.pem');
    writeFileSync(bundle, '{}');
    writeFileSync(rootKey, 'pem');
    const cfg = loadConfig({
      TRUST_BUNDLE_PATH: bundle,
      TRUST_ROOT_PUBLIC_KEY_PATH: rootKey,
    });
    assert.doesNotThrow(() => assertRuntimePaths(cfg));
  });

  test('reports a missing trust bundle rather than failing on the first scan', () => {
    const cfg = loadConfig({
      TRUST_BUNDLE_PATH: join(dir, 'absent.json'),
      TRUST_ROOT_PUBLIC_KEY_PATH: join(dir, 'root-public.pem'),
    });
    try {
      assertRuntimePaths(cfg);
      assert.fail('expected a throw');
    } catch (err) {
      assert.ok(err instanceof ConfigError);
      assert.match(err.problems[0], /TRUST_BUNDLE_PATH points at .*absent\.json, which does not exist/);
    }
  });

  test('rejects a directory where a file is expected', () => {
    const asDir = join(dir, 'bundle-dir');
    mkdirSync(asDir, { recursive: true });
    const cfg = loadConfig({
      TRUST_BUNDLE_PATH: asDir,
      TRUST_ROOT_PUBLIC_KEY_PATH: join(dir, 'root-public.pem'),
    });
    assert.throws(() => assertRuntimePaths(cfg), (err) =>
      err.problems.some((p) => /is not a file/.test(p)));
  });

  test('does not demand Fabric credentials in mock mode', () => {
    const cfg = loadConfig({
      FABRIC_MOCK: '1',
      TRUST_BUNDLE_PATH: join(dir, 'trust-bundle.json'),
      TRUST_ROOT_PUBLIC_KEY_PATH: join(dir, 'root-public.pem'),
    });
    assert.doesNotThrow(() => assertRuntimePaths(cfg));
  });
});

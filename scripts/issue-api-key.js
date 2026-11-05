/**
 * Issue an API key, and provision a cold-chain sensor.
 *
 *     npm run issue-key -- --role manufacturer --label "Sanjeevani Pune plant"
 *     npm run issue-key -- --role pharma --scope MH/25D/2019/187
 *     npm run issue-key -- --role sensor --sensor TM-SENSOR-PUN01
 *     npm run issue-key -- --revoke 9f2c...   (the key_hash, not the key)
 *     npm run issue-key -- --list-roles
 *
 * ## Why the plaintext key appears exactly once
 *
 * The store holds only `sha256(key)` (§4.2), and authentication is a hash lookup:
 * `middleware/auth.js` hashes whatever arrives in `X-API-Key` and looks the row up
 * by that hash. Nothing anywhere can turn a stored row back into a usable
 * credential, which is the point — a leaked `api_keys` table yields no keys. The
 * consequence is that this script is the only moment the plaintext exists, so it is
 * printed once and then genuinely gone. Losing it means issuing a new key and
 * revoking the old one, which is the correct trade.
 *
 * `sha256hex` is imported from the authenticator rather than reimplemented here.
 * Two lines of `createHash('sha256')` are trivially easy to write and just as easy
 * to write *differently* — base64 instead of hex, a trailing newline, a different
 * encoding argument — and the failure mode is a key that is accepted by this script
 * and rejected by every request. Sharing the function makes that class of drift
 * impossible.
 *
 * ## No secret ever reaches `argv`
 *
 * There is deliberately no flag to supply a key, a password or a sensor secret.
 * Anything in `argv` is readable by every local user through `ps`, and it lands in
 * shell history and in CI logs. So keys and sensor secrets are generated here from
 * the CSPRNG and never accepted from outside. The two values this script *does*
 * take — a licence number and a human label — are not secrets.
 *
 * That is also why revocation takes a **key hash** rather than a key. The hash is a
 * safe handle: it is what the table is indexed by, and knowing it does not let
 * anyone authenticate, because the middleware hashes the presented key and no one
 * can produce a preimage. The hash is printed at issue time for exactly this use.
 *
 * ## Why it refuses to run against the in-memory store
 *
 * `createStore` returns the in-memory twin whenever `FABRIC_MOCK=1`, which is the
 * default outside production. A key issued into that store would live in this
 * process's heap and vanish on exit, so the script would print a perfectly
 * well-formed credential that no request could ever use — the most confusing
 * possible outcome. It refuses instead, and names the one thing that does work:
 * seeding the mock stack from inside the server process (`SEED_DEMO=1 npm start`).
 */

import { randomBytes } from 'node:crypto';

import { sha256hex } from '../src/middleware/auth.js';
import {
  API_KEY_RE,
  LIMITS,
  ROLE,
  ROLES,
  ROLE_PURPOSE,
  validateSensorID,
  validateText,
} from '../src/core/rules.js';
import { SecretBox, generateSensorSecret, sensorContext } from '../src/utils/secret-box.js';

/**
 * Bytes of randomness behind a key. 16 bytes is 32 hex characters, which is what
 * `API_KEY_RE` fixes (§4.2) — the width is part of the contract, not a tunable.
 * 128 bits is far beyond guessable for a credential that is never enumerable.
 */
const KEY_BYTES = 16;

/**
 * A label is operator prose, not a contract field, so `LIMITS` has no entry for it.
 * Bounded anyway: it is stored, echoed to dashboards' error messages and written to
 * logs, and an unbounded string that reaches all three is a nuisance in each.
 */
const LABEL_MAX = 120;

/** Roles and what each one is for, in issue order. */
export function roleTable() {
  return ROLES.map((role) => ({ role, purpose: ROLE_PURPOSE[role] }));
}

/**
 * A fresh `tm_<role>_<32 hex>` key.
 *
 * The regex check is not ceremony. `API_KEY_RE` is what `roleOfApiKey` and every
 * client-side sanity check match against, so a role name that did not fit the
 * pattern would produce a key this script called valid and the rest of the system
 * called malformed. Failing here, loudly, at the only moment the plaintext exists,
 * is the cheapest possible place to catch that.
 */
export function generateApiKey(role) {
  const key = `tm_${role}_${randomBytes(KEY_BYTES).toString('hex')}`;
  if (!API_KEY_RE.test(key)) {
    throw new Error(
      `generated key for role "${role}" does not match the §4.2 key format ` +
        `${API_KEY_RE}; the role list and the regex have diverged`,
    );
  }
  return key;
}

/**
 * Validate a role and its scope together.
 *
 * §4.4a makes `scope` load-bearing for exactly one role: a `pharma` key's scope is
 * the manufacturer licence its dashboard is confined to, and the dashboard service
 * refuses a blank one rather than showing an empty board. Requiring it here is what
 * stops that refusal being discovered by a manufacturer staring at a dashboard that
 * says they have no stock.
 *
 * A scope on any other role is refused rather than ignored. Nothing reads it, so
 * accepting it would hand an operator a key they believe is confined to one licence
 * and is not — a silently over-privileged credential, which is worse than an error
 * message.
 */
export function validateRoleAndScope(role, scope) {
  if (typeof role !== 'string' || !ROLES.includes(role)) {
    const known = roleTable().map((r) => `  ${r.role.padEnd(13)}${r.purpose}`).join('\n');
    throw new Error(
      `unknown role ${JSON.stringify(role ?? null)}. The roles are:\n${known}`,
    );
  }

  const given = typeof scope === 'string' ? scope.trim() : '';

  if (role === ROLE.PHARMA) {
    if (given === '') {
      throw new Error(
        'a pharma key needs --scope <mfg_licence_no>: it is a read-only analytics ' +
          "key over ONE manufacturer's batches, and the scope is the only thing " +
          'confining it (§4.4a). Without one the dashboard refuses the key.',
      );
    }
    return validateText('scope', given, LIMITS.mfg_licence_no);
  }

  if (given !== '') {
    throw new Error(
      `--scope is only meaningful for the ${ROLE.PHARMA} role; nothing reads the ` +
        `scope of a ${role} key, so setting it here would suggest a confinement ` +
        'that does not exist. Did you mean --label?',
    );
  }
  return '';
}

/**
 * Mint a key and store its hash.
 *
 * Deliberately never logs and never prints: the plaintext is returned to the caller
 * and it is the caller's decision where a credential goes. A convenience log line
 * inside here would put a live key into whatever log sink the process happens to
 * have — the classic way a credential ends up in a log aggregator forever.
 *
 * @param {{store: {insertApiKey: Function}, role: string, scope?: string,
 *          label?: string}} args
 * @returns {Promise<{key: string, keyHash: string, row: object}>}
 */
export async function issueApiKey({ store, role, scope = '', label = '' }) {
  const checkedScope = validateRoleAndScope(role, scope);
  const checkedLabel = label === '' || label == null ? '' : validateText('label', label, LABEL_MAX);

  const key = generateApiKey(role);
  const keyHash = sha256hex(key);
  const row = await store.insertApiKey({
    role,
    keyHash,
    label: checkedLabel,
    scope: checkedScope,
  });

  return { key, keyHash, row };
}

/**
 * Provision a cold-box sensor: generate its HMAC secret, seal it, store it.
 *
 * A `sensor` API key on its own cannot submit a reading. §4.7 requires a per-device
 * MAC, and `supply-chain.js` answers 404 for an unprovisioned device precisely so
 * that an installer is sent here rather than to their API key. The two credentials
 * answer different questions — the key says which *system* is talking, the secret
 * says which *device* produced this reading — so both are issued together.
 *
 * The secret is sealed with the sensor id as AEAD context, so a row copied from one
 * device's record to another fails to open instead of authenticating as the other
 * device.
 *
 * Re-provisioning an existing sensor is refused unless `rotate` is set. Rotation
 * invalidates the secret burned into the device in the field: every reading it
 * sends is rejected as a bad MAC until someone drives out and reflashes it, and a
 * silent overwrite would make a typo in a sensor id look like a hardware fault.
 *
 * @param {{store: object, secrets: SecretBox, sensorId: string, label?: string,
 *          rotate?: boolean}} args
 * @returns {Promise<{sensorId: string, secret: string, rotated: boolean, row: object}>}
 */
export async function provisionSensor({ store, secrets, sensorId, label = '', rotate = false }) {
  const id = validateSensorID(sensorId);
  const checkedLabel = label === '' || label == null ? '' : validateText('label', label, LABEL_MAX);

  const existing = await store.getSensor(id);
  if (existing && !rotate) {
    throw new Error(
      `sensor ${id} is already provisioned. Issuing a new secret would break the ` +
        'device in the field until it is reflashed, so pass --rotate-sensor to ' +
        'replace it deliberately.',
    );
  }

  const secret = generateSensorSecret();
  const secretEnc = secrets.seal(secret, sensorContext(id));
  const row = await store.insertSensor({ sensorId: id, secretEnc, label: checkedLabel });

  return { sensorId: id, secret, rotated: Boolean(existing), row };
}

/**
 * Revoke a key by its SHA-256 hash.
 *
 * @returns {Promise<boolean>} false when the hash is unknown or already revoked
 */
export async function revokeByHash({ store, keyHash }) {
  if (typeof keyHash !== 'string' || !/^[0-9a-f]{64}$/i.test(keyHash)) {
    throw new Error(
      'a key hash is 64 hexadecimal characters — the `key_hash` printed when the ' +
        'key was issued. Revoking takes the hash rather than the key so that no ' +
        'credential is ever passed on the command line, where `ps` and shell ' +
        'history can see it.',
    );
  }
  return store.revokeApiKey(keyHash.toLowerCase());
}

// ── Command line ──────────────────────────────────────────────────────────────

const USAGE = `Issue a TrueMed API key, or provision a cold-chain sensor.

  npm run issue-key -- --role <role> [options]
  npm run issue-key -- --revoke <key_hash>
  npm run issue-key -- --list-roles

Options
  --role <role>        one of: ${ROLES.join(', ')}
  --scope <licence>    required for "pharma", refused for every other role:
                       the mfg_licence_no its dashboard is confined to (§4.4a)
  --label <text>       a note stored with the key, so an operator can tell
                       later what it was for
  --sensor <id>        also provision this cold-box sensor and print its HMAC
                       secret (TM-SENSOR-XXXX). Only with --role sensor.
  --rotate-sensor      replace the secret of an already-provisioned sensor.
                       The device stops being able to submit readings until it
                       is reflashed.
  --revoke <key_hash>  revoke by hash, never by key
  --list-roles         print the roles and what each one is for
  --json               emit one JSON object on stdout instead of a table
  --help               this text

The key is printed once and cannot be recovered afterwards: the store holds only
its SHA-256 hash. Keep the printed key_hash — it is how you revoke the key.`;

/**
 * A tiny argument parser, because the dependency list is five packages long and
 * this is one function.
 *
 * Unknown flags are an error rather than being ignored. A silently swallowed
 * `--scoped MH/25D/2019/187` would issue an unconfined key while the operator
 * believed otherwise, and a typo is much more likely than a novel flag.
 */
export function parseArgs(argv) {
  const out = {
    help: false,
    listRoles: false,
    json: false,
    rotate: false,
    role: null,
    scope: '',
    label: '',
    sensor: null,
    revoke: null,
  };

  const takesValue = new Set(['--role', '--scope', '--label', '--sensor', '--revoke']);
  const dest = {
    '--role': 'role',
    '--scope': 'scope',
    '--label': 'label',
    '--sensor': 'sensor',
    '--revoke': 'revoke',
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    // `--role=pharma` and `--role pharma` are both idiomatic; accept both rather
    // than making the operator remember which one this tool wanted.
    const eq = arg.indexOf('=');
    const name = eq === -1 ? arg : arg.slice(0, eq);
    const inline = eq === -1 ? null : arg.slice(eq + 1);

    if (takesValue.has(name)) {
      const value = inline ?? argv[++i];
      // A missing value would otherwise consume the next flag: `--role --json`
      // would set role to "--json" and then fail with a baffling "unknown role".
      if (value === undefined || (inline === null && String(value).startsWith('--'))) {
        throw new Error(`${name} needs a value\n\n${USAGE}`);
      }
      out[dest[name]] = String(value);
      continue;
    }

    switch (name) {
      case '--help':
      case '-h':
        out.help = true;
        break;
      case '--list-roles':
        out.listRoles = true;
        break;
      case '--json':
        out.json = true;
        break;
      case '--rotate-sensor':
        out.rotate = true;
        break;
      default:
        throw new Error(`unknown option ${JSON.stringify(arg)}\n\n${USAGE}`);
    }
  }

  return out;
}

/** Align a `label  value` block without pulling in a table library. */
function block(pairs) {
  const width = Math.max(...pairs.map(([k]) => k.length));
  return pairs.map(([k, v]) => `${k.padEnd(width)}  ${v}`).join('\n');
}

async function main() {
  const stdout = (s) => process.stdout.write(`${s}\n`);
  // Advisories, warnings and headings go to stderr so that stdout carries only the
  // credential material — which is what makes `--json` pipeable and what stops a
  // shell redirect capturing a page of prose around the key.
  const stderr = (s) => process.stderr.write(`${s}\n`);

  let args;
  try {
    args = parseArgs(process.argv.slice(2));
  } catch (err) {
    stderr(err.message);
    process.exitCode = 2;
    return;
  }

  if (args.help) {
    stdout(USAGE);
    return;
  }

  if (args.listRoles) {
    // rules.js requires any tool printing this list to print what each role means
    // beside it, because `pharma` and `pharmacy` are one letter and a world apart.
    stdout(block(roleTable().map((r) => [r.role, r.purpose])));
    return;
  }

  if (!args.role && !args.revoke) {
    stderr(`nothing to do: pass --role, --revoke or --list-roles\n\n${USAGE}`);
    process.exitCode = 2;
    return;
  }

  // Imported dynamically for the reason server.js does it: config validates the
  // environment at import time, and a static import turns a misconfigured
  // environment into a stack trace with the operator's actual problem buried in it.
  let config;
  let Logger;
  try {
    ({ config } = await import('../src/config/index.js'));
    ({ Logger } = await import('../src/utils/logger.js'));
  } catch (err) {
    stderr(err?.message ?? String(err));
    process.exitCode = 1;
    return;
  }

  const { createStore } = await import('../src/db/index.js');
  const logger = new Logger(
    { component: 'issue-key' },
    // Nothing on the happy path needs a log line, and a driver's own startup
    // chatter would land in the middle of the credential block.
    { level: config.log.level === 'debug' ? 'debug' : 'warn', pretty: config.log.pretty },
  );
  const store = createStore(config, logger);

  if (store.driver === 'memory') {
    stderr(
      'refusing to issue a key against the in-memory store.\n\n' +
        'FABRIC_MOCK=1 keeps the entire stack — ledger, database and cache — inside\n' +
        'one process, so a key written here would disappear when this script exits\n' +
        'and no request could ever use it.\n\n' +
        'To get working keys for the mock stack, seed it from inside the server:\n' +
        '    SEED_DEMO=1 npm start\n\n' +
        'To issue a durable key, point the service at a real PostgreSQL and Fabric\n' +
        'network (FABRIC_MOCK=0, DATABASE_URL=...) and run this again.',
    );
    process.exitCode = 1;
    return;
  }

  try {
    if (typeof store.connect === 'function') await store.connect();

    if (args.revoke) {
      const revoked = await revokeByHash({ store, keyHash: args.revoke });
      if (args.json) {
        stdout(JSON.stringify({ key_hash: args.revoke.toLowerCase(), revoked }));
      } else if (revoked) {
        stdout(`revoked ${args.revoke.toLowerCase()}`);
      } else {
        stderr('no live key with that hash: it is unknown or already revoked');
        process.exitCode = 1;
      }
      return;
    }

    if (args.sensor && args.role !== ROLE.SENSOR) {
      stderr(
        `--sensor provisions a device secret, which only a ${ROLE.SENSOR} key can ` +
          `use; --role is ${args.role}`,
      );
      process.exitCode = 2;
      return;
    }

    const { key, keyHash, row } = await issueApiKey({
      store,
      role: args.role,
      scope: args.scope,
      label: args.label,
    });

    const pairs = [
      ['role', `${row.role}   (${ROLE_PURPOSE[row.role]})`],
      ['label', row.label || '(none)'],
      ['scope', row.scope || '(none)'],
      ['key', key],
      ['key_hash', keyHash],
      ['key_id', row.id],
      ['created_at', row.created_at],
    ];
    const json = {
      role: row.role,
      label: row.label,
      scope: row.scope,
      key,
      key_hash: keyHash,
      key_id: row.id,
      created_at: row.created_at,
    };

    if (args.sensor) {
      const secrets = new SecretBox(config.secrets.encryptionKey);
      const sensor = await provisionSensor({
        store,
        secrets,
        sensorId: args.sensor,
        label: args.label,
        rotate: args.rotate,
      });
      pairs.push(['sensor_id', sensor.sensorId], ['sensor_secret', sensor.secret]);
      json.sensor_id = sensor.sensorId;
      json.sensor_secret = sensor.secret;
      if (sensor.rotated) {
        stderr(
          `sensor ${sensor.sensorId} had an existing secret and it has been ` +
            'replaced. That device cannot submit readings until it is reflashed ' +
            'with the secret below.',
        );
      }
    }

    if (args.json) {
      stdout(JSON.stringify(json));
    } else {
      stdout(block(pairs));
    }

    stderr('');
    stderr(
      'The key above is shown once. Only its SHA-256 hash is stored, so it cannot\n' +
        'be recovered — put it in your secret manager now. Keep key_hash: it is how\n' +
        `you revoke this key (--revoke ${keyHash}).`,
    );
    if (args.sensor) {
      stderr(
        '\nThe sensor secret goes in iot/include/secrets.h, which is gitignored, or\n' +
          'is provisioned over the serial console. It is stored encrypted at rest.',
      );
    }
  } catch (err) {
    stderr(err?.message ?? String(err));
    process.exitCode = 1;
  } finally {
    if (typeof store.close === 'function') {
      await store.close().catch(() => {});
    }
  }
}

// Only when run directly. Under `node --test` argv[1] is the test file, so
// importing this module to test its functions never triggers the CLI.
if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  await main();
}

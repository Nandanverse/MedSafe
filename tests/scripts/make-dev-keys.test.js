/**
 * Materialising `backend/keys/` for development.
 *
 * This script exists because `assertRuntimePaths` will not let the server start
 * without a trust bundle and a root public key, even in mock mode, and the repository
 * ships neither. So it stands between a fresh clone and `npm start`, which makes two
 * things worth proving.
 *
 * That what it writes actually loads. A bundle whose signature does not verify is
 * worse than a missing one: the server refuses to boot and the error points at the
 * trust bundle rather than at whatever produced it. So the output is loaded back here
 * through the API's own loader with signature checking on.
 *
 * That it writes *this* root and not a new one. `mobile/assets/trust_bundle.json` is
 * the same bundle, so a phone built from this repository and a server started from
 * these keys agree about who may sign a medicine. A freshly generated root would
 * verify perfectly on the server and make every scan from the app fail — the failure
 * is total, silent on the server side, and looks nothing like its cause. The test for
 * it reaches across into `mobile/` deliberately: the invariant spans both, so a test
 * that only looked at `backend/` could not see it.
 *
 * Every case writes into a temporary directory. Nothing here touches the real
 * `backend/keys/`, which on a developer's machine may be pointing at something real.
 */

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { loadTrustBundle } from '../../src/services/trust.js';
import {
  DEFAULT_FIXTURES_PATH,
  DEFAULT_OUT_DIR,
  materialiseDevKeys,
} from '../../scripts/make-dev-keys.js';

const FIXTURES = JSON.parse(readFileSync(DEFAULT_FIXTURES_PATH, 'utf8'));

/** `backend/`, so the sibling `mobile/` can be found without a hardcoded absolute. */
const BACKEND_ROOT = new URL('../../', import.meta.url);
const MOBILE_BUNDLE = new URL('../mobile/assets/trust_bundle.json', BACKEND_ROOT);
const MOBILE_PINNED_KEY = new URL('../mobile/lib/core/pinned_root_key.dart', BACKEND_ROOT);

let tmpRoot;
let counter = 0;

before(async () => {
  tmpRoot = await mkdtemp(path.join(os.tmpdir(), 'truemed-devkeys-'));
});

after(async () => {
  if (tmpRoot) await rm(tmpRoot, { recursive: true, force: true });
});

/** A directory of its own for each case, so no case can inherit another's files. */
function outDir() {
  counter += 1;
  return path.join(tmpRoot, `case-${counter}`);
}

/** A fixtures file with one field replaced, for the cases that must be refused. */
async function fixturesWith(patch) {
  const dir = outDir();
  await mkdir(dir, { recursive: true });
  const file = path.join(dir, 'fixtures.json');
  await writeFile(file, JSON.stringify({ ...FIXTURES, ...patch }), 'utf8');
  return file;
}

describe('writing the development trust keys', () => {
  test('what it writes loads through the server\'s own loader', async () => {
    const dir = outDir();
    const out = await materialiseDevKeys({ outDir: dir, env: { NODE_ENV: 'development' } });

    assert.equal(out.bundlePath, path.join(dir, 'trust-bundle.json'));
    assert.equal(out.rootPublicKeyPath, path.join(dir, 'root-public.pem'));

    // Signature checking on regardless of what the local environment says, because
    // this is the check the server will make in front of a patient.
    const bundle = await loadTrustBundle({
      bundlePath: out.bundlePath,
      rootPublicKeyPath: out.rootPublicKeyPath,
      requireSignature: true,
    });
    const summary = bundle.summary();

    assert.equal(summary.root_fingerprint, FIXTURES.root_fingerprint);
    assert.equal(out.rootFingerprint, FIXTURES.root_fingerprint);
    // Two active keys and one revoked, in the fixtures. A bundle with no active key
    // loads and verifies and then answers UNVERIFIABLE to every scan.
    assert.equal(summary.active_key_count, 2);
    assert.equal(summary.key_count, 3);
  });

  /**
   * The cross-component invariant. If this fails, the server trusts one root and the
   * phone pins another, and every scan from the app fails while the API insists
   * everything is fine.
   */
  test('it writes the same root the mobile app pins', async () => {
    const dir = outDir();
    const out = await materialiseDevKeys({ outDir: dir, env: {} });

    const written = JSON.parse(await readFile(out.bundlePath, 'utf8'));
    const shipped = JSON.parse(await readFile(MOBILE_BUNDLE, 'utf8'));
    assert.deepEqual(
      written,
      shipped,
      'the server bundle and mobile/assets/trust_bundle.json are different bundles',
    );

    const pinned = await readFile(MOBILE_PINNED_KEY, 'utf8');
    assert.ok(
      pinned.includes(FIXTURES.root_fingerprint),
      `mobile/lib/core/pinned_root_key.dart does not pin ${FIXTURES.root_fingerprint}`,
    );
  });

  /**
   * Re-serialising the bundle is only safe because the root signature covers the
   * canonical bytes of {version, issued_at, keys}, which indentation cannot reach.
   * The file is pretty-printed so a human can see which keys a dev server trusts —
   * and that is worth stating as a test, because "reformat the JSON" is an
   * innocuous-looking change that would break a signature over raw bytes.
   */
  test('pretty-printing the bundle does not invalidate its signature', async () => {
    const dir = outDir();
    const out = await materialiseDevKeys({ outDir: dir, env: {} });
    const text = await readFile(out.bundlePath, 'utf8');

    assert.ok(text.includes('\n  "version"'), 'the bundle was not pretty-printed');
    assert.ok(text.endsWith('\n'), 'no trailing newline');

    const bundle = await loadTrustBundle({
      bundlePath: out.bundlePath,
      rootPublicKeyPath: out.rootPublicKeyPath,
      requireSignature: true,
    });
    assert.equal(bundle.summary().root_fingerprint, FIXTURES.root_fingerprint);
  });

  test('the PEM it writes ends in a newline and is a public key', async () => {
    const dir = outDir();
    const out = await materialiseDevKeys({ outDir: dir, env: {} });
    const pem = await readFile(out.rootPublicKeyPath, 'utf8');

    assert.match(pem, /^-----BEGIN PUBLIC KEY-----/);
    assert.ok(pem.endsWith('\n'));
    // The one thing that must never be here. This script copies public material and
    // generates nothing, so a private key in the output would mean the fixtures
    // themselves carry one.
    assert.equal(pem.includes('PRIVATE KEY'), false);
  });

  test('it creates the directory it was pointed at', async () => {
    const dir = path.join(outDir(), 'nested', 'keys');
    const out = await materialiseDevKeys({ outDir: dir, env: {} });
    assert.deepEqual((await readdir(dir)).sort(), ['root-public.pem', 'trust-bundle.json']);
    assert.equal(path.dirname(out.bundlePath), dir);
  });
});

describe('the refusals', () => {
  /**
   * The private half of this root is generated by a published script in this
   * repository, so anyone can sign a bundle it accepts: an attacker inserts their own
   * signing key, signs the bundle with the root everybody has, and every counterfeit
   * they print verifies as genuine. Under this root, signature checking is theatre.
   *
   * The refusal is asserted on the exported function rather than through the CLI so
   * that it holds however this code is reached.
   */
  test('it refuses to run with NODE_ENV=production', async () => {
    const dir = outDir();
    await assert.rejects(
      () => materialiseDevKeys({ outDir: dir, env: { NODE_ENV: 'production' } }),
      /production/,
    );
    // And it refused before writing, not after.
    await assert.rejects(() => readdir(dir), /ENOENT/);
  });

  test('it will not overwrite existing keys unless told to', async () => {
    const dir = outDir();
    const first = await materialiseDevKeys({ outDir: dir, env: {} });
    const before = await readFile(first.bundlePath, 'utf8');

    await assert.rejects(
      () => materialiseDevKeys({ outDir: dir, env: {} }),
      /already exists/,
    );
    assert.equal(await readFile(first.bundlePath, 'utf8'), before, 'the file changed anyway');

    const second = await materialiseDevKeys({ outDir: dir, force: true, env: {} });
    assert.equal(second.rootFingerprint, first.rootFingerprint);
  });

  /**
   * The interesting failure: a bundle that is well-formed and whose signature does
   * not verify. It must be refused *and* leave nothing behind, because a half-written
   * pair would make the next run refuse with "already exists" and blame the operator
   * for this failure.
   */
  test('a forged signature is refused and no partial files survive', async () => {
    const dir = outDir();
    const fixturesPath = await fixturesWith({
      trust_bundle_signed: FIXTURES.trust_bundle_forged_signature,
    });

    await assert.rejects(
      () => materialiseDevKeys({ outDir: dir, fixturesPath, env: {} }),
      // The code, not just "it threw": a typo in the temporary fixtures path would
      // also reject, and would prove nothing about signature checking.
      (err) => {
        assert.equal(err.code, 'SIGNATURE_INVALID');
        return true;
      },
    );
    assert.deepEqual(
      await readdir(dir).catch(() => []),
      [],
      'a rejected run left files behind, including .tmp leftovers',
    );
  });

  /**
   * The attack the production refusal is about, in fixture form: a bundle carrying an
   * extra signing key that the root signature does not cover.
   */
  test('an injected signing key is refused', async () => {
    const dir = outDir();
    const fixturesPath = await fixturesWith({
      trust_bundle_signed: FIXTURES.trust_bundle_injected_key,
    });

    await assert.rejects(
      () => materialiseDevKeys({ outDir: dir, fixturesPath, env: {} }),
      (err) => {
        assert.equal(err.code, 'SIGNATURE_INVALID');
        return true;
      },
    );
    assert.deepEqual(await readdir(dir).catch(() => []), []);
  });

  /**
   * An unsigned bundle would be written happily and then fail at boot, because
   * TRUST_REQUIRE_SIGNATURE defaults to 1 — so the check has to happen here, where
   * the message can say why.
   */
  test('an unsigned bundle is refused before anything is written', async () => {
    const dir = outDir();
    const fixturesPath = await fixturesWith({
      trust_bundle_signed: FIXTURES.trust_bundle_unsigned,
    });

    await assert.rejects(
      () => materialiseDevKeys({ outDir: dir, fixturesPath, env: {} }),
      /no root_signature/,
    );
    await assert.rejects(() => readdir(dir), /ENOENT/);
  });

  test('a file that is not the fixtures is refused by name', async () => {
    const dir = outDir();
    const fixturesPath = await fixturesWith({
      trust_bundle_signed: undefined,
      root_public_key_pem: undefined,
    });

    await assert.rejects(
      () => materialiseDevKeys({ outDir: dir, fixturesPath, env: {} }),
      (err) => {
        assert.match(err.message, /trust_bundle_signed/);
        // The path is in the message: with no path, "not the TrueMed fixture file"
        // gives the reader nothing to go and look at.
        assert.ok(err.message.includes(fixturesPath));
        return true;
      },
    );
  });

  test('a missing fixtures file is reported with its path', async () => {
    const missing = path.join(tmpRoot, 'nowhere', 'fixtures.json');
    await assert.rejects(
      () => materialiseDevKeys({ outDir: outDir(), fixturesPath: missing, env: {} }),
      (err) => {
        assert.match(err.message, /could not read the fixtures/);
        assert.ok(err.message.includes(missing));
        return true;
      },
    );
  });
});

describe('where it writes by default', () => {
  /**
   * The defaults are resolved from this module's own URL rather than from
   * `process.cwd()`, so `npm run dev-keys` writes to the same place whether it is run
   * from the repository root or from `backend/`. A cwd-relative default would put the
   * keys somewhere the server does not look and report success.
   */
  test('the defaults point inside backend/, not at the working directory', () => {
    const backend = new URL('../../', import.meta.url).pathname;
    for (const p of [DEFAULT_FIXTURES_PATH, DEFAULT_OUT_DIR]) {
      assert.ok(path.isAbsolute(p), `${p} is not absolute`);
      assert.ok(p.startsWith(backend.replace(/\/$/, '')), `${p} is outside backend/`);
    }
    assert.equal(path.basename(DEFAULT_OUT_DIR), 'keys');
    assert.equal(path.basename(DEFAULT_FIXTURES_PATH), 'fixtures.json');
  });
});

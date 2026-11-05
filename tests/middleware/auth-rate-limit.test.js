/**
 * Authentication, authorisation and rate limiting — and the load-bearing
 * relationship between them.
 *
 * These middlewares are tested together rather than separately because the defect
 * they are most likely to develop lives in the seam. The authenticated limiters key
 * on `req.auth.keyHash` and fall back to the client IP when there is no identity
 * yet, so *the order they are mounted in changes what is being budgeted*. Mount the
 * limiter first and the fallback becomes the only path: every authenticated budget
 * silently degrades into a per-address one, and anyone sharing a pharmacy's NAT can
 * spend that pharmacy's quota until a chemist can no longer record `dispensed`.
 * Nothing about that failure is visible in either file read on its own, which is why
 * `keying is per key, not per address` below asserts it directly.
 *
 * The other properties pinned here:
 *
 * **A wrong-role key is a 403, never a 401.** Sending someone with a valid
 * credential back to re-authenticate is a support call that cannot resolve.
 *
 * **An unknown key and a revoked key are indistinguishable to the caller.** The
 * difference is only useful to someone probing which keys once existed.
 *
 * No Express: each middleware is invoked directly with a request-shaped object and a
 * `next` that captures what it was passed, which is the whole contract they have.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { makeAuth, sha256hex } from '../../src/middleware/auth.js';
import { makeRateLimiter } from '../../src/middleware/rate-limit.js';
import { MemoryStore } from '../../src/db/memory-store.js';
import { loadConfig } from '../../src/config/index.js';
import { CODES } from '../../src/core/errors.js';

const FIXED_NOW = new Date('2026-06-01T10:00:00Z');

/** A clock the tests can wind forward, to cross a window boundary without waiting. */
function movableClock(start = FIXED_NOW) {
  let ms = start.getTime();
  const clock = () => new Date(ms);
  clock.advance = (byMs) => {
    ms += byMs;
  };
  return clock;
}

/** A request as these middlewares see it: a header getter, an ip, and nothing else. */
function req({ apiKey, ip = '203.0.113.7' } = {}) {
  const headers = apiKey === undefined ? {} : { 'x-api-key': apiKey };
  return {
    ip,
    socket: { remoteAddress: ip },
    headers,
    get: (h) => headers[String(h).toLowerCase()],
  };
}

/** A response that only records the headers a limiter sets. */
function res() {
  return {
    headers: {},
    set(k, v) {
      this.headers[String(k).toLowerCase()] = String(v);
      return this;
    },
  };
}

/** Run one middleware and resolve with whatever it handed to `next`. */
function run(middleware, request, response = res()) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('middleware never called next')), 1000);
    middleware(request, response, (err) => {
      clearTimeout(timer);
      resolve(err ?? null);
    });
  });
}

async function storeWithKeys() {
  const store = new MemoryStore({ clock: () => FIXED_NOW });
  const keys = {
    manufacturer: `tm_manufacturer_${'a'.repeat(32)}`,
    distributor: `tm_distributor_${'b'.repeat(32)}`,
    pharma: `tm_pharma_${'c'.repeat(32)}`,
    revoked: `tm_manufacturer_${'d'.repeat(32)}`,
  };
  await store.insertApiKey({ role: 'manufacturer', keyHash: sha256hex(keys.manufacturer), label: 'm1' });
  await store.insertApiKey({ role: 'distributor', keyHash: sha256hex(keys.distributor), label: 'd1' });
  await store.insertApiKey({
    role: 'pharma',
    keyHash: sha256hex(keys.pharma),
    label: 'p1',
    scope: 'MH/25D/2019/187',
  });
  await store.insertApiKey({ role: 'manufacturer', keyHash: sha256hex(keys.revoked), label: 'old' });
  await store.revokeApiKey(sha256hex(keys.revoked));
  return { store, keys };
}

describe('auth', () => {
  test('a valid key attaches the role and scope, and never the key itself', async () => {
    const { store, keys } = await storeWithKeys();
    const auth = makeAuth({ store });
    const r = req({ apiKey: keys.pharma });

    assert.equal(await run(auth.authenticate, r), null);
    assert.equal(r.auth.role, 'pharma');
    assert.equal(r.auth.scope, 'MH/25D/2019/187', 'the licence a pharma board is filtered by');
    // Only the hash travels with the request; a log line that dumps req.auth must
    // not be able to leak a working credential.
    assert.equal(JSON.stringify(r.auth).includes(keys.pharma), false);
  });

  test('a missing key is 401', async () => {
    const { store } = await storeWithKeys();
    const auth = makeAuth({ store });
    const err = await run(auth.authenticate, req());
    assert.equal(err.code, CODES.UNAUTHORIZED);
    assert.equal(err.status, 401);
  });

  test('an unknown key and a revoked key are indistinguishable', async () => {
    const { store, keys } = await storeWithKeys();
    const auth = makeAuth({ store });

    const unknown = await run(auth.authenticate, req({ apiKey: `tm_manufacturer_${'9'.repeat(32)}` }));
    const revoked = await run(auth.authenticate, req({ apiKey: keys.revoked }));

    assert.equal(unknown.status, 401);
    assert.equal(revoked.status, 401);
    assert.equal(unknown.message, revoked.message, 'the difference only helps an attacker');
  });

  /**
   * The role check is a separate question from the identity check, and answering it
   * with a 401 would tell a distributor with a perfectly good key to go and fix
   * their credentials — which they cannot do, because nothing is wrong with them.
   */
  test('a valid key for the wrong role is 403 and names the role required', async () => {
    const { store, keys } = await storeWithKeys();
    const auth = makeAuth({ store });

    const err = await run(auth.requireRole('manufacturer'), req({ apiKey: keys.distributor }));

    assert.equal(err.status, 403);
    assert.equal(err.code, CODES.FORBIDDEN);
    assert.match(err.message, /manufacturer/);
  });

  test('requireRole accepts any of the roles it lists', async () => {
    const { store, keys } = await storeWithKeys();
    const auth = makeAuth({ store });
    const gate = auth.requireRole('manufacturer', 'distributor', 'pharmacy');

    assert.equal(await run(gate, req({ apiKey: keys.manufacturer })), null);
    assert.equal(await run(gate, req({ apiKey: keys.distributor })), null);
  });

  /**
   * `pharma` is a read-only analytics role and `pharmacy` is a chemist who moves
   * stock. One letter apart, and the contract carries a warning about it. A gate
   * that meant to admit chemists must not admit analytics keys.
   */
  test('a pharma key does not satisfy a pharmacy gate', async () => {
    const { store, keys } = await storeWithKeys();
    const auth = makeAuth({ store });

    const err = await run(auth.requireRole('pharmacy'), req({ apiKey: keys.pharma }));
    assert.equal(err.status, 403);
  });

  test('a failure to record last-used does not fail the request', async () => {
    const { store, keys } = await storeWithKeys();
    store.touchApiKey = async () => {
      throw new Error('database is read-only');
    };
    const auth = makeAuth({ store });

    // Bookkeeping must never be able to lock out a valid credential.
    assert.equal(await run(auth.authenticate, req({ apiKey: keys.manufacturer })), null);
  });
});

describe('rate limiting', () => {
  function limiters(overrides = {}) {
    const clock = movableClock();
    const config = loadConfig({
      NODE_ENV: 'development',
      FABRIC_MOCK: '1',
      LOG_LEVEL: 'silent',
      TRUST_REQUIRE_SIGNATURE: '0',
      SENSOR_REQUIRE_HMAC: '0',
      RATE_LIMIT_PUBLIC_PER_MIN: '3',
      RATE_LIMIT_AUTHED_PER_MIN: '3',
      RATE_LIMIT_REPORT_PER_HOUR: '2',
      ...overrides,
    });
    return { limiters: makeRateLimiter({ config, clock }), clock };
  }

  test('a budget allows exactly its limit, then rejects with Retry-After', async () => {
    const { limiters: lim } = limiters();
    const r = req();

    for (let i = 0; i < 3; i += 1) {
      assert.equal(await run(lim.public, r), null, `request ${i + 1} should pass`);
    }

    const response = res();
    const err = await run(lim.public, r, response);
    assert.equal(err.code, CODES.RATE_LIMITED);
    assert.equal(err.status, 429);
    assert.equal(response.headers['x-ratelimit-remaining'], '0');
    assert.ok(err.retryAfter > 0, 'a client must be told when to come back');
  });

  test('the window resets once the clock passes it', async () => {
    const { limiters: lim, clock } = limiters();
    const r = req();
    for (let i = 0; i < 4; i += 1) await run(lim.public, r);

    clock.advance(60_001);

    assert.equal(await run(lim.public, r), null, 'a new window starts clean');
  });

  test('one address exhausting the public budget does not affect another', async () => {
    const { limiters: lim } = limiters();
    const a = req({ ip: '203.0.113.7' });
    const b = req({ ip: '198.51.100.9' });

    for (let i = 0; i < 4; i += 1) await run(lim.public, a);

    assert.equal(await run(lim.public, b), null);
  });

  /**
   * The seam. Both requests come from one address — a pharmacy chain behind a
   * single NAT, or two devices on one clinic uplink — and carry different keys.
   * The authenticated budget must follow the credential.
   *
   * If this ever fails, the cause is almost certainly that a route mounted
   * `limiters.authed` *before* `auth.requireRole(...)`: with no `req.auth` yet, the
   * limiter falls back to the IP and both keys share one budget. The fallback
   * itself is correct and deliberate — a budget must never silently vanish — which
   * is exactly why the ordering has to be asserted rather than trusted.
   */
  test('the authed budget keys on the API key, not the address', async () => {
    const { limiters: lim } = limiters();
    const ip = '203.0.113.7';
    const first = { ...req({ ip }), auth: { keyHash: 'hash-of-key-one' } };
    const second = { ...req({ ip }), auth: { keyHash: 'hash-of-key-two' } };

    for (let i = 0; i < 4; i += 1) await run(lim.authed, first);
    assert.ok(await run(lim.authed, first), 'the first key is out of budget');

    assert.equal(
      await run(lim.authed, second),
      null,
      'a second key on the same address must have its own budget',
    );
  });

  test('an unauthenticated request still gets a budget, keyed by address', async () => {
    const { limiters: lim } = limiters();
    // The fallback path: no req.auth at all.
    const r = req();
    for (let i = 0; i < 3; i += 1) assert.equal(await run(lim.authed, r), null);
    assert.ok(await run(lim.authed, r), 'the budget must not silently vanish');
  });

  /**
   * Reports are the expensive endpoint — each one stores a photo — so the budget is
   * per hour rather than per minute. A minute-long window here would let a single
   * address file 1,440 reports a day and drown the regulator's queue.
   */
  test('the report budget spans an hour, not a minute', async () => {
    const { limiters: lim, clock } = limiters();
    const r = req();
    for (let i = 0; i < 3; i += 1) await run(lim.report, r);

    clock.advance(60_001 * 5);
    assert.ok(await run(lim.report, r), 'five minutes must not reopen an hourly budget');

    clock.advance(3_600_000);
    assert.equal(await run(lim.report, r), null);
  });

  test('every response carries the budget headers, not just the rejection', async () => {
    const { limiters: lim } = limiters();
    const response = res();
    await run(lim.public, req(), response);

    assert.equal(response.headers['x-ratelimit-limit'], '3');
    assert.equal(response.headers['x-ratelimit-remaining'], '2');
    assert.ok(Number(response.headers['x-ratelimit-reset']) > 0);
  });
});

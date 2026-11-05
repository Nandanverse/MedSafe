/**
 * In-memory cache — the driver behind the mock stack and the test suite.
 *
 * A plain Map with a TTL and a size cap, deliberately built with no timers. An
 * earlier instinct is to `setTimeout` each key's expiry, but a process holding
 * thousands of live timers keeps the Node event loop alive, so `node --test`
 * would hang after the assertions pass, waiting for timers that never matter.
 * Instead expiry is *lazy*: a key carries its death time and is checked on read,
 * and a bounded sweep runs opportunistically on write. Nothing here keeps the
 * loop alive, so the suite exits cleanly.
 *
 * This is not a distributed cache — each API process gets its own Map — which is
 * exactly why production uses Redis (see redis.js). For a single-process dev
 * server, one demo laptop or the test runner it is faithful to the interface and
 * needs no infrastructure.
 */

import { CACHE_STATE } from './index.js';

/** Hard ceiling on entries, so a stray loop cannot exhaust memory. */
const MAX_ENTRIES = 10000;

export class MemoryCache {
  /**
   * @param {object} redisCfg  config.redis (ttl, keyPrefix)
   * @param {import('../utils/logger.js').Logger} [logger]
   */
  constructor(redisCfg, logger) {
    this.driver = 'memory';
    this.cfg = redisCfg;
    this.log = logger ?? null;
    /** key → { value, expiresAtMs } */
    this.map = new Map();
    /** nonce key → expiresAtMs; separate map keeps verify sweeps cheap */
    this.nonces = new Map();
  }

  #now() {
    return Date.now();
  }

  #verifyKey(productID) {
    return `${this.cfg.keyPrefix}${productID}`;
  }

  /** Drop one expired entry class in bounded work; called on writes, not reads. */
  #sweep(store) {
    const now = this.#now();
    let scanned = 0;
    for (const [k, deadline] of store) {
      // A Map iterates in insertion order, and TTLs within one class are equal,
      // so the oldest keys expire first — stop at the first live one.
      if (deadline > now) break;
      store.delete(k);
      if (++scanned >= 64) break; // bound the work per write
    }
  }

  #evictIfFull(store) {
    while (store.size >= MAX_ENTRIES) {
      // Map preserves insertion order; the first key is the oldest.
      const oldest = store.keys().next().value;
      if (oldest === undefined) break;
      store.delete(oldest);
    }
  }

  /**
   * @param {string} productID
   * @returns {Promise<object|null>} the cached response body, or null on miss/expiry
   */
  async get(productID) {
    const entry = this.map.get(this.#verifyKey(productID));
    if (!entry) return null;
    if (entry.expiresAtMs <= this.#now()) {
      this.map.delete(this.#verifyKey(productID));
      return null;
    }
    // Return a copy: a caller mutating the response must not corrupt the cache.
    return JSON.parse(entry.value);
  }

  /**
   * @param {string} productID
   * @param {object} body   the response envelope to cache
   * @param {'terminal'|'active'|'negative'} state
   */
  async setVerify(productID, body, state) {
    const ttlS = this.#ttlFor(state);
    if (ttlS <= 0) return;
    this.#sweep(this.map);
    this.#evictIfFull(this.map);
    this.map.set(this.#verifyKey(productID), {
      value: JSON.stringify(body),
      expiresAtMs: this.#now() + ttlS * 1000,
    });
  }

  #ttlFor(state) {
    switch (state) {
      case CACHE_STATE.TERMINAL:
        return this.cfg.ttl.terminalS;
      case CACHE_STATE.ACTIVE:
        return this.cfg.ttl.activeS;
      case CACHE_STATE.NEGATIVE:
        return this.cfg.ttl.negativeS;
      default:
        return this.cfg.ttl.activeS;
    }
  }

  /**
   * Invalidate a cached verification (§4.6: any write to a product deletes its
   * key, so the next read reflects the new chain state rather than a stale hit).
   */
  async del(productID) {
    this.map.delete(this.#verifyKey(productID));
  }

  /**
   * Reserve a sensor nonce (§4.5 replay protection). First claim wins; a repeat
   * within the TTL is rejected. Mirrors Redis `SET key val NX EX ttl`.
   *
   * @returns {Promise<boolean>} true if reserved (fresh), false if already seen
   */
  async reserveNonce(sensorId, nonce, ttlS) {
    const key = `nonce:${sensorId}:${nonce}`;
    const now = this.#now();
    const existing = this.nonces.get(key);
    if (existing !== undefined && existing > now) return false;
    this.#sweep(this.nonces);
    this.#evictIfFull(this.nonces);
    this.nonces.set(key, now + ttlS * 1000);
    return true;
  }

  async ping() {
    return { ok: true, driver: 'memory' };
  }

  async close() {
    this.map.clear();
    this.nonces.clear();
  }
}

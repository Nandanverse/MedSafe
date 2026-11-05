/**
 * The cache interface, and the three drivers behind it.
 *
 * Redis in production, an in-memory map in development and tests, and a null
 * driver when caching is switched off. Every route talks to this interface and
 * never to a Redis client directly, so REDIS_ENABLED=0 is a supported mode rather
 * than a crash: the API is correct with the cache gone, just slower, because
 * every verification then reaches the blockchain. A cache is an optimisation, and
 * an optimisation that can take down the service it accelerates is a liability.
 *
 * Two things share this layer because both are short-lived keyed state with a TTL:
 *
 * - **Verification results** (§4.6), keyed `verify:v1:<product_id>`, with the TTL
 *   chosen by product state: an hour for terminal (dispensed/recalled), a minute
 *   for active, thirty seconds as a negative cache for not-found (which blunts an
 *   attacker enumerating product IDs).
 * - **Sensor nonces** (§4.5), so a captured temperature reading cannot be
 *   replayed for 24 hours. This is a reservation, not a cache: the first caller to
 *   claim a nonce wins and every later claim is rejected.
 */

import { MemoryCache } from './memory.js';
import { RedisCache } from './redis.js';

/** Cache states from DATA-CONTRACT.md §4.6, mapped to their TTL config key. */
export const CACHE_STATE = Object.freeze({
  TERMINAL: 'terminal',
  ACTIVE: 'active',
  NEGATIVE: 'negative',
});

/**
 * The do-nothing driver. Reads always miss, writes are dropped, and — the one
 * subtlety — a nonce reservation always succeeds, because with no shared store
 * there is nowhere to remember a nonce. That means replay protection is absent
 * when the cache is off; the server logs a warning at startup so this is a known
 * state, not a silent hole. Production keeps Redis enabled.
 */
class NullCache {
  constructor(logger) {
    this.driver = 'null';
    this.log = logger ?? null;
  }
  async get() {
    return null;
  }
  async setVerify() {
    /* dropped */
  }
  async del() {
    /* nothing cached */
  }
  async reserveNonce() {
    return true; // cannot detect a replay without a store
  }
  async ping() {
    return { ok: true, driver: 'null' };
  }
  async close() {
    /* nothing to release */
  }
}

/**
 * @param {object} config  the frozen app config
 * @param {import('../utils/logger.js').Logger} logger
 * @returns {NullCache|MemoryCache|RedisCache}
 */
export function createCache(config, logger) {
  if (!config.redis.enabled) {
    logger?.warn(
      'cache disabled (REDIS_ENABLED=0): every verification will reach the ' +
        'blockchain, and sensor nonce replay protection is inactive',
    );
    return new NullCache(logger);
  }
  // The mock stack runs with no infrastructure, so it uses an in-process cache
  // rather than requiring a Redis server for local development and tests.
  if (config.fabric.mock) {
    logger?.info('cache driver: in-memory (mock stack)');
    return new MemoryCache(config.redis, logger);
  }
  return new RedisCache(config.redis, logger);
}

export { MemoryCache, RedisCache, NullCache };

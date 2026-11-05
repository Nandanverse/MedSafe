/**
 * The Redis cache driver, used in production (FABRIC_MOCK=0, REDIS_ENABLED=1).
 *
 * Same interface as MemoryCache, so routes never know which is behind them. Two
 * design points:
 *
 * **The `redis` package is imported lazily, inside connect().** As with the
 * Fabric client, this keeps the mock/test path loadable on a machine that never
 * ran `npm install` for production, and turns a missing dependency into a clear
 * startup message rather than an import-time crash.
 *
 * **Redis is treated as a soft dependency at request time.** A cache is an
 * accelerator; if the Redis call throws mid-request, the API must still answer
 * from the blockchain. So `get`/`setVerify`/`del` swallow errors and log them,
 * degrading to cache-miss behaviour instead of failing the user's verification.
 * The one exception is `reserveNonce`: replay protection is a security control,
 * not an optimisation, so if Redis is unreachable there we fail closed and let
 * the caller surface UPSTREAM_UNAVAILABLE rather than silently accepting a
 * possible replay.
 */

import { CACHE_STATE } from './index.js';
import { CODES, TrueMedError, upstreamUnavailable } from '../core/errors.js';

export class RedisCache {
  /**
   * @param {object} redisCfg  config.redis
   * @param {import('../utils/logger.js').Logger} logger
   */
  constructor(redisCfg, logger) {
    this.driver = 'redis';
    this.cfg = redisCfg;
    this.log = logger;
    this.client = null;
    this.ready = false;
  }

  async connect() {
    if (this.client) return;

    let createClient;
    try {
      ({ createClient } = await import('redis'));
    } catch (cause) {
      throw new TrueMedError(
        CODES.INTERNAL_ERROR,
        'REDIS_ENABLED=1 but the `redis` package is not installed. Run ' +
          '`npm ci` in backend/, or set REDIS_ENABLED=0 to run without a cache.',
        { cause, expose: false },
      );
    }

    this.client = createClient({
      url: this.cfg.url,
      socket: {
        connectTimeout: this.cfg.connectTimeoutMs,
        // Bounded backoff: keep trying, but never wait more than 3s between
        // attempts, so a Redis blip self-heals without a tight reconnect loop.
        reconnectStrategy: (retries) => Math.min(retries * 100, 3000),
      },
    });

    // 'error' must have a listener or the client throws unhandled; log and let
    // the reconnect strategy recover rather than crashing the process.
    this.client.on('error', (err) => {
      this.ready = false;
      this.log?.warn('redis error', { error: err?.message });
    });
    this.client.on('ready', () => {
      this.ready = true;
      this.log?.info('redis ready', { url: redact(this.cfg.url) });
    });
    this.client.on('end', () => {
      this.ready = false;
    });

    await this.client.connect();
  }

  async #ensure() {
    if (!this.client) await this.connect();
  }

  #verifyKey(productID) {
    return `${this.cfg.keyPrefix}${productID}`;
  }

  async get(productID) {
    try {
      await this.#ensure();
      const raw = await this.client.get(this.#verifyKey(productID));
      if (!raw) return null;
      return JSON.parse(raw);
    } catch (err) {
      // Soft failure: a cache miss is always a safe fallback.
      this.log?.warn('redis get failed; treating as miss', { error: err?.message });
      return null;
    }
  }

  async setVerify(productID, body, state) {
    const ttlS = this.#ttlFor(state);
    if (ttlS <= 0) return;
    try {
      await this.#ensure();
      await this.client.set(this.#verifyKey(productID), JSON.stringify(body), { EX: ttlS });
    } catch (err) {
      // Soft failure: not caching this result only costs a future chain read.
      this.log?.warn('redis set failed; result not cached', { error: err?.message });
    }
  }

  async del(productID) {
    try {
      await this.#ensure();
      await this.client.del(this.#verifyKey(productID));
    } catch (err) {
      // Soft failure, but log loudly: a missed invalidation can serve a stale
      // verdict until the TTL lapses.
      this.log?.warn('redis del failed; cached verdict may be stale until TTL', {
        product_id: productID,
        error: err?.message,
      });
    }
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
   * Reserve a sensor nonce with SET NX EX — atomic, so two concurrent submits of
   * the same nonce cannot both win. Unlike the read/write cache methods this one
   * fails **closed**: replay protection is a security control, so if Redis is
   * unreachable we raise UPSTREAM_UNAVAILABLE rather than accept a possible replay.
   */
  async reserveNonce(sensorId, nonce, ttlS) {
    try {
      await this.#ensure();
      const key = `${this.cfg.keyPrefix}nonce:${sensorId}:${nonce}`;
      const res = await this.client.set(key, '1', { NX: true, EX: ttlS });
      return res === 'OK';
    } catch (cause) {
      throw upstreamUnavailable('the replay-protection store (redis)', cause);
    }
  }

  async ping() {
    await this.#ensure();
    const pong = await this.client.ping();
    return { ok: pong === 'PONG', driver: 'redis' };
  }

  async close() {
    if (!this.client) return;
    try {
      await this.client.quit();
    } catch {
      // If quit fails (already down), force the socket shut.
      this.client.destroy?.();
    } finally {
      this.client = null;
      this.ready = false;
    }
  }
}

/** Hide any credentials in a redis:// URL before it reaches a log line. */
function redact(url) {
  try {
    const u = new URL(url);
    if (u.password) u.password = '***';
    if (u.username) u.username = '***';
    return u.toString();
  } catch {
    return 'redis://<unparseable>';
  }
}

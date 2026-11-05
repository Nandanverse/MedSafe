/**
 * Fixed-window rate limiting, in memory, with no timers.
 *
 * Four budgets from config, each a separate middleware with its own counters:
 *   • public  — unauthenticated verify/read, per client IP
 *   • authed  — writer & dashboard calls, per API key
 *   • report  — patient counterfeit reports, per IP, per hour (abuse is costly:
 *               each report stores a photo), so this one is deliberately tight
 *   • sensor  — cold-box telemetry, per sensor's API key
 *
 * A window is a counter and a reset time; when the clock passes the reset the
 * counter starts over. No `setInterval` sweeps and no per-key timers, for the
 * same reason the cache avoids them: stray timers keep Node's event loop alive
 * and would hang `node --test`. Expired windows are pruned opportunistically on
 * access, and the bucket map is capped so a flood of distinct IPs cannot exhaust
 * memory.
 *
 * Limitation, stated rather than hidden: these counters live in one process, so
 * with several API replicas behind a load balancer the effective limit is per
 * replica. A horizontally scaled deployment should back this with a Redis
 * INCR/EXPIRE counter; the single-node budget here is correct for the demo and
 * the single-VM Oracle Cloud target, and the interface would not change.
 */

import { rateLimited } from '../core/errors.js';

const MAX_BUCKETS = 50000; // ceiling per limiter, so distinct keys can't OOM us

/**
 * @param {{config: object, logger?: import('../utils/logger.js').Logger,
 *          clock?: () => Date}} deps
 */
export function makeRateLimiter({ config, logger, clock }) {
  const nowMs = () => (clock ? clock().getTime() : Date.now());
  const rl = config.rateLimit;

  /**
   * Build one fixed-window limiter middleware.
   * @param {{name: string, windowMs: number, max: number,
   *          key: (req) => (string|null)}} spec
   */
  function limit({ name, windowMs, max, key }) {
    /** clientKey → { count, resetAt } */
    const buckets = new Map();
    let lastSweepAt = 0;

    function sweep(t) {
      for (const [k, b] of buckets) {
        if (b.resetAt <= t) buckets.delete(k);
      }
      // If still over the cap (many live windows), evict the soonest-to-reset
      // entries first — they cost the least to drop.
      if (buckets.size > MAX_BUCKETS) {
        const ordered = [...buckets.entries()].sort((a, b) => a[1].resetAt - b[1].resetAt);
        for (let i = 0; i < ordered.length && buckets.size > MAX_BUCKETS; i += 1) {
          buckets.delete(ordered[i][0]);
        }
        logger?.warn?.('rate-limiter bucket cap hit; evicted oldest windows', { limiter: name });
      }
    }

    return function rateLimit(req, res, next) {
      const t = nowMs();
      // Bounded, amortised cleanup: at most once per window, not per request.
      if (t - lastSweepAt >= windowMs) {
        sweep(t);
        lastSweepAt = t;
      }

      const k = key(req);
      if (k == null || k === '') return next(); // nothing to key on → do not limit

      let b = buckets.get(k);
      if (!b || b.resetAt <= t) {
        b = { count: 0, resetAt: t + windowMs };
        buckets.set(k, b);
      }
      b.count += 1;

      const remaining = Math.max(0, max - b.count);
      res.set('X-RateLimit-Limit', String(max));
      res.set('X-RateLimit-Remaining', String(remaining));
      res.set('X-RateLimit-Reset', String(Math.ceil(b.resetAt / 1000)));

      if (b.count > max) {
        const retryAfterSec = Math.ceil((b.resetAt - t) / 1000);
        return next(rateLimited(retryAfterSec));
      }
      return next();
    };
  }

  // Key extractors. IP honours Express `trust proxy` (set from config) so a
  // reverse proxy's X-Forwarded-For is trusted only when we configured it to be.
  const byIp = (req) => req.ip || req.socket?.remoteAddress || null;
  // Per API key; falls back to IP if somehow unauthenticated, so the budget can
  // never silently vanish.
  const byKey = (req) => req.auth?.keyHash || byIp(req);

  return {
    public: limit({ name: 'public', windowMs: 60_000, max: rl.publicPerMin, key: byIp }),
    authed: limit({ name: 'authed', windowMs: 60_000, max: rl.authedPerMin, key: byKey }),
    report: limit({ name: 'report', windowMs: 3_600_000, max: rl.reportPerHour, key: byIp }),
    sensor: limit({ name: 'sensor', windowMs: 60_000, max: rl.sensorPerMin, key: byKey }),
    /** Escape hatch for a bespoke window in a route/test. */
    custom: limit,
  };
}

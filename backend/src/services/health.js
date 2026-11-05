/**
 * `GET /healthz` and `GET /readyz`.
 *
 * These two probes answer different questions, and conflating them is the classic
 * way to turn a brief dependency outage into a self-inflicted outage of your own.
 *
 * **`/healthz` is liveness: is this process working?** It touches nothing external.
 * If Postgres is unreachable, this process is still perfectly capable of serving —
 * restarting it would not reconnect the database, it would just discard warm caches
 * and drop in-flight requests. An orchestrator restarts a container when liveness
 * fails, so a liveness probe that pings the database converts a database blip into a
 * rolling restart of every replica at exactly the moment the system is least able to
 * absorb it. So this returns `ok` whenever the event loop can answer at all.
 *
 * **`/readyz` is readiness: should traffic be sent here?** This one does check the
 * dependencies, because a replica that cannot reach the ledger should be taken out
 * of the load-balancer rotation without being killed. Failing readiness is
 * reversible and cheap; failing liveness is neither.
 *
 * Which dependencies are allowed to fail is a deliberate split. The ledger and the
 * database are hard requirements — without the ledger nothing can be verified, and
 * without the database no API key can be authenticated, so a replica missing either
 * has nothing useful to offer. The cache is explicitly *not* a hard requirement:
 * §4.6 caching is a latency optimisation over a source of truth that is still
 * reachable, so a Redis outage makes this replica slower and completely correct.
 * Reporting it as unready would remove healthy capacity for a fault that does not
 * affect a single answer the API gives.
 *
 * The response carries `status`, which the Dart client reads as the answer:
 * `HealthStatus.fromData` treats anything other than `degraded` as ready. So a
 * replica that is up but missing an optional dependency says `degraded` and still
 * answers 200, while a replica missing a hard dependency answers 503.
 */

/**
 * How long a single dependency probe may take before it is called a failure.
 *
 * A hung TCP connection is the realistic failure here, not a refused one, and
 * without a bound the probe inherits the driver's own connect timeout — which can be
 * tens of seconds. An orchestrator would give up first and record a probe timeout,
 * which is a much less useful signal than "the ledger did not answer in 2 s",
 * because the timeout tells you nothing about which dependency was at fault.
 */
const PROBE_TIMEOUT_MS = 2000;

/**
 * Resolve `promise`, or reject after `ms`.
 *
 * The timer is always cleared, and unref'd besides, so a pending probe can never
 * hold the event loop open. That matters twice over: `server.js` shuts down on
 * SIGTERM by closing the server and letting the loop drain, and `node --test` does
 * not exit while a timer is outstanding — so a leaked timer here would present as a
 * test run that passes and then hangs forever.
 */
function withTimeout(promise, ms, what) {
  let timer = null;
  const bound = new Promise((_resolve, reject) => {
    timer = setTimeout(
      () => reject(new Error(`${what} did not respond within ${ms} ms`)),
      ms,
    );
    if (typeof timer.unref === 'function') timer.unref();
  });
  return Promise.race([promise, bound]).finally(() => {
    if (timer) clearTimeout(timer);
  });
}

/**
 * Probe one dependency, never throwing.
 *
 * @returns {Promise<{ok: boolean, driver?: string, error?: string, took_ms: number}>}
 */
async function probe(name, fn, clock) {
  const startedAt = clock().getTime();
  const tookMs = () => Math.max(0, clock().getTime() - startedAt);
  if (typeof fn !== 'function') {
    // A dependency wired without a ping is a programming error, not an outage, so
    // it is reported rather than quietly counted as healthy.
    return { ok: false, error: `${name} has no ping()`, took_ms: tookMs() };
  }
  try {
    const res = await withTimeout(Promise.resolve(fn()), PROBE_TIMEOUT_MS, name);
    const out = { ok: res?.ok !== false, took_ms: tookMs() };
    if (res?.driver) out.driver = res.driver;
    return out;
  } catch (err) {
    // The message is kept: these probes are only reachable by an operator or an
    // orchestrator, and "connection refused" versus "did not respond within 2000 ms"
    // is the difference between a crashed dependency and an overloaded one. Nothing
    // here echoes client input, so there is no injection surface to worry about.
    return { ok: false, error: err?.message ?? String(err), took_ms: tookMs() };
  }
}

/**
 * @param {{store: object, cache: object, fabric: object, trust?: object,
 *          config?: object, version?: string|null,
 *          logger?: import('../utils/logger.js').Logger,
 *          clock?: () => Date}} deps
 */
export function makeHealthService({
  store,
  cache,
  fabric,
  trust,
  config,
  version = null,
  logger,
  clock = () => new Date(),
}) {
  const startedAt = clock().getTime();

  /** Whole seconds this process has been serving. */
  function uptimeSeconds() {
    return Math.max(0, Math.round((clock().getTime() - startedAt) / 1000));
  }

  /**
   * `GET /healthz` → always 200 while the process can answer.
   *
   * @returns {{status: string, uptime_s: number, env?: string, version?: string}}
   */
  function live() {
    const body = { status: 'ok', uptime_s: uptimeSeconds() };
    if (config?.env) body.env = config.env;
    if (version) body.version = version;
    return body;
  }

  /**
   * `GET /readyz` → 200 when this replica should receive traffic, 503 when not.
   *
   * The three probes run concurrently: they are independent, and running them in
   * series would make the probe's worst case the sum of three timeouts instead of
   * the longest one.
   *
   * @returns {Promise<{status: string, ready: boolean, httpStatus: number,
   *                    checks: object, uptime_s: number}>}
   */
  async function ready() {
    const [db, redis, ledger] = await Promise.all([
      probe('database', () => store.ping(), clock),
      probe('cache', () => cache.ping(), clock),
      probe('ledger', () => fabric.ping(), clock),
    ]);

    const checks = { database: db, cache: redis, ledger };

    // The trust bundle is checked without I/O — it is already in memory — but it
    // belongs here because a bundle with no usable keys means every scan returns
    // UNVERIFIABLE. That is a replica that looks healthy and answers uselessly,
    // which is the exact failure readiness exists to catch.
    if (trust?.summary) {
      try {
        const summary = trust.summary();
        const active = Number(summary.active_key_count ?? 0);
        checks.trust_bundle = {
          ok: active > 0,
          key_count: Number(summary.key_count ?? 0),
          active_key_count: active,
          signed: Boolean(summary.signed),
          issued_at: summary.issued_at ?? null,
        };
        if (active === 0) checks.trust_bundle.error = 'no active manufacturer keys';
      } catch (err) {
        checks.trust_bundle = { ok: false, error: err?.message ?? String(err) };
      }
    }

    // Hard dependencies decide traffic; the cache only colours the label.
    const hard = [db, ledger, checks.trust_bundle].filter(Boolean);
    const ready = hard.every((c) => c.ok);
    const degraded = ready && !redis.ok;

    if (!ready) {
      logger?.warn?.('readiness probe failed', {
        database: db.ok,
        ledger: ledger.ok,
        trust_bundle: checks.trust_bundle?.ok ?? null,
      });
    }

    return {
      status: ready ? (degraded ? 'degraded' : 'ok') : 'unavailable',
      ready,
      httpStatus: ready ? 200 : 503,
      checks,
      uptime_s: uptimeSeconds(),
    };
  }

  return { live, ready };
}

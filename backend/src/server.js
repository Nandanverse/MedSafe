/**
 * The process entrypoint: read the environment, build the world, listen, and shut
 * down without dropping a request.
 *
 * This is the only file in the backend that reads `process.env`, calls
 * `process.exit`, or binds a socket. Everything it constructs is passed into
 * `createApp` as an argument, so the same application can be built over an in-memory
 * store and a mock ledger by a test that never runs this file.
 *
 * **Config is imported dynamically, inside `main`.** `src/config/index.js` validates
 * the environment at import time and throws `ConfigError` from module scope; with a
 * static `import` that throw happens during this module's own loading, before any of
 * our code runs, and Node prints a stack trace with `loadConfig` frames — burying the
 * one thing the operator needs, which is the list of variables they got wrong. Loading
 * it inside a `try` turns a misconfigured deployment into a readable message and exit
 * code 1.
 *
 * The startup sequence is ordered so that anything fatal is discovered *before* the
 * port is bound. A server that accepts connections and then fails to load its trust
 * bundle would answer UNVERIFIABLE to every patient who scanned a medicine, and a
 * rolling deploy would happily replace healthy replicas with it, because it looks
 * alive. Failing loudly with nothing bound keeps the previous version serving.
 */

import { createApp, createServices } from './app.js';
import { createCache } from './cache/index.js';
import { createFabric } from './fabric/index.js';
import { createStore } from './db/index.js';
import { loadTrustBundle } from './services/trust.js';
import { SecretBox } from './utils/secret-box.js';
import { Logger } from './utils/logger.js';

/** Signals that mean "stop": SIGTERM from an orchestrator, SIGINT from a terminal. */
const STOP_SIGNALS = ['SIGTERM', 'SIGINT'];

/**
 * Close a resource without letting its failure mask an earlier one.
 * Shutdown is best-effort by nature: we are exiting either way.
 */
async function closeQuietly(label, closer, log) {
  try {
    await closer();
    log.debug('closed', { resource: label });
  } catch (err) {
    log.warn('failed to close cleanly', { resource: label, error: err?.message });
  }
}

async function main() {
  // ── 1. Configuration ──────────────────────────────────────────────────────
  let config;
  let describe;
  let assertRuntimePaths;
  let ConfigError;
  try {
    const mod = await import('./config/index.js');
    ({ config, describe, assertRuntimePaths, ConfigError } = mod);
  } catch (err) {
    // `err.problems` is the ConfigError's list of every invalid variable, reported
    // together so a misconfigured deployment is fixed in one pass instead of one
    // restart per mistake. The message never contains a secret's value.
    process.stderr.write(`${err?.message ?? err}\n`);
    process.exitCode = 1;
    return;
  }

  const logger = new Logger(
    { component: 'api' },
    { level: config.log.level, pretty: config.log.pretty },
  );

  // Paths are checked before anything opens a connection: a missing trust bundle is
  // certain to be fatal, and finding out now costs nothing.
  try {
    assertRuntimePaths(config);
  } catch (err) {
    if (err instanceof ConfigError) {
      logger.error(err.message);
      process.exitCode = 1;
      return;
    }
    throw err;
  }

  logger.info('starting TrueMed API', describe(config));

  // ── 2. Infrastructure ─────────────────────────────────────────────────────
  const store = createStore(config, logger.child({ component: 'db' }));
  const cache = createCache(config, logger.child({ component: 'cache' }));
  const fabric = createFabric(config, logger.child({ component: 'fabric' }));

  // Track what is actually open, so a failure half way through startup tears down
  // only what was created. Ordered as constructed; shutdown reverses it.
  const opened = [];

  try {
    // Not every driver needs a connection step — the in-memory store, the mock
    // ledger and the null cache are ready on construction — so `connect` is called
    // only where it exists rather than being stubbed onto each of them.
    if (typeof store.connect === 'function') await store.connect();
    opened.push(['database', () => store.close()]);

    if (typeof cache.connect === 'function') await cache.connect();
    opened.push(['cache', () => cache.close()]);

    if (typeof fabric.connect === 'function') await fabric.connect();
    opened.push(['ledger', () => fabric.close()]);

    // ── 3. Trust bundle ─────────────────────────────────────────────────────
    // Loaded once here and handed to the services, rather than read on demand: it is
    // the root of every signature check, and a server that cannot prove which keys
    // are trusted has nothing useful to say about a medicine.
    const trustBundle = await loadTrustBundle(config.trust);

    // Built here rather than left to `createServices` to default, so there is exactly
    // one box in the process and the demo seeder below provably seals with the same
    // key the API opens with.
    const secrets = new SecretBox(config.secrets.encryptionKey);

    const services = createServices({
      config,
      logger,
      store,
      cache,
      fabric,
      trustBundle,
      secrets,
      version: process.env.npm_package_version ?? null,
    });

    logger.info('trust bundle loaded', services.trust.summary());

    // ── 3b. Demo data, only when asked for ──────────────────────────────────
    // `SEED_DEMO=1 npm start` seeds the stack this process is about to serve, which
    // for the mock drivers is the only stack that will ever exist: with
    // `FABRIC_MOCK=1` the ledger, the database and the cache are objects in this heap
    // and `MockLedger` has no file behind it, so everything a separate `npm run seed`
    // wrote would vanish when it exited.
    //
    // Before `listen`, so a failed seed keeps the port unbound rather than serving an
    // empty world to whoever asked for a populated one. The import is dynamic because
    // `scripts/seed-demo.js` is not a runtime dependency of the server: it reads the
    // test fixtures, so `.dockerignore` keeps it out of the image, and a static
    // import would turn that into a crash on every boot instead of a refusal on the
    // one boot that wanted demo data.
    if (process.env.SEED_DEMO === '1') {
      const { seedDemo, formatSummary } = await import('../scripts/seed-demo.js');
      const summary = await seedDemo({ services, store, fabric, secrets, config });
      // To stdout, never through the logger: these are live credentials, and a log
      // sink keeps them long after the process that could use them is gone.
      process.stdout.write(`${formatSummary(summary)}\n`);
      logger.info('demo data seeded', {
        ledger: summary.ledger,
        units: summary.units.length,
        keys: summary.keys.length,
        readings: summary.readings.accepted,
      });
    }

    // ── 4. HTTP ─────────────────────────────────────────────────────────────
    const app = createApp({ config, logger, store, cache, fabric, trustBundle, services });

    const server = app.listen(config.server.port, config.server.host, () => {
      logger.info('listening', {
        host: config.server.host,
        port: config.server.port,
        env: config.env,
      });
    });

    // A request that arrives mid-shutdown must not be held open by a keep-alive
    // socket the client believes it can reuse. These two ceilings bound how long a
    // connection can idle, which is what allows the graceful close below to finish
    // in a predictable time rather than waiting on an idle browser tab.
    server.keepAliveTimeout = 65_000;
    server.headersTimeout = 66_000; // must exceed keepAliveTimeout (Node docs)

    // ── 5. Shutdown ─────────────────────────────────────────────────────────
    let shuttingDown = false;

    async function shutdown(signal) {
      // A second Ctrl-C is an explicit "stop waiting", so it exits immediately
      // rather than being ignored as a duplicate.
      if (shuttingDown) {
        logger.warn('second signal received; exiting now', { signal });
        process.exit(1);
      }
      shuttingDown = true;

      // Flip readiness to 503 first. The load balancer sees the next probe fail and
      // stops sending new work while in-flight requests finish on the old socket.
      app.locals.draining = true;
      logger.info('shutting down', { signal, grace_ms: config.server.shutdownGraceMs });

      // Stop accepting new connections; the callback fires once the last in-flight
      // response has been written.
      const closed = new Promise((resolveClose) => server.close(resolveClose));

      // The grace period is a ceiling, not a delay: a server with no active requests
      // resolves `closed` immediately and never waits. `unref()` keeps this timer
      // from being the thing that holds the process open once we are done.
      const timer = setTimeout(() => {
        logger.warn('grace period expired; forcing remaining connections closed');
        // Node 18.2+: sever whatever is still hanging on so we exit on schedule.
        server.closeAllConnections?.();
      }, config.server.shutdownGraceMs);
      timer.unref();

      await closed;
      clearTimeout(timer);

      // Release infrastructure in reverse order of acquisition, after the last
      // response is written — closing the database while a request is still being
      // served would turn a clean shutdown into a 500 for that user.
      for (const [label, closer] of [...opened].reverse()) {
        await closeQuietly(label, closer, logger);
      }

      logger.info('shutdown complete');
      // No `process.exit()`: with every handle closed the event loop drains and Node
      // exits on its own, which lets any final log write flush. Forcing it here is
      // how the last line of a shutdown log goes missing.
    }

    for (const signal of STOP_SIGNALS) {
      process.on(signal, () => {
        shutdown(signal).catch((err) => {
          logger.error('shutdown failed', { error: err?.message });
          process.exit(1);
        });
      });
    }

    // A crash mid-request leaves the process in an unknown state; log it with the
    // stack and let the orchestrator restart us into a known one. Staying up after
    // an unhandled rejection is how a replica ends up serving from half-initialised
    // state — far worse here than a restart, because the wrong answer to "is this
    // medicine genuine?" is not a visible failure.
    process.on('unhandledRejection', (reason) => {
      logger.error('unhandled promise rejection', {
        error: reason?.message ?? String(reason),
        stack: reason?.stack,
      });
      process.exit(1);
    });
    process.on('uncaughtException', (err) => {
      logger.error('uncaught exception', { error: err?.message, stack: err?.stack });
      process.exit(1);
    });
  } catch (err) {
    logger.error('startup failed', { error: err?.message, stack: err?.stack });
    for (const [label, closer] of [...opened].reverse()) {
      await closeQuietly(label, closer, logger);
    }
    process.exitCode = 1;
  }
}

main().catch((err) => {
  // Last resort: `main` failed before a logger existed.
  process.stderr.write(`fatal: ${err?.stack ?? err}\n`);
  process.exit(1);
});

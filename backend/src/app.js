/**
 * The application factory: dependencies in, configured Express app out.
 *
 * Nothing in this file reads `process.env`, opens a socket or constructs a client.
 * Every dependency — config, logger, store, cache, ledger, trust bundle — arrives as
 * an argument, which is what makes the whole HTTP surface testable over the in-memory
 * store, in-memory cache and mock ledger with no database, no Redis and no Fabric
 * network running. `config` in particular is a *parameter* rather than an import even
 * though `src/config/index.js` exports a ready-made singleton: that singleton is
 * frozen at import time from the real environment, so importing it here would make
 * every test inherit whatever variables happened to be set on the machine.
 *
 * Listening on a port is deliberately not this file's job — that is `server.js`. A
 * factory that also bound a socket could not be instantiated twice in one process.
 *
 * ## The middleware order, which is load-bearing
 *
 * 1. **Hardening and CORS** — cheap, header-only, and preflight must be answered
 *    before anything can reject it for missing credentials.
 * 2. **Envelope** — assigns the request id, timer and logger. It runs *before* the
 *    body parser on purpose: a malformed-JSON or oversized-body rejection is thrown
 *    by the parser, and if the envelope had not run yet that failure would have no
 *    `X-Request-Id` and no log line — the one class of error a client cannot debug
 *    from its own side would be the one we keep no record of.
 * 3. **Body parser** — JSON only.
 * 4. **Routes** — which apply their own authentication and rate limiting per §4.3.
 * 5. **Terminal 404**, then the **error handler** last, since Express only routes an
 *    error to a four-argument middleware registered after everything it guards.
 */

import express from 'express';

import { makeAuth } from './middleware/auth.js';
import { makeEnvelope } from './middleware/envelope.js';
import { makeErrorHandler, notFoundHandler } from './middleware/error-handler.js';
import { makeRateLimiter } from './middleware/rate-limit.js';
import { makeRoutes } from './routes/index.js';
import { SecretBox } from './utils/secret-box.js';

import { makeDashboardsService } from './services/dashboards.js';
import { makeHealthService } from './services/health.js';
import { makeReportsService } from './services/reports.js';
import { makeSupplyChainService } from './services/supply-chain.js';
import { makeTrustService } from './services/trust.js';
import { makeVerifyService } from './services/verify.js';

/** Methods the API actually implements; also the CORS preflight answer. */
const ALLOWED_METHODS = 'GET,POST,OPTIONS';
/** Request headers a browser dashboard legitimately sends. */
const ALLOWED_HEADERS = 'Content-Type,X-API-Key,X-Request-Id';
/** Response headers a browser must be able to read (rate-limit state, trace id). */
const EXPOSED_HEADERS =
  'X-Request-Id,X-RateLimit-Limit,X-RateLimit-Remaining,X-RateLimit-Reset,Retry-After';
/** Seconds a browser may cache a preflight result. */
const PREFLIGHT_MAX_AGE_S = 600;

/**
 * Header-only hardening, appropriate to a JSON API that serves no HTML.
 *
 * Written by hand rather than with `helmet`, because the project's dependency list is
 * deliberately five packages long and this is four headers. `default-src 'none'` is
 * safe *because* nothing here returns a document; it would be wrong on a server that
 * did.
 */
function securityHeaders(req, res, next) {
  res.set('X-Content-Type-Options', 'nosniff');
  res.set('X-Frame-Options', 'DENY');
  res.set('Referrer-Policy', 'no-referrer');
  res.set('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'");
  next();
}

/**
 * CORS against an explicit allowlist.
 *
 * With no `CORS_ORIGINS` configured this adds no headers at all, which is the correct
 * default for a mobile-first API: the Flutter client is not a browser and is unaffected
 * by CORS, so an empty list costs nothing and keeps every browser origin out.
 *
 * The origin is echoed only after it is found in the allowlist, and `*` is never sent.
 * Reflecting an arbitrary `Origin` is the standard CORS mistake, and here it would let
 * any web page a regulator visits issue authenticated dashboard reads with the API key
 * their browser already holds. `Vary: Origin` is required for the same reason the
 * allowlist is: without it a shared cache can hand one origin's permission to another.
 */
function makeCors(origins) {
  const allowed = new Set(origins ?? []);
  return function cors(req, res, next) {
    if (allowed.size === 0) return next();

    const origin = req.get('Origin');
    // `Vary` is set whenever the allowlist is active, including for requests with no
    // Origin: the response for a non-browser client differs from a browser's, and a
    // cache must not reuse one for the other.
    res.set('Vary', 'Origin');

    if (origin && allowed.has(origin)) {
      res.set('Access-Control-Allow-Origin', origin);
      res.set('Access-Control-Allow-Credentials', 'false');
      res.set('Access-Control-Expose-Headers', EXPOSED_HEADERS);
    }

    // Answer the preflight here and stop. It has to be terminated before the route's
    // `requireRole` runs, because a preflight carries no `X-API-Key` by definition —
    // a 401 here would make the browser cancel the real request and the dashboard
    // would fail with no visible cause.
    if (req.method === 'OPTIONS') {
      if (!origin || !allowed.has(origin)) return next(); // unknown origin → 404, not a grant
      res.set('Access-Control-Allow-Methods', ALLOWED_METHODS);
      res.set('Access-Control-Allow-Headers', ALLOWED_HEADERS);
      res.set('Access-Control-Max-Age', String(PREFLIGHT_MAX_AGE_S));
      return res.status(204).end();
    }

    return next();
  };
}

/**
 * Construct every service over the given infrastructure.
 *
 * Exported separately so a test — or the seed script — can drive the business logic
 * without an HTTP layer at all.
 *
 * @param {{config: object, logger: object, store: object, cache: object,
 *          fabric: object, trustBundle: object, secrets?: SecretBox,
 *          version?: string|null, clock?: () => Date}} deps
 */
export function createServices({
  config,
  logger,
  store,
  cache,
  fabric,
  trustBundle,
  secrets,
  version = null,
  clock = () => new Date(),
}) {
  const box = secrets ?? new SecretBox(config.secrets.encryptionKey);

  // The trust service comes first: verify and reports both read the active bundle
  // through it, so there is one owner of "which keys are currently trusted" and one
  // reload path, rather than a copy of the bundle in each consumer.
  const trust = makeTrustService({
    config,
    bundle: trustBundle,
    logger: logger.child({ service: 'trust' }),
    clock,
  });

  const verify = makeVerifyService({
    cache,
    fabric,
    trust,
    logger: logger.child({ service: 'verify' }),
    clock,
  });

  const supplyChain = makeSupplyChainService({
    cache,
    fabric,
    store,
    secrets: box,
    logger: logger.child({ service: 'supply-chain' }),
    clock,
  });

  const reports = makeReportsService({
    store,
    trust,
    secrets: box,
    logger: logger.child({ service: 'reports' }),
    clock,
  });

  const dashboards = makeDashboardsService({
    fabric,
    store,
    logger: logger.child({ service: 'dashboards' }),
    clock,
  });

  const health = makeHealthService({
    store,
    cache,
    fabric,
    trust,
    config,
    version,
    logger: logger.child({ service: 'health' }),
    clock,
  });

  return { trust, verify, supplyChain, reports, dashboards, health };
}

/**
 * Build the Express application.
 *
 * @param {{config: object, logger: object, store: object, cache: object,
 *          fabric: object, trustBundle: object, secrets?: SecretBox,
 *          services?: object, version?: string|null, clock?: () => Date}} deps
 * @returns {import('express').Express}
 */
export function createApp(deps) {
  const { config, logger, clock = () => new Date() } = deps;
  const services = deps.services ?? createServices(deps);

  const app = express();

  // Never advertise the framework: it tells a scanner which CVE list to try.
  app.disable('x-powered-by');

  // Express adds a weak ETag to every `res.json`. On this API that is a liveness
  // hazard rather than an optimisation: a proxy or client replaying `If-None-Match`
  // would receive a bodyless 304, and a client that expects a §4.1 envelope on every
  // response has nothing to parse. Verdicts are already cached deliberately and
  // explicitly per §4.6, with `meta.cached` telling the caller so.
  app.disable('etag');

  // `simple` uses Node's own querystring parser, so `req.query` values are only ever
  // strings or arrays of strings. The default `extended` parser builds nested objects
  // from input like `?days[a][b]=1`, which is a needlessly rich shape to hand to
  // validators that expect a scalar.
  app.set('query parser', 'simple');

  // One hop, not `true`. `trust proxy: true` tells Express to believe the *leftmost*
  // X-Forwarded-For entry, which the client itself supplies — so it would let anyone
  // set their own apparent IP, defeating the per-IP report budget and poisoning the
  // client address stored with a counterfeit report. `1` uses the address our own
  // reverse proxy observed and ignores whatever prefix the client sent.
  app.set('trust proxy', config.server.trustProxy ? 1 : false);

  app.use(securityHeaders);
  app.use(makeCors(config.server.corsOrigins));

  // Before the body parser, so a parser rejection still gets an id and a log line.
  app.use(makeEnvelope(logger));

  // JSON only. There is no urlencoded or multipart parser because no endpoint accepts
  // a form or a file upload — a counterfeit report carries its photo as base64 inside
  // the JSON body (§4.5), which is why the limit is generous.
  app.use(express.json({ limit: config.server.bodyLimit }));

  const auth = makeAuth({ store: deps.store, logger });
  const limiters = makeRateLimiter({ config, logger, clock });

  app.use(makeRoutes({ services, auth, limiters }));

  // Anything unmatched becomes a contract-shaped 404 rather than Express's HTML page.
  app.use(notFoundHandler);
  // Last, and four-argument: Express routes errors only to a handler registered after
  // the middleware that throws them.
  app.use(makeErrorHandler({ logger }));

  // Exposed for the server's shutdown path and for introspection; not used for
  // routing. `app.locals` is Express's own place for application-scoped values.
  app.locals.services = services;
  app.locals.limiters = limiters;

  return app;
}

export default createApp;

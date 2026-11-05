/**
 * `GET /healthz` and `GET /readyz` — the orchestrator's two probes.
 *
 * Neither is under `/api`, because they are not part of the medicine API: they are
 * operational endpoints an orchestrator, load balancer or uptime monitor calls, and
 * the Dart client hits them at the root to decide whether to show an "offline" chip.
 *
 * **Neither is rate limited, and that is deliberate.** A Kubernetes liveness probe
 * fires every few seconds from the node's address; behind a shared egress IP, several
 * replicas' probes would collide in one bucket and start drawing 429s. A rate-limited
 * health check reports a *healthy* service as failing and gets it restarted — the
 * limiter would manufacture the outage it was meant to protect against.
 *
 * **Readiness reports its state through the status code, not the envelope's `ok`.**
 * `res.ok(body, { status })` sends 503 with `ok: true`, which looks odd for a moment
 * and is the right choice: a readiness probe answering "I am not ready, and here is
 * which dependency is down" is a *successful* report about an unhealthy state, not a
 * protocol failure. Throwing instead would route it through the error handler, which
 * flattens everything into `{code, message}` — discarding the per-dependency `checks`
 * object that is the only reason to read a readiness body at all — and would log the
 * failure a second time on top of the line the envelope already writes for any 5xx.
 * The orchestrator reads the status code; the human reads the body.
 *
 * `httpStatus` is stripped from the body before sending. It is the service's way of
 * telling this route which code to use — transport metadata, not part of the health
 * report — and leaving it in would put a field in the response that means nothing to
 * any client.
 *
 * One accepted trade-off: these pass through the envelope middleware, so a probe every
 * two seconds writes a log line every two seconds. That buys `X-Request-Id` and
 * `res.ok` on the probe responses; a deployment that finds the volume unhelpful can
 * filter on `path` at the log aggregator rather than have the API decide what is worth
 * recording.
 */

import { Router } from 'express';

import { asyncHandler } from '../middleware/async-handler.js';

/**
 * @param {{health: {live: Function, ready: Function}}} deps
 * @returns {import('express').Router}
 */
export function makeHealthRoutes({ health }) {
  const router = Router();

  // Liveness: touches nothing external, so it answers 200 whenever the event loop
  // can respond at all. A dependency check here would turn a database blip into a
  // rolling restart of every replica.
  router.get('/healthz', (req, res) => {
    res.ok(health.live());
  });

  // Readiness: probes the dependencies concurrently and reports 503 when a hard one
  // is missing, 200 with `status: "degraded"` when only the cache is.
  router.get(
    '/readyz',
    asyncHandler(async (req, res) => {
      // Once the process has been asked to shut down it must stop attracting new
      // traffic *before* it stops accepting connections, or the load balancer keeps
      // routing requests to a socket that is about to close and users see resets
      // instead of being moved to a healthy replica. Answering 503 here is what makes
      // a rolling deploy drain cleanly. Note that `/healthz` deliberately keeps
      // answering 200 throughout: the process is alive and finishing its in-flight
      // work, and a failing liveness probe would have the orchestrator kill it
      // mid-request — which is the opposite of a graceful shutdown.
      if (req.app?.locals?.draining) {
        const { uptime_s: uptimeS } = health.live();
        res.ok({ status: 'draining', ready: false, uptime_s: uptimeS }, { status: 503 });
        return;
      }
      const { httpStatus, ...body } = await health.ready();
      res.ok(body, { status: httpStatus });
    }),
  );

  return router;
}

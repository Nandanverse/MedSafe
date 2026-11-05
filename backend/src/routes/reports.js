/**
 * `POST /api/report` — a patient reporting suspected counterfeit medicine.
 *
 * Unauthenticated, deliberately. Requiring an account would silence exactly the
 * reports the system exists to collect: the person holding a fake strip is a patient,
 * not a licensed party with an API key. That makes this the most exposed write in the
 * API, so it carries the tightest budget of any endpoint — `limiters.report` is per
 * IP *per hour*, not per minute, because each accepted report stores a photograph and
 * costs a human being triage time.
 *
 * The client IP is handed to the service explicitly rather than read from the request
 * inside it. Two reasons: the service stays a pure function of its inputs and can be
 * tested without fabricating an Express request, and it makes the one place that
 * captures personal data visible at the route. `req.ip` honours Express's
 * `trust proxy` setting, which `app.js` sets from config — so behind a load balancer
 * it is the real client, and with no proxy configured a spoofed `X-Forwarded-For` is
 * ignored.
 *
 * 201, because a report is a created resource; the response carries only its id and
 * timestamp, never the stored row.
 */

import { Router } from 'express';

import { asyncHandler } from '../middleware/async-handler.js';

/**
 * @param {{reports: {submit: Function}, limiters: object}} deps
 * @returns {import('express').Router}
 */
export function makeReportRoutes({ reports, limiters }) {
  const router = Router();

  router.post(
    '/report',
    limiters.report,
    asyncHandler(async (req, res) => {
      const data = await reports.submit(req.body ?? {}, { ip: req.ip ?? null });
      res.ok(data, { status: 201 });
    }),
  );

  return router;
}

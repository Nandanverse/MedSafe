/**
 * The two read-only dashboards: `GET /api/dashboard/cdsco` and `/api/dashboard/pharma`.
 *
 * Both are authenticated and role-gated, and the two roles are deliberately not
 * interchangeable. A `regulator` key sees the CDSCO board — a nationwide view of
 * counterfeit reports, recalls and cold-chain breaches. A `pharma` key sees only its
 * own manufacturer's production, scoped by the `mfg_licence_no` carried on the key,
 * never a query parameter; the service refuses an unscoped `pharma` key rather than
 * showing it everyone's data. Handing the whole `req.auth` object to `pharma()` is
 * what lets the service read that scope; the CDSCO board needs no scope and takes
 * only the query.
 *
 * Neither endpoint returns a verdict, so neither is on the verification path (§4.4a):
 * a dashboard that is stale, truncated or briefly down degrades a regulator's view
 * and can never change what a patient is told. That is what licenses the full-ledger
 * scan behind them, work no verification endpoint could afford — and why these sit
 * behind the ordinary `authed` budget with no special caching promise.
 *
 * `?days=` and `?limit=` are validated inside the service to the §4.4a ranges, and an
 * out-of-range value is a 400 rather than a silent clamp, so a client asking for
 * `?days=9999` learns it has a bug instead of quietly getting a different window than
 * it asked for.
 *
 * `requireRole` runs before `limiters.authed`, as it does on the write routes, because
 * the authed budget keys on `req.auth.keyHash` and would fall back to the caller's IP
 * if no key had been resolved yet — turning a per-key budget into a per-address one and
 * letting anyone sharing a regulator's uplink exhaust their allowance.
 */

import { Router } from 'express';

import { asyncHandler } from '../middleware/async-handler.js';
import { ROLE } from '../core/rules.js';

/**
 * @param {{dashboards: {cdsco: Function, pharma: Function},
 *          auth: {requireRole: Function}, limiters: object}} deps
 * @returns {import('express').Router}
 */
export function makeDashboardRoutes({ dashboards, auth, limiters }) {
  const router = Router();

  router.get(
    '/dashboard/cdsco',
    auth.requireRole(ROLE.REGULATOR),
    limiters.authed,
    asyncHandler(async (req, res) => {
      const data = await dashboards.cdsco(req.query ?? {});
      res.ok(data);
    }),
  );

  router.get(
    '/dashboard/pharma',
    auth.requireRole(ROLE.PHARMA),
    limiters.authed,
    asyncHandler(async (req, res) => {
      // The whole auth object, not just the role: the service reads `scope` (the
      // holder's mfg_licence_no) to confine the board to one manufacturer.
      const data = await dashboards.pharma(req.auth, req.query ?? {});
      res.ok(data);
    }),
  );

  return router;
}

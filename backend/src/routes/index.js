/**
 * The URL map: every path the API answers, in one file.
 *
 * This module does one thing — bind paths to the six route modules — so that the
 * question "what does this server expose?" has a single, short answer that can be
 * read against DATA-CONTRACT.md §4.3 line by line. It builds no services, reads no
 * config and creates no dependencies; everything arrives already constructed, which
 * is what lets `app.js` hand it a mock ledger and an in-memory store without this
 * file knowing the difference.
 *
 * **The `/api` prefix lives here, not in the route modules.** Each module declares
 * paths relative to its mount point (`/verify/:productID`, not
 * `/api/verify/:productID`), so the prefix appears exactly once in the codebase. The
 * two probes are the deliberate exception: `/healthz` and `/readyz` are mounted at the
 * root because an orchestrator's probe configuration is not part of the medicine API
 * and should not move if the API is ever versioned to `/api/v2`.
 *
 * The terminal 404 is *not* registered here. It belongs to the middleware pipeline in
 * `app.js`, which owns what happens before and after routing; a reader auditing
 * "what does an unmatched request get?" should find the answer in the pipeline rather
 * than buried at the bottom of a URL map. Keeping it out also means this router can be
 * mounted inside a larger application without swallowing its sibling routes.
 */

import { Router } from 'express';

import { makeDashboardRoutes } from './dashboards.js';
import { makeHealthRoutes } from './health.js';
import { makeReportRoutes } from './reports.js';
import { makeSupplyChainRoutes } from './supply-chain.js';
import { makeTrustRoutes } from './trust.js';
import { makeVerifyRoutes } from './verify.js';

/** The one place the API's path prefix is written. */
export const API_PREFIX = '/api';

/**
 * Build the application's complete route tree.
 *
 * @param {{services: {verify: object, supplyChain: object, reports: object,
 *                     dashboards: object, trust: object, health: object},
 *          auth: {requireRole: Function}, limiters: object}} deps
 * @returns {import('express').Router}
 */
export function makeRoutes({ services, auth, limiters }) {
  const router = Router();

  // Probes at the root, unauthenticated and unlimited (see routes/health.js).
  router.use('/', makeHealthRoutes({ health: services.health }));

  const api = Router();

  // Public — a patient never needs an account to check a medicine (§4.2).
  api.use(makeVerifyRoutes({ verify: services.verify, limiters }));
  api.use(makeReportRoutes({ reports: services.reports, limiters }));
  api.use(makeTrustRoutes({ trust: services.trust, limiters }));

  // Authenticated and role-gated (§4.3).
  api.use(makeSupplyChainRoutes({ supplyChain: services.supplyChain, auth, limiters }));
  api.use(makeDashboardRoutes({ dashboards: services.dashboards, auth, limiters }));

  router.use(API_PREFIX, api);

  return router;
}

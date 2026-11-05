/**
 * Public verification: `GET /api/verify/:productID` and `POST /api/verify/payload`.
 *
 * Both are unauthenticated, and that is the whole point of the system — a patient
 * standing at a counter must be able to check a strip without an account, an app
 * login, or a data plan they may not have. Rate limiting is by IP (the only key
 * available without identity), which is why these two sit behind `limiters.public`
 * rather than `limiters.authed`.
 *
 * **A verdict is never an HTTP error.** COUNTERFEIT, EXPIRED, RECALLED,
 * COLD_CHAIN_BREACH and CLONE_SUSPECTED all answer 200 with the verdict inside
 * `data`, because each is a *successful* answer to "is this genuine?". Only protocol
 * problems — a malformed product ID, a missing body, an unreachable ledger — are
 * 4xx/5xx. That separation is what lets the Flutter client treat HTTP status and
 * medical verdict as independent axes, and it is why nothing in this file inspects
 * the verdict to decide a status code.
 *
 * The one exception is a product ID that is not on the chain at all, which the
 * service raises as `NOT_ON_CHAIN` (404). That is not a verdict about a medicine; it
 * is the absence of any record to have a verdict about, and the client renders it as
 * its own screen.
 *
 * `meta.cached` is passed through from the service rather than hard-coded, because
 * §4.6 permits a verdict to be served from cache for up to an hour and a pharmacist
 * reading a cold-chain figure needs to know it could be that old.
 */

import { Router } from 'express';

import { asyncHandler } from '../middleware/async-handler.js';

/**
 * @param {{verify: {byProductID: Function, byPayload: Function}, limiters: object}} deps
 * @returns {import('express').Router}
 */
export function makeVerifyRoutes({ verify, limiters }) {
  const router = Router();

  // §4.3: a plain read of the chain's view of one unit.
  router.get(
    '/verify/:productID',
    limiters.public,
    asyncHandler(async (req, res) => {
      const { body, cached } = await verify.byProductID(req.params.productID);
      res.ok(body, { cached });
    }),
  );

  // §4.3 + §7.1: the only endpoint that records a patient scan, because it is the
  // only one that proves the scanner physically held a signed payload. A GET by
  // product ID cannot: anyone can type an ID they read off a photograph, and
  // counting those as scans would trigger CLONE_SUSPECTED on a genuine unit.
  router.post(
    '/verify/payload',
    limiters.public,
    asyncHandler(async (req, res) => {
      const { body, cached } = await verify.byPayload(req.body ?? {});
      res.ok(body, { cached });
    }),
  );

  return router;
}

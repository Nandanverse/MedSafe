/**
 * The authenticated ledger writes: `POST /api/medicine`, `/api/location`,
 * `/api/temperature` and `/api/recall`.
 *
 * Every route here is gated twice, and the two gates answer different questions.
 * `requireRole(...)` proves *who is calling* from their API key and rejects a valid
 * key of the wrong role with a 403 before the service runs. The service then
 * enforces what that role may *write* — the pharmacy status restriction (§4.3), the
 * sensor HMAC (§4.7), the RegulatorMSP-only recall. Neither gate is redundant: the
 * role check keeps a distributor's key out of the mint endpoint entirely, and the
 * service check keeps a pharmacy key — which submits under DistributorMSP on the
 * real network — from rewinding a unit's custody. Remove either and a whole class of
 * forged history becomes writable.
 *
 * `submitterFor(role)` inside the service maps the caller's role to the Fabric MSP,
 * so the submitting identity is derived from the authenticated key and never from
 * the request body. A body-supplied `actor_msp` would be an attacker choosing who is
 * accountable for a write; there is deliberately no code path that reads one.
 *
 * The status codes follow §4.5a: a mint and a temperature reading create a unit's
 * first record of their kind and answer 201; a custody hop and a recall mutate
 * existing records and answer 200. `req.auth.role` is present on every handler here
 * because `requireRole` ran first and attached it.
 *
 * **Authentication runs before the rate limiter on every route here, and the order is
 * load-bearing.** `limiters.authed` keys on `req.auth.keyHash` and falls back to the
 * client IP when no key has been resolved yet — so limiting first would silently make
 * the IP fallback the *only* path, and every authenticated budget in the system would
 * become per-address instead of per-key. That is not merely imprecise accounting: a
 * pharmacy sharing a NAT or clinic uplink with an attacker would have its 600/min
 * budget drained by traffic that never presented a valid key, and a chemist would stop
 * being able to record `dispensed` because of a stranger on the same connection. Keyed
 * on the hash, an attacker cannot touch a legitimate holder's budget without already
 * holding their key. The cost of this order is that an unauthenticated flood reaches
 * one indexed hash lookup per request before being rejected; that is a cheap, bounded
 * operation, and connection-level flooding is the reverse proxy's job, not the API's.
 */

import { Router } from 'express';

import { asyncHandler } from '../middleware/async-handler.js';
import { ROLE } from '../core/rules.js';

/**
 * @param {{supplyChain: {mint: Function, recordLocation: Function,
 *          recordTemperature: Function, recall: Function},
 *          auth: {requireRole: Function}, limiters: object}} deps
 * @returns {import('express').Router}
 */
export function makeSupplyChainRoutes({ supplyChain, auth, limiters }) {
  const router = Router();

  // §4.3: only a manufacturer mints. The unit does not exist until this call, so a
  // successful mint is a creation → 201.
  router.post(
    '/medicine',
    auth.requireRole(ROLE.MANUFACTURER),
    limiters.authed,
    asyncHandler(async (req, res) => {
      const data = await supplyChain.mint(req.body ?? {}, req.auth);
      res.ok(data, { status: 201 });
    }),
  );

  // §4.3: a custody hop may be asserted by the manufacturer, a distributor or a
  // pharmacy — but the pharmacy is confined to at_pharmacy/dispensed inside the
  // service. Mutating an existing unit → 200.
  router.post(
    '/location',
    auth.requireRole(ROLE.MANUFACTURER, ROLE.DISTRIBUTOR, ROLE.PHARMACY),
    limiters.authed,
    asyncHandler(async (req, res) => {
      const data = await supplyChain.recordLocation(req.body ?? {}, req.auth);
      res.ok(data);
    }),
  );

  // §4.3 + §4.7: an IoT cold-chain reading. Gated by the sensor role here and by a
  // per-device HMAC and nonce inside the service, so a stolen API key alone cannot
  // forge a reading. A reading behind its own budget (`limiters.sensor`, keyed on
  // the sensor's key) rather than the shared authed budget, because a cold box
  // reports far more often than a human operator. Appends a reading → 201.
  router.post(
    '/temperature',
    auth.requireRole(ROLE.SENSOR),
    limiters.sensor,
    asyncHandler(async (req, res) => {
      const data = await supplyChain.recordTemperature(req.body ?? {}, req.auth);
      res.ok(data, { status: 201 });
    }),
  );

  // §4.3: only a regulator recalls a batch. Moves existing units to `recalled` and
  // returns the chaincode's RecallResult unchanged → 200.
  router.post(
    '/recall',
    auth.requireRole(ROLE.REGULATOR),
    limiters.authed,
    asyncHandler(async (req, res) => {
      const data = await supplyChain.recall(req.body ?? {}, req.auth);
      res.ok(data);
    }),
  );

  return router;
}

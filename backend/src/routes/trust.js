/**
 * `GET /api/public-keys` — the signed trust bundle.
 *
 * Public and unauthenticated, because its entire purpose is to let a phone verify a
 * medicine with no network and no account. The bundle contains only *public* keys and
 * a root signature over them, so there is nothing here to protect; withholding it
 * would break offline verification, which is the feature that makes TrueMed usable in
 * a village with no signal.
 *
 * The response is the bundle's parsed contents as the envelope's `data`, which is what
 * the Dart client reads (`fetchTrustBundle` re-encodes `result.data` and hands it to
 * `TrustBundle.fromJson`). That re-encoding is safe here and *only* here: the root
 * signature is computed over `canonicalJSONBytes({version, issued_at, keys})`, a
 * canonical re-serialisation by definition, so key order and whitespace cannot change
 * what gets verified. One layer down the opposite rule holds — a QR payload must be
 * verified over its received bytes (§1.5) — and confusing the two would be a
 * signature bypass.
 *
 * Cached briefly at the edge via `Cache-Control`. The bundle changes only when a
 * manufacturer is onboarded or a key rotated, and every phone fetches it; a few
 * minutes of caching removes almost all of that traffic. It is deliberately short
 * rather than aggressive, because a revoked key needs to stop being served promptly —
 * `must-revalidate` keeps a stale copy from being used after it lapses.
 */

import { Router } from 'express';

import { asyncHandler } from '../middleware/async-handler.js';

/** Seconds a client or proxy may reuse the bundle. Well under the reload interval. */
const PUBLIC_KEYS_MAX_AGE_S = 300;

/**
 * @param {{trust: {publicKeys: Function}, limiters: object}} deps
 * @returns {import('express').Router}
 */
export function makeTrustRoutes({ trust, limiters }) {
  const router = Router();

  router.get(
    '/public-keys',
    limiters.public,
    asyncHandler(async (req, res) => {
      const bundle = await trust.publicKeys();
      res.set('Cache-Control', `public, max-age=${PUBLIC_KEYS_MAX_AGE_S}, must-revalidate`);
      res.ok(bundle);
    }),
  );

  return router;
}
